package api

import (
	"context"
	"errors"
	"fmt"
	prt "github.com/aau-network-security/go-domains/api/proto"
	"github.com/aau-network-security/go-domains/store"
	"github.com/go-acme/lego/providers/dns/cloudflare"
	"github.com/mholt/certmagic"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"net"
	"time"
)

var (
	MissingMidErr = errors.New("request is missing a measured id")
)

func muidFromContext(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", MissingMidErr
	}
	muids := md.Get("mid")
	if len(muids) == 0 || muids[0] == "" {
		return "", MissingMidErr
	}
	return muids[0], nil
}

func timeFromUnix(ts int64) time.Time {
	return time.Unix(int64(ts/1000), int64(ts%1000))
}

type Server struct {
	Conf  Config
	Store *store.Store
}

func (s *Server) Run() error {
	addr := fmt.Sprintf("%s:%d", s.Conf.Api.Host, s.Conf.Api.Port)
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	var opts []grpc.ServerOption
	if s.Conf.Api.Tls.Enabled {
		certConf := certmagic.NewDefault()
		provider, err := cloudflare.NewDNSProviderConfig(s.Conf.Api.Tls.Auth.ToCertmagicConfig())
		if err != nil {
			return err
		}
		certConf.DNSProvider = provider

		domains := []string{s.Conf.Api.Host}
		if err := certConf.Manage(domains); err != nil {
			return err
		}

		cert, err := certConf.CacheManagedCertificate(s.Conf.Api.Host)
		if err != nil {
			return err
		}

		transportCreds := credentials.NewServerTLSFromCert(&cert.Certificate)
		opts = append(opts, grpc.Creds(transportCreds))
	}
	serv := grpc.NewServer(opts...)
	prt.RegisterCtApiServer(serv, s)
	prt.RegisterMeasurementApiServer(serv, s)
	prt.RegisterZoneFileApiServer(serv, s)
	prt.RegisterSplunkApiServer(serv, s)
	prt.RegisterEntradaApiServer(serv, s)

	log.Debug().Msgf("running gRPC server on %s", addr)
	return serv.Serve(lis)
}
