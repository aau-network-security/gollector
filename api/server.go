package api

import (
	"context"
	"errors"
	"fmt"
	prt "github.com/aau-network-security/go-domains/api/proto"
	"github.com/aau-network-security/go-domains/config"
	"github.com/aau-network-security/go-domains/store"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"net"
	"time"
)

var (
	MissingMidErr = errors.New("request is missing a measured id")
)

func midFromContext(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", MissingMidErr
	}
	mids := md.Get("mid")
	if len(mids) == 0 || mids[0] == "" {
		return "", MissingMidErr
	}
	return mids[0], nil
}

func timeFromUnix(ts int64) time.Time {
	return time.Unix(int64(ts/1000), int64(ts%1000))
}

type Server struct {
	Conf  config.Api
	Store *store.Store
}

func (s *Server) Run() error {
	addr := fmt.Sprintf("%s:%d", s.Conf.Host, s.Conf.Port)
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	serv := grpc.NewServer()
	prt.RegisterCtApiServer(serv, s)
	prt.RegisterMeasurementApiServer(serv, s)

	log.Debug().Msgf("running gRPC server on %s", addr)
	return serv.Serve(lis)
}