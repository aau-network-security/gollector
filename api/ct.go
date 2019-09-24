package api

import (
	"context"
	prt "github.com/aau-network-security/go-domains/api/proto"
	"github.com/aau-network-security/go-domains/collectors/ct"
	"github.com/aau-network-security/go-domains/store"
	"github.com/google/certificate-transparency-go/x509"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *Server) StoreLogEntries(ctx context.Context, inp *prt.LogEntry) (*prt.Empty, error) {
	muid, err := muidFromContext(ctx)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	cert, err := x509.ParseCertificate(inp.Certificate)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	l := ct.Log{
		Description:       inp.Log.Description,
		Key:               inp.Log.Key,
		Url:               inp.Log.Url,
		MaximumMergeDelay: int(inp.Log.MaximumMergeDelay),
		DnsApiEndpoint:    inp.Log.DnsApiEndpoint,
	}
	entry := store.LogEntry{
		Cert:  cert,
		Index: uint(inp.Index),
		Ts:    timeFromUnix(inp.Timestamp),
		Log:   l,
	}
	if err := s.Store.StoreLogEntry(muid, entry); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &prt.Empty{}, nil
}
