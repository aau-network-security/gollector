package api

import (
	"context"
	prt "github.com/aau-network-security/go-domains/api/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *Server) StoreZoneEntry(ctx context.Context, ze *prt.ZoneEntry) (*prt.Empty, error) {
	muid, err := muidFromContext(ctx)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	t := timeFromUnix(ze.Timestamp)

	if _, err := s.Store.StoreZoneEntry(muid, t, ze.Apex); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &prt.Empty{}, nil
}
