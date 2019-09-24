package api

import (
	"context"
	prt "github.com/aau-network-security/go-domains/api/proto"
)

func (s *Server) StoreZoneEntry(ctx context.Context, ze *prt.ZoneEntry) (*prt.Error, error) {
	resp := &prt.Error{}

	muid, err := muidFromContext(ctx)
	if err != nil {
		resp.Error = err.Error()
		return resp, nil
	}

	t := timeFromUnix(ze.Timestamp)

	if _, err := s.Store.StoreZoneEntry(muid, t, ze.Fqdn); err != nil {
		resp.Error = err.Error()
		return resp, nil
	}
	return resp, nil
}
