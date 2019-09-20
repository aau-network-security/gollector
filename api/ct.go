package api

import (
	"context"
	prt "github.com/aau-network-security/go-domains/api/proto"
	"github.com/aau-network-security/go-domains/ct"
	"github.com/aau-network-security/go-domains/store"
	"github.com/google/certificate-transparency-go/x509"
)

func (s *Server) StoreLogEntries(ctx context.Context, inp *prt.LogEntry) (*prt.Error, error) {
	resp := &prt.Error{}

	mid, err := midFromContext(ctx)
	if err != nil {
		resp.Error = err.Error()
		return resp, nil
	}

	cert, err := x509.ParseCertificate(inp.Certificate)
	if err != nil {
		resp.Error = err.Error()
		return resp, nil
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
	if err := s.Store.StoreLogEntry(mid, entry); err != nil {
		resp.Error = err.Error()
		return resp, nil
	}
	return resp, nil
}
