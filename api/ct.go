package api

import (
	api "github.com/aau-network-security/go-domains/api/proto"
	"github.com/aau-network-security/go-domains/collectors/ct"
	"github.com/aau-network-security/go-domains/store"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"io"
	"sync"
)

func (s *Server) StoreLogEntries(str api.CtApi_StoreLogEntriesServer) error {
	muid, err := muidFromContext(str.Context())
	if err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}

	wg := sync.WaitGroup{}

	for {
		batch, err := str.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return status.Error(codes.Internal, err.Error())
		}

		for _, le := range batch.LogEntries {
			res := &api.Result{
				Ok:    true,
				Error: "",
			}

			cert, err := x509.ParseCertificate(le.Certificate)
			if err != nil {
				res = &api.Result{
					Ok:    false,
					Error: err.Error(),
				}
			} else {
				l := ct.Log{
					Description:       le.Log.Description,
					Key:               le.Log.Key,
					Url:               le.Log.Url,
					MaximumMergeDelay: int(le.Log.MaximumMergeDelay),
					DnsApiEndpoint:    le.Log.DnsApiEndpoint,
				}
				entry := store.LogEntry{
					Cert:  cert,
					Index: uint(le.Index),
					Ts:    timeFromUnix(le.Timestamp),
					Log:   l,
				}
				if err := s.Store.StoreLogEntry(muid, entry); err != nil {
					res = &api.Result{
						Ok:    false,
						Error: err.Error(),
					}
				}
			}

			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := str.Send(res); err != nil {
					log.Debug().Msgf("failed to send response to client: %s", err)
				}
			}()
		}
	}
	wg.Wait()

	return nil
}
