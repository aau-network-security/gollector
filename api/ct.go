package api

import (
	"context"
	api "github.com/aau-network-security/gollector/api/proto"
	"github.com/aau-network-security/gollector/app"
	"github.com/aau-network-security/gollector/collectors/ct"
	"github.com/aau-network-security/gollector/store"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"io"
	"sync"
)

func certFromLogEntry(le *api.LogEntry) (*x509.Certificate, error) {
	if le.IsPrecert {
		return x509.ParseTBSCertificate(le.Certificate)
	}
	return x509.ParseCertificate(le.Certificate)
}

func (s *Server) StoreLogEntries(str api.CtApi_StoreLogEntriesServer) error {
	muid, err := muidFromContext(str.Context())
	if err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}

	log.Debug().Str("muid", muid).Msgf("connection opened for ct log entries")
	defer func() {
		log.Debug().Str("muid", muid).Msgf("connection closed for ct log entries")
		// should *not* be necessary
		if err := s.Store.RunPostHooks(); err != nil {
			log.Fatal().Str("muid", muid).Msgf("failed to run post hooks: %s", err)
		}
	}()

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

			cert, err := certFromLogEntry(le)
			if err != nil {
				s.Log.Log(err, app.LogOptions{
					Msg: "failed to parse certificate",
					Tags: map[string]string{
						"log": le.Log.Url,
					},
				})
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
					Cert:      cert,
					IsPrecert: le.IsPrecert,
					Index:     uint(le.Index),
					Ts:        timeFromUnix(le.Timestamp),
					Log:       l,
				}

				if err := s.Store.StoreLogEntry(muid, entry); err != nil {
					s.Log.Log(err, app.LogOptions{
						Msg: "failed to store log entry",
						Tags: map[string]string{
							"log": le.Log.Url,
						},
					})
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
					s.Log.Log(err, app.LogOptions{
						Msg: "failed to send response to client",
						Tags: map[string]string{
							"muid": muid,
						},
					})
				}
			}()
		}
	}
	wg.Wait()

	return nil
}

func (s *Server) GetLastDBEntry(ctx context.Context, url *api.KnownLogURL) (*api.Index, error) {
	logEntryIndex, err := s.Store.GetLastIndexLog(url.LogURL)
	if err != nil {
		return nil, err
	}
	return &api.Index{Start: logEntryIndex}, nil
}
