package api

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"sync"
	"time"

	api "github.com/aau-network-security/gollector/api/proto"
	"github.com/aau-network-security/gollector/app"
	"github.com/aau-network-security/gollector/collectors/ct"
	"github.com/aau-network-security/gollector/store"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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

	log.Debug().Str("muid", muid).Msgf("connection opened for log entries")
	defer log.Debug().Str("muid", muid).Msgf("connection closed for log entries")

	wg := sync.WaitGroup{}

	for {
		batch, err := str.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return status.Error(codes.Internal, err.Error())
		}

		s.Store.NewBatchQueryDB()

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
				startTime := time.Now()
				if err := s.Store.MapEntry(muid, entry); err != nil {
					s.Log.Log(err, app.LogOptions{
						Msg: "failed to map log entry with Cache",
						Tags: map[string]string{
							"log": le.Log.Url,
						},
					})
					res = &api.Result{
						Ok:    false,
						Error: err.Error(),
					}
				}

				//if err := s.Store.StoreLogEntry(muid, entry); err != nil {
				//	s.Log.Log(err, app.LogOptions{
				//		Msg: "failed to store log entry",
				//		Tags: map[string]string{
				//			"log": le.Log.Url,
				//		},
				//	})
				//	res = &api.Result{
				//		Ok:    false,
				//		Error: err.Error(),
				//	}
				//}
				// write a chunk
				finishTime := time.Since(startTime)
				if _, err := s.BenchmarkFile.Write([]byte(strconv.FormatInt(finishTime.Microseconds(), 10) + ",")); err != nil {
					panic(err)
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
		//todo change the response to the client
		errs := s.Store.MapBatchWithCacheAndDB()
		if len(errs) != 0 {
			fmt.Println(errs)
		}
		err = s.Store.StoreBatchPostHook()
		if err != nil {
			fmt.Println(err)
		}

		log.Info().Msgf("%v", s.Store.Counter)
		s.Store.ResetCounter()
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
