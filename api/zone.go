package api

import (
	"context"
	prt "github.com/aau-network-security/gollector/api/proto"
	"github.com/aau-network-security/gollector/app"
	"github.com/aau-network-security/gollector/collectors/zone"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"io"
	"sync"
	"time"
)

func (s *Server) StoreZoneEntry(str prt.ZoneFileApi_StoreZoneEntryServer) error {
	muid, err := muidFromContext(str.Context())
	if err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}

	log.Debug().Str("muid", muid).Msgf("connection opened for zone entries")
	defer log.Debug().Str("muid", muid).Msgf("connection closed for zone entries")

	wg := sync.WaitGroup{}

	for {
		batch, err := str.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return status.Error(codes.Internal, err.Error())
		}

		for _, ze := range batch.ZoneEntries {
			ts := timeFromUnix(ze.Timestamp)

			res := &prt.Result{
				Ok:    true,
				Error: "",
			}
			if _, err := s.Store.StoreZoneEntry(muid, ts, ze.Apex); err != nil {
				s.Log.Log(err, app.LogOptions{
					Msg: "failed to store zone entry",
				})
				res = &prt.Result{
					Ok:    false,
					Error: err.Error(),
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

func (s *Server) GetStartTime(ctx context.Context, iv *prt.Interval) (*prt.StartTime, error) {
	st, err := zone.GetStartTime(s.Conf.Store, time.Duration(iv.Interval)*time.Millisecond)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	ts := st.UnixNano() / 1e06
	resp := &prt.StartTime{
		Timestamp: ts,
	}
	return resp, nil
}
