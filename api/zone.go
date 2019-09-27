package api

import (
	"context"
	prt "github.com/aau-network-security/go-domains/api/proto"
	"github.com/aau-network-security/go-domains/collectors/zone"
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
				res = &prt.Result{
					Ok:    false,
					Error: err.Error(),
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
