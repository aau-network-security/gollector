package api

import (
	prt "github.com/aau-network-security/go-domains/api/proto"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"io"
	"sync"
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
