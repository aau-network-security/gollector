package api

import (
	api "github.com/aau-network-security/go-domains/api/proto"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"io"
	"sync"
)

func (s *Server) StorePassiveEntry(str api.SplunkApi_StorePassiveEntryServer) error {
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

		for _, se := range batch.SplunkEntries {
			ts := timeFromUnix(se.Timestamp)

			res := &api.Result{
				Ok:    true,
				Error: "",
			}
			if _, err := s.Store.StorePassiveEntry(muid, se.Query, se.QueryType, ts); err != nil {
				res = &api.Result{
					Ok:    false,
					Error: err.Error(),
				}
			}

			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := str.Send(res); err != nil {
					log.Debug().Msgf("failed to send response to client")
				}
			}()
		}
	}
	wg.Wait()

	return nil
}
