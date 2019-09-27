package api

import (
	api "github.com/aau-network-security/go-domains/api/proto"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"io"
	"sync"
)

func (s *Server) StoreEntradaEntry(str api.EntradaApi_StoreEntradaEntryServer) error {
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

		for _, ee := range batch.EntradaEntries {
			ts := timeFromUnix(ee.Timestamp)

			res := &api.Result{
				Ok:    true,
				Error: "",
			}

			if _, err := s.Store.StoreEntradaEntry(muid, ee.Fqdn, ts); err != nil {
				res = &api.Result{
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
