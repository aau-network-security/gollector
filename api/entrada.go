package api

import (
	"context"
	api "github.com/aau-network-security/gollector/api/proto"
	"github.com/aau-network-security/gollector/app"
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

	log.Debug().Str("muid", muid).Msgf("connection opened for entrada entries")
	defer func() {
		log.Debug().Str("muid", muid).Msgf("connection closed for entrada entries")
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

		for _, ee := range batch.EntradaEntries {
			ts := timeFromUnix(ee.Timestamp)

			res := &api.Result{
				Ok:    true,
				Error: "",
			}

			if err := s.Store.StoreEntradaEntry(muid, ee.Fqdn, ts); err != nil {
				s.Log.Log(err, app.LogOptions{
					Msg: "failed to store entrada entry",
					Tags: map[string]string{
						"fqdn": ee.Fqdn,
					},
				})
				res = &api.Result{
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

func (s *Server) GetOffset(context.Context, *api.Empty) (*api.Offset, error) {
	offset, err := s.Store.GetEntradaOffset()
	if err != nil {
		return nil, err
	}
	return &api.Offset{Offset: offset}, nil
}
