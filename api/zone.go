package api

import (
	prt "github.com/aau-network-security/go-domains/api/proto"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"io"
)

func (s *Server) StoreZoneEntry(server prt.ZoneFileApi_StoreZoneEntryServer) error {
	muid, err := muidFromContext(server.Context())
	if err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}

	for {
		batch, err := server.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		for _, ze := range batch.ZoneEntries {
			t := timeFromUnix(ze.Timestamp)

			res := &prt.Result{
				Ok:    true,
				Error: "",
			}
			if _, err := s.Store.StoreZoneEntry(muid, t, ze.Apex); err != nil {
				res = &prt.Result{
					Ok:    false,
					Error: err.Error(),
				}
			}
			if err := server.Send(res); err != nil {
				log.Debug().Msgf("failed to send response to client")
			}
		}

	}

	return nil
}
