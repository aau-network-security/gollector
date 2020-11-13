package api

import (
	"context"

	api "github.com/aau-network-security/gollector/api/proto"
	"github.com/aau-network-security/gollector/app"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *Server) StartMeasurement(ctx context.Context, meta *api.Meta) (*api.StartMeasurementResponse, error) {
	muid, err := s.Store.StartMeasurement(meta.Description, meta.Host)
	if err != nil {
		s.Log.Log(err, app.LogOptions{
			Msg: "failed to start measurement",
			Tags: map[string]string{
				"muid": muid,
			},
		})
		return nil, status.Error(codes.Internal, err.Error())
	}

	log.Debug().Str("muid", muid).Msgf("started measurement")

	resp := &api.StartMeasurementResponse{
		MeasurementId: &api.MeasurementId{
			Id: muid,
		},
	}
	return resp, nil
}

func (s *Server) StopMeasurement(ctx context.Context, muid *api.MeasurementId) (*api.Empty, error) {
	if err := s.Store.StopMeasurement(muid.Id); err != nil {
		s.Log.Log(err, app.LogOptions{
			Msg: "failed to stop measurement",
			Tags: map[string]string{
				"muid": muid.Id,
			},
		})
		return nil, status.Error(codes.Internal, err.Error())
	}

	log.Debug().Str("muid", muid.Id).Msgf("stopped measurement")

	return &api.Empty{}, nil
}

func (s *Server) StartStage(ctx context.Context, muid *api.MeasurementId) (*api.Empty, error) {
	if err := s.Store.StartStage(muid.Id); err != nil {
		s.Log.Log(err, app.LogOptions{
			Msg: "failed to start stage",
			Tags: map[string]string{
				"muid": muid.Id,
			},
		})
		return nil, status.Error(codes.Internal, err.Error())
	}

	log.Debug().Str("muid", muid.Id).Msgf("started stage")
	return &api.Empty{}, nil
}

func (s *Server) StopStage(ctx context.Context, muid *api.MeasurementId) (*api.Empty, error) {
	if err := s.Store.StopStage(muid.Id); err != nil {
		s.Log.Log(err, app.LogOptions{
			Msg: "failed to stop stage",
			Tags: map[string]string{
				"muid": muid.Id,
			},
		})
		return nil, status.Error(codes.Internal, err.Error())
	}

	log.Debug().Str("muid", muid.Id).Msgf("stopped stage")

	return &api.Empty{}, nil
}
