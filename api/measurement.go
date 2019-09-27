package api

import (
	"context"
	api "github.com/aau-network-security/go-domains/api/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *Server) StartMeasurement(ctx context.Context, meta *api.Meta) (*api.StartMeasurementResponse, error) {
	muid, err := s.Store.StartMeasurement(meta.Description, meta.Host)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	resp := &api.StartMeasurementResponse{
		MeasurementId: &api.MeasurementId{
			Id: muid,
		},
	}
	return resp, nil
}

func (s *Server) StopMeasurement(ctx context.Context, muid *api.MeasurementId) (*api.Empty, error) {
	if err := s.Store.StopMeasurement(muid.Id); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &api.Empty{}, nil
}

func (s *Server) StartStage(ctx context.Context, muid *api.MeasurementId) (*api.Empty, error) {
	if err := s.Store.StartStage(muid.Id); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &api.Empty{}, nil
}

func (s *Server) StopStage(ctx context.Context, muid *api.MeasurementId) (*api.Empty, error) {
	if err := s.Store.StopStage(muid.Id); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &api.Empty{}, nil
}
