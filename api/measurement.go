package api

import (
	"context"
	api "github.com/aau-network-security/go-domains/api/proto"
)

func (s *Server) StartMeasurement(ctx context.Context, meta *api.Meta) (*api.StartMeasurementResponse, error) {
	resp := &api.StartMeasurementResponse{
		Error:         &api.Error{},
		MeasurementId: &api.MeasurementId{},
	}
	mid, err := s.Store.StartMeasurement(meta.Description, meta.Host)
	if err != nil {
		resp.Error.Error = err.Error()
		return resp, nil
	}
	resp.MeasurementId.Id = mid

	return resp, nil
}

func (s *Server) StopMeasurement(ctx context.Context, mid *api.MeasurementId) (*api.Error, error) {
	resp := &api.Error{}
	if err := s.Store.StopMeasurement(mid.Id); err != nil {
		resp.Error = err.Error()
	}
	return resp, nil
}

func (s *Server) NextStage(ctx context.Context, mid *api.MeasurementId) (*api.Error, error) {
	resp := &api.Error{}
	if err := s.Store.NextStage(mid.Id); err != nil {
		resp.Error = err.Error()
	}
	return resp, nil
}
