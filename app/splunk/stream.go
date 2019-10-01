package main

import (
	"context"
	"github.com/aau-network-security/gollector/api"
	prt "github.com/aau-network-security/gollector/api/proto"
	"google.golang.org/grpc"
)

type stream struct {
	str prt.SplunkApi_StorePassiveEntryClient
}

func (s *stream) Send(batch api.Batch) error {
	casted, ok := batch.(*prt.SplunkEntryBatch)
	if !ok {
		return prt.AssertionErr
	}
	return s.str.Send(casted)
}

func (s *stream) Recv() (*prt.Result, error) {
	return s.str.Recv()
}

func (s *stream) CloseSend() error {
	return s.str.CloseSend()
}

func newStream(ctx context.Context, cc *grpc.ClientConn) (api.Stream, error) {
	str, err := prt.NewSplunkApiClient(cc).StorePassiveEntry(ctx)
	if err != nil {
		return nil, err
	}
	s := stream{
		str: str,
	}
	return &s, nil
}
