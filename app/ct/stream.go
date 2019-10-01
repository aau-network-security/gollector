package main

import (
	"context"
	"github.com/aau-network-security/go-domains/api"
	prt "github.com/aau-network-security/go-domains/api/proto"
	"google.golang.org/grpc"
)

type stream struct {
	str prt.CtApi_StoreLogEntriesClient
}

func (s *stream) Send(batch api.Batch) error {
	casted, ok := batch.(*prt.LogEntryBatch)
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
	str, err := prt.NewCtApiClient(cc).StoreLogEntries(ctx)
	if err != nil {
		return nil, err
	}
	s := stream{
		str: str,
	}
	return &s, nil
}
