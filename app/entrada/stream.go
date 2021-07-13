package main

import (
	"context"
	"github.com/aau-network-security/gollector/api"
	prt "github.com/aau-network-security/gollector/api/proto"
	"google.golang.org/grpc"
	"sync"
)

type stream struct {
	m   sync.Mutex
	str prt.EntradaApi_StoreEntradaEntryClient
}

func (s *stream) Send(batch api.Batch) error {
	s.m.Lock()
	defer s.m.Unlock()
	casted, ok := batch.(*prt.EntradaEntryBatch)
	if !ok {
		return prt.AssertionErr
	}
	return s.str.Send(casted)
}

func (s *stream) Recv() (*prt.Result, error) {
	return s.str.Recv()
}

func (s *stream) CloseSend() error {
	s.m.Lock()
	defer s.m.Unlock()
	return s.str.CloseSend()
}

func newStream(ctx context.Context, cc *grpc.ClientConn) (api.Stream, error) {
	str, err := prt.NewEntradaApiClient(cc).StoreEntradaEntry(ctx)
	if err != nil {
		return nil, err
	}
	s := stream{
		m:   sync.Mutex{},
		str: str,
	}
	return &s, nil
}
