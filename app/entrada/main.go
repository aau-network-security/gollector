package main

import (
	"context"
	"flag"
	"fmt"
	api "github.com/aau-network-security/go-domains/api/proto"
	"github.com/aau-network-security/go-domains/collectors/entrada"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/semaphore"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"io"
	"sync"
	"time"
)

type bufferedStream struct {
	stream api.EntradaApi_StoreEntradaEntryClient
	size   int
	buffer []*api.EntradaEntry
	sem    *semaphore.Weighted
	l      sync.Mutex
	done   chan bool
}

func (bs *bufferedStream) Recv() (*api.Result, error) {
	res, err := bs.stream.Recv()
	if err != io.EOF {
		bs.sem.Release(1)
	}
	return res, err
}

func (bs *bufferedStream) Send(ctx context.Context, ee *api.EntradaEntry) error {
	bs.l.Lock()
	defer bs.l.Unlock()
	bs.buffer = append(bs.buffer, ee)
	if len(bs.buffer) >= bs.size {
		if err := bs.flush(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (bs *bufferedStream) flush(ctx context.Context) error {
	batch := api.EntradaEntryBatch{
		EntradaEntries: []*api.EntradaEntry{},
	}
	if err := bs.sem.Acquire(ctx, int64(len(bs.buffer))); err != nil {
		return err
	}

	for _, se := range bs.buffer {
		batch.EntradaEntries = append(batch.EntradaEntries, se)
	}

	if err := bs.stream.Send(&batch); err != nil {
		return err
	}

	bs.buffer = []*api.EntradaEntry{}

	return nil
}

func (bs *bufferedStream) CloseSend(ctx context.Context) error {
	if err := bs.flush(ctx); err != nil {
		return err
	}

	if err := bs.stream.CloseSend(); err != nil {
		return err
	}
	select {
	case <-bs.done:
		break
	case <-ctx.Done():
		break
	}
	return nil
}

func newBufferedStream(ctx context.Context, cc *grpc.ClientConn, batchSize int, windowSize int64) (*bufferedStream, error) {
	str, err := api.NewEntradaApiClient(cc).StoreEntradaEntry(ctx)
	if err != nil {
		return nil, err
	}
	sem := semaphore.NewWeighted(windowSize)

	bs := bufferedStream{
		stream: str,
		size:   batchSize,
		buffer: []*api.EntradaEntry{},
		sem:    sem,
		l:      sync.Mutex{},
		done:   make(chan bool),
	}
	return &bs, nil
}

func main() {
	ctx := context.Background()

	confFile := flag.String("config", "config/config.yml", "location of configuration file")
	flag.Parse()

	conf, err := readConfig(*confFile)
	if err != nil {
		log.Fatal().Msgf("error while reading configuration: %s", err)
	}

	if err := conf.isValid(); err != nil {
		log.Fatal().Msgf("invalid entrada configuration: %s", err)
	}

	cc, err := conf.ApiAddr.Dial()
	if err != nil {
		log.Fatal().Msgf("failed to dial: %s", err)
	}

	mClient := api.NewMeasurementApiClient(cc)

	meta := api.Meta{
		Description: conf.Meta.Description,
		Host:        conf.Meta.Host,
	}
	startResp, err := mClient.StartMeasurement(ctx, &meta)
	if err != nil {
		log.Fatal().Msgf("failed to start measurement: %s", err)
	}
	muid := startResp.MeasurementId.Id

	defer func() {
		if _, err := mClient.StopMeasurement(ctx, startResp.MeasurementId); err != nil {
			log.Fatal().Msgf("failed to stop measurement: %s", err)
		}
	}()

	// obtain stream to daemon
	md := metadata.New(map[string]string{
		"mid": muid,
	})
	ctx = metadata.NewOutgoingContext(ctx, md)

	bs, err := newBufferedStream(ctx, cc, 1000, 10000)
	if err != nil {
		log.Fatal().Msgf("failed to obtain stream to api: %s", err)
	}

	// asynchronously read messages from stream and output
	go func() {
		for {
			res, err := bs.Recv()
			if err == io.EOF {
				break
			}
			if err != nil {
				log.Error().Msgf("failed to receive message: %s", err)
			}
			if !res.Ok {
				log.Error().Msgf("error while processing zone file entry: %s", res.Error)
			}
		}
		bs.done <- true
	}()

	entryFn := func(fqdn string, t time.Time) error {
		ts := t.UnixNano() / 1e06

		ee := api.EntradaEntry{
			Fqdn:      fqdn,
			Timestamp: ts,
		}
		if bs.Send(ctx, &ee); err != nil {
			log.Debug().Msgf("failed to store entry: %s", err)
		}
		return nil
	}

	// todo: remove limit
	src := entrada.NewSource(conf.Host, conf.Port)
	entradaOpts := entrada.Options{
		Query: fmt.Sprintf("SELECT qname, unixtime FROM dns.queries LIMIT %d", 10000),
	}

	if err := src.Process(ctx, entryFn, entradaOpts); err != nil {
		log.Fatal().Msgf("error while processing impala source: %s", err)
	}

	if err := bs.CloseSend(ctx); err != nil {
		log.Fatal().Msgf("error while closing connection to server: %s", err)
	}
}
