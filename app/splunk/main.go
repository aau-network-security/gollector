package main

import (
	"context"
	"flag"
	api "github.com/aau-network-security/go-domains/api/proto"
	"github.com/aau-network-security/go-domains/collectors/splunk"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/semaphore"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"io"
	"sync"
)

type bufferedStream struct {
	stream api.SplunkApi_StorePassiveEntryClient
	size   int
	buffer []*api.SplunkEntry
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

func (bs *bufferedStream) Send(ctx context.Context, se *api.SplunkEntry) error {
	bs.l.Lock()
	defer bs.l.Unlock()
	bs.buffer = append(bs.buffer, se)
	if len(bs.buffer) >= bs.size {
		if err := bs.flush(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (bs *bufferedStream) flush(ctx context.Context) error {
	batch := api.SplunkEntryBatch{
		SplunkEntries: []*api.SplunkEntry{},
	}
	if err := bs.sem.Acquire(ctx, int64(len(bs.buffer))); err != nil {
		return err
	}

	for _, ze := range bs.buffer {
		batch.SplunkEntries = append(batch.SplunkEntries, ze)
	}

	if err := bs.stream.Send(&batch); err != nil {
		return err
	}

	bs.buffer = []*api.SplunkEntry{}

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
	str, err := api.NewSplunkApiClient(cc).StorePassiveEntry(ctx)
	if err != nil {
		return nil, err
	}
	sem := semaphore.NewWeighted(windowSize)

	bs := bufferedStream{
		stream: str,
		size:   batchSize,
		buffer: []*api.SplunkEntry{},
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

	cc, err := grpc.Dial("localhost:20000", grpc.WithInsecure())
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
				log.Error().Msgf("error while processing splunk entry: %s", res.Error)
			}
		}
		bs.done <- true
	}()

	entryFn := func(entry splunk.Entry) error {
		for _, qr := range entry.QueryResults() {
			ts := entry.Result.Timestamp.UnixNano() / 1e06

			se := api.SplunkEntry{
				Query:     qr.Query,
				QueryType: qr.QueryType,
				Timestamp: ts,
			}

			if err := bs.Send(ctx, &se); err != nil {
				return errors.Wrap(err, "store passive entry")
			}
		}
		return nil
	}

	if err := splunk.Process(conf.Directory, entryFn); err != nil {
		log.Error().Msgf("error while processing splunk logs: %s", err)
	}

	if err := bs.CloseSend(ctx); err != nil {
		log.Fatal().Msgf("error while closing connection to server: %s", err)
	}
}
