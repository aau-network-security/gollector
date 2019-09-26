package main

import (
	"context"
	"flag"
	"fmt"
	api "github.com/aau-network-security/go-domains/api/proto"
	"github.com/aau-network-security/go-domains/collectors/ct"
	ct2 "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	"github.com/vbauerster/mpb"
	"github.com/vbauerster/mpb/decor"
	"golang.org/x/sync/semaphore"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"io"
	"sync"
	"time"
)

var (
	UnsupportedCertTypeErr = errors.New("provided certificate is not supported")
)

func certFromLogEntry(entry *ct2.LogEntry) (*x509.Certificate, error) {
	var cert *x509.Certificate
	if entry.Precert != nil {
		cert = entry.Precert.TBSCertificate
	} else if entry.X509Cert != nil {
		cert = entry.X509Cert
	} else {
		return nil, UnsupportedCertTypeErr
	}
	return cert, nil
}

type bufferedStream struct {
	stream api.CtApi_StoreLogEntriesClient
	size   int
	buffer []*api.LogEntry
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

func (bs *bufferedStream) Send(ctx context.Context, le *api.LogEntry) error {
	bs.l.Lock()
	defer bs.l.Unlock()
	bs.buffer = append(bs.buffer, le)
	if len(bs.buffer) >= bs.size {
		if err := bs.flush(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (bs *bufferedStream) flush(ctx context.Context) error {
	batch := api.LogEntryBatch{
		LogEntries: []*api.LogEntry{},
	}
	if err := bs.sem.Acquire(ctx, int64(len(bs.buffer))); err != nil {
		return err
	}

	for _, se := range bs.buffer {
		batch.LogEntries = append(batch.LogEntries, se)
	}

	if err := bs.stream.Send(&batch); err != nil {
		return err
	}

	bs.buffer = []*api.LogEntry{}

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
	str, err := api.NewCtApiClient(cc).StoreLogEntries(ctx)
	if err != nil {
		return nil, err
	}
	sem := semaphore.NewWeighted(windowSize)

	bs := bufferedStream{
		stream: str,
		size:   batchSize,
		buffer: []*api.LogEntry{},
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

	t, err := time.Parse("2006-01-02", conf.Time)
	if err != nil {
		log.Fatal().Msgf("failed to parse time from config: %s", err)
	}

	// todo: use host/port from config
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
				log.Error().Msgf("error while processing log entry: %s", res.Error)
			}
		}
		bs.done <- true
	}()

	logList, err := ct.AllLogs()
	if err != nil {
		log.Fatal().Msgf("error while retrieving list of existing logs: %s", err)
	}

	//logs := logList.Logs
	logs := []ct.Log{logList.Logs[2]}
	//logs := logList.Logs[0:3]

	wg := sync.WaitGroup{}

	p := mpb.New(mpb.WithWaitGroup(&wg))

	wg.Add(len(logs))
	m := sync.Mutex{}
	progress := 0

	for _, l := range logs {
		go func(l ct.Log) {
			var count int64

			defer func() {
				m.Lock()
				progress++
				log.Info().
					Str("log", l.Name()).
					Str("progress", fmt.Sprintf("%d/%d", progress, len(logs))).
					Msgf("retrieved %d log entries", count)
				m.Unlock()
				wg.Done()
			}()

			start, end, err := ct.IndexByDate(ctx, &l, t)
			if err != nil {
				return
			}

			bar := p.AddBar(end-start,
				mpb.PrependDecorators(
					decor.Name(l.Name()),
					decor.CountersNoUnit("%d / %d", decor.WCSyncSpace)),
				mpb.AppendDecorators(
					decor.NewPercentage("% .1f"),
					decor.OnComplete(
						decor.EwmaETA(decor.ET_STYLE_GO, 60, decor.WC{W: 4}), "done",
					)))
			defer bar.Abort(false)

			entryFn := func(entry *ct2.LogEntry) error {
				bar.Increment()

				cert, err := certFromLogEntry(entry)
				if err != nil {
					return err
				}

				var operatedBy []int64
				for _, ob := range l.OperatedBy {
					operatedBy = append(operatedBy, int64(ob))
				}

				log := api.Log{
					Description:       l.Description,
					Key:               l.Key,
					Url:               l.Url,
					MaximumMergeDelay: int64(l.MaximumMergeDelay),
					OperatedBy:        operatedBy,
					DnsApiEndpoint:    l.DnsApiEndpoint,
				}

				le := api.LogEntry{
					Certificate: cert.Raw,
					Index:       entry.Index,
					Timestamp:   int64(entry.Leaf.TimestampedEntry.Timestamp),
					Log:         &log,
				}

				if err := bs.Send(ctx, &le); err != nil {
					return errors.Wrap(err, "error while sending log entry to server")
				}
				return nil
			}

			opts := ct.Options{
				WorkerCount: conf.WorkerCount,
				StartIndex:  start,
				//EndIndex:    end,
				EndIndex: start + 100,
			}

			count, err = ct.Scan(ctx, &l, entryFn, opts)
			if err != nil {
				log.Debug().Str("log", l.Name()).Msgf("error while scanning log: %s", l.Url)
			}
		}(l)
	}
	p.Wait()

	if err := bs.CloseSend(ctx); err != nil {
		log.Fatal().Msgf("error while closing connection to server: %s", err)
	}
}
