package api

import (
	"context"
	api "github.com/aau-network-security/gollector/api/proto"
	"github.com/mohae/deepcopy"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/semaphore"
	"google.golang.org/grpc/status"
	"io"
	"sync"
)

type Stream interface {
	Send(Batch) error
	Recv() (*api.Result, error)
	CloseSend() error
}

type Batch interface {
	Add(interface{}) error
}

type bufferedStream struct {
	stream   Stream
	size     int
	buffer   []interface{}
	sem      *semaphore.Weighted
	l        sync.Mutex
	done     chan bool
	template Batch
}

func (bs *bufferedStream) recv() (*api.Result, error) {
	res, err := bs.stream.Recv()
	if err == nil {
		bs.sem.Release(1)
	}
	return res, err
}

func (bs *bufferedStream) Send(ctx context.Context, el interface{}) error {
	bs.l.Lock()
	defer bs.l.Unlock()

	if err := bs.sem.Acquire(ctx, 1); err != nil {
		return err
	}
	bs.buffer = append(bs.buffer, el)

	if len(bs.buffer) >= bs.size {
		if err := bs.flush(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (bs *bufferedStream) flush(ctx context.Context) error {
	batch := deepcopy.Copy(bs.template).(Batch)

	for _, el := range bs.buffer {
		if err := batch.Add(el); err != nil {
			return errors.Wrap(err, "add element to batch")
		}
	}

	if err := bs.stream.Send(batch); err != nil {
		return errors.Wrap(err, "send batch over stream")
	}

	bs.buffer = []interface{}{}

	return nil
}

func (bs *bufferedStream) CloseSend(ctx context.Context) error {
	bs.l.Lock()
	defer bs.l.Unlock()
	if err := bs.flush(ctx); err != nil {
		return errors.Wrap(err, "flush buffered stream")
	}

	if err := bs.stream.CloseSend(); err != nil {
		return errors.Wrap(err, "close connection")
	}
	select {
	case <-bs.done:
		break
	case <-ctx.Done():
		break
	}
	return nil
}

type BufferedStreamOpts struct {
	BatchSize  int
	WindowSize int64
}

func NewBufferedStream(str Stream, tmpl Batch, opts BufferedStreamOpts) (*bufferedStream, error) {
	sem := semaphore.NewWeighted(opts.WindowSize)

	bs := bufferedStream{
		stream:   str,
		size:     opts.BatchSize,
		buffer:   []interface{}{},
		sem:      sem,
		l:        sync.Mutex{},
		done:     make(chan bool),
		template: tmpl,
	}

	// asynchronously read messages from stream and output
	go func() {
		for {
			res, err := bs.recv()
			if err == io.EOF {
				break
			}
			if err != nil {
				st := status.Convert(err)
				msg := st.Message()
				log.Error().Msgf("failed to receive message: %s", msg)
				if msg == "transport is closing" {
					break
				}
				continue
			}
			if !res.Ok {
				log.Error().Msgf("error while processing batch entry: %s", res.Error)
			}
		}
		bs.done <- true
	}()

	return &bs, nil
}
