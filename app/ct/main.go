package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/aau-network-security/go-domains/config"
	"github.com/aau-network-security/go-domains/ct"
	"github.com/aau-network-security/go-domains/store"
	ct2 "github.com/google/certificate-transparency-go"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	"github.com/vbauerster/mpb"
	"github.com/vbauerster/mpb/decor"
	"sync"
	"time"
)

func main() {
	ctx := context.Background()

	confFile := flag.String("config", "config/config.yml", "location of configuration file")
	flag.Parse()

	conf, err := config.ReadConfig(*confFile)
	if err != nil {
		log.Fatal().Msgf("error while reading configuration: %s", err)
	}

	t, err := time.Parse("2006-01-02", conf.Ct.Time)
	if err != nil {
		log.Fatal().Msgf("failed to parse time from config: %s", err)
	}

	opts := store.Opts{
		AllowedInterval: 1 * time.Second, // field is unused, so we don't care about its value
		BatchSize:       50000,
	}

	s, err := store.NewStore(conf.Store, opts)
	if err != nil {
		log.Fatal().Msgf("error while creating store: %s", err)
	}

	logList, err := ct.AllLogs()
	if err != nil {
		log.Fatal().Msgf("error while retrieving list of existing logs: %s", err)
	}

	logs := logList.Logs
	//logs := []ct.Log{logList.Logs[0]}
	//logs := logList.Logs[0:3]

	wg := sync.WaitGroup{}

	p := mpb.New(mpb.WithWaitGroup(&wg))

	wg.Add(len(logs))
	m := sync.Mutex{}
	progress := 0

	for _, l := range logs {
		go func(l ct.Log) {
			defer wg.Done()

			start, end, err := ct.IndexByDate(ctx, &l, t)
			if err != nil {
				m.Lock()
				progress++
				log.Debug().
					Str("log", l.Name()).
					Str("progress", fmt.Sprintf("%d/%d", progress, len(logs))).
					Msgf("error while getting index by date: %s", err)
				m.Unlock()
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

			entryFunc := func(entry *ct2.LogEntry) error {
				err := s.StoreLogEntry(entry, l)
				bar.Increment()
				return errors.Wrap(err, "store log entry")
			}

			opts := ct.Options{
				WorkerCount: conf.Ct.WorkerCount,
				StartIndex:  start,
				EndIndex:    end,
			}

			count, err := ct.Scan(ctx, &l, entryFunc, opts)
			if err != nil {
				log.Warn().
					Str("log", l.Name()).
					Msgf("error while retrieving logs: %s", err)
			}
			m.Lock()
			progress++
			log.Info().
				Str("log", l.Name()).
				Str("progress", fmt.Sprintf("%d/%d", progress, len(logs))).
				Msgf("retrieved %d log entries", count)
			m.Unlock()
		}(l)
	}
	p.Wait()

	if err := s.RunPostHooks(); err != nil {
		log.Fatal().Msgf("error while running post hooks: %s", err)
	}
}
