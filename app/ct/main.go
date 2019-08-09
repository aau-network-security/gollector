package main

import (
	"context"
	"flag"
	"github.com/aau-network-security/go-domains/config"
	"github.com/aau-network-security/go-domains/ct"
	"github.com/aau-network-security/go-domains/store"
	ct2 "github.com/google/certificate-transparency-go"
	"github.com/rs/zerolog/log"
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

	s, err := store.NewStore(conf.Store, store.DefaultOpts)
	if err != nil {
		log.Fatal().Msgf("error while creating store: %s", err)
	}

	logList, err := ct.AllLogs()
	if err != nil {
		log.Fatal().Msgf("error while retrieving list of existing logs: %s", err)
	}

	//logs := logList.Logs
	logs := []ct.Log{logList.Logs[0]}

	wg := sync.WaitGroup{}
	wg.Add(len(logs))
	for _, l := range logs {
		go func(l ct.Log) {
			defer wg.Done()
			entryFunc := func(entry *ct2.LogEntry) error {
				return s.StoreLogEntry(entry, l)
			}

			count, err := ct.ScanFromTime(ctx, l, t, entryFunc)
			if err != nil {
				log.Warn().
					Str("log", l.Url).
					Msgf("error while retrieving logs: %s", err)
				return
			}
			log.Info().
				Str("log", l.Url).
				Msgf("retrieved %d log entries", count)
		}(l)
	}
	wg.Wait()

	if err := s.RunPostHooks(); err != nil {
		log.Fatal().Msgf("error while running post hooks: %s", err)
	}
}
