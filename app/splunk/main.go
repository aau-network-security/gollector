package main

import (
	"flag"
	"github.com/aau-network-security/go-domains/config"
	"github.com/aau-network-security/go-domains/splunk"
	"github.com/aau-network-security/go-domains/store"
	"github.com/rs/zerolog/log"
	"time"
)

func main() {
	confFile := flag.String("config", "config/config.yml", "location of configuration file")
	flag.Parse()

	conf, err := config.ReadConfig(*confFile)
	if err != nil {
		log.Fatal().Msgf("error while reading configuration: %s", err)
	}

	opts := store.Opts{
		AllowedInterval: 1 * time.Second, // field is unused, so we don't care about its value
		BatchSize:       20000,
	}

	s, err := store.NewStore(conf.Store, opts)
	if err != nil {
		log.Fatal().Msgf("error while creating store: %s", err)
	}

	if err := s.StartMeasurement(conf.Splunk.Meta.Description, conf.Splunk.Meta.Host); err != nil {
		log.Fatal().Msgf("failed to start measurement", err)
	}

	defer func() {
		if err := s.StopMeasurement(); err != nil {
			log.Fatal().Msgf("error while stopping measurement", err)
		}
	}()

	entryFn := func(entry splunk.Entry) error {
		for _, qr := range entry.QueryResults() {
			if _, err := s.StorePassiveEntry(qr.Query, qr.QueryType, entry.Result.Timestamp); err != nil {
				return err
			}
		}
		return nil
	}

	if err := splunk.Process(conf.Splunk, entryFn); err != nil {
		log.Fatal().Msgf("error while processing splunk files: %s", err)
	}

	if err := s.RunPostHooks(); err != nil {
		log.Fatal().Msgf("error while running post hooks: %s", err)
	}
}
