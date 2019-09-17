package main

import (
	"context"
	"flag"
	"github.com/aau-network-security/go-domains/config"
	"github.com/aau-network-security/go-domains/entrada"
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
		BatchSize:       50000,
	}

	s, err := store.NewStore(conf.Store, opts)
	if err != nil {
		log.Fatal().Msgf("error while creating store: %s", err)
	}
	defer func() {
		if err := s.RunPostHooks(); err != nil {
			log.Fatal().Msgf("error while running storepost hooks")
		}
	}()

	if err := s.StartMeasurement(conf.Entrada.Meta.Description, conf.Entrada.Meta.Host); err != nil {
		log.Fatal().Msgf("failed to start measurement: %s", err)
	}

	defer func() {
		if err := s.StopMeasurement(); err != nil {
			log.Fatal().Msgf("error while stopping measurement", err)
		}
	}()

	entryFn := func(fqdn string, t time.Time) error {
		if _, err := s.StorePassiveEntry(fqdn, "", t); err != nil {
			log.Debug().Msgf("failed to store entry: %s", err)
		}
		return nil
	}

	ctx := context.Background()

	src := entrada.NewSource(conf.Entrada.Host, conf.Entrada.Port)
	if err := src.Process(ctx, entryFn, entrada.DefaultOptions); err != nil {
		log.Fatal().Msgf("error while processing impala source: %s", err)
	}
}