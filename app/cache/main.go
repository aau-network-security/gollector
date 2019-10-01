package main

import (
	"flag"
	"fmt"
	"github.com/aau-network-security/go-domains/api"
	"github.com/aau-network-security/go-domains/app"
	"github.com/aau-network-security/go-domains/store"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"net"
	"os"
	"time"
)

func main() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	confFile := flag.String("config", "config/config.yml", "location of configuration file")
	flag.Parse()

	conf, err := readConfig(*confFile)
	if err != nil {
		log.Fatal().Msgf("error while reading configuration: %s", err)
	}

	if err := conf.Sentry.IsValid(); err != nil {
		log.Fatal().Msgf("sentry configuration is invalid: %s", err)
	}

	opts := store.Opts{
		AllowedInterval: 1 * time.Second, // field is unused, so we don't care about its value
		BatchSize:       50000,
	}

	start := time.Now()
	s, err := store.NewStore(conf.Api.Store, opts)
	if err != nil {
		log.Fatal().Msgf("error while creating store: %s", err)
	}

	go func() {
		s.Ready.Wait()

		diff := time.Now().Sub(start)
		log.Info().Msgf("loading store took %s", diff.String())
	}()

	la := store.NewSha256LabelAnonymizer()
	a := store.NewAnonymizer(la)
	s = s.WithAnonymizer(a)

	hub, err := app.NewSentryHub(conf.Sentry)
	if err != nil {
		log.Fatal().Msgf("failed to create sentry hub: %s", err)
	}

	tags := map[string]string{
		"app": "cache",
	}
	logger := hub.GetLogger(tags)

	serv := api.Server{
		Conf:  conf.Api,
		Store: s,
		Log:   logger,
	}

	addr := fmt.Sprintf(":%d", conf.Api.Api.Port)
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal().Msgf("failed to listen on address %s: %s", addr, err)
	}

	if err := serv.Run(lis); err != nil {
		log.Fatal().Msgf("error while running api server: %s", err)
	}
}
