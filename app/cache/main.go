package main

import (
	"flag"
	"github.com/aau-network-security/go-domains/api"
	"github.com/aau-network-security/go-domains/store"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
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

	opts := store.Opts{
		AllowedInterval: 1 * time.Second, // field is unused, so we don't care about its value
		BatchSize:       50000,
	}

	start := time.Now()
	s, err := store.NewStore(conf.Api.Store, opts)
	if err != nil {
		log.Fatal().Msgf("error while creating store: %s", err)
	}
	diff := time.Now().Sub(start)
	log.Info().Msgf("Loading store took %s", diff.String())

	la := store.NewSha256LabelAnonymizer()
	a := store.NewAnonymizer(la)
	s = s.WithAnonymizer(a)

	serv := api.Server{
		Conf:  conf.Api,
		Store: s,
	}

	if err := serv.Run(); err != nil {
		log.Fatal().Msgf("error while running api server: %s", err)
	}
}
