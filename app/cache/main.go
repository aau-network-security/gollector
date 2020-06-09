package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime"
	"time"

	"github.com/aau-network-security/gollector/api"
	"github.com/aau-network-security/gollector/app"
	"github.com/aau-network-security/gollector/store"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	runtime.SetBlockProfileRate(1)

	go func() {
		http.ListenAndServe(":8881", nil)
	}()
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
		AllowedInterval: 36 * time.Hour,
		BatchSize:       50000,
		CacheSize:       20000,
		TLDChaceSize:    2000,
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

	tags := map[string]string{
		"app": "cache",
	}

	var logger app.ErrLogger
	if conf.Sentry.Enabled {
		hub, err := app.NewSentryHub(conf.Sentry)
		if err != nil {
			log.Fatal().Msgf("failed to create sentry hub: %s", err)
		}
		logger = hub.GetLogger(tags)
	} else {
		logger = app.NewZeroLogger(tags)
	}

	// open output file
	fo, err := os.Create("output/output.txt")
	if err != nil {
		panic(err)
	}
	// close fo on exit and check for its returned error
	defer func() {
		if err := fo.Close(); err != nil {
			panic(err)
		}
	}()

	serv := api.Server{
		Conf:          conf.Api,
		Store:         s,
		Log:           logger,
		BenchmarkFile: fo,
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
