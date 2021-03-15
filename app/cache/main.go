package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"time"

	"github.com/aau-network-security/gollector/api"
	"github.com/aau-network-security/gollector/app"
	"github.com/aau-network-security/gollector/store"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	log.Logger = log.Output(zerolog.ConsoleWriter{
		Out:        os.Stderr,
		TimeFormat: time.RFC3339,
	})

	confFile := flag.String("config", "config/config.yml", "location of configuration file")
	flag.Parse()

	conf, err := readConfig(*confFile)
	if err != nil {
		log.Fatal().Msgf("error while reading configuration: %s", err)
	}

	logLevel, err := zerolog.ParseLevel(conf.LogLevel)
	if err != nil {
		log.Fatal().Msgf("error while parsing log level: %s", err)
	}
	zerolog.SetGlobalLevel(logLevel)

	if conf.PprofPort > 0 {
		go func() {
			addr := fmt.Sprintf("localhost:%d", conf.PprofPort)
			log.Info().Msgf("running pprof server on [::]:%d", conf.PprofPort)
			if err := http.ListenAndServe(addr, nil); err != nil {
				log.Fatal().Msgf("error while running pprof handler: %s", err)
			}
		}()
	}

	if err := conf.Sentry.IsValid(); err != nil {
		log.Fatal().Msgf("sentry configuration is invalid: %s", err)
	}

	opts := store.Opts{
		AllowedInterval: 36 * time.Hour,
		BatchSize:       conf.StoreOpts.BatchSize,
		CacheOpts: store.CacheOpts{
			LogSize:       conf.StoreOpts.CacheSize.Log,
			TLDSize:       conf.StoreOpts.CacheSize.TLD,
			PSuffSize:     conf.StoreOpts.CacheSize.PSuffix,
			ApexSize:      conf.StoreOpts.CacheSize.Apex,
			FQDNSize:      conf.StoreOpts.CacheSize.Fqdn,
			CertSize:      conf.StoreOpts.CacheSize.Cert,
			ZoneEntrySize: conf.StoreOpts.CacheSize.ZoneEntry,
		},
	}

	log.Debug().Msgf("creating store")
	start := time.Now()
	s, err := store.NewStore(conf.Api.Store, opts)
	if err != nil {
		log.Fatal().Msgf("error while creating store: %s", err)
	}
	log.Debug().Msgf("created store")

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
		logger = app.NewZeroLogger(tags, logLevel)
	}

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
