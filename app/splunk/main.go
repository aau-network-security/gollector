package main

import (
	"flag"
	"github.com/aau-network-security/go-domains/config"
	"github.com/aau-network-security/go-domains/splunk"
	"github.com/aau-network-security/go-domains/store"
	"github.com/pkg/errors"
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

	tags := map[string]string{
		"app": "splunk",
	}
	zl := config.NewZeroLogger(tags)
	el := config.NewErrLogChain(zl)
	if conf.Sentry.Enabled {
		h, err := config.NewSentryHub(conf)
		if err != nil {
			log.Fatal().Msgf("error while creating sentry hub: %s", err)
		}
		sl := h.GetLogger(tags)
		el.Add(sl)
	}

	opts := store.Opts{
		AllowedInterval: 1 * time.Second, // field is unused, so we don't care about its value
		BatchSize:       20000,
	}

	s, err := store.NewStore(conf.Store, opts)
	if err != nil {
		opts := config.LogOptions{
			Msg: "error while creating store",
		}
		el.Log(err, opts)
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
				return errors.Wrap(err, "store passive entry")
			}
		}
		return nil
	}

	if err := splunk.Process(conf.Splunk, entryFn); err != nil {
		opts := config.LogOptions{
			Msg: "error while processing splunk files",
		}
		el.Log(err, opts)
	}

	if err := s.RunPostHooks(); err != nil {
		opts := config.LogOptions{
			Msg: "error while running post hooks",
		}
		el.Log(err, opts)
	}
}
