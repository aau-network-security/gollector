package main

import (
	"flag"
	"github.com/aau-network-security/gollector/app/zonediffer/zone"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"io"
	"os"
	"time"
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

	zfp, err := zone.NewZonefileProvider(conf.InputDir)
	if err != nil {
		log.Fatal().Msgf("error while creating zone file provider: %s", err)
	}
	for _, tld := range zfp.Tlds() {
		for {
			zf, err := zfp.Next(tld)
			if err == io.EOF {
				log.Debug().Str("tld", tld).Msgf("done")
				break
			} else if err != nil {
				log.Error().Str("tld", tld).Msgf("error while getting next zone file: %s", err)
				break
			}
			log.Debug().Msgf("file: %s", zf.Name())

			remaining := 10
			for {
				zfe, err := zf.Next()
				if err == io.EOF {
					log.Debug().Str("file", zf.Name()).Msgf("done")
					break
				} else if err != nil {
					log.Error().Str("file", zf.Name()).Msgf("error while getting next zone file entry: %s", err)
					break
				}
				log.Debug().Str("file", zf.Name()).Msgf("%s", zfe.Domain)

				remaining--
				if remaining == 0 {
					break
				}
			}
		}
	}
}
