package main

import (
	"os"

	"github.com/aau-network-security/gollector/app/offline/extract_features"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	batchSize := 1
	ef, err := extract_features.NexExtractFeatures(batchSize)
	if err != nil {
		log.Fatal().Msgf("error while creating store: %s", err)
	}

	err = ef.Start()
	if err != nil {
		log.Fatal().Msgf("error while extracting features: %s", err)
	}
}
