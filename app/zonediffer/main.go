package main

import (
	"context"
	"flag"
	"github.com/aau-network-security/gollector/api"
	prt "github.com/aau-network-security/gollector/api/proto"
	"github.com/aau-network-security/gollector/app/zonediffer/zone"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc/metadata"
	"io"
	"os"
	"time"
)

func main() {
	ctx := context.Background()

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

	cc, err := conf.ApiAddr.Dial()
	if err != nil {
		log.Fatal().Msgf("failed to dial: %s", err)
	}

	mClient := prt.NewMeasurementApiClient(cc)
	meta := prt.Meta{
		Description: conf.Meta.Description,
		Host:        conf.Meta.Host,
	}
	startResp, err := mClient.StartMeasurement(ctx, &meta)
	if err != nil {
		log.Fatal().Msgf("failed to start measurement: %s", err)
	}
	muid := startResp.MeasurementId.Id

	defer func() {
		if _, err := mClient.StopMeasurement(ctx, startResp.MeasurementId); err != nil {
			log.Fatal().Msgf("failed to stop measurement: %s", err)
		}
	}()

	// obtain stream to daemon
	md := metadata.New(map[string]string{
		"muid": muid,
	})
	ctx = metadata.NewOutgoingContext(ctx, md)

	str, err := newStream(ctx, cc)
	if err != nil {
		log.Fatal().Msgf("failed to create log entry stream: %s", err)
	}

	tmpl := prt.ZoneEntryBatch{
		ZoneEntries: []*prt.ZoneEntry{},
	}

	opts := api.BufferedStreamOpts{
		BatchSize:  1000,
		WindowSize: 10000,
	}

	bs, err := api.NewBufferedStream(str, &tmpl, opts)
	if err != nil {
		log.Fatal().Msgf("failed to create buffered stream to api: %s", err)
	}

	for _, tld := range zfp.Tlds() {
		prevDomains := make(map[string]interface{})
		curDomains := make(map[string]interface{})

		i := 0
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

			for {
				zfe, err := zf.Next()
				if err == io.EOF {
					log.Debug().Str("file", zf.Name()).Msgf("done")
					break
				} else if err != nil {
					log.Error().Str("file", zf.Name()).Msgf("error while getting next zone file entry: %s", err)
					break
				}
				// using a map also ensures that duplicate domains are only counted once
				curDomains[zfe.Domain] = nil
			}

			//skip first file of each TLD, as there is not comparison material
			if i == 0 {
				prevDomains = curDomains
				curDomains = make(map[string]interface{})
				i++
				continue
			}

			expired, registered := zone.Compare(prevDomains, curDomains)
			if len(expired) > 0 {
				log.Debug().Msgf("expired: %d", len(expired))
			}
			if len(registered) > 0 {
				log.Debug().Msgf("registered: %d", len(registered))
			}

			for _, domain := range expired {
				entry := prt.ZoneEntry{
					Apex:       domain,
					Timestamp:  zf.Timestamp().UnixNano() / 1e06,
					Registered: false,
				}
				if err := bs.Send(ctx, &entry); err != nil {
					log.Warn().Msgf("failed to send entry to backend: %s", err)
				}
			}

			for _, domain := range registered {
				entry := prt.ZoneEntry{
					Apex:       domain,
					Timestamp:  zf.Timestamp().UnixNano() / 1e06,
					Registered: true,
				}
				if err := bs.Send(ctx, &entry); err != nil {
					log.Warn().Msgf("failed to send entry to backend: %s", err)
				}
			}

			prevDomains = curDomains
			curDomains = make(map[string]interface{})

			i++
		}
	}

	if err := bs.CloseSend(ctx); err != nil {
		log.Fatal().Msgf("error while closing connection to server: %s", err)
	}
}
