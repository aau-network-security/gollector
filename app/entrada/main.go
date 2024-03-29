package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/aau-network-security/gollector/api"
	prt "github.com/aau-network-security/gollector/api/proto"
	"github.com/aau-network-security/gollector/collectors/entrada"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc/metadata"
	"os"
	"sync"
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

	if err := conf.isValid(); err != nil {
		log.Fatal().Msgf("invalid entrada configuration: %s", err)
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
		log.Fatal().Msgf("failed to create buffered stream to api: %s", err)
	}

	tmpl := prt.EntradaEntryBatch{
		EntradaEntries: []*prt.EntradaEntry{},
	}
	opts := api.BufferedStreamOpts{
		BatchSize:        1000,
		WindowSize:       10000,
		AcceptedFailures: 10,
	}

	bs, err := api.NewBufferedStream(str, &tmpl, opts)
	if err != nil {
		log.Fatal().Msgf("failed to obtain stream to api: %s", err)
	}

	entryFn := func(fqdn string, minTime time.Time, maxTime time.Time) error {
		tsMin := minTime.UnixNano() / 1e06
		tsMax := maxTime.UnixNano() / 1e06

		ee := prt.EntradaEntry{
			Fqdn:         fqdn,
			MinTimestamp: tsMin,
			MaxTimestamp: tsMax,
		}
		if bs.Send(ctx, &ee); err != nil {
			log.Debug().Msgf("failed to store entry: %s", err)
		}
		return nil
	}

	src := entrada.NewSource(conf.Host, conf.Port)

	startTime, err := time.Parse("2006-01-02", conf.TimeWindow.Start)
	if err != nil {
		log.Fatal().Msgf("failed to parse the start date: %s", err)
	}
	startTimeNano := startTime.Unix()

	endTime, err := time.Parse("2006-01-02", conf.TimeWindow.End)
	if err != nil {
		log.Fatal().Msgf("failed to parse the end date: %s", err)
	}
	endTimeNano := endTime.Unix()

	// do rely on a limit
	if conf.Limit > 0 {
		var offset int64
		if conf.ResumeFromDb {
			offsetObj, err := prt.NewEntradaApiClient(cc).GetOffset(ctx, &prt.Empty{})
			if err != nil {
				log.Fatal().Msgf("error while obtaining offset: %s", err)
			}
			if offsetObj.Offset > 0 {
				log.Info().Msgf("resuming from state in database: offset = %d", offsetObj.Offset)
			}
			offset = offsetObj.Offset
		}
		// pagination
		type entradaEntryStr struct {
			fqdn    string
			minTime time.Time
			maxTime time.Time
		}
		q := make(chan entradaEntryStr)

		wg := sync.WaitGroup{}
		go func() {
			wg.Add(1)
			defer wg.Done()
			for el := range q {
				tsMin := el.minTime.UnixNano() / 1e06
				tsMax := el.maxTime.UnixNano() / 1e06

				ee := prt.EntradaEntry{
					Fqdn:         el.fqdn,
					MinTimestamp: tsMin,
					MaxTimestamp: tsMax,
				}
				if bs.Send(ctx, &ee); err != nil {
					log.Debug().Msgf("failed to store entry: %s", err)
				}
			}
		}()

		entryFn = func(fqdn string, minTime time.Time, maxTime time.Time) error {
			q <- entradaEntryStr{
				fqdn:    fqdn,
				minTime: minTime,
				maxTime: maxTime,
			}
			return nil
		}

		for {
			eopts := entrada.Options{
				Query: fmt.Sprintf("SELECT qname, min(unixtime), max(unixtime) FROM dns.queries WHERE unixtime >= %d AND unixtime < %d GROUP BY qname ORDER BY qname LIMIT %d OFFSET %d", startTimeNano, endTimeNano, conf.Limit, offset),
			}
			log.Debug().Msgf("Querying impala db for %d rows with offset %d", conf.Limit, offset)
			c, err := src.Process(ctx, entryFn, eopts)
			if err != nil {
				log.Fatal().Msgf("error while processing impala source: %s", err)
			}
			offset += c
			log.Debug().Msgf("Processed %d entries so far (%d in current page)", offset, c)
			if c < conf.Limit {
				break
			}
		}
		close(q)
		wg.Wait()
	} else {
		eopts := entrada.Options{
			Query: fmt.Sprintf("SELECT qname, min(unixtime), max(unixtime) FROM dns.queries WHERE unixtime >= %d AND unixtime < %d GROUP BY qname"),
		}
		c, err := src.Process(ctx, entryFn, eopts)
		if err != nil {
			log.Fatal().Msgf("error while processing impala source: %s", err)
		}
		log.Debug().Msgf("Processed %d entries", c)
	}

	if err := bs.CloseSend(ctx); err != nil {
		log.Fatal().Msgf("error while closing connection to server: %s", err)
	}
}
