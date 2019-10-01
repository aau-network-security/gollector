package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/aau-network-security/go-domains/api"
	prt "github.com/aau-network-security/go-domains/api/proto"
	"github.com/aau-network-security/go-domains/collectors/entrada"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc/metadata"
	"time"
)

func main() {
	ctx := context.Background()

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
		BatchSize:  1000,
		WindowSize: 10000,
	}

	bs, err := api.NewBufferedStream(str, &tmpl, opts)
	if err != nil {
		log.Fatal().Msgf("failed to obtain stream to api: %s", err)
	}

	entryFn := func(fqdn string, t time.Time) error {
		ts := t.UnixNano() / 1e06

		ee := prt.EntradaEntry{
			Fqdn:      fqdn,
			Timestamp: ts,
		}
		if bs.Send(ctx, &ee); err != nil {
			log.Debug().Msgf("failed to store entry: %s", err)
		}
		return nil
	}

	// todo: remove limit
	src := entrada.NewSource(conf.Host, conf.Port)
	entradaOpts := entrada.Options{
		Query: fmt.Sprintf("SELECT qname, unixtime FROM dns.queries LIMIT %d", 10000),
	}

	if err := src.Process(ctx, entryFn, entradaOpts); err != nil {
		log.Fatal().Msgf("error while processing impala source: %s", err)
	}

	if err := bs.CloseSend(ctx); err != nil {
		log.Fatal().Msgf("error while closing connection to server: %s", err)
	}
}
