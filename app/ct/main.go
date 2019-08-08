package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/aau-network-security/go-domains/config"
	"github.com/aau-network-security/go-domains/ct"
	"github.com/aau-network-security/go-domains/store"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/rs/zerolog/log"
	"net/http"
	"time"
)

func ScanLogFromTime(ctx context.Context, log ct.Log, t time.Time, certFunc ct.CertFunc) error {
	uri := fmt.Sprintf("https://%s", log.Url)
	hc := http.Client{}
	opts := jsonclient.Options{}
	lc, err := client.New(uri, &hc, opts)
	if err != nil {
		return err
	}
	return ct.ScanFromTime(ctx, lc, t, certFunc)
}

func storeCertInDbFunc(s *store.Store) ct.CertFunc {
	return func(cert *x509.Certificate) error {
		// TODO: store certificate in store
		return nil
	}
}

func main() {
	confFile := flag.String("config", "config/config.yml", "location of configuration file")
	flag.Parse()

	conf, err := config.ReadConfig(*confFile)
	if err != nil {
		log.Fatal().Msgf("error while reading configuration: %s", err)
	}

	s, err := store.NewStore(conf.Store, 20000, time.Hour*36)
	if err != nil {
		log.Fatal().Msgf("error while creating store: %s", err)
	}

	logList, err := ct.AllLogs()
	if err != nil {
		log.Fatal().Msgf("error while retrieving list of existing logs: %s", err)
	}

	t := time.Now() // TODO: read from configuration instead
	ctx := context.Background()

	certFunc := storeCertInDbFunc(s)

	for _, l := range logList.Logs {

		if err := ScanLogFromTime(ctx, l, t, certFunc); err != nil {
			log.Debug().Msgf("error while retrieving logs: %s", err)
		}
	}
}
