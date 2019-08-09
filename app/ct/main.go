package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/aau-network-security/go-domains/config"
	"github.com/aau-network-security/go-domains/ct"
	"github.com/aau-network-security/go-domains/store"
	ct2 "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/rs/zerolog/log"
	"net/http"
	"sync"
	"time"
)

func ScanLogFromTime(ctx context.Context, log ct.Log, t time.Time, entryFunc ct.EntryFunc) (int64, error) {
	uri := fmt.Sprintf("https://%s", log.Url)
	hc := http.Client{}
	opts := jsonclient.Options{}
	lc, err := client.New(uri, &hc, opts)
	if err != nil {
		return 0, err
	}
	return ct.ScanFromTime(ctx, lc, t, entryFunc)
}

func main() {
	ctx := context.Background()

	confFile := flag.String("config", "config/config.yml", "location of configuration file")
	flag.Parse()

	conf, err := config.ReadConfig(*confFile)
	if err != nil {
		log.Fatal().Msgf("error while reading configuration: %s", err)
	}

	t, err := time.Parse("2006-01-02", conf.Ct.Time)
	if err != nil {
		log.Fatal().Msgf("failed to parse time from config: %s", err)
	}

	s, err := store.NewStore(conf.Store, store.DefaultOpts)
	if err != nil {
		log.Fatal().Msgf("error while creating store: %s", err)
	}

	logList, err := ct.AllLogs()
	if err != nil {
		log.Fatal().Msgf("error while retrieving list of existing logs: %s", err)
	}

	//logs := logList.Logs // todo: Use this list instead of next line!
	logs := []ct.Log{logList.Logs[0]}

	wg := sync.WaitGroup{}
	wg.Add(len(logs))
	for _, l := range logs {
		go func() {
			defer wg.Done()
			entryFunc := func(entry *ct2.LogEntry) error {
				return s.StoreLogEntry(entry, l)
			}

			count, err := ScanLogFromTime(ctx, l, t, entryFunc)
			if err != nil {
				log.Debug().Msgf("error while retrieving logs: %s", err)
				return
			}
			log.Debug().Msgf("retrieved %d certificates", count)
		}()
	}
	wg.Wait()

	if err := s.RunPostHooks(); err != nil {
		log.Fatal().Msgf("error while running post hooks: %s", err)
	}
}
