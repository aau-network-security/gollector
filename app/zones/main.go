package main

import (
	"flag"
	"github.com/aau-network-security/go-domains/generic"
	"github.com/aau-network-security/go-domains/store"
	"github.com/aau-network-security/go-domains/zone"
	"github.com/aau-network-security/go-domains/zone/czds"
	"github.com/aau-network-security/go-domains/zone/ftp"
	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"sync"
	"time"
)

type config struct {
	Com   ftp.Config   `yaml:"com"`
	Net   czds.Config  `yaml:"net"`
	Store store.Config `yaml:"store"`
}

func readConfig(path string) (config, error) {
	var conf config
	f, err := ioutil.ReadFile(path)
	if err != nil {
		return conf, err
	}
	if err := yaml.Unmarshal(f, &conf); err != nil {
		return conf, err
	}

	return conf, nil
}

func main() {
	confFile := flag.String("config", "config/config.yml", "location of configuration file")
	flag.Parse()

	conf, err := readConfig(*confFile)
	if err != nil {
		log.Fatal().Msgf("error while reading configuration: %s", err)
	}

	s, err := store.NewStore(conf.Store, time.Hour*36)
	if err != nil {
		log.Fatal().Msgf("error while creating store: %s", err)
	}
	_ = s

	f := func(t time.Time) error {
		wg := sync.WaitGroup{}

		net := czds.New(conf.Net)
		com, err := ftp.New(conf.Com)
		if err != nil {
			log.Fatal().Msgf("failed to create .com zone retriever: %s", err)
		}
		zones := []zone.Zone{com, net}

		domainFunc := func(domain string) error {
			_, err := s.StoreZoneEntry(t, domain)
			return err
		}

		for _, z := range zones {
			go func() {
				wg.Add(1)
				defer wg.Done()

				if err := zone.Process(z, domainFunc); err != nil {
					log.Debug().Msgf("error while processing zone file: %s", err)
				}
			}()
		}

		wg.Wait()
		return nil
	}

	if err := generic.Repeat(f, time.Now(), time.Hour*24, -1); err != nil {
		log.Fatal().Msgf("error while retrieving zone files: %s", err)
	}
}
