package main

import (
	"flag"
	"github.com/aau-network-security/go-domains/generic"
	"github.com/aau-network-security/go-domains/store"
	"github.com/aau-network-security/go-domains/zone"
	"github.com/aau-network-security/go-domains/zone/czds"
	"github.com/aau-network-security/go-domains/zone/ftp"
	"github.com/aau-network-security/go-domains/zone/http"
	"github.com/aau-network-security/go-domains/zone/ssh"
	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"sync"
	"time"
)

type Com struct {
	Ftp ftp.Config `yaml:"ftp"`
	Ssh ssh.Config `yaml:"ssh"`
}

type Dk struct {
	Http http.Config `yaml:"http"`
	Ssh  ssh.Config  `yaml:"ssh"`
}

type Net struct {
	Czds czds.Config `yaml:"czds""`
}

type config struct {
	Com   Com          `yaml:"com"`
	Net   czds.Config  `yaml:"net"`
	Dk    Dk           `yaml:"dk"`
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

		sshDialFunc, err := ssh.DialFunc(conf.Com.Ssh)
		com, err := ftp.New(conf.Com.Ftp, sshDialFunc)
		if err != nil {
			log.Fatal().Msgf("failed to create .com zone retriever: %s", err)
		}

		httpClient, err := ssh.HttpClient(conf.Dk.Ssh)
		dk, err := http.New(conf.Dk.Http, httpClient)
		if err != nil {
			log.Fatal().Msgf("failed to create .dk zone retriever: %s", err)
		}

		domainFunc := func(domain string) error {
			_, err := s.StoreZoneEntry(t, domain)
			return err
		}

		zoneConfigs := []struct {
			zone           zone.Zone
			streamWrappers []zone.StreamWrapper
			streamHandler  zone.StreamHandler
		}{
			{com, []zone.StreamWrapper{zone.GzipWrapper}, zone.ZoneFileHandler},
			//{net, []zone.StreamWrapper{zone.GzipWrapper}, zone.ZoneFileHandler},
			//{dk, nil, zone.ListHandler},
		}
		_, _ = dk, net

		for _, zc := range zoneConfigs {
			go func() {
				wg.Add(1)
				defer wg.Done()

				opts := zone.ProcessOpts{
					DomainFunc:     domainFunc,
					StreamWrappers: zc.streamWrappers,
					StreamHandler:  zc.streamHandler,
				}

				if err := zone.Process(zc.zone, opts); err != nil {
					log.Debug().Msgf("error while processing zone file: %s", err)
				}
			}()
		}

		wg.Wait()
		return nil
	}

	// retrieve all zone files on a daily basis
	if err := generic.Repeat(f, time.Now(), time.Hour*24, -1); err != nil {
		log.Fatal().Msgf("error while retrieving zone files: %s", err)
	}
}
