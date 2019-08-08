package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/aau-network-security/go-domains/config"
	"github.com/aau-network-security/go-domains/generic"
	"github.com/aau-network-security/go-domains/store"
	"github.com/aau-network-security/go-domains/zone"
	"github.com/aau-network-security/go-domains/zone/czds"
	"github.com/aau-network-security/go-domains/zone/ftp"
	"github.com/aau-network-security/go-domains/zone/http"
	"github.com/aau-network-security/go-domains/zone/ssh"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/semaphore"
	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/charmap"
	"net"
	"sync"
	"time"
)

type zoneConfig struct {
	zone           zone.Zone
	streamWrappers []zone.StreamWrapper
	streamHandler  zone.StreamHandler
	decoder        *encoding.Decoder
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

	authenticator := czds.NewAuthenticator(conf.Czds.Creds)
	ctx := context.Background()

	f := func(t time.Time) error {
		wg := sync.WaitGroup{}
		var zoneConfigs []zoneConfig

		for _, tld := range conf.Czds.Tlds {
			z := czds.New(authenticator, tld)
			zc := zoneConfig{
				z,
				[]zone.StreamWrapper{zone.GzipWrapper},
				zone.ZoneFileHandler,
				nil,
			}

			zoneConfigs = append(zoneConfigs, zc)
		}

		var sshDialFunc func(network, address string) (net.Conn, error)
		if conf.Com.SshEnabled {
			sshDialFunc, err = ssh.DialFunc(conf.Com.Ssh)
			if err != nil {
				log.Fatal().Msgf("failed to create SSH dial func: %s", err)
			}
		}
		comZone, err := ftp.New(conf.Com.Ftp, sshDialFunc)
		if err != nil {
			log.Fatal().Msgf("failed to create .com zone retriever: %s", err)
		}

		httpClient, err := ssh.HttpClient(conf.Dk.Ssh)
		dkZone, err := http.New(conf.Dk.Http, httpClient)
		if err != nil {
			log.Fatal().Msgf("failed to create .dk zone retriever: %s", err)
		}

		zoneConfigs = append([]zoneConfig{
			{
				comZone,
				[]zone.StreamWrapper{zone.GzipWrapper},
				zone.ZoneFileHandler,
				nil,
			},
			{
				dkZone,
				nil,
				zone.ListHandler,
				charmap.ISO8859_1.NewDecoder(),
			},
		}, zoneConfigs...)

		sem := semaphore.NewWeighted(10) // allow 10 concurrent zone files to be retrieved
		wg.Add(len(zoneConfigs))
		progress := 0
		for _, zc := range zoneConfigs {
			go func(zc zoneConfig) {
				defer wg.Done()
				if err := sem.Acquire(ctx, 1); err != nil {
					log.Debug().Msgf("failed to acquire semaphore: %s", err)
					return
				}
				defer sem.Release(1)

				c := 0
				domainFunc := func(domain []byte) error {
					c++
					if zc.decoder != nil {
						var err error
						domain, err = zc.decoder.Bytes(domain)
						if err != nil {
							return err
						}
					}

					_, err := s.StoreZoneEntry(t, string(domain))
					if err != nil {
						log.Debug().Msgf("failed to store domain '%s': %s", domain, err)
					}
					c++
					return nil
				}

				opts := zone.ProcessOpts{
					DomainFunc:     domainFunc,
					StreamWrappers: zc.streamWrappers,
					StreamHandler:  zc.streamHandler,
				}

				resultStatus := "ok"
				if err := zone.Process(zc.zone, opts); err != nil {
					log.Error().Msgf("error while processing zone file: %s", err)
					resultStatus = "failed"
				}
				progress++

				log.Info().
					Str("status", resultStatus).
					Str("progress", fmt.Sprintf("%d/%d", progress, len(zoneConfigs))).
					Int("processed domains", c).
					Msgf("finished zone '%s'", zc.zone.Tld())
			}(zc)
		}

		wg.Wait()

		return s.RunPostHooks()
	}

	// retrieve all zone files on a daily basis
	if err := generic.Repeat(f, time.Now(), time.Hour*24, -1); err != nil {
		log.Fatal().Msgf("error while retrieving zone files: %s", err)
	}
}
