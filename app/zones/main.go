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
	"github.com/pkg/errors"
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

	if !conf.Zone.Czds.IsValid() {
		log.Fatal().Msgf("czds configuration is invalid")
	}
	if err := conf.Zone.Dk.IsValid(); err != nil {
		log.Fatal().Msgf("dk configuration is invalid: %s", err)
	}
	if err := conf.Zone.Com.IsValid(); err != nil {
		log.Fatal().Msgf("com configuration is invalid: %s", err)
	}

	log.Debug().Msgf("loading store..")
	s, err := store.NewStore(conf.Store, store.DefaultOpts)
	if err != nil {
		log.Fatal().Msgf("error while creating store: %s", err)
	}
	log.Debug().Msgf("loaded store..!")

	interval := 24 * time.Hour

	st, err := zone.GetStartTime(conf.Store, interval)
	if err != nil {
		log.Fatal().Msgf("error while creating gorm database: %s", err)
	}

	if err := s.StartMeasurement(conf.Zone.Meta.Description, conf.Zone.Meta.Host); err != nil {
		log.Fatal().Msgf("failed to start measurement: %s", err)
	}

	defer func() {
		if err := s.StopMeasurement(); err != nil {
			log.Fatal().Msgf("error while stopping measurement", err)
		}
	}()

	var h *config.SentryHub
	if conf.Sentry.Enabled {
		h, err = config.NewSentryHub(conf)
		if err != nil {
			log.Fatal().Msgf("error while creating sentry hub: %s", err)
		}
	}

	authenticator := czds.NewAuthenticator(conf.Zone.Czds.Creds)
	ctx := context.Background()

	c := 0
	fn := func(t time.Time) error {
		defer func() {
			c++
		}()
		if c != 0 {
			if err := s.NextStage(); err != nil {
				log.Fatal().Msgf("error while starting next stage", err)
			}
		}
		wg := sync.WaitGroup{}
		var zoneConfigs []zoneConfig

		for _, tld := range conf.Zone.Czds.Tlds {
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
		if conf.Zone.Com.SshEnabled {
			sshDialFunc, err = ssh.DialFunc(conf.Zone.Com.Ssh)
			if err != nil {
				return errors.Wrap(err, "failed to create SSH dial func")
			}
		}
		comZone, err := ftp.New(conf.Zone.Com.Ftp, sshDialFunc)
		if err != nil {
			return errors.Wrap(err, "failed to create .com zone retriever")
		}

		httpClient, err := ssh.HttpClient(conf.Zone.Dk.Ssh)
		dkZone, err := http.New(conf.Zone.Dk.Http, httpClient)
		if err != nil {
			return errors.Wrap(err, "failed to create .dk zone retriever")
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
			tags := map[string]string{
				"app": "zones",
				"tld": zc.zone.Tld(),
			}
			zl := config.NewZeroLogger(tags)
			el := config.NewErrLogChain(zl)
			if conf.Sentry.Enabled {
				sl := h.GetLogger(tags)
				el.Add(sl)
			}

			go func(el config.ErrLogger, zc zoneConfig) {
				defer wg.Done()
				if err := sem.Acquire(ctx, 1); err != nil {
					el.Log(err, config.LogOptions{Msg: "failed to acquire semaphore"})
					return
				}
				defer sem.Release(1)

				c := 0
				domainFn := func(domain []byte) error {
					c++
					if zc.decoder != nil {
						var err error
						domain, err = zc.decoder.Bytes(domain)
						if err != nil {
							return errors.Wrap(err, "decode domain")
						}
					}

					_, err := s.StoreZoneEntry(t, string(domain))
					if err != nil {
						tags := map[string]string{
							"domain": string(domain),
						}
						el.Log(err, config.LogOptions{
							Tags: tags,
							Msg:  "failed to store domain",
						})
					}
					c++
					return nil
				}

				opts := zone.ProcessOpts{
					DomainFn:       domainFn,
					StreamWrappers: zc.streamWrappers,
					StreamHandler:  zc.streamHandler,
				}

				resultStatus := "ok"
				if err := zone.Process(zc.zone, opts); err != nil {
					el.Log(err, config.LogOptions{Msg: "error while processing zone file"})
					resultStatus = "failed"
				}
				progress++

				log.Info().
					Str("status", resultStatus).
					Str("progress", fmt.Sprintf("%d/%d", progress, len(zoneConfigs))).
					Int("processed domains", c).
					Msgf("finished zone '%s'", zc.zone.Tld())
			}(el, zc)
		}

		wg.Wait()

		return s.RunPostHooks()
	}

	// retrieve all zone files on a daily basis
	if err := generic.Repeat(fn, st, interval, -1); err != nil {
		log.Fatal().Msgf("error while retrieving zone files: %s", err)
	}
}
