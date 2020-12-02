package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/aau-network-security/gollector/api"
	prt "github.com/aau-network-security/gollector/api/proto"
	"github.com/aau-network-security/gollector/app"
	"github.com/aau-network-security/gollector/collectors/zone"
	czds2 "github.com/aau-network-security/gollector/collectors/zone/czds"
	"github.com/aau-network-security/gollector/collectors/zone/ftp"
	"github.com/aau-network-security/gollector/collectors/zone/http"
	"github.com/aau-network-security/gollector/collectors/zone/ssh"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/semaphore"
	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/charmap"
	"google.golang.org/grpc/metadata"
	"net"
	"os"
	"sync"
	"time"
)

type zoneConfig struct {
	zone           zone.Zone
	streamWrappers []zone.StreamWrapper
	streamHandler  zone.StreamHandler
	decoder        *encoding.Decoder
}

// returns the list of tlds that should be retrieved from czds
func getCzdsTlds(client czds2.Client, conf Czds) ([]string, error) {
	tlds := make(map[string]bool)
	if conf.All {
		// add all accessible zones
		all, err := client.DownloadableZones()
		if err != nil {
			return nil, err
		}
		for _, zone := range all {
			tlds[zone] = true
		}
	}

	for _, included := range conf.Included {
		tlds[included] = true
	}

	for _, excluded := range conf.Excluded {
		delete(tlds, excluded)
	}

	var res []string
	for k := range tlds {
		res = append(res, k)
	}

	return res, nil
}

// returns a set of zone configurations based on the config file
func getZoneConfigs(conf config, client czds2.Client) ([]zoneConfig, error) {
	var res []zoneConfig

	if conf.Com.Enabled {
		var sshDialFunc func(network, address string) (net.Conn, error)
		if conf.Com.SshEnabled {
			var err error
			sshDialFunc, err = ssh.DialFunc(conf.Com.Ssh)
			if err != nil {
				return nil, errors.Wrap(err, "failed to create SSH dial func")
			}
		}
		comZone, err := ftp.New(conf.Com.Ftp, sshDialFunc)
		if err != nil {
			return nil, errors.Wrap(err, "failed to create .com zone retriever")
		}
		res = append(res, zoneConfig{
			comZone,
			[]zone.StreamWrapper{zone.GzipWrapper},
			zone.ZoneFileHandler,
			nil,
		})
	}

	if conf.Dk.Enabled {
		httpClient, err := ssh.HttpClient(conf.Dk.Ssh)
		dkZone, err := http.New(conf.Dk.Http, httpClient)
		if err != nil {
			return nil, errors.Wrap(err, "failed to create .dk zone retriever")
		}

		res = append(res, zoneConfig{
			dkZone,
			nil,
			zone.ListHandler,
			charmap.ISO8859_1.NewDecoder(), // must decode Danish domains in zone file
		})
	}

	if conf.Czds.Enabled {
		tlds, err := getCzdsTlds(client, conf.Czds)
		if err != nil {
			log.Fatal().Msgf("failed to obtain czds URLs to process: %s", err)
		}

		for _, tld := range tlds {
			z := czds2.NewFromClient(client, tld)
			zc := zoneConfig{
				z,
				[]zone.StreamWrapper{zone.GzipWrapper},
				zone.ZoneFileHandler,
				nil,
			}

			res = append(res, zc)
		}
	}

	return res, nil
}

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

	if err := conf.Czds.IsValid(); err != nil {
		log.Fatal().Msgf("czds configuration is invalid: %s", err)
	}
	if err := conf.Dk.IsValid(); err != nil {
		log.Fatal().Msgf("dk configuration is invalid: %s", err)
	}
	if err := conf.Com.IsValid(); err != nil {
		log.Fatal().Msgf("com configuration is invalid: %s", err)
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

	interval := 24 * time.Hour
	zfClient := prt.NewZoneFileApiClient(cc)
	in := prt.Interval{
		Interval: int64(interval.Nanoseconds() / 1e06),
	}
	stResp, err := zfClient.GetStartTime(ctx, &in)
	if err != nil {
		log.Fatal().Msgf("failed to acquire starting time: %s", err)
	}

	auth := czds2.NewAuthenticator(conf.Czds.Creds, conf.Czds.AuthBaseUrl)
	client := czds2.NewClient(auth, conf.Czds.ZoneBaseUrl)

	// request access on a daily basis
	ticker := time.NewTicker(24 * time.Hour)
	done := make(chan bool)
	go func() {
		f := func() error {
			return client.RequestAccess(conf.Czds.Reason)
		}
		for {
			if err := app.Retry(f, 2); err != nil {
				log.Warn().Msgf("failed to request access to new zones: %s", err)
			}
			select {
			case <-done:
				return
			case <-ticker.C:
			}
		}
	}()
	defer func() {
		done <- true
	}()

	c := 0
	fn := func(t time.Time) error {
		defer func() {
			c++
		}()
		if c != 0 {
			if _, err := mClient.StartStage(ctx, startResp.MeasurementId); err != nil {
				return err
			}
		}

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

		zoneConfigs, err := getZoneConfigs(conf, client)
		if err != nil {
			log.Fatal().Msgf("failed to obtain zone configs: %s", err)
		}

		log.Info().Msgf("retrieving %d zone files", len(zoneConfigs))

		wg := sync.WaitGroup{}
		zfSem := semaphore.NewWeighted(10) // allow 10 concurrent zone files to be retrieved
		wg.Add(len(zoneConfigs))
		progress := 0

		for _, zc := range zoneConfigs {
			go func(zc zoneConfig) {
				defer wg.Done()
				if err := zfSem.Acquire(ctx, 1); err != nil {
					log.Error().Msgf("failed to acquire semaphore: %s", err)
				}
				defer zfSem.Release(1)

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

					ts := t.UnixNano() / 1e06

					ze := prt.ZoneEntry{
						Timestamp: ts,
						Apex:      string(domain),
					}

					if err := bs.Send(ctx, &ze); err != nil {
						log.Error().Msgf("failed to store domain: %s", err)
					}
					return nil
				}

				opts := zone.ProcessOpts{
					DomainFn:       domainFn,
					StreamWrappers: zc.streamWrappers,
					StreamHandler:  zc.streamHandler,
				}

				retryFn := func() error {
					return zone.Process(zc.zone, opts)
				}
				resultStatus := "ok"
				if err := app.Retry(retryFn, 3); err != nil {
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

		if err := bs.CloseSend(ctx); err != nil {
			log.Debug().Msgf("failed to close stream: %s", err)
		}

		if _, err := mClient.StopStage(ctx, startResp.MeasurementId); err != nil {
			return err
		}

		return nil
	}

	st := app.TimeFromUnix(stResp.Timestamp)
	if conf.Now {
		st = time.Now().Add(-1 * time.Millisecond)
	}

	if err := app.Repeat(fn, st, interval, -1); err != nil {
		log.Fatal().Msgf("error while retrieving zone files: %s", err)
	}
}
