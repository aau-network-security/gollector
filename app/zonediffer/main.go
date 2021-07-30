package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"github.com/aau-network-security/gollector/api"
	prt "github.com/aau-network-security/gollector/api/proto"
	"github.com/aau-network-security/gollector/app/zonediffer/zone"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc/metadata"
	"io"
	"os"
	"time"
)

// ensures a TLDs file exists, and truncates it in case this run does not resume from a prior run
func prepareTldsFile(fname string, resume bool) error {
	// make sure file exists
	_, err := os.Stat(fname)
	if os.IsNotExist(err) {
		// create file
		f, err := os.Create(fname)
		if err != nil {
			return err
		}
		f.Close()
	} else if err != nil {
		return err
	} else if !resume {
		// file exists, truncate if not resume
		if err := os.Truncate(fname, 0); err != nil {
			return err
		}
	}
	return nil
}

// read a set of TLDs from a file and return it as a map
func readTldsFromFile(fname string) (map[string]interface{}, error) {
	f, err := os.Open(fname)
	if err != nil {
		return nil, errors.Wrap(err, "opening file failed")
	}

	res := make(map[string]interface{})

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		tld := scanner.Text()
		res[tld] = nil
	}

	if err := scanner.Err(); err != nil {
		return nil, errors.Wrap(err, "scanning file failed")
	}

	return res, nil
}

func finishTld(fname, tld string) error {
	f, err := os.OpenFile(fname, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.WriteString(fmt.Sprintf("%s\n", tld)); err != nil {
		return err
	}
	return nil
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

	logLevel, err := zerolog.ParseLevel(conf.LogLevel)
	if err != nil {
		log.Fatal().Msgf("error while parsing log level: %s", err)
	}
	zerolog.SetGlobalLevel(logLevel)

	if err := prepareTldsFile(conf.Resume.FinishedTldsFile, conf.Resume.Enabled); err != nil {
		log.Fatal().Msgf("error while preparing tlds file: %s", err)
	}
	ignoredTlds, err := readTldsFromFile(conf.Resume.FinishedTldsFile)
	if err != nil {
		log.Fatal().Msgf("error while reading file of ignored TLDs: %s")
	}

	cc, err := conf.ApiAddr.Dial()
	if err != nil {
		log.Fatal().Msgf("failed to dial: %s", err)
	}

	log.Debug().Msgf("starting measurement")
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

	log.Debug().Msgf("creating buffered stream")
	bs, err := api.NewBufferedStream(str, &tmpl, opts)
	if err != nil {
		log.Fatal().Msgf("failed to create buffered stream to api: %s", err)
	}

	log.Info().Msgf("considering zone files between '%s' and '%s", conf.Start.String(), conf.End.String())

	log.Debug().Msgf("creating zone file provider")
	zfp, err := zone.NewZonefileProvider(conf.InputDir, conf.Start, conf.End)
	if err != nil {
		log.Fatal().Msgf("error while creating zone file provider: %s", err)
	}

	tldCount := len(zfp.Tlds())
	for tldIdx, tld := range zfp.Tlds() {
		if _, ok := ignoredTlds[tld]; ok {
			log.Debug().Msgf("ignoring tld '%s'", tld)

			log.Debug().
				Str("tld", tld).
				Str("progress", fmt.Sprintf("%d/%d", tldIdx+1, tldCount)).
				Msgf("done")
			continue
		}

		prevDomains := make(map[string]interface{})
		curDomains := make(map[string]interface{})

		fileCount := zfp.Count(tld)
		fileIdx := 0
		for {
			zf, err := zfp.Next(tld)
			if err == io.EOF {
				break
			} else if err != nil {
				log.Error().Str("tld", tld).Msgf("error while getting next zone file: %s", err)
				break
			}

			for {
				zfe, err := zf.Next()
				if err == io.EOF {
					break
				} else if err != nil {
					log.Error().Str("file", zf.Name()).Msgf("error while getting next zone file entry: %s", err)
					break
				}
				// using a map also ensures that duplicate domains are only counted once
				curDomains[zfe.Domain] = nil
			}
			log.Debug().
				Str("file", zf.Name()).
				Str("progress", fmt.Sprintf("%d/%d", fileIdx+1, fileCount)).
				Msgf("done")

			// skip first file of each TLD, as there is not comparison material
			if fileIdx == 0 {
				for domain := range curDomains {
					entry := prt.ZoneEntry{
						Apex:      domain,
						Timestamp: zf.Timestamp().UnixNano() / 1e06,
						Type:      prt.ZoneEntry_FIRST_SEEN,
					}
					if err := bs.Send(ctx, &entry); err != nil {
						log.Warn().Msgf("failed to send entry to backend: %s", err)
					}
				}
				log.Debug().Msgf("first seen: %d", len(curDomains))

				prevDomains = curDomains
				curDomains = make(map[string]interface{})
				fileIdx++
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
					Apex:      domain,
					Timestamp: zf.Timestamp().UnixNano() / 1e06,
					Type:      prt.ZoneEntry_EXPIRATION,
				}
				if err := bs.Send(ctx, &entry); err != nil {
					log.Warn().Msgf("failed to send entry to backend: %s", err)
				}
			}

			for _, domain := range registered {
				entry := prt.ZoneEntry{
					Apex:      domain,
					Timestamp: zf.Timestamp().UnixNano() / 1e06,
					Type:      prt.ZoneEntry_REGISTRATION,
				}
				if err := bs.Send(ctx, &entry); err != nil {
					log.Warn().Msgf("failed to send entry to backend: %s", err)
				}
			}

			prevDomains = curDomains
			curDomains = make(map[string]interface{})

			fileIdx++
		}

		if err := finishTld(conf.Resume.FinishedTldsFile, tld); err != nil {
			log.Warn().Msgf("failed to write finished tld to file: %s", err)
		}

		log.Debug().
			Str("tld", tld).
			Str("progress", fmt.Sprintf("%d/%d", tldIdx+1, tldCount)).
			Msgf("done")
	}

	if err := bs.CloseSend(ctx); err != nil {
		log.Fatal().Msgf("error while closing connection to server: %s", err)
	}
}
