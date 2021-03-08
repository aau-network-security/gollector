package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/aau-network-security/gollector/api"
	prt "github.com/aau-network-security/gollector/api/proto"
	"github.com/aau-network-security/gollector/collectors/ct"
	ct2 "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/vbauerster/mpb/v4"
	"github.com/vbauerster/mpb/v4/decor"
	"google.golang.org/grpc/metadata"
	"os"
	"sync"
	"time"
)

var (
	UnsupportedCertTypeErr = errors.New("provided certificate is not supported")
)

func certFromLogEntry(entry *ct2.LogEntry) (*x509.Certificate, bool, error) {
	var cert *x509.Certificate
	isPrecert := false
	if entry.Precert != nil {
		cert = entry.Precert.TBSCertificate
		isPrecert = true
	} else if entry.X509Cert != nil {
		cert = entry.X509Cert
	} else {
		return nil, false, UnsupportedCertTypeErr
	}
	return cert, isPrecert, nil
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

	cc, err := conf.ApiAddr.Dial()
	if err != nil {
		log.Fatal().Msgf("failed to dial: %s", err)
	}

	mClient := prt.NewMeasurementApiClient(cc)
	ctApiClient := newCTApiClient(cc)

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

	str, err := newStream(ctx, ctApiClient)
	if err != nil {
		log.Fatal().Msgf("failed to create log entry stream: %s", err)
	}

	tmpl := prt.LogEntryBatch{
		LogEntries: []*prt.LogEntry{},
	}

	opts := api.BufferedStreamOpts{
		BatchSize:  1000,
		WindowSize: 10000,
	}

	bs, err := api.NewBufferedStream(str, &tmpl, opts)
	if err != nil {
		log.Fatal().Msgf("failed to create buffered stream to api: %s", err)
	}

	logList, err := ct.AllLogs()
	if err != nil {
		log.Fatal().Msgf("error while retrieving list of existing logs: %s", err)
	}

	logList = logList.Filter(conf.All, conf.Included, conf.Excluded)
	logs := logList.Logs

	wg := sync.WaitGroup{}

	p := mpb.New(mpb.WithWaitGroup(&wg))

	wg.Add(len(logs))
	m := sync.Mutex{}
	progress := 0

	for _, l := range logs {
		go func(l ct.Log) {
			var count int64

			defer func() {
				m.Lock()
				progress++
				log.Info().
					Str("log", l.Name()).
					Str("progress", fmt.Sprintf("%d/%d", progress, len(logs))).
					Msgf("retrieved %d log entries", count)
				m.Unlock()
				wg.Done()
			}()

			startIndexInDb, endIndex, err := ct.IndexByLastEntryDB(ctx, &l, ctApiClient)
			if err != nil {
				log.Warn().Msgf("failed to get the last index from the database: %s", err)
				return
			}
			startIndex := startIndexInDb

			if conf.TimeWindow.Active {
				startTime, err := time.Parse("2006-01-02", conf.TimeWindow.Start)
				if err != nil {
					log.Warn().Msgf("failed to parse the start date: %s", err)
					return
				}

				endTime, err := time.Parse("2006-01-02", conf.TimeWindow.End)
				if err != nil {
					log.Warn().Msgf("failed to parse the end date: %s", err)
					return
				}

				log.Debug().Str("log", l.Name()).Msgf("obtaining start index from time")
				startIndexByDate, err := ct.IndexByDate(ctx, &l, startTime)
				if err != nil {
					log.Warn().Msgf("failed to obtain index from start time: %s", err)
					return
				}

				log.Debug().Str("log", l.Name()).Msgf("obtaining end index from time..")
				endIndexByDate, err := ct.IndexByDate(ctx, &l, endTime)
				if err != nil {
					log.Warn().Msgf("failed to obtain index from start time: %s", err)
					return
				}
				if startIndexByDate == endIndexByDate {
					log.Warn().Msgf("given time window completely falls outside the window of the CT log")
					return
				}

				if startIndexByDate > startIndex {
					startIndex = startIndexByDate
				}

				if endIndexByDate < endIndex {
					endIndex = endIndexByDate
				}
			}

			log.Info().
				Str("log", l.Name()).
				Msgf("start index %d", startIndex)

			totalCount := endIndex - startIndex
			if totalCount < 0 {
				log.Error().Msgf("cannot continue with a negative entry count")
				return
			}
			log.Debug().Str("log", l.Name()).Msgf("scanning %d entries", totalCount)
			bar := p.AddBar(totalCount,
				mpb.PrependDecorators(
					decor.Name(l.Name()),
					decor.CountersNoUnit("%d / %d", decor.WCSyncSpace)),
				mpb.AppendDecorators(
					decor.NewPercentage("% .1f"),
					decor.OnComplete(
						decor.EwmaETA(decor.ET_STYLE_GO, 60, decor.WC{W: 4}), "done",
					)))
			defer bar.Abort(false)

			entryFn := func(entry *ct2.LogEntry) error {
				bar.Increment()

				//cert, isPrecert, err := certFromLogEntry(entry)
				//if err != nil {
				//	return err
				//}
				//
				//var operatedBy []int64
				//for _, ob := range l.OperatedBy {
				//	operatedBy = append(operatedBy, int64(ob))
				//}
				//
				//log := prt.Log{
				//	Description:       l.Description,
				//	Key:               l.Key,
				//	Url:               l.Url,
				//	MaximumMergeDelay: int64(l.MaximumMergeDelay),
				//	OperatedBy:        operatedBy,
				//	DnsApiEndpoint:    l.DnsApiEndpoint,
				//}
				//
				//le := prt.LogEntry{
				//	Certificate: cert.Raw,
				//	Index:       entry.Index,
				//	Timestamp:   int64(entry.Leaf.TimestampedEntry.Timestamp),
				//	Log:         &log,
				//	IsPrecert:   isPrecert,
				//}
				//
				//if err := bs.Send(ctx, &le); err != nil {
				//	return errors.Wrap(err, "error while sending log entry to server")
				//}
				return nil
			}

			opts := ct.Options{
				WorkerCount: conf.WorkerCount,
				StartIndex:  startIndex,
				EndIndex:    endIndex,
			}

			count, err = ct.Scan(ctx, &l, entryFn, opts)
			if err != nil {
				log.Debug().Str("log", l.Name()).Msgf("error while scanning log: %s", l.Url)
			}
		}(l)
	}
	p.Wait()
	if err := bs.CloseSend(ctx); err != nil {
		log.Fatal().Msgf("error while closing connection to server: %s", err)
	}
}
