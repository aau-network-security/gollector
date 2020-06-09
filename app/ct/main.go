package main

import (
	"context"
	"flag"
	"fmt"
	"sync"
	"time"

	"github.com/aau-network-security/gollector/api"
	prt "github.com/aau-network-security/gollector/api/proto"
	"github.com/aau-network-security/gollector/collectors/ct"
	ct2 "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	"github.com/vbauerster/mpb/v4"
	"github.com/vbauerster/mpb/v4/decor"
	"google.golang.org/grpc/metadata"
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

	confFile := flag.String("config", "config/config.yml", "location of configuration file")
	flag.Parse()

	conf, err := readConfig(*confFile)
	if err != nil {
		log.Fatal().Msgf("error while reading configuration: %s", err)
	}

	//t, err := time.Parse("2006-01-02", conf.Time)
	//if err != nil {
	//	log.Fatal().Msgf("failed to parse time from config: %s", err)
	//}

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

	//logs := logList.Logs
	logs := []ct.Log{logList.Logs[2]}
	//logs := logList.Logs[0:3]

	wg := sync.WaitGroup{}

	p := mpb.New(mpb.WithWaitGroup(&wg))

	wg.Add(len(logs))
	m := sync.Mutex{}
	progress := 0

	startTime := time.Now()

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

			//start, end, err := ct.IndexByDate(ctx, &l, t)
			//if err != nil {
			//	return
			//}

			start, end, err := ct.IndexByLastEntryDB(ctx, &l, ctApiClient)
			if err != nil {
				return
			}
			log.Info().
				Str("log", l.Name()).
				Msgf("start index %d", start)

			bar := p.AddBar(end-start,
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

				cert, isPrecert, err := certFromLogEntry(entry)
				if err != nil {
					return err
				}

				var operatedBy []int64
				for _, ob := range l.OperatedBy {
					operatedBy = append(operatedBy, int64(ob))
				}

				log := prt.Log{
					Description:       l.Description,
					Key:               l.Key,
					Url:               l.Url,
					MaximumMergeDelay: int64(l.MaximumMergeDelay),
					OperatedBy:        operatedBy,
					DnsApiEndpoint:    l.DnsApiEndpoint,
				}

				le := prt.LogEntry{
					Certificate: cert.Raw,
					Index:       entry.Index,
					Timestamp:   int64(entry.Leaf.TimestampedEntry.Timestamp),
					Log:         &log,
					IsPrecert:   isPrecert,
				}

				if err := bs.Send(ctx, &le); err != nil {
					return errors.Wrap(err, "error while sending log entry to server")
				}
				return nil
			}

			opts := ct.Options{
				WorkerCount: conf.WorkerCount,
				StartIndex:  0,
				//EndIndex:    end,
				//EndIndex: index.Start + 100,
				EndIndex: 100000,
			}

			count, err = ct.Scan(ctx, &l, entryFn, opts)
			if err != nil {
				log.Debug().Str("log", l.Name()).Msgf("error while scanning log: %s", l.Url)
			}
		}(l)
	}
	p.Wait()
	fmt.Println(time.Since(startTime))
	if err := bs.CloseSend(ctx); err != nil {
		log.Fatal().Msgf("error while closing connection to server: %s", err)
	}
}
