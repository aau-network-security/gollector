package main

import (
	"context"
	"flag"
	"fmt"
	api "github.com/aau-network-security/go-domains/api/proto"
	"github.com/aau-network-security/go-domains/collectors/ct"
	"github.com/aau-network-security/go-domains/config"
	ct2 "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	"github.com/vbauerster/mpb"
	"github.com/vbauerster/mpb/decor"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"sync"
	"time"
)

var (
	UnsupportedCertTypeErr = errors.New("provided certificate is not supported")
)

func certFromLogEntry(entry *ct2.LogEntry) (*x509.Certificate, error) {
	var cert *x509.Certificate
	if entry.Precert != nil {
		cert = entry.Precert.TBSCertificate
		// todo: revert
		//encoded := &bytes.Buffer{}
		//encoder := base64.NewEncoder(base64.StdEncoding, encoded)
		//defer encoder.Close()
		//encoder.Write(cert.Raw)
		//encodedStr := fmt.Sprintf("%s", encoded)
		//_ = encodedStr
	} else if entry.X509Cert != nil {
		cert = entry.X509Cert
	} else {
		return nil, UnsupportedCertTypeErr
	}
	return cert, nil
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

	cc, err := grpc.Dial("localhost:20000", grpc.WithInsecure())
	if err != nil {
		log.Fatal().Msgf("failed to dial: %s", err)
	}

	mClient := api.NewMeasurementApiClient(cc)
	ctClient := api.NewCtApiClient(cc)

	meta := api.Meta{
		Description: conf.Ct.Meta.Description,
		Host:        conf.Ct.Meta.Host,
	}
	startResp, err := mClient.StartMeasurement(ctx, &meta)
	if err != nil {
		log.Fatal().Msgf("failed to start measurement: %s", err)
	}
	if startResp.Error.Error != "" {
		log.Fatal().Msgf("failed to start measurement: %s", startResp.Error.Error)
	}
	mid := startResp.MeasurementId.Id

	defer func() {
		stopResp, err := mClient.StopMeasurement(ctx, startResp.MeasurementId)
		if err != nil {
			log.Fatal().Msgf("failed to stop measurement: %s", err)
		}
		if stopResp.Error != "" {
			log.Fatal().Msgf("failed to stop measurement: %s", err)
		}
	}()

	logList, err := ct.AllLogs()
	if err != nil {
		log.Fatal().Msgf("error while retrieving list of existing logs: %s", err)
	}

	var h *config.SentryHub
	if conf.Sentry.Enabled {
		h, err = config.NewSentryHub(conf)
		if err != nil {
			log.Fatal().Msgf("error while creating sentry hub: %s", err)
		}
	}

	//logs := logList.Logs
	logs := []ct.Log{logList.Logs[2]}
	//logs := logList.Logs[0:3]

	wg := sync.WaitGroup{}

	p := mpb.New(mpb.WithWaitGroup(&wg))

	wg.Add(len(logs))
	m := sync.Mutex{}
	progress := 0

	for _, l := range logs {
		tags := map[string]string{
			"app": "ct",
			"log": l.Name(),
		}
		zl := config.NewZeroLogger(tags)
		el := config.NewErrLogChain(zl)
		if conf.Sentry.Enabled {
			sl := h.GetLogger(tags)
			el.Add(sl)
		}

		go func(el config.ErrLogger, l ct.Log) {
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

			start, end, err := ct.IndexByDate(ctx, &l, t)
			if err != nil {
				opts := config.LogOptions{
					Msg: "error while getting index by date",
				}
				el.Log(err, opts)
				return
			}

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

				cert, err := certFromLogEntry(entry)
				if err != nil {
					return err
				}

				var operatedBy []int64
				for _, ob := range l.OperatedBy {
					operatedBy = append(operatedBy, int64(ob))
				}

				log := api.Log{
					Description:       l.Description,
					Key:               l.Key,
					Url:               l.Url,
					MaximumMergeDelay: int64(l.MaximumMergeDelay),
					OperatedBy:        operatedBy,
					DnsApiEndpoint:    l.DnsApiEndpoint,
				}

				le := api.LogEntry{
					Certificate: cert.Raw,
					Index:       entry.Index,
					Timestamp:   int64(entry.Leaf.TimestampedEntry.Timestamp),
					Log:         &log,
				}

				md := metadata.New(map[string]string{
					"mid": mid,
				})
				ctx := metadata.NewOutgoingContext(ctx, md)
				resp, err := ctClient.StoreLogEntries(ctx, &le)
				if err != nil {
					return errors.Wrap(err, "error while sending log entry to server")
				}
				if resp.Error != "" {
					return errors.New(fmt.Sprintf("failed to store log entry: %s", resp.Error))
				}
				return nil
			}

			errorFn := func(err error) {
				el.Log(err, config.LogOptions{})
			}

			opts := ct.Options{
				WorkerCount: conf.Ct.WorkerCount,
				StartIndex:  start,
				//EndIndex:    end,
				EndIndex: start + 100,
			}

			count, err = ct.Scan(ctx, &l, entryFn, errorFn, opts)
			if err != nil {
				opts := config.LogOptions{
					Msg: "error while retrieving logs",
				}
				el.Log(err, opts)
			}
		}(el, l)
	}
	p.Wait()
}
