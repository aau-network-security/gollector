package main

import (
	"context"
	"flag"
	"fmt"
	api "github.com/aau-network-security/go-domains/api/proto"
	"github.com/aau-network-security/go-domains/app"
	"github.com/aau-network-security/go-domains/collectors/zone"
	"github.com/aau-network-security/go-domains/collectors/zone/czds"
	"github.com/aau-network-security/go-domains/collectors/zone/ftp"
	"github.com/aau-network-security/go-domains/collectors/zone/http"
	"github.com/aau-network-security/go-domains/collectors/zone/ssh"
	"github.com/aau-network-security/go-domains/config"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/semaphore"
	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/charmap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"io"
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

type bufferedStream struct {
	stream api.ZoneFileApi_StoreZoneEntryClient
	size   int
	buffer []*api.ZoneEntry
	sem    *semaphore.Weighted
	l      sync.Mutex
}

func (bs *bufferedStream) Recv() (*api.Result, error) {
	res, err := bs.stream.Recv()
	if err != io.EOF {
		bs.sem.Release(1)
	}
	return res, err
}

func (bs *bufferedStream) Send(ctx context.Context, ze *api.ZoneEntry) error {
	bs.l.Lock()
	defer bs.l.Unlock()
	bs.buffer = append(bs.buffer, ze)
	if len(bs.buffer) >= bs.size {
		batch := api.ZoneEntryBatch{
			ZoneEntries: []*api.ZoneEntry{},
		}

		if err := bs.sem.Acquire(ctx, int64(len(bs.buffer))); err != nil {
			return err
		}

		for _, ze := range bs.buffer {
			batch.ZoneEntries = append(batch.ZoneEntries, ze)
		}

		if err := bs.stream.Send(&batch); err != nil {
			return err
		}

		bs.buffer = []*api.ZoneEntry{}
	}
	return nil
}

func newBufferedStream(ctx context.Context, cc *grpc.ClientConn, batchSize int, windowSize int64) (*bufferedStream, error) {
	str, err := api.NewZoneFileApiClient(cc).StoreZoneEntry(ctx)
	if err != nil {
		return nil, err
	}
	sem := semaphore.NewWeighted(windowSize)

	bs := bufferedStream{
		stream: str,
		size:   batchSize,
		buffer: []*api.ZoneEntry{},
		sem:    sem,
		l:      sync.Mutex{},
	}
	return &bs, nil
}

func main() {
	ctx := context.Background()

	confFile := flag.String("config", "config/config.yml", "location of configuration file")
	flag.Parse()

	conf, err := config.ReadConfig(*confFile)
	if err != nil {
		log.Fatal().Msgf("error while reading configuration: %s", err)
	}

	if err := conf.Zone.Czds.IsValid(); err != nil {
		log.Fatal().Msgf("czds configuration is invalid: %s", err)
	}
	if err := conf.Zone.Dk.IsValid(); err != nil {
		log.Fatal().Msgf("dk configuration is invalid: %s", err)
	}
	if err := conf.Zone.Com.IsValid(); err != nil {
		log.Fatal().Msgf("com configuration is invalid: %s", err)
	}

	interval := 24 * time.Hour

	st, err := zone.GetStartTime(conf.Store, interval)
	if err != nil {
		log.Fatal().Msgf("error while creating gorm database: %s", err)
	}

	// todo: use host/port from config
	cc, err := grpc.Dial("localhost:20000", grpc.WithInsecure())
	if err != nil {
		log.Fatal().Msgf("failed to dial: %s", err)
	}

	mClient := api.NewMeasurementApiClient(cc)

	meta := api.Meta{
		Description: conf.Ct.Meta.Description,
		Host:        conf.Ct.Meta.Host,
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

	var h *config.SentryHub
	if conf.Sentry.Enabled {
		h, err = config.NewSentryHub(conf)
		if err != nil {
			log.Fatal().Msgf("error while creating sentry hub: %s", err)
		}
	}

	authenticator := czds.NewAuthenticator(conf.Zone.Czds.Creds)

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
			"mid": muid,
		})
		ctx = metadata.NewOutgoingContext(ctx, md)

		bs, err := newBufferedStream(ctx, cc, 1000, 10000)
		if err != nil {
			log.Fatal().Msgf("failed to obtain stream to api: %s", err)
		}

		// asynchronously read messages from stream and output
		go func() {
			for {
				res, err := bs.Recv()
				if err == io.EOF {
					return
				}
				if err != nil {
					log.Error().Msgf("failed to receive message: %s", err)
				}
				if !res.Ok {
					log.Error().Msgf("error while processing zone file entry: %s", res.Error)
				}
			}
		}()

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

		_, _ = comZone, dkZone

		zoneConfigs = append([]zoneConfig{
			//{
			//	comZone,
			//	[]zone.StreamWrapper{zone.GzipWrapper},
			//	zone.ZoneFileHandler,
			//	nil,
			//},
			{
				dkZone,
				nil,
				zone.ListHandler,
				charmap.ISO8859_1.NewDecoder(), // must decode Danish domains in zone file
			},
		}, zoneConfigs...)

		zfSem := semaphore.NewWeighted(10) // allow 10 concurrent zone files to be retrieved
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
				if err := zfSem.Acquire(ctx, 1); err != nil {
					el.Log(err, config.LogOptions{Msg: "failed to acquire semaphore"})
					return
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

					ze := api.ZoneEntry{
						Timestamp: ts,
						Apex:      string(domain),
					}

					if err := bs.Send(ctx, &ze); err != nil {
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

		if err := bs.stream.CloseSend(); err != nil {
			log.Debug().Msgf("failed to close stream: %s", err)
		}

		if _, err := mClient.StopStage(ctx, startResp.MeasurementId); err != nil {
			return err
		}

		return nil
	}

	// retrieve all zone files on a daily basis
	if err := app.Repeat(fn, st, interval, -1); err != nil {
		log.Fatal().Msgf("error while retrieving zone files: %s", err)
	}
}
