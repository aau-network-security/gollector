package store

import (
	"github.com/influxdata/influxdb-client-go/v2"
	influxapi "github.com/influxdata/influxdb-client-go/v2/api"
	"io"
	"sync"
	"time"
)

type InfluxService interface {
	StoreHit(status string, insertType string, count int)
	LogCount(logName string)
	io.Closer
}

type influxService struct {
	client    influxdb2.Client
	api       influxapi.WriteAPI
	done      chan bool
	ticker    *time.Ticker
	storeHits map[storeHitTuple]int
	logCounts map[string]int
	m         *sync.Mutex
}

type storeHitTuple struct {
	status     string
	insertType string
}

func (ifs *influxService) StoreHit(status string, insertType string, count int) {
	ifs.m.Lock()
	defer ifs.m.Unlock()

	t := storeHitTuple{status, insertType}
	k, hit := ifs.storeHits[t]
	if !hit {
		k = 0
	}
	k += count

	ifs.storeHits[t] = k
}

func (ifs *influxService) LogCount(logname string) {
	ifs.m.Lock()
	defer ifs.m.Unlock()

	k, hit := ifs.logCounts[logname]
	if !hit {
		k = 0
	}
	k++

	ifs.logCounts[logname] = k
}

func (ifs *influxService) Close() error {

	ifs.done <- true
	ifs.ticker.Stop()

	ifs.client.Close()

	return nil
}

func (ifs *influxService) write() {
	ifs.m.Lock()
	defer ifs.m.Unlock()

	// write store hits
	for tuple, count := range ifs.storeHits {
		tags := map[string]string{
			"status": tuple.status,
			"type":   tuple.insertType,
		}
		fields := map[string]interface{}{
			"count": count,
		}
		p := influxdb2.NewPoint("store-hits", tags, fields, time.Now())
		ifs.api.WritePoint(p)
	}

	// write log counts
	for logName, count := range ifs.logCounts {
		tags := map[string]string{
			"logName": logName,
		}
		fields := map[string]interface{}{
			"count": count,
		}
		p := influxdb2.NewPoint("log-entries", tags, fields, time.Now())
		ifs.api.WritePoint(p)
	}

	ifs.storeHits = map[storeHitTuple]int{}
	ifs.logCounts = map[string]int{}
}

type InfluxOpts struct {
	Enabled      bool   `yaml:"enabled"`
	ServUrl      string `yaml:"server-url"`
	AuthToken    string `yaml:"auth-token"`
	Organisation string `yaml:"organisation"`
	Bucket       string `yaml:"bucket"`
	Interval     int    `yaml:"interval"` // in seconds
}

// service that is being used when influxdb is disabled
type disabledService struct{}

func (ds *disabledService) StoreHit(status string, insertType string, count int) {
	return
}

func (ds *disabledService) LogCount(logName string) {
	return
}

func (ds *disabledService) Close() error {
	return nil
}

func NewInfluxService(opts InfluxOpts) InfluxService {
	if !opts.Enabled {
		return &disabledService{}
	}

	client := influxdb2.NewClient(opts.ServUrl, opts.AuthToken)
	api := client.WriteAPI(opts.Organisation, opts.Bucket)

	return NewInfluxServiceWithClient(client, api, opts.Interval)
}

func NewInfluxServiceWithClient(client influxdb2.Client, api influxapi.WriteAPI, interval int) InfluxService {
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	done := make(chan bool)

	is := influxService{
		client:    client,
		api:       api,
		done:      done,
		storeHits: map[storeHitTuple]int{},
		logCounts: map[string]int{},
		ticker:    ticker,
		m:         &sync.Mutex{},
	}

	go func() {
		// write to influxdb at interval
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				is.write()
			}
		}
	}()

	return &is
}
