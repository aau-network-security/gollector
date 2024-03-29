package store

import (
	lru "github.com/hashicorp/golang-lru"
	"github.com/influxdata/influxdb-client-go/v2"
	influxapi "github.com/influxdata/influxdb-client-go/v2/api"
	"io"
	"os"
	"sync"
	"time"
)

type InfluxService interface {
	StoreHit(status string, insertType string, count int)
	LogCount(logName string)
	CacheSize(cacheName string, c *lru.Cache, total int)
	ZoneCount(tld string)
	io.Closer
}

type influxService struct {
	client     influxdb2.Client
	api        influxapi.WriteAPI
	done       chan bool
	ticker     *time.Ticker
	storeHits  map[storeHitTuple]int
	logCounts  map[string]int
	cacheSize  map[string]cacheInfo
	zoneCounts map[string]int
	m          *sync.Mutex
	hostname   string
}

type storeHitTuple struct {
	status     string
	insertType string
}

func (ifs *influxService) StoreHit(status string, insertType string, count int) {
	ifs.m.Lock()
	defer ifs.m.Unlock()

	t := storeHitTuple{status, insertType}
	k, ok := ifs.storeHits[t]
	if !ok {
		k = 0
	}
	k += count

	ifs.storeHits[t] = k
}

func (ifs *influxService) LogCount(logname string) {
	ifs.m.Lock()
	defer ifs.m.Unlock()

	k, ok := ifs.logCounts[logname]
	if !ok {
		k = 0
	}
	k++

	ifs.logCounts[logname] = k
}

func (ifs *influxService) ZoneCount(tld string) {
	ifs.m.Lock()
	defer ifs.m.Unlock()

	k, ok := ifs.zoneCounts[tld]
	if !ok {
		k = 0
	}
	k++

	ifs.zoneCounts[tld] = k
}

type cacheInfo struct {
	cur   int
	total int
}

func (ifs *influxService) CacheSize(cacheName string, c *lru.Cache, total int) {
	ifs.m.Lock()
	defer ifs.m.Unlock()

	ifs.cacheSize[cacheName] = cacheInfo{c.Len(), total}
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

	t := time.Now()

	// write store hits
	for tuple, count := range ifs.storeHits {
		tags := map[string]string{
			"status": tuple.status,
			"type":   tuple.insertType,
			"host":   ifs.hostname,
		}
		fields := map[string]interface{}{
			"count": count,
		}
		p := influxdb2.NewPoint("store-hits", tags, fields, t)
		ifs.api.WritePoint(p)
	}

	// write log counts
	for logName, count := range ifs.logCounts {
		tags := map[string]string{
			"logName": logName,
			"host":    ifs.hostname,
		}
		fields := map[string]interface{}{
			"count": count,
		}
		p := influxdb2.NewPoint("log-entries", tags, fields, t)
		ifs.api.WritePoint(p)
	}

	// write zone counts
	for tld, count := range ifs.zoneCounts {
		tags := map[string]string{
			"tld":  tld,
			"host": ifs.hostname,
		}
		fields := map[string]interface{}{
			"count": count,
		}
		p := influxdb2.NewPoint("zone-entries", tags, fields, t)
		ifs.api.WritePoint(p)
	}

	// write cache sizes
	for cacheName, info := range ifs.cacheSize {
		tags := map[string]string{
			"cacheName": cacheName,
			"host":      ifs.hostname,
		}
		perc := float64(info.cur) / float64(info.total) * float64(100)
		fields := map[string]interface{}{
			"perc":  perc,
			"cur":   info.cur,
			"total": info.total,
		}
		p := influxdb2.NewPoint("cache", tags, fields, t)
		ifs.api.WritePoint(p)
	}

	// reset the counters
	ifs.storeHits = map[storeHitTuple]int{}
	ifs.logCounts = map[string]int{}
	ifs.cacheSize = map[string]cacheInfo{}
	ifs.zoneCounts = map[string]int{}
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

func (ds *disabledService) CacheSize(cacheName string, cache2 *lru.Cache, total int) {
	return
}

func (ds *disabledService) ZoneCount(tld string) {
	return
}

func (ds *disabledService) Close() error {
	return nil
}

func NewInfluxService(opts InfluxOpts) (InfluxService, error) {
	if !opts.Enabled {
		return &disabledService{}, nil
	}

	client := influxdb2.NewClient(opts.ServUrl, opts.AuthToken)
	api := client.WriteAPI(opts.Organisation, opts.Bucket)

	return NewInfluxServiceWithClient(client, api, opts.Interval)
}

func NewInfluxServiceWithClient(client influxdb2.Client, api influxapi.WriteAPI, interval int) (InfluxService, error) {
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	done := make(chan bool)

	hostname, err := os.Hostname()
	if err != nil {
		return nil, err
	}

	is := influxService{
		client:     client,
		api:        api,
		done:       done,
		storeHits:  map[storeHitTuple]int{},
		logCounts:  map[string]int{},
		zoneCounts: map[string]int{},
		cacheSize:  map[string]cacheInfo{},
		ticker:     ticker,
		m:          &sync.Mutex{},
		hostname:   hostname,
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

	return &is, nil
}
