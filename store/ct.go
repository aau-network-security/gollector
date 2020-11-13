package store

import (
	"github.com/aau-network-security/gollector/collectors/ct"
	"github.com/aau-network-security/gollector/store/models"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/pkg/errors"
	"time"
)

var cacheNotFull = errors.New("skip query to the DB cause cache not full")

type LogEntry struct {
	Cert      *x509.Certificate
	IsPrecert bool
	Index     uint
	Ts        time.Time
	Log       ct.Log
}

func (s *Store) getLogFromCacheOrDB(log ct.Log) (*models.Log, error) {
	//Check if it is in the cache
	lI, ok := s.cache.logByUrl.Get(log.Url)
	if !ok {
		if s.cache.logByUrl.Len() < s.cacheOpts.LogSize {
			// to cache
			s.influxService.StoreHit("cache-insert", "log", 1)
			return nil, cacheNotFull
		}
		var log models.Log
		if err := s.db.Model(&log).Where("url = ?", log.Url).First(); err != nil {
			s.influxService.StoreHit("db-insert", "log", 1)
			return nil, err
		}
		s.influxService.StoreHit("db-hit", "log", 1)
		return &log, nil //It is in DB
	}
	res := lI.(*models.Log)
	s.influxService.StoreHit("cache-hit", "log", 1)
	return res, nil //It is in Cache
}

func (s *Store) getOrCreateLog(log ct.Log) (*models.Log, error) {
	l, err := s.getLogFromCacheOrDB(log)
	if err != nil { // It is not in cache or DB
		l := &models.Log{
			ID:          s.ids.logs,
			Url:         log.Url,
			Description: log.Description,
		}
		if err := s.db.Insert(l); err != nil {
			return nil, errors.Wrap(err, "insert log")
		}

		s.cache.logByUrl.Add(log.Url, l)
		s.ids.logs++
		return l, nil
	}
	return l, nil
}
