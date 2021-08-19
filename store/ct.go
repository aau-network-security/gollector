package store

import (
	"crypto/sha256"
	"fmt"
	"github.com/aau-network-security/gollector/collectors/ct"
	"github.com/aau-network-security/gollector/store/models"
	"github.com/go-pg/pg"
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

func (s *Store) StoreLogEntry(muid string, entry LogEntry) error {
	s.m.Lock()
	defer s.m.Unlock()

	s.ensureReady()

	s.influxService.LogCount(entry.Log.Url)

	sid, ok := s.ms.SId(muid)
	if !ok {
		return NoActiveStageErr
	}

	fp := fmt.Sprintf("%x", sha256.Sum256(entry.Cert.Raw))
	s.batchEntities.certByFingerprint[fp] = &certstruct{
		cert:  nil,
		entry: entry,
		sid:   sid,
	}

	for _, d := range entry.Cert.DNSNames {
		domain, err := NewDomain(d)
		if err != nil {
			continue
		}
		s.anonymizer.Anonymize(domain)

		s.batchEntities.AddFqdn(domain, false)
	}
	return s.conditionalPostHooks()
}

// collect ids for all observed certificates in the batch, either from the cache or the database
func (s *Store) backpropCert() error {
	if len(s.batchEntities.certByFingerprint) == 0 {
		return nil
	}

	// fetch ids from cache
	var certsNotFoundInCache []string
	for k := range s.batchEntities.certByFingerprint {
		certI, ok := s.cache.certByFingerprint.Get(k)
		if !ok {
			certsNotFoundInCache = append(certsNotFoundInCache, k)
			continue
		}
		s.influxService.StoreHit("cache-hit", "cert", 1)
		cert := certI.(*models.Certificate)
		existing := s.batchEntities.certByFingerprint[k]
		existing.cert = cert
		s.batchEntities.certByFingerprint[k] = existing
	}

	// the cache is not full yet, so the remaining (cache-miss) certs cannot be in the database
	if s.cache.certByFingerprint.Len() < s.cacheOpts.CertSize {
		return nil
	}

	// fetch ids from database
	var certsFoundInDB []*models.Certificate
	if err := s.db.Model(&certsFoundInDB).Column("id", "sha256_fingerprint").Where("sha256_fingerprint in (?)", pg.In(certsNotFoundInCache)).Select(); err != nil {
		return err
	}

	for _, c := range certsFoundInDB {
		existing := s.batchEntities.certByFingerprint[c.Sha256Fingerprint]
		existing.cert = c
		s.batchEntities.certByFingerprint[c.Sha256Fingerprint] = existing
		s.cache.certByFingerprint.Add(c.Sha256Fingerprint, c)
	}
	s.influxService.StoreHit("db-hit", "cert", len(certsFoundInDB))

	return nil
}

func (s *Store) forpropCerts() error {
	for k, certstr := range s.batchEntities.certByFingerprint {

		if certstr.cert == nil {
			// get TLD name from domain object
			cert := &models.Certificate{
				ID:                s.ids.certs,
				Sha256Fingerprint: k,
				Raw:               certstr.entry.Cert.Raw,
			}

			// create an association between FQDNs in database and the newly created certificate
			for _, d := range certstr.entry.Cert.DNSNames {
				domain, err := NewDomain(d)
				if err != nil {
					continue
				}
				fqdnstr := s.batchEntities.fqdnByName[domain.fqdn.normal]
				fqdn := fqdnstr.obj.(*models.Fqdn)

				ctof := models.CertificateToFqdn{
					CertificateID: cert.ID,
					FqdnID:        fqdn.ID,
				}
				s.inserts.certToFqdns = append(s.inserts.certToFqdns, &ctof)
				s.ids.certsToFqdn++
			}

			certstr.cert = cert
			s.inserts.certs = append(s.inserts.certs, cert)
			s.ids.certs++
			s.cache.certByFingerprint.Add(k, cert)
		}

		l, err := s.getOrCreateLog(certstr.entry.Log)
		if err != nil {
			return err
		}

		le := models.LogEntry{
			LogID:         l.ID,
			Index:         certstr.entry.Index,
			CertificateID: certstr.cert.ID,
			Timestamp:     certstr.entry.Ts,
			StageID:       certstr.sid,
			IsPrecert:     certstr.entry.IsPrecert,
		}

		s.inserts.logEntries = append(s.inserts.logEntries, &le)
	}
	return nil
}
