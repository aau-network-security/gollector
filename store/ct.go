package store

import (
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/aau-network-security/gollector/collectors/ct"
	"github.com/aau-network-security/gollector/store/models"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/pkg/errors"
)

func (s *Store) getLogFromCacheOrDB(log ct.Log) (*models.Log, error) {
	//Check if it is in the cache
	lI, ok := s.cache.logByUrl.Get(log.Url)
	if !ok {
		if s.cache.logByUrl.Len() < s.cacheOpts.LogSize {
			return nil, errors.New("skip query to the DB cause cache not full")
		}
		var log models.Log
		if err := s.db.Model(&log).Where("url = ?", log.Url).First(); err != nil {
			return nil, err
		}
		return &log, nil //It is in DB
	}
	res := lI.(*models.Log)
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

func (s *Store) getCertFromCacheOrDB(fp string) (*models.Certificate, error) {
	//Check if it is in the cache
	certI, ok := s.cache.certByFingerprint.Get(fp)
	if !ok {
		if s.cache.certByFingerprint.Len() < s.cacheOpts.CertSize {
			return nil, errors.New("skip query to the DB cause cache not full")
		}
		var cert models.Certificate
		if err := s.db.Model(&cert).Where("sha256_fingerprint = ?", fp).First(); err != nil {
			s.Counter.certNew++
			return nil, err
		}
		s.Counter.certDBHit++
		return &cert, nil //It is in DB
	}
	s.Counter.certCacheHit++
	res := certI.(*models.Certificate)
	return res, nil //It is in Cache
}

func (s *Store) getOrCreateCertificate(c *x509.Certificate) (*models.Certificate, error) {
	fp := fmt.Sprintf("%x", sha256.Sum256(c.Raw))

	cert, err := s.getCertFromCacheOrDB(fp)
	if err != nil { // It is not in cache or DB
		cert := &models.Certificate{
			ID:                s.ids.certs,
			Sha256Fingerprint: fp,
		}

		// create an association between FQDNs in database and the newly created certificate
		for _, d := range c.DNSNames {
			domain, err := NewDomain(d)
			if err != nil {
				return nil, err
			}

			fqdn, err := s.getOrCreateFqdn(domain)
			if err != nil {
				return nil, err
			}
			ctof := models.CertificateToFqdn{
				CertificateID: cert.ID,
				FqdnID:        fqdn.ID,
			}
			s.inserts.certToFqdns = append(s.inserts.certToFqdns, &ctof)
		}

		s.inserts.certs = append(s.inserts.certs, cert)
		s.cache.certByFingerprint.Add(fp, cert)
		s.ids.certs++
		return cert, nil
	}
	return cert, nil
}

type LogEntry struct {
	Cert      *x509.Certificate
	IsPrecert bool
	Index     uint
	Ts        time.Time
	Log       ct.Log
}

func (s *Store) StoreLogEntry(muid string, entry LogEntry) error {
	s.m.Lock()
	defer s.m.Unlock()

	s.ensureReady()

	sid, ok := s.ms.SId(muid)
	if !ok {
		return NoActiveStageErr
	}

	l, err := s.getOrCreateLog(entry.Log)
	if err != nil {
		return err
	}

	cert, err := s.getOrCreateCertificate(entry.Cert)
	if err != nil {
		return err
	}

	le := models.LogEntry{
		LogID:         l.ID,
		Index:         entry.Index,
		CertificateID: cert.ID,
		Timestamp:     entry.Ts,
		StageID:       sid,
		IsPrecert:     entry.IsPrecert,
	}

	s.inserts.logEntries = append(s.inserts.logEntries, &le)

	return s.conditionalPostHooks()
}
