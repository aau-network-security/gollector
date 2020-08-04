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

func (s *Store) getOrCreateLog(log ct.Log) (*models.Log, error) {
	l, ok := s.cache.logByUrl[log.Url]
	if !ok {
		l = &models.Log{
			ID:          s.ids.logs,
			Url:         log.Url,
			Description: log.Description,
		}
		if err := s.db.Insert(l); err != nil {
			return nil, errors.Wrap(err, "insert log")
		}

		s.cache.logByUrl[log.Url] = l
		s.ids.logs++
	}
	return l, nil
}

func (s *Store) getOrCreateCertificate(c *x509.Certificate) (*models.Certificate, error) {
	fp := fmt.Sprintf("%x", sha256.Sum256(c.Raw))

	cert, ok := s.cache.certByFingerprint[fp]
	if !ok {
		cert = &models.Certificate{
			ID:                s.ids.certs,
			Sha256Fingerprint: fp,
			Raw:               c.Raw,
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
		s.cache.certByFingerprint[fp] = cert
		s.ids.certs++
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
