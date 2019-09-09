package store

import (
	"crypto/sha256"
	"fmt"
	"github.com/aau-network-security/go-domains/ct"
	"github.com/aau-network-security/go-domains/models"
	ct2 "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/pkg/errors"
	"time"
)

func timeFromLogEntry(entry *ct2.LogEntry) time.Time {
	ts := entry.Leaf.TimestampedEntry.Timestamp
	return time.Unix(int64(ts/1000), int64(ts%1000))
}

func certFromLogEntry(entry *ct2.LogEntry) (*x509.Certificate, error) {
	var cert *x509.Certificate
	if entry.Precert != nil {
		cert = entry.Precert.TBSCertificate
	} else if entry.X509Cert != nil {
		cert = entry.X509Cert
	} else {
		return nil, UnsupportedCertTypeErr
	}
	return cert, nil
}

func (s *Store) getOrCreateLog(log ct.Log) (*models.Log, error) {
	l, ok := s.logByUrl[log.Url]
	if !ok {
		l = &models.Log{
			ID:          s.ids.logs,
			Url:         log.Url,
			Description: log.Description,
		}
		if err := s.db.Insert(l); err != nil {
			return nil, errors.Wrap(err, "insert log")
		}

		s.logByUrl[log.Url] = l
		s.ids.logs++
	}
	return l, nil
}

func (s *Store) getOrCreateCertificate(entry *ct2.LogEntry) (*models.Certificate, error) {
	c, err := certFromLogEntry(entry)
	if err != nil {
		return nil, err
	}

	fp := fmt.Sprintf("%x", sha256.Sum256(c.Raw))

	cert, ok := s.certByFingerprint[fp]
	if !ok {
		cert = &models.Certificate{
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
		s.certByFingerprint[fp] = cert
		s.ids.certs++
	}
	return cert, nil
}

func (s *Store) StoreLogEntry(entry *ct2.LogEntry, log ct.Log) error {
	s.m.Lock()
	defer s.m.Unlock()

	l, err := s.getOrCreateLog(log)
	if err != nil {
		return err
	}

	cert, err := s.getOrCreateCertificate(entry)
	if err != nil {
		return err
	}

	ts := timeFromLogEntry(entry)

	le := models.LogEntry{
		LogID:         l.ID,
		Index:         uint(entry.Index),
		CertificateID: cert.ID,
		Timestamp:     ts,
		StageID:       s.curStage.ID,
	}

	s.inserts.logEntries = append(s.inserts.logEntries, &le)

	return s.conditionalPostHooks()
}
