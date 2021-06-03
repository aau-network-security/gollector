package store

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/aau-network-security/gollector/store/models"
	"github.com/go-pg/pg"
)

type domainstruct struct {
	obj    interface{}
	create bool
	domain *domain
}

type certstruct struct {
	cert  *models.Certificate
	entry LogEntry
	sid   uint
}

var cacheNotFound = errors.New("not found in the cache")

type zoneentrystruct struct {
	ze   *models.ZonefileEntry
	apex string
}

type passiveentrystruct struct {
	pe   *models.PassiveEntry
	fqdn string
}

type entradaentrystruct struct {
	ee   *models.EntradaEntry
	fqdn string
}

type BatchEntities struct {
	size                   int
	tldByName              map[string]*domainstruct
	tldAnonByName          map[string]*domainstruct
	publicSuffixByName     map[string]*domainstruct
	publicSuffixAnonByName map[string]*domainstruct
	apexByName             map[string]*domainstruct
	apexByNameAnon         map[string]*domainstruct
	fqdnByName             map[string]*domainstruct
	fqdnByNameAnon         map[string]*domainstruct
	certByFingerprint      map[string]*certstruct
	zoneEntries            []*zoneentrystruct
	passiveEntries         []*passiveentrystruct
	entradaEntries         []*entradaentrystruct
}

// used to determine if the batch is full, which depends on the number of zone entries or the number of log entries (measured by certs)
func (be *BatchEntities) IsFull() bool {
	return be.Len() >= be.size
}

func (be *BatchEntities) Len() int {
	return len(be.zoneEntries) + len(be.certByFingerprint) + len(be.passiveEntries)
}

func (be *BatchEntities) Reset() {
	be.tldByName = make(map[string]*domainstruct)
	be.tldAnonByName = make(map[string]*domainstruct)
	be.publicSuffixByName = make(map[string]*domainstruct)
	be.publicSuffixAnonByName = make(map[string]*domainstruct)
	be.apexByName = make(map[string]*domainstruct)
	be.apexByNameAnon = make(map[string]*domainstruct)
	be.fqdnByName = make(map[string]*domainstruct)
	be.fqdnByNameAnon = make(map[string]*domainstruct)
	be.certByFingerprint = make(map[string]*certstruct)
	be.zoneEntries = []*zoneentrystruct{}
	be.passiveEntries = []*passiveentrystruct{}
}

func NewBatchEntities(size int) BatchEntities {
	res := BatchEntities{
		size: size,
	}
	res.Reset()
	return res
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
		s.batchEntities.fqdnByName[domain.fqdn.normal] = &domainstruct{
			create: true,
			domain: domain,
		}
		s.batchEntities.apexByName[domain.apex.normal] = &domainstruct{
			create: true,
			domain: domain,
		}
		s.batchEntities.publicSuffixByName[domain.publicSuffix.normal] = &domainstruct{
			create: true,
			domain: domain,
		}
		s.batchEntities.tldByName[domain.tld.normal] = &domainstruct{
			create: true,
			domain: domain,
		}
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
	if err := s.db.Model(&certsFoundInDB).Where("sha256_fingerprint in (?)", pg.In(certsNotFoundInCache)).Select(); err != nil {
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
