package store

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/aau-network-security/gollector/store/models"
	"github.com/go-pg/pg"
)

type domainstruct struct {
	obj    interface{}
	domain *domain
}

type certstruct struct {
	cert  *models.Certificate
	entry LogEntry
	sid   uint
}

var cacheNotFound = errors.New("not found in the cache")

type zoneentrystruct struct {
	ze  *models.ZonefileEntry
	t   time.Time
	sid uint
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
	zoneEntryByApex        map[string]*zoneentrystruct
}

// used to determine if the batch is full, which depends on the number of zone entries or the number of log entries (measured by certs)
func (be *BatchEntities) IsFull() bool {
	return be.Len() >= be.size
}

func (be *BatchEntities) Len() int {
	return len(be.zoneEntryByApex) + len(be.certByFingerprint)
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
	be.zoneEntryByApex = map[string]*zoneentrystruct{}
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
			domain: domain,
		}
		s.batchEntities.apexByName[domain.apex.normal] = &domainstruct{
			domain: domain,
		}
		s.batchEntities.publicSuffixByName[domain.publicSuffix.normal] = &domainstruct{
			domain: domain,
		}
		s.batchEntities.tldByName[domain.tld.normal] = &domainstruct{
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

// collect ids for all observed FQDNs in the batch, either from the cache or the database
func (s *Store) backpropFqdn() error {
	if len(s.batchEntities.fqdnByName) == 0 {
		return nil
	}

	// fetch ids from cache
	var fqndNotFoundInCache []string
	for k := range s.batchEntities.fqdnByName {
		fqdnI, ok := s.cache.fqdnByName.Get(k)
		if !ok {
			fqndNotFoundInCache = append(fqndNotFoundInCache, k)
			continue
		}
		s.influxService.StoreHit("cache-hit", "fqdn", 1)
		fqdn := fqdnI.(*models.Fqdn)
		existing := s.batchEntities.fqdnByName[k]
		existing.obj = fqdn
		s.batchEntities.fqdnByName[k] = existing
	}

	// the cache is not full yet, so the remaining (cache-miss) fqdns cannot be in the database
	if s.cache.fqdnByName.Len() < s.cacheOpts.FQDNSize {
		return nil
	}

	// all entities have been found in the cache, no need to perform a database queries
	if len(fqndNotFoundInCache) == 0 {
		return nil
	}

	// fetch ids from database
	var fqdnFoundInDB []*models.Fqdn
	if err := s.db.Model(&fqdnFoundInDB).Where("fqdn in (?)", pg.In(fqndNotFoundInCache)).Select(); err != nil {
		return err
	}

	for _, f := range fqdnFoundInDB {
		existing := s.batchEntities.fqdnByName[f.Fqdn]
		existing.obj = f
		s.batchEntities.fqdnByName[f.Fqdn] = existing
		s.cache.fqdnByName.Add(f.Fqdn, f)
	}
	s.influxService.StoreHit("db-hit", "fqdn", len(fqdnFoundInDB))
	return nil
}

// collect ids for all observed apexes in the batch, either from the cache or the database
func (s *Store) backpropApex() error {
	if len(s.batchEntities.apexByName) == 0 {
		return nil
	}

	// fetch ids from cache
	var apexNotFoundInCache []string
	for k := range s.batchEntities.apexByName {
		apexI, ok := s.cache.apexByName.Get(k)
		if !ok {
			apexNotFoundInCache = append(apexNotFoundInCache, k)
			continue
		}
		s.influxService.StoreHit("cache-hit", "apex", 1)
		apex := apexI.(*models.Apex)
		existing := s.batchEntities.apexByName[k]
		existing.obj = apex
		s.batchEntities.apexByName[k] = existing
	}

	// the cache is not full yet, so the remaining (cache-miss) apexes cannot be in the database
	if s.cache.apexByName.Len() < s.cacheOpts.ApexSize {
		return nil
	}

	// all entities have been found in the cache, no need to perform a database queries
	if len(apexNotFoundInCache) == 0 {
		return nil
	}

	// fetch ids from database
	var apexFoundInDB []*models.Apex
	if err := s.db.Model(&apexFoundInDB).Where("apex in (?)", pg.In(apexNotFoundInCache)).Select(); err != nil {
		return err
	}

	for _, a := range apexFoundInDB {
		existing := s.batchEntities.apexByName[a.Apex]
		existing.obj = a
		s.batchEntities.apexByName[a.Apex] = existing
		s.cache.apexByName.Add(a.Apex, a)
	}
	s.influxService.StoreHit("db-hit", "apex", len(apexFoundInDB))
	return nil
}

// collect ids for all observed public suffixes in the batch, either from the cache or the database
func (s *Store) backpropPublicSuffix() error {
	if len(s.batchEntities.publicSuffixByName) == 0 {
		return nil
	}

	// fetch ids from cache
	var psNotFoundInCache []string
	for k := range s.batchEntities.publicSuffixByName {
		psI, ok := s.cache.publicSuffixByName.Get(k)
		if !ok {
			psNotFoundInCache = append(psNotFoundInCache, k)
			continue
		}
		s.influxService.StoreHit("cache-hit", "public-suffix", 1)
		ps := psI.(*models.PublicSuffix)
		existing := s.batchEntities.publicSuffixByName[k]
		existing.obj = ps
		s.batchEntities.publicSuffixByName[k] = existing
	}

	// the cache is not full yet, so the remaining (cache-miss) public suffixes cannot be in the database
	if s.cache.publicSuffixByName.Len() < s.cacheOpts.PSuffSize {
		return nil
	}

	// all entities have been found in the cache, no need to perform a database queries
	if len(psNotFoundInCache) == 0 {
		return nil
	}

	// fetch ids from database
	var psFoundInDB []*models.PublicSuffix
	if err := s.db.Model(&psFoundInDB).Where("public_suffix in (?)", pg.In(psNotFoundInCache)).Select(); err != nil {
		return err
	}

	for _, ps := range psFoundInDB {
		existing := s.batchEntities.publicSuffixByName[ps.PublicSuffix]
		existing.obj = ps
		s.batchEntities.publicSuffixByName[ps.PublicSuffix] = existing
	}
	s.influxService.StoreHit("db-hit", "public-suffix", len(psFoundInDB))
	return nil
}

// collect ids for all observed TLDs in the batch, either from the cache or the database
func (s *Store) backpropTld() error {
	if len(s.batchEntities.tldByName) == 0 {
		return nil
	}

	// fetch ids from cache
	var tldNotFoundInCache []string
	for k := range s.batchEntities.tldByName {
		tldI, ok := s.cache.tldByName.Get(k)
		if !ok {
			tldNotFoundInCache = append(tldNotFoundInCache, k)
			continue
		}
		s.influxService.StoreHit("cache-hit", "tld", 1)
		tld := tldI.(*models.Tld)
		existing := s.batchEntities.tldByName[k]
		existing.obj = tld
		s.batchEntities.tldByName[k] = existing
	}

	// the cache is not full yet, so the remaining (cache-miss) tlds cannot be in the database
	if s.cache.tldByName.Len() < s.cacheOpts.TLDSize {
		return nil
	}

	// all entities have been found in the cache, no need to perform a database queries
	if len(tldNotFoundInCache) == 0 {
		return nil
	}

	// fetch ids from database
	var tldFoundInDB []*models.Tld
	if err := s.db.Model(&tldFoundInDB).Where("tld in (?)", pg.In(tldNotFoundInCache)).Select(); err != nil {
		return err
	}

	for _, tld := range tldFoundInDB {
		existing := s.batchEntities.tldByName[tld.Tld]
		existing.obj = tld
		s.batchEntities.tldByName[tld.Tld] = existing
		s.cache.tldByName.Add(tld.Tld, tld)
	}
	s.influxService.StoreHit("db-hit", "apex", len(tldFoundInDB))
	return nil
}

func (s *Store) forpropTld() {
	for k, str := range s.batchEntities.tldByName {
		if str.obj == nil {
			res := &models.Tld{
				ID:  s.ids.tlds,
				Tld: k,
			}
			s.inserts.tld = append(s.inserts.tld, res)
			str.obj = res
			s.batchEntities.tldByName[k] = str
			s.ids.tlds++
			s.cache.tldByName.Add(k, res)
		}
	}
}

func (s *Store) forpropPublicSuffix() {
	for k, str := range s.batchEntities.publicSuffixByName {
		if str.obj == nil {
			// get TLD name from public suffix object
			tldstr := s.batchEntities.tldByName[str.domain.tld.normal]
			tld := tldstr.obj.(*models.Tld)
			res := &models.PublicSuffix{
				ID:           s.ids.suffixes,
				TldID:        tld.ID,
				PublicSuffix: k,
			}
			str.obj = res
			s.inserts.publicSuffix = append(s.inserts.publicSuffix, res)
			s.batchEntities.publicSuffixByName[k] = str
			s.ids.suffixes++
			s.cache.publicSuffixByName.Add(k, res)
		}
	}
}

func (s *Store) forpropApex() {
	for k, str := range s.batchEntities.apexByName {
		if str.obj == nil {

			// get TLD name from domain object
			tldstr := s.batchEntities.tldByName[str.domain.tld.normal]
			tld := tldstr.obj.(*models.Tld)

			suffixstr := s.batchEntities.publicSuffixByName[str.domain.publicSuffix.normal]
			suffix := suffixstr.obj.(*models.PublicSuffix)

			res := &models.Apex{
				ID:             s.ids.apexes,
				TldID:          tld.ID,
				PublicSuffixID: suffix.ID,
				Apex:           k,
			}
			str.obj = res
			s.inserts.apexes[res.ID] = res
			s.batchEntities.apexByName[k] = str
			s.ids.apexes++
			s.cache.apexByName.Add(k, res)
		}
	}
}

func (s *Store) forpropFqdn() {
	for k, str := range s.batchEntities.fqdnByName {

		if str.obj == nil {
			// get TLD name from domain object
			tldstr := s.batchEntities.tldByName[str.domain.tld.normal]
			tld := tldstr.obj.(*models.Tld)

			suffixstr := s.batchEntities.publicSuffixByName[str.domain.publicSuffix.normal]
			suffix := suffixstr.obj.(*models.PublicSuffix)

			apexstr := s.batchEntities.apexByName[str.domain.apex.normal]
			apex := apexstr.obj.(*models.Apex)

			res := &models.Fqdn{
				ID:             s.ids.fqdns,
				TldID:          tld.ID,
				PublicSuffixID: suffix.ID,
				ApexID:         apex.ID,
				Fqdn:           k,
			}
			str.obj = res
			s.inserts.fqdns = append(s.inserts.fqdns, res)
			s.batchEntities.fqdnByName[k] = str
			s.ids.fqdns++
			s.cache.fqdnByName.Add(k, res)
		}
	}
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
