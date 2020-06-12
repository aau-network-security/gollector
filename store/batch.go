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
	domain *domain
}

type certstruct struct {
	cert  *models.Certificate
	entry LogEntry
	sid   uint
}

var cacheNotFound = errors.New("not found in the cache")

type HashMapDB struct {
	tldByName              map[string]*domainstruct
	tldAnonByName          map[string]*domainstruct
	publicSuffixByName     map[string]*domainstruct
	publicSuffixAnonByName map[string]*domainstruct
	apexByName             map[string]*domainstruct
	apexByNameAnon         map[string]*domainstruct
	fqdnByName             map[string]*domainstruct
	fqdnByNameAnon         map[string]*domainstruct
	certByFingerprint      map[string]*certstruct
}

func NewBatchQueryDB() HashMapDB {
	return HashMapDB{
		tldByName:              make(map[string]*domainstruct),
		tldAnonByName:          make(map[string]*domainstruct),
		publicSuffixByName:     make(map[string]*domainstruct),
		publicSuffixAnonByName: make(map[string]*domainstruct),
		apexByName:             make(map[string]*domainstruct),
		apexByNameAnon:         make(map[string]*domainstruct),
		fqdnByName:             make(map[string]*domainstruct),
		fqdnByNameAnon:         make(map[string]*domainstruct),
		certByFingerprint:      make(map[string]*certstruct),
	}
}

func (s *Store) MapEntry(muid string, entry LogEntry) error {
	s.m.Lock()
	defer s.m.Unlock()

	s.ensureReady()

	sid, ok := s.ms.SId(muid)
	if !ok {
		return NoActiveStageErr
	}

	fp := fmt.Sprintf("%x", sha256.Sum256(entry.Cert.Raw))
	s.hashMapDB.certByFingerprint[fp] = &certstruct{
		cert:  nil,
		entry: entry,
		sid:   sid,
	}

	for _, d := range entry.Cert.DNSNames {
		domain, err := NewDomain(d)
		if err != nil {
			return err
		}
		s.hashMapDB.fqdnByName[domain.fqdn.normal] = &domainstruct{
			domain: domain,
		}
		s.hashMapDB.apexByName[domain.apex.normal] = &domainstruct{
			domain: domain,
		}
		s.hashMapDB.publicSuffixByName[domain.publicSuffix.normal] = &domainstruct{
			domain: domain,
		}
		s.hashMapDB.tldByName[domain.tld.normal] = &domainstruct{
			domain: domain,
		}
	}
	return s.conditionalPostHooks()
}

func (s *Store) MapBatchWithCacheAndDB() []error {

	var errs []error
	if err := s.mapCert(); err != nil {
		errs = append(errs, err)
	}
	if err := s.mapFQDN(); err != nil {
		errs = append(errs, err)
	}
	if err := s.mapApex(); err != nil {
		errs = append(errs, err)
	}
	if err := s.mapPublicSuffix(); err != nil {
		errs = append(errs, err)
	}
	if err := s.mapTLD(); err != nil {
		errs = append(errs, err)
	}
	return errs
}

func (s *Store) mapCert() error {

	var certsNotFoundInCache []string
	//map from cache
	for k := range s.hashMapDB.certByFingerprint {
		certI, ok := s.cache.certByFingerprint.Get(k)
		if !ok {
			certsNotFoundInCache = append(certsNotFoundInCache, k)
			continue
		}
		cert := certI.(*models.Certificate)
		existing := s.hashMapDB.certByFingerprint[k]
		existing.cert = cert
		s.hashMapDB.certByFingerprint[k] = existing
	}

	//map with DB
	var certsFoundInDB []*models.Certificate

	if err := s.db.Model(&certsFoundInDB).Where("sha256_fingerprint in (?)", pg.In(certsNotFoundInCache)).Select(); err != nil {
		return err
	}

	for _, c := range certsFoundInDB {
		existing := s.hashMapDB.certByFingerprint[c.Sha256Fingerprint]
		existing.cert = c
		s.hashMapDB.certByFingerprint[c.Sha256Fingerprint] = existing
	}

	return nil
}

func (s *Store) mapFQDN() error {

	var fqndNotFoundInCache []string

	for k := range s.hashMapDB.fqdnByName {
		fqdnI, ok := s.cache.fqdnByName.Get(k)
		if !ok {
			fqndNotFoundInCache = append(fqndNotFoundInCache, k)
			continue
		}
		fqdn := fqdnI.(*models.Fqdn)
		existing := s.hashMapDB.fqdnByName[k]
		existing.obj = fqdn
		s.hashMapDB.fqdnByName[k] = existing
	}

	//map with DB
	var fqdnFoundInDB []*models.Fqdn

	if err := s.db.Model(&fqdnFoundInDB).Where("fqdn in (?)", pg.In(fqndNotFoundInCache)).Select(); err != nil {
		return err
	}

	for _, f := range fqdnFoundInDB {
		existing := s.hashMapDB.fqdnByName[f.Fqdn]
		existing.obj = f
		s.hashMapDB.fqdnByName[f.Fqdn] = existing
	}
	return nil
}

func (s *Store) mapApex() error {

	var apexNotFoundInCache []string

	for k := range s.hashMapDB.apexByName {
		apexI, ok := s.cache.apexByName.Get(k)
		if !ok {
			apexNotFoundInCache = append(apexNotFoundInCache, k)
			continue
		}
		apex := apexI.(*models.Apex)
		existing := s.hashMapDB.fqdnByName[k]
		existing.obj = apex
		s.hashMapDB.apexByName[k] = existing
	}

	//map with DB
	var apexFoundInDB []*models.Apex

	if err := s.db.Model(&apexFoundInDB).Where("apex in (?)", pg.In(apexNotFoundInCache)).Select(); err != nil {
		return err
	}

	for _, a := range apexFoundInDB {
		existing := s.hashMapDB.apexByName[a.Apex]
		existing.obj = a
		s.hashMapDB.apexByName[a.Apex] = existing
	}
	return nil
}

func (s *Store) mapPublicSuffix() error {

	var psNotFoundInCache []string

	for k := range s.hashMapDB.publicSuffixByName {
		psI, ok := s.cache.publicSuffixByName.Get(k)
		if !ok {
			psNotFoundInCache = append(psNotFoundInCache, k)
			continue
		}
		ps := psI.(*models.PublicSuffix)
		existing := s.hashMapDB.publicSuffixByName[k]
		existing.obj = ps
		s.hashMapDB.publicSuffixByName[k] = existing
	}

	//map with DB
	var psFoundInDB []*models.PublicSuffix

	if err := s.db.Model(&psFoundInDB).Where("public_suffix in (?)", pg.In(psNotFoundInCache)).Select(); err != nil {
		return err
	}

	for _, ps := range psFoundInDB {
		existing := s.hashMapDB.publicSuffixByName[ps.PublicSuffix]
		existing.obj = ps
		s.hashMapDB.publicSuffixByName[ps.PublicSuffix] = existing
	}
	return nil
}

func (s *Store) mapTLD() error {

	var tldNotFoundInCache []string

	for k := range s.hashMapDB.tldByName {
		tldI, ok := s.cache.tldByName.Get(k)
		if !ok {
			tldNotFoundInCache = append(tldNotFoundInCache, k)
			continue
		}
		tld := tldI.(*models.Tld)
		existing := s.hashMapDB.tldByName[k]
		existing.obj = tld
		s.hashMapDB.tldByName[k] = existing
	}

	//map with DB
	var tldFoundInDB []*models.Tld

	if err := s.db.Model(&tldFoundInDB).Where("tld in (?)", pg.In(tldNotFoundInCache)).Select(); err != nil {
		return err
	}

	for _, tld := range tldFoundInDB {
		existing := s.hashMapDB.tldByName[tld.Tld]
		existing.obj = tld
		s.hashMapDB.tldByName[tld.Tld] = existing
	}
	return nil
}

func (s *Store) StoreBatchPostHook() error {
	for k, str := range s.hashMapDB.tldByName {
		//tld := str.obj.(*models.Tld)
		if str.obj == nil {
			res := &models.Tld{
				ID:  s.ids.tlds,
				Tld: k,
			}
			s.inserts.tld = append(s.inserts.tld, res)
			str.obj = res
			s.hashMapDB.tldByName[k] = str
			s.ids.tlds++
		}
	}

	for k, str := range s.hashMapDB.publicSuffixByName {
		if str.obj == nil {
			// get TLD name from public suffix object
			tldstr := s.hashMapDB.tldByName[str.domain.tld.normal]
			tld := tldstr.obj.(*models.Tld)
			res := &models.PublicSuffix{
				ID:           s.ids.suffixes,
				TldID:        tld.ID,
				PublicSuffix: k,
			}
			str.obj = res
			s.inserts.publicSuffix = append(s.inserts.publicSuffix, res)
			s.hashMapDB.publicSuffixByName[k] = str
			s.ids.suffixes++
		}
	}

	// apexes
	for k, str := range s.hashMapDB.apexByName {
		if str.obj == nil {
			// get TLD name from domain object
			tldstr := s.hashMapDB.tldByName[str.domain.tld.normal]
			tld := tldstr.obj.(*models.Tld)

			suffixstr := s.hashMapDB.publicSuffixByName[str.domain.publicSuffix.normal]
			suffix := suffixstr.obj.(*models.PublicSuffix)

			res := &models.Apex{
				ID:             s.ids.apexes,
				TldID:          tld.ID,
				PublicSuffixID: suffix.ID,
				Apex:           k,
			}
			str.obj = res
			s.inserts.apexes[res.ID] = res
			s.hashMapDB.apexByName[k] = str
			s.ids.apexes++
		}
	}

	// fqdns
	for k, str := range s.hashMapDB.fqdnByName {
		if str.obj == nil {
			// get TLD name from domain object
			tldstr := s.hashMapDB.tldByName[str.domain.tld.normal]
			tld := tldstr.obj.(*models.Tld)

			suffixstr := s.hashMapDB.publicSuffixByName[str.domain.publicSuffix.normal]
			suffix := suffixstr.obj.(*models.PublicSuffix)

			apexstr := s.hashMapDB.apexByName[str.domain.apex.normal]
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
			s.hashMapDB.fqdnByName[k] = str
			s.ids.fqdns++
		}
	}

	// certificates
	for k, certstr := range s.hashMapDB.certByFingerprint {
		if certstr.cert == nil {
			// get TLD name from domain object
			cert := &models.Certificate{
				ID:                s.ids.certs,
				Sha256Fingerprint: k,
			}

			// create an association between FQDNs in database and the newly created certificate
			for _, d := range certstr.entry.Cert.DNSNames {
				fqdnstr := s.hashMapDB.fqdnByName[d]
				fqdn := fqdnstr.obj.(*models.Fqdn)

				ctof := models.CertificateToFqdn{
					CertificateID: cert.ID,
					FqdnID:        fqdn.ID,
				}
				s.inserts.certToFqdns = append(s.inserts.certToFqdns, &ctof)
			}
			// TODO: do not forget to insert in cache

			certstr.cert = cert
			s.inserts.certs = append(s.inserts.certs, cert)
			s.ids.certs++

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

	// log entries

	//todo return s.conditionalPostHooks()
	return nil
}
