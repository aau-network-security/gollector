package store

import (
	"crypto/sha256"
	b64 "encoding/base64"
	"fmt"
	"strings"

	"github.com/aau-network-security/gollector/store/models"
	"github.com/rs/zerolog/log"
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

type hashMapDB struct {
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

func NewBatchQueryDB() hashMapDB {
	return hashMapDB{
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
			//log.Debug().Msgf("error creating domain [%s]: %s", d, err)
			continue
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

func (s *Store) MapBatchWithCacheAndDB() {

	s.mapCert()
	s.mapFQDN()
	s.mapApex()
	s.mapPublicSuffix()
	s.mapTLD()
}

func (s *Store) mapCert() {

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
		s.Counter.tldCacheHit++
	}

	// Cache not full so the certificate can not be in the DB
	if s.cache.certByFingerprint.Len() < s.cacheOpts.CertSize {
		return
	}

	//map with DB
	var certsFoundInDB []*models.Certificate
	var id uint
	var sha256Fingerprint string
	var raw string

	q := fmt.Sprintf("SELECT id, sha256_fingerprint, raw FROM certificates WHERE sha256_fingerprint IN %s", "('"+strings.Join(certsNotFoundInCache, "', '")+"')")
	iter := s.db.Query(q).Iter()
	for iter.Scan(&id, &sha256Fingerprint, &raw) {
		certsFoundInDB = append(certsFoundInDB, &models.Certificate{
			ID:                id,
			Sha256Fingerprint: sha256Fingerprint,
			Raw:               raw,
		})
	}
	if err := iter.Close(); err != nil {
		log.Error().Msgf("error retrieve Certificates from DB [mapCert]: %s", err)
	}

	for _, c := range certsFoundInDB {
		existing := s.hashMapDB.certByFingerprint[c.Sha256Fingerprint]
		existing.cert = c
		s.hashMapDB.certByFingerprint[c.Sha256Fingerprint] = existing
		s.cache.certByFingerprint.Add(c.Sha256Fingerprint, c)
		s.Counter.tldDBHit++
	}
}

func (s *Store) mapFQDN() {

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
		s.Counter.fqdnCacheHit++
	}

	// Cache not full so the certificate can not be in the DB
	if s.cache.fqdnByName.Len() < s.cacheOpts.FQDNSize {
		return
	}

	if len(fqndNotFoundInCache) == 0 {
		return
	}

	//map with DB
	var fqdnFoundInDB []*models.Fqdn
	var id, tldID, psID, apexID uint
	var fqdn string

	q := fmt.Sprintf("SELECT id, fqdn, tld_id, public_suffix_id, apex_id FROM fqdns WHERE fqdn IN %s", "('"+strings.Join(fqndNotFoundInCache, "', '")+"')")
	iter := s.db.Query(q).Iter()
	for iter.Scan(&id, &fqdn, &tldID, &psID, &apexID) {
		fqdnFoundInDB = append(fqdnFoundInDB, &models.Fqdn{
			ID:             id,
			Fqdn:           fqdn,
			TldID:          tldID,
			PublicSuffixID: psID,
			ApexID:         apexID,
		})
	}
	if err := iter.Close(); err != nil {
		log.Error().Msgf("error retrieve FQDN from DB [mapFQDN]: %s", err)
	}

	for _, f := range fqdnFoundInDB {
		existing := s.hashMapDB.fqdnByName[f.Fqdn]
		existing.obj = f
		s.hashMapDB.fqdnByName[f.Fqdn] = existing
		s.cache.fqdnByName.Add(f.Fqdn, f)
		s.Counter.fqdnDBHit++
	}
}

func (s *Store) mapApex() {

	var apexNotFoundInCache []string

	for k := range s.hashMapDB.apexByName {
		apexI, ok := s.cache.apexByName.Get(k)
		if !ok {
			apexNotFoundInCache = append(apexNotFoundInCache, k)
			continue
		}
		apex := apexI.(*models.Apex)
		existing := s.hashMapDB.apexByName[k]
		existing.obj = apex
		s.hashMapDB.apexByName[k] = existing
		s.Counter.apexCacheHit++
	}

	// Cache not full so the certificate can not be in the DB
	if s.cache.apexByName.Len() < s.cacheOpts.ApexSize {
		return
	}

	if len(apexNotFoundInCache) == 0 {
		return
	}

	//map with DB
	var apexFoundInDB []*models.Apex
	var id, tldID, psID uint
	var apex string

	q := fmt.Sprintf("SELECT id, apex, tld_id, public_suffix_id FROM apexes WHERE apex IN %s", "('"+strings.Join(apexNotFoundInCache, "', '")+"')")
	iter := s.db.Query(q).Iter()
	for iter.Scan(&id, &apex, &tldID, &psID) {
		apexFoundInDB = append(apexFoundInDB, &models.Apex{
			ID:             id,
			Apex:           apex,
			TldID:          tldID,
			PublicSuffixID: psID,
		})
	}
	if err := iter.Close(); err != nil {
		log.Error().Msgf("error retrieve Apex from DB [mapApex]: %s", err)
	}

	for _, a := range apexFoundInDB {
		existing := s.hashMapDB.apexByName[a.Apex]
		existing.obj = a
		s.hashMapDB.apexByName[a.Apex] = existing
		s.cache.apexByName.Add(a.Apex, a)
		s.Counter.apexDBHit++
	}
}

func (s *Store) mapPublicSuffix() {

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
		s.Counter.psCacheHit++
	}

	// Cache not full so the certificate can not be in the DB
	if s.cache.publicSuffixByName.Len() < s.cacheOpts.PSuffSize {
		return
	}

	if len(psNotFoundInCache) == 0 {
		return
	}

	//map with DB
	var psFoundInDB []*models.PublicSuffix
	var id, tldID uint
	var ps string

	q := fmt.Sprintf("SELECT id, public_suffix, tld_id FROM public_suffixes WHERE public_suffix IN %s", "('"+strings.Join(psNotFoundInCache, "', '")+"')")
	iter := s.db.Query(q).Iter()
	for iter.Scan(&id, &ps, &tldID) {
		psFoundInDB = append(psFoundInDB, &models.PublicSuffix{
			ID:           id,
			PublicSuffix: ps,
			TldID:        tldID,
		})
	}
	if err := iter.Close(); err != nil {
		log.Error().Msgf("error retrieve PS from DB [mapPublicSuffix]: %s", err)
	}

	for _, ps := range psFoundInDB {
		existing := s.hashMapDB.publicSuffixByName[ps.PublicSuffix]
		existing.obj = ps
		s.hashMapDB.publicSuffixByName[ps.PublicSuffix] = existing
		s.cache.publicSuffixByName.Add(ps.PublicSuffix, ps)
		s.Counter.psDBHit++
	}
}

func (s *Store) mapTLD() {

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
		s.Counter.tldCacheHit++
	}

	// Cache not full so the certificate can not be in the DB
	if s.cache.tldByName.Len() < s.cacheOpts.TLDSize {
		return
	}

	if len(tldNotFoundInCache) == 0 {
		return
	}

	//map with DB
	var tldFoundInDB []*models.Tld
	var id uint
	var tld string

	q := fmt.Sprintf("SELECT id, tld FROM tlds WHERE tld IN %s", "('"+strings.Join(tldNotFoundInCache, "', '")+"')")
	iter := s.db.Query(q).Iter()
	for iter.Scan(&id, &tld) {
		tldFoundInDB = append(tldFoundInDB, &models.Tld{
			ID:  id,
			Tld: tld,
		})
	}
	if err := iter.Close(); err != nil {
		log.Error().Msgf("error retrieve TLD from DB [mapTLD]: %s", err)
	}

	for _, tld := range tldFoundInDB {
		existing := s.hashMapDB.tldByName[tld.Tld]
		existing.obj = tld
		s.hashMapDB.tldByName[tld.Tld] = existing
		s.cache.tldByName.Add(tld.Tld, tld)
		s.Counter.tldDBHit++
	}
	return
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
			s.cache.tldByName.Add(k, res)
			s.Counter.tldNew++
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
			s.cache.publicSuffixByName.Add(k, res)
			s.Counter.psNew++
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
			s.cache.apexByName.Add(k, res)
			s.Counter.apexNew++
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
			s.cache.fqdnByName.Add(k, res)
			s.Counter.fqdnNew++
		}
	}

	// certificates
	for k, certstr := range s.hashMapDB.certByFingerprint {
		if certstr.cert == nil {
			// get TLD name from domain object
			certEnc := b64.StdEncoding.EncodeToString(certstr.entry.Cert.Raw)
			cert := &models.Certificate{
				ID:                s.ids.certs,
				Sha256Fingerprint: k,
				Raw:               certEnc,
			}

			// create an association between FQDNs in database and the newly created certificate
			for _, d := range certstr.entry.Cert.DNSNames {
				domain, err := NewDomain(d)
				if err != nil {
					continue
				}
				fqdnstr := s.hashMapDB.fqdnByName[domain.fqdn.normal]
				fqdn := fqdnstr.obj.(*models.Fqdn)

				ctof := models.CertificateToFqdn{
					ID:            s.ids.certToFqdn,
					CertificateID: cert.ID,
					FqdnID:        fqdn.ID,
				}
				s.ids.certToFqdn++
				s.inserts.certToFqdns = append(s.inserts.certToFqdns, &ctof)
			}

			certstr.cert = cert
			s.inserts.certs = append(s.inserts.certs, cert)
			s.ids.certs++
			s.cache.certByFingerprint.Add(k, cert)
			s.Counter.certNew++
		}

		l, err := s.getOrCreateLog(certstr.entry.Log)
		if err != nil {
			return err
		}

		le := models.LogEntry{
			ID:            s.ids.logEntries,
			LogID:         l.ID,
			Index:         certstr.entry.Index,
			CertificateID: certstr.cert.ID,
			Timestamp:     certstr.entry.Ts,
			StageID:       certstr.sid,
			IsPrecert:     certstr.entry.IsPrecert,
		}
		s.ids.logEntries++
		s.inserts.logEntries = append(s.inserts.logEntries, &le)
	}

	return nil
}
