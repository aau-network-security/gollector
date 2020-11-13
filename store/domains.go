package store

import (
	"crypto/sha256"
	"fmt"
	"net"
	"strings"

	"github.com/aau-network-security/gollector/store/models"
	"github.com/pkg/errors"
	"github.com/weppos/publicsuffix-go/net/publicsuffix"
)

var (
	AnonymizerErr     = errors.New("cannot anonymize without anonymizer")
	FqdnIsIpErr       = errors.New("fqdn is an IP address instead")
	DefaultAnonymizer = Anonymizer{&DefaultLabelAnonymizer{}}
)

type LabelAnonymizer interface {
	AnonymizeLabel(string) string
}

type DefaultLabelAnonymizer struct{}

func (la *DefaultLabelAnonymizer) AnonymizeLabel(s string) string {
	return s
}

type Sha256LabelAnonymizer struct{}

func (la *Sha256LabelAnonymizer) AnonymizeLabel(s string) string {
	h := sha256.New()
	h.Write([]byte(s))
	return fmt.Sprintf("%x", h.Sum(nil))
}

func NewSha256LabelAnonymizer() *Sha256LabelAnonymizer {
	return &Sha256LabelAnonymizer{}
}

type Anonymizer struct {
	la LabelAnonymizer
}

func (a *Anonymizer) Anonymize(d *domain) {
	d.tld.anon = a.la.AnonymizeLabel(d.tld.normal)
	d.publicSuffix.anon = a.la.AnonymizeLabel(d.publicSuffix.normal)
	d.apex.anon = a.la.AnonymizeLabel(d.apex.normal)
	d.fqdn.anon = a.la.AnonymizeLabel(d.fqdn.normal)
	d.anonymized = true
}

func NewAnonymizer(la LabelAnonymizer) *Anonymizer {
	return &Anonymizer{
		la: la,
	}
}

type label struct {
	normal, anon string
}

func newLabel(l string) label {
	return label{normal: l}
}

type domain struct {
	tld, publicSuffix, apex, fqdn label
	anonymized                    bool
}

func NewDomain(fqdn string) (*domain, error) {
	fqdn = strings.TrimSuffix(fqdn, ".")
	fqdn = strings.ToLower(fqdn)
	fqdn = strings.ReplaceAll(fqdn, "\t", "")
	fqdn = strings.ReplaceAll(fqdn, "\n", "")

	if net.ParseIP(fqdn) != nil {
		return nil, FqdnIsIpErr
	}

	d := &domain{
		fqdn: newLabel(fqdn),
	}

	splitted := strings.Split(fqdn, ".")
	tld := splitted[len(splitted)-1]
	d.tld = newLabel(tld)

	if len(splitted) == 1 {
		// domain is a tld
		d.publicSuffix = newLabel(fqdn)
		d.apex = newLabel(fqdn)
		return d, nil
	}

	apex, err := publicsuffix.EffectiveTLDPlusOne(fqdn)
	if err != nil {
		if strings.HasSuffix(err.Error(), "is a suffix") {
			// domain is a public suffix
			d.publicSuffix = newLabel(fqdn)
			d.apex = newLabel(fqdn)
			return d, nil
		}
		return nil, err
	}
	suffix := strings.Join(strings.Split(apex, ".")[1:], ".")

	d.publicSuffix = newLabel(suffix)
	d.apex = newLabel(apex)

	return d, nil
}

func (s *Store) ensureAnonymized(domain *domain) error {
	if !domain.anonymized {
		if s.anonymizer == nil {
			return AnonymizerErr
		}
		s.anonymizer.Anonymize(domain)
	}
	return nil
}

//Return the Tld found, otherwise error
func (s *Store) getTldFromCacheOrDB(domain *domain) (*models.Tld, error) {
	//Check if it is in the cache
	resI, ok := s.cache.tldByName.Get(domain.tld.normal)
	if !ok {
		if s.cache.tldByName.Len() < s.cacheOpts.TLDSize {
			s.influxService.StoreHit("cache-insert", "tld", 1)
			return nil, cacheNotFull
		}
		//Check if it is in the DB
		var tld models.Tld
		if err := s.db.Model(&tld).Where("tld = ?", domain.tld.normal).First(); err != nil {
			s.influxService.StoreHit("db-insert", "tld", 1)
			return nil, err
		}
		s.influxService.StoreHit("db-hit", "tld", 1)
		return &tld, nil //It is in DB
	}
	res := resI.(*models.Tld)
	s.influxService.StoreHit("cache-hit", "tld", 1)
	return res, nil //It is in Cache
}

func (s *Store) getTldAnonFromCacheOrDB(domain *domain) (*models.TldAnon, error) {
	anonI, ok := s.cache.tldAnonByName.Get(domain.tld.anon)
	if !ok {
		if s.cache.tldAnonByName.Len() < s.cacheOpts.TLDSize {
			s.influxService.StoreHit("cache-insert", "tld-anon", 1)
			return nil, cacheNotFull
		}
		var tldAnon models.TldAnon
		if err := s.db.Model(&tldAnon).Where("tld = ?", domain.tld.normal).First(); err != nil {
			s.influxService.StoreHit("db-insert", "tld-anon", 1)
			return nil, err
		}
		s.influxService.StoreHit("db-hit", "tld-anon", 1)
		return &tldAnon, nil //It is in DB
	}
	anon := anonI.(*models.TldAnon)
	s.influxService.StoreHit("cache-hit", "tld-anon", 1)
	return anon, nil //It is in Cache
}

func (s *Store) getOrCreateTld(domain *domain) (*models.Tld, error) {
	if err := s.ensureAnonymized(domain); err != nil {
		return nil, err
	}

	res, err := s.getTldFromCacheOrDB(domain)
	if err != nil { // It is not in cache or DB

		tx, err := s.db.Begin()
		if err != nil {
			return nil, err
		}

		res = &models.Tld{
			ID:  s.ids.tlds,
			Tld: domain.tld.normal,
		}
		if err := tx.Insert(res); err != nil {
			return nil, errors.Wrap(err, "insert tld")
		}

		// update anonymized model (if it exists)
		anon, err := s.getTldAnonFromCacheOrDB(domain)
		if err == nil { //It is in the cache
			anon.TldID = res.ID
			if err := tx.Update(anon); err != nil {
				return nil, err
			}
		}

		if err := tx.Commit(); err != nil {
			return nil, err
		}

		s.cache.tldByName.Add(domain.tld.normal, res)
		s.ids.tlds++
	}
	return res, nil //it was in cache or DB
}

func (s *Store) getOrCreateTldAnon(domain *domain) (*models.TldAnon, error) {
	if err := s.ensureAnonymized(domain); err != nil {
		return nil, err
	}

	res, err := s.getTldAnonFromCacheOrDB(domain)
	if err != nil { // It is not in cache or DB
		tldId := uint(0)
		tld, err := s.getTldFromCacheOrDB(domain)
		if err == nil { // It is in cache or DB
			tldId = tld.ID
		}
		res = &models.TldAnon{
			Tld: models.Tld{
				ID:  s.ids.tldsAnon,
				Tld: domain.tld.anon,
			},
			TldID: tldId,
		}
		if err := s.db.Insert(res); err != nil {
			return nil, errors.Wrap(err, "insert anon tld")
		}
		s.cache.tldAnonByName.Add(domain.tld.anon, res)
		s.ids.tldsAnon++
	}
	return res, nil
}

func (s *Store) getPublicSuffixFromCacheOrDB(domain *domain) (*models.PublicSuffix, error) {
	psI, ok := s.cache.publicSuffixByName.Get(domain.publicSuffix.normal)
	if !ok {
		if s.cache.publicSuffixByName.Len() < s.cacheOpts.PSuffSize {
			s.influxService.StoreHit("cache-insert", "public-suffix", 1)
			return nil, cacheNotFull
		}
		var ps models.PublicSuffix
		if err := s.db.Model(&ps).Where("public_suffix = ?", domain.publicSuffix.normal).First(); err != nil {
			s.influxService.StoreHit("db-insert", "public-suffix", 1)
			return nil, err
		}
		s.influxService.StoreHit("db-hit", "public-suffix", 1)
		return &ps, nil //It is in DB
	}
	ps := psI.(*models.PublicSuffix)
	s.influxService.StoreHit("cache-hit", "public-suffix", 1)
	return ps, nil //It is in Cache
}

func (s *Store) getPublicSuffixAnonFromCacheOrDB(domain *domain) (*models.PublicSuffixAnon, error) {
	psI, ok := s.cache.publicSuffixAnonByName.Get(domain.publicSuffix.anon)
	if !ok {
		if s.cache.publicSuffixAnonByName.Len() < s.cacheOpts.PSuffSize {
			s.influxService.StoreHit("cache-insert", "public-suffix-anon", 1)
			return nil, cacheNotFull
		}
		var psAnon models.PublicSuffixAnon
		if err := s.db.Model(&psAnon).Where("public_suffix = ?", domain.publicSuffix.anon).First(); err != nil {
			s.influxService.StoreHit("db-insert", "public-suffix-anon", 1)
			return nil, err
		}
		s.influxService.StoreHit("db-hit", "public-suffix-anon", 1)
		return &psAnon, nil //It is in DB
	}
	ps := psI.(*models.PublicSuffixAnon)
	s.influxService.StoreHit("cache-hit", "public-suffix-anon", 1)
	return ps, nil //It is in Cache
}

func (s *Store) getOrCreatePublicSuffix(domain *domain) (*models.PublicSuffix, error) {
	if err := s.ensureAnonymized(domain); err != nil {
		return nil, err
	}

	res, err := s.getPublicSuffixFromCacheOrDB(domain)
	if err != nil { // It is not in cache or DB

		tx, err := s.db.Begin()
		if err != nil {
			return nil, err
		}
		defer tx.Rollback()

		tld, err := s.getOrCreateTld(domain)
		if err != nil {
			return nil, err
		}

		res = &models.PublicSuffix{
			ID:           s.ids.suffixes,
			PublicSuffix: domain.publicSuffix.normal,
			TldID:        tld.ID,
		}
		if err := tx.Insert(res); err != nil {
			return nil, errors.Wrap(err, "insert public suffix")
		}

		// update anonymized model (if it exists)
		anon, err := s.getPublicSuffixAnonFromCacheOrDB(domain)
		if err == nil { //It is in the cache or DB
			anon.PublicSuffixID = res.ID
			if err := tx.Update(anon); err != nil {
				return nil, err
			}
		}

		if err := tx.Commit(); err != nil {
			return nil, err
		}

		s.cache.publicSuffixByName.Add(domain.publicSuffix.normal, res)
		s.ids.suffixes++
	}
	return res, nil
}

func (s *Store) getOrCreatePublicSuffixAnon(domain *domain) (*models.PublicSuffixAnon, error) {
	if err := s.ensureAnonymized(domain); err != nil {
		return nil, err
	}

	res, err := s.getPublicSuffixAnonFromCacheOrDB(domain)
	if err != nil { // It is not in cache or DB
		tldAnon, err := s.getOrCreateTldAnon(domain)
		if err != nil {
			return nil, err
		}

		suffixId := uint(0)
		suffix, err := s.getPublicSuffixFromCacheOrDB(domain)
		if err == nil { //It is in the cache or DB
			suffixId = suffix.ID
		}

		res = &models.PublicSuffixAnon{
			PublicSuffix: models.PublicSuffix{
				ID:           s.ids.suffixesAnon,
				PublicSuffix: domain.publicSuffix.anon,
				TldID:        tldAnon.ID,
			},
			PublicSuffixID: suffixId,
		}
		if err := s.db.Insert(res); err != nil {
			return nil, errors.Wrap(err, "insert anon public suffix")
		}
		s.cache.publicSuffixAnonByName.Add(domain.publicSuffix.anon, res)
		s.ids.suffixesAnon++
	}
	return res, nil
}

func (s *Store) getApexFromCacheOrDB(domain *domain) (*models.Apex, error) {
	aI, ok := s.cache.apexByName.Get(domain.apex.normal)
	if !ok {
		if s.cache.apexByName.Len() < s.cacheOpts.ApexSize {
			s.influxService.StoreHit("cache-insert", "apex", 1)
			return nil, cacheNotFull
		}
		var a models.Apex
		if err := s.db.Model(&a).Where("apex = ?", domain.apex.normal).First(); err != nil {
			s.influxService.StoreHit("db-insert", "apex", 1)
			return nil, err
		}
		s.influxService.StoreHit("db-hit", "apex", 1)
		return &a, nil //It is in DB
	}
	apex := aI.(*models.Apex)
	s.influxService.StoreHit("cache-hit", "apex", 1)
	return apex, nil //It is in Cache
}

func (s *Store) getApexAnonFromCacheOrDB(domain *domain) (*models.ApexAnon, error) {
	aI, ok := s.cache.apexByNameAnon.Get(domain.apex.anon)
	if !ok {
		if s.cache.apexByNameAnon.Len() < s.cacheOpts.ApexSize {
			s.influxService.StoreHit("cache-insert", "apex-anon", 1)
			return nil, cacheNotFull
		}
		var aAnon models.ApexAnon
		if err := s.db.Model(&aAnon).Where("apex = ?", domain.apex.anon).First(); err != nil {
			s.influxService.StoreHit("db-insert", "apex-anon", 1)
			return nil, err
		}
		s.influxService.StoreHit("db-hit", "apex-anon", 1)
		return &aAnon, nil //It is in DB
	}
	a := aI.(*models.ApexAnon)
	s.influxService.StoreHit("cache-hit", "apex-anon", 1)
	return a, nil //It is in Cache
}

func (s *Store) getOrCreateApex(domain *domain) (*models.Apex, error) {
	if err := s.ensureAnonymized(domain); err != nil {
		return nil, err
	}

	res, err := s.getApexFromCacheOrDB(domain)
	if err != nil { // It is not in cache or DB
		ps, err := s.getOrCreatePublicSuffix(domain)
		if err != nil {
			return nil, err
		}

		res = &models.Apex{
			ID:             s.ids.apexes,
			Apex:           domain.apex.normal,
			TldID:          ps.TldID,
			PublicSuffixID: ps.ID,
		}

		s.cache.apexByName.Add(domain.apex.normal, res)
		s.inserts.apexes[res.ID] = res
		s.ids.apexes++

		// update anonymized model (if it exists)
		anon, err := s.getApexAnonFromCacheOrDB(domain)
		if err == nil { // It is in cache or DB
			anon.ApexID = res.ID
			s.updates.apexesAnon[anon.ID] = anon
		}
	}
	return res, nil
}

func (s *Store) getOrCreateApexAnon(domain *domain) (*models.ApexAnon, error) {
	if err := s.ensureAnonymized(domain); err != nil {
		return nil, err
	}

	res, err := s.getApexAnonFromCacheOrDB(domain)
	if err != nil { // It is not in cache or DB
		ps, err := s.getOrCreatePublicSuffixAnon(domain)
		if err != nil {
			return nil, err
		}

		apexId := uint(0)
		apex, err := s.getApexFromCacheOrDB(domain)
		if err == nil { // It is in cache or DB
			apexId = apex.ID
		}

		res = &models.ApexAnon{
			Apex: models.Apex{
				ID:             s.ids.apexesAnon,
				Apex:           domain.apex.anon,
				TldID:          ps.TldID,
				PublicSuffixID: ps.ID,
			},
			ApexID: apexId,
		}

		s.cache.apexByNameAnon.Add(domain.apex.anon, res)
		s.inserts.apexesAnon[res.ID] = res
		s.ids.apexesAnon++
	}
	return res, nil
}

func (s *Store) getFqdnFromCacheOrDB(domain *domain) (*models.Fqdn, error) {
	fqdnI, ok := s.cache.fqdnByName.Get(domain.fqdn.normal)
	if !ok {
		if s.cache.fqdnByName.Len() < s.cacheOpts.FQDNSize {
			s.influxService.StoreHit("cache-insert", "fqdn", 1)
			return nil, cacheNotFull
		}
		var fqdn models.Fqdn
		if err := s.db.Model(&fqdn).Where("fqdn = ?", domain.fqdn.normal).First(); err != nil {
			s.influxService.StoreHit("db-insert", "fqdn", 1)
			return nil, err
		}
		s.influxService.StoreHit("db-hit", "fqdn", 1)
		return &fqdn, nil //It is in DB
	}
	fqdn := fqdnI.(*models.Fqdn)
	s.influxService.StoreHit("cache-hit", "fqdn", 1)
	return fqdn, nil //It is in Cache
}

func (s *Store) getFqdnAnonFromCacheOrDB(domain *domain) (*models.FqdnAnon, error) {
	fqdnI, ok := s.cache.fqdnByNameAnon.Get(domain.fqdn.anon)
	if !ok {
		if s.cache.fqdnByNameAnon.Len() < s.cacheOpts.FQDNSize {
			s.influxService.StoreHit("cache-insert", "fqdn-anon", 1)
			return nil, cacheNotFull
		}
		var fqdnAnon models.FqdnAnon
		if err := s.db.Model(&fqdnAnon).Where("fqdn = ?", domain.fqdn.anon).First(); err != nil {
			s.influxService.StoreHit("db-insert", "fqdn-anon", 1)
			return nil, err
		}
		s.influxService.StoreHit("db-hit", "fqdn-anon", 1)
		return &fqdnAnon, nil //It is in DB
	}
	fqdnAnon := fqdnI.(*models.FqdnAnon)
	s.influxService.StoreHit("cache-hit", "fqdn-anon", 1)
	return fqdnAnon, nil //It is in Cache
}

func (s *Store) getOrCreateFqdn(domain *domain) (*models.Fqdn, error) {
	if err := s.ensureAnonymized(domain); err != nil {
		return nil, err
	}

	res, err := s.getFqdnFromCacheOrDB(domain)
	if err != nil { // It is not in cache or DB
		a, err := s.getOrCreateApex(domain)
		if err != nil {
			return nil, err
		}

		res = &models.Fqdn{
			ID:             s.ids.fqdns,
			Fqdn:           domain.fqdn.normal,
			ApexID:         a.ID,
			TldID:          a.TldID,
			PublicSuffixID: a.PublicSuffixID,
		}
		s.inserts.fqdns = append(s.inserts.fqdns, res)
		s.cache.fqdnByName.Add(domain.fqdn.normal, res)
		s.ids.fqdns++

		// update anonymized model (if it exists)
		anon, err := s.getFqdnAnonFromCacheOrDB(domain)
		if err == nil { // It is in cache or DB
			anon.FqdnID = res.ID
			s.updates.fqdnsAnon = append(s.updates.fqdnsAnon, anon)
		}
		return res, nil
	}
	return res, nil
}

func (s *Store) getOrCreateFqdnAnon(domain *domain) (*models.FqdnAnon, error) {
	if err := s.ensureAnonymized(domain); err != nil {
		return nil, err
	}

	res, err := s.getFqdnAnonFromCacheOrDB(domain)
	if err != nil { // It is not in cache or DB
		apex, err := s.getOrCreateApexAnon(domain)
		if err != nil {
			return nil, err
		}

		fqdnId := uint(0)
		fqdn, err := s.getFqdnFromCacheOrDB(domain)
		if err == nil { // It is  in cache or DB
			fqdnId = fqdn.ID
		}

		res = &models.FqdnAnon{
			Fqdn: models.Fqdn{
				ID:             s.ids.fqdnsAnon,
				Fqdn:           domain.fqdn.anon,
				ApexID:         apex.ID,
				TldID:          apex.TldID,
				PublicSuffixID: apex.PublicSuffixID,
			},
			FqdnID: fqdnId,
		}
		s.inserts.fqdnsAnon = append(s.inserts.fqdnsAnon, res)
		s.cache.fqdnByNameAnon.Add(domain.fqdn.anon, res)
		s.ids.fqdnsAnon++
		return res, nil
	}
	return res, nil
}
