package store

import (
	"crypto/sha256"
	"fmt"
	"github.com/aau-network-security/gollector/store/models"
	"github.com/go-pg/pg"
	"net"
	"strings"

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

func NewSha256LabelAnonymizer() LabelAnonymizer {
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
	curCacheSize := s.cache.fqdnByName.Len()
	maxCacheSize := s.cacheOpts.FQDNSize
	if curCacheSize < maxCacheSize {
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
	s.influxService.StoreHit("db-hit", "tld", len(tldFoundInDB))
	return nil
}

func (s *Store) backpropFqdnAnon() error {
	if len(s.batchEntities.fqdnByNameAnon) == 0 {
		return nil
	}

	// fetch ids from cache
	var notFoundInCache []string
	for k := range s.batchEntities.fqdnByNameAnon {
		fqdnI, ok := s.cache.fqdnByNameAnon.Get(k)
		if !ok {
			notFoundInCache = append(notFoundInCache, k)
			continue
		}
		s.influxService.StoreHit("cache-hit", "fqdn-anon", 1)
		fqdn := fqdnI.(*models.FqdnAnon)
		existing := s.batchEntities.fqdnByNameAnon[k]
		existing.obj = fqdn
		s.batchEntities.fqdnByNameAnon[k] = existing
	}

	// the cache is not full yet, so the remaining (cache-miss) fqdns cannot be in the database
	curCacheSize := s.cache.fqdnByNameAnon.Len()
	maxCacheSize := s.cacheOpts.FQDNSize
	if curCacheSize < maxCacheSize {
		return nil
	}

	// all entities have been found in the cache, no need to perform a database queries
	if len(notFoundInCache) == 0 {
		return nil
	}

	// fetch ids from database
	var foundInDB []*models.FqdnAnon
	if err := s.db.Model(&foundInDB).Where("fqdn in (?)", pg.In(notFoundInCache)).Select(); err != nil {
		return err
	}

	for _, f := range foundInDB {
		existing := s.batchEntities.fqdnByNameAnon[f.Fqdn.Fqdn]
		existing.obj = f
		s.batchEntities.fqdnByNameAnon[f.Fqdn.Fqdn] = existing
		s.cache.fqdnByNameAnon.Add(f.Fqdn, f)
	}
	s.influxService.StoreHit("db-hit", "fqdn-anon", len(foundInDB))
	return nil
}

// collect ids for all observed apexes in the batch, either from the cache or the database
func (s *Store) backpropApexAnon() error {
	if len(s.batchEntities.apexByNameAnon) == 0 {
		return nil
	}

	// fetch ids from cache
	var notFoundInCache []string
	for k := range s.batchEntities.apexByNameAnon {
		apexI, ok := s.cache.apexByNameAnon.Get(k)
		if !ok {
			notFoundInCache = append(notFoundInCache, k)
			continue
		}
		s.influxService.StoreHit("cache-hit", "apex-anon", 1)
		apex := apexI.(*models.ApexAnon)
		existing := s.batchEntities.apexByNameAnon[k]
		existing.obj = apex
		s.batchEntities.apexByNameAnon[k] = existing
	}

	// all entities have been found in the cache, no need to perform a database queries
	if len(notFoundInCache) == 0 {
		return nil
	}

	// fetch ids from database
	var foundInDB []*models.ApexAnon
	if err := s.db.Model(&foundInDB).Where("apex in (?)", pg.In(notFoundInCache)).Select(); err != nil {
		return err
	}

	for _, a := range foundInDB {
		existing := s.batchEntities.apexByNameAnon[a.Apex.Apex]
		existing.obj = a
		s.batchEntities.apexByNameAnon[a.Apex.Apex] = existing
		s.cache.apexByNameAnon.Add(a.Apex, a)
	}
	s.influxService.StoreHit("db-hit", "apex-anon", len(foundInDB))
	return nil
}

// collect ids for all observed public suffixes in the batch, either from the cache or the database
func (s *Store) backpropPublicSuffixAnon() error {
	if len(s.batchEntities.publicSuffixAnonByName) == 0 {
		return nil
	}

	// fetch ids from cache
	var notFoundInCache []string
	for k := range s.batchEntities.publicSuffixAnonByName {
		psI, ok := s.cache.publicSuffixAnonByName.Get(k)
		if !ok {
			notFoundInCache = append(notFoundInCache, k)
			continue
		}
		s.influxService.StoreHit("cache-hit", "public-suffix-anon", 1)
		ps := psI.(*models.PublicSuffixAnon)
		existing := s.batchEntities.publicSuffixAnonByName[k]
		existing.obj = ps
		s.batchEntities.publicSuffixAnonByName[k] = existing
	}

	// the cache is not full yet, so the remaining (cache-miss) public suffixes cannot be in the database
	if s.cache.publicSuffixAnonByName.Len() < s.cacheOpts.PSuffSize {
		return nil
	}

	// all entities have been found in the cache, no need to perform a database queries
	if len(notFoundInCache) == 0 {
		return nil
	}

	// fetch ids from database
	var foundInDB []*models.PublicSuffixAnon
	if err := s.db.Model(&foundInDB).Where("public_suffix in (?)", pg.In(notFoundInCache)).Select(); err != nil {
		return err
	}

	for _, ps := range foundInDB {
		existing := s.batchEntities.publicSuffixAnonByName[ps.PublicSuffix.PublicSuffix]
		existing.obj = ps
		s.batchEntities.publicSuffixAnonByName[ps.PublicSuffix.PublicSuffix] = existing
	}
	s.influxService.StoreHit("db-hit", "public-suffix-anon", len(foundInDB))
	return nil
}

// collect ids for all observed TLDs in the batch, either from the cache or the database
func (s *Store) backpropTldAnon() error {
	if len(s.batchEntities.tldAnonByName) == 0 {
		return nil
	}

	// fetch ids from cache
	var notFoundInCache []string
	for k := range s.batchEntities.tldAnonByName {
		tldI, ok := s.cache.tldAnonByName.Get(k)
		if !ok {
			notFoundInCache = append(notFoundInCache, k)
			continue
		}
		s.influxService.StoreHit("cache-hit", "tld-anon", 1)
		tld := tldI.(*models.TldAnon)
		existing := s.batchEntities.tldAnonByName[k]
		existing.obj = tld
		s.batchEntities.tldAnonByName[k] = existing
	}

	// the cache is not full yet, so the remaining (cache-miss) tlds cannot be in the database
	if s.cache.tldAnonByName.Len() < s.cacheOpts.TLDSize {
		return nil
	}

	// all entities have been found in the cache, no need to perform a database queries
	if len(notFoundInCache) == 0 {
		return nil
	}

	// fetch ids from database
	var foundInDB []*models.TldAnon
	if err := s.db.Model(&foundInDB).Where("tld in (?)", pg.In(notFoundInCache)).Select(); err != nil {
		return err
	}

	for _, tld := range foundInDB {
		existing := s.batchEntities.tldAnonByName[tld.Tld.Tld]
		existing.obj = tld
		s.batchEntities.tldAnonByName[tld.Tld.Tld] = existing
		s.cache.tldAnonByName.Add(tld.Tld, tld)
	}
	s.influxService.StoreHit("db-hit", "tld-anon", len(foundInDB))
	return nil
}

func (s *Store) forpropTld() {
	for k, str := range s.batchEntities.tldByName {
		if str.obj == nil && str.create {
			res := &models.Tld{
				ID:  s.ids.tlds,
				Tld: k,
			}
			s.inserts.tld = append(s.inserts.tld, res)
			str.obj = res
			s.batchEntities.tldByName[k] = str
			s.ids.tlds++
			s.cache.tldByName.Add(k, res)

			// update anonymized TLD if exists
			tldstr := s.batchEntities.tldAnonByName[str.domain.tld.anon]
			if tldstr.obj != nil {
				tldAnon := tldstr.obj.(*models.TldAnon)
				tldAnon.TldID = res.ID
				s.updates.tldAnon = append(s.updates.tldAnon, tldAnon)
			}
		}
	}
}

func (s *Store) forpropPublicSuffix() {
	for k, str := range s.batchEntities.publicSuffixByName {
		if str.obj == nil && str.create {
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

			// update anonymized public suffix if exists
			psuffixstr := s.batchEntities.publicSuffixAnonByName[str.domain.publicSuffix.anon]
			if psuffixstr.obj != nil {
				psuffixAnon := psuffixstr.obj.(*models.PublicSuffixAnon)
				psuffixAnon.PublicSuffixID = res.ID
				s.updates.publicSuffixAnon = append(s.updates.publicSuffixAnon, psuffixAnon)
			}
		}
	}
}

func (s *Store) forpropApex() {
	for k, str := range s.batchEntities.apexByName {
		if str.obj == nil && str.create {
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

			// update anonymized apex if exists
			apexstr := s.batchEntities.apexByNameAnon[str.domain.apex.anon]
			if apexstr.obj != nil {
				apexAnon := apexstr.obj.(*models.ApexAnon)
				apexAnon.ApexID = res.ID
				s.updates.apexesAnon[res.ID] = apexAnon
			}
		}
	}
}

func (s *Store) forpropFqdn() {
	for k, str := range s.batchEntities.fqdnByName {
		if str.obj == nil && str.create {
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

			// update anonymized fqdn if exists
			fqdnstr := s.batchEntities.fqdnByNameAnon[str.domain.fqdn.anon]
			if fqdnstr.obj != nil {
				fqdnAnon := fqdnstr.obj.(*models.FqdnAnon)
				fqdnAnon.FqdnID = res.ID
				s.updates.fqdnsAnon = append(s.updates.fqdnsAnon, fqdnAnon)
			}
		}
	}
}

func (s *Store) forpropTldAnon() {
	for k, str := range s.batchEntities.tldAnonByName {
		if str.obj == nil && str.create {
			res := &models.TldAnon{
				Tld: models.Tld{
					ID:  s.ids.tldsAnon,
					Tld: k,
				},
			}

			tldstr := s.batchEntities.tldByName[str.domain.tld.normal]

			if tldstr.obj != nil {
				tld := tldstr.obj.(*models.Tld)
				res.TldID = tld.ID
			}

			s.inserts.tldAnon = append(s.inserts.tldAnon, res)
			str.obj = res
			s.batchEntities.tldAnonByName[k] = str
			s.ids.tldsAnon++
			s.cache.tldAnonByName.Add(k, res)
		}
	}
}

func (s *Store) forpropPublicSuffixAnon() {
	for k, str := range s.batchEntities.publicSuffixAnonByName {
		if str.obj == nil && str.create {
			tldstr := s.batchEntities.tldAnonByName[str.domain.tld.anon]
			tldAnon := tldstr.obj.(*models.TldAnon)

			res := &models.PublicSuffixAnon{
				PublicSuffix: models.PublicSuffix{
					ID:           s.ids.suffixesAnon,
					TldID:        tldAnon.ID,
					PublicSuffix: k,
				},
			}

			psuffixstr := s.batchEntities.publicSuffixByName[str.domain.publicSuffix.normal]
			if psuffixstr.obj != nil {
				psuffix := psuffixstr.obj.(*models.PublicSuffix)
				res.PublicSuffixID = psuffix.ID
			}

			str.obj = res
			s.inserts.publicSuffixAnon = append(s.inserts.publicSuffixAnon, res)
			s.batchEntities.publicSuffixAnonByName[k] = str
			s.ids.suffixesAnon++
			s.cache.publicSuffixAnonByName.Add(k, res)
		}
	}
}

func (s *Store) forpropApexAnon() {
	for k, str := range s.batchEntities.apexByNameAnon {
		if str.obj == nil && str.create {
			suffixstr := s.batchEntities.publicSuffixAnonByName[str.domain.publicSuffix.anon]
			suffixAnon := suffixstr.obj.(*models.PublicSuffixAnon)

			res := &models.ApexAnon{
				Apex: models.Apex{
					ID:             s.ids.apexesAnon,
					Apex:           k,
					TldID:          suffixAnon.TldID,
					PublicSuffixID: suffixAnon.ID,
				},
			}

			apexstr := s.batchEntities.apexByName[str.domain.apex.normal]
			if apexstr.obj != nil {
				apex := apexstr.obj.(*models.Apex)
				res.ApexID = apex.ID

			}

			str.obj = res
			s.inserts.apexesAnon[res.ID] = res
			s.batchEntities.apexByNameAnon[k] = str
			s.ids.apexesAnon++
			s.cache.apexByNameAnon.Add(k, res)
		}
	}
}

func (s *Store) forpropFqdnAnon() {
	for k, str := range s.batchEntities.fqdnByNameAnon {

		if str.obj == nil && str.create {
			apexstr := s.batchEntities.apexByNameAnon[str.domain.apex.anon]
			apexAnon := apexstr.obj.(*models.ApexAnon)

			res := &models.FqdnAnon{
				Fqdn: models.Fqdn{
					ID:             s.ids.fqdnsAnon,
					Fqdn:           k,
					TldID:          apexAnon.TldID,
					PublicSuffixID: apexAnon.PublicSuffixID,
					ApexID:         apexAnon.ID,
				},
			}

			fqdnstr := s.batchEntities.fqdnByName[str.domain.fqdn.normal]
			if fqdnstr.obj != nil {
				fqdn := fqdnstr.obj.(*models.Fqdn)
				res.FqdnID = fqdn.ID
			}

			str.obj = res
			s.inserts.fqdnsAnon = append(s.inserts.fqdnsAnon, res)
			s.batchEntities.fqdnByNameAnon[k] = str
			s.ids.fqdnsAnon++
			s.cache.fqdnByNameAnon.Add(k, res)
		}
	}
}
