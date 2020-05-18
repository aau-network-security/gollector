package store

import (
	"crypto/sha256"
	"fmt"
	"github.com/aau-network-security/gollector/store/models"
	"github.com/pkg/errors"
	"github.com/weppos/publicsuffix-go/net/publicsuffix"
	"strings"
)

var (
	AnonymizerErr     = errors.New("cannot anonymize without anonymizer")
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

func (s *Store) getOrCreateTld(domain *domain) (*models.Tld, error) {
	if err := s.ensureAnonymized(domain); err != nil {
		return nil, err
	}

	//Check if it is in the cache
	resI, ok := s.cache.tldByName.Get(domain.tld.normal)
	if !ok {
		//todo make another check here (check in the DB)
		tx, err := s.db.Begin()
		if err != nil {
			return nil, err
		}

		res := &models.Tld{
			ID:  s.ids.tlds,
			Tld: domain.tld.normal,
		}
		if err := tx.Insert(res); err != nil {
			return nil, errors.Wrap(err, "insert tld")
		}

		// update anonymized model (if it exists)
		anonI, ok := s.cache.tldAnonByName.Get(domain.tld.anon)
		if ok {
			anon := anonI.(models.TldAnon)
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
		return res, nil
	}
	res := resI.(*models.Tld)
	return res, nil
}

func (s *Store) getOrCreateTldAnon(domain *domain) (*models.TldAnon, error) {
	if err := s.ensureAnonymized(domain); err != nil {
		return nil, err
	}

	resI, ok := s.cache.tldAnonByName.Get(domain.tld.anon)
	if !ok {
		//todo make another check here (check in the DB)
		tldId := uint(0)
		tldI, ok := s.cache.tldByName.Get(domain.tld.normal)
		if ok {
			tld := tldI.(models.Tld)
			tldId = tld.ID
		}
		res := &models.TldAnon{
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
		return res, nil
	}
	res := resI.(*models.TldAnon)
	return res, nil
}

func (s *Store) getOrCreatePublicSuffix(domain *domain) (*models.PublicSuffix, error) {
	if err := s.ensureAnonymized(domain); err != nil {
		return nil, err
	}

	resI, ok := s.cache.publicSuffixByName.Get(domain.publicSuffix.normal)
	if !ok {
		//todo make another check here (check in the DB)
		tx, err := s.db.Begin()
		if err != nil {
			return nil, err
		}
		defer tx.Rollback()

		tld, err := s.getOrCreateTld(domain)
		if err != nil {
			return nil, err
		}

		res := &models.PublicSuffix{
			ID:           s.ids.suffixes,
			PublicSuffix: domain.publicSuffix.normal,
			TldID:        tld.ID,
		}
		if err := tx.Insert(res); err != nil {
			return nil, errors.Wrap(err, "insert public suffix")
		}

		// update anonymized model (if it exists)
		anonI, ok := s.cache.publicSuffixAnonByName.Get(domain.publicSuffix.anon)
		if ok {
			anon := anonI.(*models.PublicSuffixAnon)
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
		return res, nil
	}
	res := resI.(*models.PublicSuffix)
	return res, nil
}

func (s *Store) getOrCreatePublicSuffixAnon(domain *domain) (*models.PublicSuffixAnon, error) {
	if err := s.ensureAnonymized(domain); err != nil {
		return nil, err
	}

	resI, ok := s.cache.publicSuffixAnonByName.Get(domain.publicSuffix.anon)
	if !ok {
		//todo make another check here (check in the DB)
		tldAnon, err := s.getOrCreateTldAnon(domain)
		if err != nil {
			return nil, err
		}

		suffixId := uint(0)
		suffixI, ok := s.cache.publicSuffixByName.Get(domain.publicSuffix.normal)
		if ok {
			suffix := suffixI.(*models.PublicSuffix)
			suffixId = suffix.ID
		}

		res := &models.PublicSuffixAnon{
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
		return res, nil
	}
	res := resI.(*models.PublicSuffixAnon)
	return res, nil
}

func (s *Store) getOrCreateApex(domain *domain) (*models.Apex, error) {
	if err := s.ensureAnonymized(domain); err != nil {
		return nil, err
	}

	resI, ok := s.cache.apexByName.Get(domain.apex.normal)
	if !ok {
		//todo make another check here (check in the DB)
		ps, err := s.getOrCreatePublicSuffix(domain)
		if err != nil {
			return nil, err
		}

		res := &models.Apex{
			ID:             s.ids.apexes,
			Apex:           domain.apex.normal,
			TldID:          ps.TldID,
			PublicSuffixID: ps.ID,
		}

		s.cache.apexByName.Add(domain.apex.normal, res)
		s.inserts.apexes[res.ID] = res
		s.ids.apexes++

		// update anonymized model (if it exists)
		anonI, ok := s.cache.apexByNameAnon.Get(domain.apex.anon)
		if ok {
			anon := anonI.(*models.ApexAnon)
			anon.ApexID = res.ID
			s.updates.apexesAnon[anon.ID] = anon
		}
		return res, nil
	}
	res := resI.(*models.Apex)
	return res, nil
}

func (s *Store) getOrCreateApexAnon(domain *domain) (*models.ApexAnon, error) {
	if err := s.ensureAnonymized(domain); err != nil {
		return nil, err
	}

	resI, ok := s.cache.apexByNameAnon.Get(domain.apex.anon)
	if !ok {
		//todo make another check here (check in the DB)
		ps, err := s.getOrCreatePublicSuffixAnon(domain)
		if err != nil {
			return nil, err
		}

		apexId := uint(0)
		apexI, ok := s.cache.apexByName.Get(domain.apex.normal)
		if ok {
			apex := apexI.(*models.Apex)
			apexId = apex.ID
		}

		res := &models.ApexAnon{
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
		return res, nil
	}
	res := resI.(*models.ApexAnon)
	return res, nil
}

func (s *Store) getOrCreateFqdn(domain *domain) (*models.Fqdn, error) {
	if err := s.ensureAnonymized(domain); err != nil {
		return nil, err
	}

	resI, ok := s.cache.fqdnByName.Get(domain.fqdn.normal)
	if !ok {
		//todo make another check here (check in the DB)
		a, err := s.getOrCreateApex(domain)
		if err != nil {
			return nil, err
		}

		res := &models.Fqdn{
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
		anonI, ok := s.cache.fqdnByNameAnon.Get(domain.fqdn.anon)
		if ok {
			anon := anonI.(*models.FqdnAnon)
			anon.FqdnID = res.ID
			s.updates.fqdnsAnon = append(s.updates.fqdnsAnon, anon)
		}
		return res, nil
	}
	res := resI.(*models.Fqdn)
	return res, nil
}

func (s *Store) getOrCreateFqdnAnon(domain *domain) (*models.FqdnAnon, error) {
	if err := s.ensureAnonymized(domain); err != nil {
		return nil, err
	}

	resI, ok := s.cache.fqdnByNameAnon.Get(domain.fqdn.anon)
	if !ok {
		//todo make another check here (check in the DB)
		apex, err := s.getOrCreateApexAnon(domain)
		if err != nil {
			return nil, err
		}

		fqdnId := uint(0)
		fqdnI, ok := s.cache.fqdnByName.Get(domain.fqdn.normal)
		if ok {
			fqdn := fqdnI.(*models.Fqdn)
			fqdnId = fqdn.ID
		}

		res := &models.FqdnAnon{
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
	res := resI.(*models.FqdnAnon)
	return res, nil
}
