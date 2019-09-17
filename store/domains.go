package store

import (
	"github.com/aau-network-security/go-domains/models"
	"github.com/pkg/errors"
	"github.com/weppos/publicsuffix-go/net/publicsuffix"
	"strings"
)

var (
	UnanonymizedErr = errors.New("domain is unanonymized")
)

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

type Anonymizer struct {
	fn func(string) string
}

func (a *Anonymizer) Anonymize(d *domain) {
	d.tld.anon = a.fn(d.tld.normal)
	d.publicSuffix.anon = a.fn(d.publicSuffix.normal)
	d.apex.anon = a.fn(d.apex.normal)
	d.fqdn.anon = a.fn(d.fqdn.normal)
	d.anonymized = true
}

func NewDomain(fqdn string) (*domain, error) {
	d := &domain{
		fqdn: newLabel(fqdn),
	}

	splitted := strings.Split(fqdn, ".")

	if len(splitted) == 1 {
		// domain is a tld
		d.tld = newLabel(fqdn)
		return d, nil
	}

	tld := splitted[len(splitted)-1]
	d.tld = newLabel(tld)

	apex, err := publicsuffix.EffectiveTLDPlusOne(fqdn)
	if err != nil {
		if strings.HasSuffix(err.Error(), "is a suffix") {
			// domain is a public suffix
			d.publicSuffix = newLabel(fqdn)
			return d, nil
		}
		return nil, err
	}
	suffix := strings.Join(strings.Split(apex, ".")[1:], ".")

	d.publicSuffix = newLabel(suffix)
	d.apex = newLabel(apex)

	return d, nil
}

func (s *Store) getOrCreateTld(domain *domain) (*models.Tld, error) {
	res, ok := s.tldByName[domain.tld.normal]
	if !ok {
		res = &models.Tld{
			ID:  s.ids.tlds,
			Tld: domain.tld.normal,
		}
		if err := s.db.Insert(res); err != nil {
			return nil, errors.Wrap(err, "insert tld")
		}

		s.tldByName[domain.tld.normal] = res
		s.ids.tlds++
	}
	return res, nil
}

func (s *Store) getOrCreateTldAnon(domain *domain) (*models.TldAnon, error) {
	if !domain.anonymized {
		return nil, UnanonymizedErr
	}

	res, ok := s.tldAnonByName[domain.tld.anon]
	if !ok {
		tld, err := s.getOrCreateTld(domain)
		if err != nil {
			return nil, err
		}
		res = &models.TldAnon{
			Tld: models.Tld{
				ID:  s.ids.tldsAnon,
				Tld: domain.tld.anon,
			},
			TldID: tld.ID,
		}
		if err := s.db.Insert(res); err != nil {
			return nil, errors.Wrap(err, "insert anon tld")
		}
		s.tldAnonByName[domain.tld.anon] = res
		s.ids.tldsAnon++
	}
	return res, nil
}

func (s *Store) getOrCreatePublicSuffix(domain *domain) (*models.PublicSuffix, error) {
	res, ok := s.publicSuffixByName[domain.publicSuffix.normal]
	if !ok {
		tld, err := s.getOrCreateTld(domain)
		if err != nil {
			return nil, err
		}

		res = &models.PublicSuffix{
			ID:           s.ids.suffixes,
			PublicSuffix: domain.publicSuffix.normal,
			TldID:        tld.ID,
		}
		if err := s.db.Insert(res); err != nil {
			return nil, errors.Wrap(err, "insert public suffix")
		}
		s.publicSuffixByName[domain.publicSuffix.normal] = res
		s.ids.suffixes++
	}
	return res, nil
}

func (s *Store) getOrCreatePublicSuffixAnon(domain *domain) (*models.PublicSuffixAnon, error) {
	if !domain.anonymized {
		return nil, UnanonymizedErr
	}

	res, ok := s.publicSuffixAnonByName[domain.publicSuffix.anon]
	if !ok {
		tldAnon, err := s.getOrCreateTldAnon(domain)
		if err != nil {
			return nil, err
		}

		suffix, err := s.getOrCreatePublicSuffix(domain)
		if err != nil {
			return nil, err
		}

		res = &models.PublicSuffixAnon{
			PublicSuffix: models.PublicSuffix{
				ID:           s.ids.suffixesAnon,
				PublicSuffix: domain.publicSuffix.anon,
				TldID:        tldAnon.ID,
			},
			PublicSuffixID: suffix.ID,
		}
		if err := s.db.Insert(res); err != nil {
			return nil, errors.Wrap(err, "insert anon public suffix")
		}
		s.publicSuffixAnonByName[domain.publicSuffix.anon] = res
		s.ids.suffixesAnon++
	}
	return res, nil
}

func (s *Store) getOrCreateApex(domain *domain) (*models.Apex, error) {
	res, ok := s.apexByName[domain.apex.normal]
	if !ok {
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

		s.apexByName[domain.apex.normal] = res
		s.inserts.apexes[res.ID] = res
		s.ids.apexes++
	}
	return res, nil
}

func (s *Store) getOrCreateApexAnon(domain *domain) (*models.ApexAnon, error) {
	if !domain.anonymized {
		return nil, UnanonymizedErr
	}

	res, ok := s.apexByNameAnon[domain.apex.anon]
	if !ok {
		ps, err := s.getOrCreatePublicSuffixAnon(domain)
		if err != nil {
			return nil, err
		}

		apex, err := s.getOrCreateApex(domain)
		if err != nil {
			return nil, err
		}

		res := &models.ApexAnon{
			Apex: models.Apex{
				ID:             s.ids.apexesAnon,
				Apex:           domain.apex.anon,
				TldID:          ps.TldID,
				PublicSuffixID: ps.ID,
			},
			ApexID: apex.ID,
		}

		s.apexByNameAnon[domain.apex.anon] = res
		s.inserts.apexesAnon[res.ID] = res
		s.ids.apexesAnon++
	}
	return res, nil
}

func (s *Store) getOrCreateFqdn(domain *domain) (*models.Fqdn, error) {
	res, ok := s.fqdnByName[domain.fqdn.normal]
	if !ok {
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
		s.fqdnByName[domain.fqdn.normal] = res
		s.ids.fqdns++
	}
	return res, nil
}

func (s *Store) getOrCreateFqdnAnon(domain *domain) (*models.FqdnAnon, error) {
	if !domain.anonymized {
		return nil, UnanonymizedErr
	}

	res, ok := s.fqdnByNameAnon[domain.fqdn.anon]
	if !ok {
		apex, err := s.getOrCreateApexAnon(domain)
		if err != nil {
			return nil, err
		}

		fqdn, err := s.getOrCreateFqdn(domain)
		if err != nil {
			return nil, err
		}

		res := &models.FqdnAnon{
			Fqdn: models.Fqdn{
				ID:             s.ids.fqdnsAnon,
				Fqdn:           domain.fqdn.anon,
				ApexID:         apex.ID,
				TldID:          apex.TldID,
				PublicSuffixID: apex.PublicSuffixID,
			},
			FqdnID: fqdn.ID,
		}
		s.inserts.fqdnsAnon = append(s.inserts.fqdnsAnon, res)
		s.fqdnByNameAnon[domain.fqdn.anon] = res
		s.ids.fqdnsAnon++
	}
	return res, nil
}
