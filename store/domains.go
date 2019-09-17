package store

import (
	"github.com/aau-network-security/go-domains/models"
	"github.com/pkg/errors"
	"github.com/weppos/publicsuffix-go/net/publicsuffix"
	"strings"
)

type domain struct {
	tld, publicSuffix, apex, fqdn string
}

func NewDomain(fqdn string) (*domain, error) {
	d := &domain{
		fqdn: fqdn,
	}

	splitted := strings.Split(fqdn, ".")

	if len(splitted) == 1 {
		// domain is a tld
		d.tld = fqdn
		return d, nil
	}

	tld := splitted[len(splitted)-1]
	d.tld = tld

	apex, err := publicsuffix.EffectiveTLDPlusOne(fqdn)
	if err != nil {
		if strings.HasSuffix(err.Error(), "is a suffix") {
			// domain is a public suffix
			d.publicSuffix = fqdn
			return d, nil
		}
		return nil, err
	}
	suffix := strings.Join(strings.Split(apex, ".")[1:], ".")

	d.publicSuffix = suffix
	d.apex = apex

	return d, nil
}

func toApex(fqdn string) (string, error) {
	return publicsuffix.EffectiveTLDPlusOne(fqdn)
}

func (s *Store) getOrCreateTld(domain *domain) (*models.Tld, error) {
	res, ok := s.tldByName[domain.tld]
	if !ok {
		res = &models.Tld{
			ID:  s.ids.tlds,
			Tld: domain.tld,
		}
		if err := s.db.Insert(res); err != nil {
			return nil, errors.Wrap(err, "insert tld")
		}

		s.tldByName[domain.tld] = res
		s.ids.tlds++
	}
	return res, nil
}

func (s *Store) getOrCreatePublicSuffix(domain *domain) (*models.PublicSuffix, error) {
	res, ok := s.publicSuffixByName[domain.publicSuffix]
	if !ok {
		tld, err := s.getOrCreateTld(domain)
		if err != nil {
			return nil, err
		}

		res = &models.PublicSuffix{
			ID:           s.ids.pss,
			PublicSuffix: domain.publicSuffix,
			TldID:        tld.ID,
		}
		if err := s.db.Insert(res); err != nil {
			return nil, errors.Wrap(err, "insert public suffix")
		}
		s.publicSuffixByName[domain.publicSuffix] = res
		s.ids.pss++
	}
	return res, nil
}

func (s *Store) getOrCreateApex(domain *domain) (*models.Apex, error) {
	res, ok := s.apexByName[domain.apex]
	if !ok {
		ps, err := s.getOrCreatePublicSuffix(domain)
		if err != nil {
			return nil, err
		}

		model := &models.Apex{
			ID:             s.ids.apexes,
			Apex:           domain.apex,
			TldID:          ps.TldID,
			PublicSuffixID: ps.ID,
		}

		s.apexByName[domain.apex] = model
		s.inserts.apexes[model.ID] = model
		s.ids.apexes++

		res = model
	}
	return res, nil
}

func (s *Store) getOrCreateFqdn(domain *domain) (*models.Fqdn, error) {
	f, ok := s.fqdnByName[domain.fqdn]
	if !ok {
		a, err := s.getOrCreateApex(domain)
		if err != nil {
			return nil, err
		}

		f = &models.Fqdn{
			ID:             s.ids.fqdns,
			Fqdn:           domain.fqdn,
			ApexID:         a.ID,
			TldID:          a.TldID,
			PublicSuffixID: a.PublicSuffixID,
		}
		s.inserts.fqdns = append(s.inserts.fqdns, f)
		s.fqdnByName[domain.fqdn] = f
		s.ids.fqdns++
	}
	return f, nil
}
