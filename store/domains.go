package store

import (
	"github.com/aau-network-security/go-domains/models"
	"github.com/pkg/errors"
	"github.com/weppos/publicsuffix-go/net/publicsuffix"
	"strings"
)

func toApex(fqdn string) (string, error) {
	return publicsuffix.EffectiveTLDPlusOne(fqdn)
}

func (s *Store) getOrCreateTld(tld string) (*models.Tld, error) {
	t, ok := s.tldByName[tld]
	if !ok {
		t = &models.Tld{
			ID:  s.ids.tlds,
			Tld: tld,
		}
		if err := s.db.Insert(t); err != nil {
			return nil, errors.Wrap(err, "insert tld")
		}

		s.tldByName[tld] = t
		s.ids.tlds++
	}
	return t, nil
}

func (s *Store) getOrCreateApex(domain string) (*models.Apex, error) {
	res, ok := s.apexByName[domain]
	if !ok {
		splitted := strings.Split(domain, ".")
		if len(splitted) == 1 {
			return nil, InvalidDomainErr{domain}
		}

		tld, err := s.getOrCreateTld(splitted[len(splitted)-1])
		if err != nil {
			return nil, err
		}

		model := &models.Apex{
			ID:    s.ids.apexes,
			Apex:  domain,
			TldID: tld.ID,
		}

		s.apexByName[domain] = model
		s.inserts.apexes[model.ID] = model
		s.ids.apexes++

		res = model
	}
	return res, nil
}

func (s *Store) getOrCreateFqdn(domain string) (*models.Fqdn, error) {
	f, ok := s.fqdnByName[domain]
	if !ok {
		apex, err := toApex(domain)
		if err != nil {
			return nil, err
		}

		a, err := s.getOrCreateApex(apex)
		if err != nil {
			return nil, err
		}

		f = &models.Fqdn{
			ID:     s.ids.fqdns,
			Fqdn:   domain,
			ApexID: a.ID,
		}
		s.inserts.fqdns = append(s.inserts.fqdns, f)
		s.fqdnByName[domain] = f
		s.ids.fqdns++
	}
	return f, nil
}

func (s *Store) storeApexDomain(name string) (*models.Apex, error) {
	splitted := strings.Split(name, ".")
	if len(splitted) == 1 {
		return nil, InvalidDomainErr{name}
	}

	tld, err := s.getOrCreateTld(splitted[len(splitted)-1])
	if err != nil {
		return nil, err
	}

	model := &models.Apex{
		ID:    s.ids.apexes,
		Apex:  name,
		TldID: tld.ID,
	}

	s.apexByName[name] = model
	s.inserts.apexes[model.ID] = model
	s.ids.apexes++

	if err := s.conditionalPostHooks(); err != nil {
		return nil, err
	}

	return model, nil
}
