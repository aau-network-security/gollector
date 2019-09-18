package store

import (
	"github.com/aau-network-security/go-domains/models"
	"time"
)

func (s *Store) StoreEntradaEntry(fqdn string, t time.Time) (*models.FqdnAnon, error) {
	s.m.Lock()
	defer s.m.Unlock()

	domain, err := NewDomain(fqdn)
	if err != nil {
		return nil, err
	}

	return s.getOrCreateFqdnAnon(domain)
}
