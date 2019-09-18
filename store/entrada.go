package store

import (
	"github.com/aau-network-security/go-domains/models"
	"github.com/pkg/errors"
	"time"
)

func (s *Store) StoreEntradaEntry(fqdn string, t time.Time) (*models.EntradaEntry, error) {
	s.m.Lock()
	defer s.m.Unlock()

	domain, err := NewDomain(fqdn)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create domain")
	}

	fqdnAnon, err := s.getOrCreateFqdnAnon(domain)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get or create anon fqdn")
	}

	entry := &models.EntradaEntry{
		FirstSeen: t,
		FqdnID:    fqdnAnon.ID,
		StageID:   s.curStage.ID,
	}

	s.inserts.entradaEntries = append(s.inserts.entradaEntries, entry)

	return entry, nil
}
