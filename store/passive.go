package store

import (
	"strings"
	"time"

	"github.com/aau-network-security/gollector/store/models"
)

func (s *Store) StorePassiveEntry(muid string, query string, t time.Time) (*models.PassiveEntry, error) {
	s.m.Lock()
	defer s.m.Unlock()

	s.ensureReady()

	sid, ok := s.ms.SId(muid)
	if !ok {
		return nil, NoActiveStageErr
	}

	query = strings.ToLower(query)

	domain, err := NewDomain(query)
	if err != nil {
		return nil, err
	}
	s.batchEntities.fqdnByName[domain.fqdn.normal] = &domainstruct{
		domain: domain,
	}
	s.batchEntities.apexByName[domain.apex.normal] = &domainstruct{
		domain: domain,
	}
	s.batchEntities.publicSuffixByName[domain.publicSuffix.normal] = &domainstruct{
		domain: domain,
	}
	s.batchEntities.tldByName[domain.tld.normal] = &domainstruct{
		domain: domain,
	}

	pe := &passiveentrystruct{
		pe: &models.PassiveEntry{
			Timestamp: t,
			StageID:   sid,
		},
		fqdn: query,
	}

	s.batchEntities.passiveEntries = append(s.batchEntities.passiveEntries, pe)
	return pe.pe, nil
}
