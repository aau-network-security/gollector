package store

import (
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	"strings"
	"time"

	"github.com/aau-network-security/gollector/store/models"
)

func (s *Store) StorePassiveEntry(muid string, query string, t time.Time) error {
	s.m.Lock()
	defer s.m.Unlock()

	s.ensureReady()

	sid, ok := s.ms.SId(muid)
	if !ok {
		return NoActiveStageErr
	}

	query = strings.ToLower(query)
	domain, err := NewDomain(query)
	if err != nil {
		return errors.Wrap(err, "failed to create domain")
	}
	s.anonymizer.Anonymize(domain)

	s.batchEntities.AddFqdn(domain, false)

	pe := &passiveentrystruct{
		pe: &models.PassiveEntry{
			Timestamp: t,
			StageID:   sid,
		},
		fqdn: query,
	}

	s.batchEntities.passiveEntries = append(s.batchEntities.passiveEntries, pe)
	return s.conditionalPostHooks()
}

func (s *Store) forpropPassiveEntries() {
	log.Debug().Msgf("forward propagating passive entries..")
	for _, pe := range s.batchEntities.passiveEntries {
		fqdnStr, ok := s.batchEntities.fqdnByName[pe.fqdn]
		if !ok {
			log.Warn().Msgf("failed to find fqdn id for passive entry for fqdn '%s': skipping", pe.fqdn)
			continue
		}
		fqdn := fqdnStr.obj.(*models.Fqdn)

		pe.pe.FqdnID = fqdn.ID
		s.inserts.passiveEntries = append(s.inserts.passiveEntries, pe.pe)
	}
	log.Debug().Msgf("forward propagating passive entries.. done!")
}
