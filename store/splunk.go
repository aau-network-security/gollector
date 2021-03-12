package store

import (
	"github.com/aau-network-security/gollector/store/models"
	"github.com/rs/zerolog/log"
)

func (s *Store) forpropPassiveEntries() {
	log.Debug().Msgf("forward propagating passive entries..")
	for _, pe := range s.batchEntities.passiveEntries {
		fqdnStr := s.batchEntities.fqdnByName[pe.fqdn]
		fqdn := fqdnStr.obj.(*models.Fqdn)

		pe.pe.FqdnID = fqdn.ID
		s.inserts.passiveEntries = append(s.inserts.passiveEntries, pe.pe)
	}
	log.Debug().Msgf("forward propagating passive entries.. done!")
}
