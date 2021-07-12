package store

import (
	"github.com/aau-network-security/gollector/store/models"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	"strings"
	"time"
)

func (s *Store) StoreEntradaEntry(muid string, fqdn string, t time.Time) error {
	s.m.Lock()
	defer s.m.Unlock()

	s.ensureReady()

	sid, ok := s.ms.SId(muid)
	if !ok {
		return NoActiveStageErr
	}

	fqdn = strings.ToLower(fqdn)

	domain, err := NewDomain(fqdn)
	if err != nil {
		return errors.Wrap(err, "failed to create domain")
	}
	s.anonymizer.Anonymize(domain)

	s.batchEntities.fqdnByName[domain.fqdn.normal] = &domainstruct{
		domain: domain,
		create: false,
	}
	s.batchEntities.fqdnByNameAnon[domain.fqdn.anon] = &domainstruct{
		domain: domain,
		create: true,
	}
	s.batchEntities.apexByName[domain.apex.normal] = &domainstruct{
		domain: domain,
		create: false,
	}
	s.batchEntities.apexByNameAnon[domain.apex.anon] = &domainstruct{
		domain: domain,
		create: true,
	}
	s.batchEntities.publicSuffixByName[domain.publicSuffix.normal] = &domainstruct{
		domain: domain,
		create: false,
	}
	s.batchEntities.publicSuffixAnonByName[domain.publicSuffix.anon] = &domainstruct{
		domain: domain,
		create: true,
	}
	s.batchEntities.tldByName[domain.tld.normal] = &domainstruct{
		domain: domain,
		create: false,
	}
	s.batchEntities.tldAnonByName[domain.tld.anon] = &domainstruct{
		domain: domain,
		create: true,
	}

	ee := &entradaentrystruct{
		ee: &models.EntradaEntry{
			FirstSeen: t,
			StageID:   sid,
		},
		fqdn: domain.fqdn.anon,
	}

	s.batchEntities.entradaEntries = append(s.batchEntities.entradaEntries, ee)
	return s.conditionalPostHooks()
}

func (s *Store) forpropEntradaEntries() {
	log.Debug().Msgf("forward propagating entrada entries..")
	for _, ee := range s.batchEntities.entradaEntries {
		fqdnStr, ok := s.batchEntities.fqdnByNameAnon[ee.fqdn]
		if !ok {
			// should not happen?
			log.Error().Msgf("failed to find anonymized fqdn '%s'", ee.fqdn)
			log.Error().Msgf("anonymized fqdns in current entity batch: '%+v'", s.batchEntities.fqdnByNameAnon)
			panic("failure!")
			continue
		}
		fqdnAnon := fqdnStr.obj.(*models.FqdnAnon)

		ee.ee.FqdnID = fqdnAnon.ID

		s.inserts.entradaEntries = append(s.inserts.entradaEntries, ee.ee)
	}
	log.Debug().Msgf("forward propagating entrada entries.. done!")
}

func (s *Store) GetEntradaOffset() (int64, error) {
	var offset int64
	if _, err := s.db.QueryOne(&offset, "SELECT count(distinct(fqdn_id)) FROM entrada_entries"); err != nil {
		return 0, err
	}
	return offset, nil
}
