package store

import (
	"time"

	"github.com/aau-network-security/gollector/store/models"
)

func (s *Store) StoreZoneEntry(muid string, t time.Time, fqdn string, registered bool) error {
	s.m.Lock()
	defer s.m.Unlock()

	s.ensureReady()

	sid, ok := s.ms.SId(muid)
	if !ok {
		return NoActiveStageErr
	}

	domain, err := NewDomain(fqdn)
	if err != nil {
		return err
	}

	s.influxService.ZoneCount(domain.tld.normal)

	s.batchEntities.apexByName[domain.apex.normal] = &domainstruct{
		create: true,
		domain: domain,
	}
	s.batchEntities.publicSuffixByName[domain.publicSuffix.normal] = &domainstruct{
		create: true,
		domain: domain,
	}
	s.batchEntities.tldByName[domain.tld.normal] = &domainstruct{
		create: true,
		domain: domain,
	}
	ze := &models.ZonefileEntry{
		StageID: sid,
	}
	if registered {
		ze.Registered = t
	} else {
		ze.Expired = t
	}

	s.batchEntities.zoneEntries = append(s.batchEntities.zoneEntries, &zoneentrystruct{
		ze:   ze,
		apex: domain.apex.normal,
	})

	return s.conditionalPostHooks()
}

func (s *Store) forpropZoneEntries() {
	for _, zeStruct := range s.batchEntities.zoneEntries {
		apexStr := s.batchEntities.apexByName[zeStruct.apex]
		apex := apexStr.obj.(*models.Apex)

		zeStruct.ze.ApexID = apex.ID
		s.inserts.zoneEntries = append(s.inserts.zoneEntries, zeStruct.ze)
	}
}
