package store

import (
	prt "github.com/aau-network-security/gollector/api/proto"
	"time"

	"github.com/aau-network-security/gollector/store/models"
)

func (s *Store) StoreZoneEntry(muid string, t time.Time, fqdn string, zoneEntryType prt.ZoneEntry_ZoneEntryType) error {
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
	s.anonymizer.Anonymize(domain)

	s.influxService.ZoneCount(domain.tld.normal)

	s.batchEntities.AddApex(domain, false)

	ze := &models.ZonefileEntry{
		StageID: sid,
	}
	if zoneEntryType == prt.ZoneEntry_EXPIRATION {
		ze.Expired = t
	} else if zoneEntryType == prt.ZoneEntry_REGISTRATION {
		ze.Registered = t
	} else if zoneEntryType == prt.ZoneEntry_FIRST_SEEN {
		// don't fill in any of the timestamp
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
