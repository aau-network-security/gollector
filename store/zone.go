package store

import (
	"github.com/go-pg/pg"
	"time"

	"github.com/aau-network-security/gollector/store/models"
)

func (s *Store) StoreZoneEntry(muid string, t time.Time, fqdn string) (*models.ZonefileEntry, error) {
	s.m.Lock()
	defer s.m.Unlock()

	s.ensureReady()

	sid, ok := s.ms.SId(muid)
	if !ok {
		return nil, NoActiveStageErr
	}

	domain, err := NewDomain(fqdn)
	if err != nil {
		return nil, err
	}

	s.influxService.ZoneCount(domain.tld.normal)

	s.batchEntities.apexByName[domain.apex.normal] = &domainstruct{
		domain: domain,
	}
	s.batchEntities.publicSuffixByName[domain.publicSuffix.normal] = &domainstruct{
		domain: domain,
	}
	s.batchEntities.tldByName[domain.tld.normal] = &domainstruct{
		domain: domain,
	}
	s.batchEntities.zoneEntryByApex[domain.apex.normal] = &zoneentrystruct{
		t:   t,
		sid: sid,
	}
	return nil, nil
}

// get all existing zone entries
func (s *Store) backpropZoneEntries() error {
	if len(s.batchEntities.zoneEntryByApex) == 0 {
		return nil
	}

	// fetch ids from cache
	var zoneEntriesNotFoundInCache []string

	for k := range s.batchEntities.zoneEntryByApex {
		zeI, ok := s.cache.zoneEntriesByApexName.Get(k)
		if !ok {
			zoneEntriesNotFoundInCache = append(zoneEntriesNotFoundInCache, k)
			continue
		}
		s.influxService.StoreHit("cache-hit", "zone-entry", 1)
		ze := zeI.(*models.ZonefileEntry)
		existing := s.batchEntities.zoneEntryByApex[k]
		existing.ze = ze
		s.batchEntities.zoneEntryByApex[k] = existing
	}

	// TODO: enable again when filling of cache works properly
	// the cache is not full yet, so the remaining (cache-miss) tlds cannot be in the database
	//if s.cache.zoneEntriesByApexName.Len() < s.cacheOpts.ZoneEntrySize {
	//	return nil
	//}

	// all entities have been found in the cache, no need to perform a database queries
	if len(zoneEntriesNotFoundInCache) == 0 {
		return nil
	}

	// get IDs of apexes from batch entities
	var apexIdList []uint
	apexIdToName := make(map[uint]string)
	for _, apexStruct := range s.batchEntities.apexByName {
		apex := apexStruct.obj.(*models.Apex)
		apexIdList = append(apexIdList, apex.ID)
		apexIdToName[apex.ID] = apex.Apex
	}

	// fetch zone ids from database
	var zoneEntriesFoundInDB []*models.ZonefileEntry
	if err := s.db.Model(&zoneEntriesFoundInDB).Where("apex_id in (?)", pg.In(apexIdList)).Where("active = true").Select(); err != nil {
		return err
	}

	for _, ze := range zoneEntriesFoundInDB {
		apexName := apexIdToName[ze.ApexID]
		existing := s.batchEntities.zoneEntryByApex[apexName]
		existing.ze = ze
		s.batchEntities.zoneEntryByApex[apexName] = existing
		s.cache.zoneEntriesByApexName.Add(apexName, ze)
	}

	s.influxService.StoreHit("db-hit", "zone-entry", len(zoneEntriesFoundInDB))
	return nil
}

func (s *Store) forpropZoneEntries() {
	for apexName, zeStruct := range s.batchEntities.zoneEntryByApex {
		apexStr := s.batchEntities.apexByName[apexName]
		apex := apexStr.obj.(*models.Apex)

		existing := zeStruct.ze
		t := zeStruct.t
		sid := zeStruct.sid

		if existing == nil {
			// create a new one
			newZoneEntry := &models.ZonefileEntry{
				ID:        s.ids.zoneEntries,
				ApexID:    apex.ID,
				FirstSeen: t,
				LastSeen:  t,
				Active:    true,
				StageID:   sid,
			}
			s.cache.zoneEntriesByApexName.Add(apexName, newZoneEntry)
			s.inserts.zoneEntries[newZoneEntry.ID] = newZoneEntry
			s.ids.zoneEntries++
		} else {
			// update the existing one
			limit := existing.LastSeen.Add(s.allowedInterval)
			if t.After(limit) {
				existing.Active = false
				s.updates.zoneEntries[existing.ID] = existing

				newZoneEntry := &models.ZonefileEntry{
					ID:        s.ids.zoneEntries,
					ApexID:    apex.ID,
					FirstSeen: t,
					LastSeen:  t,
					Active:    true,
					StageID:   sid,
				}
				s.cache.zoneEntriesByApexName.Add(apexName, newZoneEntry)
				s.inserts.zoneEntries[newZoneEntry.ID] = newZoneEntry
				s.ids.zoneEntries++
			} else {
				existing.LastSeen = t
				s.updates.zoneEntries[existing.ID] = existing
			}
		}
	}
}
