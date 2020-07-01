package store

import (
	"time"

	"github.com/aau-network-security/gollector/store/models"
)

func (s *Store) getStoreZoneEntryFromCacheOrDB(apex *models.Apex) (*models.ZonefileEntry, error) {
	existingZEI, ok := s.cache.zoneEntriesByApexName.Get(apex.Apex)
	if !ok {
		if s.cache.zoneEntriesByApexName.Len() < s.cacheOpts.ApexSize {
			return nil, cacheNotFull
		}
		var ze models.ZonefileEntry
		if err := s.db.Model(&ze).Where("apex_id = ?", apex.ID).First(); err != nil {
			return nil, err
		}
		return &ze, nil //It is in DB
	}
	existingZE := existingZEI.(*models.ZonefileEntry)
	return existingZE, nil
}

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

	apex, err := s.getOrCreateApex(domain)
	if err != nil {
		return nil, err
	}

	existingZE, err := s.getStoreZoneEntryFromCacheOrDB(apex)
	if err != nil {
		// non-active domain, create a new zone entry
		newZoneEntry := &models.ZonefileEntry{
			ID:        s.ids.zoneEntries,
			ApexID:    apex.ID,
			FirstSeen: t,
			LastSeen:  t,
			Active:    true,
			StageID:   sid,
		}

		s.cache.zoneEntriesByApexName.Add(apex.Apex, newZoneEntry)
		s.inserts.zoneEntries[newZoneEntry.ID] = newZoneEntry
		s.ids.zoneEntries++

		if err := s.conditionalPostHooks(); err != nil {
			return nil, err
		}

		return newZoneEntry, nil
	}
	limit := existingZE.LastSeen.Add(s.allowedInterval)
	if t.After(limit) {
		// detected re-registration, set old entry inactive and create new

		existingZE.Active = false
		s.updates.zoneEntries[existingZE.ID] = existingZE

		newZE := &models.ZonefileEntry{
			ID:        s.ids.zoneEntries,
			ApexID:    apex.ID,
			FirstSeen: t,
			LastSeen:  t,
			Active:    true,
			StageID:   sid,
		}

		s.cache.zoneEntriesByApexName.Add(apex.Apex, newZE)
		s.inserts.zoneEntries[newZE.ID] = newZE
		s.ids.zoneEntries++

		if err := s.conditionalPostHooks(); err != nil {
			return nil, err
		}

		return newZE, nil
	}

	// update existing
	existingZE.LastSeen = t
	s.updates.zoneEntries[existingZE.ID] = existingZE

	if err := s.conditionalPostHooks(); err != nil {
		return nil, err
	}

	return existingZE, nil
}
