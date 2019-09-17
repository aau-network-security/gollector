package store

import (
	"github.com/aau-network-security/go-domains/models"
	"time"
)

func (s *Store) StoreZoneEntry(t time.Time, fqdn string) (*models.ZonefileEntry, error) {
	s.m.Lock()
	defer s.m.Unlock()

	domain, err := NewDomain(fqdn)
	if err != nil {
		return nil, err
	}

	apex, err := s.getOrCreateApex(domain)
	if err != nil {
		return nil, err
	}

	existingZoneEntry, ok := s.zoneEntriesByApexName[apex.Apex]
	if !ok {
		// non-active domain, create a new zone entry
		newZoneEntry := &models.ZonefileEntry{
			ID:        s.ids.zoneEntries,
			ApexID:    apex.ID,
			FirstSeen: t,
			LastSeen:  t,
			Active:    true,
			StageID:   s.curStage.ID,
		}

		s.zoneEntriesByApexName[apex.Apex] = newZoneEntry
		s.inserts.zoneEntries[newZoneEntry.ID] = newZoneEntry
		s.ids.zoneEntries++

		if err := s.conditionalPostHooks(); err != nil {
			return nil, err
		}

		return newZoneEntry, nil
	}

	// active domain
	if existingZoneEntry.LastSeen.Before(time.Now().Add(-s.allowedInterval)) {
		// detected re-registration, set old entry inactive and create new

		existingZoneEntry.Active = false
		s.updates.zoneEntries[existingZoneEntry.ID] = existingZoneEntry

		newZoneEntry := &models.ZonefileEntry{
			ID:        s.ids.zoneEntries,
			ApexID:    apex.ID,
			FirstSeen: t,
			LastSeen:  t,
			Active:    true,
			StageID:   s.curStage.ID,
		}

		s.zoneEntriesByApexName[apex.Apex] = newZoneEntry
		s.inserts.zoneEntries[newZoneEntry.ID] = newZoneEntry
		s.ids.zoneEntries++

		if err := s.conditionalPostHooks(); err != nil {
			return nil, err
		}

		return newZoneEntry, nil
	}

	// update existing
	existingZoneEntry.LastSeen = t
	s.updates.zoneEntries[existingZoneEntry.ID] = existingZoneEntry

	if err := s.conditionalPostHooks(); err != nil {
		return nil, err
	}

	return existingZoneEntry, nil
}
