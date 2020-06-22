package store

import (
	"strings"
	"time"

	"github.com/aau-network-security/gollector/store/models"
)

type splunkEntryMap struct {
	byQueryType map[string]map[string]*models.PassiveEntry
}

func (m *splunkEntryMap) get(query, queryType string) (*models.PassiveEntry, bool) {
	byQType, ok := m.byQueryType[queryType]
	if !ok {
		return nil, false
	}
	res, ok := byQType[query]
	return res, ok
}

func (m *splunkEntryMap) add(query, queryType string, entry *models.PassiveEntry) {
	byQType, ok := m.byQueryType[queryType]
	if !ok {
		byQType = make(map[string]*models.PassiveEntry)
	}
	byQType[query] = entry
	m.byQueryType[queryType] = byQType
}

func (m *splunkEntryMap) len() int {
	sum := 0
	for _, v := range m.byQueryType {
		sum += len(v)
	}
	return sum
}

func newSplunkEntryMap() splunkEntryMap {
	return splunkEntryMap{
		byQueryType: make(map[string]map[string]*models.PassiveEntry),
	}
}

func (s *Store) getorCreateRecordType(rtype string) (*models.RecordType, error) {
	rtI, ok := s.cache.recordTypeByName.Get(rtype)
	//todo implement request to the DB here
	if !ok {
		//rt := &models.RecordType{
		//	ID:   s.ids.recordTypes,
		//	Type: rtype,
		//}
		//if err := s.db.Insert(rt); err != nil {
		//	return nil, errors.Wrap(err, "insert record type")
		//}
		//
		//s.cache.recordTypeByName.Add(rtype, rt)
		//s.ids.recordTypes++
		return nil, nil
	}
	rt := rtI.(*models.RecordType)
	return rt, nil
}

func (s *Store) StorePassiveEntry(muid string, query string, queryType string, t time.Time) (*models.PassiveEntry, error) {
	s.m.Lock()
	defer s.m.Unlock()

	s.ensureReady()

	query = strings.ToLower(query)
	queryType = strings.ToLower(queryType)

	pe, ok := s.cache.passiveEntryByFqdn.get(query, queryType)
	//todo implement request db
	if !ok {
		// create a new entry
		sid, ok := s.ms.SId(muid)
		if !ok {
			return nil, NoActiveStageErr
		}

		domain, err := NewDomain(query)
		if err != nil {
			return nil, err
		}

		fqdn, err := s.getOrCreateFqdn(domain)
		if err != nil {
			return nil, err
		}

		rt, err := s.getorCreateRecordType(queryType)
		if err != nil {
			return nil, err
		}

		pe = &models.PassiveEntry{
			FqdnID:       fqdn.ID,
			FirstSeen:    t,
			RecordTypeID: rt.ID,
			StageID:      sid,
		}

		s.cache.passiveEntryByFqdn.add(query, queryType, pe)
		s.inserts.passiveEntries = append(s.inserts.passiveEntries, pe)
	} else if t.Before(pe.FirstSeen) {
		// see if we must update the existing one
		pe.FirstSeen = t
		s.updates.passiveEntries = append(s.updates.passiveEntries, pe)
	}

	return pe, nil
}
