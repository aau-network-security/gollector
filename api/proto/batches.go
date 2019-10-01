package api

import "errors"

var (
	AssertionErr = errors.New("failed to assert type")
)

func (m *LogEntryBatch) Add(el interface{}) error {
	casted, ok := el.(*LogEntry)
	if !ok {
		return AssertionErr
	}
	m.LogEntries = append(m.LogEntries, casted)
	return nil
}

func (m *EntradaEntryBatch) Add(el interface{}) error {
	casted, ok := el.(*EntradaEntry)
	if !ok {
		return AssertionErr
	}
	m.EntradaEntries = append(m.EntradaEntries, casted)
	return nil
}

func (m *SplunkEntryBatch) Add(el interface{}) error {
	casted, ok := el.(*SplunkEntry)
	if !ok {
		return AssertionErr
	}
	m.SplunkEntries = append(m.SplunkEntries, casted)
	return nil
}

func (m *ZoneEntryBatch) Add(el interface{}) error {
	casted, ok := el.(*ZoneEntry)
	if !ok {
		return AssertionErr
	}
	m.ZoneEntries = append(m.ZoneEntries, casted)
	return nil
}
