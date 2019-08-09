package store

import "sync"

type Lock struct {
	zoneEntries, apexes, certs, logEntries, fqdns, logs, tlds *sync.Mutex
}

func NewLock() *Lock {
	return &Lock{
		zoneEntries: &sync.Mutex{},
		apexes:      &sync.Mutex{},
		certs:       &sync.Mutex{},
		logEntries:  &sync.Mutex{},
		fqdns:       &sync.Mutex{},
		logs:        &sync.Mutex{},
		tlds:        &sync.Mutex{},
	}
}

func (l *Lock) LockAll() {
	l.zoneEntries.Lock()
	l.apexes.Lock()
	l.certs.Lock()
	l.logEntries.Lock()
	l.fqdns.Lock()
	l.logs.Lock()
	l.tlds.Lock()
}

func (l *Lock) UnlockAll() {
	l.zoneEntries.Unlock()
	l.apexes.Unlock()
	l.certs.Unlock()
	l.logEntries.Unlock()
	l.fqdns.Unlock()
	l.logs.Unlock()
	l.tlds.Unlock()
}
