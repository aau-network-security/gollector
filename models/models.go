package models

import (
	"time"
)

type Tld struct {
	ID  uint `gorm:"primary_key"`
	Tld string
}

// ----- BEGIN ZONEFILE -----
type Apex struct {
	ID    uint `gorm:"primary_key"`
	Apex  string
	TldID uint
}

type ZonefileEntry struct {
	ID        uint `gorm:"primary_key"`
	FirstSeen time.Time
	LastSeen  time.Time
	ApexID    uint
	Active    bool
}

// ----- END ZONEFILE -----

// ----- BEGIN CT -----
type Fqdn struct {
	ID     uint `gorm:"primary_key"`
	Fqdn   string
	ApexID uint
}

type CertificateToFqdn struct {
	ID            uint `gorm:"primary_key"`
	FqdnID        uint
	CertificateID uint
}

type Certificate struct {
	ID                uint `gorm:"primary_key"`
	Sha256Fingerprint string
}

type LogEntry struct {
	ID            uint `gorm:"primary_key"`
	Timestamp     time.Time
	CertificateID uint
	LogID         uint
}

type Log struct {
	ID          uint `gorm:"primary_key"`
	Url         string
	Description string
}

// ----- END CT -----

// ----- BEGIN PASSIVE DNS -----
// ----- END PASSIVE DNS -----
