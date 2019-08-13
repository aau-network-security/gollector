package models

import (
	"time"
)

// ----- BEGIN DOMAIN -----
type Tld struct {
	ID  uint `gorm:"primary_key"`
	Tld string
}

type Apex struct {
	ID    uint `gorm:"primary_key"`
	Apex  string
	TldID uint
}

type Fqdn struct {
	ID     uint `gorm:"primary_key"`
	Fqdn   string
	ApexID uint
}

// ----- END DOMAIN -----

// ----- BEGIN ZONEFILE -----
type ZonefileEntry struct {
	ID        uint `gorm:"primary_key"`
	FirstSeen time.Time
	LastSeen  time.Time
	ApexID    uint
	Active    bool
}

// ----- END ZONEFILE -----

// ----- BEGIN CT -----
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
	Index         uint
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
type PassiveEntry struct {
	ID           uint `gorm:"primary_key"`
	FqdnID       uint
	RecordTypeID uint
	FirstSeen    time.Time
}

type RecordType struct {
	ID   uint `gorm:"primary_key"`
	Type string
}

// ----- END PASSIVE DNS -----
