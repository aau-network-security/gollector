package models

import (
	"time"
)

// ----- BEGIN DOMAIN -----

type Tld struct {
	ID  uint `gorm:"primary_key" pg:",pk"`
	Tld string
}

type PublicSuffix struct {
	ID           uint `gorm:"primary_key" pg:",pk"`
	TldID        uint
	PublicSuffix string
}

type Apex struct {
	ID             uint   `gorm:"primary_key" pg:",pk"`
	Apex           string `gorm:"index"`
	TldID          uint
	PublicSuffixID uint
}

type Fqdn struct {
	ID             uint   `gorm:"primary_key" pg:",pk"`
	Fqdn           string `gorm:"index"`
	TldID          uint
	PublicSuffixID uint
	ApexID         uint
}

type TldAnon struct {
	Tld
	tableName struct{} `sql:"tlds_anon"`
	TldID     uint
}

func (TldAnon) TableName() string {
	return "tlds_anon"
}

type PublicSuffixAnon struct {
	PublicSuffix
	tableName      struct{} `sql:"public_suffixes_anon"`
	PublicSuffixID uint
}

func (t PublicSuffixAnon) TableName() string {
	return "public_suffixes_anon"
}

type ApexAnon struct {
	Apex
	tableName struct{} `sql:"apexes_anon"`
	ApexID    uint
}

func (t ApexAnon) TableName() string {
	return "apexes_anon"
}

type FqdnAnon struct {
	Fqdn
	tableName struct{} `sql:"fqdns_anon"`
	FqdnID    uint
}

func (t FqdnAnon) TableName() string {
	return "fqdns_anon"
}

// ----- END DOMAIN -----

// ----- BEGIN ZONEFILE -----
type ZonefileEntry struct {
	ID         uint `gorm:"primary_key" pg:",pk"`
	Registered time.Time
	Expired    time.Time
	ApexID     uint `gorm:"index"`
	StageID    uint
}

// ----- END ZONEFILE -----

// ----- BEGIN CT -----
type CertificateToFqdn struct {
	ID            uint `gorm:"primary_key" pg:",pk"`
	FqdnID        uint
	CertificateID uint
}

type Certificate struct {
	ID                uint   `gorm:"primary_key" pg:",pk"`
	Sha256Fingerprint string `gorm:"index"`
	Raw               []byte `gorm:"type:bytea"`
}

type LogEntry struct {
	ID            uint `gorm:"primary_key" pg:",pk"`
	Index         uint
	Timestamp     time.Time
	IsPrecert     bool
	CertificateID uint
	LogID         uint
	StageID       uint
}

type Log struct {
	ID          uint `gorm:"primary_key" pg:",pk"`
	Url         string
	Description string
}

// ----- END CT -----

// ----- BEGIN PASSIVE DNS -----
type PassiveEntry struct {
	ID        uint `gorm:"primary_key" pg:",pk"`
	FqdnID    uint
	Timestamp time.Time
	StageID   uint
}

type EntradaEntry struct {
	ID        uint `gorm:"primary_key" pg:",pk"`
	FqdnID    uint
	FirstSeen time.Time
	LastSeen  time.Time
	StageID   uint
}

type RecordType struct {
	ID   uint `gorm:"primary_key" pg:",pk"`
	Type string
}

// ----- END PASSIVE DNS -----

// ----- BEGIN MEASUREMENT -----

// Meta information for invidual measurements
type Measurement struct {
	ID          uint `gorm:"primary_key" pg:",pk"`
	Muid        string
	Description string
	Host        string
	StartTime   time.Time
	EndTime     time.Time
	Stage       uint `sql:"-"`
}

// An individual measurement can repeat a single stage multiple times
type Stage struct {
	ID            uint `gorm:"primary_key" pg:",pk"`
	MeasurementID uint
	Stage         uint
	StartTime     time.Time
	StopTime      time.Time
}

// ----- END MEASUREMENT -----
