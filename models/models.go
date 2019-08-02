package models

import (
	"time"
)

type Tld struct {
	ID  uint `gorm:"primary_key"`
	Tld string
}

type Apex struct {
	ID    uint `gorm:"primary_key"`
	Apex  string
	TldID uint
}

type Subdomain struct {
	ID     uint `gorm:"primary_key"`
	Sub    string
	ApexID uint
}

type ZonefileEntry struct {
	ID        uint `gorm:"primary_key"`
	FirstSeen time.Time
	LastSeen  time.Time
	ApexID    uint
	Active    bool
}
