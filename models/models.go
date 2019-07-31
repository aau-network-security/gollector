package models

import (
	"time"
)

type Apex struct {
	ID   uint `gorm:"primary_key"`
	Apex string
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
