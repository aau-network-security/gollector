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
	Apex   Apex
	ApexID uint
}

type ZonefileEntry struct {
	ID        uint `gorm:"primary_key"`
	FirstSeen time.Time
	LastSeen  time.Time
	Apex      Apex
	ApexID    uint
	Active    bool
}
