package models

import "time"

type Apex struct {
	Id           int64 // pk
	PublicSuffix string
	Root         string
}

func (a *Apex) Equals(other Apex) bool {
	return a.PublicSuffix == other.PublicSuffix && a.Root == other.Root
}

type Subdomain struct {
	Id     int64 // pk
	Sub    string
	ApexId int64 // fk
}

type Zone struct {
	Id   int64
	Name string
}

type ZoneEntry struct {
	Id        int64
	FirstSeen *time.Time
	LastSeen  *time.Time
	ApexId    int64 // fk
	ZoneId    int64 // fk
}
