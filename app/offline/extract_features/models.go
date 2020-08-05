package extract_features

import (
	"database/sql"
	"time"
)

type Features struct {
	//Domain features
	CertID          uint `gorm:"primary_key" pg:",pk"`
	IssuerID        int
	Algo            string
	Country         string        // Subject
	ValidationLevel sql.NullInt64 // dv/ov/ev
	NotBefore       *time.Time
	NotAfter        *time.Time
	ValidityPeriod  int

	//Sans features
	DomainCount         int
	UniqueApexCount     int
	UniqueSldCount      int
	ShortestDomain      sql.NullInt64
	LongestDomain       sql.NullInt64
	MeanDomainLength    sql.NullFloat64
	MinSubLabels        sql.NullInt64
	MaxSubLabels        sql.NullInt64
	MeanSubLabels       sql.NullFloat64
	UniqueTlds          int // normalized for number of domains
	UniqueTldsPerDomain sql.NullFloat64
	ApexLCS             string        // longest common substring (LCS) among apex part of all covered domains, normalized according to shortest apex
	LenApexLcs          sql.NullInt64 // length of LCS
	LenApexLcsNorm      sql.NullFloat64
}

type Issuer struct {
	ID         int `gorm:"primary_key" pg:",pk"`
	Name       string
	Popularity sql.NullFloat64
}
