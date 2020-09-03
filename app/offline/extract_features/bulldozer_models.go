package extract_features

type Cert struct {
	ID                uint `gorm:"primary_key" pg:",pk"`
	Fingerprint       string
	Raw               []byte
	DomainID          uint
	AppleWasValid     bool
	NssWasValid       bool
	MicrosoftWasValid bool
	ValidationLevelID uint
}

// all sampled domains
type BulldozerDomain struct {
	ID         uint `gorm:"primary_key" pg:",pk"`
	Fqdn       string
	Tld        string
	Apex       string
	Subdomain  string
	DomainType int64
	IsFqdn     bool
}

type BulldozerValidationLevel struct {
	ID   uint `gorm:"primary_key" pg:",pk"`
	Name string
}
