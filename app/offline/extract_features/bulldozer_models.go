package extract_features

type BulldozerCert struct {
	ID                uint `gorm:"primary_key" pg:",pk"`
	Fingerprint       string
	Raw               []byte
	Domain            *BulldozerDomain
	DomainID          uint
	AppleWasValid     bool
	NssWasValid       bool
	MicrosoftWasValid bool
	ValidationLevel   BulldozerValidationLevel
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
