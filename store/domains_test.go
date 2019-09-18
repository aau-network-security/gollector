package store

import (
	"github.com/aau-network-security/go-domains/models"
	"testing"
)

type TestLabelAnonymizer struct{}

func (la *TestLabelAnonymizer) AnonymizeLabel(s string) string {
	return s + "(anon)"
}

type expected struct {
	tld, publicSuffix, apex, fqdn string
}

func (exp *expected) Equals(d *domain) bool {
	return d.tld.normal == exp.tld &&
		d.publicSuffix.normal == exp.publicSuffix &&
		d.apex.normal == exp.apex &&
		d.fqdn.normal == exp.fqdn
}

func TestNewDomain(t *testing.T) {
	tests := []struct {
		name     string
		fqdn     string
		expected expected
	}{
		{
			"empty",
			".",
			expected{
				tld:          "",
				publicSuffix: "",
				apex:         "",
				fqdn:         "",
			},
		},
		{
			"tld only",
			"com.",
			expected{
				tld:          "com",
				publicSuffix: "com",
				apex:         "com",
				fqdn:         "com",
			},
		},
		{
			"suffix only",
			"co.uk.",
			expected{
				tld:          "uk",
				publicSuffix: "co.uk",
				apex:         "co.uk",
				fqdn:         "co.uk",
			},
		},
		{
			"apex only",
			"example.co.uk.",
			expected{
				tld:          "uk",
				publicSuffix: "co.uk",
				apex:         "example.co.uk",
				fqdn:         "example.co.uk",
			},
		},
		{
			"full fqdn",
			"www.example.co.uk.",
			expected{
				tld:          "uk",
				publicSuffix: "co.uk",
				apex:         "example.co.uk",
				fqdn:         "www.example.co.uk",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual, err := NewDomain(test.fqdn)
			if err != nil {
				t.Fatalf("unexpected error while parsing fqdn: %s", err)
			}
			if !test.expected.Equals(actual) {
				t.Fatalf("expected %v, but got %v", test.expected, *actual)
			}
		})
	}
}

func TestAnonymizer(t *testing.T) {
	a := Anonymizer{
		la: &TestLabelAnonymizer{},
	}
	d := domain{
		tld:          newLabel("a"),
		publicSuffix: newLabel("b"),
		apex:         newLabel("c"),
		fqdn:         newLabel("d"),
	}
	a.Anonymize(&d)

	if d.tld.anon != "a(anon)" ||
		d.publicSuffix.anon != "b(anon)" ||
		d.apex.anon != "c(anon)" ||
		d.fqdn.anon != "d(anon)" {
		t.Fatalf("failed to anonymize domain")
	}
}

// check for correct creation of all db models for an anon fqdn when no unanon fqdn exists
func TestGetOrCreateFqdnAnon_NoUnanon(t *testing.T) {
	conf := Config{
		User:     "postgres",
		Password: "postgres",
		DBName:   "domains",
		Host:     "localhost",
		Port:     10001,
	}

	s, g, err := openStore(conf)
	if err != nil {
		t.Fatalf("failed to open store: %s", err)
	}

	domain, err := NewDomain("www.example.co.uk")
	if err != nil {
		t.Fatalf("failed to created new domain: %s", err)
	}
	anonymizer := Anonymizer{
		la: &TestLabelAnonymizer{},
	}
	s = s.WithAnonymizer(&anonymizer)

	if _, err := s.getOrCreateFqdnAnon(domain); err != nil {
		t.Fatalf("failed to create anon fqdn: %s", err)
	}

	if err := s.RunPostHooks(); err != nil {
		t.Fatalf("failed to run store post hooks: %s", err)
	}

	// check that anon tld is in db, and has no reference to an unanon tld
	var tldAnon models.TldAnon
	if err := g.First(&tldAnon).Error; err != nil {
		t.Fatalf("failed to retrieve anon tld from db: %s", err)
	}

	if tldAnon.TldID != 0 {
		t.Fatalf("expected reference to tld to be %d, but is %d", 0, tldAnon.TldID)
	}

	// check that anon suffix is in db, and has no reference to an unanon suffix
	var suffixAnon models.PublicSuffixAnon
	if err := g.First(&suffixAnon).Error; err != nil {
		t.Fatalf("failed to retrieve anon suffix from db: %s", err)
	}

	if suffixAnon.PublicSuffixID != 0 {
		t.Fatalf("expected reference to suffix to be %d, but is %d", 0, suffixAnon.TldID)
	}

	// check that anon suffix is in db, and has no reference to an unanon suffix
	var apexAnon models.ApexAnon
	if err := g.First(&apexAnon).Error; err != nil {
		t.Fatalf("failed to retrieve anon apex from db: %s", err)
	}

	if apexAnon.ApexID != 0 {
		t.Fatalf("expected reference to apex to be %d, but is %d", 0, apexAnon.ApexID)
	}

	// check that anon suffix is in db, and has no reference to an unanon suffix
	var fqdnAnon models.FqdnAnon
	if err := g.First(&fqdnAnon).Error; err != nil {
		t.Fatalf("failed to retrieve anon fqdn from db: %s", err)
	}

	if fqdnAnon.FqdnID != 0 {
		t.Fatalf("expected reference to fqdn to be %d, but is %d", 0, fqdnAnon.FqdnID)
	}
}

// check for correct creation of all db models for an unanon fqdn when no anon fqdn exists
func TestGetOrCreateFqdn_NoUnanon(t *testing.T) {
	conf := Config{
		User:     "postgres",
		Password: "postgres",
		DBName:   "domains",
		Host:     "localhost",
		Port:     10001,
	}

	s, g, err := openStore(conf)
	if err != nil {
		t.Fatalf("failed to open store: %s", err)
	}

	domain, err := NewDomain("www.example.co.uk")
	if err != nil {
		t.Fatalf("failed to created new domain: %s", err)
	}
	anonymizer := Anonymizer{
		la: &TestLabelAnonymizer{},
	}
	s = s.WithAnonymizer(&anonymizer)

	if _, err := s.getOrCreateFqdn(domain); err != nil {
		t.Fatalf("failed to create anon fqdn: %s", err)
	}

	if err := s.RunPostHooks(); err != nil {
		t.Fatalf("failed to run store post hooks: %s", err)
	}

	// check that models are in db, with correct references to each other
	var fqdn models.Fqdn
	if err := g.First(&fqdn).Error; err != nil {
		t.Fatalf("failed to retrieve fqdn from db: %s", err)
	}
	var apex models.Apex
	if err := g.First(&apex).Error; err != nil {
		t.Fatalf("failed to retrieve apex from db: %s", err)
	}
	var suffix models.PublicSuffix
	if err := g.First(&suffix).Error; err != nil {
		t.Fatalf("failed to retrieve suffix from db: %s", err)
	}
	var tld models.Tld
	if err := g.First(&tld).Error; err != nil {
		t.Fatalf("failed to retrieve tld from db: %s", err)
	}

	if fqdn.TldID != tld.ID || fqdn.PublicSuffixID != suffix.ID || fqdn.ApexID != apex.ID {
		t.Fatalf("invalid model references for fqdn")
	}

	if apex.TldID != tld.ID || apex.PublicSuffixID != suffix.ID {
		t.Fatalf("invalid model references for apex")
	}
	if suffix.TldID != tld.ID {
		t.Fatalf("invalid model references for suffix")
	}
}

// check for correct creation of all db models for an unanon fqdn when anon fqdn exists
func TestGetOrCreateFqdn_WithUnanon(t *testing.T) {
	conf := Config{
		User:     "postgres",
		Password: "postgres",
		DBName:   "domains",
		Host:     "localhost",
		Port:     10001,
	}

	// create an anonymized domain
	s, g, err := openStore(conf)
	if err != nil {
		t.Fatalf("failed to open store: %s", err)
	}

	domain, err := NewDomain("www.example.co.uk")
	if err != nil {
		t.Fatalf("failed to created new domain: %s", err)
	}
	anonymizer := Anonymizer{
		la: &TestLabelAnonymizer{},
	}
	s = s.WithAnonymizer(&anonymizer)

	if _, err := s.getOrCreateFqdnAnon(domain); err != nil {
		t.Fatalf("failed to create anon fqdn: %s", err)
	}

	// create un-anonymized domains
	if _, err := s.getOrCreateFqdn(domain); err != nil {
		t.Fatalf("failed to create fqdn: %s", err)
	}

	if err := s.RunPostHooks(); err != nil {
		t.Fatalf("failed to run store post hooks: %s", err)
	}

	// check that anon tld is in db, and now has a reference to an unanon tld
	var tldAnon models.TldAnon
	if err := g.First(&tldAnon).Error; err != nil {
		t.Fatalf("failed to retrieve anon tld from db: %s", err)
	}

	if tldAnon.TldID != 1 {
		t.Fatalf("expected reference to tld to be %d, but is %d", 1, tldAnon.TldID)
	}

	// check that anon suffix is in db, and now has a reference to an unanon suffix
	var suffixAnon models.PublicSuffixAnon
	if err := g.First(&suffixAnon).Error; err != nil {
		t.Fatalf("failed to retrieve anon suffix from db: %s", err)
	}

	if suffixAnon.PublicSuffixID != 1 {
		t.Fatalf("expected reference to suffix to be %d, but is %d", 1, suffixAnon.TldID)
	}

	// check that anon suffix is in db, and now has a reference to an unanon suffix
	var apexAnon models.ApexAnon
	if err := g.First(&apexAnon).Error; err != nil {
		t.Fatalf("failed to retrieve anon apex from db: %s", err)
	}

	if apexAnon.ApexID != 1 {
		t.Fatalf("expected reference to apex to be %d, but is %d", 1, apexAnon.ApexID)
	}

	// check that anon suffix is in db, and now has a reference to an unanon suffix
	var fqdnAnon models.FqdnAnon
	if err := g.First(&fqdnAnon).Error; err != nil {
		t.Fatalf("failed to retrieve anon fqdn from db: %s", err)
	}

	if fqdnAnon.FqdnID != 1 {
		t.Fatalf("expected reference to fqdn to be %d, but is %d", 1, fqdnAnon.FqdnID)
	}
}

// check for correct creation of all db models for an anon fqdn when unanon fqdn exists
func TestGetOrCreateFqdnAnon_WithUnanon(t *testing.T) {
	conf := Config{
		User:     "postgres",
		Password: "postgres",
		DBName:   "domains",
		Host:     "localhost",
		Port:     10001,
	}

	// create an unanon domain
	s, g, err := openStore(conf)
	if err != nil {
		t.Fatalf("failed to open store: %s", err)
	}

	domain, err := NewDomain("www.example.co.uk")
	if err != nil {
		t.Fatalf("failed to created new domain: %s", err)
	}
	anonymizer := Anonymizer{
		la: &TestLabelAnonymizer{},
	}
	s = s.WithAnonymizer(&anonymizer)

	if _, err := s.getOrCreateFqdn(domain); err != nil {
		t.Fatalf("failed to create fqdn: %s", err)
	}

	// create anonymized domains
	if _, err := s.getOrCreateFqdnAnon(domain); err != nil {
		t.Fatalf("failed to create anon fqdn: %s", err)
	}

	if err := s.RunPostHooks(); err != nil {
		t.Fatalf("failed to run store post hooks: %s", err)
	}

	// check that anon tld is in db, and now has a reference to an unanon tld
	var tldAnon models.TldAnon
	if err := g.First(&tldAnon).Error; err != nil {
		t.Fatalf("failed to retrieve anon tld from db: %s", err)
	}

	if tldAnon.TldID != 1 {
		t.Fatalf("expected reference to tld to be %d, but is %d", 1, tldAnon.TldID)
	}

	// check that anon suffix is in db, and now has a reference to an unanon suffix
	var suffixAnon models.PublicSuffixAnon
	if err := g.First(&suffixAnon).Error; err != nil {
		t.Fatalf("failed to retrieve anon suffix from db: %s", err)
	}

	if suffixAnon.PublicSuffixID != 1 {
		t.Fatalf("expected reference to suffix to be %d, but is %d", 1, suffixAnon.TldID)
	}

	// check that anon suffix is in db, and now has a reference to an unanon suffix
	var apexAnon models.ApexAnon
	if err := g.First(&apexAnon).Error; err != nil {
		t.Fatalf("failed to retrieve anon apex from db: %s", err)
	}

	if apexAnon.ApexID != 1 {
		t.Fatalf("expected reference to apex to be %d, but is %d", 1, apexAnon.ApexID)
	}

	// check that anon suffix is in db, and now has a reference to an unanon suffix
	var fqdnAnon models.FqdnAnon
	if err := g.First(&fqdnAnon).Error; err != nil {
		t.Fatalf("failed to retrieve anon fqdn from db: %s", err)
	}

	if fqdnAnon.FqdnID != 1 {
		t.Fatalf("expected reference to fqdn to be %d, but is %d", 1, fqdnAnon.FqdnID)
	}
}
