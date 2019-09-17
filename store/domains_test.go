package store

import (
	"testing"
)

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
			"",
			expected{},
		},
		{
			"tld only",
			"com",
			expected{
				tld:  "com",
				fqdn: "com",
			},
		},
		{
			"suffix only",
			"co.uk",
			expected{
				tld:          "uk",
				publicSuffix: "co.uk",
				fqdn:         "co.uk",
			},
		},
		{
			"apex only",
			"example.co.uk",
			expected{
				tld:          "uk",
				publicSuffix: "co.uk",
				apex:         "example.co.uk",
				fqdn:         "example.co.uk",
			},
		},
		{
			"full fqdn",
			"www.example.co.uk",
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
		func(s string) string {
			return s + "(anon)"
		},
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
