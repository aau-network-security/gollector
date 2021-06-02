package store

import (
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
		{
			"wildcard domain (1)",
			"*.gov.bn.",
			expected{
				tld:          "bn",
				publicSuffix: "gov.bn",
				apex:         "*.gov.bn",
				fqdn:         "*.gov.bn",
			},
		},
		{
			"wildcard domain (2)",
			"z7*.gov.bn.",
			expected{
				tld:          "bn",
				publicSuffix: "gov.bn",
				apex:         "z7*.gov.bn",
				fqdn:         "z7*.gov.bn",
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
