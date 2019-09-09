package store

import (
	"gotest.tools/assert/cmp"
	"testing"
)

func TestNewDomain(t *testing.T) {
	tests := []struct {
		name     string
		fqdn     string
		expected domain
	}{
		{
			"empty",
			"",
			domain{},
		},
		{
			"tld only",
			"com",
			domain{
				tld:  "com",
				fqdn: "com",
			},
		},
		{
			"suffix only",
			"co.uk",
			domain{
				tld:          "uk",
				publicSuffix: "co.uk",
				fqdn:         "co.uk",
			},
		},
		{
			"apex only",
			"example.co.uk",
			domain{
				tld:          "uk",
				publicSuffix: "co.uk",
				apex:         "example.co.uk",
				fqdn:         "example.co.uk",
			},
		},
		{
			"full fqdn",
			"www.example.co.uk",
			domain{
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
			if !cmp.Equal(*actual, test.expected)().Success() {
				t.Fatalf("expected %v, but got %v", test.expected, *actual)
			}
		})
	}
}
