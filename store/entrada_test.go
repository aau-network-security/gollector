package store

import (
	"github.com/aau-network-security/gollector/store/models"
	"reflect"
	"testing"
	"time"
)

func TestStoreEntradaEntry(t *testing.T) {
	s, g, muid, err := OpenStore(TestConfig, TestOpts)
	if err != nil {
		t.Fatalf("failed to open store: %s", err)
	}
	a := NewAnonymizer(NewSha256LabelAnonymizer())
	s = s.WithAnonymizer(a)

	fqdns := []string{
		"www.example.co.uk",
		"test.example.co.uk",
		"gollector.co.uk",
		"gollector.co.uk",
	}
	for _, fqdn := range fqdns {
		ts := time.Now()
		if err := s.StoreEntradaEntry(muid, fqdn, ts); err != nil {
			t.Fatalf("failed to store ENTRADA entry: %s", err)
		}
	}

	if err := s.RunPostHooks(); err != nil {
		t.Fatalf("failed to run post hooks: %s", err)
	}

	counts := []struct {
		count uint
		model interface{}
	}{
		{1, &models.Tld{}},
		{1, &models.TldAnon{}},
		{1, &models.PublicSuffix{}},
		{1, &models.PublicSuffixAnon{}},
		{2, &models.Apex{}},
		{2, &models.ApexAnon{}},
		{3, &models.Fqdn{}},
		{3, &models.FqdnAnon{}},
		{4, &models.EntradaEntry{}},
	}

	for _, tc := range counts {
		var count uint

		if err := g.Model(tc.model).Count(&count).Error; err != nil {
			t.Fatalf("failed to retrieve model count: %s", err)
		}

		if count != tc.count {
			n := reflect.TypeOf(tc.model)
			t.Fatalf("expected %d %s elements, but got %d", tc.count, n, count)
		}
	}

}
