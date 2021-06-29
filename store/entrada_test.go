package store

import (
	"github.com/aau-network-security/gollector/store/models"
	"reflect"
	"testing"
	"time"
)

func TestStoreEntradaEntry_NonExistingUnanonymized(t *testing.T) {
	s, g, muid, err := OpenStore(TestConfig, TestOpts)
	if err != nil {
		t.Fatalf("failed to open store: %s", err)
	}
	a := NewAnonymizer(
		NewSha256LabelAnonymizer(""),
		NewSha256LabelAnonymizer(""),
		NewSha256LabelAnonymizer(""),
		NewSha256LabelAnonymizer(""),
	)
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
		{0, &models.Tld{}},
		{1, &models.TldAnon{}},
		{0, &models.PublicSuffix{}},
		{1, &models.PublicSuffixAnon{}},
		{0, &models.Apex{}},
		{2, &models.ApexAnon{}},
		{0, &models.Fqdn{}},
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

func TestStoreEntradaEntry_ExistingUnanonymized(t *testing.T) {
	opts := Opts{
		BatchSize: 10,
		CacheOpts: CacheOpts{
			LogSize:       1,
			TLDSize:       1,
			PSuffSize:     1,
			ApexSize:      1,
			FQDNSize:      1,
			CertSize:      1,
			ZoneEntrySize: 1,
		},
		AllowedInterval: 10,
	}
	s, g, muid, err := OpenStore(TestConfig, opts)
	if err != nil {
		t.Fatalf("failed to open store: %s", err)
	}

	// add existing TLD
	tld := &models.Tld{
		ID:  1,
		Tld: "uk",
	}
	if err := g.Create(tld).Error; err != nil {
		t.Fatalf("failed to create TLD: %s", err)
	}
	s.cache.tldByName.Add("uk", tld)
	// add existing public suffix
	psuffix := &models.PublicSuffix{
		ID:           1,
		TldID:        1,
		PublicSuffix: "co.uk",
	}
	if err := g.Create(psuffix).Error; err != nil {
		t.Fatalf("failed to create public suffix: %s", err)
	}
	s.cache.publicSuffixByName.Add("co.uk", psuffix)
	// add existing apex
	apex := &models.Apex{
		ID:             1,
		Apex:           "example.co.uk",
		TldID:          1,
		PublicSuffixID: 1,
	}
	if err := g.Create(apex).Error; err != nil {
		t.Fatalf("failed to create apex: %s", err)
	}
	s.cache.apexByName.Add("exmaple.co.uk", apex)

	a := NewAnonymizer(
		NewSha256LabelAnonymizer(""),
		NewSha256LabelAnonymizer(""),
		NewSha256LabelAnonymizer(""),
		NewSha256LabelAnonymizer(""),
	)
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
		{1, &models.Apex{}},
		{2, &models.ApexAnon{}},
		{0, &models.Fqdn{}},
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
