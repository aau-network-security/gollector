package store

import (
	"github.com/aau-network-security/gollector/collectors/ct"
	"github.com/aau-network-security/gollector/store/models"
	"github.com/google/certificate-transparency-go/x509"
	"testing"
	"time"
)

func TestStore_StoreLogEntry(t *testing.T) {
	conf := Config{
		User:     "postgres",
		Password: "postgres",
		DBName:   "domains",
		Host:     "localhost",
		Port:     10001,
	}

	s, g, muid, err := OpenStore(conf)
	if err != nil {
		t.Fatalf("failed to create store: %s", err)
	}

	sanLists := [][]string{
		{
			"www.a.com",
			"www.b.com",
		},
		{
			"mail.a.com",
			"www.c.com",
		},
	}
	for _, sanList := range sanLists {
		now := time.Now()
		raw, err := selfSignedCert(now, now, sanList)
		if err != nil {
			t.Fatalf("unexpected error while creating self-signed certificate: %s", err)
		}

		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			t.Fatalf("unexpected error while parsing certificate: %s", err)
		}

		le := LogEntry{
			Cert:  cert,
			Index: 1,
			Log:   ct.Log{},
			Ts:    now,
		}

		if err := s.StoreLogEntry(muid, le); err != nil {
			t.Fatalf("unexpected error while storing log entry: %s", err)
		}
	}
	if err := s.RunPostHooks(); err != nil {
		t.Fatalf("unexpected error while running post hooks: %s", err)
	}

	// test for correct entry count in database
	counts := []struct {
		count uint
		model interface{}
	}{
		{1, &models.Tld{}},
		{1, &models.PublicSuffix{}},
		{3, &models.Apex{}},
		{4, &models.Fqdn{}},
		{4, &models.CertificateToFqdn{}},
		{2, &models.Certificate{}},
		{2, &models.LogEntry{}},
	}

	for _, tc := range counts {
		var count uint
		if err := g.Model(tc.model).Count(&count).Error; err != nil {
			t.Fatalf("failed to retrieve apex count: %s", err)
		}

		if count != tc.count {
			t.Fatalf("expected %d elements, but got %d", tc.count, count)
		}
	}

	// check initialization of new store
	opts := Opts{
		BatchSize:       10,
		AllowedInterval: 10 * time.Millisecond,
	}

	s, err = NewStore(conf, opts)
	if err != nil {
		t.Fatalf("failed to create store: %s", err)
	}
	s.Ready.Wait()

	comparisons := []struct {
		name             string
		actual, expected int
	}{
		{
			"fqdnByName",
			len(s.cache.fqdnByName),
			4,
		},
		{
			"apexByName",
			len(s.cache.apexByName),
			3,
		},
		{
			"certByFingerprint",
			len(s.cache.certByFingerprint),
			2,
		},
		{
			"logByUrl",
			len(s.cache.logByUrl),
			1,
		},
	}
	for _, c := range comparisons {
		if c.actual != c.expected {
			t.Fatalf("expected map %s to contain %d values, but got %d", c.name, c.expected, c.actual)
		}
	}
}
