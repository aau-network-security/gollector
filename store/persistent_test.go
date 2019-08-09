package store

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"github.com/aau-network-security/go-domains/ct"
	"github.com/aau-network-security/go-domains/models"
	ct2 "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509/pkix"
	"github.com/jinzhu/gorm"
	"math/big"
	"testing"
	"time"
)

func resetDb(g *gorm.DB) error {
	tables := []string{
		"apexes",
		"zonefile_entries",
		"tlds",
		"fqdns",
		"certificate_to_fdqns",
		"certificates",
		"log_entries",
		"logs",
	}

	for _, table := range tables {
		qry := fmt.Sprintf("DROP TABLE IF EXISTS %s", table)
		if err := g.Exec(qry).Error; err != nil {
			return err
		}
	}

	migrateExamples := []interface{}{
		&models.Apex{},
		&models.ZonefileEntry{},
		&models.Tld{},
		&models.Fqdn{},
		&models.CertificateToFqdn{},
		&models.Certificate{},
		&models.LogEntry{},
		&models.Log{},
	}
	for _, ex := range migrateExamples {
		if err := g.AutoMigrate(ex).Error; err != nil {
			return err
		}
	}
	return nil
}

func logEntryFromCertData(raw []byte, ts uint64) (*ct2.LogEntry, error) {
	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, err
	}
	le := &ct2.LogEntry{
		Leaf: ct2.MerkleTreeLeaf{
			TimestampedEntry: &ct2.TimestampedEntry{
				EntryType: ct2.X509LogEntryType,
				X509Entry: &ct2.ASN1Cert{
					Data: raw,
				},
				Timestamp: ts,
			},
		},
		X509Cert: cert,
	}

	return le, nil
}

func selfSignedCert(notBefore, notAfter time.Time, sans []string) ([]byte, error) {
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Org"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              sans,
	}

	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, err
	}

	return x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
}

// test against locally running postgres server
func TestStore_StoreZoneEntry(t *testing.T) {
	conf := Config{
		User:     "postgres",
		Password: "postgres",
		DBName:   "domains",
		Host:     "localhost",
		Port:     10001,
	}

	g, err := conf.Open()
	if err != nil {
		t.Fatalf("failed to open gorm database: %s", err)
	}

	if err := resetDb(g); err != nil {
		t.Fatalf("failed to reset database: %s", err)
	}

	opts := Opts{
		BatchSize:       10,
		AllowedInterval: 10 * time.Millisecond,
	}

	s, err := NewStore(conf, opts)
	if err != nil {
		t.Fatalf("failed to create store: %s", err)
	}

	iterations := 3
	for i := 0; i < iterations; i++ {
		for j := 0; j < 10; j++ {
			if _, err := s.StoreZoneEntry(time.Now(), "example.org"); err != nil {
				t.Fatalf("error while storing entry: %s", err)
			}
		}
		time.Sleep(15 * time.Millisecond)
	}
	if err := s.RunPostHooks(); err != nil {
		t.Fatalf("error while running post hooks: %s", err)
	}

	counts := []struct {
		count      uint
		model      interface{}
		whereQuery string
	}{
		{1, &models.Apex{}, ""},
		{3, &models.ZonefileEntry{}, ""},
		{1, &models.ZonefileEntry{}, "active = true"},
		{1, &models.Tld{}, ""},
	}

	for _, tc := range counts {
		var count uint
		qry := g.Model(tc.model)
		if tc.whereQuery != "" {
			qry = qry.Where(tc.whereQuery)
		}

		if err := qry.Count(&count).Error; err != nil {
			t.Fatalf("failed to retrieve apex count: %s", err)
		}

		if count != tc.count {
			t.Fatalf("expected %d elements, but got %d", tc.count, count)
		}
	}
}

func TestStore_StoreLogEntry(t *testing.T) {
	conf := Config{
		User:     "postgres",
		Password: "postgres",
		DBName:   "domains",
		Host:     "localhost",
		Port:     10001,
	}

	g, err := conf.Open()
	if err != nil {
		t.Fatalf("failed to open gorm database: %s", err)
	}

	if err := resetDb(g); err != nil {
		t.Fatalf("failed to reset database: %s", err)
	}

	opts := Opts{
		BatchSize:       10,
		AllowedInterval: 10 * time.Millisecond,
	}

	s, err := NewStore(conf, opts)
	if err != nil {
		t.Fatalf("failed to create store: %s", err)
	}

	l := ct.Log{
		Url:         "localhost",
		Description: "some description",
	}

	domains := []string{
		"a.com",
		"b.com",
	}
	now := time.Now()
	raw, err := selfSignedCert(now, now, domains)
	if err != nil {
		t.Fatalf("unexpected error while creating self-signed certificate: %s", err)
	}

	le, err := logEntryFromCertData(raw, uint64(now.Unix()))
	if err != nil {
		t.Fatalf("unexpected error while creating log entry: %s", err)
	}

	if err := s.StoreLogEntry(le, l); err != nil {
		t.Fatalf("unexpected error while storing log entry: %s", err)
	}
	if err := s.RunPostHooks(); err != nil {
		t.Fatalf("unexpected error while running post hooks: %s", err)
	}
}

func TestInit(t *testing.T) {
	conf := Config{
		User:     "postgres",
		Password: "postgres",
		DBName:   "domains",
		Host:     "localhost",
		Port:     10001,
	}

	g, err := conf.Open()
	if err != nil {
		t.Fatalf("failed to open gorm database: %s", err)
	}

	if err := resetDb(g); err != nil {
		t.Fatalf("failed to reset database: %s", err)
	}

	for i := 0; i < 10; i++ {
		if err := g.Create(&models.Apex{Apex: fmt.Sprintf("%d.com", i)}).Error; err != nil {
			t.Fatalf("error while writing apex to db: %s", err)
		}
	}

	opts := Opts{
		BatchSize:       10,
		AllowedInterval: 10 * time.Millisecond,
	}

	s, err := NewStore(conf, opts)
	if err != nil {
		t.Fatalf("failed to create store: %s", err)
	}

	if s.ids.apexes != 11 {
		t.Fatalf("expected next id to be %d, but got %d", 11, s.ids.apexes)
	}
}
