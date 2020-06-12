package store

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"math/big"
	"reflect"
	"testing"
	"time"

	"github.com/aau-network-security/gollector/collectors/ct"

	"github.com/aau-network-security/gollector/store/models"
	tst "github.com/aau-network-security/gollector/testing"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509/pkix"
)

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

// check if storing a zone entry creates the correct db models
func TestStore_StoreZoneEntry(t *testing.T) {
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

	iterations := 3
	for i := 0; i < iterations; i++ {
		for j := 0; j < 2; j++ {
			// this should only update the "last_seen" field of the current active zonefile entry
			go func() {
				if _, err := s.StoreZoneEntry(muid, time.Now(), "example.org"); err != nil {
					t.Fatalf("error while storing entry: %s", err)
				}
			}()
		}
		// this should enforce to create a new zonefile entry in the next loop iteration
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
		{1, &models.Tld{}, ""},
		{1, &models.PublicSuffix{}, ""},
		{1, &models.Apex{}, ""},
		{uint(iterations), &models.ZonefileEntry{}, ""},
		{1, &models.ZonefileEntry{}, "active = true"},
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
			n := reflect.TypeOf(tc.model)
			t.Fatalf("expected %d %s elements, but got %d", tc.count, n, count)
		}
	}
}

func TestSplunkEntryMap_Add(t *testing.T) {
	tests := []struct {
		name          string
		queries       []string
		queryTypes    []string
		expectedCount int
	}{
		{
			"single query",
			[]string{"a.com"},
			[]string{"A"},
			1,
		},
		{
			"multiple query types",
			[]string{"a.com", "a.com"},
			[]string{"A", "AAAA"},
			2,
		},
		{
			"multiple queries",
			[]string{"a.com", "b.com"},
			[]string{"A", "A"},
			2,
		},
		{
			"multiple queries, multile query types",
			[]string{"a.com", "a.com", "b.com", "b.com"},
			[]string{"A", "AAAA", "A", "AAAA"},
			4,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if len(test.queries) != len(test.queryTypes) {
				t.Fatalf("invalid test case (number of queries must match number of query types)!")
			}

			sem := newSplunkEntryMap()

			pe := &models.PassiveEntry{}

			for i := range test.queries {
				sem.add(test.queries[i], test.queryTypes[i], pe)
			}

			if sem.len() != test.expectedCount {
				t.Fatalf("expected length to be %d, but got %d", test.expectedCount, sem.len())
			}
		})
	}
}

func TestStore_StoreSplunkEntry(t *testing.T) {
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

	tm := time.Now()

	entries := []struct {
		query     string
		queryType string
		tm        time.Time
	}{
		{
			"a.com",
			"A",
			tm,
		},
		{
			"a.com",
			"AAAA",
			tm,
		},
		{
			"www.a.com",
			"A",
			tm,
		},
		{
			"b.org",
			"A",
			tm.Add(2 * time.Second),
		},
		{
			"b.org",
			"A",
			tm.Add(1 * time.Second),
		},
		{
			"b.org",
			"A",
			tm,
		},
	}

	for _, entry := range entries {
		if _, err := s.StorePassiveEntry(muid, entry.query, entry.queryType, entry.tm); err != nil {
			t.Fatalf("unexpected error while storing passive entry: %s", err)
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
		{2, &models.Tld{}},
		{2, &models.Apex{}},
		{3, &models.Fqdn{}},
		{4, &models.PassiveEntry{}},
		{2, &models.RecordType{}},
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
		BatchSize: 10,
		CacheOpts: CacheOpts{
			LogSize:   3,
			TLDSize:   3,
			PSuffSize: 3,
			ApexSize:  5,
			FQDNSize:  5,
			CertSize:  5,
		},
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
			"tldByName",
			s.cache.tldByName.Len(),
			2,
		},
		{
			"apexByName",
			s.cache.apexByName.Len(),
			2,
		},
		{
			"fqdnByName",
			s.cache.fqdnByName.Len(),
			3,
		},
		{
			"passiveEntryByFqdn",
			s.cache.passiveEntryByFqdn.len(),
			4,
		},
		{
			"recordTypeByName",
			s.cache.recordTypeByName.Len(),
			2,
		},
	}
	for _, c := range comparisons {
		if c.actual != c.expected {
			t.Fatalf("expected map %s to contain %d values, but got %d", c.name, c.expected, c.actual)
		}
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

	if err := tst.ResetDb(g); err != nil {
		t.Fatalf("failed to reset database: %s", err)
	}

	for i := 0; i < 10; i++ {
		if err := g.Create(&models.Apex{Apex: fmt.Sprintf("%d.com", i)}).Error; err != nil {
			t.Fatalf("error while writing apex to db: %s", err)
		}
	}

	opts := Opts{
		BatchSize: 10,
		CacheOpts: CacheOpts{
			LogSize:   3,
			TLDSize:   3,
			PSuffSize: 3,
			ApexSize:  5,
			FQDNSize:  5,
			CertSize:  5,
		},
		AllowedInterval: 10 * time.Millisecond,
	}

	s, err := NewStore(conf, opts)
	if err != nil {
		t.Fatalf("failed to create store: %s", err)
	}
	s.Ready.Wait()

	if s.ids.apexes != 11 {
		t.Fatalf("expected next id to be %d, but got %d", 11, s.ids.apexes)
	}
}

func TestHashMap(t *testing.T) {
	conf := Config{
		User:     "postgres",
		Password: "postgres",
		DBName:   "domains",
		Host:     "localhost",
		Port:     10001,
	}

	// check initialization of new store
	opts := Opts{
		BatchSize: 10,
		CacheOpts: CacheOpts{
			LogSize:   1000,
			TLDSize:   1,
			PSuffSize: 5000,
			ApexSize:  20000,
			FQDNSize:  20000,
			CertSize:  20,
		},
		AllowedInterval: 10 * time.Millisecond,
	}

	s, err := NewStore(conf, opts)
	if err != nil {
		t.Fatalf("failed to create store: %s", err)
	}
	s.Ready.Wait()

}

func TestDebug(t *testing.T) {

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
			"www.b.org",
		},
		{
			"www.b.org",
			"www.c.com",
			"test.c.com",
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
			Log: ct.Log{
				Description: "test description",
				Url:         "www://localhost:443/ct",
			},
			Ts: now,
		}

		if err := s.MapEntry(muid, le); err != nil {
			t.Fatalf("unexpected error while storing log entry: %s", err)
		}
	}

	if err := s.RunPostHooks(); err != nil {
		t.Fatalf("unexpected error while running post hooks: %s", err)
	}

	sanLists = [][]string{
		{
			"www.a.com",
			"www.b.org",
		},
		{
			"www.b.org",
			"www.c.com",
			"test.c.com",
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
			Log: ct.Log{
				Description: "test description",
				Url:         "www://localhost:443/ct",
			},
			Ts: now,
		}

		if err := s.MapEntry(muid, le); err != nil {
			t.Fatalf("unexpected error while storing log entry: %s", err)
		}
	}

	if err := s.RunPostHooks(); err != nil {
		t.Fatalf("unexpected error while running post hooks: %s", err)
	}

	_ = g
}

func TestResetDB(t *testing.T) {
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

	if err := tst.ResetDb(g); err != nil {
		t.Fatalf("failed to reset database: %s", err)
	}
}
