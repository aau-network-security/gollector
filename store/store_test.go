package store

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	testing2 "github.com/aau-network-security/gollector/testing"
	"github.com/go-pg/pg"
	lru "github.com/hashicorp/golang-lru"
	influxdb2 "github.com/influxdata/influxdb-client-go/v2"
	influxapi "github.com/influxdata/influxdb-client-go/v2/api"
	"github.com/influxdata/influxdb-client-go/v2/api/write"
	"github.com/rs/zerolog/log"
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
	s, g, muid, err := OpenStore(TestConfig, TestOpts)
	if err != nil {
		t.Fatalf("failed to create store: %s", err)
	}

	iterations := 3
	for i := 0; i < iterations; i++ {
		for j := 0; j < 2; j++ {
			// this should only update the "last_seen" field of the current active zonefile entry
			go func() {
				if err := s.StoreZoneEntry(muid, time.Now(), "example.org", true); err != nil {
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

func TestStore_StoreSplunkEntry(t *testing.T) {
	s, g, muid, err := OpenStore(TestConfig, TestOpts)
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
		if err := s.StorePassiveEntry(muid, entry.query, entry.tm); err != nil {
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
	s, err = NewStore(TestConfig, TestOpts)
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
		User:       "postgres",
		Password:   "postgres",
		DBName:     "domains",
		Host:       "localhost",
		Port:       5432,
		InfluxOpts: InfluxOpts{Enabled: false},
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
	s, g, muid, err := OpenStore(TestConfig, TestOpts)

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

		if err := s.StoreLogEntry(muid, le); err != nil {
			t.Fatalf("unexpected error while storing log entry: %s", err)
		}
	}

	if err := s.RunPostHooks(); err != nil {
		t.Fatalf("unexpected error while running post hooks: %s", err)
	}

	sanLists = [][]string{
		{
			"wWw.a.Com",
			"www.b.org",
		},
		{
			"www.b.Org",
			"wWw.C.com",
			"teSt.c.com",
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

		if err := s.StoreLogEntry(muid, le); err != nil {
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

type testInfluxdbClient struct {
	influxdb2.Client
}

func (d testInfluxdbClient) Close() {}

type testWriteApi struct {
	influxapi.WriteAPI
}

func (d testWriteApi) WritePoint(point *write.Point) {
}

func TestInfluxDb(t *testing.T) {
	testing2.SkipCI(t)

	s, _, muid, err := OpenStore(TestConfig, TestOpts)
	if err != nil {
		t.Fatalf("failed to open store: %s", err)
	}

	client := testInfluxdbClient{}
	api := testWriteApi{}
	ifs, err := NewInfluxServiceWithClient(client, api, 1)
	if err != nil {
		t.Fatalf("unexpected error while creating influxdb service: %s", err)
	}

	s.influxService = ifs

	for _, domain := range []string{"www.domain1.com", "test.domain1.com"} {
		now := time.Now()
		raw, err := selfSignedCert(now, now, []string{domain})
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

		if err := s.StoreLogEntry(muid, le); err != nil {
			t.Fatalf("unexpected error while storing log entry: %s", err)
		}

		s.RunPostHooks()
	}

	time.Sleep(1)

	ifs.Close()
}

func TestInitWithExistingDb(t *testing.T) {
	s, _, muid, err := OpenStore(TestConfig, TestOpts)
	if err != nil {
		t.Fatalf("failed to create store: %s", err)
	}

	now := time.Now()
	if err := s.StoreZoneEntry(muid, now, "example.org", true); err != nil {
		t.Fatalf("failed to store zone entry: %s", err)
	}

	if err := s.RunPostHooks(); err != nil {
		t.Fatalf("failed to run post hooks: %s", err)
	}

	// test initialization
	s, err = NewStore(TestConfig, TestOpts)
	if err != nil {
		t.Fatalf("failed to create store: %s", err)
	}
	s.Ready.Wait()

	for _, cache := range []*lru.Cache{s.cache.zoneEntriesByApexName, s.cache.apexByName, s.cache.tldByName, s.cache.publicSuffixByName} {
		l := cache.Len()
		if l != 1 {
			t.Fatalf("unexpected amount of entries in the cache: got %d, but expected %d", l, 1)
		}
	}
}

type qh struct{}

func (h *qh) BeforeQuery(event *pg.QueryEvent) {}

func (h *qh) AfterQuery(event *pg.QueryEvent) {
	query, err := event.FormattedQuery()
	if err != nil {
		log.Warn().Msgf("failed to format query: %s", err)
	} else if event.Error != nil {
		log.Warn().Msgf("query failed [%s]: %s", query, event.Error)
	} else {
		log.Debug().Msgf("query successful [%s]", query)
	}
}

func TestMaxValForColumn(t *testing.T) {
	s, _, _, err := OpenStore(TestConfig, TestOpts)
	if err != nil {
		t.Fatalf("failed to create store: %s", err)
	}
	s.db.AddQueryHook(&qh{})

	qry := "INSERT INTO apexes VALUES (?, ?, ?, ?)"

	// insert 10 apexes in database
	for i := 1; i < 11; i++ {
		domain := fmt.Sprintf("%d.google.com", i)
		id := i
		if _, err := s.db.Exec(qry, id, domain, 1, 1); err != nil {
			t.Fatalf("failed to insert test data in database: %s", err)
		}
	}

	maxId, err := s.maxValForColumn("apexes", "id")
	if err != nil {
		t.Fatalf("failed to retrieve max id: %s", err)
	}
	if maxId != 10 {
		t.Fatalf("unexpected max id: expected %d, but got %d", 10, maxId)
	}

	maxTldId, err := s.maxValForColumn("apexes", "tld_id")
	if err != nil {
		t.Fatalf("failed to retrieve max id: %s", err)
	}

	if maxTldId != 1 {
		t.Fatalf("unexpected max tld id: expected %d, but got %d", 1, maxTldId)
	}

	// without any rows in the db
	s, _, _, err = OpenStore(TestConfig, TestOpts)
	if err != nil {
		t.Fatalf("failed to create store: %s", err)
	}
	s.db.AddQueryHook(&qh{})
	maxId, err = s.maxValForColumn("apexes", "id")
	if err != nil {
		t.Fatalf("failed to retrieve max id: %s", err)
	}

	if maxId != 0 {
		t.Fatalf("unexpected max id: expected %d, but got %d", 0, maxTldId)
	}
}

func TestConditionalPostHooks(t *testing.T) {
	opts := TestOpts
	opts.BatchSize = 2

	s, _, muid, err := OpenStore(TestConfig, opts)
	if err != nil {
		t.Fatalf("failed to create store: %s", err)
	}
	ts := time.Now()
	if err := s.StoreZoneEntry(muid, ts, "example.org", true); err != nil {
		t.Fatalf("unexpected error while storing zone entry: %s", err)
	}

	// batch should NOT be full, and conditional post hooks must NOT be run
	if s.batchEntities.IsFull() {
		t.Fatalf("expected batch to be not full, but it is not")
	}
	if s.batchEntities.Len() != 1 {
		t.Fatalf("unexpected batch size: expected %d, but got %d", 2, s.batchEntities.Len())
	}
	if err := s.conditionalPostHooks(); err != nil {
		t.Fatalf("unexpected error while running conditional post hooks: %s", err)
	}
	if s.batchEntities.IsFull() {
		t.Fatalf("expected batch to be not full, but it is not")
	}
	if s.batchEntities.Len() != 1 {
		t.Fatalf("unexpected batch size: expected %d, but got %d", 2, s.batchEntities.Len())
	}

	raw, err := selfSignedCert(ts, ts, []string{"example.org"})
	if err != nil {
		t.Fatalf("unexpected error while creating self-signed cert: %s", err)
	}

	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatalf("unexpected error while parsing certificate: %s", err)
	}

	le := LogEntry{
		Cert:      cert,
		IsPrecert: false,
		Index:     0,
		Ts:        ts,
		Log: ct.Log{
			Description:       "",
			Key:               "",
			Url:               "",
			MaximumMergeDelay: 0,
			OperatedBy:        nil,
			DnsApiEndpoint:    "",
		},
	}
	if err := s.StoreLogEntry(muid, le); err != nil {
		t.Fatalf("unexpected error while storing log entry: %s", err)
	}
	// conditional post hooks must be run
	if s.batchEntities.IsFull() {
		t.Fatalf("expected batch to be not full, but it is")
	}
	if s.batchEntities.Len() != 0 {
		t.Fatalf("unexpected batch size: expected %d, but got %d", 0, s.batchEntities.Len())
	}
}

func TestUpdateAnonymizedDomains(t *testing.T) {
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
	s, g, _, err := OpenStore(TestConfig, opts)
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

	s.db.AddQueryHook(&qh{})

	domain, err := NewDomain("www.example.co.uk")
	if err != nil {
		t.Fatalf("failed to create domain: %s", err)
	}
	s.anonymizer.Anonymize(domain)

	// add anonymized domains
	// add existing TLD
	tld := &models.TldAnon{
		Tld: models.Tld{
			ID:  1,
			Tld: domain.tld.anon, // uk
		},
	}
	if err := g.Create(tld).Error; err != nil {
		t.Fatalf("failed to create TLD: %s", err)
	}
	s.cache.tldAnonByName.Add(domain.tld.anon, tld)

	// add existing public suffix
	psuffix := &models.PublicSuffixAnon{
		PublicSuffix: models.PublicSuffix{
			PublicSuffix: domain.publicSuffix.anon, // co.uk
			ID:           1,
			TldID:        1,
		},
	}
	if err := g.Create(psuffix).Error; err != nil {
		t.Fatalf("failed to create public suffix: %s", err)
	}
	s.cache.publicSuffixAnonByName.Add(domain.publicSuffix.anon, psuffix)

	// add existing apex
	apex := &models.ApexAnon{
		Apex: models.Apex{
			Apex:           domain.apex.anon, // example.co.uk
			ID:             1,
			TldID:          1,
			PublicSuffixID: 1,
		},
	}
	if err := g.Create(apex).Error; err != nil {
		t.Fatalf("failed to create apex: %s", err)
	}
	s.cache.apexByNameAnon.Add(domain.apex.anon, apex)

	// add existing apex
	fqdn := &models.FqdnAnon{
		Fqdn: models.Fqdn{
			Fqdn:           domain.fqdn.anon, // www.example.co.uk
			ID:             1,
			TldID:          1,
			PublicSuffixID: 1,
			ApexID:         1,
		},
	}
	if err := g.Create(fqdn).Error; err != nil {
		t.Fatalf("failed to create apex: %s", err)
	}
	s.cache.fqdnByNameAnon.Add(domain.fqdn.anon, fqdn)

	// create unanonymized FQDNs
	s.batchEntities.fqdnByName[domain.fqdn.normal] = &domainstruct{
		create: true,
		domain: domain,
	}
	s.batchEntities.apexByName[domain.apex.normal] = &domainstruct{
		create: true,
		domain: domain,
	}
	s.batchEntities.publicSuffixByName[domain.publicSuffix.normal] = &domainstruct{
		create: true,
		domain: domain,
	}
	s.batchEntities.tldByName[domain.tld.normal] = &domainstruct{
		create: true,
		domain: domain,
	}

	// add anonymized FQDNs to batch entities
	s.batchEntities.fqdnByNameAnon[domain.fqdn.anon] = &domainstruct{
		create: false,
		domain: domain,
	}
	s.batchEntities.apexByNameAnon[domain.apex.anon] = &domainstruct{
		create: false,
		domain: domain,
	}
	s.batchEntities.publicSuffixAnonByName[domain.publicSuffix.anon] = &domainstruct{
		create: false,
		domain: domain,
	}
	s.batchEntities.tldAnonByName[domain.tld.anon] = &domainstruct{
		create: false,
		domain: domain,
	}

	if err := s.RunPostHooks(); err != nil {
		t.Fatalf("failed to run post hooks: %s", err)
	}
}

func TestStoreDifferentEntries(t *testing.T) {
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
	a := NewAnonymizer(
		NewSha256LabelAnonymizer(""),
		NewSha256LabelAnonymizer(""),
		NewSha256LabelAnonymizer(""),
		NewSha256LabelAnonymizer(""),
	)
	s = s.WithAnonymizer(a)

	s.db.AddQueryHook(&qh{})

	domain := "www.example.co.uk"
	ts := time.Now()
	// passive entry
	if err := s.StorePassiveEntry(muid, domain, ts); err != nil {
		t.Fatalf("failed to create passive store entry: %s", err)
	}
	// ENTRADA entry
	if err := s.StoreEntradaEntry(muid, domain, ts); err != nil {
		t.Fatalf("failed to create passive store entry: %s", err)
	}
	// zone entry
	if err := s.StoreZoneEntry(muid, ts, domain, false); err != nil {
		t.Fatalf("failed to create passive store entry: %s", err)
	}
	// log entry
	raw, err := selfSignedCert(ts, ts.Add(10*time.Minute), []string{domain})
	if err != nil {
		t.Fatalf("failed to create self-signe cert: %s", err)
	}

	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatalf("unexpected error while parsing certificate: %s", err)
	}

	logEntry := LogEntry{
		Cert:      cert,
		IsPrecert: false,
		Index:     0,
		Ts:        ts,
		Log: ct.Log{
			Description:       "Test log",
			Key:               "No key",
			Url:               "localhost",
			MaximumMergeDelay: 10,
			OperatedBy:        []int{1},
			DnsApiEndpoint:    "aau.dk",
		},
	}

	if err := s.StoreLogEntry(muid, logEntry); err != nil {
		t.Fatalf("failed to create passive store entry: %s", err)
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
		{1, &models.ApexAnon{}},
		{1, &models.Fqdn{}},
		{1, &models.FqdnAnon{}},
		{1, &models.Certificate{}},
		{1, &models.CertificateToFqdn{}},
		{1, &models.LogEntry{}},
		{1, &models.PassiveEntry{}},
		{1, &models.ZonefileEntry{}},
		{1, &models.EntradaEntry{}},
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
