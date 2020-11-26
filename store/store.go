package store

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aau-network-security/gollector/store/models"
	"github.com/go-pg/pg"
	lru "github.com/hashicorp/golang-lru"
	"github.com/jinzhu/gorm"
	_ "github.com/lib/pq"
	errs "github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

var (
	DefaultCacheOpts = CacheOpts{
		LogSize:   1000,
		TLDSize:   2000,
		PSuffSize: 4000,
		ApexSize:  10000,
		FQDNSize:  20000,
		CertSize:  50000,
	}
	DefaultOpts = Opts{
		BatchSize:       20000,
		CacheOpts:       DefaultCacheOpts,
		AllowedInterval: 36 * time.Hour,
	}
)

type EntryExistsErr struct {
	Domain string
}

func (err EntryExistsErr) Error() string {
	return fmt.Sprintf("trying to store zonefile entry for existing domain '%s'", err.Domain)
}

type InvalidDomainErr struct {
	Domain string
}

func (err InvalidDomainErr) Error() string {
	return fmt.Sprintf("cannot store invalid domain: %s", err.Domain)
}

type Config struct {
	User       string     `yaml:"user"`
	Password   string     `yaml:"password"`
	Host       string     `yaml:"host"`
	Port       int        `yaml:"port"`
	DBName     string     `yaml:"dbname"`
	Debug      bool       `yaml:"debug"`
	InfluxOpts InfluxOpts `yaml:"influxdb"`

	d *gorm.DB
}

func (c *Config) Open() (*gorm.DB, error) {
	var err error
	if c.d == nil {
		c.d, err = gorm.Open("postgres", c.DSN())
	}
	return c.d, err
}

func (c *Config) DSN() string {
	return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		c.Host, c.Port, c.User, c.Password, c.DBName)
}

type ModelSet struct {
	zoneEntries      map[uint]*models.ZonefileEntry
	fqdns            []*models.Fqdn
	fqdnsAnon        []*models.FqdnAnon
	apexes           map[uint]*models.Apex
	apexesAnon       map[uint]*models.ApexAnon
	certs            []*models.Certificate
	logEntries       []*models.LogEntry
	certToFqdns      []*models.CertificateToFqdn
	passiveEntries   []*models.PassiveEntry
	entradaEntries   []*models.EntradaEntry
	tld              []*models.Tld
	tldAnon          []*models.TldAnon
	publicSuffix     []*models.PublicSuffix
	publicSuffixAnon []*models.PublicSuffixAnon
}

func (ms *ModelSet) Len() int {
	return len(ms.zoneEntries) +
		len(ms.fqdns) +
		len(ms.fqdnsAnon) +
		len(ms.apexes) +
		len(ms.apexesAnon) +
		len(ms.certs) +
		len(ms.logEntries) +
		len(ms.certToFqdns) +
		len(ms.passiveEntries) +
		len(ms.entradaEntries)
}

func (ms *ModelSet) zoneEntryList() []*models.ZonefileEntry {
	var res []*models.ZonefileEntry
	for _, v := range ms.zoneEntries {
		res = append(res, v)
	}
	return res
}

func (ms *ModelSet) apexList() []*models.Apex {
	var res []*models.Apex
	for _, v := range ms.apexes {
		res = append(res, v)
	}
	return res
}

func (ms *ModelSet) apexAnonList() []*models.ApexAnon {
	var res []*models.ApexAnon
	for _, v := range ms.apexesAnon {
		res = append(res, v)
	}
	return res
}

func NewModelSet() ModelSet {
	return ModelSet{
		zoneEntries:      make(map[uint]*models.ZonefileEntry),
		apexes:           make(map[uint]*models.Apex),
		apexesAnon:       make(map[uint]*models.ApexAnon),
		fqdns:            []*models.Fqdn{},
		fqdnsAnon:        []*models.FqdnAnon{},
		certToFqdns:      []*models.CertificateToFqdn{},
		certs:            []*models.Certificate{},
		logEntries:       []*models.LogEntry{},
		passiveEntries:   []*models.PassiveEntry{},
		entradaEntries:   []*models.EntradaEntry{},
		tld:              []*models.Tld{},
		tldAnon:          []*models.TldAnon{},
		publicSuffix:     []*models.PublicSuffix{},
		publicSuffixAnon: []*models.PublicSuffixAnon{},
	}
}

type postHook func(*Store) error

type Ids struct {
	zoneEntries  uint
	tlds         uint
	tldsAnon     uint
	suffixes     uint
	suffixesAnon uint
	apexes       uint
	apexesAnon   uint
	fqdns        uint
	fqdnsAnon    uint
	certs        uint
	certsToFqdn  uint
	logs         uint
	recordTypes  uint
}

type cache struct {
	tldByName              *lru.Cache //map[string]*models.Tld
	tldAnonByName          *lru.Cache //map[string]*models.TldAnon
	publicSuffixByName     *lru.Cache //map[string]*models.PublicSuffix
	publicSuffixAnonByName *lru.Cache //map[string]*models.PublicSuffixAnon
	apexByName             *lru.Cache //map[string]*models.Apex
	apexByNameAnon         *lru.Cache //map[string]*models.ApexAnon
	apexById               *lru.Cache //map[uint]*models.Apex
	fqdnByName             *lru.Cache //map[string]*models.Fqdn
	fqdnByNameAnon         *lru.Cache //map[string]*models.FqdnAnon
	zoneEntriesByApexName  *lru.Cache //map[string]*models.ZonefileEntry
	certByFingerprint      *lru.Cache //map[string]*models.Certificate
	logByUrl               *lru.Cache //map[string]*models.Log
	recordTypeByName       *lru.Cache //map[string]*models.RecordType
	passiveEntryByFqdn     splunkEntryMap
	entradaEntryByFqdn     *lru.Cache //map[string]*models.EntradaEntry
}

// prints the current status to standard output
func (c *cache) describe() {
	log.Debug().Msgf("tlds:            %d", c.tldByName.Len())
	log.Debug().Msgf("tlds (anon):     %d", c.tldAnonByName.Len())
	log.Debug().Msgf("suffixes:        %d", c.publicSuffixByName.Len())
	log.Debug().Msgf("suffixes (anon): %d", c.publicSuffixAnonByName.Len())
	log.Debug().Msgf("apexes:          %d", c.apexByName.Len())
	log.Debug().Msgf("apexes (anon):   %d", c.apexByNameAnon.Len())
	log.Debug().Msgf("fqdns:           %d", c.fqdnByName.Len())
	log.Debug().Msgf("fqdns (anon):    %d", c.fqdnByNameAnon.Len())
	log.Debug().Msgf("zone entries:    %d", c.zoneEntriesByApexName.Len())
	log.Debug().Msgf("certificates:    %d", c.certByFingerprint.Len())
	log.Debug().Msgf("logs:            %d", c.logByUrl.Len())
	log.Debug().Msgf("record types:    %d", c.recordTypeByName.Len())
	log.Debug().Msgf("passive entries: %d", c.passiveEntryByFqdn.len())
	//log.Debug().Msgf("entrada entries: %d", c.entradaEntryByFqdn.Len())
}

func newLRUCache(cacheSize int) *lru.Cache {
	c, err := lru.New(cacheSize)
	if err != nil {
		log.Error().Msgf("Error Creating LRU Cache: %s", err)
		return &lru.Cache{}
	}
	return c
}

func newCache(opts CacheOpts) cache {
	return cache{
		tldByName:              newLRUCache(opts.TLDSize),       //make(map[string]*models.Tld)
		tldAnonByName:          newLRUCache(opts.TLDSize),       //make(map[string]*models.TldAnon),
		publicSuffixByName:     newLRUCache(opts.PSuffSize),     //make(map[string]*models.PublicSuffix),
		publicSuffixAnonByName: newLRUCache(opts.PSuffSize),     //make(map[string]*models.PublicSuffixAnon),
		apexByName:             newLRUCache(opts.ApexSize),      //make(map[string]*models.Apex),
		apexByNameAnon:         newLRUCache(opts.ApexSize),      //make(map[string]*models.ApexAnon),
		apexById:               newLRUCache(opts.ApexSize),      //make(map[uint]*models.Apex),
		fqdnByName:             newLRUCache(opts.FQDNSize),      //make(map[string]*models.Fqdn),
		fqdnByNameAnon:         newLRUCache(opts.FQDNSize),      //make(map[string]*models.FqdnAnon),
		zoneEntriesByApexName:  newLRUCache(opts.ZoneEntrySize), //make(map[string]*models.ZonefileEntry),
		logByUrl:               newLRUCache(opts.LogSize),       //make(map[string]*models.Log),
		certByFingerprint:      newLRUCache(opts.CertSize),      //make(map[string]*models.Certificate),
		passiveEntryByFqdn:     newSplunkEntryMap(),
		recordTypeByName:       newLRUCache(opts.TLDSize), //make(map[string]*models.RecordType),
	}
}

type Ready struct {
	isReady bool
	c       chan bool
}

func (r *Ready) IsReady() bool {
	return r.isReady
}

func (r *Ready) Wait() {
	if r.isReady {
		return
	}
	<-r.c
	r.isReady = true
}

func (r *Ready) Finish() {
	r.c <- true
}

func NewReady() *Ready {
	return &Ready{
		isReady: false,
		c:       make(chan bool),
	}
}

type Store struct {
	conf            Config
	db              *pg.DB
	cache           cache
	cacheOpts       CacheOpts
	m               *sync.Mutex
	ids             Ids
	allowedInterval time.Duration
	batchSize       int
	postHooks       []postHook
	inserts         ModelSet
	updates         ModelSet
	ms              measurementState
	anonymizer      *Anonymizer
	Ready           *Ready
	batchEntities   BatchEntities // datastructure with all entities in batch
	influxService   InfluxService
}

func (s *Store) WithAnonymizer(a *Anonymizer) *Store {
	s.anonymizer = a
	return s
}

func (s *Store) ensureReady() {
	if !s.Ready.isReady {
		s.Ready.Wait()
	}
}

func (s *Store) RunPostHooks() error {
	s.m.Lock()
	defer s.m.Unlock()
	return s.runPostHooks()
}

func (s *Store) runPostHooks() error {
	log.Debug().Msgf("running post hooks..")
	for _, h := range s.postHooks {
		if err := h(s); err != nil {
			return err
		}
	}
	log.Debug().Msgf("post hooks are done!")
	return nil
}

func (s *Store) conditionalPostHooks() error {
	if len(s.batchEntities.certByFingerprint) >= s.batchSize {
		log.Debug().Msgf("batch is full (%d), writing to database..", len(s.batchEntities.certByFingerprint))
		return s.runPostHooks()
	}
	return nil
}

func (s *Store) GetLastIndexLog(knowLogURL string) (int64, error) {
	var knowLog models.Log
	if err := s.db.Model(&knowLog).Where("url = ?", knowLogURL).First(); err != nil {
		if !strings.Contains(err.Error(), "no rows in result set") {
			return 0, err
		}
		return 0, nil //know log in not present in DB (it's new)
	}

	var lastLogEntry models.LogEntry
	if err := s.db.Model(&lastLogEntry).Where("log_id = ?", knowLog.ID).Last(); err != nil {
		if !strings.Contains(err.Error(), "no rows in result set") {
			return 0, err
		}
		return 0, nil
	}

	return int64(lastLogEntry.Index + 1), nil
}

// use Gorm's auto migrate functionality
func (s *Store) migrate() error {
	g, err := s.conf.Open()
	if err != nil {
		return err
	}

	migrateExamples := []interface{}{
		&models.ZonefileEntry{},
		&models.Tld{},
		&models.TldAnon{},
		&models.Apex{},
		&models.ApexAnon{},
		&models.PublicSuffix{},
		&models.PublicSuffixAnon{},
		&models.Fqdn{},
		&models.FqdnAnon{},
		&models.CertificateToFqdn{},
		&models.Certificate{},
		&models.LogEntry{},
		&models.Log{},
		&models.RecordType{},
		&models.PassiveEntry{},
		&models.EntradaEntry{},
		&models.Measurement{},
		&models.Stage{},
	}
	for _, ex := range migrateExamples {
		if err := g.AutoMigrate(ex).Error; err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) init() error {
	var tlds []*models.Tld
	if err := s.db.Model(&tlds).Order("id ASC").Limit(s.cacheOpts.TLDSize).Select(); err != nil {
		return err
	}
	for _, tld := range tlds {
		s.cache.tldByName.Add(tld.Tld, tld)
	}

	var tldsAnon []*models.TldAnon
	if err := s.db.Model(&tldsAnon).Order("id ASC").Limit(s.cacheOpts.TLDSize).Select(); err != nil {
		return err
	}
	for _, tld := range tldsAnon {
		s.cache.tldAnonByName.Add(tld.Tld.Tld, tld)
	}

	var suffixes []*models.PublicSuffix
	if err := s.db.Model(&suffixes).Order("id ASC").Limit(s.cacheOpts.PSuffSize).Select(); err != nil {
		return err
	}
	for _, suffix := range suffixes {
		s.cache.publicSuffixByName.Add(suffix.PublicSuffix, suffix)
	}

	var suffixesAnon []*models.PublicSuffixAnon
	if err := s.db.Model(&suffixesAnon).Order("id ASC").Limit(s.cacheOpts.PSuffSize).Select(); err != nil {
		return err
	}
	for _, suffix := range suffixesAnon {
		s.cache.publicSuffixAnonByName.Add(suffix.PublicSuffix.PublicSuffix, suffix)
	}

	var apexes []*models.Apex
	if err := s.db.Model(&apexes).Order("id ASC").Limit(s.cacheOpts.ApexSize).Select(); err != nil {
		return err
	}
	for _, apex := range apexes {
		s.cache.apexByName.Add(apex.Apex, apex)
		s.cache.apexById.Add(apex.ID, apex)
	}

	var apexesAnon []*models.ApexAnon
	if err := s.db.Model(&apexesAnon).Order("id ASC").Limit(s.cacheOpts.ApexSize).Select(); err != nil {
		return err
	}
	for _, apex := range apexesAnon {
		s.cache.apexByNameAnon.Add(apex.Apex.Apex, apex)
	}

	var fqdns []*models.Fqdn
	if err := s.db.Model(&fqdns).Order("id ASC").Limit(s.cacheOpts.FQDNSize).Select(); err != nil {
		return err
	}
	fqdnsById := make(map[uint]*models.Fqdn)
	for _, fqdn := range fqdns {
		s.cache.fqdnByName.Add(fqdn.Fqdn, fqdn)
		fqdnsById[fqdn.ID] = fqdn
	}

	var fqdnsAnon []*models.FqdnAnon
	if err := s.db.Model(&fqdnsAnon).Order("id ASC").Limit(s.cacheOpts.FQDNSize).Select(); err != nil {
		return err
	}
	for _, fqdn := range fqdnsAnon {
		s.cache.fqdnByNameAnon.Add(fqdn.Fqdn.Fqdn, fqdn)
	}

	var entries []*models.ZonefileEntry
	if err := s.db.Model(&entries).Order("id ASC").Limit(s.cacheOpts.ZoneEntrySize).Select(); err != nil {
		return err
	}
	for _, entry := range entries {
		apexI, _ := s.cache.apexById.Get(entry.ApexID)
		apex := apexI.(*models.Apex)
		s.cache.zoneEntriesByApexName.Add(apex.Apex, entry)
	}

	var logs []*models.Log
	if err := s.db.Model(&logs).Order("id ASC").Limit(s.cacheOpts.LogSize).Select(); err != nil {
		return err
	}
	for _, l := range logs {
		s.cache.logByUrl.Add(l.Url, l)
	}

	var certs []*models.Certificate
	if err := s.db.Model(&certs).Order("id ASC").Limit(s.cacheOpts.CertSize).Select(); err != nil {
		return err
	}
	for _, c := range certs {
		s.cache.certByFingerprint.Add(c.Sha256Fingerprint, c)
	}

	var rtypes []*models.RecordType
	if err := s.db.Model(&rtypes).Order("id ASC").Select(); err != nil {
		return err
	}
	rtypeById := make(map[uint]*models.RecordType)
	for _, rtype := range rtypes {
		s.cache.recordTypeByName.Add(rtype.Type, rtype)
		rtypeById[rtype.ID] = rtype
	}

	var passiveEntries []*models.PassiveEntry
	if err := s.db.Model(&passiveEntries).Order("id ASC").Select(); err != nil {
		return err
	}
	for _, entry := range passiveEntries {
		fqdn := fqdnsById[entry.FqdnID]
		rtype := rtypeById[entry.RecordTypeID]
		s.cache.passiveEntryByFqdn.add(fqdn.Fqdn, rtype.Type, entry)
	}

	s.ids.zoneEntries = 1
	if len(entries) > 0 {
		s.ids.zoneEntries = entries[len(entries)-1].ID + 1
	}
	s.ids.tlds = 1
	if len(tlds) > 0 {
		s.ids.tlds = tlds[len(tlds)-1].ID + 1
	}
	s.ids.tldsAnon = 1
	if len(tldsAnon) > 0 {
		s.ids.tldsAnon = tldsAnon[len(tldsAnon)-1].ID + 1
	}
	s.ids.suffixes = 1
	if len(suffixes) > 0 {
		s.ids.suffixes = suffixes[len(suffixes)-1].ID + 1
	}
	s.ids.suffixesAnon = 1
	if len(suffixesAnon) > 0 {
		s.ids.suffixesAnon = suffixesAnon[len(suffixesAnon)-1].ID + 1
	}
	s.ids.apexes = 1
	if len(apexes) > 0 {
		s.ids.apexes = apexes[len(apexes)-1].ID + 1
	}
	s.ids.apexesAnon = 1
	if len(apexesAnon) > 0 {
		s.ids.apexesAnon = apexesAnon[len(apexesAnon)-1].ID + 1
	}
	s.ids.fqdns = 1
	if len(fqdns) > 0 {
		s.ids.fqdns = fqdns[len(fqdns)-1].ID + 1
	}
	s.ids.fqdnsAnon = 1
	if len(fqdnsAnon) > 0 {
		s.ids.fqdnsAnon = fqdnsAnon[len(fqdnsAnon)-1].ID + 1
	}
	s.ids.logs = 1
	if len(logs) > 0 {
		s.ids.logs = logs[len(logs)-1].ID + 1
	}
	s.ids.certs = 1
	if len(certs) > 0 {
		s.ids.certs = certs[len(certs)-1].ID + 1
	}
	s.ids.recordTypes = 1
	if len(rtypes) > 0 {
		s.ids.recordTypes = rtypes[len(rtypes)-1].ID + 1
	}

	return nil
}

type CacheOpts struct {
	LogSize       int
	TLDSize       int
	PSuffSize     int
	ApexSize      int
	FQDNSize      int
	CertSize      int
	ZoneEntrySize int
}

type Opts struct {
	BatchSize       int
	CacheOpts       CacheOpts
	AllowedInterval time.Duration
}

type debugHook struct{}

func (hook *debugHook) BeforeQuery(qe *pg.QueryEvent) {
	fq, err := qe.FormattedQuery()
	if err != nil {
		return
	}
	log.Debug().Msgf("%s", fq)
}

func (hook *debugHook) AfterQuery(qe *pg.QueryEvent) {}

func NewStore(conf Config, opts Opts) (*Store, error) {
	pgOpts := pg.Options{
		User:     conf.User,
		Password: conf.Password,
		Addr:     fmt.Sprintf("%s:%d", conf.Host, conf.Port),
		Database: conf.DBName,
	}

	db := pg.Connect(&pgOpts)
	if conf.Debug {
		db.AddQueryHook(&debugHook{})
	}

	ifs, err := NewInfluxService(conf.InfluxOpts)
	if err != nil {
		return nil, err
	}

	s := Store{
		conf:            conf,
		db:              db,
		cache:           newCache(opts.CacheOpts),
		cacheOpts:       opts.CacheOpts,
		allowedInterval: opts.AllowedInterval,
		batchSize:       opts.BatchSize,
		m:               &sync.Mutex{},
		postHooks:       []postHook{},
		inserts:         NewModelSet(),
		updates:         NewModelSet(),
		ids:             Ids{},
		anonymizer:      &DefaultAnonymizer,
		ms:              NewMeasurementState(),
		Ready:           NewReady(),
		batchEntities:   NewBatchEntities(),
		influxService:   ifs,
	}

	s.postHooks = append(s.postHooks, propagationPosthook(), storeCachedValuePosthook())

	if err := s.migrate(); err != nil {
		return nil, errs.Wrap(err, "migrate models")
	}

	//make the table unlogged to improve performance
	tableList := []string{"apexes", "certificate_to_fqdns", "certificates", "fqdns", "log_entries", "public_suffixes", "tlds"}

	for _, tl := range tableList {
		line := fmt.Sprintf("ALTER TABLE %s SET UNLOGGED;", tl)
		_, err := s.db.Exec(line)
		if err != nil {
			log.Debug().Msgf("error creating unlogged %s table: %s", tl, err.Error())
		}
	}

	go func() {
		if err := s.init(); err != nil {
			log.Error().Msgf("error while initializing database: %s", err)
		}

		s.cache.describe()

		s.Ready.Finish()
	}()

	return &s, nil
}

func propagationPosthook() postHook {
	return func(s *Store) error {
		// backprop all (but zone entries)
		log.Debug().Msgf("propagating backwards..")
		if err := s.backpropCert(); err != nil {
			return err
		}

		if err := s.backpropFqdn(); err != nil {
			return err
		}

		if err := s.backpropApex(); err != nil {
			return err
		}

		if err := s.backpropPublicSuffix(); err != nil {
			return err
		}

		if err := s.backpropTld(); err != nil {
			return err
		}

		// forward prop all (but zone entries)
		log.Debug().Msgf("propagating forwards..")
		s.forpropTld()
		s.forpropPublicSuffix()
		s.forpropApex()
		s.forpropFqdn()
		if err := s.forpropCerts(); err != nil {
			return err
		}

		log.Debug().Msgf("propagating backwards (zone entries)..")
		// backprop zone entries
		if err := s.backpropZoneEntries(); err != nil {
			return err
		}

		log.Debug().Msgf("propagating forwards (zone entries)..")
		// forward prop zone entries
		s.forpropZoneEntries()

		s.influxService.StoreHit("db-insert", "tld", len(s.inserts.tld))
		s.influxService.StoreHit("db-insert", "public-suffix", len(s.inserts.publicSuffix))
		s.influxService.StoreHit("db-insert", "apex", len(s.inserts.apexes))
		s.influxService.StoreHit("db-insert", "fqdn", len(s.inserts.fqdns))
		s.influxService.StoreHit("db-insert", "cert", len(s.inserts.certs))
		s.influxService.StoreHit("db-insert", "zone-entry", len(s.inserts.zoneEntries))
		s.influxService.StoreHit("db-update", "zone-entry", len(s.updates.zoneEntries))

		return nil
	}
}

func storeCachedValuePosthook() postHook {
	return func(s *Store) error {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		defer tx.Rollback()

		// inserts
		if len(s.inserts.fqdns) > 0 {
			if err := tx.Insert(&s.inserts.fqdns); err != nil {
				return errs.Wrap(err, "insert fqdns")
			}
		}

		if len(s.inserts.fqdnsAnon) > 0 {
			if err := tx.Insert(&s.inserts.fqdnsAnon); err != nil {
				return errs.Wrap(err, "insert anon fqdns")
			}
		}

		if len(s.inserts.apexes) > 0 {
			a := s.inserts.apexList()
			if err := tx.Insert(&a); err != nil {
				return errs.Wrap(err, "insert apexes")
			}
		}

		if len(s.inserts.apexesAnon) > 0 {
			a := s.inserts.apexAnonList()
			if err := tx.Insert(&a); err != nil {
				return errs.Wrap(err, "insert anon apexes")
			}
		}

		if len(s.inserts.publicSuffix) > 0 {
			if err := tx.Insert(&s.inserts.publicSuffix); err != nil {
				return errs.Wrap(err, "insert public suffix")
			}
		}

		if len(s.inserts.publicSuffixAnon) > 0 {
			if err := tx.Insert(&s.inserts.publicSuffixAnon); err != nil {
				return errs.Wrap(err, "insert anon public suffix")
			}
		}

		if len(s.inserts.tld) > 0 {
			if err := tx.Insert(&s.inserts.tld); err != nil {
				return errs.Wrap(err, "insert tld")
			}
		}

		if len(s.inserts.tldAnon) > 0 {
			if err := tx.Insert(&s.inserts.tldAnon); err != nil {
				return errs.Wrap(err, "insert tld")
			}
		}

		if len(s.inserts.zoneEntries) > 0 {
			z := s.inserts.zoneEntryList()
			if err := tx.Insert(&z); err != nil {
				return errs.Wrap(err, "insert zone entries")
			}
		}

		if len(s.inserts.logEntries) > 0 {
			if err := tx.Insert(&s.inserts.logEntries); err != nil {
				return errs.Wrap(err, "insert log entries")
			}
		}

		if len(s.inserts.certs) > 0 {
			if err := tx.Insert(&s.inserts.certs); err != nil {
				return errs.Wrap(err, "insert certs")
			}
		}

		if len(s.inserts.certToFqdns) > 0 {
			if err := tx.Insert(&s.inserts.certToFqdns); err != nil {
				return errs.Wrap(err, "insert cert-to-fqdns")
			}
		}

		if len(s.inserts.passiveEntries) > 0 {
			if err := tx.Insert(&s.inserts.passiveEntries); err != nil {
				return errs.Wrap(err, "insert passive entries")
			}
		}

		if len(s.inserts.entradaEntries) > 0 {
			if err := tx.Insert(&s.inserts.entradaEntries); err != nil {
				return errs.Wrap(err, "insert entrada entries")
			}
		}

		// updates
		if len(s.updates.apexes) > 0 {
			a := s.updates.apexList()
			if err := tx.Update(&a); err != nil {
				return errs.Wrap(err, "update apexes")
			}
		}

		if len(s.updates.zoneEntries) > 0 {
			z := s.updates.zoneEntryList()
			_, err := tx.Model(&z).Column("last_seen", "active").Update()
			if err != nil {
				return errs.Wrap(err, "update zone entries")
			}
		}
		if len(s.updates.passiveEntries) > 0 {
			if _, err := tx.Model(&s.updates.passiveEntries).Column("first_seen").Update(); err != nil {
				return errs.Wrap(err, "update passive entries")
			}
		}

		s.updates = NewModelSet()
		s.inserts = NewModelSet()

		if err := tx.Commit(); err != nil {
			return errs.Wrap(err, "committing transaction")
		}

		s.batchEntities = NewBatchEntities()

		// TODO: add anonymized
		// write size of cache to influx
		s.influxService.CacheSize("cert", s.cache.certByFingerprint, s.cacheOpts.CertSize)
		s.influxService.CacheSize("fqdn", s.cache.fqdnByName, s.cacheOpts.FQDNSize)
		s.influxService.CacheSize("apex", s.cache.apexByName, s.cacheOpts.ApexSize)
		s.influxService.CacheSize("public-suffix", s.cache.publicSuffixByName, s.cacheOpts.ApexSize)
		s.influxService.CacheSize("tld", s.cache.tldByName, s.cacheOpts.TLDSize)
		s.influxService.CacheSize("zone-entry", s.cache.zoneEntriesByApexName, s.cacheOpts.ZoneEntrySize)

		log.Debug().Msgf("Finished storing batch")

		return nil
	}
}
