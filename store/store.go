package store

import (
	"fmt"
	"github.com/pingcap/errors"
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
		LogSize:       1000,
		TLDSize:       2000,
		PSuffSize:     4000,
		ApexSize:      10000,
		FQDNSize:      20000,
		CertSize:      50000,
		ZoneEntrySize: 10000,
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
	fqdns            []*models.Fqdn
	fqdnsAnon        []*models.FqdnAnon
	apexes           map[uint]*models.Apex
	apexesAnon       map[uint]*models.ApexAnon
	publicSuffix     []*models.PublicSuffix
	publicSuffixAnon []*models.PublicSuffixAnon
	tld              []*models.Tld
	tldAnon          []*models.TldAnon
	certs            []*models.Certificate
	certToFqdns      []*models.CertificateToFqdn
	zoneEntries      []*models.ZonefileEntry
	logEntries       []*models.LogEntry
	passiveEntries   []*models.PassiveEntry
	entradaEntries   []*models.EntradaEntry
}

func (ms *ModelSet) Description() string {
	res := "[\n"
	if len(ms.fqdns) > 0 {
		res += fmt.Sprintf("fqdns: %d\n", len(ms.fqdns))
	}
	if len(ms.fqdnsAnon) > 0 {
		res += fmt.Sprintf("fqdnsAnon: %d\n", len(ms.fqdnsAnon))
	}
	if len(ms.apexes) > 0 {
		res += fmt.Sprintf("apexes: %d\n", len(ms.apexes))
	}
	if len(ms.apexesAnon) > 0 {
		res += fmt.Sprintf("apexesAnon: %d\n", len(ms.apexesAnon))
	}
	if len(ms.publicSuffix) > 0 {
		res += fmt.Sprintf("publicSuffix: %d\n", len(ms.publicSuffix))
	}
	if len(ms.publicSuffixAnon) > 0 {
		res += fmt.Sprintf("publicSuffixAnon: %d\n", len(ms.publicSuffixAnon))
	}
	if len(ms.tld) > 0 {
		res += fmt.Sprintf("tld: %d\n", len(ms.tld))
	}
	if len(ms.tldAnon) > 0 {
		res += fmt.Sprintf("tldAnon: %d\n", len(ms.tldAnon))
	}
	if len(ms.certs) > 0 {
		res += fmt.Sprintf("certs: %d\n", len(ms.certs))
	}
	if len(ms.certToFqdns) > 0 {
		res += fmt.Sprintf("certToFqdns: %d\n", len(ms.certToFqdns))
	}
	if len(ms.zoneEntries) > 0 {
		res += fmt.Sprintf("zoneEntries: %d\n", len(ms.zoneEntries))
	}
	if len(ms.logEntries) > 0 {
		res += fmt.Sprintf("logEntries: %d\n", len(ms.logEntries))
	}
	if len(ms.passiveEntries) > 0 {
		res += fmt.Sprintf("passiveEntries: %d\n", len(ms.passiveEntries))
	}
	if len(ms.entradaEntries) > 0 {
		res += fmt.Sprintf("entradaEntries: %d\n", len(ms.entradaEntries))
	}
	res += "]"
	return res
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
		zoneEntries:      []*models.ZonefileEntry{},
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
	certByFingerprint      *lru.Cache //map[string]*models.Certificate
	logByUrl               *lru.Cache //map[string]*models.Log
	recordTypeByName       *lru.Cache //map[string]*models.RecordType
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
	log.Debug().Msgf("certificates:    %d", c.certByFingerprint.Len())
	log.Debug().Msgf("logs:            %d", c.logByUrl.Len())
	log.Debug().Msgf("record types:    %d", c.recordTypeByName.Len())
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
		tldByName:              newLRUCache(opts.TLDSize),   //make(map[string]*models.Tld)
		tldAnonByName:          newLRUCache(opts.TLDSize),   //make(map[string]*models.TldAnon),
		publicSuffixByName:     newLRUCache(opts.PSuffSize), //make(map[string]*models.PublicSuffix),
		publicSuffixAnonByName: newLRUCache(opts.PSuffSize), //make(map[string]*models.PublicSuffixAnon),
		apexByName:             newLRUCache(opts.ApexSize),  //make(map[string]*models.Apex),
		apexByNameAnon:         newLRUCache(opts.ApexSize),  //make(map[string]*models.ApexAnon),
		apexById:               newLRUCache(opts.ApexSize),  //make(map[uint]*models.Apex),
		fqdnByName:             newLRUCache(opts.FQDNSize),  //make(map[string]*models.Fqdn),
		fqdnByNameAnon:         newLRUCache(opts.FQDNSize),  //make(map[string]*models.FqdnAnon),
		logByUrl:               newLRUCache(opts.LogSize),   //make(map[string]*models.Log),
		certByFingerprint:      newLRUCache(opts.CertSize),  //make(map[string]*models.Certificate),
		recordTypeByName:       newLRUCache(opts.TLDSize),   //make(map[string]*models.RecordType),
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
	if s.batchEntities.IsFull() {
		log.Debug().Msgf("batch is full (%d), writing to database..", s.batchEntities.Len())
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

func (s *Store) maxValForColumn(table string, column string) (uint, error) {
	var res uint
	qry := fmt.Sprintf("SELECT max(%s) FROM %s", column, table)
	if _, err := s.db.Query(&res, qry); err != nil {
		return 0, err
	}
	return res, nil
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

	// initialize counters
	maxId, err := s.maxValForColumn("zonefile_entries", "id")
	if err != nil {
		return err
	}
	s.ids.zoneEntries = maxId + 1

	maxId, err = s.maxValForColumn("tlds", "id")
	if err != nil {
		return err
	}
	s.ids.tlds = maxId + 1

	maxId, err = s.maxValForColumn("tlds_anon", "id")
	if err != nil {
		return err
	}
	s.ids.tldsAnon = maxId + 1

	maxId, err = s.maxValForColumn("public_suffixes", "id")
	if err != nil {
		return err
	}
	s.ids.suffixes = maxId + 1

	maxId, err = s.maxValForColumn("public_suffixes_anon", "id")
	if err != nil {
		return err
	}
	s.ids.suffixesAnon = maxId + 1

	maxId, err = s.maxValForColumn("apexes", "id")
	if err != nil {
		return err
	}
	s.ids.apexes = maxId + 1

	maxId, err = s.maxValForColumn("apexes_anon", "id")
	if err != nil {
		return err
	}
	s.ids.apexesAnon = maxId + 1

	maxId, err = s.maxValForColumn("fqdns", "id")
	if err != nil {
		return err
	}
	s.ids.fqdns = maxId + 1

	maxId, err = s.maxValForColumn("fqdns_anon", "id")
	if err != nil {
		return err
	}
	s.ids.fqdnsAnon = maxId + 1

	maxId, err = s.maxValForColumn("logs", "id")
	if err != nil {
		return err
	}
	s.ids.logs = maxId + 1

	maxId, err = s.maxValForColumn("certificates", "id")
	if err != nil {
		return err
	}
	s.ids.certs = maxId + 1

	maxId, err = s.maxValForColumn("record_types", "id")
	if err != nil {
		return err
	}
	s.ids.recordTypes = maxId + 1

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

func (co *CacheOpts) Verify() error {
	if !(co.LogSize > 0 && co.TLDSize > 0 && co.PSuffSize > 0 && co.ApexSize > 0 && co.FQDNSize > 0 && co.CertSize > 0 && co.ZoneEntrySize > 0) {
		return errors.New("all cache sizes must be positive integers")
	}
	return nil
}

type Opts struct {
	BatchSize       int
	CacheOpts       CacheOpts
	AllowedInterval time.Duration
}

func (o *Opts) Verify() error {
	if err := o.CacheOpts.Verify(); err != nil {
		return err
	}
	return nil
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
	if err := opts.Verify(); err != nil {
		return nil, errors.Wrap(err, "provided options are not valid")
	}

	pgOpts := pg.Options{
		User:     conf.User,
		Password: conf.Password,
		Addr:     fmt.Sprintf("%s:%d", conf.Host, conf.Port),
		Database: conf.DBName,
	}

	log.Debug().Msgf("connecting to database..")
	db := pg.Connect(&pgOpts)
	if conf.Debug {
		db.AddQueryHook(&debugHook{})
	}
	log.Debug().Msgf("connecting to database: done!")

	log.Debug().Msgf("creating influx service..")
	ifs, err := NewInfluxService(conf.InfluxOpts)
	if err != nil {
		return nil, err
	}
	log.Debug().Msgf("creating influx service: done!")

	postHooks := []postHook{propagationPosthook(), storeCachedValuePosthook()}

	s := Store{
		conf:            conf,
		db:              db,
		cache:           newCache(opts.CacheOpts),
		cacheOpts:       opts.CacheOpts,
		allowedInterval: opts.AllowedInterval,
		m:               &sync.Mutex{},
		postHooks:       postHooks,
		inserts:         NewModelSet(),
		updates:         NewModelSet(),
		ids:             Ids{},
		anonymizer:      &DefaultAnonymizer,
		ms:              NewMeasurementState(),
		Ready:           NewReady(),
		batchEntities:   NewBatchEntities(opts.BatchSize),
		influxService:   ifs,
	}

	log.Debug().Msgf("migrating models..!")
	if err := s.migrate(); err != nil {
		return nil, errs.Wrap(err, "migrate models")
	}
	log.Debug().Msgf("migrating models: done!")

	log.Debug().Msgf("unlogging db tables..")

	//make the table unlogged to improve performance
	tableList := []string{
		"apexes",
		"apexes_anon",
		"certificate_to_fqdns",
		"certificates",
		"entrada_entries",
		"fqdns",
		"fqdns_anon",
		"log_entries",
		"logs",
		"passive_entries",
		"public_suffixes",
		"public_suffixes_anon",
		"record_types",
		"stages",
		"tlds",
		"tlds_anon",
		"zonefile_entries",
	}

	// check which columns are already unlogged
	type item struct {
		Relname        string
		Relpersistence string
	}
	var items []item
	qry := "SELECT relname, relpersistence FROM pg_class"
	if _, err := s.db.Query(&items, qry); err != nil {
		return nil, err
	}

	//var unlogged []string
	unlogMapping := make(map[string]string)
	for _, item := range items {
		unlogMapping[item.Relname] = item.Relpersistence
	}

	for _, table := range tableList {
		unlogStatus, ok := unlogMapping[table]
		if !ok {
			log.Warn().Msgf("unknown logged status; %s", table)
		} else if unlogStatus == "u" {
			log.Debug().Msgf("already unlogged: %s", table)
			continue
		}

		line := fmt.Sprintf("ALTER TABLE %s SET UNLOGGED;", table)
		_, err := s.db.Exec(line)
		if err != nil {
			log.Debug().Msgf("error creating unlogged %s table: %s", table, err.Error())
		}
		log.Debug().Msgf("unlogged: %s", table)
	}

	log.Debug().Msgf("unlogging db tables: done!")

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
		backprops := []struct {
			name string
			f    func() error
		}{
			{"certs", s.backpropCert},
			{"fqdns", s.backpropFqdn},
			{"apexes", s.backpropApex},
			{"public suffixes", s.backpropPublicSuffix},
			{"tlds", s.backpropTld},
			{"fqdn anon", s.backpropFqdnAnon},
			{"apexes anon", s.backpropApexAnon},
			{"public suffixes anon", s.backpropPublicSuffixAnon},
			{"tlds anon", s.backpropTldAnon},
		}

		for i, backprop := range backprops {
			if err := backprop.f(); err != nil {
				return errs.Wrap(err, fmt.Sprintf("back prop %s", backprop.name))
			}
			log.Debug().Msgf("(%d/%d)", i+1, len(backprops))
		}

		// forward prop all (but zone entries)
		log.Debug().Msgf("propagating forwards..")
		s.forpropTld()
		log.Debug().Msgf("(1/12)")
		s.forpropPublicSuffix()
		log.Debug().Msgf("(2/12)")
		s.forpropApex()
		log.Debug().Msgf("(3/12)")
		s.forpropFqdn()
		log.Debug().Msgf("(4/12)")
		s.forpropTldAnon()
		log.Debug().Msgf("(5/12)")
		s.forpropPublicSuffixAnon()
		log.Debug().Msgf("(6/12)")
		s.forpropApexAnon()
		log.Debug().Msgf("(7/12)")
		s.forpropFqdnAnon()
		log.Debug().Msgf("(8/12)")

		if err := s.forpropCerts(); err != nil {
			return err
		}
		log.Debug().Msgf("(9/12)")
		s.forpropZoneEntries()
		log.Debug().Msgf("(10/12)")
		s.forpropPassiveEntries()
		log.Debug().Msgf("(11/12)")
		s.forpropEntradaEntries()
		log.Debug().Msgf("(12/12)")

		s.influxService.StoreHit("db-insert", "tld", len(s.inserts.tld))
		s.influxService.StoreHit("db-insert", "tld-anon", len(s.inserts.tldAnon))
		s.influxService.StoreHit("db-insert", "public-suffix", len(s.inserts.publicSuffix))
		s.influxService.StoreHit("db-insert", "public-suffix-anon", len(s.inserts.publicSuffixAnon))
		s.influxService.StoreHit("db-insert", "apex", len(s.inserts.apexes))
		s.influxService.StoreHit("db-insert", "apex-anon", len(s.inserts.apexesAnon))
		s.influxService.StoreHit("db-insert", "fqdn", len(s.inserts.fqdns))
		s.influxService.StoreHit("db-insert", "fqdn-anon", len(s.inserts.fqdnsAnon))
		s.influxService.StoreHit("db-insert", "cert", len(s.inserts.certs))
		s.influxService.StoreHit("db-insert", "zone-entry", len(s.inserts.zoneEntries))
		s.influxService.StoreHit("db-insert", "passive-entry", len(s.inserts.passiveEntries))
		s.influxService.StoreHit("db-insert", "entrada-entry", len(s.inserts.entradaEntries))

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

		apexInsertList := s.inserts.apexList()
		apexAnonInsertList := s.inserts.apexAnonList()

		inserts := []struct {
			name   string
			models interface{}
			length int
		}{
			{
				name:   "fqdns",
				models: &s.inserts.fqdns,
				length: len(s.inserts.fqdns),
			},
			{
				name:   "anon fqdns",
				models: &s.inserts.fqdnsAnon,
				length: len(s.inserts.fqdnsAnon),
			},
			{
				name:   "apexes",
				models: &apexInsertList,
				length: len(s.inserts.apexes),
			},
			{
				name:   "apexes fqdns",
				models: &apexAnonInsertList,
				length: len(s.inserts.apexesAnon),
			},
			{
				name:   "public suffixes",
				models: &s.inserts.publicSuffix,
				length: len(s.inserts.publicSuffix),
			},
			{
				name:   "anon public suffixes",
				models: &s.inserts.publicSuffixAnon,
				length: len(s.inserts.publicSuffixAnon),
			},
			{
				name:   "tlds",
				models: &s.inserts.tld,
				length: len(s.inserts.tld),
			},
			{
				name:   "anon tlds",
				models: &s.inserts.tldAnon,
				length: len(s.inserts.tldAnon),
			},
			{
				name:   "zone entries",
				models: &s.inserts.zoneEntries,
				length: len(s.inserts.zoneEntries),
			},
			{
				name:   "log entries",
				models: &s.inserts.logEntries,
				length: len(s.inserts.logEntries),
			},
			{
				name:   "certs",
				models: &s.inserts.certs,
				length: len(s.inserts.certs),
			},
			{
				name:   "cert-to-fqdns",
				models: &s.inserts.certToFqdns,
				length: len(s.inserts.certToFqdns),
			},
			{
				name:   "passive entries",
				models: &s.inserts.passiveEntries,
				length: len(s.inserts.passiveEntries),
			},
			{
				name:   "entrada entries",
				models: &s.inserts.entradaEntries,
				length: len(s.inserts.entradaEntries),
			},
		}

		log.Debug().Msgf("storing cached values")
		for i, insert := range inserts {
			if insert.length > 0 {
				if err := tx.Insert(insert.models); err != nil {
					return errs.Wrap(err, fmt.Sprintf("insert %s", insert.name))
				}
			}
			log.Debug().Msgf("(%d/%d)", i+1, len(inserts))
		}

		// updates
		apexAnonUpdateList := s.updates.apexAnonList()

		updates := []struct {
			name   string
			length int
			models interface{}
			column string
		}{
			{
				name:   "anonymous tlds",
				models: &s.updates.tldAnon,
				length: len(s.updates.tldAnon),
				column: "tld_id",
			},
			{
				name:   "anonymous public suffixes",
				models: &s.updates.publicSuffixAnon,
				length: len(s.updates.publicSuffixAnon),
				column: "public_suffix_id",
			},
			{
				name:   "anonymous apexes",
				models: &apexAnonUpdateList,
				length: len(s.updates.apexesAnon),
				column: "apex_id",
			},
			{
				name:   "anonymous fqdns",
				models: &s.updates.fqdnsAnon,
				length: len(s.updates.fqdnsAnon),
				column: "fqdn_id",
			},
		}
		log.Debug().Msgf("updating cached values")
		for i, update := range updates {
			if update.length > 0 {
				if _, err := tx.Model(update.models).Column(update.column).Update(); err != nil {
					return errs.Wrap(err, fmt.Sprintf("update %s", update.name))
				}
			}
			log.Debug().Msgf("(%d/%d)", i+1, len(updates))
		}

		if err := tx.Commit(); err != nil {
			return errs.Wrap(err, "committing transaction")
		}
		log.Debug().Msgf("transaction committed!")

		log.Debug().Msgf("inserted the following number of entities: %s", s.inserts.Description())
		log.Debug().Msgf("updated the following number of entities: %s", s.updates.Description())

		s.updates = NewModelSet()
		s.inserts = NewModelSet()
		s.batchEntities.Reset()

		// write size of cache to influx
		s.influxService.CacheSize("cert", s.cache.certByFingerprint, s.cacheOpts.CertSize)
		s.influxService.CacheSize("fqdn", s.cache.fqdnByName, s.cacheOpts.FQDNSize)
		s.influxService.CacheSize("fqdn-anon", s.cache.fqdnByNameAnon, s.cacheOpts.FQDNSize)
		s.influxService.CacheSize("apex", s.cache.apexByName, s.cacheOpts.ApexSize)
		s.influxService.CacheSize("apex-anon", s.cache.apexByNameAnon, s.cacheOpts.ApexSize)
		s.influxService.CacheSize("public-suffix", s.cache.publicSuffixByName, s.cacheOpts.PSuffSize)
		s.influxService.CacheSize("public-suffix-anon", s.cache.publicSuffixAnonByName, s.cacheOpts.PSuffSize)
		s.influxService.CacheSize("tld", s.cache.tldByName, s.cacheOpts.TLDSize)
		s.influxService.CacheSize("tld-anon", s.cache.tldAnonByName, s.cacheOpts.TLDSize)

		log.Debug().Msgf("finished storing batch")

		return nil
	}
}
