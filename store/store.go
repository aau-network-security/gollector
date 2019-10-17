package store

import (
	"fmt"
	"github.com/aau-network-security/gollector/store/models"
	"github.com/go-pg/pg"
	"github.com/jinzhu/gorm"
	_ "github.com/lib/pq"
	errs "github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	"sync"
	"time"
)

var (
	DefaultOpts = Opts{
		BatchSize:       20000,
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
	User     string `yaml:"user"`
	Password string `yaml:"password"`
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	DBName   string `yaml:"dbname"`
	Debug    bool   `yaml:"debug"`

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
	zoneEntries    map[uint]*models.ZonefileEntry
	fqdns          []*models.Fqdn
	fqdnsAnon      []*models.FqdnAnon
	apexes         map[uint]*models.Apex
	apexesAnon     map[uint]*models.ApexAnon
	certs          []*models.Certificate
	logEntries     []*models.LogEntry
	certToFqdns    []*models.CertificateToFqdn
	passiveEntries []*models.PassiveEntry
	entradaEntries []*models.EntradaEntry
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
		zoneEntries:    make(map[uint]*models.ZonefileEntry),
		apexes:         make(map[uint]*models.Apex),
		apexesAnon:     make(map[uint]*models.ApexAnon),
		fqdns:          []*models.Fqdn{},
		fqdnsAnon:      []*models.FqdnAnon{},
		certToFqdns:    []*models.CertificateToFqdn{},
		certs:          []*models.Certificate{},
		logEntries:     []*models.LogEntry{},
		passiveEntries: []*models.PassiveEntry{},
		entradaEntries: []*models.EntradaEntry{},
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
	logs         uint
	recordTypes  uint
}

type cache struct {
	tldByName              map[string]*models.Tld
	tldAnonByName          map[string]*models.TldAnon
	publicSuffixByName     map[string]*models.PublicSuffix
	publicSuffixAnonByName map[string]*models.PublicSuffixAnon
	apexByName             map[string]*models.Apex
	apexByNameAnon         map[string]*models.ApexAnon
	apexById               map[uint]*models.Apex
	fqdnByName             map[string]*models.Fqdn
	fqdnByNameAnon         map[string]*models.FqdnAnon
	zoneEntriesByApexName  map[string]*models.ZonefileEntry
	certByFingerprint      map[string]*models.Certificate
	logByUrl               map[string]*models.Log
	recordTypeByName       map[string]*models.RecordType
	passiveEntryByFqdn     splunkEntryMap
	entradaEntryByFqdn     map[string]*models.EntradaEntry
}

// prints the current status to standard output
func (c *cache) describe() {
	log.Debug().Msgf("tlds:            %d", len(c.tldByName))
	log.Debug().Msgf("tlds (anon):     %d", len(c.tldAnonByName))
	log.Debug().Msgf("suffixes:        %d", len(c.publicSuffixByName))
	log.Debug().Msgf("suffixes (anon): %d", len(c.publicSuffixAnonByName))
	log.Debug().Msgf("apexes:          %d", len(c.apexByName))
	log.Debug().Msgf("apexes (anon):   %d", len(c.apexByNameAnon))
	log.Debug().Msgf("fqdns:           %d", len(c.fqdnByName))
	log.Debug().Msgf("fqdns (anon):    %d", len(c.fqdnByNameAnon))
	log.Debug().Msgf("zone entries:    %d", len(c.zoneEntriesByApexName))
	log.Debug().Msgf("certificates:    %d", len(c.certByFingerprint))
	log.Debug().Msgf("logs:            %d", len(c.logByUrl))
	log.Debug().Msgf("record types:    %d", len(c.recordTypeByName))
	log.Debug().Msgf("passive entries: %d", c.passiveEntryByFqdn.len())
	log.Debug().Msgf("entrada entries: %d", len(c.entradaEntryByFqdn))
}

func newCache() cache {
	return cache{
		tldByName:              make(map[string]*models.Tld),
		tldAnonByName:          make(map[string]*models.TldAnon),
		publicSuffixByName:     make(map[string]*models.PublicSuffix),
		publicSuffixAnonByName: make(map[string]*models.PublicSuffixAnon),
		apexByName:             make(map[string]*models.Apex),
		apexByNameAnon:         make(map[string]*models.ApexAnon),
		apexById:               make(map[uint]*models.Apex),
		fqdnByName:             make(map[string]*models.Fqdn),
		fqdnByNameAnon:         make(map[string]*models.FqdnAnon),
		zoneEntriesByApexName:  make(map[string]*models.ZonefileEntry),
		logByUrl:               make(map[string]*models.Log),
		certByFingerprint:      make(map[string]*models.Certificate),
		passiveEntryByFqdn:     newSplunkEntryMap(),
		recordTypeByName:       make(map[string]*models.RecordType),
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
	for _, h := range s.postHooks {
		if err := h(s); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) conditionalPostHooks() error {
	if s.updates.Len()+s.inserts.Len() >= s.batchSize {
		return s.runPostHooks()
	}
	return nil
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
	if err := s.db.Model(&tlds).Order("id ASC").Select(); err != nil {
		return err
	}
	for _, tld := range tlds {
		s.cache.tldByName[tld.Tld] = tld
	}

	var tldsAnon []*models.TldAnon
	if err := s.db.Model(&tldsAnon).Order("id ASC").Select(); err != nil {
		return err
	}
	for _, tld := range tldsAnon {
		s.cache.tldAnonByName[tld.Tld.Tld] = tld
	}

	var suffixes []*models.PublicSuffix
	if err := s.db.Model(&suffixes).Order("id ASC").Select(); err != nil {
		return err
	}
	for _, suffix := range suffixes {
		s.cache.publicSuffixByName[suffix.PublicSuffix] = suffix
	}

	var suffixesAnon []*models.PublicSuffixAnon
	if err := s.db.Model(&suffixesAnon).Order("id ASC").Select(); err != nil {
		return err
	}
	for _, suffix := range suffixesAnon {
		s.cache.publicSuffixAnonByName[suffix.PublicSuffix.PublicSuffix] = suffix
	}

	var apexes []*models.Apex
	if err := s.db.Model(&apexes).Order("id ASC").Select(); err != nil {
		return err
	}
	for _, apex := range apexes {
		s.cache.apexByName[apex.Apex] = apex
		s.cache.apexById[apex.ID] = apex
	}

	var apexesAnon []*models.ApexAnon
	if err := s.db.Model(&apexesAnon).Order("id ASC").Select(); err != nil {
		return err
	}
	for _, apex := range apexesAnon {
		s.cache.apexByNameAnon[apex.Apex.Apex] = apex
	}

	var fqdns []*models.Fqdn
	if err := s.db.Model(&fqdns).Order("id ASC").Select(); err != nil {
		return err
	}
	fqdnsById := make(map[uint]*models.Fqdn)
	for _, fqdn := range fqdns {
		s.cache.fqdnByName[fqdn.Fqdn] = fqdn
		fqdnsById[fqdn.ID] = fqdn
	}

	var fqdnsAnon []*models.FqdnAnon
	if err := s.db.Model(&fqdnsAnon).Order("id ASC").Select(); err != nil {
		return err
	}
	for _, fqdn := range fqdnsAnon {
		s.cache.fqdnByNameAnon[fqdn.Fqdn.Fqdn] = fqdn
	}

	var entries []*models.ZonefileEntry
	if err := s.db.Model(&entries).Order("id ASC").Select(); err != nil {
		return err
	}
	for _, entry := range entries {
		apex := s.cache.apexById[entry.ApexID]
		s.cache.zoneEntriesByApexName[apex.Apex] = entry
	}

	var logs []*models.Log
	if err := s.db.Model(&logs).Order("id ASC").Select(); err != nil {
		return err
	}
	for _, l := range logs {
		s.cache.logByUrl[l.Url] = l
	}

	var certs []*models.Certificate
	if err := s.db.Model(&certs).Order("id ASC").Select(); err != nil {
		return err
	}
	for _, c := range certs {
		s.cache.certByFingerprint[c.Sha256Fingerprint] = c
	}

	var rtypes []*models.RecordType
	if err := s.db.Model(&rtypes).Order("id ASC").Select(); err != nil {
		return err
	}
	rtypeById := make(map[uint]*models.RecordType)
	for _, rtype := range rtypes {
		s.cache.recordTypeByName[rtype.Type] = rtype
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

	var measurements []*models.Measurement
	if err := s.db.Model(&measurements).Order("id ASC").Select(); err != nil {
		return err
	}

	var stages []*models.Stage
	if err := s.db.Model(&stages).Order("id ASC").Select(); err != nil {
		return err
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
	if len(suffixes) > 1 {
		s.ids.suffixes = suffixes[len(suffixes)-1].ID + 1
	}
	s.ids.suffixesAnon = 1
	if len(suffixesAnon) > 1 {
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

type Opts struct {
	BatchSize       int
	AllowedInterval time.Duration
}

type debugHook struct{}

func (hook *debugHook) BeforeQuery(qe *pg.QueryEvent) {}

func (hook *debugHook) AfterQuery(qe *pg.QueryEvent) {
	fq, err := qe.FormattedQuery()
	if err != nil {
		return
	}
	log.Debug().Msgf("%s", fq)
}

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

	s := Store{
		conf:            conf,
		db:              db,
		cache:           newCache(),
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
	}

	postHook := storeCachedValuePosthook()
	s.postHooks = append(s.postHooks, postHook)

	if err := s.migrate(); err != nil {
		return nil, errs.Wrap(err, "migrate models")
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
			_, err := tx.Model(&z).Column("last_seen").Update()
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

		return nil
	}
}
