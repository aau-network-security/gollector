package store

import (
	"errors"
	"fmt"
	"github.com/aau-network-security/go-domains/models"
	"github.com/go-pg/pg"
	"github.com/jinzhu/gorm"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
	errors2 "github.com/pkg/errors"
	"sync"
	"time"
)

var (
	UnsupportedCertTypeErr = errors.New("provided certificate is not supported")
	DefaultOpts            = Opts{
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
	apexes         map[uint]*models.Apex
	certs          []*models.Certificate
	logEntries     []*models.LogEntry
	certToFqdns    []*models.CertificateToFqdn
	fqdns          []*models.Fqdn
	passiveEntries []*models.PassiveEntry
}

func (s *ModelSet) Len() int {
	return len(s.zoneEntries) +
		len(s.apexes) +
		len(s.certs) +
		len(s.logEntries) +
		len(s.certToFqdns) +
		len(s.fqdns) +
		len(s.passiveEntries)
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

func NewModelSet() ModelSet {
	return ModelSet{
		zoneEntries:    make(map[uint]*models.ZonefileEntry),
		apexes:         make(map[uint]*models.Apex),
		fqdns:          []*models.Fqdn{},
		certToFqdns:    []*models.CertificateToFqdn{},
		certs:          []*models.Certificate{},
		logEntries:     []*models.LogEntry{},
		passiveEntries: []*models.PassiveEntry{},
	}
}

type postHook func(*Store) error

type Ids struct {
	zoneEntries, apexes, tlds, pss, certs, logs, fqdns, recordTypes, measurements, stages uint
}

type Store struct {
	conf                  Config
	db                    *pg.DB
	apexByName            map[string]*models.Apex
	apexById              map[uint]*models.Apex
	zoneEntriesByApexName map[string]*models.ZonefileEntry
	tldByName             map[string]*models.Tld
	publicSuffixByName    map[string]*models.PublicSuffix
	certByFingerprint     map[string]*models.Certificate
	logByUrl              map[string]*models.Log
	fqdnByName            map[string]*models.Fqdn
	recordTypeByName      map[string]*models.RecordType
	passiveEntryByFqdn    splunkEntryMap
	m                     *sync.Mutex
	ids                   Ids
	allowedInterval       time.Duration
	batchSize             int
	postHooks             []postHook
	inserts               ModelSet
	updates               ModelSet
	curStage              *models.Stage
	curMeasurement        *models.Measurement
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
		&models.Apex{},
		&models.ZonefileEntry{},
		&models.Tld{},
		&models.Fqdn{},
		&models.CertificateToFqdn{},
		&models.Certificate{},
		&models.LogEntry{},
		&models.Log{},
		&models.RecordType{},
		&models.PassiveEntry{},
		&models.Measurement{},
		&models.Stage{},
		&models.PublicSuffix{},
	}
	for _, ex := range migrateExamples {
		if err := g.AutoMigrate(ex).Error; err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) init() error {
	var apexes []*models.Apex
	if err := s.db.Model(&apexes).Order("id ASC").Select(); err != nil {
		return err
	}
	for _, apex := range apexes {
		s.apexByName[apex.Apex] = apex
		s.apexById[apex.ID] = apex
	}

	var entries []*models.ZonefileEntry
	if err := s.db.Model(&entries).Order("id ASC").Select(); err != nil {
		return err
	}
	for _, entry := range entries {
		apex := s.apexById[entry.ApexID]
		s.zoneEntriesByApexName[apex.Apex] = entry
	}

	var tlds []*models.Tld
	if err := s.db.Model(&tlds).Order("id ASC").Select(); err != nil {
		return err
	}
	for _, tld := range tlds {
		s.tldByName[tld.Tld] = tld
	}

	var pss []*models.PublicSuffix
	if err := s.db.Model(&pss).Order("id ASC").Select(); err != nil {
		return err
	}
	for _, ps := range pss {
		s.publicSuffixByName[ps.PublicSuffix] = ps
	}

	var fqdns []*models.Fqdn
	if err := s.db.Model(&fqdns).Order("id ASC").Select(); err != nil {
		return err
	}
	fqdnsById := make(map[uint]*models.Fqdn)
	for _, fqdn := range fqdns {
		s.fqdnByName[fqdn.Fqdn] = fqdn
		fqdnsById[fqdn.ID] = fqdn
	}

	var logs []*models.Log
	if err := s.db.Model(&logs).Order("id ASC").Select(); err != nil {
		return err
	}
	for _, l := range logs {
		s.logByUrl[l.Url] = l
	}

	var certs []*models.Certificate
	if err := s.db.Model(&certs).Order("id ASC").Select(); err != nil {
		return err
	}
	for _, c := range certs {
		s.certByFingerprint[c.Sha256Fingerprint] = c
	}

	var rtypes []*models.RecordType
	if err := s.db.Model(&rtypes).Order("id ASC").Select(); err != nil {
		return err
	}
	rtypeById := make(map[uint]*models.RecordType)
	for _, rtype := range rtypes {
		s.recordTypeByName[rtype.Type] = rtype
		rtypeById[rtype.ID] = rtype
	}

	var passiveEntries []*models.PassiveEntry
	if err := s.db.Model(&passiveEntries).Order("id ASC").Select(); err != nil {
		return err
	}
	for _, entry := range passiveEntries {
		fqdn := fqdnsById[entry.FqdnID]
		rtype := rtypeById[entry.RecordTypeID]
		s.passiveEntryByFqdn.add(fqdn.Fqdn, rtype.Type, entry)
	}

	var measurements []*models.Measurement
	if err := s.db.Model(&measurements).Order("id ASC").Select(); err != nil {
		return err
	}

	var stages []*models.Stage
	if err := s.db.Model(&stages).Order("id ASC").Select(); err != nil {
		return err
	}

	s.ids.apexes = 1
	if len(apexes) > 0 {
		s.ids.apexes = apexes[len(apexes)-1].ID + 1
	}
	s.ids.zoneEntries = 1
	if len(entries) > 0 {
		s.ids.zoneEntries = entries[len(entries)-1].ID + 1
	}
	s.ids.tlds = 1
	if len(tlds) > 0 {
		s.ids.tlds = tlds[len(tlds)-1].ID + 1
	}
	s.ids.pss = 1
	if len(pss) > 1 {
		s.ids.pss = pss[len(pss)-1].ID + 1
	}
	s.ids.fqdns = 1
	if len(fqdns) > 0 {
		s.ids.fqdns = fqdns[len(fqdns)-1].ID + 1
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
	s.ids.measurements = 1
	if len(measurements) > 0 {
		s.ids.measurements = measurements[len(measurements)-1].ID + 1
	}
	s.ids.stages = 1
	if len(stages) > 0 {
		s.ids.stages = stages[len(stages)-1].ID + 1
	}

	return nil
}

type Opts struct {
	BatchSize       int
	AllowedInterval time.Duration
}

func NewStore(conf Config, opts Opts) (*Store, error) {
	pgOpts := pg.Options{
		User:     conf.User,
		Password: conf.Password,
		Addr:     fmt.Sprintf("%s:%d", conf.Host, conf.Port),
		Database: conf.DBName,
	}

	db := pg.Connect(&pgOpts)

	s := Store{
		conf:                  conf,
		db:                    db,
		apexByName:            make(map[string]*models.Apex),
		apexById:              make(map[uint]*models.Apex),
		zoneEntriesByApexName: make(map[string]*models.ZonefileEntry),
		tldByName:             make(map[string]*models.Tld),
		publicSuffixByName:    make(map[string]*models.PublicSuffix),
		fqdnByName:            make(map[string]*models.Fqdn),
		logByUrl:              make(map[string]*models.Log),
		certByFingerprint:     make(map[string]*models.Certificate),
		passiveEntryByFqdn:    newSplunkEntryMap(),
		recordTypeByName:      make(map[string]*models.RecordType),
		allowedInterval:       opts.AllowedInterval,
		batchSize:             opts.BatchSize,
		m:                     &sync.Mutex{},
		postHooks:             []postHook{},
		inserts:               NewModelSet(),
		updates:               NewModelSet(),
		ids:                   Ids{},
	}

	postHook := func(s *Store) error {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		defer tx.Rollback()

		// inserts
		if len(s.inserts.apexes) > 0 {
			a := s.inserts.apexList()
			if err := tx.Insert(&a); err != nil {
				return errors2.Wrap(err, "insert apexes")
			}
		}
		if len(s.inserts.zoneEntries) > 0 {
			z := s.inserts.zoneEntryList()
			if err := tx.Insert(&z); err != nil {
				return errors2.Wrap(err, "insert zone entries")
			}
		}
		if len(s.inserts.logEntries) > 0 {
			if err := tx.Insert(&s.inserts.logEntries); err != nil {
				return errors2.Wrap(err, "insert log entries")
			}
		}
		if len(s.inserts.certs) > 0 {
			if err := tx.Insert(&s.inserts.certs); err != nil {
				return errors2.Wrap(err, "insert certs")
			}
		}
		if len(s.inserts.certToFqdns) > 0 {
			if err := tx.Insert(&s.inserts.certToFqdns); err != nil {
				return errors2.Wrap(err, "insert cert-to-fqdns")
			}
		}
		if len(s.inserts.fqdns) > 0 {
			if err := tx.Insert(&s.inserts.fqdns); err != nil {
				return errors2.Wrap(err, "insert fqdns")
			}
		}
		if len(s.inserts.passiveEntries) > 0 {
			if err := tx.Insert(&s.inserts.passiveEntries); err != nil {
				return errors2.Wrap(err, "insert passive entries")
			}
		}

		// updates
		if len(s.updates.apexes) > 0 {
			a := s.updates.apexList()
			if err := tx.Update(&a); err != nil {
				return errors2.Wrap(err, "update apexes")
			}
		}
		if len(s.updates.zoneEntries) > 0 {
			z := s.updates.zoneEntryList()
			_, err := tx.Model(&z).Column("last_seen").Update()
			if err != nil {
				return errors2.Wrap(err, "update zone entries")
			}
		}
		if len(s.updates.passiveEntries) > 0 {
			if _, err := tx.Model(&s.updates.passiveEntries).Column("first_seen").Update(); err != nil {
				return errors2.Wrap(err, "update passive entries")
			}
		}

		s.updates = NewModelSet()
		s.inserts = NewModelSet()

		return tx.Commit()
	}

	s.postHooks = append(s.postHooks, postHook)

	if err := s.migrate(); err != nil {
		return nil, errors2.Wrap(err, "migrate models")
	}

	if err := s.init(); err != nil {
		return nil, errors2.Wrap(err, "initialize database")
	}

	s.curStage = &models.Stage{}
	s.curMeasurement = &models.Measurement{}

	return &s, nil
}
