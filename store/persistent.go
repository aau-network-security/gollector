package store

import (
	"fmt"
	"github.com/aau-network-security/go-domains/models"
	"github.com/go-pg/pg"
	"github.com/jinzhu/gorm"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
	"strings"
	"sync"
	"time"
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
	zoneEntries map[uint]*models.ZonefileEntry
	apexes      map[uint]*models.Apex
}

func (s *ModelSet) Len() int {
	return len(s.zoneEntries) + len(s.apexes)
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
		zoneEntries: make(map[uint]*models.ZonefileEntry),
		apexes:      make(map[uint]*models.Apex),
	}
}

type postHook func(*Store) error

type Ids struct {
	zoneEntries, apexes, tlds uint
}

type Store struct {
	conf                  Config
	db                    *pg.DB
	apexByName            map[string]*models.Apex
	apexById              map[uint]*models.Apex
	zoneEntriesByApexName map[string]*models.ZonefileEntry
	tldByName             map[string]*models.Tld

	allowedInterval time.Duration
	m               *sync.Mutex
	batchSize       int
	postHooks       []postHook
	ids             Ids

	inserts ModelSet
	updates ModelSet
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

func (s *Store) getOrCreateTld(tld string) (*models.Tld, error) {
	t, ok := s.tldByName[tld]
	if !ok {
		t = &models.Tld{
			ID:  s.ids.tlds,
			Tld: tld,
		}
		if err := s.db.Insert(t); err != nil {
			return nil, err
		}

		s.tldByName[tld] = t
		s.ids.tlds++
	}
	return t, nil
}

func (s *Store) storeApexDomain(name string) (*models.Apex, error) {
	splitted := strings.Split(name, ".")
	if len(splitted) == 1 {
		return nil, InvalidDomainErr{name}
	}

	tld, err := s.getOrCreateTld(splitted[len(splitted)-1])
	if err != nil {
		return nil, err
	}

	model := &models.Apex{
		ID:    s.ids.apexes,
		Apex:  name,
		TldID: tld.ID,
	}

	s.apexByName[name] = model
	s.inserts.apexes[model.ID] = model
	s.ids.apexes++

	if err := s.conditionalPostHooks(); err != nil {
		return nil, err
	}

	return model, nil
}

func (s *Store) getOrCreateApex(domain string) (*models.Apex, error) {
	res, ok := s.apexByName[domain]
	if !ok {
		var err error
		res, err = s.storeApexDomain(domain)
		if err != nil {
			return nil, err
		}
	}
	return res, nil
}

func (s *Store) StoreZoneEntry(t time.Time, domain string) (*models.ZonefileEntry, error) {
	s.m.Lock()
	defer s.m.Unlock()
	apexModel, err := s.getOrCreateApex(domain)
	if err != nil {
		return nil, err
	}

	existingZoneEntry, ok := s.zoneEntriesByApexName[domain]
	if !ok {
		// non-active domain, create a new zone entry
		newZoneEntry := &models.ZonefileEntry{
			ID:        s.ids.zoneEntries,
			ApexID:    apexModel.ID,
			FirstSeen: t,
			LastSeen:  t,
			Active:    true,
		}

		s.zoneEntriesByApexName[domain] = newZoneEntry
		s.inserts.zoneEntries[newZoneEntry.ID] = newZoneEntry
		s.ids.zoneEntries++

		if err := s.conditionalPostHooks(); err != nil {
			return nil, err
		}

		return newZoneEntry, nil
	}

	// active domain
	if existingZoneEntry.LastSeen.Before(time.Now().Add(-s.allowedInterval)) {
		// detected re-registration, set old entry inactive and create new

		existingZoneEntry.Active = false
		s.updates.zoneEntries[existingZoneEntry.ID] = existingZoneEntry

		newZoneEntry := &models.ZonefileEntry{
			ID:        s.ids.zoneEntries,
			ApexID:    apexModel.ID,
			FirstSeen: t,
			LastSeen:  t,
			Active:    true,
		}

		s.zoneEntriesByApexName[domain] = newZoneEntry
		s.inserts.zoneEntries[newZoneEntry.ID] = newZoneEntry
		s.ids.zoneEntries++

		if err := s.conditionalPostHooks(); err != nil {
			return nil, err
		}

		return newZoneEntry, nil
	}

	// update existing
	existingZoneEntry.LastSeen = t
	s.updates.zoneEntries[existingZoneEntry.ID] = existingZoneEntry

	if err := s.conditionalPostHooks(); err != nil {
		return nil, err
	}

	return existingZoneEntry, nil
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
	if err := s.db.Model(&apexes).Select(); err != nil {
		return err
	}
	for _, apex := range apexes {
		s.apexByName[apex.Apex] = apex
		s.apexById[apex.ID] = apex
	}

	var entries []*models.ZonefileEntry
	if err := s.db.Model(&entries).Select(); err != nil {
		return err
	}
	for _, entry := range entries {
		apex := s.apexById[entry.ApexID]
		s.zoneEntriesByApexName[apex.Apex] = entry
	}

	var tlds []*models.Tld
	if err := s.db.Model(&entries).Select(); err != nil {
		return err
	}
	for _, tld := range tlds {
		s.tldByName[tld.Tld] = tld
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
		s.ids.tlds = entries[len(tlds)-1].ID + 1
	}

	return nil
}

func NewStore(conf Config, batchSize int, allowedInterval time.Duration) (*Store, error) {
	opts := pg.Options{
		User:     conf.User,
		Password: conf.Password,
		Addr:     fmt.Sprintf("%s:%d", conf.Host, conf.Port),
		Database: conf.DBName,
	}

	db := pg.Connect(&opts)

	s := Store{
		conf:                  conf,
		db:                    db,
		apexByName:            make(map[string]*models.Apex),
		apexById:              make(map[uint]*models.Apex),
		zoneEntriesByApexName: make(map[string]*models.ZonefileEntry),
		tldByName:             make(map[string]*models.Tld),
		allowedInterval:       allowedInterval,
		m:                     &sync.Mutex{},
		batchSize:             batchSize,
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
		if len(s.inserts.apexes) > 0 {
			a := s.inserts.apexList()
			if err := tx.Insert(&a); err != nil {
				return err
			}
		}
		if len(s.inserts.zoneEntries) > 0 {
			z := s.inserts.zoneEntryList()
			if err := tx.Insert(&z); err != nil {
				return err
			}
		}
		if len(s.updates.apexes) > 0 {
			a := s.updates.apexList()
			if err := tx.Update(&a); err != nil {
				return err
			}
		}
		if len(s.updates.zoneEntries) > 0 {
			z := s.updates.zoneEntryList()
			_, err := tx.Model(&z).Column("last_seen").Update()
			if err != nil {
				return err
			}
		}
		s.updates = NewModelSet()
		s.inserts = NewModelSet()

		return tx.Commit()
	}

	s.postHooks = append(s.postHooks, postHook)

	if err := s.migrate(); err != nil {
		return nil, err
	}

	if err := s.init(); err != nil {
		return nil, err
	}
	return &s, nil
}
