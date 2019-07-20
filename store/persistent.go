package store

import (
	"fmt"
	"github.com/aau-network-security/go-domains/models"
	"github.com/go-sql-driver/mysql"
	"github.com/jinzhu/gorm"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
	"sync"
	"time"
)

var (
	SQLITE   = "sqlite3"
	MYSQL    = "mysql"
	POSTGRES = "postgres"
)

type EntryExistsErr struct {
	Domain string
}

func (err EntryExistsErr) Error() string {
	return fmt.Sprintf("trying to store zonefile entry for existing domain '%s'", err.Domain)
}

type Config struct {
	User       string `yaml:"user"`
	Password   string `yaml:"password"`
	Host       string `yaml:"host"`
	Port       int    `yaml:"port"`
	DBName     string `yaml:"dbname"`
	DriverName string `yaml:"driver"`
	FileName   string `yaml:"filename"`

	d *gorm.DB
}

func (c *Config) Open() (*gorm.DB, error) {
	var err error
	if c.d == nil {
		c.d, err = gorm.Open(c.DriverName, c.DSN())
	}
	return c.d, err
}

func (c *Config) DSN() string {
	var dsn string
	switch c.DriverName {
	case SQLITE:
		switch c.FileName {
		case "": // in memory
			dsn = "file::memory:?mode=memory&cache=shared"
		default:
			dsn = fmt.Sprintf("file:%s", c.FileName)
		}
	case MYSQL: // default to postgres
		conf := mysql.Config{
			User:              c.User,
			Passwd:            c.Password,
			Net:               "tcp",
			Addr:              fmt.Sprintf("%s:%d", c.Host, c.Port),
			DBName:            c.DBName,
			InterpolateParams: true,
			Params: map[string]string{
				"parseTime": "true",
			},
		}
		dsn = conf.FormatDSN()
	case POSTGRES, "": // default to postgres
		return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
			c.Host, c.Port, c.User, c.Password, c.DBName)
	}
	return dsn
}

type Store struct {
	db          *gorm.DB
	apexes      map[string]*models.Apex
	zoneEntries map[string]*models.ZonefileEntry

	allowedInterval time.Duration
	apexMutex       *sync.Mutex
}

func (s *Store) StoreApexDomain(name string) (*models.Apex, error) {
	model := models.Apex{
		Apex: name,
	}
	if err := s.db.Create(&model).Error; err != nil {
		return nil, err
	}
	s.apexMutex.Lock()
	s.apexes[name] = &model
	s.apexMutex.Unlock()
	return &model, nil
}

func (s *Store) GetApexDomain(domain string) (*models.Apex, error) {
	res, ok := s.apexes[domain]
	if !ok {
		var err error
		res, err = s.StoreApexDomain(domain)
		if err != nil {
			return nil, err
		}
	}
	return res, nil
}

func (s *Store) StoreZoneEntry(t time.Time, domain string) (*models.ZonefileEntry, error) {
	apexModel, err := s.GetApexDomain(domain)
	if err != nil {
		return nil, err
	}

	existingZoneEntry, ok := s.zoneEntries[domain]
	if !ok {
		// non-active domain, create a new zone entry
		newZoneEntry := &models.ZonefileEntry{
			Apex:      *apexModel,
			FirstSeen: t,
			LastSeen:  t,
			Active:    true,
		}

		if err := s.db.Create(&newZoneEntry).Error; err != nil {
			return nil, err
		}
		s.apexMutex.Lock()
		s.zoneEntries[domain] = newZoneEntry
		s.apexMutex.Unlock()

		return newZoneEntry, nil
	}

	// active domain
	if existingZoneEntry.LastSeen.Before(time.Now().Add(-s.allowedInterval)) {
		// detected re-registration, set old entry inactive and create new
		if err := s.db.Model(existingZoneEntry).Update("active", false).Error; err != nil {
			return nil, err
		}

		newZoneEntry := &models.ZonefileEntry{
			Apex:      *apexModel,
			FirstSeen: t,
			LastSeen:  t,
			Active:    true,
		}

		if err := s.db.Create(&newZoneEntry).Error; err != nil {
			return nil, err
		}

		s.apexMutex.Lock()
		s.zoneEntries[domain] = newZoneEntry
		s.apexMutex.Unlock()

		return newZoneEntry, nil
	}

	// update existing
	if err := s.db.Model(existingZoneEntry).Update("last_seen", t).Error; err != nil {
		return nil, err
	}

	return existingZoneEntry, nil
}

func (s *Store) migrate() error {
	migrateExamples := []interface{}{
		&models.Apex{},
		&models.ZonefileEntry{},
	}
	for _, ex := range migrateExamples {
		if err := s.db.AutoMigrate(ex).Error; err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) init() error {
	s.apexMutex.Lock()
	defer s.apexMutex.Unlock()

	var apexes []models.Apex
	if err := s.db.Find(&apexes).Error; err != nil {
		return err
	}
	for _, apex := range apexes {
		s.apexes[apex.Apex] = &apex
	}

	var entries []models.ZonefileEntry
	if err := s.db.Preload("Apex").Where(models.ZonefileEntry{Active: true}).Find(&entries).Error; err != nil {
		return err
	}
	for _, entry := range entries {
		s.zoneEntries[entry.Apex.Apex] = &entry
	}

	return nil
}

func NewStore(conf Config, allowedInterval time.Duration) (*Store, error) {
	db, err := conf.Open()
	if err != nil {
		return nil, err
	}

	s := Store{
		db:              db,
		apexes:          make(map[string]*models.Apex),
		zoneEntries:     make(map[string]*models.ZonefileEntry),
		allowedInterval: allowedInterval,
		apexMutex:       &sync.Mutex{},
	}

	if err := s.migrate(); err != nil {
		return nil, err
	}

	if err := s.init(); err != nil {
		return nil, err
	}
	return &s, nil
}
