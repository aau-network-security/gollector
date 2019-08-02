package store

import (
	"fmt"
	"github.com/aau-network-security/go-domains/models"
	"github.com/jinzhu/gorm"
	"testing"
	"time"
)

func resetDb(g *gorm.DB) error {
	tables := []string{
		"apexes",
		"zonefile_entries",
		"tlds",
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
	}
	for _, ex := range migrateExamples {
		if err := g.AutoMigrate(ex).Error; err != nil {
			return err
		}
	}
	return nil
}

// test against locally running postgres server
func TestStore(t *testing.T) {
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

	s, err := NewStore(conf, 10, 10*time.Millisecond)
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

	s, err := NewStore(conf, 10, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("failed to create store: %s", err)
	}

	if s.ids.apexes != 11 {
		t.Fatalf("expected next id to be %d, but got %d", 11, s.ids.apexes)
	}
}
