package store

import (
	"github.com/aau-network-security/go-domains/models"
	"testing"
	"time"
)

func TestStore(t *testing.T) {
	conf := Config{
		DriverName: "sqlite3",
	}
	s, err := NewStore(conf, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("Failed to create store: %s", err)
	}

	iterations := 3
	for i := 0; i < iterations; i++ {
		for j := 0; j < 10; j++ {
			if _, err := s.StoreZoneEntry(time.Now(), "example.org"); err != nil {
				t.Fatalf("Error while storing entry: %s", err)
			}
		}
		time.Sleep(15 * time.Millisecond)
	}

	counts := []struct {
		count      uint
		model      interface{}
		whereQuery interface{}
		whereArgs  interface{}
	}{
		{1, &models.Apex{}, nil, nil},
		{3, &models.ZonefileEntry{}, nil, nil},
		{1, &models.ZonefileEntry{Active: true}, "active", true},
	}

	for _, tc := range counts {
		var count uint
		qry := s.db.Model(tc.model)
		if tc.whereQuery != nil {
			qry = qry.Where(tc.whereQuery, tc.whereArgs)
		}

		if err := qry.Count(&count).Error; err != nil {
			t.Fatalf("failed to retrieve apex count: %s", err)
		}

		if count != tc.count {
			t.Fatalf("expected %d elements, but got %d", tc.count, count)
		}
	}
}

func TestDsn(t *testing.T) {
	tests := []struct {
		name     string
		conf     Config
		expected string
	}{
		{
			"in memory sqlite3",
			Config{
				DriverName: SQLITE,
			},
			"file::memory:?mode=memory&cache=shared",
		},
		{
			"file sqlite3",
			Config{
				DriverName: SQLITE,
				FileName:   "test.db",
			},
			"file:test.db",
		},
		{
			"mysql",
			Config{
				DriverName: MYSQL,
				Host:       "host",
				Password:   "pass",
				User:       "user",
				DBName:     "db",
				Port:       5901,
			},
			"user:pass@tcp(host:5901)/db?allowNativePasswords=false&interpolateParams=true&maxAllowedPacket=0&parseTime=true",
		},
		{
			"postgres",
			Config{
				DriverName: POSTGRES,
				Host:       "host",
				Password:   "pass",
				User:       "user",
				DBName:     "db",
				Port:       5901,
			},
			"host=host port=5901 user=user password=pass dbname=db sslmode=disable",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := test.conf.DSN()
			if actual != test.expected {
				t.Fatalf("expected DSN '%s', but got '%s'", test.expected, actual)
			}
		})
	}
}
