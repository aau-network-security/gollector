package store

import (
	"time"

	"github.com/aau-network-security/gollector/testing"
	"github.com/jinzhu/gorm"
	"github.com/pkg/errors"
)

var TestOpts = Opts{
	BatchSize: 10,
	CacheOpts: CacheOpts{
		LogSize:       3,
		TLDSize:       3,
		PSuffSize:     3,
		ApexSize:      5,
		FQDNSize:      5,
		CertSize:      5,
		ZoneEntrySize: 10,
	},
	AllowedInterval: 10 * time.Millisecond,
}

var TestConfig = Config{
	User:     "postgres",
	Password: "postgres",
	DBName:   "domains",
	Host:     "localhost",
	Port:     5432,
}

func OpenStore(conf Config, opts Opts) (*Store, *gorm.DB, string, error) {
	g, err := conf.Open()
	if err != nil {
		return nil, nil, "", errors.Wrap(err, "failed to open gorm database")
	}

	if err := testing.ResetDb(g); err != nil {
		return nil, nil, "", errors.Wrap(err, "failed to reset database")
	}

	s, err := NewStore(conf, opts)
	if err != nil {
		return nil, nil, "", errors.Wrap(err, "failed to open store")
	}
	s.Ready.Wait()

	muid, err := s.StartMeasurement("test", "test.local")
	if err != nil {
		return nil, nil, "", errors.Wrap(err, "failed to start measurement")
	}

	return s, g, muid, nil
}
