package store

import (
	"time"

	"github.com/aau-network-security/gollector/testing"
	"github.com/jinzhu/gorm"
	"github.com/pkg/errors"
)

func OpenStore(conf Config) (*Store, *gorm.DB, string, error) {
	g, err := conf.Open()
	if err != nil {
		return nil, nil, "", errors.Wrap(err, "failed to open gorm database")
	}

	if err := testing.ResetDb(g); err != nil {
		return nil, nil, "", errors.Wrap(err, "failed to reset database")
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
		return nil, nil, "", errors.Wrap(err, "failed to open store")
	}
	s.Ready.Wait()

	muid, err := s.StartMeasurement("test", "test.local")
	if err != nil {
		return nil, nil, "", errors.Wrap(err, "failed to start measurement")
	}

	return s, g, muid, nil
}
