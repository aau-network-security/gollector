package czds

import (
	"github.com/aau-network-security/go-domains/zone"
	"github.com/rs/zerolog/log"
	"os"
	"testing"
)

func TestCzds(t *testing.T) {
	user := os.Getenv("CZDS_USER")
	pass := os.Getenv("CZDS_PASS")
	conf := Config{
		Zone:     "net",
		Username: user,
		Password: pass,
	}
	z := New(conf)
	f := func(domain string) error {
		log.Debug().Msgf("%s", domain)
		return nil
	}

	opts := zone.ProcessOpts{
		DomainFunc:     f,
		StreamWrappers: []zone.StreamWrapper{zone.GzipWrapper},
		StreamHandler:  zone.ZoneFileHandler,
	}

	if err := zone.Process(z, opts); err != nil {
		t.Fatalf("Error while processing CZDS zone file: %s", err)
	}
}
