package czds

import (
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
	c := NewCzds(conf)
	f := func(domain string) error {
		log.Debug().Msgf("%s", domain)
		return nil
	}

	if err := c.Process(f); err != nil {
		t.Fatalf("Error while processing CZDS zone file: %s", err)
	}
}
