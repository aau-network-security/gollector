package socks

import (
	"github.com/aau-network-security/go-domains/zone"
	"github.com/rs/zerolog/log"
	"os"
	"testing"
)

func TestSocks(t *testing.T) {
	conf := Config{
		SSH: SSH{
			//Host:     "kh@js3.es.aau.dk",
			Host:     "js3.es.aau.dk:22",
			User:     os.Getenv("AAU_USER"),
			Password: os.Getenv("AAU_PASS"),
		},
		Url: "https://xn--domneliste-f6a.dk-hostmaster.dk/domainlist.txt",
	}
	s, err := New(conf)
	if err != nil {
		t.Fatalf("error while creating SOCKS zone retriever: %s", err)
	}

	f := func(domain string) error {
		log.Debug().Msgf("%s", domain)
		return nil
	}

	if err := zone.Process(s, f); err != nil {
		t.Fatalf("error while processing zone: %s", err)
	}
}
