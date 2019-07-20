package http

import (
	"github.com/aau-network-security/go-domains/zone"
	"github.com/aau-network-security/go-domains/zone/ssh"
	"github.com/rs/zerolog/log"
	"os"
	"testing"
)

func TestSocks(t *testing.T) {

	sshConf := ssh.Config{
		Host:     "js3.es.aau.dk",
		User:     os.Getenv("AAU_USER"),
		AuthType: "password",
		Password: os.Getenv("AAU_PASS"),
	}

	httpConf := Config{
		Url: "https://xn--domneliste-f6a.dk-hostmaster.dk/domainlist.txt",
	}

	httpClient, err := ssh.HttpClient(sshConf)
	if err != nil {
		t.Fatalf("error while creating HTTP-over-SSH client: %s", err)
	}

	s, err := New(httpConf, httpClient)
	if err != nil {
		t.Fatalf("error while creating HTTP zone retriever: %s", err)
	}

	f := func(domain string) error {
		log.Debug().Msgf("%s", domain)
		return nil
	}

	opts := zone.ProcessOpts{
		DomainFunc:     f,
		StreamWrappers: []zone.StreamWrapper{},
		StreamHandler:  zone.ListHandler,
	}

	if err := zone.Process(s, opts); err != nil {
		t.Fatalf("error while processing zone: %s", err)
	}
}
