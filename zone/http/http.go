package http

import (
	"github.com/aau-network-security/go-domains/zone"
	"io"
	"net/http"
)

type Config struct {
	Url string `yaml:"url"`
}

type httpZone struct {
	conf Config
	c    *http.Client
}

func (z *httpZone) Stream() (io.Reader, error) {
	req, err := http.NewRequest("GET", z.conf.Url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := z.c.Do(req)
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

func New(conf Config, client *http.Client) (zone.Zone, error) {
	if client == nil {
		client = http.DefaultClient
	}

	s := httpZone{
		conf: conf,
		c:    client,
	}
	return &s, nil
}
