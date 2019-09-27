package http

import (
	"fmt"
	zone2 "github.com/aau-network-security/go-domains/collectors/zone"
	"io"
	"net/http"
)

type NotOkStatusErr struct {
	code int
}

func (err NotOkStatusErr) Error() string {
	return fmt.Sprintf("http error: status code %d", err.code)
}

type Config struct {
	Tld string `yaml:"tld"`
	Url string `yaml:"url"`
}

type httpZone struct {
	conf Config
	c    *http.Client
}

func (z *httpZone) Tld() string {
	return z.conf.Tld
}

func (z *httpZone) Stream() (io.ReadCloser, error) {
	req, err := http.NewRequest("GET", z.conf.Url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := z.c.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		return nil, NotOkStatusErr{resp.StatusCode}
	}
	return resp.Body, nil
}

func New(conf Config, client *http.Client) (zone2.Zone, error) {
	if client == nil {
		client = http.DefaultClient
	}

	s := httpZone{
		conf: conf,
		c:    client,
	}
	return &s, nil
}
