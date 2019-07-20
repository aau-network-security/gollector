package czds

import (
	"github.com/aau-network-security/go-domains/zone"
	"io"
)

type Config struct {
	Tld      string `yaml:"tld"`
	Username string `yaml:"username"`
	Password string
}

type czdsZone struct {
	conf   Config
	client Client
	seen   map[string]interface{}
}

func (z *czdsZone) Tld() string {
	return z.conf.Tld
}

func (z *czdsZone) Stream() (io.Reader, error) {
	return z.client.GetZone(z.conf.Tld)
}

func New(conf Config) zone.Zone {
	client := NewClient(conf)

	zone := czdsZone{
		conf:   conf,
		client: client,
		seen:   make(map[string]interface{}),
	}
	return &zone
}
