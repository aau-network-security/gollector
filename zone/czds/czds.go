package czds

import (
	"github.com/aau-network-security/go-domains/zone"
	"io"
)

type Config struct {
	Zone     string `yaml:"zone"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type czdsZone struct {
	conf   Config
	client Client
	seen   map[string]interface{}
}

func (z *czdsZone) Stream() (io.Reader, error) {
	return z.client.GetZone(z.conf.Zone)
}

func (z *czdsZone) GzipRequired() bool {
	return true
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
