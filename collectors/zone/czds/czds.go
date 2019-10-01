package czds

import (
	zone2 "github.com/aau-network-security/gollector/collectors/zone"
	"io"
)

type Credentials struct {
	Username string `yaml:"username"`
	Password string
}

type czdsZone struct {
	tld    string
	client Client
}

func (z *czdsZone) Tld() string {
	return z.tld
}

func (z *czdsZone) Stream() (io.ReadCloser, error) {
	return z.client.GetZone(z.tld)
}

func New(authenticator *Authenticator, tld string) zone2.Zone {
	client := NewClient(authenticator)

	zone := czdsZone{
		tld:    tld,
		client: client,
	}
	return &zone
}

func NewFromClient(client Client, tld string) zone2.Zone {
	return &czdsZone{
		tld:    tld,
		client: client,
	}
}
