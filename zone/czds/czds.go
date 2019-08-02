package czds

import (
	"github.com/aau-network-security/go-domains/zone"
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

func New(cred Credentials, tld string) zone.Zone {
	client := NewClient(cred)

	zone := czdsZone{
		tld:    tld,
		client: client,
	}
	return &zone
}
