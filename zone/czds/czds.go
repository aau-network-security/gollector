package czds

import (
	"github.com/kdhageman/go-domains/zone"
)

type Config struct {
	Username string
	Password string
}

type czds struct {
	client Client
}

func NewCzds(conf Config) (zone.Zone, error) {
	client := NewClient(conf)

	zone := czds{
		client: client,
	}
	return &zone, nil
}

func (zone *czds) Download() error {
	panic("implement me")
}

func (zone *czds) Process(f func(domainName string) error) error {
	return nil
}
