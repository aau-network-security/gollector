package czds

import (
	"compress/gzip"
	"github.com/kdhageman/go-domains/zone"
	"github.com/miekg/dns"
	"strings"
)

type Config struct {
	Zone     string `yaml:"zone"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type czds struct {
	conf   Config
	client Client
	seen   map[string]interface{}
}

func (zone *czds) Process(f zone.DomainFunc) error {
	resp, err := zone.client.GetZone(zone.conf.Zone)
	if err != nil {
		return err
	}
	defer resp.Close()

	r, err := gzip.NewReader(resp)
	if err != nil {
		return err
	}

	for t := range dns.ParseZone(r, "", "") {
		if t.Error != nil {
			return t.Error
		}
		switch v := t.RR.(type) {
		case *dns.NS:
			domain := strings.TrimSuffix(strings.ToLower(v.Header().Name), ".")

			if _, ok := zone.seen[domain]; !ok {
				if err := f(domain); err != nil {
					return err
				}
				zone.seen[domain] = nil
			}
		}
	}
	return nil
}

func NewCzds(conf Config) zone.Zone {
	client := NewClient(conf)

	zone := czds{
		conf:   conf,
		client: client,
		seen:   make(map[string]interface{}),
	}
	return &zone
}
