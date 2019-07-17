package com

import (
	"compress/gzip"
	"github.com/jlaffaye/ftp"
	"github.com/kdhageman/go-domains/store"
	"github.com/kdhageman/go-domains/zone"
	"github.com/miekg/dns"
	"strings"
)

const (
	zoneFileName = "com.zone.gz"
)

type Config struct {
	Addr     string
	Username string
	Password string
}

type com struct {
	client zone.FtpClient
	cache  store.Cache
	seen   map[string]interface{}
}

func (zone *com) Process(f zone.DomainFunc) error {
	resp, err := zone.client.Retr(zoneFileName)
	if err != nil {
		return err
	}

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

func NewCom(conf Config, cache store.Cache, client zone.FtpClient) (zone.Zone, error) {
	if client == nil {
		client, err := ftp.Dial(conf.Addr)
		if err != nil {
			return nil, err
		}

		if err := client.Login(conf.Username, conf.Password); err != nil {
			return nil, err
		}
	}

	c := com{
		client: client,
		cache:  cache,
		seen:   map[string]interface{}{},
	}
	return &c, nil
}
