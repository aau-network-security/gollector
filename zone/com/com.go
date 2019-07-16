package com

import (
	"compress/gzip"
	"errors"
	"github.com/jlaffaye/ftp"
	"github.com/kdhageman/go-domains/store"
	"github.com/kdhageman/go-domains/zone"
	"github.com/miekg/dns"
	"io"
	"io/ioutil"
	"os"
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
	file  *os.File
	conn  *ftp.ServerConn
	cache store.Cache
	seen  map[string]interface{}
}

func (zone *com) Download() error {
	f, err := ioutil.TempFile("com", "")
	if err != nil {
		return err
	}
	defer f.Close()

	resp, err := zone.conn.Retr(zoneFileName)
	if err != nil {
		return err
	}

	w := gzip.NewWriter(f)

	n, err := io.Copy(w, resp)
	if err != nil {
		return err
	}
	if n == 0 {
		return errors.New(".com zone file was empty")
	}

	return nil
}

func (zone *com) Process(f func(domainName string) error) error {
	for t := range dns.ParseZone(zone.file, "", "") {
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

func NewCom(conf Config, cache store.Cache) (zone.Zone, error) {
	conn, err := ftp.Dial(conf.Addr)
	if err != nil {
		return nil, err
	}

	if err := conn.Login(conf.Username, conf.Password); err != nil {
		return nil, err
	}

	c := com{
		conn:  conn,
		cache: cache,
		seen:  map[string]interface{}{},
	}
	return &c, nil
}
