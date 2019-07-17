package ftp

import (
	"github.com/jlaffaye/ftp"
	"github.com/kdhageman/go-domains/store"
	"github.com/kdhageman/go-domains/zone"
	"io"
)

type Config struct {
	File     string `yaml:file`
	Host     string `yaml:"addr"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type Client interface {
	Retr(string) (io.Reader, error)
}

type ftpZone struct {
	conf   Config
	client Client
	store  store.Store
	seen   map[string]interface{}
}

func (z *ftpZone) Stream() (io.Reader, error) {
	return z.client.Retr(z.conf.File)
}

func New(conf Config, store store.Store, client Client) (zone.Zone, error) {
	if client == nil {
		client, err := ftp.Dial(conf.Host)
		if err != nil {
			return nil, err
		}

		if err := client.Login(conf.Username, conf.Password); err != nil {
			return nil, err
		}
	}

	c := ftpZone{
		client: client,
		store:  store,
		seen:   make(map[string]interface{}),
	}
	return &c, nil
}
