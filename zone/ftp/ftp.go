package ftp

import (
	"fmt"
	"github.com/aau-network-security/go-domains/zone"
	"github.com/jlaffaye/ftp"
	"io"
)

type Config struct {
	File     string `yaml:"file"`
	Host     string `yaml:"host"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type Client interface {
	Retr(string) (io.Reader, error)
}

type client struct {
	c *ftp.ServerConn
}

func (c *client) Retr(s string) (io.Reader, error) {
	return c.c.Retr(s)
}

type ftpZone struct {
	conf   Config
	client Client
	seen   map[string]interface{}
}

func (z *ftpZone) Stream() (io.Reader, error) {
	return z.client.Retr(z.conf.File)
}

func New(conf Config) (zone.Zone, error) {
	host := fmt.Sprintf("%s:21", conf.Host)
	c, err := ftp.Dial(host)
	if err != nil {
		return nil, err
	}

	if err := c.Login(conf.Username, conf.Password); err != nil {
		return nil, err
	}

	z := ftpZone{
		conf:   conf,
		client: &client{c},
		seen:   make(map[string]interface{}),
	}
	return &z, nil
}
