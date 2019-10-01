package ftp

import (
	zone2 "github.com/aau-network-security/gollector/collectors/zone"
	"github.com/jlaffaye/ftp"
	"io"
	"net"
)

type Config struct {
	Tld      string `yaml:"tld"`
	Host     string `yaml:"host"`
	Username string `yaml:"username"`
	Password string
	File     string `yaml:"file"`
}

type Client interface {
	Login(user, pass string) error
	Retr(string) (io.ReadCloser, error)
}

type client struct {
	c *ftp.ServerConn
}

func (c *client) Login(user, pass string) error {
	return c.c.Login(user, pass)
}

func (c *client) Retr(s string) (io.ReadCloser, error) {
	return c.c.Retr(s)
}

type ftpZone struct {
	conf   Config
	client Client
	seen   map[string]interface{}
}

func (z *ftpZone) Tld() string {
	return z.conf.Tld
}

func (z *ftpZone) Stream() (io.ReadCloser, error) {
	if err := z.client.Login(z.conf.Username, z.conf.Password); err != nil {
		return nil, err
	}
	return z.client.Retr(z.conf.File)
}

func New(conf Config, dialFunc func(network, address string) (net.Conn, error)) (zone2.Zone, error) {
	var opts []ftp.DialOption
	if dialFunc != nil {
		opts = append(opts, ftp.DialWithDialFunc(dialFunc))
	}

	host := net.JoinHostPort(conf.Host, "21")
	c, err := ftp.Dial(host, opts...)

	if err != nil {
		return nil, err
	}

	z := ftpZone{
		conf:   conf,
		client: &client{c},
		seen:   make(map[string]interface{}),
	}
	return &z, nil
}
