package ftp

import (
	"fmt"
	"github.com/jlaffaye/ftp"
	"github.com/kdhageman/go-domains/zone"
	"golang.org/x/crypto/ssh"
	"io"
	"io/ioutil"
	"net"
)

type SSH struct {
	Enabled bool   `yaml:"enabled"`
	Host    string `yaml:"host"`
	User    string `yaml:"user"`
	Key     string `yaml:"key"`
}

type Config struct {
	File     string `yaml:"file"`
	Host     string `yaml:"host"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	SSH      SSH    `yaml:"ssh"`
}

type Client interface {
	Retr(string) (*ftp.Response, error)
}

type ftpZone struct {
	conf   Config
	client Client
	seen   map[string]interface{}
}

func (z *ftpZone) Stream() (io.Reader, error) {
	return z.client.Retr(z.conf.File)
}

func privateKeyAuth(path string) (ssh.AuthMethod, error) {
	buffer, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, err := ssh.ParsePrivateKey(buffer)
	if err != nil {
		return nil, err
	}
	return ssh.PublicKeys(key), nil
}

func sshClient(conf Config) (*ssh.Client, error) {
	auth, err := privateKeyAuth(conf.SSH.Key)
	if err != nil {
		return nil, err
	}
	sshConf := ssh.ClientConfig{
		User: conf.SSH.User,
		Auth: []ssh.AuthMethod{
			auth,
		},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
	}
	host := fmt.Sprintf("%s:22", conf.SSH.Host)
	return ssh.Dial("tcp", host, &sshConf)
}

func New(conf Config) (zone.Zone, error) {
	host := fmt.Sprintf("%s:21", conf.Host)

	var opts []ftp.DialOption
	if conf.SSH.Enabled {
		sc, err := sshClient(conf)
		if err != nil {
			return nil, err
		}

		conn, err := sc.Dial("tcp", host)
		if err != nil {
			return nil, err
		}
		opts = append(opts, ftp.DialWithNetConn(conn))
	}
	client, err := ftp.Dial(host, opts...)
	if err != nil {
		return nil, err
	}

	if err := client.Login(conf.Username, conf.Password); err != nil {
		return nil, err
	}

	c := ftpZone{
		conf:   conf,
		client: client,
		seen:   make(map[string]interface{}),
	}
	return &c, nil
}
