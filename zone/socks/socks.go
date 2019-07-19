package socks

import (
	"github.com/aau-network-security/go-domains/zone"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/proxy"
	"io"
	"net"
	"net/http"
)

type SSH struct {
	Host     string `yaml:"host"`
	User     string `yaml:"user"`
	Key      string `yaml:key`
	Password string `yaml:"password"`
}

type Config struct {
	SSH SSH    `yaml:"ssh"`
	Url string `yaml:"url"`
}

type socksZone struct {
	conf Config
	c    *http.Client
}

func (z *socksZone) Stream() (io.Reader, error) {
	req, err := http.NewRequest("GET", z.conf.Url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := z.c.Do(req)
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

func (z *socksZone) GzipRequired() bool {
	return false
}

func New(conf Config) (zone.Zone, error) {
	//auth := ssh.Password(conf.SSH.Password)
	//t := NewSSHTunnel(conf.SSH.Host, auth, conf.Host)
	//go func() {
	//	if err := t.Start(); err != nil {
	//		log.Debug().Msgf("error while tunneling ssh traffic: %s", err)
	//	}
	//}()

	auth := ssh.Password(conf.SSH.Password)

	clientConfig := ssh.ClientConfig{
		User:            conf.SSH.User,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error { return nil },
		Auth:            []ssh.AuthMethod{auth},
	}

	sshDialer, err := ssh.Dial("tcp", conf.SSH.Host, &clientConfig)
	if err != nil {
		return nil, err
	}

	//auth := proxy.Auth{
	//	User:     conf.SSH.User,
	//	Password: conf.SSH.Password,
	//}

	//dialer, err := proxy.SOCKS5("tcp", host, &auth, nil)
	//dialer, err := proxy.SOCKS5("tcp", t.Local.String(), nil, nil)
	address := sshDialer.LocalAddr().String()
	log.Debug().Msgf("local ssh tunnel address: %s", address)
	dialer, err := proxy.SOCKS5("tcp", address, nil, sshDialer)
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{}
	transport.Dial = dialer.Dial
	c := &http.Client{
		Transport: transport,
	}

	s := socksZone{
		conf: conf,
		c:    c,
	}
	return &s, nil
}
