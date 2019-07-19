package http

import (
	"github.com/aau-network-security/go-domains/zone"
	"golang.org/x/crypto/ssh"
	"io"
	"net"
	"net/http"
)

type SSH struct {
	Host     string `yaml:"host"`
	User     string `yaml:"user"`
	Password string `yaml:"password"`
}

type Config struct {
	SSH SSH    `yaml:"ssh"`
	Url string `yaml:"url"`
}

func SshClient(conf SSH) (*http.Client, error) {
	auth := ssh.Password(conf.Password)

	clientConfig := ssh.ClientConfig{
		User:            conf.User,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error { return nil },
		Auth:            []ssh.AuthMethod{auth},
	}

	host := net.JoinHostPort(conf.Host, "22")
	sshClient, err := ssh.Dial("tcp", host, &clientConfig)
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{
		Dial: sshClient.Dial,
	}
	httpClient := &http.Client{
		Transport: transport,
	}

	return httpClient, nil
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

func New(conf Config, client *http.Client) (zone.Zone, error) {
	if client == nil {
		client = http.DefaultClient
	}

	s := socksZone{
		conf: conf,
		c:    client,
	}
	return &s, nil
}
