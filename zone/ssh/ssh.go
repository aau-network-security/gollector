package ssh

import (
	"errors"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"net"
	"net/http"
)

var (
	InvalidConfErr = errors.New("configuration is invalid")
)

type Config struct {
	Host     string `yaml:"host"`
	User     string `yaml:"user"`
	AuthType string `yaml:"authtype"`
	Password string `yaml:"password"`
	Key      string `yaml:"key"`
}

func (conf *Config) isValid() bool {
	switch conf.AuthType {
	case "password":
		return conf.Password != ""
	case "key":
		return conf.Key != ""
	default:
		return false
	}
}

func (conf *Config) getAuth() (ssh.AuthMethod, error) {
	if !conf.isValid() {
		return nil, InvalidConfErr
	}

	var auth ssh.AuthMethod
	switch conf.AuthType {
	case "password":
		auth = ssh.Password(conf.Password)
	case "key":
		buffer, err := ioutil.ReadFile(conf.Key)
		if err != nil {
			return nil, err
		}
		key, err := ssh.ParsePrivateKey(buffer)
		if err != nil {
			return nil, err
		}
		auth = ssh.PublicKeys(key)
	}
	return auth, nil
}

func HttpClient(conf Config) (*http.Client, error) {
	f, err := DialFunc(conf)
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{
		Dial: f,
	}
	httpClient := &http.Client{
		Transport: transport,
	}

	return httpClient, nil
}

func DialFunc(conf Config) (func(network, address string) (net.Conn, error), error) {
	auth, err := conf.getAuth()
	if err != nil {
		return nil, err
	}

	clientConfig := ssh.ClientConfig{
		User: conf.User,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
		Auth: []ssh.AuthMethod{
			auth,
		},
	}

	host := net.JoinHostPort(conf.Host, "22")
	sshClient, err := ssh.Dial("tcp", host, &clientConfig)

	return sshClient.Dial, err
}
