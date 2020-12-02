package main

import (
	"github.com/aau-network-security/gollector/app"
	czds2 "github.com/aau-network-security/gollector/collectors/zone/czds"
	"github.com/aau-network-security/gollector/collectors/zone/ftp"
	"github.com/aau-network-security/gollector/collectors/zone/http"
	"github.com/aau-network-security/gollector/collectors/zone/ssh"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
)

const (
	ComFtpPass = "COM_FTP_PASS"
	CzdsPass   = "CZDS_PASS"
	DkSshPass  = "DK_SSH_PASS"
)

type com struct {
	Enabled    bool       `yaml:"enabled"`
	Ftp        ftp.Config `yaml:"ftp"`
	SshEnabled bool       `yaml:"ssh-enabled"`
	Ssh        ssh.Config `yaml:"ssh"`
}

func (c *com) IsValid() error {
	if c.Enabled {
		return nil
	}
	if c.SshEnabled {
		ce := app.NewConfigErr()
		if c.Ssh.AuthType != "key" {
			ce.Add("SSH auth type must be 'key'")
		}
		if c.Ssh.Key == "" {
			ce.Add("SSH key cannot be empty")
		}
		if ce.IsError() {
			return &ce
		}
	}
	return nil
}

type dk struct {
	Enabled bool        `yaml:"enabled"`
	Http    http.Config `yaml:"http"`
	Ssh     ssh.Config  `yaml:"ssh"`
}

func (d *dk) IsValid() error {
	if !d.Enabled {
		return nil
	}
	ce := app.NewConfigErr()
	if d.Ssh.AuthType != "password" {
		ce.Add("SSH auth type must be 'password'")
	}
	if d.Ssh.Password == "" {
		ce.Add("SSH password cannot be empty")
	}
	if ce.IsError() {
		return &ce
	}
	return nil
}

type Czds struct {
	Enabled     bool              `yaml:"enabled"`
	ZoneBaseUrl string            `yaml:"zone-base-url"`
	AuthBaseUrl string            `yaml:"auth-base-url"`
	Reason      string            `yaml:"reason"`
	All         bool              `yaml:"all"`
	Included    []string          `yaml:"included"`
	Excluded    []string          `yaml:"excluded"`
	Creds       czds2.Credentials `yaml:"credentials"`
}

func (c *Czds) IsValid() error {
	if !c.Enabled {
		return nil
	}
	ce := app.NewConfigErr()
	if c.Creds.Password == "" {
		ce.Add("password cannot be empty")
	}
	if ce.IsError() {
		return &ce
	}
	return nil
}

type config struct {
	Com     com         `yaml:"com"`
	Czds    Czds        `yaml:"czds"`
	Dk      dk          `yaml:"dk"`
	ApiAddr app.Address `yaml:"api-address"`
	Meta    app.Meta    `yaml:"meta"`
	Now     bool        `yaml:"now"`
}

func readConfig(path string) (config, error) {
	var conf config
	f, err := ioutil.ReadFile(path)
	if err != nil {
		return conf, errors.Wrap(err, "read config file")
	}
	if err := yaml.Unmarshal(f, &conf); err != nil {
		return conf, errors.Wrap(err, "unmarshal config file")
	}

	conf.Com.Ftp.Password = os.Getenv(ComFtpPass)
	conf.Czds.Creds.Password = os.Getenv(CzdsPass)
	conf.Dk.Ssh.Password = os.Getenv(DkSshPass)

	for _, env := range []string{ComFtpPass, CzdsPass, DkSshPass} {
		os.Setenv(env, "")
	}

	return conf, nil
}
