package config

import (
	"github.com/aau-network-security/go-domains/collectors/zone/czds"
	"github.com/aau-network-security/go-domains/collectors/zone/ftp"
	"github.com/aau-network-security/go-domains/collectors/zone/http"
	"github.com/aau-network-security/go-domains/collectors/zone/ssh"
	"github.com/aau-network-security/go-domains/store"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
	"strings"
)

const (
	ComFtpPass = "COM_FTP_PASS"
	CzdsPass   = "CZDS_PASS"
	DkSshPass  = "DK_SSH_PASS"
)

type ConfigErr struct {
	errs []string
}

func (ce *ConfigErr) add(s string) {
	ce.errs = append(ce.errs, s)
}

func (ce *ConfigErr) Error() string {
	return "config err: " + strings.Join(ce.errs, ",")
}

func (ce *ConfigErr) isError() bool {
	return len(ce.errs) > 0
}

func newConfigErr() ConfigErr {
	return ConfigErr{
		errs: []string{},
	}
}

type Validatable interface {
	IsValid() error
}

type Com struct {
	Validatable
	Ftp        ftp.Config `yaml:"ftp"`
	SshEnabled bool       `yaml:"ssh-enabled"`
	Ssh        ssh.Config `yaml:"ssh"`
}

func (c *Com) IsValid() error {
	if c.SshEnabled {
		ce := newConfigErr()
		if c.Ssh.AuthType != "key" {
			ce.add("SSH auth type must be 'key'")
		}
		if c.Ssh.Key == "" {
			ce.add("SSH key cannot be empty")
		}
		if ce.isError() {
			return &ce
		}
	}
	return nil
}

type Dk struct {
	Validatable
	Http http.Config `yaml:"http"`
	Ssh  ssh.Config  `yaml:"ssh"`
}

func (d *Dk) IsValid() error {
	ce := newConfigErr()
	if d.Ssh.AuthType != "password" {
		ce.add("SSH auth type must be 'password'")
	}
	if d.Ssh.Password == "" {
		ce.add("SSH password cannot be empty")
	}
	if ce.isError() {
		return &ce
	}
	return nil
}

type Czds struct {
	Validatable
	Tlds  []string         `yaml:"tlds"`
	Creds czds.Credentials `yaml:"credentials"`
}

func (c *Czds) IsValid() bool {
	return c.Creds.Password != ""
}

type Zone struct {
	Com  Com  `yaml:"com"`
	Czds Czds `yaml:"czds"`
	Dk   Dk   `yaml:"dk"`
	Meta Meta `yaml:"meta"`
}

type Ct struct {
	Time        string `yaml:"time"`
	WorkerCount int    `yaml:"worker_count"`
	Meta        Meta   `yaml:"meta"`
}

type Splunk struct {
	Directory string `yaml:"directory"`
	Meta      Meta   `yaml:"meta"`
}

type Entrada struct {
	Validatable
	Host string `yaml:"host"`
	Port string `yaml:"port"`
	Meta Meta   `yaml:"meta"`
}

func (e *Entrada) IsValid() error {
	ce := newConfigErr()
	if e.Host == "" {
		ce.add("host cannot be empty")
	}
	if e.Port == "" {
		ce.add("port cannot be empty")
	}
	if ce.isError() {
		return &ce
	}
	return nil
}

type config struct {
	Zone    Zone         `yaml:"zone"`
	Ct      Ct           `yaml:"ct"`
	Splunk  Splunk       `yaml:"splunk"`
	Entrada Entrada      `yaml:"entrada"`
	Store   store.Config `yaml:"store"`
	Sentry  Sentry       `yaml:"sentry"`
	Api     Api          `yaml:"api"`
}

type Sentry struct {
	Enabled bool   `yaml:"enabled"`
	Dsn     string `yaml:"dsn"`
}

type Meta struct {
	Description string `yaml:"description"`
	Host        string `yaml:"host"`
}

type Api struct {
	Host string
	Port int
}

func ReadConfig(path string) (config, error) {
	var conf config
	f, err := ioutil.ReadFile(path)
	if err != nil {
		return conf, errors.Wrap(err, "read config file")
	}
	if err := yaml.Unmarshal(f, &conf); err != nil {
		return conf, errors.Wrap(err, "unmarshal config file")
	}

	conf.Zone.Com.Ftp.Password = os.Getenv(ComFtpPass)
	conf.Zone.Czds.Creds.Password = os.Getenv(CzdsPass)
	conf.Zone.Dk.Ssh.Password = os.Getenv(DkSshPass)

	for _, env := range []string{ComFtpPass, CzdsPass, DkSshPass} {
		os.Setenv(env, "")
	}

	return conf, nil
}
