package config

import (
	"github.com/aau-network-security/go-domains/store"
	"github.com/aau-network-security/go-domains/zone/czds"
	"github.com/aau-network-security/go-domains/zone/ftp"
	"github.com/aau-network-security/go-domains/zone/http"
	"github.com/aau-network-security/go-domains/zone/ssh"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
)

const (
	ComFtpPass = "COM_FTP_PASS"
	CzdsPass   = "CZDS_PASS"
	DkSshPass  = "DK_SSH_PASS"
)

type Com struct {
	Ftp        ftp.Config `yaml:"ftp"`
	SshEnabled bool       `yaml:"ssh-enabled"`
	Ssh        ssh.Config `yaml:"ssh"`
}

type Dk struct {
	Http http.Config `yaml:"http"`
	Ssh  ssh.Config  `yaml:"ssh"`
}

type Czds struct {
	Tlds  []string         `yaml:"tlds"`
	Creds czds.Credentials `yaml:"credentials"`
}

type Zone struct {
	Com  Com  `yaml:"com"`
	Czds Czds `yaml:"czds"`
	Dk   Dk   `yaml:"dk"`
}

type Ct struct {
	Time        string `yaml:"time"`
	WorkerCount int    `yaml:"worker_count"`
}

type config struct {
	Zone  Zone         `yaml:"zone"`
	Ct    Ct           `yaml:"ct"`
	Store store.Config `yaml:"store"`
}

func ReadConfig(path string) (config, error) {
	var conf config
	f, err := ioutil.ReadFile(path)
	if err != nil {
		return conf, err
	}
	if err := yaml.Unmarshal(f, &conf); err != nil {
		return conf, err
	}

	conf.Zone.Com.Ftp.Password = os.Getenv(ComFtpPass)
	conf.Zone.Czds.Creds.Password = os.Getenv(CzdsPass)
	conf.Zone.Dk.Ssh.Password = os.Getenv(DkSshPass)

	for _, env := range []string{ComFtpPass, CzdsPass, DkSshPass} {
		os.Setenv(env, "")
	}

	return conf, nil
}
