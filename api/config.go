package api

import (
	"github.com/aau-network-security/go-domains/store"
	"github.com/go-acme/lego/providers/dns/cloudflare"
)

type Config struct {
	Store store.Config `yaml:"store"`
	Api   Api          `yaml:"api"`
}

type Api struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
	Tls  Tls    `yaml:"tls"`
}

type Tls struct {
	Enabled bool           `yaml:"enabled"`
	Auth    CloudflareAuth `yaml:"cloudflare-auth"`
}

type CloudflareAuth struct {
	Email  string `yaml:"email"`
	ApiKey string `yaml:"api-key"`
}

func (auth *CloudflareAuth) ToCertmagicConfig() *cloudflare.Config {
	conf := cloudflare.NewDefaultConfig()
	conf.AuthEmail = auth.Email
	conf.AuthKey = auth.ApiKey
	return conf
}
