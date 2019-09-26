package api

import "github.com/aau-network-security/go-domains/store"

type Config struct {
	Store store.Config `yaml:"store"`
	Api   Api          `yaml:"api"`
}

type Api struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
	Tls  struct {
		Enabled         bool   `yaml:"enabled"`
		CertificateFile string `yaml:"certificate-file"`
		KeyFile         string `yaml:"key-file"`
	} `yaml:"tls"`
}
