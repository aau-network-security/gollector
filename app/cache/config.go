package main

import (
	"github.com/aau-network-security/gollector/api"
	"github.com/aau-network-security/gollector/app"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
	"io/ioutil"
)

type cacheSize struct {
	Log       int `yaml:"log"`
	TLD       int `yaml:"tld"`
	PSuffix   int `yaml:"public-suffix"`
	Apex      int `yaml:"apex"`
	Fqdn      int `yaml:"fqdn"`
	Cert      int `yaml:"cert"`
	ZoneEntry int `yaml:"zone-entry"`
}

type storeOpts struct {
	BatchSize int       `yaml:"batch-size"`
	CacheSize cacheSize `yaml:"cache-size"`
}

type anonymizeSalt struct {
	TldSalt, PSuffixSalt, ApexSalt, FqdnSalt string
}

type config struct {
	AnonymizeSalt anonymizeSalt `yaml:"anonymize-salt"`
	Sentry        app.Sentry    `yaml:"sentry"`
	Api           api.Config    `yaml:"api"`
	StoreOpts     storeOpts     `yaml:"store"`
	PprofPort     int           `yaml:"pprof-port"`
	LogLevel      string        `yaml:"log-level"`
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

	return conf, nil
}
