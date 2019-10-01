package main

import (
	"github.com/aau-network-security/gollector/app"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
	"io/ioutil"
)

type config struct {
	Host    string      `yaml:"host"`
	Port    string      `yaml:"port"`
	ApiAddr app.Address `yaml:"api-address"`
	Meta    app.Meta    `yaml:"meta"`
}

func (c *config) isValid() error {
	ce := app.NewConfigErr()
	if c.Host == "" {
		ce.Add("host cannot be empty")
	}
	if c.Port == "" {
		ce.Add("port cannot be empty")
	}
	if ce.IsError() {
		return &ce
	}
	return nil
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
