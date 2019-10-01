package main

import (
	"github.com/aau-network-security/gollector/app"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
	"io/ioutil"
)

type config struct {
	Directory string      `yaml:"directory"`
	ApiAddr   app.Address `yaml:"api-address"`
	Meta      app.Meta    `yaml:"meta"`
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
