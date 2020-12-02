package main

import (
	"github.com/aau-network-security/gollector/app"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
	"io/ioutil"
)

type config struct {
	Time        string      `yaml:"time"`
	WorkerCount int         `yaml:"worker_count"`
	ApiAddr     app.Address `yaml:"api-address"`
	Meta        app.Meta    `yaml:"meta"`
	All         bool        `yaml:"all"`
	Included    []string    `yaml:"included"` // urls to include
	Excluded    []string    `yaml:"excluded"` // urls to exclude
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
