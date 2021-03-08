package main

import (
	"github.com/aau-network-security/gollector/app"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
	"io/ioutil"
)

type TimeWindow struct {
	Active bool   `yaml:"active"`
	Start  string `yaml:"start"`
	End    string `yaml:"end"`
}

type config struct {
	TimeWindow  TimeWindow  `yaml:"time-window"`
	WorkerCount int         `yaml:"worker_count"`
	ApiAddr     app.Address `yaml:"api-address"`
	Meta        app.Meta    `yaml:"meta"`
	All         bool        `yaml:"all"`
	Included    []string    `yaml:"included"` // urls to include
	Excluded    []string    `yaml:"excluded"` // urls to exclude
	LogLevel    string      `yaml:"log-level"`
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
