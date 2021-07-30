package main

import (
	"github.com/aau-network-security/gollector/app"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"time"
)

type Resume struct {
	Enabled          bool   `yaml:"enabled"`
	FinishedTldsFile string `yaml:"finished-tlds-file"`
}

type config struct {
	InputDir    string      `yaml:"input-dir"`
	ApiAddr     app.Address `yaml:"api-address"`
	Meta        app.Meta    `yaml:"meta"`
	LogLevel    string      `yaml:"log-level"`
	Start       time.Time   `yaml:"-"`
	StartString string      `yaml:"start"`
	End         time.Time   `yaml:"-"`
	EndString   string      `yaml:"end"`
	Resume      Resume      `yaml:"resume"`
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

	ts, err := time.Parse("2006-01-02", conf.StartString)
	if err != nil {
		return conf, errors.Wrap(err, "start time")
	}
	conf.Start = ts

	ts, err = time.Parse("2006-01-02", conf.EndString)
	if err != nil {
		return conf, errors.Wrap(err, "end time")
	}
	conf.End = ts

	return conf, nil
}
