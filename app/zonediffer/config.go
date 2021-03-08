package main

import (
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
	"io/ioutil"
)

type config struct {
	InputDir string `yaml:"input-dir"`
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
