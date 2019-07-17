package main

import (
	"flag"
	"github.com/kdhageman/go-domains/zone/com"
	"github.com/kdhageman/go-domains/zone/czds"
	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v2"
	"io/ioutil"
)

type config struct {
	Com com.Config  `yaml:"com"`
	Net czds.Config `yaml:"net"`
}

func readConfig(path string) (config, error) {
	var conf config
	f, err := ioutil.ReadFile(path)
	if err != nil {
		return conf, err
	}
	if err := yaml.Unmarshal(f, &conf); err != nil {
		return conf, err
	}

	return conf, nil
}

func main() {
	confFile := flag.String("config", "config/config.yml", "location of configuration file")
	flag.Parse()

	conf, err := readConfig(*confFile)
	if err != nil {
		log.Fatal().Msgf("Error while reading configuration: %s", err)
	}

	_ = conf

	// todo: do something with configuration
}
