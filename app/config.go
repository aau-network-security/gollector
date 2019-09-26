package app

import "strings"

type ConfigErr struct {
	errs []string
}

func (ce *ConfigErr) Add(s string) {
	ce.errs = append(ce.errs, s)
}

func (ce *ConfigErr) Error() string {
	return "config err: " + strings.Join(ce.errs, ",")
}

func (ce *ConfigErr) IsError() bool {
	return len(ce.errs) > 0
}

func NewConfigErr() ConfigErr {
	return ConfigErr{
		errs: []string{},
	}
}

type Meta struct {
	Description string `yaml:"description"`
	Host        string `yaml:"host"`
}
