package app

import (
	"crypto/tls"
	"fmt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"strings"
)

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

type Address struct {
	Secure bool   `yaml:"secure"`
	Host   string `yaml:"host"`
	Port   int    `yaml:"port"`
}

func (a *Address) Dial() (*grpc.ClientConn, error) {
	addr := fmt.Sprintf("%s:%d", a.Host, a.Port)
	var opts []grpc.DialOption
	if !a.Secure {
		opts = append(opts, grpc.WithInsecure())
	} else {
		tlsConf := &tls.Config{
			InsecureSkipVerify: false,
		}
		transportCreds := credentials.NewTLS(tlsConf)
		opts = append(opts, grpc.WithTransportCredentials(transportCreds))
	}
	return grpc.Dial(addr, opts...)
}
