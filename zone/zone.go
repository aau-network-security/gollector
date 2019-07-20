package zone

import (
	"bufio"
	"compress/gzip"
	"errors"
	"github.com/miekg/dns"
	"io"
	"strings"
)

var (
	OptsInvalidErr = errors.New("process options are invalid")
)

type DomainFunc func(string) error

type StreamWrapper func(io.Reader) (io.Reader, error)

type StreamHandler func(io.Reader, DomainFunc) error

type ProcessOpts struct {
	DomainFunc     DomainFunc
	StreamWrappers []StreamWrapper
	StreamHandler  StreamHandler
}

func (opts *ProcessOpts) isValid() bool {
	return opts.DomainFunc != nil
}

// this handler reads files that fulfill the zone file standard
func ZoneFileHandler(str io.Reader, f DomainFunc) error {
	seen := make(map[string]interface{})

	for t := range dns.ParseZone(str, "", "") {
		if t.Error != nil {
			return t.Error
		}
		switch v := t.RR.(type) {
		case *dns.NS:
			domain := strings.TrimSuffix(strings.ToLower(v.Header().Name), ".")

			if _, ok := seen[domain]; !ok {
				if err := f(domain); err != nil {
					return err
				}
				seen[domain] = nil
			}
		}
	}
	return nil
}

// this handler reads files that contains a list of domain names
func ListHandler(str io.Reader, f DomainFunc) error {
	scanner := bufio.NewScanner(str)
	for scanner.Scan() {
		domain := scanner.Text()
		if err := f(domain); err != nil {
			return err
		}
	}
	return nil
}

func GzipWrapper(r io.Reader) (io.Reader, error) {
	return gzip.NewReader(r)
}

type Zone interface {
	Stream() (io.Reader, error)
}

func Process(z Zone, opts ProcessOpts) error {
	if !opts.isValid() {
		return OptsInvalidErr
	}

	str, err := z.Stream()
	if err != nil {
		return err
	}

	for _, w := range opts.StreamWrappers {
		str, err = w(str)
		if err != nil {
			return err
		}
	}

	return opts.StreamHandler(str, opts.DomainFunc)
}
