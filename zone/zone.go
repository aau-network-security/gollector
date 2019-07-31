package zone

import (
	"bufio"
	"compress/gzip"
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
	"io"
	"strings"
)

var (
	OptsInvalidErr = errors.New("process options are invalid")
)

type ZoneErr struct {
	tld string
	err error
}

func (err *ZoneErr) Error() string {
	return fmt.Sprintf("zone error (%s): %s", err.tld, err.err)
}

type DomainFunc func([]byte) error

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

			// silently ignore tld domains (e.g. `com` or `net`)
			if len(strings.Split(domain, ".")) == 1 {
				continue
			}

			if _, ok := seen[domain]; !ok {
				if err := f([]byte(domain)); err != nil {
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
		b := scanner.Bytes()
		if err := f(b); err != nil {
			return nil
		}
	}
	return nil
}

func GzipWrapper(r io.Reader) (io.Reader, error) {
	return gzip.NewReader(r)
}

type Zone interface {
	Stream() (io.Reader, error)
	Tld() string
}

func Process(z Zone, opts ProcessOpts) error {
	if !opts.isValid() {
		return OptsInvalidErr
	}

	str, err := z.Stream()
	if err != nil {
		return &ZoneErr{z.Tld(), err}
	}
	log.Info().Msgf("successfully obtained stream for '%s'", z.Tld())

	for _, w := range opts.StreamWrappers {
		str, err = w(str)
		if err != nil {
			return &ZoneErr{z.Tld(), err}
		}
	}

	if err := opts.StreamHandler(str, opts.DomainFunc); err != nil {
		return &ZoneErr{z.Tld(), err}
	}
	return nil
}
