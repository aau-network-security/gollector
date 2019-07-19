package zone

import (
	"compress/gzip"
	"github.com/miekg/dns"
	"io"
	"strings"
)

type DomainFunc func(string) error

type Zone interface {
	Stream() (io.Reader, error)
	GzipRequired() bool
}

func Process(z Zone, f DomainFunc) error {
	str, err := z.Stream()
	if err != nil {
		return err
	}

	if z.GzipRequired() {
		str, err = gzip.NewReader(str)
		if err != nil {
			return err
		}
	}

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
