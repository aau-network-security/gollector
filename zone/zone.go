package zone

import (
	"bufio"
	"compress/gzip"
	"errors"
	"fmt"
	"github.com/aau-network-security/go-domains/models"
	"github.com/aau-network-security/go-domains/store"
	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
	"io"
	"strings"
	"time"
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

type StreamWrapper func(closer io.ReadCloser) (io.ReadCloser, error)

type StreamHandler func(io.Reader, DomainFunc) error

type ProcessOpts struct {
	DomainFn       DomainFunc
	StreamWrappers []StreamWrapper
	StreamHandler  StreamHandler
}

func (opts *ProcessOpts) isValid() bool {
	return opts.DomainFn != nil
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

func GzipWrapper(r io.ReadCloser) (io.ReadCloser, error) {
	return gzip.NewReader(r)
}

type Zone interface {
	Stream() (io.ReadCloser, error)
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
	defer str.Close()
	log.Info().Msgf("successfully obtained stream for '%s'", z.Tld())

	for _, w := range opts.StreamWrappers {
		str, err = w(str)
		if err != nil {
			return &ZoneErr{z.Tld(), err}
		}
	}

	if err := opts.StreamHandler(str, opts.DomainFn); err != nil {
		return &ZoneErr{z.Tld(), err}
	}
	return nil
}

// returns a start time to continue a measurement that synchronizes with the last measurement
func GetStartTime(conf store.Config, interval time.Duration) (time.Time, error) {
	g, err := conf.Open()
	if err != nil {
		return time.Now(), err
	}

	var entries []*models.ZonefileEntry
	if err := g.Limit(1).Order("last_seen desc").Find(&entries).Error; err != nil {
		return time.Now(), err
	}

	// no database entries, run measurement now
	if len(entries) == 0 {
		return time.Now(), nil
	}

	st := entries[0].LastSeen.Add(interval)
	for st.Before(time.Now()) {
		st = st.Add(interval)
	}

	return st, nil
}
