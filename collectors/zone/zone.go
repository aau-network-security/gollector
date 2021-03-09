package zone

import (
	"bufio"
	"compress/gzip"
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
	"io"
	"os"
	"path/filepath"
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
	TargetDir      string
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
		case *dns.NS, *dns.A, *dns.AAAA:
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
	log.Info().Msgf("finished handler")
	return nil
}

// this handler reads files that contains a list of domain names
func ListHandler(str io.Reader, f DomainFunc) error {
	scanner := bufio.NewScanner(str)
	start := time.Now()
	for scanner.Scan() {
		b := scanner.Bytes()
		if err := f(b); err != nil {
			return nil
		}
	}
	passed := time.Now().Sub(start)
	log.Debug().Msgf("Took %.1f ms", float64(passed.Nanoseconds())/1e06)
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

	// write zone file to temporary file on filesystem before processing
	now := time.Now().Format("2006-01-02")
	fileName := fmt.Sprintf("%s.%s", z.Tld(), now)
	filePathTemp := filepath.Join(opts.TargetDir, fileName)
	filePathPerm := fmt.Sprintf("%s.gz", filePathTemp)

	fTemp, err := os.OpenFile(filePathTemp, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		return &ZoneErr{z.Tld(), err}
	}
	defer os.Remove(fTemp.Name())

	if _, err := io.Copy(fTemp, str); err != nil {
		return &ZoneErr{z.Tld(), err}
	}

	log.Debug().Msgf("successfully written stream to file for '%s'", z.Tld())

	// process content of zone file according to domain function
	// TODO: re-enable
	//if err := opts.StreamHandler(fTemp, opts.DomainFn); err != nil {
	//	return &ZoneErr{z.Tld(), err}
	//}

	if err := fTemp.Close(); err != nil {
		return &ZoneErr{z.Tld(), err}
	}

	// write to permanent file
	fin, err := os.Open(filePathTemp)
	if err != nil {
		return &ZoneErr{z.Tld(), err}
	}
	defer fin.Close()

	fout, err := os.OpenFile(filePathPerm, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		return &ZoneErr{z.Tld(), err}
	}
	defer fout.Close()

	wout := gzip.NewWriter(fout)
	defer wout.Close()

	if _, err := io.Copy(wout, fin); err != nil {
		return &ZoneErr{z.Tld(), err}
	}

	return nil
}
