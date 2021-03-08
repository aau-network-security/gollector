package zone

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"github.com/miekg/dns"
	"github.com/pkg/errors"
	"io"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"
)

type ZoneFileEntry struct {
	Domain string
}

type ZoneFile interface {
	Next() (*ZoneFileEntry, error)
	Name() string
	Tld() string
	io.Closer
}

type standardZonefile struct {
	f   *os.File
	zp  *dns.ZoneParser
	tld string
}

func (zf *standardZonefile) Next() (*ZoneFileEntry, error) {
	rr, ok := zf.zp.Next()
	if !ok {
		return nil, io.EOF
	}
	if err := zf.zp.Err(); err != nil {
		return nil, err
	}

	domain := strings.TrimSuffix(rr.Header().Name, ".")
	if domain == zf.tld {
		// ignore this value
		return zf.Next()
	}

	zfe := ZoneFileEntry{
		Domain: domain,
	}
	return &zfe, nil
}

func (zf *standardZonefile) Tld() string {
	return zf.tld
}

func (zf *standardZonefile) Close() error {
	return zf.f.Close()
}

func (zf *standardZonefile) Name() string {
	return zf.f.Name()
}

func newStandardZonefile(path, tld string) (*standardZonefile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	g, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}

	zp := dns.NewZoneParser(g, "", "")

	zf := standardZonefile{
		f:   f,
		zp:  zp,
		tld: tld,
	}
	return &zf, nil
}

type dkZoneFile struct {
	f *os.File
	s *bufio.Scanner
}

func (zf dkZoneFile) Next() (*ZoneFileEntry, error) {
	if !zf.s.Scan() {
		return nil, io.EOF
	}
	domain := zf.s.Text()
	zfe := ZoneFileEntry{
		Domain: domain,
	}

	return &zfe, nil
}

func (zf *dkZoneFile) Name() string {
	return zf.f.Name()
}

func (zf *dkZoneFile) Close() error {
	return zf.f.Close()
}

func (zf *dkZoneFile) Tld() string {
	return "dk"
}

func NewDkZoneFile(path string) (ZoneFile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	g, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}

	s := bufio.NewScanner(g)

	zf := dkZoneFile{
		f: f,
		s: s,
	}
	return &zf, nil
}

type ZonefileProvider struct {
	zonefiles map[string][]string
}

// returns the zone file of the
func (zfp *ZonefileProvider) Next(tld string) (ZoneFile, error) {
	l, ok := zfp.zonefiles[tld]
	if !ok {
		return nil, errors.New("unknown TLD")
	}
	if len(l) == 0 {
		// there are no more files for this tld
		return nil, io.EOF
	}
	fpath := l[0]

	var zf ZoneFile
	var err error
	if tld == "dk" {
		zf, err = NewDkZoneFile(fpath)
	} else {
		zf, err = newStandardZonefile(fpath, tld)
	}
	if err != nil {
		return nil, err
	}
	zfp.zonefiles[tld] = l[1:]

	return zf, nil
}

// return a list of all TLDs
func (zfp *ZonefileProvider) Tlds() []string {
	var res []string
	for tld := range zfp.zonefiles {
		res = append(res, tld)
	}
	return res
}

func NewZonefileProvider(dir string) (*ZonefileProvider, error) {
	// read all files in dir
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	zonefiles := make(map[string][]string)
	_ = zonefiles
	for _, info := range files {
		fname := info.Name()
		ext := filepath.Ext(fname)
		basename := fname[:len(fname)-len(ext)]
		splitted := strings.Split(basename, ".")
		if len(splitted) != 2 {
			return nil, errors.New(fmt.Sprintf("invalid filename structure: %s", fname))
		}
		tld := splitted[0]
		// TODO: we ignore date for now
		l, ok := zonefiles[tld]
		if !ok {
			l = []string{}
		}
		fpath := path.Join(dir, fname)
		l = append(l, fpath)
		zonefiles[tld] = l
	}

	zfp := ZonefileProvider{
		zonefiles: zonefiles,
	}
	return &zfp, nil
}
