package ftp

import (
	zone2 "github.com/aau-network-security/go-domains/collectors/zone"
	"io"
	"os"
	"testing"
)

type testFtpClient struct{}

func (c *testFtpClient) Login(user, pass string) error {
	return nil
}

func (c *testFtpClient) Retr(string) (io.Reader, error) {
	return os.Open("fixtures/zone.sample.gz")
}

func TestProcess(t *testing.T) {
	z := ftpZone{
		conf: Config{
			Tld: "com",
		},
		client: &testFtpClient{},
		seen:   make(map[string]interface{}),
	}

	domainMap := make(map[string]interface{})
	f := func(domain []byte) error {
		domainMap[string(domain)] = nil
		return nil
	}

	opts := zone2.ProcessOpts{
		DomainFn:       f,
		StreamWrappers: []zone2.StreamWrapper{zone2.GzipWrapper},
		StreamHandler:  zone2.ZoneFileHandler,
	}

	if err := zone2.Process(&z, opts); err != nil {
		t.Fatalf("Error while processing ftp zone file: %s", err)
	}

	expected := 5
	actual := len(domainMap)
	if actual != expected {
		t.Fatalf("Expected %d domains to be processed, but got %d", expected, actual)
	}
}
