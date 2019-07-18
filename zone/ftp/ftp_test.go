package ftp

import (
	"github.com/kdhageman/go-domains/zone"
	"io"
	"os"
	"testing"
)

type testFtpClient struct{}

func (c *testFtpClient) Retr(string) (io.Reader, error) {
	return os.Open("fixtures/zone.sample.gz")
}

func TestProcess(t *testing.T) {
	conf := Config{}
	ftpClient := testFtpClient{}

	z, err := New(conf, &ftpClient)
	if err != nil {
		t.Fatalf("Error while creating ftp zone parser: %s", err)
	}

	domainMap := make(map[string]interface{})
	f := func(domain string) error {
		domainMap[domain] = nil
		return nil
	}

	if err := zone.Process(z, f); err != nil {
		t.Fatalf("Error while processing ftp zone file: %s", err)
	}

	expected := 6
	actual := len(domainMap)
	if actual != expected {
		t.Fatalf("Expected %d domains to be processed, but got %d", expected, actual)
	}
}
