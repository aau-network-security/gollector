package com

import (
	"github.com/kdhageman/go-domains/store"
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
	cache := store.NewCache()
	ftpClient := testFtpClient{}

	c, err := NewCom(conf, cache, &ftpClient)
	if err != nil {
		t.Fatalf("Error while creating .com zone parser: %s", err)
	}

	domainMap := make(map[string]interface{})
	f := func(domain string) error {
		domainMap[domain] = nil
		return nil
	}
	if err := c.Process(f); err != nil {
		t.Fatalf("Error while processing .com zone file: %s", err)
	}

	expected := 6
	actual := len(domainMap)
	if actual != expected {
		t.Fatalf("Expected %d domains to be processed, but got %d", expected, actual)
	}
}
