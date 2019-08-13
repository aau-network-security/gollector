package splunk

import (
	"github.com/aau-network-security/go-domains/config"
	"testing"
)

func TestProcess(t *testing.T) {
	conf := config.Splunk{
		Directory: "fixtures",
	}

	count := 0
	entryFn := func(entry Entry) error {
		count++
		return nil
	}

	if err := Process(conf, entryFn); err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	if count != 5 {
		t.Fatalf("expected %d entries, but got %d", 5, count)
	}
}
