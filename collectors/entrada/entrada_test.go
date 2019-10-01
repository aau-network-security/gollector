package entrada

import (
	"context"
	"fmt"
	testing2 "github.com/aau-network-security/gollector/testing"
	"testing"
	"time"
)

func Test(t *testing.T) {
	testing2.SkipCI(t)

	src := NewSource("localhost", "21050")
	defer src.Close()

	ctx := context.Background()

	c := 0
	entryFn := func(qname string, unixTime time.Time) error {
		c++
		return nil
	}

	expected := 1000
	opts := Options{
		Query: fmt.Sprintf("SELECT qname, unixtime FROM dns.queries LIMIT %d", expected),
	}

	if err := src.Process(ctx, entryFn, opts); err != nil {
		t.Fatalf("unexpected error while processing impala data: %s", err)
	}

	if c != expected {
		t.Fatalf("expected %d function calls, but got %d", expected, c)
	}
}
