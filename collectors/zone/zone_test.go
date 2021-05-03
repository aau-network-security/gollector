package zone

import (
	"errors"
	"github.com/aau-network-security/gollector/app"
	"github.com/aau-network-security/gollector/store"
	testing2 "github.com/aau-network-security/gollector/testing"
	"io"
	"strings"
	"testing"
	"time"
)

type insertEntry struct {
	tm     time.Time
	domain string
}

func TestGetStartTime(t *testing.T) {
	testing2.SkipCI(t)

	interval := 24 * time.Hour

	tBase := time.Now()

	tests := []struct {
		name             string
		entries          []insertEntry
		expectedInterval time.Duration
	}{
		{
			"multiple existing entries",
			[]insertEntry{
				{
					tBase,
					"example.org",
				},
				{
					tBase.Add(10 * time.Hour),
					"example.com",
				},
			},
			34 * time.Hour,
		},
		{
			"no existing entry",
			[]insertEntry{},
			0,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			conf := store.Config{
				Host:     "localhost",
				User:     "postgres",
				Password: "postgres",
				Port:     10001,
				DBName:   "domains",
			}

			g, err := conf.Open()
			if err != nil {
				t.Fatalf("unexpected error while creating gorm database: %s", err)
			}

			if err := testing2.ResetDb(g); err != nil {
				t.Fatalf("unexpected error while restting database: %s", err)
			}

			s, err := store.NewStore(conf, store.DefaultOpts)
			if err != nil {
				t.Fatalf("unexpected error while creating store: %s", err)
			}
			//todo commented cause those methods don't exist
			//s.WaitUntilReady()
			//
			//for _, entry := range test.entries {
			//	if _, err := s.StoreZoneEntry(entry.tm, entry.domain); err != nil {
			//		t.Fatalf("unexpected error while storing zone entry: %s", err)
			//	}
			//}
			if err := s.RunPostHooks(); err != nil {
				t.Fatalf("unexpected error while running post hooks: %s", err)
			}
		})
	}
}

func TestStoreLogentry(t *testing.T) {
	testing2.SkipCI(t)

	s, _, muid, err := store.OpenStore(store.TestConfig, store.TestOpts)
	if err != nil {
		t.Fatalf("unexpected error while opening store: %s", err)
	}

	ts := time.Now()
	fqdn := "example.org"

	if err := s.StoreZoneEntry(muid, ts, fqdn); err != nil {
		t.Fatalf("unexpected error while storing zone entry: %s", err)
	}
	if err := s.RunPostHooks(); err != nil {
		t.Fatalf("unexpected error while running post hooks: %s", err)
	}
}

func almostEqual(t1, t2 time.Time, space time.Duration) bool {
	return t2.After(t1.Add(-space)) && t2.Before(t1.Add(space))
}

type testReadCloser struct {
	reader *strings.Reader
	count  int
}

func (rc *testReadCloser) Read(p []byte) (n int, err error) {
	if rc.count == 0 {
		// first call fails
		rc.count++
		return 0, errors.New("read error")
	}
	// return content
	return rc.reader.Read(p)
}

func (rc *testReadCloser) Close() error {
	return nil
}

func NewTestReadCloser(content string) io.ReadCloser {
	reader := strings.NewReader(content)
	rc := testReadCloser{
		reader: reader,
	}
	return &rc
}

type testZone struct {
	rc io.ReadCloser
}

func (z testZone) Stream() (io.ReadCloser, error) {
	return z.rc, nil
}

func (z testZone) Tld() string {
	return "test"
}

func TestRetryProcess(t *testing.T) {
	z := testZone{
		rc: NewTestReadCloser("\n"),
	}

	df := func([]byte) error {
		return nil
	}

	po := ProcessOpts{
		DomainFn:       df,
		StreamWrappers: []StreamWrapper{},
		StreamHandler:  ZoneFileHandler,
	}

	retryFn := func() error {
		return Process(z, po)
	}

	if err := app.Retry(retryFn, 2); err != nil {
		t.Fatalf("unexpected error while processing zone: %s", err)
	}
}
