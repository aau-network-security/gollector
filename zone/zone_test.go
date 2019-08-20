package zone

import (
	"github.com/aau-network-security/go-domains/store"
	testing2 "github.com/aau-network-security/go-domains/testing"
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

	tests := []struct {
		name             string
		entries          []insertEntry
		expectedInterval time.Duration
	}{
		{
			"existing entry",
			[]insertEntry{
				{
					time.Now(),
					"example.org",
				},
			},
			24 * time.Hour,
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

			for _, entry := range test.entries {
				if _, err := s.StoreZoneEntry(entry.tm, entry.domain); err != nil {
					t.Fatalf("unexpected error while storing zone entry: %s", err)
				}
			}
			if err := s.RunPostHooks(); err != nil {
				t.Fatalf("unexpected error while running post hooks: %s", err)
			}

			actual, err := GetStartTime(conf, interval)
			if err != nil {
				t.Fatalf("unexpected error while getting start time: %s", err)
			}

			expected := time.Now().Add(test.expectedInterval)

			if !almostEqual(actual, expected, 10*time.Second) {
				t.Fatalf("expected start time to be %s, but got %s", expected, actual)
			}
		})
	}
}

func almostEqual(t1, t2 time.Time, space time.Duration) bool {
	return t2.After(t1.Add(-space)) && t2.Before(t1.Add(space))
}
