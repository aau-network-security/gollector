package generic

import (
	"testing"
	"time"
)

func TestRepeat(t *testing.T) {
	count := 0
	f := func(time.Time) error {
		count++
		return nil
	}
	startTime := time.Now().Add(time.Millisecond)
	interval := 10 * time.Millisecond
	go Repeat(f, startTime, interval, 5)

	cases := []struct {
		sleeptime     time.Duration
		expectedCount int
	}{
		{25 * time.Millisecond, 3},
		{40 * time.Millisecond, 5},
	}

	for _, tc := range cases {
		time.Sleep(tc.sleeptime)
		if count != tc.expectedCount {
			t.Fatalf("Expected %d function calls, but got %d", tc.expectedCount, count)
		}
	}
}
