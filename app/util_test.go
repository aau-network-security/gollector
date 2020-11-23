package app

import (
	"errors"
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

func TestRetry(t *testing.T) {
	calls := 0
	f := func() error {
		calls++
		if calls == 4 {
			return nil
		}
		return errors.New("error")
	}

	// retry only twice, and we expect an error as a result
	err := Retry(f, 2)
	if err == nil {
		t.Fatalf("expected an error, but got none")
	}
	// two retries = three function call
	if calls != 3 {
		t.Fatalf("expected %d calls, but got %d", 2, calls)
	}

	// retry six times, and we expect a success (after four calls)
	calls = 0
	err = Retry(f, 6)
	if err != nil {
		t.Fatalf("expected no error, but got one")
	}
	// when success, do NOT retry again
	if calls != 4 {
		t.Fatalf("expected %d calls, but got %d", 3, calls)
	}
}
