package ct

import (
	"context"
	"fmt"
	ct "github.com/google/certificate-transparency-go"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func fileHandler(t *testing.T, filename string) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := ioutil.ReadFile(filename)
		if err != nil {
			t.Fatalf("error while reading file: %s", err)
		}
		if _, err := w.Write(raw); err != nil {
			t.Fatalf("error while writing HTTP response: %s", err)
		}
	})
}

func TestLogsFromUrl(t *testing.T) {
	s := httptest.NewServer(fileHandler(t, "fixtures/logs.json"))

	logs, err := logsFromUrl(s.URL)
	if err != nil {
		t.Fatalf("unexpected error while retrieving logs: %s", err)
	}
	if len(logs.Logs) != 83 {
		t.Fatalf("expected %d logs, but got %d", 83, len(logs.Logs))
	}
	if len(logs.Operators) != 19 {
		t.Fatalf("expected %d operators, but got %d", 19, len(logs.Operators))
	}
}

func getEntriesHandleFunc(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		start := req.URL.Query().Get("start")
		end := req.URL.Query().Get("end")
		fname := fmt.Sprintf("fixtures/entry_%s_%s.json", start, end)
		fileHandler(t, fname)(w, req)
	}
}

func TestIndexByDate(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name               string
		time               time.Time
		expectedStartIndex int64
		expectedEndIndex   int64
		expectErr          bool
	}{
		{
			name:               "Within range of logs",
			time:               time.Unix(1502376196, 0), // just before the entry with index 2
			expectedStartIndex: 2,
			expectedEndIndex:   5,
		},
		{
			name:               "Before range",
			time:               time.Unix(0, 0), // 01-01-1970,
			expectedStartIndex: 0,
			expectedEndIndex:   5,
		},
		{
			name:      "After range",
			time:      now, // timestamp after any cert in the test log data set
			expectErr: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()

			mux := http.NewServeMux()
			mux.HandleFunc("/ct/v1/get-entries", getEntriesHandleFunc(t))
			mux.HandleFunc("/ct/v1/get-sth", fileHandler(t, "fixtures/sth.json"))

			s := httptest.NewServer(mux)

			l := Log{
				Url: s.URL,
			}

			startIndex, err := IndexByDate(ctx, &l, test.time)
			if (err == nil) == test.expectErr {
				t.Fatalf("expected error: %t, but got: %t", test.expectErr, err == nil)
			}
			if startIndex != test.expectedStartIndex {
				t.Fatalf("expected start index %d, but got %d", test.expectedStartIndex, startIndex)
			}
		})
	}
}

func TestScanFromTime(t *testing.T) {
	ctx := context.Background()

	mux := http.NewServeMux()
	mux.HandleFunc("/ct/v1/get-entries", getEntriesHandleFunc(t))
	mux.HandleFunc("/ct/v1/get-sth", fileHandler(t, "fixtures/sth.json"))

	s := httptest.NewServer(mux)

	observedCount := 0
	entryFunc := func(entry *ct.LogEntry) error {
		observedCount++
		return nil
	}

	l := Log{
		Url: s.URL,
	}

	receivedCount, err := ScanFromTime(ctx, &l, time.Unix(0, 0), entryFunc)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	if observedCount != 5 {
		t.Fatalf("expected %d observerd certs, but got %d", 5, observedCount)
	}

	if receivedCount != 5 {
		t.Fatalf("expected %d received certs, but got %d", 5, receivedCount)
	}
}

func TestFilter(t *testing.T) {
	tests := []struct {
		name        string
		all         bool
		included    []string
		excluded    []string
		expectedLen int
	}{
		{
			"all + include",
			true,
			[]string{
				"https://example.org/log1",
			},
			[]string{},
			3,
		},
		{
			"all + exclude",
			true,
			[]string{},
			[]string{
				"https://example.org/log1",
			},
			2,
		},
		{
			"not all + include",
			false,
			[]string{
				"https://example.org/log1",
			},
			[]string{},
			1,
		},
		{
			"not all + exclude",
			false,
			[]string{},
			[]string{
				"https://example.org/log1",
			},
			0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ll := LogList{
				Logs: []Log{
					{
						Url: "https://example.org/log1",
					},
					{
						Url: "https://example.org/log2",
					}, {
						Url: "https://example.org/log3",
					},
				},
				Operators: []Operator{
					{
						Name: "o1",
						Id:   1,
					}, {
						Name: "o2",
						Id:   2,
					},
				},
			}
			res := ll.Filter(tt.all, tt.included, tt.excluded)
			actual := len(res.Logs)
			if actual != tt.expectedLen {
				t.Fatalf("unexpected size of filtered logs: expected %d, but got %d", tt.expectedLen, actual)
			}
			if len(res.Operators) != 2 {
				t.Fatalf("unexpected size of filtered operators: expected %d, but got %d", 2, len(res.Operators))
			}
		})
	}

}
