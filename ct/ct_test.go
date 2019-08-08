package ct

import (
	"context"
	"fmt"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/rs/zerolog/log"
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

func TestSize(t *testing.T) {
	s := httptest.NewServer(fileHandler(t, "fixtures/sth.json"))

	l := Log{
		Url: s.URL,
	}
	size, err := l.size()
	if err != nil {
		t.Fatalf("unexpected error while retrieving log size: %s", err)
	}
	if size != 5 {
		t.Fatalf("expected size to be %d, but got %d", 64450, size)
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

func getSthHandleFunc() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		log.Debug().Msgf("req.Header: %s", req.Header)
		w.WriteHeader(200)
	}
}

func Test(t *testing.T) {

}

func TestIndexByDate(t *testing.T) {
	tests := []struct {
		name          string
		time          time.Time
		expectedIndex int64
		expectedErr   error
	}{
		{
			name:          "Within range of logs",
			time:          time.Unix(1502376196, 0), // just before the entry with index 2
			expectedIndex: 2,
		},
		{
			name:          "Before range",
			time:          time.Unix(0, 0), // 01-01-1970,
			expectedIndex: 0,
		},
		{
			name:        "After range",
			time:        time.Now(), // timestamp after any cert in the test log data set
			expectedErr: IndexTooLargeErr,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()

			mux := http.NewServeMux()
			mux.HandleFunc("/ct/v1/get-entries", getEntriesHandleFunc(t))
			mux.HandleFunc("/ct/v1/get-sth", fileHandler(t, "fixtures/sth.json"))

			s := httptest.NewServer(mux)
			httptest.NewTLSServer(mux)

			hc := s.Client()
			opts := jsonclient.Options{}
			lc, err := client.New(s.URL, hc, opts)
			if err != nil {
				t.Fatalf("failed to create log client: %s", err)
			}

			idx, err := IndexByDate(ctx, lc, test.time)
			if err != test.expectedErr {
				t.Fatalf("expected error %s, but got %s", test.expectedErr, err)
			}
			if idx != test.expectedIndex {
				t.Fatalf("expected index %d, but got %d", test.expectedIndex, idx)
			}
		})
	}
}
