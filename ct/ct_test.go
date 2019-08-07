package ct

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
)

func fileHandler(filename string) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := ioutil.ReadFile(filename)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}
		if _, err := w.Write(raw); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}
	})
}

func TestLogsFromUrl(t *testing.T) {
	s := httptest.NewServer(fileHandler("fixtures/logs.json"))

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
	s := httptest.NewServer(fileHandler("fixtures/sth.json"))

	l := Log{
		Url: s.URL,
	}
	size, err := l.size()
	if err != nil {
		t.Fatalf("unexpected error while retrieving log size: %s", err)
	}
	if size != 64450 {
		t.Fatalf("expected size to be %d, but got %d", 64450, size)
	}
}
