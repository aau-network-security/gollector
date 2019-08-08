package ct

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/scanner"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/rs/zerolog/log"
	"net/http"
	"time"
)

var (
	NoIndexFoundErr        = errors.New("no index found")
	IndexTooLargeErr       = errors.New("cannot determine index to start from, as all entries in log are before requested date")
	UnsupportedCertTypeErr = errors.New("provided certificate is not supported")
)

type EntryCountErr struct {
	count int
}

func (err EntryCountErr) Error() string {
	return fmt.Sprintf("retrieved %d log entries, where 2 were expected", err.count)
}

type Sth struct {
	TreeSize          int    `json:"tree_size"`
	Timestamp         int    `json:"timestamp"`
	Sha256RootHash    string `json:"sha256_root_hash"`
	TreeHeadSignature string `json:"tree_head_signature"`
}

type CachedLogClient struct {
	cache  map[int64]*ct.LogEntry
	client client.LogClient
}

func indexByDate(ctx context.Context, client *client.LogClient, t time.Time, lower int64, upper int64) (int64, error) {
	middle := int64((lower + upper) / 2)

	entries, err := client.GetEntries(ctx, middle, middle+1)
	if err != nil {
		return 0, err
	}
	if len(entries) != 2 {
		return 0, EntryCountErr{len(entries)}
	}
	cur, next := entries[0], entries[1]
	ts := cur.Leaf.TimestampedEntry.Timestamp
	curTs := time.Unix(int64(ts/1000), int64(ts%1000))
	ts = next.Leaf.TimestampedEntry.Timestamp
	nextTs := time.Unix(int64(ts/1000), int64(ts%1000))

	// found it!
	if t.After(curTs) && t.Before(nextTs) {
		return middle + 1, nil
	}

	// must seek left of middle
	if t.Before(curTs) {
		// time is under lower bound index, so the first index to return must be ZERO
		if middle == 0 {
			return 0, nil
		}
		return indexByDate(ctx, client, t, lower, middle)
	}

	// must seek right of middle
	if t.After(nextTs) {
		// time is over upper bound index, so return an IndexTooLargeErr
		if middle == upper-1 {
			return 0, IndexTooLargeErr
		}
		return indexByDate(ctx, client, t, middle, upper)
	}

	return 0, NoIndexFoundErr
}

func IndexByDate(ctx context.Context, client *client.LogClient, t time.Time) (int64, error) {
	sth, err := client.GetSTH(ctx)
	if err != nil {
		return 0, err
	}

	return indexByDate(ctx, client, t, 0, int64(sth.TreeSize)-1)
}

type Log struct {
	Description       string `json:"description"`
	Key               string `json:"key"`
	Url               string `json:"url"`
	MaximumMergeDelay int    `json:"maximum_merge_delay"`
	OperatedBy        []int  `json:"operated_by"`
	DnsApiEndpoint    string `json:"dns_api_endpoint"`
}

type Operator struct {
	Name string `json:"name"`
	Id   int    `json:"id"`
}

type LogList struct {
	Logs      []Log      `json:"logs"`
	Operators []Operator `json:"operators"`
}

// returns a list of logs given the JSON file located at a URL
func logsFromUrl(url string) (*LogList, error) {
	c := http.Client{}
	resp, err := c.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, errors.New(fmt.Sprintf("failed to retrieve log JSON: %d", resp.StatusCode))
	}

	var logList LogList
	if err := json.NewDecoder(resp.Body).Decode(&logList); err != nil {
		return nil, err
	}
	return &logList, nil
}

// returns a list of all known logs
func AllLogs() (*LogList, error) {
	return logsFromUrl("https://www.gstatic.com/ct/log_list/all_logs_list.json")
}

// returns a list of all trusted logs
func TrustedLogs() (*LogList, error) {
	return logsFromUrl("https://www.gstatic.com/ct/log_list/log_list.json")
}

type CertFunc func(certificate *x509.Certificate) error

func handleRawLogEntryFunc(certFunc CertFunc) func(rle *ct.RawLogEntry) {
	return func(rle *ct.RawLogEntry) {
		if err := func() error {
			logEntry, err := rle.ToLogEntry()
			if err != nil {
				return err
			}

			var cert *x509.Certificate
			if logEntry.Precert != nil {
				cert = logEntry.Precert.TBSCertificate
			} else if logEntry.X509Cert != nil {
				cert = logEntry.X509Cert
			} else {
				return UnsupportedCertTypeErr
			}
			return certFunc(cert)
		}(); err != nil {
			log.Debug().Msgf("error while handling raw log entry: %s", err)
		}
	}
}

func ScanFromTime(ctx context.Context, logClient *client.LogClient, t time.Time, f CertFunc) error {
	startIndex, err := IndexByDate(ctx, logClient, t)
	if err != nil {
		return err
	}

	opts := scanner.ScannerOptions{
		FetcherOptions: scanner.FetcherOptions{
			StartIndex: startIndex,
			Continuous: false,
		},
	}

	sc := scanner.NewScanner(logClient, opts)
	rleFunc := handleRawLogEntryFunc(f)

	return sc.Scan(ctx, rleFunc, rleFunc)
}
