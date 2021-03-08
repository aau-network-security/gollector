package ct

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	prt "github.com/aau-network-security/gollector/api/proto"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/scanner"
	errors2 "github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

var (
	NoIndexFoundErr        = errors.New("no index found")
	UnsupportedCertTypeErr = errors.New("provided certificate is not supported")
)

type IndexTooLargeErr struct {
	t time.Time
}

func (err IndexTooLargeErr) Error() string {
	return fmt.Sprintf("cannot determine index to start from, as all entries in log are after upper limit date: %s", err.t)
}

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

func indexByDate(ctx context.Context, client *Client, t time.Time, lower int64, upper int64) (int64, error) {
	middle := (lower + upper) / 2

	entries, err := client.GetEntries(ctx, middle, middle+1)
	if err != nil {
		return 0, errors2.Wrap(err, "get CT log entries")
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
			return 0, IndexTooLargeErr{nextTs}
		}
		return indexByDate(ctx, client, t, middle, upper)
	}

	return 0, NoIndexFoundErr
}

// returns the index of the first entry in the log past a given timestamp
func IndexByDate(ctx context.Context, l *Log, t time.Time) (int64, error) {
	lc, err := l.GetClient()
	if err != nil {
		return 0, errors2.Wrap(err, "get log client")
	}

	sth, err := lc.GetSTH(ctx)
	if err != nil {
		return 0, errors2.Wrap(err, "get CT STH")
	}

	// get first entry
	entries, err := lc.GetEntries(ctx, 0, 0)
	if err != nil {
		return 0, err
	}
	unixMin := entries[0].Leaf.TimestampedEntry.Timestamp
	tsMin := time.Unix(int64(unixMin/1000), int64(unixMin%1000))
	if tsMin.After(t) {
		// first entry is after provided t
		return 0, nil
	}

	// get last entry
	treeSize := int64(sth.TreeSize)
	entries, err = lc.GetEntries(ctx, treeSize-1, treeSize-1)
	if err != nil {
		return 0, err
	}
	unixMax := entries[0].Leaf.TimestampedEntry.Timestamp
	tsMax := time.Unix(int64(unixMax/1000), int64(unixMax%1000))
	if tsMax.Before(t) {
		// last entry is before t
		return treeSize, nil
	}

	idx, err := indexByDate(ctx, lc, t, 0, int64(sth.TreeSize)-1)
	if err != nil {
		return 0, errors2.Wrap(err, "get index by date")
	}

	return idx, nil
}

func IndexByLastEntryDB(ctx context.Context, l *Log, cc prt.CtApiClient) (int64, int64, error) {
	lc, err := l.GetClient()
	if err != nil {
		return 0, 0, errors2.Wrap(err, "get log client")
	}

	sth, err := lc.GetSTH(ctx)
	if err != nil {
		return 0, 0, errors2.Wrap(err, "get CT STH")
	}

	index, err := cc.GetLastDBEntry(ctx, &prt.KnownLogURL{
		LogURL: l.Url,
	})
	if err != nil {
		return 0, 0, errors2.Wrap(err, "get Last LogEntry DB")
	}

	return index.Start, int64(sth.TreeSize), nil
}

type Client struct {
	cancelFn   context.CancelFunc
	lock       *sync.Mutex
	maxRetries float64
	curRetries float64
	c          *client.LogClient
}

func (c *Client) BaseURI() string {
	return c.c.BaseURI()
}

func (c *Client) GetSTH(ctx context.Context) (*ct.SignedTreeHead, error) {
	return c.c.GetSTH(ctx)
}

func (c *Client) GetRawEntries(ctx context.Context, start, end int64) (*ct.GetEntriesResponse, error) {
	c.lock.Lock()
	defer c.lock.Unlock()

	resp, err := c.c.GetRawEntries(ctx, start, end)
	if err == nil && c.curRetries > 0 {
		c.curRetries -= 0.05
	} else {
		c.curRetries += 1
		if c.curRetries >= c.maxRetries {
			log.Warn().Msgf("max retries reached")
			if c.cancelFn != nil {
				c.cancelFn()
			}
		}
	}
	return resp, err
}

func (c *Client) GetEntries(ctx context.Context, start, end int64) ([]ct.LogEntry, error) {
	return c.c.GetEntries(ctx, start, end)
}

func (c *Client) SetCancelFunc(fn context.CancelFunc) {
	c.cancelFn = fn
}

type Log struct {
	Description       string `json:"description"`
	Key               string `json:"key"`
	Url               string `json:"url"`
	MaximumMergeDelay int    `json:"maximum_merge_delay"`
	OperatedBy        []int  `json:"operated_by"`
	DnsApiEndpoint    string `json:"dns_api_endpoint"`
	c                 *Client
}

func (l *Log) GetClient() (*Client, error) {
	if l.c != nil {
		return l.c, nil
	}
	uri := fmt.Sprintf("https://%s", l.Url)
	hc := http.Client{}
	jsonOpts := jsonclient.Options{}
	lc, err := client.New(uri, &hc, jsonOpts)
	if err != nil {
		return nil, errors2.Wrap(err, "create new log client")
	}
	client := &Client{
		lock:       &sync.Mutex{},
		maxRetries: 100,
		curRetries: 0,
		c:          lc,
	}
	l.c = client
	return client, nil
}

func (l *Log) Name() string {
	return l.Url
}

type Operator struct {
	Name string `json:"name"`
	Id   int    `json:"id"`
}

type LogList struct {
	Logs      []Log      `json:"logs"`
	Operators []Operator `json:"operators"`
}

// returns true if the list contains the given element
func containsStr(list []string, v string) bool {
	for _, e := range list {
		if e == v {
			return true
		}
	}
	return false
}

// filter the log list according to urls to include and exclude
func (ll *LogList) Filter(all bool, included []string, excluded []string) *LogList {
	res := LogList{
		Logs:      []Log{},
		Operators: ll.Operators, // copy all operators
	}

	if all {
		// select all, and exclude
		for _, log := range ll.Logs {
			if !containsStr(excluded, log.Url) {
				res.Logs = append(res.Logs, log)
			}
		}

	} else {
		// select none, and include
		for _, log := range ll.Logs {
			if containsStr(included, log.Url) {
				res.Logs = append(res.Logs, log)
			}
		}
	}

	return &res
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

type EntryFunc func(entry *ct.LogEntry) error

func handleRawLogEntryFunc(entryFn EntryFunc) func(rle *ct.RawLogEntry) {
	return func(rle *ct.RawLogEntry) {
		logEntry, err := rle.ToLogEntry()
		if err != nil {
			log.Error().Msgf("failed to parse raw log entry: %s", err)
		}
		if err := entryFn(logEntry); err != nil {
			log.Error().Msgf("failed to handle log entry: %s", err)
		}
	}
}

type Options struct {
	StartIndex, EndIndex int64
	WorkerCount          int
}

func (o Options) Count() int64 {
	if o.EndIndex == 0 {
		return 0
	}
	return o.EndIndex - o.StartIndex
}

func Scan(ctx context.Context, l *Log, entryFn EntryFunc, opts Options) (int64, error) {
	ctx, cancelFn := context.WithCancel(ctx)

	lc, err := l.GetClient()
	if err != nil {
		return 0, err
	}
	lc.SetCancelFunc(cancelFn)

	scannerOpts := scanner.ScannerOptions{
		FetcherOptions: scanner.FetcherOptions{
			BatchSize:     1000,
			ParallelFetch: opts.WorkerCount,
			StartIndex:    opts.StartIndex,
			EndIndex:      opts.EndIndex,
			Continuous:    true,
		},
		Matcher:     &scanner.MatchAll{},
		PrecertOnly: false,
		NumWorkers:  opts.WorkerCount,
	}

	sc := scanner.NewScanner(lc, scannerOpts)
	rleFunc := handleRawLogEntryFunc(entryFn)

	errChannel := make(chan error)
	go func() {
		errChannel <- sc.Scan(ctx, rleFunc, rleFunc)
	}()

	select {
	case err := <-errChannel:
		if err != nil {
			return 0, err
		}
		break
	case <-ctx.Done():
		break
	}
	return opts.Count(), nil
}

func ScanFromTime(ctx context.Context, l *Log, t time.Time, entryFn EntryFunc) (int64, error) {
	startIndex, err := IndexByDate(ctx, l, t)
	if err != nil {
		return 0, err
	}

	opts := Options{
		WorkerCount: 10,
		StartIndex:  startIndex,
		EndIndex:    0,
	}

	return Scan(ctx, l, entryFn, opts)
}
