package splunk

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

type QueryResult struct {
	Query     string
	QueryType string
}

type strSlice []string

func (s *strSlice) UnmarshalJSON(b []byte) error {
	switch b[0] {
	case '[':
		var content []string
		if err := json.Unmarshal(b, &content); err != nil {
			return err
		}
		*s = content
	default:
		var content string
		if err := json.Unmarshal(b, &content); err != nil {
			return err
		}
		*s = []string{content}
	}
	return nil
}

type Result struct {
	Timestamp  time.Time `json:"timestamp"`
	Queries    strSlice  `json:"query{}"`
	QueryTypes strSlice  `json:"query_type{}"`
}

type Entry struct {
	Preview bool   `json:"preview"`
	Offset  int    `json:"offset"`
	Result  Result `json:"result"`
}

func (e *Entry) QueryResults() []QueryResult {
	var res []QueryResult
	for i := range e.Result.Queries {
		qr := QueryResult{
			Query:     e.Result.Queries[i],
			QueryType: e.Result.QueryTypes[i],
		}
		res = append(res, qr)
	}
	return res
}

type EntryFunc func(Entry) error

func Process(dir string, entryFn EntryFunc) error {
	walkFn := func(path string, info os.FileInfo, err error) error {
		// ignore errors
		if err != nil {
			return err
		}
		// ignore directories
		if info.IsDir() {
			return nil
		}

		file, err := os.Open(path)
		if err != nil {
			return err
		}
		sc := bufio.NewScanner(file)
		for sc.Scan() {
			var entry Entry
			b := sc.Bytes()
			if err := json.Unmarshal(b, &entry); err != nil {
				return err
			}
			if err := entryFn(entry); err != nil {

			}
		}
		return nil
	}
	return filepath.Walk(dir, walkFn)
}
