package splunk

import (
	"bufio"
	"encoding/json"
	"github.com/aau-network-security/go-domains/config"
	"os"
	"path/filepath"
	"time"
)

type Result struct {
	Timestamp time.Time `json:"timestamp"`
	Query     string    `json:"query{}"`
	QueryType string    `json:"query_type{}"`
}

type Entry struct {
	Preview bool   `json:"preview"`
	Offset  int    `json:"offset"`
	Result  Result `json:"result"`
}

type EntryFunc func(Entry) error

func Process(conf config.Splunk, entryFn EntryFunc) error {
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
			if err := json.Unmarshal(sc.Bytes(), &entry); err != nil {
				return err
			}
			if err := entryFn(entry); err != nil {

			}
		}
		return nil
	}
	return filepath.Walk(conf.Directory, walkFn)
}
