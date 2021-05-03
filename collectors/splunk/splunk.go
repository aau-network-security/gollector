package splunk

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/rs/zerolog/log"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"
)

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
	Timestamp time.Time `json:"timestamp"`
	Queries   strSlice  `json:"query{}"`
}

type Entry struct {
	Preview bool   `json:"preview"`
	Offset  int    `json:"offset"`
	Result  Result `json:"result"`
}

func (e *Entry) Queries() []string {
	var res []string
	for _, qry := range e.Result.Queries {
		res = append(res, qry)
	}
	return res
}

type EntryFunc func(Entry) error

func Process(dir string, entryFn EntryFunc) error {
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		return err
	}
	nFiles := len(files)

	for i, info := range files {
		if info.IsDir() {
			continue
		}
		ext := filepath.Ext(info.Name())
		if ext != ".json" {
			continue
		}

		path := filepath.Join(dir, info.Name())
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		sc := bufio.NewScanner(file)
		count := 0
		for sc.Scan() {
			var entry Entry
			b := sc.Bytes()
			if err := json.Unmarshal(b, &entry); err != nil {
				log.Debug().Msgf("failed to unmarshal json: %s", err)
				continue
			}
			if err := entryFn(entry); err != nil {
				log.Warn().Msgf("failed to apply function to entry: %s", err)
			}
			count++
		}
		log.Debug().
			Str("progress", fmt.Sprintf("%d/%d", i+1, nFiles)).
			Int("count", count).
			Msgf("finished DNS file")
	}
	return nil
}
