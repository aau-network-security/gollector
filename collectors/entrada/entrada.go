package entrada

import (
	"context"
	"database/sql"
	imp "github.com/bippio/go-impala"
	"github.com/rs/zerolog/log"
	"io"
	"time"
)

var (
	DefaultOptions = Options{
		Query: "SELECT qname, min(unixtime) FROM dns.queries GROUP BY qname",
	}
)

type EntryFunc func(fqdn string, t time.Time) error

type unixTime struct {
	unix int64
}

func (ut *unixTime) toTime() time.Time {
	return time.Unix(ut.unix, 0)
}

type row struct {
	qname    string
	unixTime unixTime
}

type Options struct {
	Query string
}

type Source struct {
	io.Closer
	db *sql.DB
}

func (src *Source) Close() error {
	return src.db.Close()
}

func (src *Source) Process(ctx context.Context, entryFn EntryFunc, opts Options) (int64, error) {
	rows, err := src.db.QueryContext(ctx, opts.Query)
	if err != nil {
		return 0, err
	}

	var count int64
	for rows.Next() {
		count += 1
		r := row{}
		if err := rows.Scan(&r.qname, &r.unixTime.unix); err != nil {
			return 0, err
		}
		if err := entryFn(r.qname, r.unixTime.toTime()); err != nil {
			log.Warn().Msgf("failed to process qname: %s", err)
		}
	}

	return count, rows.Err()
}

func NewSource(host, port string) *Source {
	opts := imp.DefaultOptions
	opts.Host = host
	opts.Port = port
	opts.QueryTimeout = 60 * 60 * 24 // 1 day
	opts.BatchSize = 0
	opts.BufferSize = 65536

	c := imp.NewConnector(&opts)
	db := sql.OpenDB(c)
	src := &Source{
		db: db,
	}
	return src
}

func NewSourceByDb(db *sql.DB) *Source {
	return &Source{
		db: db,
	}
}
