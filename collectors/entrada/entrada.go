package entrada

import (
	"context"
	"database/sql"
	"io"
	"time"

	imp "github.com/bippio/go-impala"
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

func (src *Source) Process(ctx context.Context, entryFn EntryFunc, opts Options) error {
	rows, err := src.db.QueryContext(ctx, opts.Query)
	if err != nil {
		return err
	}

	for rows.Next() {
		r := row{}
		if err := rows.Scan(&r.qname, &r.unixTime.unix); err != nil {
			return err
		}
		if err := entryFn(r.qname, r.unixTime.toTime()); err != nil {
			return err
		}
	}

	return rows.Err()
}

func NewSource(host, port string) *Source {
	opts := imp.DefaultOptions
	opts.Host = host
	opts.Port = port

	c := imp.NewConnector(&opts)
	db := sql.OpenDB(c)
	src := &Source{
		db: db,
	}
	return src
}
