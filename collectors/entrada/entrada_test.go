package entrada

import (
	"context"
	"fmt"
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/aau-network-security/gollector/store"
	"testing"
	"time"
)

func Test(t *testing.T) {
	// create mock ENTRADA source
	expected := 5
	opts := Options{
		Query: fmt.Sprintf("SELECT qname, unixtime FROM dns.queries LIMIT %d", expected),
	}

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock SQL")
	}
	csvString := `www.example.co.uk,1 
a,2
a,3
1.2.3.4,3
help.me,4
`
	mock.ExpectQuery(opts.Query).WillReturnRows(sqlmock.NewRows([]string{"a", "b"}).FromCSVString(csvString))

	src := Source{
		db: db,
	}
	defer src.Close()

	// create store
	storeOpts := store.TestOpts
	storeOpts.BatchSize = 2
	s, _, muid, err := store.OpenStore(store.TestConfig, store.TestOpts)
	if err != nil {
		t.Fatalf("failed to open store: %s", err)
	}

	a := store.NewAnonymizer(
		store.NewSha256LabelAnonymizer("1"),
		store.NewSha256LabelAnonymizer("2"),
		store.NewSha256LabelAnonymizer("3"),
		store.NewSha256LabelAnonymizer("4"),
	)
	s = s.WithAnonymizer(a)

	c := 0
	entryFn := func(qname string, unixTime time.Time) error {
		c++
		return s.StoreEntradaEntry(muid, qname, unixTime)
	}

	// execute test
	ctx := context.Background()
	if _, err := src.Process(ctx, entryFn, opts); err != nil {
		t.Fatalf("unexpected error while processing impala data: %s", err)
	}

	if c != expected {
		t.Fatalf("expected %d function calls, but got %d", expected, c)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("there were unfulfilled expectations: %s", err)
	}

	if err := s.RunPostHooks(); err != nil {
		t.Fatalf("unexpected error while running post hooks: %s", err)
	}
}
