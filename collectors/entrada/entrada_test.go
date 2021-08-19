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
		Query: fmt.Sprintf("SELECT 1"), // it doesn't matter what the query is here
	}

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock SQL")
	}
	csvString := `www.example.co.uk,1,1,1 
a,2,2,1
a,3,3,1
1.2.3.4,3,3,1
help.me,4,4,1
`
	mock.ExpectQuery(opts.Query).WillReturnRows(sqlmock.NewRows([]string{"a", "b", "c", "d"}).FromCSVString(csvString))

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
	entryFn := func(fqdn string, minTime time.Time, maxTime time.Time, count int64) error {
		c++
		return s.StoreEntradaEntry(muid, fqdn, minTime, maxTime, count)
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
