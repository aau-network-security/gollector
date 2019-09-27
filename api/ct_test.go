package api

import (
	"context"
	"encoding/base64"
	api "github.com/aau-network-security/go-domains/api/proto"
	"github.com/aau-network-security/go-domains/config"
	"github.com/aau-network-security/go-domains/store"
	tst "github.com/aau-network-security/go-domains/testing"
	"github.com/jinzhu/gorm"
	"github.com/pkg/errors"
	"google.golang.org/grpc/metadata"
	"io/ioutil"
	"testing"
	"time"
)

// todo: remove duplicate code
func openStore(conf store.Config) (*store.Store, *gorm.DB, string, error) {
	g, err := conf.Open()
	if err != nil {
		return nil, nil, "", errors.Wrap(err, "failed to open gorm database")
	}

	if err := tst.ResetDb(g); err != nil {
		return nil, nil, "", errors.Wrap(err, "failed to reset database")
	}

	opts := store.Opts{
		BatchSize:       10,
		AllowedInterval: 10 * time.Millisecond,
	}

	s, err := store.NewStore(conf, opts)
	if err != nil {
		return nil, nil, "", errors.Wrap(err, "failed to open store")
	}
	s.Ready.Wait()

	mid, err := s.StartMeasurement("test", "test.local")
	if err != nil {
		return nil, nil, "", errors.Wrap(err, "failed to start measurement")
	}

	return s, g, mid, nil
}

// todo: make sure this test passes
func TestServer_StoreLogEntries(t *testing.T) {
	tests := []struct {
		name     string
		certFile string // base64 encoded
	}{
		{
			name:     "Normal cert",
			certFile: "fixtures/cert.crt",
		},
		{
			name:     "Pre-cert",
			certFile: "fixtures/precert.crt",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			conf := store.Config{
				User:     "postgres",
				Password: "postgres",
				DBName:   "domains",
				Host:     "localhost",
				Port:     10001,
			}

			s, _, mid, err := openStore(conf)
			if err != nil {
				t.Fatalf("failed to open store: %s", err)
			}

			apiConfig := config.Api{
				Host: "localhost",
				Port: 0,
			}

			serv := Server{
				Store: s,
				Conf:  apiConfig,
			}

			ctx := context.Background()

			rawEncoded, err := ioutil.ReadFile(test.certFile)
			if err != nil {
				t.Fatalf("failed to read cert file: %s", err)
			}

			rawDecoded, err := base64.StdEncoding.DecodeString(string(rawEncoded))
			if err != nil {
				t.Fatalf("failed to decode cert: %s", err)
			}

			md := metadata.New(map[string]string{
				"mid": mid,
			})
			ctx = metadata.NewIncomingContext(ctx, md)

			req := api.LogEntry{
				Certificate: rawDecoded,
				Index:       10,
				Timestamp:   10,
				Log: &api.Log{
					Description: "test",
					Url:         "localhost.",
				},
			}
			apiErr, err := serv.StoreLogEntries(ctx, &req)
			if err != nil {
				t.Fatalf("unexpected error while storing log entries: %s", err)
			}
			if apiErr.Error != "" {
				t.Fatalf("unexpected error while storing log entries: %s", apiErr.Error)
			}
			if err := s.RunPostHooks(); err != nil {
				t.Fatalf("failed to run post hooks: %s", err)
			}
		})
	}
}
