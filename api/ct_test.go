package api

import (
	"context"
	"encoding/hex"
	api "github.com/aau-network-security/gollector/api/proto"
	"github.com/aau-network-security/gollector/app"
	"github.com/aau-network-security/gollector/store"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"
	"io"
	"io/ioutil"
	"net"
	"testing"
)

func getBufDialer(lis *bufconn.Listener) func(context.Context, string) (net.Conn, error) {
	return func(ctx context.Context, url string) (net.Conn, error) {
		return lis.Dial()
	}
}

func TestServer_StoreLogEntries(t *testing.T) {
	tests := []struct {
		name      string
		certFile  string // hexadecimal encoded
		isPrecert bool
	}{
		{
			name:      "Normal cert",
			certFile:  "fixtures/cert.crt",
			isPrecert: false,
		},
		{
			name:      "Pre-cert",
			certFile:  "fixtures/precert.crt",
			isPrecert: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s, _, muid, err := store.OpenStore(store.TestConfig, store.TestOpts)
			if err != nil {
				t.Fatalf("failed to open store: %s", err)
			}

			serv := Server{
				Conf:  Config{},
				Store: s,
				Log:   app.NewZeroLogger(nil),
			}

			lis := bufconn.Listen(1024 * 1024)

			go func() {
				serv.Run(lis)
			}()

			ctx := context.Background()

			// prepare cert to store
			rawEncoded, err := ioutil.ReadFile(test.certFile)
			if err != nil {
				t.Fatalf("failed to read cert file: %s", err)
			}

			rawDecoded := make([]byte, hex.DecodedLen(len(rawEncoded)))

			if _, err := hex.Decode(rawDecoded, rawEncoded); err != nil {
				t.Fatalf("failed to decode hex cert: %s", err)
			}

			// prepare connection & stream
			cc, err := grpc.Dial("", grpc.WithContextDialer(getBufDialer(lis)), grpc.WithInsecure())
			if err != nil {
				t.Fatalf("failed to dial: %s", err)
			}

			client := api.NewCtApiClient(cc)

			md := metadata.New(map[string]string{
				"muid": muid,
			})
			ctx = metadata.NewOutgoingContext(ctx, md)

			str, err := client.StoreLogEntries(ctx)
			if err != nil {
				t.Fatalf("failed to create stream to store log entries: %s", err)
			}

			count := 0
			failures := 0
			done := make(chan bool)
			go func() {
				for {
					res, err := str.Recv()
					if err == io.EOF {
						break
					}
					if err != nil {
						t.Fatalf("unexpected error: %s", err)
					}
					if !res.Ok {
						failures++
					}
					count++
				}
				done <- true
			}()

			// store log entry using the stream
			batch := api.LogEntryBatch{
				LogEntries: []*api.LogEntry{
					{
						Log: &api.Log{
							Description: "test",
							Url:         "localhost.",
						},
						Index:       10,
						Certificate: rawDecoded,
						Timestamp:   10,
						IsPrecert:   test.isPrecert,
					},
				},
			}

			if err := str.Send(&batch); err != nil {
				t.Fatalf("failed to send log entry batch: %s", err)
			}

			if err := str.CloseSend(); err != nil {
				t.Fatalf("failed to close connection: %s", err)
			}
			<-done

			// check for expected output
			if count != 1 {
				t.Fatalf("expected %d results, but got %d", 1, count)
			}

			if failures != 0 {
				t.Fatalf("expected %d failures, but got %d", 0, failures)
			}
		})
	}
}
