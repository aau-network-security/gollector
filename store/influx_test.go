package store

import (
	testing2 "github.com/aau-network-security/gollector/testing"
	"os"
	"testing"
	"time"
)

func TestNewInfluxService(t *testing.T) {
	testing2.SkipCI(t)
	tests := []struct {
		name        string
		measurement string
	}{
		{
			"standard",
			"measurement",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := InfluxOpts{
				ServUrl:      "https://influxdb.hageman.dk",
				AuthToken:    os.Getenv("INFLUX-AUTH-TOKEN"),
				Organisation: "AAU",
				Bucket:       "gollector",
				Interval:     1,
			}

			ifs := NewInfluxService(opts)
			ifs.StoreHit("cache-hit", "log", 1)
			ifs.StoreHit("cache-hit", "cert", 1)
			ifs.StoreHit("cache-insert", "cert", 1)
			ifs.LogCount("log1")
			ifs.LogCount("log1")
			ifs.LogCount("log2")

			time.Sleep(1 * time.Second)

			ifs.Close()
		})
	}
}
