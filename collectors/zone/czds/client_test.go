package czds

import (
	"compress/gzip"
	tst "github.com/aau-network-security/go-domains/testing"
	"github.com/rs/zerolog/log"
	"os"
	"testing"
)

func TestClient(t *testing.T) {
	tst.SkipCI(t)

	user := os.Getenv("CZDS_USER")
	pass := os.Getenv("CZDS_PASS")
	creds := Credentials{
		Username: user,
		Password: pass,
	}
	auth := NewAuthenticator(creds)

	c := NewClient(auth)

	resp, err := c.GetZone("net")
	if err != nil {
		t.Fatalf("Error while retrieving zone: %s", err)
	}
	defer resp.Close()

	_, err = gzip.NewReader(resp)
	if err != nil {
		t.Fatalf("Error while creating gzip reader: %s", err)
	}
}

func TestAllZones(t *testing.T) {
	tst.SkipCI(t)
	user := os.Getenv("CZDS_USER")
	pass := os.Getenv("CZDS_PASS")
	cred := Credentials{
		Username: user,
		Password: pass,
	}
	auth := NewAuthenticator(cred)

	c := NewClient(auth)

	zones, err := c.AllZones()
	if err != nil {
		t.Fatalf("failed to retrieve all zones: %s", err)
	}

	for _, zone := range zones {
		log.Debug().Msgf("%s", zone)
	}
}
