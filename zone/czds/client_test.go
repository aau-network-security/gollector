package czds

import (
	"compress/gzip"
	"os"
	"testing"
)

func TestClient(t *testing.T) {
	user := os.Getenv("CZDS_USER")
	pass := os.Getenv("CZDS_PASS")
	creds := Credentials{
		Username: user,
		Password: pass,
	}
	a := NewAuthenticator(creds)

	c := NewClient(a)

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
