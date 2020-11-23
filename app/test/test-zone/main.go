package main

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"net"
	"net/http"
)

type zonefileServer struct {
	tld string
	zlp ZoneListProvider
}

// interface for obtaining zone information
type ZoneListProvider interface {
	Zone() string
}

type roundRobinZoneLlistProvider struct {
	i        int
	contents []string
}

func (r *roundRobinZoneLlistProvider) Zone() string {
	content := r.contents[r.i]
	r.i = (r.i + 1) % len(r.contents)
	return content
}

// generate a valid JWT
func (s *zonefileServer) Authenticate(w http.ResponseWriter, req *http.Request) {
	sm := jwt.SigningMethodHS256
	claims := jwt.MapClaims{
		"exp": 1.0,
	}
	token := jwt.NewWithClaims(sm, claims)
	key := []byte("test")
	tokenStr, err := token.SignedString(key)
	if err != nil {
		w.WriteHeader(500)
		return
	}

	resMap := map[string]string{
		"accessToken": tokenStr,
	}
	b, err := json.Marshal(resMap)
	if err != nil {
		w.WriteHeader(500)
		return
	}

	w.Header().Add("content-type", "application/json")
	w.Write(b)
}

func (s *zonefileServer) ServeZone(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/dns")
	gz := gzip.NewWriter(w)
	defer gz.Close()
	fmt.Fprintf(gz, s.zlp.Zone())
}

func (s *zonefileServer) start(addr string) error {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	fmt.Printf("Running HTTP server on port %d", listener.Addr().(*net.TCPAddr).Port)

	zonePath := fmt.Sprintf("/czds/downloads/%s.zone", s.tld)
	http.HandleFunc(zonePath, s.ServeZone)
	http.HandleFunc("/api/authenticate", s.Authenticate)

	return http.Serve(listener, nil)
}

func newZonefileServer(zlp ZoneListProvider, tld string) *zonefileServer {
	return &zonefileServer{
		tld: tld,
		zlp: zlp,
	}
}

func main() {
	tld := "test"

	contents := []string{
		`first.org. IN NS ns1.dns.com.
second.co.uk. IN NS ns2.dns.com.
third.net. IN A 10.0.0.1
fourth.net. IN AAAA ::1
`,
		`first.org. IN NS ns1.dns.com.
third.net. IN A 10.0.0.1
fourth.net. IN AAAA ::1
`,
		`first.org. IN NS ns1.dns.com.
second.co.uk. IN NS ns2.dns.com.
fourth.net. IN AAAA ::1
`,
	}
	zlp := roundRobinZoneLlistProvider{
		contents: contents,
	}

	s := newZonefileServer(&zlp, tld)

	s.start(":57962")
}
