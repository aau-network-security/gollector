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
	tld     string
	content string
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
	fmt.Fprintf(gz, s.content)
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

func newZonefileServer(content string, tld string) *zonefileServer {
	return &zonefileServer{
		tld:     tld,
		content: content,
	}
}

func main() {
	tld := "test"

	content := `first.org. IN NS ns1.dns.com.
first.com. IN NS ns2.dns.com.
second.com. IN NS ns3.dns.com.
second.dk. IN NS ns3.dns.com.
test.co.uk. IN NS ns4.dns.com.
third.net. IN A 10.0.0.1
fourth.net. IN AAAA ::1
`
	s := newZonefileServer(content, tld)

	s.start(":57962")
}
