package main

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/rs/zerolog/log"
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

func (s *zonefileServer) TermsConditions(w http.ResponseWriter, req *http.Request) {
	payload := map[string]string{
		"version": "1.0",
	}
	b, err := json.Marshal(payload)
	if err != nil {
		w.WriteHeader(500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
}

func (s *zonefileServer) RequestAccess(w http.ResponseWriter, req *http.Request) {
	if err := req.ParseForm(); err != nil {
		w.WriteHeader(400)
		return
	}
	reason := req.PostForm.Get("reason")
	tcVersion := req.PostForm.Get("tcVersion")
	allTlds := req.PostForm.Get("allTlds")

	log.Debug().Msgf("request access with reason: %s", reason)
	log.Debug().Msgf("request access with terms and condition version: %s", tcVersion)
	log.Debug().Msgf("request access for all TLDs?: %s", allTlds)

	w.WriteHeader(200)
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
	http.HandleFunc("/czds/terms/condition/", s.TermsConditions)
	http.HandleFunc("/czds/requests/create", s.RequestAccess)

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
