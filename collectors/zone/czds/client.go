package czds

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"regexp"
	"time"
)

const (
	singleZoneUrl        = "%s/czds/downloads/%s.zone"
	downloadableZonesUrl = "%s/czds/downloads/links"
)

var (
	MalformedZoneUrl = errors.New("malfored url structure")
)

// check if the given slice contains the given item
// returns both the item and whether the slice contains the item or not
func contains(slice []string, item string) (string, bool) {
	for _, v := range slice {
		if v == item {
			return v, true
		}
	}
	return "", false
}

type HttpErr struct {
	code int
}

func (err HttpErr) Error() string {
	return fmt.Sprintf("Failed to retrieve zone file: status code %d", err.code)
}

type Client interface {
	GetZone(tld string) (io.ReadCloser, error)
	DownloadableZones() ([]string, error)
	RequestAccess(reason string) error
}

type client struct {
	baseUrl       string
	authenticator *Authenticator
	httpClient    *http.Client
}

// fetches the current version of the terms and conditions
func (c *client) tcVersion() (string, error) {
	url := fmt.Sprintf("%s/czds/terms/condition/", c.baseUrl)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case 200:
		type TC struct {
			Version    string `json:"version"`
			Content    string `json:"content"`
			ContentUrl string `json:"contentUrl"`
			Created    string `json:"created"`
		}

		var tc TC
		err := json.NewDecoder(resp.Body).Decode(&tc)
		if err != nil {
			return "", err
		}

		return tc.Version, nil
	default:
		return "", HttpErr{code: resp.StatusCode}
	}
}

func (c *client) GetZone(tld string) (io.ReadCloser, error) {
	url := fmt.Sprintf(singleZoneUrl, c.baseUrl, tld)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	token, err := c.authenticator.Token()
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	switch resp.StatusCode {
	case 200:
		return resp.Body, nil
	default:
		resp.Body.Close()
		return nil, HttpErr{resp.StatusCode}
	}
}

// returns a list of all zones that can be retrieved from the authenticated client, using the czds api
func (c *client) DownloadableZones() ([]string, error) {
	url := fmt.Sprintf(downloadableZonesUrl, c.baseUrl)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	token, err := c.authenticator.Token()
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case 200:
		raw, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}

		var urlList []string
		if err := json.Unmarshal(raw, &urlList); err != nil {
			return nil, err
		}

		r, err := regexp.Compile("https://czds-api.icann.org/czds/downloads/(.*).zone")
		if err != nil {
			return nil, err
		}

		var res []string
		for _, url := range urlList {
			matches := r.FindStringSubmatch(url)
			if len(matches) != 2 {
				return nil, err
			}
			res = append(res, matches[1])
		}

		return res, nil
	default:
		return nil, HttpErr{code: resp.StatusCode}
	}
}

// TLDRequest represents a request to access TLDs
type tldRequest struct {
	AllTLDs bool     `json:"allTlds"`
	TLD     []string `json:"tldNames"`
	Reason  string   `json:"reason"`
	Version string   `json:"tcVersion"`
}

// request access for all available TLDs
func (c *client) RequestAccess(reason string) error {
	// ensure authenticated
	if err := c.authenticator.ensureAuthenticated(); err != nil {
		return err
	}

	// get terms and condition version
	tcVersion, err := c.tcVersion()
	if err != nil {
		return err
	}
	log.Debug().Msgf("terms and condition version: %s", tcVersion)

	payload, err := json.Marshal(tldRequest{
		AllTLDs: true,
		TLD:     nil,
		Reason:  reason,
		Version: tcVersion,
	})
	if err != nil {
		return err
	}

	// prepare HTTP POST request
	body := bytes.NewReader(payload)
	url := fmt.Sprintf("%s/czds/requests/create", c.baseUrl)

	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return err
	}

	// add headers
	token, err := c.authenticator.Token()
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Add("User-Agent", "gollector/0.1")
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}

	switch resp.StatusCode {
	case 200:
		// pass
	default:
		return HttpErr{code: resp.StatusCode}
	}
	defer resp.Body.Close()

	return nil
}

func NewClient(authenticator *Authenticator, baseUrl string) Client {
	httpClient := &http.Client{
		//Timeout: time.Minute * 120, // this timeout also included reading resp body,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 120 * time.Second,
				DualStack: true,
			}).DialContext,
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   20 * time.Second,
			ResponseHeaderTimeout: 20 * time.Second,
			ExpectContinueTimeout: 5 * time.Second,
		},
	}
	c := client{
		baseUrl:       baseUrl,
		authenticator: authenticator,
		httpClient:    httpClient,
	}
	return &c
}
