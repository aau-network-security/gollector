package czds

import (
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"regexp"
	"time"
)

const (
	singleZoneUrl = "%s/czds/downloads/%s.zone"
	allZonesUrl   = "%s/czds/downloads/links"
)

var (
	MalformedZoneUrl = errors.New("malfored url structure")
)

type HttpErr struct {
	code int
}

func (err HttpErr) Error() string {
	return fmt.Sprintf("Failed to retrieve zone file: status code %d", err.code)
}

type Client interface {
	GetZone(tld string) (io.ReadCloser, error)
	AllZones() ([]string, error)
}

type client struct {
	baseUrl       string
	authenticator *Authenticator
	httpClient    *http.Client
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
func (c *client) AllZones() ([]string, error) {
	url := fmt.Sprintf(allZonesUrl, c.baseUrl)
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
