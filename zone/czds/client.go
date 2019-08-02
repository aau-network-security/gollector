package czds

import (
	"fmt"
	"io"
	"net/http"
)

const (
	authUrl = "https://account-api.icann.org/api/authenticate"
	apiUrl  = "https://czds-api.icann.org/czds/downloads/%s.zone"
)

type HttpErr struct {
	code int
}

func (err HttpErr) Error() string {
	return fmt.Sprintf("Failed to retrieve zone file: status code %d", err.code)
}

type Client interface {
	GetZone(tld string) (io.ReadCloser, error)
}

type client struct {
	authenticator *Authenticator
	httpClient    *http.Client
}

func NewClient(authenticator *Authenticator) Client {
	httpClient := &http.Client{}
	c := client{
		authenticator: authenticator,
		httpClient:    httpClient,
	}
	return &c
}

func (c *client) GetTLD() error {
	return nil
}

func (c *client) GetZone(tld string) (io.ReadCloser, error) {
	url := fmt.Sprintf(apiUrl, tld)
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
