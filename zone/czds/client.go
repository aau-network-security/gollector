package czds

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"io"
	"net"
	"net/http"
	"time"
)

const (
	authUrl = "https://account-api.icann.org/api/authenticate"
	apiUrl  = "https://czds-api.icann.org/czds/downloads/%s.zone"
)

var (
	JwtTokenErr = errors.New("error while parsing JWT token")
)

type HttpErr struct {
	code int
}

func (err *HttpErr) Error() string {
	return fmt.Sprintf("Failed to retrieve zone file: status code %d", err.code)
}

type Client interface {
	GetZone(tld string) (io.ReadCloser, error)
}

type authRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type authResponse struct {
	AccessToken string `json:"accessToken"`
	Message     string `json:"message"`
}

func (ar *authResponse) isExpired() (bool, error) {
	token, err := jwt.Parse(ar.AccessToken, nil)
	if err != nil {
		return false, err
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		exp, ok := claims["exp"].(int64)
		if !ok {
			return false, JwtTokenErr
		}
		expiration := time.Unix(exp, 0)
		return time.Now().After(expiration), nil
	}

	return false, JwtTokenErr
}

type client struct {
	cred       Credentials
	httpClient *http.Client
	auth       *authResponse
}

func NewClient(cred Credentials) Client {
	httpClient := &http.Client{
		//Timeout: time.Minute * 120, // this timeout also included reading resp body,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).DialContext,
			//MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   20 * time.Second,
			ResponseHeaderTimeout: 20 * time.Second,
			ExpectContinueTimeout: 5 * time.Second,
		},
	}
	c := client{
		cred:       cred,
		httpClient: httpClient,
	}
	return &c
}

func (c *client) GetTLD() error {
	return nil
}

func (c *client) ensureAuthenticated() error {
	if c.auth == nil {
		return c.authenticate()
	}
	expired, err := c.auth.isExpired()
	if err != nil {
		return err
	}
	if expired {
		return c.authenticate()
	}
	return nil
}

func (c *client) authenticate() error {
	postBody := authRequest{
		Username: c.cred.Username,
		Password: c.cred.Password,
	}
	marshalled, err := json.Marshal(postBody)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", authUrl, bytes.NewBuffer(marshalled))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	auth := &authResponse{}
	if err := json.NewDecoder(resp.Body).Decode(auth); err != nil {
		return err
	}

	c.auth = auth

	return nil
}

func (c *client) GetZone(tld string) (io.ReadCloser, error) {
	if err := c.ensureAuthenticated(); err != nil {
		return nil, err
	}

	url := fmt.Sprintf(apiUrl, tld)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.auth.AccessToken))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	switch resp.StatusCode {
	case 200:
		return resp.Body, nil
	default:
		resp.Body.Close()
		return nil, &HttpErr{resp.StatusCode}
	}
}
