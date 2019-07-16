package czds

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"io"
	"net/http"
	"time"
)

const (
	baseApiUrl       = "https://account-api.icann.org"
	authenticatePath = "/api/authenticate"
)

var (
	JwtTokenErr = errors.New("error while parsing JWT token")
)

type Client interface {
	GetZone(tld string, output io.Writer) error
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
	conf       Config
	httpClient *http.Client
	auth       *authResponse
}

func NewClient(conf Config) Client {
	httpClient := &http.Client{}
	c := client{
		conf:       conf,
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
	postBody := authRequest{}
	marshalled, err := json.Marshal(postBody)
	if err != nil {
		return err
	}

	url := baseApiUrl + authenticatePath
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(marshalled))
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

func (c *client) GetZone(tld string, output io.Writer) error {
	if err := c.ensureAuthenticated(); err != nil {
		return err
	}

	url := fmt.Sprintf("%s/czds/downloads/%s.zone", baseApiUrl, tld)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authentication", fmt.Sprintf("Bearer %s", c.auth.AccessToken))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	n, err := io.Copy(output, resp.Body)
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("%s was empty", url)
	}

	return nil
}
