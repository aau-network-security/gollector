package czds

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/dgrijalva/jwt-go"
	"net/http"
	"sync"
	"time"
)

var (
	JwtTokenErr = errors.New("error while parsing JWT token")
)

type authRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type authResponse struct {
	AccessToken string `json:"accessToken"`
	Message     string `json:"message"`
}

type accessToken string

// ignores validation errors
func (at accessToken) isExpired() (bool, error) {
	token, err := jwt.Parse(string(at), nil)
	if err != nil {
		if _, ok := err.(*jwt.ValidationError); !ok {
			return false, err
		}
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		expIf, ok := claims["exp"]
		if !ok {
			return false, JwtTokenErr
		}

		expInt64, ok := expIf.(float64)
		if !ok {
			return false, JwtTokenErr
		}

		expiration := time.Unix(int64(expInt64), 0)
		return time.Now().After(expiration), nil
	}

	return false, JwtTokenErr
}

type Authenticator struct {
	client      *http.Client
	accessToken accessToken
	cred        Credentials
	m           *sync.Mutex
}

func (a *Authenticator) authenticate() error {
	postBody := authRequest{
		Username: a.cred.Username,
		Password: a.cred.Password,
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

	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return HttpErr{resp.StatusCode}
	}

	auth := &authResponse{}
	if err := json.NewDecoder(resp.Body).Decode(auth); err != nil {
		return err
	}

	a.accessToken = accessToken(auth.AccessToken)

	return nil
}

func (a *Authenticator) ensureAuthenticated() error {
	if a.accessToken == "" {
		return a.authenticate()
	}
	expired, err := a.accessToken.isExpired()
	if err != nil {
		return err
	}
	if expired {
		return a.authenticate()
	}
	return nil
}

func (a *Authenticator) Token() (string, error) {
	a.m.Lock()
	defer a.m.Unlock()
	if err := a.ensureAuthenticated(); err != nil {
		return "", errors.New("error while authenticating: " + err.Error())
	}
	return string(a.accessToken), nil
}

func NewAuthenticator(cred Credentials) *Authenticator {
	httpClient := &http.Client{}
	return &Authenticator{
		cred:        cred,
		client:      httpClient,
		accessToken: "",
		m:           &sync.Mutex{},
	}
}
