package client

import (
	"encoding/json"
	"github.com/pkg/errors"
	"net/http"
	"time"
)

type AuthTokens struct {
	Bearer             bool
	AuthTokenHeader    string
	AuthTokenCookie    *http.Cookie
	RefreshTokenHeader string
	RefreshTokenCookie *http.Cookie
	// CSRFToken          string
}

type JWTAuthTokens struct {
	Bearer       bool
	AuthToken    string
	RefreshToken string
	// CSRFToken    string
}

func GetCredentials(authUrl string, bearer bool,
	authName, refreshName /*, csrfName*/ string, timeout time.Duration) (*AuthTokens, error) {
	// get credentials
	cl := &http.Client{
		Timeout: timeout,
	}
	req, err := http.NewRequest("GET", authUrl, nil)
	if err != nil {
		return nil, errors.Wrap(err, "Error in GetCredentials: couldn't build request")
	}

	resp, err := cl.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "Error in GetCredentials: couldn't send request to auth server")
	}

	return GrabAuthTokens(resp, authName, refreshName /*, csrfName*/)
}

func GrabAuthTokens(resp *http.Response, authName, refreshName /*, csrfName*/ string) (*AuthTokens, error) {
	tok := AuthTokens{}
	// tok.CSRFToken = resp.Header.Get(csrfName)

	rc := resp.Cookies()
	for i, cookie := range rc {
		if cookie.Name == authName {
			tok.AuthTokenCookie = rc[i]
		} else if cookie.Name == refreshName {
			tok.RefreshTokenCookie = rc[i]
		}
	}
	if tok.AuthTokenCookie != nil && tok.RefreshTokenCookie != nil /*&& tok.CSRFToken != ""*/ {
		tok.Bearer = false
		return &tok, nil
	}

	tok.AuthTokenHeader = resp.Header.Get(authName)
	tok.RefreshTokenHeader = resp.Header.Get(refreshName)
	if tok.AuthTokenHeader != "" || tok.RefreshTokenHeader != "" /*&& tok.CSRFToken != ""*/ {
		tok.Bearer = true
		return &tok, nil
	}

	if resp.StatusCode > 199 && resp.StatusCode < 300 {
		jwtTok := JWTAuthTokens{}
		defer resp.Body.Close()

		err := json.NewDecoder(resp.Body).Decode(&jwtTok)
		if err != nil {
			return nil, errors.Wrap(err, "Couldn't Unmarshal response body")
		}
		if jwtTok.AuthToken != "" || jwtTok.RefreshToken != "" /*|| jwtTok.CSRFToken != ""*/ {
			if !jwtTok.Bearer {
				return nil, errors.New("Invalid bearer type in jwt body response")
			}
			tok.AuthTokenHeader = jwtTok.AuthToken
			tok.RefreshTokenHeader = jwtTok.RefreshToken
			// tok.CSRFToken = jwtTok.CSRFToken
			return &tok, nil
		}
	}

	return nil, errors.New("Invalid credentials")
}
