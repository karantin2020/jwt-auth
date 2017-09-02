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
}

type JWTAuthTokens struct {
	Bearer       bool
	AuthToken    string
	RefreshToken string
}

func GetCredentials(authUrl string, bearer bool,
	authName, refreshName string, timeout time.Duration) (*AuthTokens, error) {
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

	return GrabAuthTokens(resp, authName, refreshName)
}

func GrabAuthTokens(resp *http.Response, authName, refreshName string) (*AuthTokens, error) {
	tok := AuthTokens{}

	rc := resp.Cookies()
	for i, cookie := range rc {
		if cookie.Name == authName {
			tok.AuthTokenCookie = rc[i]
		} else if cookie.Name == refreshName {
			tok.RefreshTokenCookie = rc[i]
		}
	}
	if tok.AuthTokenCookie != nil && tok.RefreshTokenCookie != nil {
		tok.Bearer = false
		return &tok, nil
	}

	tok.AuthTokenHeader = resp.Header.Get(authName)
	tok.RefreshTokenHeader = resp.Header.Get(refreshName)
	if tok.AuthTokenHeader != "" || tok.RefreshTokenHeader != "" {
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
		// !!! Check if here is correct || validation
		if jwtTok.AuthToken != "" && jwtTok.RefreshToken != "" {
			if !jwtTok.Bearer {
				return nil, errors.New("Invalid bearer type in jwt body response")
			}
			tok.AuthTokenHeader = jwtTok.AuthToken
			tok.RefreshTokenHeader = jwtTok.RefreshToken
			return &tok, nil
		}
	}

	return nil, errors.New("Invalid credentials")
}
