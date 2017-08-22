package client

import (
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
	CSRFToken          string
}

func GetCredentials(authUrl string, bearer bool,
	authName, refreshName, csrfName string, timeout time.Duration) (*AuthTokens, error) {
	tok := AuthTokens{}
	// get credentials
	cl := &http.Client{
		Timeout: time.Second * 3,
	}
	req, err := http.NewRequest("GET", authUrl, nil)
	if err != nil {
		return nil, errors.Wrap(err, "Error in AuthorizeJWT: couldn't build request")
	}

	resp, err := cl.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "Error in AuthorizeJWT: couldn't send request to auth server")
	}

	tok.Bearer = bearer
	if !bearer {
		rc := resp.Cookies()
		// fmt.Printf("resp Cookies: %#v\n", rc)
		if len(rc) == 0 {
			return nil, errors.New("Couldn't get response cookies")
		}

		for i, cookie := range rc {
			if cookie.Name == authName {
				tok.AuthTokenCookie = rc[i]
			} else if cookie.Name == refreshName {
				tok.RefreshTokenCookie = rc[i]
			}
		}
	} else {
		if len(resp.Header) == 0 {
			return nil, errors.New("Couldn't get response headers")
		}

		rha := resp.Header.Get(authName)
		if rha == "" {
			return nil, errors.New("Couldn't get response auth header")
		}
		tok.AuthTokenHeader = rha
		rhr := resp.Header.Get(refreshName)
		if rhr == "" {
			return nil, errors.New("Couldn't get response refresh headers")
		}
		tok.RefreshTokenHeader = rhr
	}
	tok.CSRFToken = resp.Header.Get(csrfName)

	if tok.Bearer && (tok.AuthTokenHeader == "" || tok.RefreshTokenHeader == "") ||
		!tok.Bearer && (tok.AuthTokenCookie == nil || tok.RefreshTokenCookie == nil) || tok.CSRFToken == "" {
		return nil, errors.New("Invalid credentials, some tokens are empty")
	}

	return &tok, nil

	// all, err := ioutil.ReadAll(res.Body)
	// if err != nil {
	// 	t.Fatal("ReadAll:", err)
	// }
	// if !bytes.Equal(all, msg) && !wantErr {
	// 	t.Fatalf("Got body %q; want %q", all, msg)
	// }
}
