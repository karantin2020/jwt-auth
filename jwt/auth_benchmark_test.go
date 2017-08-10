package jwt

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	//"net/url"
	//"strings"
	jwt "gopkg.in/square/go-jose.v2/jwt"
	"testing"
	"time"
)

var msg = []byte("Hello world.\n")

var (
	debug = false
)

func TestBaseServer(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Write(msg)
	}))
	defer ts.Close()

	req, err := http.NewRequest("GET", ts.URL, nil)
	if err != nil {
		t.Fatalf("Couldn't build request; Err: %v", err)
	}

	tr := &http.Transport{}
	defer tr.CloseIdleConnections()
	cl := &http.Client{
		Transport: tr,
	}

	// b.ResetTimer()

	// for i := 0; i < b.N; i++ {
	res, err := cl.Do(req)
	if err != nil {
		t.Fatal("Get:", err)
	}
	all, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Fatal("ReadAll:", err)
	}
	if !bytes.Equal(all, msg) {
		t.Fatalf("Got body %q; want %q", all, msg)
	}
	// }
}

func TestValidAuthTokenWithCookies(t *testing.T) {
	opts := []Options{}
	a, authErr := New(opts...)
	a.options.Debug = debug
	if authErr != nil {
		t.Errorf("Failed to build jwt server; Err: %v", authErr)
		return
	}
	a.SetBearerTokens(false)

	ts := httptest.NewServer(a.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(msg)
	})))
	defer ts.Close()

	as := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := ClaimsType{}
		claims.Subject = from(r)

		a.IssueNewTokens(w, &claims)
		fmt.Fprintln(w, "Hello, client")
	}))
	defer as.Close()

	// get credentials
	resp, err := http.Get(as.URL)
	if err != nil {
		t.Errorf("Couldn't send request to test server; Err: %v", err)
	}

	rc := resp.Cookies()
	if len(rc) == 0 {
		t.Errorf("Couldn't get response cookies")
		return
	}
	var authCookieIndex int
	var refreshCookieIndex int

	for i, cookie := range rc {
		if cookie.Name == "AuthToken" {
			authCookieIndex = i
		}
		if cookie.Name == "RefreshToken" {
			refreshCookieIndex = i
		}
	}

	cl := &http.Client{}

	req, err := http.NewRequest("GET", ts.URL, nil)
	if err != nil {
		t.Fatalf("Couldn't build request; Err: %v", err)
	}
	req.AddCookie(rc[authCookieIndex])
	req.AddCookie(rc[refreshCookieIndex])
	req.Header.Add("X-CSRF-Token", resp.Header.Get("X-CSRF-Token"))

	// b.ResetTimer()

	// for i := 0; i < b.N; i++ {
	res, err := cl.Do(req)
	if err != nil {
		t.Fatal("Get:", err)
	}
	all, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Fatal("ReadAll:", err)
	}
	if !bytes.Equal(all, msg) {
		t.Fatalf("Got body %q; want %q", all, msg)
	}
	// }
}

// FAILING
// func TestValidAuthTokenWithBearerTokens(t *testing.T) {
// 	var a Auth
// 	var c credentials
// 	authErr := New(&a, Options{
// 		SigningMethodString: "HS256",
// 		HMACKey: []byte(`#5K+¥¼ƒ~ew{¦Z³(æðTÉ(©„²ÒP.¿ÓûZ’ÒGï–Š´Ãwb="=.!r.OÀÍšõgÐ€£`),
// 		RefreshTokenValidTime: 72 * time.Hour,
// 		AuthTokenValidTime:    15 * time.Minute,
// 		BearerTokens:          true,
// 		Debug:                 false,
// 		IsDevEnv:              true,
// 	})
// 	if authErr != nil {
// 		b.Errorf("Failed to build jwt server; Err: %v", authErr)
// 	}

// 	ts := httptest.NewServer(a.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 		w.Write(msg)
// 	})))
// 	defer ts.Close()

// 	var claims ClaimsType
// 	claims.CustomClaims = make(map[string]interface{})
// 	claims.CustomClaims["Role"] = "user"

// 	err := a.buildCredentialsFromClaims(&c, &claims)
// 	if err != nil {
// 		b.Fatal("Unable to build credentials; Err: %v", err)
// 	}

// 	authTokenString, authStringErr := c.AuthToken.Token.SignedString(a.signKey)
// 	if authStringErr != nil {
// 		b.Fatal("Unable to build credentials; Err: %v", authStringErr)
// 	}
// 	refreshTokenString, refreshStringErr := c.RefreshToken.Token.SignedString(a.signKey)
// 	if refreshStringErr != nil {
// 		b.Fatal("Unable to build credentials; Err: %v", refreshStringErr)
// 	}

// 	// form := url.Values{}
// 	// form.Add("X-Auth-Token", authTokenString)
// 	// form.Add("X-Refresh-Token", refreshTokenString)
// 	// form.Add("X-CSRF-Token", c.CsrfString)
// 	// // log.Println(authTokenString, refreshTokenString, c.CsrfString)

// 	// req, reqErr := http.NewRequest("POST", ts.URL, strings.NewReader(form.Encode()))
// 	// now test json encoded tokens
// 	var jsonStr = []byte(`{"X-Auth-Token":"` + authTokenString + `", "X-Refresh-Token": "` + refreshTokenString + `"}`)
// 	req, reqErr := http.NewRequest("POST", ts.URL, bytes.NewBuffer(jsonStr))
// 	if reqErr != nil {
// 		b.Fatal("Error building request for testing; err: %v", reqErr)
// 	}
// 	req.Header.Add("X-CSRF-Token", c.CsrfString)
// 	req.Header.Set("Content-Type", "application/json")
// 	// req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

// 	tr := &http.Transport{}
// 	defer tr.CloseIdleConnections()
// 	cl := &http.Client{
// 		Transport: tr,
// 	}

// 	b.ResetTimer()

// 	for i := 0; i < b.N; i++ {
// 		res, err := cl.Do(req)
// 		if err != nil {
// 			b.Fatal("Get:", err)
// 		}
// 		all, err := ioutil.ReadAll(res.Body)
// 		if err != nil {
// 			b.Fatal("ReadAll:", err)
// 		}
// 		if !bytes.Equal(all, msg) {
// 			t.Fatalf("Got body %q; want %q", all, msg)
// 		}
// 	}
// }

func TestExpiredAuthTokenWithCookies(t *testing.T) {
	opts := Options{
		RefreshTokenValidTime: 72 * time.Hour,
		AuthTokenValidTime:    1 * time.Second,
	}
	err := DevelOpts(&opts)
	opts.Debug = debug
	if err != nil {
		t.Errorf("Failed to build jwt server; Err: %v", err)
		return
	}
	a, authErr := New(opts)
	if authErr != nil {
		t.Errorf("Failed to build jwt server; Err: %v", authErr)
		return
	}
	a.SetBearerTokens(false)

	ts := httptest.NewServer(a.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(msg)
	})))
	defer ts.Close()

	as := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := ClaimsType{}
		claims.Subject = from(r)

		a.IssueNewTokens(w, &claims)
		fmt.Fprintln(w, "Hello, client")
	}))
	defer as.Close()

	// get credentials
	resp, err := http.Get(as.URL)
	if err != nil {
		t.Errorf("Couldn't send request to test server; Err: %v", err)
	}
	rc := resp.Cookies()
	if len(rc) == 0 {
		t.Errorf("Couldn't get response cookies")
		return
	}
	var authCookieIndex int
	var refreshCookieIndex int

	for i, cookie := range rc {
		if cookie.Name == "AuthToken" {
			authCookieIndex = i
		}
		if cookie.Name == "RefreshToken" {
			refreshCookieIndex = i
		}
	}

	cl := &http.Client{}

	req, err := http.NewRequest("GET", ts.URL, nil)
	if err != nil {
		t.Fatalf("Couldn't build request; Err: %v", err)
	}
	req.AddCookie(rc[authCookieIndex])
	req.AddCookie(rc[refreshCookieIndex])
	req.Header.Add("X-CSRF-Token", resp.Header.Get("X-CSRF-Token"))

	// need to sleep to check expiry time differences
	duration := time.Duration(1100) * time.Millisecond // Pause
	time.Sleep(duration)

	// b.ResetTimer()

	// for i := 0; i < b.N; i++ {
	res, err := cl.Do(req)
	if err != nil {
		t.Fatal("Get:", err)
	}
	all, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Fatal("ReadAll:", err)
	}
	if !bytes.Equal(all, msg) {
		t.Fatalf("Got body %q; want %q", all, msg)
	}
	// }
}

func TestAuthTokenWithHeader(t *testing.T) {
	type datas struct {
		opts   []Options
		cl     *ClaimsType
		bearer bool
		wait   time.Duration
	}
	type args struct {
		token string
		w     http.ResponseWriter
	}
	dev_opts := Options{
		RefreshTokenValidTime: 72 * time.Hour,
		AuthTokenValidTime:    1 * time.Second,
	}
	err := DevelOpts(&dev_opts)
	dev_opts.Debug = debug
	if err != nil {
		t.Errorf("Failed to build jwt server; Err: %v", err)
		return
	}
	tests := []struct {
		name    string
		data    datas
		wantErr bool
	}{
		{
			"Empty/devel options",
			datas{
				[]Options{
					dev_opts,
				},
				&ClaimsType{
					Claims: jwt.Claims{
						Subject: "127.0.0.1",
					},
				},
				true,
				0,
			},
			false,
		},
		{
			"Empty/devel options and empty claims",
			datas{
				[]Options{
					dev_opts,
				},
				&ClaimsType{},
				true,
				0,
			},
			false,
		},
		{
			"Empty/devel options and wrong claims",
			datas{
				[]Options{
					dev_opts,
				},
				&ClaimsType{
					Claims: jwt.Claims{
						Subject: "127.3.2.1",
					},
				},
				true,
				0,
			},
			true,
		},
		{
			"Devel options and bearer tokens",
			datas{
				[]Options{
					dev_opts,
				},
				&ClaimsType{
					Claims: jwt.Claims{
						Subject: "127.0.0.1",
					},
				},
				true,
				time.Duration(1500) * time.Millisecond,
			},
			false,
		},
		{
			"Devel options and cookie tokens",
			datas{
				[]Options{
					dev_opts,
				},
				&ClaimsType{
					Claims: jwt.Claims{
						Subject: "127.0.0.1",
					},
				},
				false,
				time.Duration(1500) * time.Millisecond,
			},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, authErr := New(tt.data.opts...)
			if authErr != nil {
				t.Errorf("Failed to make new Auth; Err: %v", authErr)
				return
			}
			a.SetBearerTokens(tt.data.bearer)
			ts := httptest.NewServer(a.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write(msg)
			})))
			defer ts.Close()

			as := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				a.IssueNewTokens(w, tt.data.cl)
				fmt.Fprintln(w, "Hello, client")
			}))
			defer as.Close()
			// get credentials
			resp, err := http.Get(as.URL)
			if err != nil {
				t.Errorf("Couldn't send request to test server; Err: %v", err)
			}

			cl := &http.Client{}
			req, err := http.NewRequest("GET", ts.URL, nil)
			if err != nil {
				t.Fatalf("Couldn't build request; Err: %v", err)
			}

			if !tt.data.bearer {
				rc := resp.Cookies()
				if len(rc) == 0 {
					t.Errorf("Couldn't get response cookies")
					return
				}
				var authCookieIndex int
				var refreshCookieIndex int

				for i, cookie := range rc {
					if cookie.Name == "AuthToken" {
						authCookieIndex = i
					}
					if cookie.Name == "RefreshToken" {
						refreshCookieIndex = i
					}
				}

				req.AddCookie(rc[authCookieIndex])
				req.AddCookie(rc[refreshCookieIndex])
				req.Header.Add("X-CSRF-Token", resp.Header.Get("X-CSRF-Token"))
			} else {
				if len(resp.Header) == 0 {
					t.Errorf("Couldn't get response headers")
					return
				}

				auth_hdv := resp.Header.Get(a.options.AuthTokenName)
				if auth_hdv == "" {
					t.Errorf("Couldn't get response auth headers")
					return
				}
				refresh_hdv := resp.Header.Get(a.options.RefreshTokenName)
				if refresh_hdv == "" {
					t.Errorf("Couldn't get response refresh headers")
					return
				}

				req.Header.Add(a.options.AuthTokenName, auth_hdv)
				req.Header.Add(a.options.RefreshTokenName, refresh_hdv)
				req.Header.Add("X-CSRF-Token", resp.Header.Get("X-CSRF-Token"))
			}
			// need to sleep to check expiry time differences
			time.Sleep(tt.data.wait)
			res, err := cl.Do(req)
			if err != nil {
				t.Fatal("Get:", err)
			}
			all, err := ioutil.ReadAll(res.Body)
			if err != nil {
				t.Fatal("ReadAll:", err)
			}
			if !bytes.Equal(all, msg) && !tt.wantErr {
				t.Fatalf("Got body %q; want %q", all, msg)
			}
		})
	}
}
