package jwt

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	//"net/url"
	//"strings"
	"github.com/go-chi/chi"
	// "github.com/go-chi/chi/middleware"
	"github.com/urfave/negroni"
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
	opts := []func(o *Options) error{}
	a, authErr := NewAuth(opts...)
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
// 	authErr := NewAuth(&a, Options{
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
	dev_opts := func(o *Options) error {
		o.RefreshTokenValidTime = 72 * time.Hour
		o.AuthTokenValidTime = 1 * time.Second
		o.IsDevEnv = true
		return nil
	}
	a, authErr := NewAuth(dev_opts)
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
		opts   []func(o *Options) error
		cl     *ClaimsType
		bearer bool
		wait   time.Duration
	}
	type args struct {
		token string
		w     http.ResponseWriter
	}
	dev_opts := func(o *Options) error {
		o.RefreshTokenValidTime = 72 * time.Hour
		o.AuthTokenValidTime = 1 * time.Second
		o.IsDevEnv = true
		return nil
	}
	tests := []struct {
		name    string
		data    datas
		wantErr bool
	}{
		{
			"Empty/devel options",
			datas{
				[]func(o *Options) error{
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
				[]func(o *Options) error{
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
				[]func(o *Options) error{
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
				[]func(o *Options) error{
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
				[]func(o *Options) error{
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
			a, authErr := NewAuth(tt.data.opts...)
			if authErr != nil {
				t.Errorf("Failed to make new Auth; Err: %v", authErr)
				return
			}
			a.SetBearerTokens(tt.data.bearer)
			ts := httptest.NewServer(a.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				auth_claims, err := AuthClaims(r)
				if err != nil {
					t.Fatalf("No auth token in request context found, Error: %v", err)
				}
				fmt.Printf("Auth claims ID %#v\n", auth_claims.ID)
				tm, err := TokenTime(auth_claims.ID)
				if err != nil {
					t.Fatalf("Error getting token id time: %v", err)
				}
				fmt.Printf("Auth claims ID time %s\n", tm)
				w.Write(msg)
			})))
			defer ts.Close()

			as := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				a.IssueNewTokens(w, tt.data.cl)
				fmt.Fprintln(w, "Hello, client")
			}))
			defer as.Close()

			testServer(as.URL, ts.URL, a.options.AuthTokenName, a.options.RefreshTokenName,
				tt.data.bearer, tt.data.wait, tt.wantErr, t)
		})
	}
}

func TestAuthMiddlewareNegroni(t *testing.T) {
	type datas struct {
		opts   []func(o *Options) error
		cl     *ClaimsType
		bearer bool
		wait   time.Duration
	}
	type args struct {
		token string
		w     http.ResponseWriter
	}
	signVerify, err := generateRandomBytes(32)
	if err != nil {
		t.Fatalf("Couldn't generate sign/verify key, Error: %v", err)
	}
	tests := []struct {
		name    string
		data    datas
		wantErr bool
	}{
		{
			"Empty/devel options",
			datas{
				[]func(o *Options) error{
					func(o *Options) error {
						o.IsDevEnv = true
						o.BearerTokens = true
						o.SignKey = signVerify
						o.VerifyKey = signVerify
						o.EncryptKey = signVerify
						o.DecryptKey = signVerify
						return nil
					},
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, authErr := NewAuth(tt.data.opts...)
			if authErr != nil {
				t.Errorf("Failed to make new Auth; Err: %v", authErr)
				return
			}
			// a.SetBearerTokens(tt.data.bearer)
			n := negroni.New()
			n.UseFunc(JwtAuthFunc(tt.data.opts...))
			n.UseHandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// fmt.Printf("Start handler")
				auth_claims, err := AuthClaims(r)
				if err != nil {
					t.Fatalf("No auth token in request context found, Error: %v", err)
				}
				fmt.Printf("Auth claims ID %#v\n", auth_claims.ID)
				tm, err := TokenTime(auth_claims.ID)
				if err != nil {
					t.Fatalf("Error getting token id time: %v", err)
				}
				fmt.Printf("Auth claims ID time %s\n", tm)
				// fmt.Printf("Write message")
				w.Write(msg)
			})
			ts := httptest.NewServer(n)
			defer ts.Close()

			as := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				a.IssueNewTokens(w, tt.data.cl)
				fmt.Fprintln(w, "Hello, client")
			}))
			defer as.Close()

			testServer(as.URL, ts.URL, a.options.AuthTokenName, a.options.RefreshTokenName,
				tt.data.bearer, tt.data.wait, tt.wantErr, t)
		})
	}
}

func TestAuthMiddlewareChi(t *testing.T) {
	type datas struct {
		opts   []func(o *Options) error
		cl     *ClaimsType
		bearer bool
		wait   time.Duration
	}
	signVerify, err := generateRandomBytes(32)
	if err != nil {
		t.Fatalf("Couldn't generate sign/verify key, Error: %v", err)
	}
	tests := []struct {
		name    string
		data    datas
		wantErr bool
	}{
		{
			"Empty/devel options",
			datas{
				[]func(o *Options) error{
					func(o *Options) error {
						o.IsDevEnv = true
						o.BearerTokens = true
						o.SignKey = signVerify
						o.VerifyKey = signVerify
						o.EncryptKey = signVerify
						o.DecryptKey = signVerify
						return nil
					},
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, authErr := NewAuth(tt.data.opts...)
			if authErr != nil {
				t.Errorf("Failed to make new Auth; Err: %v", authErr)
				return
			}
			// a.SetBearerTokens(tt.data.bearer)
			r := chi.NewRouter()
			r.Use(MidOne)
			r.Use(MidTwo)
			r.Use(JwtAuth(tt.data.opts...))
			r.Get("/", func(w http.ResponseWriter, r *http.Request) {
				fmt.Println("Start handler")
				auth_claims, err := AuthClaims(r)
				if err != nil {
					t.Fatalf("No auth token in request context found, Error: %v", err)
				}
				fmt.Printf("Auth claims ID %#v\n", auth_claims.ID)
				tm, err := TokenTime(auth_claims.ID)
				if err != nil {
					t.Fatalf("Error getting token id time: %v", err)
				}
				fmt.Printf("Auth claims ID time %s\n", tm)
				// fmt.Printf("Write message")
				w.Write(msg)
			})
			ts := httptest.NewServer(r)
			defer ts.Close()
			as := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				a.IssueNewTokens(w, tt.data.cl)
				fmt.Fprintln(w, "Hello, client")
			}))
			defer as.Close()
			testServer(as.URL, ts.URL, a.options.AuthTokenName, a.options.RefreshTokenName,
				tt.data.bearer, tt.data.wait, tt.wantErr, t)
		})
	}
}

func testServer(authUrl, tokenUrl, AuthTokenName, RefreshTokenName string,
	bearer bool, wait time.Duration, wantErr bool, t *testing.T) {
	// get credentials
	resp, err := http.Get(authUrl)
	if err != nil {
		t.Errorf("Couldn't send request to test server; Err: %v", err)
	}

	cl := &http.Client{}
	req, err := http.NewRequest("GET", tokenUrl, nil)
	if err != nil {
		t.Fatalf("Couldn't build request; Err: %v", err)
	}
	if !bearer {
		rc := resp.Cookies()
		// fmt.Printf("resp Cookies: %#v\n", rc)
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
		// fmt.Printf("resp Headers: %#v\n", resp.Header)

		auth_hdv := resp.Header.Get(AuthTokenName)
		if auth_hdv == "" {
			t.Errorf("Couldn't get response auth headers")
			return
		}
		refresh_hdv := resp.Header.Get(RefreshTokenName)
		if refresh_hdv == "" {
			t.Errorf("Couldn't get response refresh headers")
			return
		}

		req.Header.Add(AuthTokenName, auth_hdv)
		req.Header.Add(RefreshTokenName, refresh_hdv)
		req.Header.Add("X-CSRF-Token", resp.Header.Get("X-CSRF-Token"))
	}
	// need to sleep to check expiry time differences
	time.Sleep(wait)
	res, err := cl.Do(req)
	if err != nil {
		t.Fatal("Get:", err)
	}
	all, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Fatal("ReadAll:", err)
	}
	if !bytes.Equal(all, msg) && !wantErr {
		t.Fatalf("Got body %q; want %q", all, msg)
	}
}

func MidOne(h http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("MidOne")
		h.ServeHTTP(w, r)
	}

	return http.HandlerFunc(fn)
}
func MidTwo(h http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("MidTwo")
		h.ServeHTTP(w, r)
	}

	return http.HandlerFunc(fn)
}
