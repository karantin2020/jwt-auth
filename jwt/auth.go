package jwt

import (
	"github.com/pkg/errors"
	"log"
	"net/http"
	"time"
)

// Auth is a struct that provides jwt based authentication.
type Auth struct {
	authStore    *jwtStore
	refreshStore *jwtStore
	csrfStore    *mixStore

	options Options

	// Handlers for when an error occurs
	errorHandler        http.Handler
	unauthorizedHandler http.Handler

	// funcs for verifiing and revoking tokens
	revokeTokenByID    TokenRevoker
	checkTokenId       TokenIdChecker
	getTokenId         TokenIdGetter
	verifyAuthToken    func(r *http.Request) error
	verifyRefreshToken func(r *http.Request) error
}

const (
	defaultRefreshTokenValidTime  = 72 * time.Hour
	defaultAuthTokenValidTime     = 10 * time.Minute
	defaultBearerAuthTokenName    = "X-Auth-Token"
	defaultBearerRefreshTokenName = "X-Refresh-Token"
	defaultCSRFTokenName          = "X-CSRF-Token"
	defaultCookieAuthTokenName    = "AuthToken"
	defaultCookieRefreshTokenName = "RefreshToken"
	authTokenKey                  = "jwtAuth.jwt.auth.Token"
)

// CSRF token length in bytes.
const tokenLength = 32

const (
	AuthToken    = 0
	RefreshToken = 1
)

type AuthTokens struct {
	Bearer       bool
	AuthToken    string
	RefreshToken string
	CSRFToken    string
}

var (
	UnauthorizedRequest = errors.New("Unauthorized Request")
)

func defaultTokenRevoker(tokenId string) error {
	return nil
}

// TokenRevoker : a type to revoke tokens
type TokenRevoker func(tokenId string) error

func defaultCheckTokenId(tokenId string) bool {
	// return true if the token id is valid (has not been revoked). False otherwise
	return true
}

// TokenIdChecker : a type to check tokens
type TokenIdChecker func(tokenId string) bool

func defaultGetTokenId() string {
	// return empty string
	return NewTokenId()
}

// TokenIdGetter : a type to get token ids
type TokenIdGetter func() string

func defaultErrorHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Internal Server Error", 500)
	return
}

func defaultUnauthorizedHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Unauthorized", 401)
	return
}

// New constructs a new Auth instance with supplied options.
func NewAuth(fopts ...func(o *Options) error) (*Auth, error) {
	var opts Options
	for _, fn := range fopts {
		err := fn(&opts)
		if err != nil {
			return nil, errors.Wrap(err, "Error init auth options")
		}
	}

	if opts.IsDevEnv || len(fopts) == 0 {
		err := DevelOpts(&opts)
		if err != nil {
			return nil, errors.Wrap(err, "Error init development options")
		}
	} else {
		err := DefOpts(&opts)
		if err != nil {
			return nil, errors.Wrap(err, "Error init default auth options")
		}
	}

	auth := &Auth{}
	err := auth.setOptions(&opts)
	if err != nil {
		return nil, errors.Wrap(err, "Error setting auth options")
	}
	return auth, nil
}

func (a *Auth) setOptions(o *Options) error {
	aus, err := NewJWTStore(o, o.AuthTokenName, AuthToken, false)
	if err != nil {
		return errors.Wrap(err, "Error creating auth store")
	}
	a.authStore = aus
	rs, err := NewJWTStore(o, o.RefreshTokenName, RefreshToken, true)
	if err != nil {
		return errors.Wrap(err, "Error creating refresh store")
	}
	a.refreshStore = rs
	a.csrfStore = &mixStore{o.CSRFTokenName}

	a.options = *o

	a.errorHandler = http.HandlerFunc(defaultErrorHandler)
	a.unauthorizedHandler = http.HandlerFunc(defaultUnauthorizedHandler)
	a.revokeTokenByID = defaultTokenRevoker
	a.checkTokenId = defaultCheckTokenId
	a.getTokenId = defaultGetTokenId
	// a.verifyAuthToken = defaultValidator
	// a.verifyRefreshToken = defaultValidator
	return nil
}

// SetErrorHandler : add methods to allow the changing of default functions
func (a *Auth) SetErrorHandler(handler http.Handler) {
	a.errorHandler = handler
}

// SetUnauthorizedHandler : set the 401 handler
func (a *Auth) SetUnauthorizedHandler(handler http.Handler) {
	a.unauthorizedHandler = handler
}

// SetRevokeTokenFunction : set the function which revokes a token
func (a *Auth) SetRevokeTokenFunction(revoker TokenRevoker) {
	a.revokeTokenByID = revoker
}

// SetCheckTokenIdFunction : set the function which checks token id's
func (a *Auth) SetCheckTokenIdFunction(checker TokenIdChecker) {
	a.checkTokenId = checker
}

func (a *Auth) SetVerifyAuthFunction(fn func(r *http.Request) error) {
	a.verifyAuthToken = fn
}

func (a *Auth) SetVerifyRefreshFunction(fn func(r *http.Request) error) {
	a.verifyRefreshToken = fn
}

func (a *Auth) SetBearerTokens(bt bool) error {
	if a.authStore == nil || a.refreshStore == nil {
		return errors.New("Auth.SetBearerTokens error: token store is not initialized")
	}
	a.options.BearerTokens = bt
	a.authStore.bearerTokens = bt
	a.refreshStore.bearerTokens = bt
	var authName, refreshName string
	if bt {
		authName = defaultBearerAuthTokenName
		refreshName = defaultBearerRefreshTokenName
	} else {
		authName = defaultCookieAuthTokenName
		refreshName = defaultCookieRefreshTokenName
	}
	a.options.AuthTokenName = authName
	a.options.RefreshTokenName = refreshName
	a.authStore.tokenName = authName
	a.authStore.cookieStore.name = authName
	a.refreshStore.tokenName = refreshName
	a.refreshStore.cookieStore.name = refreshName
	return nil
}

func JwtAuth(fopts ...func(o *Options) error) func(next http.Handler) http.Handler {
	a, authErr := NewAuth(fopts...)
	if authErr != nil {
		panic("Failed to init new JwtAuth middleware; Err: " + authErr.Error())
	}
	return a.Handler
}

// Handler implements the http.HandlerFunc for integration with the standard net/http lib.
func (a *Auth) Handler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// if next handler is nil then raise an error
		a.pkgLog("Auth JWT middleware")
		if h == nil {
			a.errorHandler.ServeHTTP(w, r)
			return
		}

		// Process the request. If it returns an error,
		// that indicates the request should not continue.
		auth_token, err := a.Process(w, r)

		// If there was an error, do not continue.
		if err != nil {
			if auth_token != nil {
				a.NullifyTokens(auth_token.ID, w)
			}
			if err == UnauthorizedRequest {
				a.pkgLog("Unauthorized processing\n")
				a.unauthorizedHandler.ServeHTTP(w, r)
				return
			}
			a.pkgLog("Error processing\n")
			a.pkgLog("%#v\n", err)
			a.errorHandler.ServeHTTP(w, r)
			return
		}
		if auth_token != nil {
			r = contextSave(r, authTokenKey, auth_token)
		}
		h.ServeHTTP(w, r)
	})
}

// HandlerFunc works identically to Handler, but takes a HandlerFunc instead of a Handler.
func (a *Auth) HandlerFunc(fn http.HandlerFunc) http.Handler {
	if fn == nil {
		return a.Handler(nil)
	}
	return a.Handler(fn)
}

func JwtAuthFunc(fopts ...func(o *Options) error) func(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	a, authErr := NewAuth(fopts...)
	if authErr != nil {
		panic("Failed to init new JwtAuth middleware; Err: " + authErr.Error())
	}
	return a.HandlerFuncWithNext
}

// HandlerFuncWithNext is a special implementation for Negroni, but could be used elsewhere.
func (a *Auth) HandlerFuncWithNext(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	if next == nil {
		a.errorHandler.ServeHTTP(w, r)
		return
	}

	auth_token, err := a.Process(w, r)

	if err != nil {
		if auth_token != nil {
			a.NullifyTokens(auth_token.ID, w)
		}
		if err == UnauthorizedRequest {
			a.unauthorizedHandler.ServeHTTP(w, r)
			return
		}
		a.errorHandler.ServeHTTP(w, r)
		return
	}

	if auth_token != nil {
		r = contextSave(r, authTokenKey, auth_token)
	}

	// If there was an error, do not call next.
	next(w, r)

}

// Process runs the actual checks and returns an error if the middleware chain should stop.
func (a *Auth) Process(w http.ResponseWriter, r *http.Request) (*ClaimsType, error) {
	// cookies aren't included with options, so simply pass through
	if r.Method == "OPTIONS" {
		return nil, nil
	}

	// grab the credentials from the request
	var c credentials
	if err := a.getCredentials(r, &c); err != nil {
		a.pkgLog("Invalid credentials, Err: %#v\n", err)
		return nil, UnauthorizedRequest
	}
	// a.pkgLog("%#v\n", c.AuthToken)

	// // check the credential's validity; updating expiry's if necessary and/or allowed
	if err := c.Validate(r); err != nil {
		if err == AuthTokenExpired {
			a.pkgLog("Auth token is expired. Renew Auth token\n")
			err = c.RenewAuthToken(r)
			if err != nil {
				a.pkgLog("Error renew auth token, Err: %#v\n", err)
				return c.AuthToken, UnauthorizedRequest
			}
			return c.AuthToken, nil
		}
		return c.AuthToken, UnauthorizedRequest
	}
	a.pkgLog("Auth token is not expired. Process...\n")

	// // if we've made it this far, everything is valid!
	// // And tokens have been refreshed if need-be
	if !a.options.VerifyOnlyServer {
		if err := a.setCredentials(w, &c); err != nil {
			return c.AuthToken, errors.Wrap(err, "Error setting credentials")
		}
	}
	return c.AuthToken, nil
}

// IssueNewTokens : and also modify create refresh and auth token functions!
func (a *Auth) IssueNewTokens(w http.ResponseWriter, claims *ClaimsType) error {
	if a.options.VerifyOnlyServer {
		return errors.New("Auth.IssueNewTokens: Server is not authorized to issue new tokens")

	}

	var c credentials
	err := a.newCredentials(&c, claims)
	if err != nil {
		return errors.Wrap(err, "Error creating new credentials")
	}
	// fmt.Printf("%#v\n", c.AuthToken)
	// fmt.Printf("%#v\n", c.RefreshToken)

	err = a.setCredentials(w, &c)
	if err != nil {
		return errors.Wrap(err, "Error setting credentials")
	}

	return nil
}

// NullifyTokens : invalidate tokens
// note @adam-hanna: what if there are no credentials in the request?
func (a *Auth) NullifyTokens(tokenID string, w http.ResponseWriter) error {
	a.authStore.Revoke(w)
	a.refreshStore.Revoke(w)
	a.csrfStore.Save("", w)

	err := a.revokeTokenByID(tokenID)
	if err != nil {
		return errors.Wrap(err, "Auth.NullifyTokens: Error revoking token")
	}

	return nil
}

// GrabTokenClaims : extract the claims from the request
// note: we always grab from the authToken
func (a *Auth) GrabTokenClaims(r *http.Request) (*ClaimsType, error) {
	ca, err := a.authStore.Get(r)
	if err != nil {
		return nil, errors.Wrap(err, "Auth.GrabTokenClaims: Error getting auth claims")
	}

	return ca, nil
}

func (c *Auth) pkgLog(format string, v ...interface{}) {
	if c.options.Debug {
		log.Printf(format, v...)
	}
}
