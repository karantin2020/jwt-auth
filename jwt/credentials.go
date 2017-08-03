package jwt

import (
	// "fmt"
	"net"
	"net/http"
	"time"

	"github.com/mohae/deepcopy"
	"github.com/pkg/errors"
	jose "gopkg.in/square/go-jose.v2"
	jwt "gopkg.in/square/go-jose.v2/jwt"
)

type credentials struct {
	CsrfString string

	AuthToken    *ClaimsType
	RefreshToken *ClaimsType

	csrfEncrypter jose.Encrypter

	options credentialsOptions
}

type credentialsOptions struct {
	authTokenValidTime    time.Duration
	refreshTokenValidTime time.Duration

	checkTokenId TokenIdChecker

	verifyAuthToken    func(a *Auth, r *http.Request) error
	verifyRefreshToken func(a *Auth, r *http.Request) error

	verifyOnlyServer bool

	debug bool
}

var (
	AuthTokenNotValid    = errors.New("Auth jwt token is not valid")
	RefreshTokenNotValid = errors.New("Refresh jwt token is not valid")
	AuthTokenExpired     = errors.New("Auth jwt token is expired")
	RefreshTokenExpired  = errors.New("Refresh jwt token is expired")
)

func (a *Auth) getCredentials(r *http.Request, c *credentials) error {
	if c == nil {
		return errors.New("Auth.getCredentials: Credentials pointer is nil")
	}
	ca, err := a.authStore.Get(r)
	if err != nil {
		return errors.Wrap(err, "Auth.getCredentials: Error get auth claims")
	}
	c.AuthToken = ca
	cr, err := a.refreshStore.Get(r)
	if err != nil {
		return errors.Wrap(err, "Auth.getCredentials: Error get refresh claims")
	}
	c.RefreshToken = cr
	cs, err := a.csrfStore.Get(r)
	if err != nil {
		return errors.Wrap(err, "Auth.getCredentials: Error get csrf string")
	}
	c.CsrfString = cs

	c.options = credentialsOptions{
		authTokenValidTime:    a.options.AuthTokenValidTime,
		refreshTokenValidTime: a.options.RefreshTokenValidTime,
		checkTokenId:          a.checkTokenId,
		verifyAuthToken:       a.verifyAuthToken,
		verifyRefreshToken:    a.verifyRefreshToken,
		verifyOnlyServer:      a.options.VerifyOnlyServer,
		debug:                 a.options.Debug,
	}

	return nil
}

func (a *Auth) newCredentials(c *credentials, claims *ClaimsType) error {
	newCsrfString, err := GenerateNewCsrfString()
	if err != nil {
		return errors.Wrap(err, "Error generating new csrf string")
	}
	c.CsrfString = newCsrfString
	c.csrfEncrypter = a.csrfEncrypter

	c.options.authTokenValidTime = a.options.AuthTokenValidTime
	c.options.refreshTokenValidTime = a.options.RefreshTokenValidTime
	c.options.checkTokenId = a.checkTokenId
	c.options.verifyOnlyServer = a.options.VerifyOnlyServer
	c.options.debug = a.options.Debug

	tokenId := a.getTokenId()

	if claims == nil {
		c.AuthToken = &ClaimsType{}
		c.RefreshToken = &ClaimsType{}
	} else {
		authClaims := deepcopy.Copy(claims)
		c.AuthToken = authClaims.(*ClaimsType)
		refreshClaims := deepcopy.Copy(claims)
		c.RefreshToken = refreshClaims.(*ClaimsType)
	}
	encCsrf, err := c.csrfEncrypter.Encrypt([]byte(newCsrfString))
	if err != nil {
		return errors.Wrap(err, "Error encrypt csrf string")
	}
	encoded, err := encCsrf.CompactSerialize()
	if err != nil {
		return errors.Wrap(err, "Error encrypt csrf string")
	}
	c.AuthToken.ID = tokenId
	c.AuthToken.Csrf = encoded
	c.AuthToken.Expiry = jwt.NewNumericDate(time.Now().UTC().Add(a.options.AuthTokenValidTime))
	c.AuthToken.NotBefore = jwt.NewNumericDate(time.Now().UTC())
	c.AuthToken.IssuedAt = jwt.NewNumericDate(time.Now().UTC())

	c.RefreshToken.ID = tokenId
	c.RefreshToken.Csrf = newCsrfString
	c.RefreshToken.Expiry = jwt.NewNumericDate(time.Now().UTC().Add(a.options.RefreshTokenValidTime))
	c.RefreshToken.NotBefore = jwt.NewNumericDate(time.Now().UTC())
	c.RefreshToken.IssuedAt = jwt.NewNumericDate(time.Now().UTC())

	return nil
}

func (a *Auth) setCredentials(w http.ResponseWriter, c *credentials) error {
	err := a.authStore.Save(c.AuthToken, w)
	if err != nil {
		return errors.Wrap(err, "Error save auth JWT claims")
	}
	err = a.refreshStore.Save(c.RefreshToken, w)
	if err != nil {
		return errors.Wrap(err, "Error save refresh JWT claims")
	}
	err = a.csrfStore.Save(c.CsrfString, w)
	if err != nil {
		return errors.Wrap(err, "Error save scrf token")
	}
	return nil
}

func (c *credentials) Validate(a *Auth, r *http.Request) error {
	err := c.validateCsrf()
	if err != nil {
		return errors.Wrap(err, "credentials.Validate: Error validate csrf string")
	}
	if c.AuthToken.ID != c.RefreshToken.ID || !c.options.checkTokenId(c.AuthToken.ID) {
		return errors.New("credentials.Validate: Tokens ID is not valid")
	}
	err = c.AuthToken.Validate(a, r)
	if err != nil {
		return AuthTokenExpired
	}

	return nil
}

// func (c *credentials) Update(r *http.Request) error {
// 	return nil
// }

func (c *credentials) validateCsrf() error {
	// note @adam-hanna: check csrf in refresh token? Careful! These tokens are
	// 									 coming from a request, and the csrf in the credential may have been
	//								   updated!
	if c.CsrfString != c.AuthToken.Csrf {
		return errors.New("credentials.validateCsrf: CSRF token doesn't match value in auth token")
	}
	if c.CsrfString != c.RefreshToken.Csrf {
		return errors.New("credentials.validateCsrf: CSRF token doesn't match value in refresh token")
	}

	return nil
}

// func (c *credentials) defaultValidator(r *http.Request) error {
// 	u := r.URL
// 	err := c.AuthToken.Validate(jwt.Expected{
// 		Issuer:  u.Host,
// 		Subject: from(r),
// 		Time:    time.Now().UTC(),
// 	})
// 	return err
// }

func (c *credentials) RenewAuthToken(a *Auth, r *http.Request) error {
	if !c.options.checkTokenId(c.RefreshToken.ID) {
		return errors.New("Refresh token is not valid")
	}
	err := c.RefreshToken.Validate(a, r)
	if err != nil {
		return RefreshTokenNotValid
	}
	// nope, the refresh token has not expired
	// issue a new tokens with a new csrf and update all expiries
	newCsrfString, err := GenerateNewCsrfString()
	if err != nil {
		return errors.Wrap(err, "Error generate csrf string")
	}

	c.CsrfString = newCsrfString

	err = c.updateExpiryAndCsrf(newCsrfString)
	if err != nil {
		return errors.Wrap(err, "Error update csrf and expiry")
	}
	return nil
}

// from makes a best effort to compute the request client IP.
func from(req *http.Request) string {
	if f := req.Header.Get("X-Forwarded-For"); f != "" {
		return f
	}
	f := req.RemoteAddr
	ip, _, err := net.SplitHostPort(f)
	if err != nil {
		return f
	}
	return ip
}

func (c *credentials) updateExpiryAndCsrf(newCsrfString string) error {
	c.AuthToken.Expiry = jwt.NewNumericDate(time.Now().UTC().Add(c.options.authTokenValidTime))
	c.RefreshToken.Expiry = jwt.NewNumericDate(time.Now().UTC().Add(c.options.refreshTokenValidTime))
	encCsrf, err := c.csrfEncrypter.Encrypt([]byte(newCsrfString))
	if err != nil {
		return errors.Wrap(err, "Error encrypt csrf string")
	}
	encoded, err := encCsrf.CompactSerialize()
	if err != nil {
		return errors.Wrap(err, "Error encrypt csrf string")
	}
	c.AuthToken.Csrf = encoded
	c.RefreshToken.Csrf = newCsrfString
	return nil
}
