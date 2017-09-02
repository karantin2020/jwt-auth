package jwt

import (
	// "fmt"
	"net"
	"net/http"
	"time"

	"github.com/mohae/deepcopy"
	"github.com/pkg/errors"
	// jose "gopkg.in/square/go-jose.v2"
	jwt "gopkg.in/square/go-jose.v2/jwt"
)

type credentials struct {
	AuthToken    *ClaimsType
	RefreshToken *ClaimsType

	verifyAuthToken    func(r *http.Request) error
	verifyRefreshToken func(r *http.Request) error

	options credentialsOptions
}

type credentialsOptions struct {
	authTokenValidTime    time.Duration
	refreshTokenValidTime time.Duration

	checkTokenId TokenIdChecker

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

	c.verifyAuthToken = a.verifyAuthToken
	c.verifyRefreshToken = a.verifyRefreshToken

	c.options = credentialsOptions{
		authTokenValidTime:    a.options.AuthTokenValidTime,
		refreshTokenValidTime: a.options.RefreshTokenValidTime,
		checkTokenId:          a.checkTokenId,
		verifyOnlyServer:      a.options.VerifyOnlyServer,
		debug:                 a.options.Debug,
	}

	return nil
}

func (a *Auth) newCredentials(c *credentials, claims *ClaimsType) error {
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
	c.AuthToken.ID = tokenId
	if int64(c.AuthToken.Expiry) == 0 {
		c.AuthToken.Expiry = jwt.NewNumericDate(time.Now().UTC().Add(a.options.AuthTokenValidTime))
	}
	if int64(c.AuthToken.NotBefore) == 0 {
		c.AuthToken.NotBefore = jwt.NewNumericDate(time.Now().UTC())
	}
	if int64(c.AuthToken.IssuedAt) == 0 {
		c.AuthToken.IssuedAt = jwt.NewNumericDate(time.Now().UTC())
	}

	c.RefreshToken.ID = tokenId
	if int64(c.RefreshToken.Expiry) == 0 {
		c.RefreshToken.Expiry = jwt.NewNumericDate(time.Now().UTC().Add(a.options.RefreshTokenValidTime))
	}
	if int64(c.RefreshToken.NotBefore) == 0 {
		c.RefreshToken.NotBefore = jwt.NewNumericDate(time.Now().UTC())
	}
	if int64(c.RefreshToken.IssuedAt) == 0 {
		c.RefreshToken.IssuedAt = jwt.NewNumericDate(time.Now().UTC())
	}

	return nil
}

func (a *Auth) setCredentials(w http.ResponseWriter, c *credentials) error {
	if c.AuthToken == nil || c.RefreshToken == nil {
		return errors.New("Auth.setCredentials error: nil pointer AuthToken or RefreshToken")
	}
	if a.authStore == nil || a.refreshStore == nil {
		return errors.New("Auth.setCredentials error: nil pointer authStore or refreshStore")
	}
	err := a.authStore.Save(c.AuthToken, w)
	if err != nil {
		return errors.Wrap(err, "Error save auth JWT claims")
	}
	err = a.refreshStore.Save(c.RefreshToken, w)
	if err != nil {
		return errors.Wrap(err, "Error save refresh JWT claims")
	}
	return nil
}

func (c *credentials) Validate(r *http.Request) error {
	if c.AuthToken.ID != c.RefreshToken.ID || !c.options.checkTokenId(c.AuthToken.ID) {
		return errors.New("credentials.Validate: Tokens ID is not valid")
	}
	err := c.AuthToken.Validate(r)
	if err != nil {
		if err == jwt.ErrExpired {
			return AuthTokenExpired
		} else {
			return AuthTokenNotValid
		}
	}
	if c.verifyAuthToken != nil {
		err = c.verifyAuthToken(r)
		if err != nil {
			return AuthTokenNotValid
		}
	}

	return nil
}

func (c *credentials) RenewAuthToken(r *http.Request) error {
	if !c.options.checkTokenId(c.RefreshToken.ID) {
		return errors.New("Refresh token is not valid")
	}
	err := c.RefreshToken.Validate(r)
	if err != nil {
		return errors.Wrap(err, "RenewAuthToken error: validate refresh token")
	}
	if c.verifyRefreshToken != nil {
		err = c.verifyRefreshToken(r)
		if err != nil {
			return errors.Wrap(err, "RenewAuthToken error: validate refresh token")
		}
	}

	err = c.updateExpiry()
	if err != nil {
		return errors.Wrap(err, "Error update expiry")
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

func (c *credentials) updateExpiry() error {
	c.AuthToken.Expiry = jwt.NewNumericDate(time.Now().UTC().Add(c.options.authTokenValidTime))
	c.RefreshToken.Expiry = jwt.NewNumericDate(time.Now().UTC().Add(c.options.refreshTokenValidTime))
	return nil
}
