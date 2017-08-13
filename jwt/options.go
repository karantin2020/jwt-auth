package jwt

import (
	// "io/ioutil"
	// "net/http"
	// "reflect"
	// "strconv"
	"time"

	"github.com/pkg/errors"
	jose "gopkg.in/square/go-jose.v2"
	// jwt "gopkg.in/square/go-jose.v2/jwt"
)

// Options is a struct for specifying configuration options
type Options struct {
	SigningMethodString string
	EncryptMethodString string
	SignKey             interface{}
	VerifyKey           interface{}
	EncryptKey          interface{}
	DecryptKey          interface{}
	// CsrfEncryptKey        []byte
	VerifyOnlyServer      bool
	BearerTokens          bool
	AuthCookieForJS       bool // Set HttpOnly auth cookie property to false. Enable js parsing of jwt
	RefreshTokenValidTime time.Duration
	AuthTokenValidTime    time.Duration
	AuthTokenName         string
	RefreshTokenName      string
	CSRFTokenName         string
	RevokeRefreshToken    TokenRevoker
	Path                  string
	Domain                string
	Debug                 bool
	IsDevEnv              bool
}

var DefaultOptions = Options{
	SigningMethodString:   string(jose.HS256),
	EncryptMethodString:   string(jose.A256GCM),
	RefreshTokenValidTime: defaultRefreshTokenValidTime,
	AuthTokenValidTime:    defaultAuthTokenValidTime,
	AuthTokenName:         defaultCookieAuthTokenName,
	RefreshTokenName:      defaultCookieRefreshTokenName,
	CSRFTokenName:         defaultCSRFTokenName,
	Debug:                 true,
	IsDevEnv:              true,
}

func DefOpts(o *Options) error {
	if o.SigningMethodString == "" {
		o.SigningMethodString = string(jose.HS256)
	}
	if o.EncryptMethodString == "" {
		o.EncryptMethodString = string(jose.A256GCM)
	}
	if o.RefreshTokenValidTime == 0 {
		o.RefreshTokenValidTime = defaultRefreshTokenValidTime
	}
	if o.AuthTokenValidTime == 0 {
		o.AuthTokenValidTime = defaultAuthTokenValidTime
	}
	if o.AuthTokenName == "" {
		o.AuthTokenName = defaultCookieAuthTokenName
	}
	if o.RefreshTokenName == "" {
		o.RefreshTokenName = defaultCookieRefreshTokenName
	}
	if o.CSRFTokenName == "" {
		o.CSRFTokenName = defaultCSRFTokenName
	}
	if o.SignKey == nil || o.VerifyKey == nil {
		return errors.New("SignKey and VerifyKey must be defined")
	}
	if o.EncryptKey == nil || o.DecryptKey == nil {
		return errors.New("EncryptKey and DecryptKey must be defined")
	}
	// if o.CsrfEncryptKey == nil {
	// 	return errors.New("CsrfEncryptKey must be defined")
	// }
	if o.Path == "" || o.Domain == "" {
		return errors.New("Cookie Path and Domain must be defined")
	}
	return nil
}

func DevelOpts(o *Options) error {
	DefOpts(o)
	o.AuthTokenName = defaultBearerAuthTokenName
	o.RefreshTokenName = defaultBearerRefreshTokenName
	if o.SignKey == nil || o.VerifyKey == nil {
		sv, err := generateRandomBytes(32)
		if err != nil {
			return errors.Wrap(err, "Error generating sign/verify key")
		}
		o.SignKey = sv
		o.VerifyKey = sv
	}
	if o.EncryptKey == nil || o.DecryptKey == nil {
		ed, err := generateRandomBytes(32)
		if err != nil {
			return errors.Wrap(err, "Error generating encrypt/decrypt key")
		}
		o.EncryptKey = ed
		o.DecryptKey = ed
	}
	// if o.CsrfEncryptKey == nil {
	// 	ck, err := generateRandomBytes(32)
	// 	if err != nil {
	// 		return errors.Wrap(err, "Error generating csrfEncrypt key")
	// 	}
	// 	o.CsrfEncryptKey = ck
	// }
	o.VerifyOnlyServer = false
	o.Path = "/"
	o.Domain = "localhost"
	o.BearerTokens = true
	o.Debug = true
	// repeat here to init default empty development options
	o.IsDevEnv = true
	return nil
}
