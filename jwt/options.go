package jwt

import (
	"io/ioutil"
	"time"

	"github.com/pkg/errors"
	jose "gopkg.in/square/go-jose.v2"
)

// Options is a struct for specifying configuration options
type Options struct {
	SigningMethodString string
	EncryptMethodString string
	PrivateKeyLocation  string
	PublicKeyLocation   string
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
	if (o.SignKey == nil && !o.VerifyOnlyServer) || o.VerifyKey == nil {
		// create the sign and verify keys
		signKey, verifyKey, err := o.buildSignAndVerifyKeys()
		if err != nil {
			return errors.Wrap(err, "Error buildSignAndVerifyKeys")
		}
		o.SignKey = signKey
		o.VerifyKey = verifyKey
	}
	if (o.DecryptKey == nil && !o.VerifyOnlyServer) || o.EncryptKey == nil {
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
	sd, err := generateRandomBytes(32)
	if err != nil {
		return errors.Wrap(err, "Error generating encrypt/decrypt key")
	}
	if (o.SignKey == nil && !o.VerifyOnlyServer) || o.VerifyKey == nil {
		o.SignKey = sd
		o.VerifyKey = sd
	}
	if (o.DecryptKey == nil && !o.VerifyOnlyServer) || o.EncryptKey == nil {
		o.EncryptKey = sd
		o.DecryptKey = sd
	}
	// o.VerifyOnlyServer = false // False by default
	o.Path = "/"
	o.Domain = "localhost"
	o.BearerTokens = true
	o.Debug = true
	// repeat here to init default empty development options
	o.IsDevEnv = true
	return nil
}

func (o *Options) buildSignAndVerifyKeys() (signKey interface{}, verifyKey interface{}, err error) {
	if o.SigningMethodString == "HS256" || o.SigningMethodString == "HS384" || o.SigningMethodString == "HS512" {
		return o.buildHMACKeys()

	} else if o.SigningMethodString == "RS256" || o.SigningMethodString == "RS384" || o.SigningMethodString == "RS512" {
		return o.buildRSAKeys()

	} else if o.SigningMethodString == "ES256" || o.SigningMethodString == "ES384" || o.SigningMethodString == "ES512" {
		return o.buildESKeys()

	}

	err = errors.New("Signing method string not recognized!")
	return
}

func (o *Options) buildHMACKeys() (signKey interface{}, verifyKey interface{}, err error) {
	if !o.VerifyOnlyServer {
		signKey = o.SignKey
	}
	verifyKey = o.VerifyKey

	return
}

func (o *Options) buildRSAKeys() (signKey interface{}, verifyKey interface{}, err error) {
	var signBytes []byte
	var verifyBytes []byte

	// check to make sure the provided options are valid
	if o.PrivateKeyLocation == "" && !o.VerifyOnlyServer {
		err = errors.New("Private key location is required!")
		return
	}
	if o.PublicKeyLocation == "" {
		err = errors.New("Public key location is required!")
		return
	}

	// read the key files
	if !o.VerifyOnlyServer {
		signBytes, err = ioutil.ReadFile(o.PrivateKeyLocation)
		if err != nil {
			return
		}

		signKey, err = ParseRSAPrivateKeyFromPEM(signBytes)
		if err != nil {
			return
		}
	}

	verifyBytes, err = ioutil.ReadFile(o.PublicKeyLocation)
	if err != nil {
		return
	}

	verifyKey, err = ParseRSAPublicKeyFromPEM(verifyBytes)
	if err != nil {
		return
	}

	return
}

func (o *Options) buildESKeys() (signKey interface{}, verifyKey interface{}, err error) {
	var signBytes []byte
	var verifyBytes []byte

	// check to make sure the provided options are valid
	if o.PrivateKeyLocation == "" && !o.VerifyOnlyServer {
		err = errors.New("Private key location is required!")
		return
	}
	if o.PublicKeyLocation == "" {
		err = errors.New("Public key location is required!")
		return
	}

	// read the key files
	if !o.VerifyOnlyServer {
		signBytes, err = ioutil.ReadFile(o.PrivateKeyLocation)
		if err != nil {
			return
		}

		signKey, err = ParseECPrivateKeyFromPEM(signBytes)
		if err != nil {
			return
		}
	}

	verifyBytes, err = ioutil.ReadFile(o.PublicKeyLocation)
	if err != nil {
		return
	}

	verifyKey, err = ParseECPublicKeyFromPEM(verifyBytes)
	if err != nil {
		return
	}

	return
}
