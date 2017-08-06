package jwt

import (
	// "fmt"
	"net/http"
	"strings"
	"time"

	"github.com/pkg/errors"
	jose "gopkg.in/square/go-jose.v2"
	jwt "gopkg.in/square/go-jose.v2/jwt"
)

var (
	NoJWTCookie         = errors.New("No JWT cookie found")
	InternalServerError = errors.New("Internal Server Error")
)

// store represents the session storage used for JWT tokens.
type store interface {
	// Get returns the real JWT token from the store.
	Get(*http.Request) ([]byte, error)
	// Save stores the real JWT token in the store and writes a
	// cookie to the http.ResponseWriter.
	// For non-cookie stores, the cookie should contain a unique (256 bit) ID
	// or key that references the token in the backend store.
	// JWT.GenerateRandomBytes is a helper function for generating secure IDs.
	Save(token []byte, w http.ResponseWriter) error
}

// cookieStore is a signed cookie session store for JWT tokens.
type cookieStore struct {
	name     string
	maxAge   int
	secure   bool
	httpOnly bool
	path     string
	domain   string
}

// Get retrieves a JWT token from the session cookie. It returns an empty token
// if decoding fails (e.g. HMAC validation fails or the named cookie doesn't exist).
func (cs *cookieStore) Get(r *http.Request) (string, error) {
	// Retrieve the cookie from the request
	cookie, err := r.Cookie(cs.name)
	if err != nil {
		return "", err
	}

	return cookie.Value, nil
}

// Save stores the JWT token in the session cookie.
func (cs cookieStore) Save(token string, w http.ResponseWriter) error {
	// Generate an encoded cookie value with the JWT token.
	cookie := &http.Cookie{
		Name:     cs.name,
		Value:    token,
		MaxAge:   cs.maxAge,
		HttpOnly: cs.httpOnly,
		Secure:   cs.secure,
		Path:     cs.path,
		Domain:   cs.domain,
	}

	// Set the Expires field on the cookie based on the MaxAge
	// If MaxAge <= 0, we don't set the Expires attribute, making the cookie
	// session-only.
	if cs.maxAge > 0 {
		cookie.Expires = time.Now().Add(
			time.Duration(cs.maxAge) * time.Second)
	}

	// Write the authenticated cookie to the response.
	http.SetCookie(w, cookie)

	// Set the Vary: Cookie header to protect clients from caching the response.
	w.Header().Add("Vary", "Cookie")

	return nil
}

// headerStore is used to store JWT tokens in request/response header.
type headerStore struct {
	name   string
	maxAge int
}

// Get retrieves a JWT token from request header
func (hs *headerStore) Get(r *http.Request) (string, error) {
	// Retrieve token from the request
	return r.Header.Get(hs.name), nil
}

// Save stores the JWT token in response header
func (hs headerStore) Save(token string, w http.ResponseWriter) error {
	setHeader(w, hs.name, token)
	return nil
}

type claimStore interface {
	Get(r *http.Request) (*ClaimsType, error)
	Save(c *ClaimsType, w http.ResponseWriter) error
}

// jwtStore is used to store JWT tokens in request/response header.
type jwtStore struct {
	bearerTokens        bool
	tokenName           string
	encrypt             bool
	signer              jose.Signer
	encrypter           jose.Encrypter
	csrfEncrypter       jose.Encrypter
	signingMethodString string
	encryptMethodString string
	signKey             interface{}
	verifyKey           interface{}
	encryptKey          interface{}
	decryptKey          interface{}
	// revokeToken         func(tokenId string) error
	cookieStore
}

func NewJWTStore(o *Options, tokName string, tokType int, enc bool) (*jwtStore, error) {
	out := &jwtStore{
		bearerTokens:        o.BearerTokens,
		tokenName:           tokName,
		encrypt:             enc,
		signingMethodString: o.SigningMethodString,
		signKey:             o.SignKey,
		verifyKey:           o.VerifyKey,
		// revokeToken:         defaultTokenRevoker,
	}
	if !o.BearerTokens {
		out.cookieStore = cookieStore{
			name:     tokName,
			secure:   !o.IsDevEnv,
			httpOnly: true,
			path:     o.Path,
			domain:   o.Domain,
		}
		if tokType == AuthToken {
			out.cookieStore.maxAge = int(o.AuthTokenValidTime)
			out.cookieStore.httpOnly = o.AuthCookieForJS
		} else {
			out.cookieStore.maxAge = int(o.RefreshTokenValidTime)
		}
	}
	// if enc {
	out.encryptMethodString = o.EncryptMethodString
	out.encryptKey = o.EncryptKey
	out.decryptKey = o.DecryptKey
	// }
	err := initJWTStore(out)
	if err != nil {
		return nil, errors.Wrap(err, "Error init jwtStore "+tokName)
	}
	return out, nil
}

func initJWTStore(js *jwtStore) error {
	if js.signingMethodString == "" || js.signKey == nil ||
		(js.encrypt && js.encryptMethodString == "") {
		return errors.Wrapf(InternalServerError, "jwtStore was not properly initiated: %#v %#v %#v",
			js.signingMethodString, js.signKey, js.encryptMethodString)
	}

	csrfEnc, err := jose.NewEncrypter(
		jose.ContentEncryption(js.encryptMethodString),
		jose.Recipient{
			Algorithm: jose.DIRECT,
			Key:       js.encryptKey,
		},
		&jose.EncrypterOptions{},
	)
	if err != nil {
		return errors.Wrap(err, "Couldn't create new encrypter")
	}
	js.csrfEncrypter = csrfEnc

	if !js.encrypt {
		sig, err := jose.NewSigner(jose.SigningKey{
			Algorithm: jose.SignatureAlgorithm(js.signingMethodString),
			Key:       js.signKey,
		}, (&jose.SignerOptions{}).WithType("JWT"))
		if err != nil {
			return errors.Wrap(err, "Couldn't create new signer for jwt store")
		}
		js.signer = sig
	} else {
		enc, err := jose.NewEncrypter(
			jose.ContentEncryption(js.encryptMethodString),
			jose.Recipient{
				Algorithm: jose.DIRECT,
				Key:       js.encryptKey,
			},
			(&jose.EncrypterOptions{}).WithType("JWT").WithContentType("JWT"),
		)
		if err != nil {
			return errors.Wrap(err, "Couldn't create new encrypter")
		}
		js.encrypter = enc

		sig, err := jose.NewSigner(jose.SigningKey{
			Algorithm: jose.SignatureAlgorithm(js.signingMethodString),
			Key:       js.signKey}, nil)
		if err != nil {
			return errors.Wrap(err, "Couldn't create new signer for jwt store")
		}
		js.signer = sig
	}

	return nil
}

// Get retrieves a JWT token from request header or cookie
func (js jwtStore) Get(r *http.Request) (*ClaimsType, error) {
	// read header
	if js.bearerTokens {
		return js.ParseJWT(r.Header.Get(js.tokenName))
	}

	// read cookies
	cookie, tokErr := r.Cookie(js.tokenName)
	if tokErr == http.ErrNoCookie {
		return nil, NoJWTCookie
	} else if tokErr != nil {
		return nil, errors.Wrap(tokErr, "Error get JWT cookie")
	}

	return js.ParseJWT(cookie.Value)
}

func (js jwtStore) ParseJWT(tokenString string) (*ClaimsType, error) {
	cl := ClaimsType{}
	if js.encrypt {
		tok, err := jwt.ParseSignedAndEncrypted(tokenString)
		if err != nil {
			return nil, errors.Wrap(err, "Error parse encrypted JWT")
		}
		nested, err := tok.Decrypt(js.decryptKey)
		if err != nil {
			return nil, errors.Wrap(err, "Error decrypt encrypted JWT")
		}

		if err := nested.Claims(js.verifyKey, &cl); err != nil {
			return nil, errors.Wrap(err, "Error verify encrypted JWT")
		}
	} else {
		tok, err := jwt.ParseSigned(tokenString)
		if err != nil {
			return nil, errors.Wrap(err, "Error parse signed JWT")
		}

		if err := tok.Claims(js.verifyKey, &cl); err != nil {
			return nil, errors.Wrap(err, "Error verify signed JWT")
		}
		parsed, err := jose.ParseEncrypted(cl.Csrf)
		if err != nil {
			return nil, errors.Wrapf(err, "error in parse on msg '%s'", msg)
		}
		output, err := parsed.Decrypt(js.decryptKey.([]byte))
		if err != nil {
			return nil, errors.Wrapf(err, "error on decrypt")
		}
		cl.Csrf = string(output)

	}
	return &cl, nil
}

func (js jwtStore) Encrypt(c *ClaimsType) (string, error) {
	if !js.encrypt {
		return jwt.Signed(js.signer).Claims(c).CompactSerialize()
	}
	return jwt.SignedAndEncrypted(js.signer, js.encrypter).Claims(c).CompactSerialize()
}

// Save stores the JWT token in response
func (js jwtStore) Save(c *ClaimsType, w http.ResponseWriter) error {
	if !js.encrypt {
		csrfEncoded, err := js.csrfEncrypter.Encrypt([]byte(c.Csrf))
		if err != nil {
			return errors.Wrap(err, "Error encrypt claims csrf")
		}
		ce, err := csrfEncoded.CompactSerialize()
		if err != nil {
			return errors.Wrap(err, "Error encrypt compact serialize claims csrf")
		}
		c.Csrf = ce
	}
	token, err := js.Encrypt(c)
	if err != nil {
		return errors.Wrap(err, "Error encrypt claims")
	}

	if js.bearerTokens {
		// tokens are not in cookies
		setHeader(w, js.tokenName, token)
	} else {
		// tokens are in cookies
		// note: don't use an "Expires" in auth cookies bc browsers won't send expired cookies?
		js.cookieStore.Save(token, w)
	}
	return nil
}

func (js jwtStore) Revoke(w http.ResponseWriter) error {
	setHeader(w, js.tokenName, "")
	cookie := http.Cookie{
		Name:     js.tokenName,
		Value:    "",
		Expires:  time.Now().Add(-1000 * time.Hour),
		HttpOnly: true,
		Secure:   true,
		Path:     js.path,
		Domain:   js.domain,
	}
	http.SetCookie(w, &cookie)

	return nil
}

// mixStore is used to store CSRF tokens in request/response header.
type mixStore struct {
	name string
}

// Get retrieves a CSRF token from request header
func (ms mixStore) Get(r *http.Request) (string, error) {
	// Retrieve token from the request
	tokenString := r.Header.Get(ms.name)
	if tokenString != "" {
		return unmaskString(tokenString), nil
	}

	tokenString = r.FormValue(ms.name)
	if tokenString != "" {
		return unmaskString(tokenString), nil
	}

	auth := r.Header.Get("Authorization")
	tokenString = strings.Replace(auth, "Bearer", "", 1)
	tokenString = strings.Replace(tokenString, " ", "", -1)
	if tokenString == "" {
		return tokenString, errors.New("No CSRF string found in request")
	}
	byteCsrfString := unmask(tokenString)
	if byteCsrfString == nil {
		return "", errors.New("Invalid CSRF string in request")
	}

	return string(byteCsrfString), nil
}

// Save stores the CSRF token in response header
func (ms mixStore) Save(token string, w http.ResponseWriter) error {
	// msk := mask([]byte(token))
	// fmt.Println(string(msk))
	setHeader(w, ms.name, mask([]byte(token)))
	return nil
}

func setHeader(w http.ResponseWriter, header string, value string) {
	w.Header().Set(header, value)
}
