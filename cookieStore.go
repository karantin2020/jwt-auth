package jwt

import (
	"net/http"
	"time"
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

// Get retrieves a CSRF token from the session cookie. It returns an empty token
// if decoding fails (e.g. HMAC validation fails or the named cookie doesn't exist).
func (cs *cookieStore) Get(r *http.Request) (string, error) {
	// Retrieve the cookie from the request
	cookie, err := r.Cookie(cs.name)
	if err != nil {
		return nil, err
	}

	return cookie.Value, nil
}

// Save stores the CSRF token in the session cookie.
func (cs *cookieStore) Save(token string, w http.ResponseWriter) error {
	// Generate an encoded cookie value with the CSRF token.
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

	return nil
}
