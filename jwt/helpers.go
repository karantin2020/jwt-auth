package jwt

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"net/url"

	"github.com/pkg/errors"
)

// AuthToken returns auth token claims
func AuthClaims(r *http.Request) (*ClaimsType, error) {
	val, err := contextGet(r, authTokenKey)
	if err != nil {
		return nil, errors.Wrap(err, "Error get auth token claims from request context")
	}
	if auth_token, ok := val.(*ClaimsType); ok {
		return auth_token, nil
	}
	return nil, errors.New("Invalid auth token claims context")
}

// mask returns a unique-per-request token to mitigate the BREACH attack
// as per http://breachattack.com/#mitigations
func mask(realToken []byte) string {
	otp, err := generateRandomBytes(tokenLength)
	if err != nil {
		return ""
	}

	// XOR the OTP with the real token to generate a masked token. Append the
	// OTP to the front of the masked token to allow unmasking in the subsequent
	// request.
	return base64.StdEncoding.EncodeToString(append(otp, xorToken(otp, realToken)...))
}

// unmask splits the issued token (one-time-pad + masked token) and returns the
// unmasked request token for comparison.
func unmask(issued string) []byte {
	biss, err := base64.StdEncoding.DecodeString(issued)
	if err != nil {
		return nil
	}
	// Issued tokens are always masked and combined with the pad.
	if len(biss) != tokenLength*2 {
		return nil
	}

	// We now know the length of the byte slice.
	otp := biss[tokenLength:]
	masked := biss[:tokenLength]

	// Unmask the token by XOR'ing it against the OTP used to mask it.
	return xorToken(otp, masked)
}

// unmask string
func unmaskString(issued string) string {
	return string(unmask(issued))
}

// generateRandomBytes returns securely generated random bytes.
// It will return an error if the system's secure random number generator
// fails to function correctly.
func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// err == nil only if len(b) == n
	if err != nil {
		return nil, err
	}

	return b, nil

}

// generateRandomString returns securely generated random string.
// It will return an error if the system's secure random number generator
// fails to function correctly.
func generateRandomString(n int) (string, error) {
	bb, err := generateRandomBytes(n)

	return string(bb), err

}

// sameOrigin returns true if URLs a and b share the same origin. The same
// origin is defined as host (which includes the port) and scheme.
func sameOrigin(a, b *url.URL) bool {
	return (a.Scheme == b.Scheme && a.Host == b.Host)
}

// compare securely (constant-time) compares the unmasked token from the request
// against the real token from the session.
func compareTokens(a, b []byte) bool {
	// This is required as subtle.ConstantTimeCompare does not check for equal
	// lengths in Go versions prior to 1.3.
	if len(a) != len(b) {
		return false
	}

	return subtle.ConstantTimeCompare(a, b) == 1
}

// compare securely (constant-time) compares the unmasked token from the request
// against the real token from the session.
func compareTokenStrings(a, b string) bool {
	return compareTokens([]byte(a), []byte(a))
}

// xorToken XORs tokens ([]byte) to provide unique-per-request tokens. It
// will return a masked token if the base token is XOR'ed with a one-time-pad.
// An unmasked token will be returned if a masked token is XOR'ed with the
// one-time-pad used to mask it.
func xorToken(a, b []byte) []byte {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}

	res := make([]byte, n)

	for i := 0; i < n; i++ {
		res[i] = a[i] ^ b[i]
	}

	return res
}

// xorToken XORs tokens (ыекштп) to provide unique-per-request tokens. It
// will return a masked token if the base token is XOR'ed with a one-time-pad.
// An unmasked token will be returned if a masked token is XOR'ed with the
// one-time-pad used to mask it.
func xorTokenStrings(a, b string) []byte {
	return xorToken([]byte(a), []byte(a))
}

// contains is a helper function to check if a string exists in a slice - e.g.
// whether a HTTP method exists in a list of safe methods.
func contains(vals []string, s string) bool {
	for _, v := range vals {
		if v == s {
			return true
		}
	}

	return false
}
