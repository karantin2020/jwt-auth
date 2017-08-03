package jwt

import (
	"net/http"
	"time"

	// "github.com/pkg/errors"
	// // jose "gopkg.in/square/go-jose.v2"
	jwt "gopkg.in/square/go-jose.v2/jwt"
)

// ClaimsType : holds the claims encoded in the jwt
type ClaimsType struct {
	// Claims are the standard jwt claims from the ietf standard
	// https://tools.ietf.org/html/rfc7519
	jwt.Claims `json:"claims"`
	Csrf       string      `json:"csrf"`
	Custom     interface{} `json:"custom"`
}

// // Public claim values (as specified in RFC 7519).
// type Claims struct {
// 	Issuer    string      `json:"iss,omitempty"`
// 	Subject   string      `json:"sub,omitempty"`
// 	Audience  Audience    `json:"aud,omitempty"`
// 	Expiry    NumericDate `json:"exp,omitempty"`
// 	NotBefore NumericDate `json:"nbf,omitempty"`
// 	IssuedAt  NumericDate `json:"iat,omitempty"`
// 	ID        string      `json:"jti,omitempty"`
// }

// // Expected defines values used for protected claims validation.
// // If field has zero value then validation is skipped.
// type Expected struct {
// 	// Issuer matches the "iss" claim exactly.
// 	Issuer string
// 	// Subject matches the "sub" claim exactly.
// 	Subject string
// 	// Audience matches the values in "aud" claim, regardless of their order.
// 	Audience Audience
// 	// ID matches the "jti" claim exactly.
// 	ID string
// 	// Time matches the "exp" and "ebf" claims with leeway.
// 	Time time.Time
// }

func (c *ClaimsType) Validate(a *Auth, r *http.Request) error {
	err := c.Claims.Validate(jwt.Expected{
		Subject: from(r),
		Time:    time.Now().UTC(),
	})
	return err
}
