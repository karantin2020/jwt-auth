package jwt

import (
	// "net/http"
	// "fmt"
	"testing"
	// jose "gopkg.in/square/go-jose.v2"
)

func TestAuth_newCredentials(t *testing.T) {
	opts := Options{}
	err := DevelOpts(&opts)
	if err != nil {
		t.Errorf("TestAuth_newCredentials: couldn't create devel options")
	}
	auth, err := New(opts)
	if err != nil {
		t.Errorf("TestAuth_newCredentials: couldn't create new Auth instance")
	}
	type args struct {
		c      *credentials
		claims *ClaimsType
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			"Test claim equality",
			args{
				&credentials{},
				&ClaimsType{
					Custom: map[string]int{
						"asd": 123,
						"dsa": 321,
					},
				},
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := auth
			if err := a.newCredentials(tt.args.c, tt.args.claims); (err != nil) != tt.wantErr {
				t.Errorf("Auth.newCredentials() error = %v, wantErr %v", err, tt.wantErr)
			}
			tt.args.c.AuthToken.Custom.(map[string]int)["asd"] = 654
			// fmt.Printf("%#v\n", tt.args.c.AuthToken)
			// fmt.Printf("%#v\n", tt.args.c.RefreshToken)
		})
	}
}
