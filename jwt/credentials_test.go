package jwt

import (
	// "fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	// jose "gopkg.in/square/go-jose.v2"
)

func TestAuth_newCredentials(t *testing.T) {
	auth, err := NewAuth()
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

func TestAuth_setCredentials(t *testing.T) {
	auth, err := NewAuth()
	if err != nil {
		t.Errorf("TestAuth_newCredentials: couldn't create new Auth instance")
	}
	type args struct {
		w http.ResponseWriter
		c *credentials
	}
	cr := credentials{}
	a := auth
	if err := a.newCredentials(&cr, &ClaimsType{
		Custom: map[string]int{
			"asd": 123,
			"dsa": 321,
		},
	}); err != nil {
		t.Errorf("Auth.setCredentials() error = %v", err)
	}
	// fmt.Printf("%#v\n", cr)
	// fmt.Printf("%#v\n", cr.RefreshToken)
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			"One",
			args{
				httptest.NewRecorder(),
				&cr,
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := auth
			// fmt.Printf("%#v\n", tt.args.w)
			if err := a.setCredentials(tt.args.w, tt.args.c); (err != nil) != tt.wantErr {
				t.Errorf("Auth.setCredentials() error = %v, wantErr %v", err, tt.wantErr)
			}
			// tt.args.c.AuthToken.Custom.(map[string]int)["asd"] = 654
			// fmt.Printf("%#v\n", tt.args.c.AuthToken)
			// fmt.Printf("%#v\n", tt.args.c.RefreshToken)
		})
	}
}
