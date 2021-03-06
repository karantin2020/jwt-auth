package jwt

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuth_New(t *testing.T) {
	tests := []struct {
		name    string
		fields  []func(*Options) error
		wantErr bool
	}{
		{
			"One",
			nil,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewAuth(tt.fields...)
			if err != nil {
				t.Errorf("Auth.IssueNewTokens() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAuth_IssueNewTokens(t *testing.T) {
	type args struct {
		w      http.ResponseWriter
		claims *ClaimsType
	}
	tests := []struct {
		name    string
		fields  []func(*Options) error
		args    args
		wantErr bool
	}{
		{
			"One",
			nil,
			args{
				httptest.NewRecorder(),
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
			a, err := NewAuth(tt.fields...)
			if err != nil {
				t.Errorf("Auth.IssueNewTokens() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err = a.IssueNewTokens(tt.args.w, tt.args.claims); (err != nil) != tt.wantErr {
				t.Errorf("Auth.IssueNewTokens() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
