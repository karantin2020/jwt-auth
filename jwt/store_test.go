package jwt

import (
	"net/http"
	"net/http/httptest"
	"testing"
	// "fmt"
)

func Test_mixStore_Save(t *testing.T) {
	type fields struct {
		name string
	}
	type args struct {
		token string
		w     http.ResponseWriter
	}
	rnd, err := generateRandomBytes(tokenLength)
	emptyString := ""
	if err != nil {
		t.Errorf("Error generating randomString")
		return
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name:   "Test mix store one",
			fields: fields{},
			args: args{
				string(rnd),
				httptest.NewRecorder(),
			},
			wantErr: false,
		},
		{
			name:   "Test revoke csrf",
			fields: fields{"Csrf-Token"},
			args: args{
				emptyString,
				httptest.NewRecorder(),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ms := mixStore{
				name: tt.fields.name,
			}
			if err := ms.Save(tt.args.token, tt.args.w); (err != nil) != tt.wantErr {
				t.Errorf("mixStore.Save() error = %v, wantErr %v", err, tt.wantErr)
			}
			// fmt.Printf("%#v\n", tt.args.w.Header()[ms.name])
			if unmaskString(tt.args.w.Header()[ms.name][0]) != tt.args.token {
				t.Errorf("mixStore.Save() error, wrong result")
			}
		})
	}
}
