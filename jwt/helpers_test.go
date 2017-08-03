package jwt

import (
	"reflect"
	"testing"
)

func Test_unmask(t *testing.T) {
	type args struct {
		issued string
	}
	rnd, err := generateRandomBytes(tokenLength)
	// emptyToken := []byte("")
	if err != nil {
		t.Errorf("Error generating random string")
		return
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		{
			"Test random string",
			args{mask(rnd)},
			rnd,
		},
		// {
		// 	"Test empty string",
		// 	args{mask(emptyToken)},
		// 	emptyToken,
		// },
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := unmask(tt.args.issued); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("unmask() = %#v, want %#v", got, tt.want)
			}
		})
	}
}
