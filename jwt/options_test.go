package jwt

import "testing"

func TestDefOpts(t *testing.T) {
	opts := &Options{}
	DevelOpts(opts)

	type args struct {
		o *Options
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name:    "Empty options",
			args:    args{&Options{}},
			wantErr: true,
		},
		{
			name:    "Default options",
			args:    args{opts},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := DefOpts(tt.args.o); (err != nil) != tt.wantErr {
				t.Errorf("DefOpts() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDevelOpts(t *testing.T) {
	type args struct {
		o *Options
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name:    "Empty options",
			args:    args{&Options{}},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := DevelOpts(tt.args.o); (err != nil) != tt.wantErr {
				t.Errorf("DevelOpts() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
