package toyaes

import (
	"reflect"
	"testing"
)

func Test_shift(t *testing.T) {
	{
		input := []byte{1, 2, 3, 4}
		shift(input, 1)
		want := []byte{2, 3, 4, 1}
		if !reflect.DeepEqual(input, want) {
			t.Errorf("got=%v, want=%v", input, want)
		}
	}
	{
		input := []byte{1, 2, 3, 4, 5}
		shift(input[0:4], 2)
		want := []byte{3, 4, 1, 2, 5}
		if !reflect.DeepEqual(input, want) {
			t.Errorf("got=%v, want=%v", input, want)
		}
	}
	{
		input := []byte{9, 1, 2, 3, 4, 5}
		shift(input[1:5], 3)
		want := []byte{9, 4, 1, 2, 3, 5}
		if !reflect.DeepEqual(input, want) {
			t.Errorf("got=%v, want=%v", input, want)
		}
	}
}

func Test_mul(t *testing.T) {
	type args struct {
		x byte
		y byte
	}
	tests := []struct {
		name string
		args args
		want byte
	}{
		{name: "0x57 x 0x83 = c1", args: args{x: 0x57, y: 0x83}, want: 0xc1},
		{name: "0x57 x 0x13 = f3", args: args{x: 0x57, y: 0x13}, want: 0xfe},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mul(tt.args.x, tt.args.y); got != tt.want {
				t.Errorf("mul() = %v, want %v", got, tt.want)
			}
		})
	}
}
