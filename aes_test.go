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

