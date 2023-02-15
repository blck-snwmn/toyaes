package main

import (
	"fmt"

	"github.com/blck-snwmn/toyaes"
)

func main() {
	for _, v := range []byte{0x02, 0x03, 0x0e, 0x0b, 0x0d, 0x09} {
		fmt.Printf("0x%02X\n", v)
		for i := 0; i <= 0xFF; i++ {
			result := toyaes.Mul(v, byte(i))
			fmt.Printf("0x%02X,", result)
			if i%10 == 9 {
				fmt.Println()
			}
		}
		fmt.Printf("\n\n")
	}
}
