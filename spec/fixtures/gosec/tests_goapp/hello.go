package main

import (
	"fmt"
)

func main() {
	fmt.Println("hello, from the vulnerable app")
}

func AbsValue(int) int {
	return 5
}
