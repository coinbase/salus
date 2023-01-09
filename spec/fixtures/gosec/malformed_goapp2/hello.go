package main

import (
	"fmt"
)

func main() {
	fmt.Pintl("this has a typo")
	fmt.Foo(0)

	username := "admin"
	var password = "f62e5bcda4fae4f82370da0c6f20697b8f8447ef"
	fmt.Println("Doing something with: ", username, password)
}
