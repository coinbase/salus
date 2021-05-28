package main

import (
	"crypto/md5"
	"fmt"
	"io"
)

func main() {

	password := "hhend77dyyydbh&^psNSSZ)JSM--_%"

	h := md5.New()
	fmt.Printf("%x", h.Sum(nil))

	fmt.Println("hello, from the vulnerable app" + password)
}
