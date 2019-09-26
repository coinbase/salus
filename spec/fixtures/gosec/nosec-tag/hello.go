package main

import (
	"fmt"
)

func main() {
	/* #falsepositive */
	password := "hhend77dyyydbh&^psNSSZ)JSM--_%"
	fmt.Println("hello, from the vulnerable app" + password)
}
