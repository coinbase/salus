package main

import (
	"fmt"
	"testing"
)

func TestAbsValue(t *testing.T) {
	password := "hhend77dyyydbh&^psNSSZ)JSM--_%"
	fmt.Println(password)

	got := AbsValue(-1)
	if got != 1 {
		t.Errorf("Abs(-1) = %d; want 1", got)
	}
}
