package main

import (
	"fmt"
	"os"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "nhi-reach:", err)
		os.Exit(exitCode(err))
	}
}
