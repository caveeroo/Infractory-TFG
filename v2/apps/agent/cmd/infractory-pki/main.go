package main

import (
	"fmt"
	"os"
	"time"

	"github.com/infractory/infractory/v2/agent/internal/pki"
)

func main() {
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "infractory-pki accepts JSON on stdin and writes JSON on stdout; it accepts no arguments")
		os.Exit(2)
	}
	if err := pki.Handle(os.Stdin, os.Stdout, time.Now().UTC()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
