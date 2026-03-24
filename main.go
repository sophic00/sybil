package main

import (
	"log"

	"github.com/sophic00/sybil/internal/cli"
)

func main() {
	if err := cli.Run(); err != nil {
		log.Fatal(err)
	}
}
