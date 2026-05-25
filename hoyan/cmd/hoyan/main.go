package main

import (
	"os"

	"github.com/81ueman/network-sandbox/hoyan/internal/cli"
)

func main() {
	os.Exit(cli.Execute(cli.NewRootCommand()))
}
