package main

import (
	"os"

	"github.com/81ueman/network-sandbox/hoyan/internal/cli"
)

func main() {
	cmd := cli.NewRIBCompareCommand()
	cmd.Use = "hoyan-rib-compare"
	os.Exit(cli.Execute(cmd))
}
