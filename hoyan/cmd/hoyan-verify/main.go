package main

import (
	"os"

	"github.com/81ueman/network-sandbox/hoyan/internal/cli"
)

func main() {
	cmd := cli.NewVerifyCommand()
	cmd.Use = "hoyan-verify"
	os.Exit(cli.Execute(cmd))
}
