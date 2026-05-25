package main

import (
	"os"

	"github.com/81ueman/network-sandbox/hoyan/internal/cli"
)

func main() {
	cmd := cli.NewLiveCheckCommand()
	cmd.Use = "hoyan-live-check"
	os.Exit(cli.Execute(cmd))
}
