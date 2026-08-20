package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"bastionctl/internal/cli"
)

var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(cli.Run(ctx, os.Args[1:], version, os.Stdin, os.Stdout, os.Stderr))
}
