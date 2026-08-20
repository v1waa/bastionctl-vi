package server

import (
	"context"

	"bastionctl/internal/config"
	"bastionctl/internal/report"
)

type Options struct {
	Action     string
	ConfigPath string
	Yes        bool
}

func Run(ctx context.Context, cfg config.Config, version string, options Options) *report.Report {
	if options.Action == "reset-plan" || options.Action == "reset" {
		return resetPlatform(ctx, cfg, version, options)
	}
	return runPlatform(ctx, cfg, version, options)
}
