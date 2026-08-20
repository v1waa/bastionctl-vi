//go:build !linux

package server

import (
	"context"
	"runtime"

	"bastionctl/internal/config"
	"bastionctl/internal/report"
)

func resetPlatform(_ context.Context, _ config.Config, version string, options Options) *report.Report {
	r := report.New(version, "server", options.Action, runtime.GOOS)
	r.Add(report.Result{Control: "platform", Status: report.Fail, Severity: "critical", Message: "сброс серверной политики поддерживается только на Linux"})
	return r
}
