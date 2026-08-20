//go:build !linux

package server

import (
	"context"
	"runtime"

	"bastionctl/internal/config"
	"bastionctl/internal/report"
)

func runPlatform(_ context.Context, _ config.Config, version string, options Options) *report.Report {
	r := report.New(version, "server", options.Action, runtime.GOOS)
	status := report.Warn
	severity := "medium"
	message := "server-режим поддерживается только на Linux; используйте этот бинарник в admin-режиме"
	if options.Action == "apply" {
		status = report.Fail
		severity = "critical"
	}
	r.Add(report.Result{Control: "platform", Status: status, Severity: severity, Message: message})
	return r
}
