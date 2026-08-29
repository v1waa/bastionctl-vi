//go:build !linux

package workload

import (
	"context"

	"bastionctl/internal/report"
)

func runXHTTPPlatform(_ context.Context, version, action string, _ XHTTPConfig, _ bool, _ RuntimePolicy) *report.Report {
	r := report.New(version, "server", XHTTPReportAction(action), "localhost")
	r.Add(report.Result{Control: "platform", Status: report.Fail, Severity: "critical", Message: "серверный модуль XHTTP поддерживается только на Linux"})
	return r
}
