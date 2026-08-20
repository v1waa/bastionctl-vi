//go:build !linux

package server

import (
	"context"

	"bastionctl/internal/config"
	"bastionctl/internal/report"
)

func createUserPlatform(_ context.Context, _ config.Config, version string, _ UserRequest) *report.Report {
	r := report.New(version, "server", "user-add", "localhost")
	r.Add(report.Result{Control: "platform", Status: report.Fail, Severity: "critical", Message: "создание серверного пользователя поддерживается только на Linux"})
	return r
}
