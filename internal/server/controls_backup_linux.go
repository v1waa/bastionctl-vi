//go:build linux

package server

import (
	"fmt"
	"os"
	"strings"
	"time"

	"bastionctl/internal/report"
)

func backupControl() control {
	return functionalControl{
		name: "backup",
		audit: func(ctx *serverContext) []report.Result {
			settings := ctx.config.Server
			if len(settings.BackupMarkers) == 0 {
				status := report.Warn
				severity := "high"
				message := "backup markers не настроены; свежесть копий не проверяется"
				if settings.BackupRequired {
					status = report.Fail
					severity = "critical"
					message = "backup_required=true, но backup_markers пуст"
				}
				return []report.Result{{Control: "backup", Status: status, Severity: severity, Message: message}}
			}
			results := make([]report.Result, 0, len(settings.BackupMarkers)+1)
			maximumAge := time.Duration(settings.BackupMaxAgeHours) * time.Hour
			for _, path := range settings.BackupMarkers {
				info, err := os.Lstat(path)
				if err != nil {
					results = append(results, report.Result{Control: "backup", Status: report.Fail, Severity: "critical", Message: "backup marker недоступен", Details: map[string]string{"path": path, "error": err.Error()}})
					continue
				}
				if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
					results = append(results, report.Result{Control: "backup", Status: report.Fail, Severity: "critical", Message: "backup marker должен быть обычным файлом без symlink", Details: map[string]string{"path": path}})
					continue
				}
				age := time.Since(info.ModTime())
				status := report.Pass
				severity := "high"
				message := "backup marker свежий"
				if age < 0 {
					status = report.Warn
					message = "backup marker находится в будущем; проверьте время"
				} else if age > maximumAge {
					status = report.Fail
					severity = "critical"
					message = "backup marker устарел"
				}
				results = append(results, report.Result{Control: "backup", Status: status, Severity: severity, Message: message, Details: map[string]string{"path": path, "modified_at": info.ModTime().UTC().Format(time.RFC3339), "age": age.Round(time.Minute).String(), "maximum_age": maximumAge.String()}})
			}
			results = append(results, report.Result{Control: "backup", Status: report.Warn, Severity: "high", Message: "свежий marker не заменяет регулярный тест восстановления"})
			return results
		},
		plan: func(ctx *serverContext) report.Result {
			markers := strings.Join(ctx.config.Server.BackupMarkers, ", ")
			if markers == "" {
				markers = "не настроены"
			}
			return report.Result{Control: "backup", Status: report.Info, Severity: "critical", Message: "read-only проверка возраста backup markers", Details: map[string]string{"markers": markers, "maximum_age_hours": fmt.Sprintf("%d", ctx.config.Server.BackupMaxAgeHours)}}
		},
	}
}
