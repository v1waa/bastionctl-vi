//go:build linux

package server

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"bastionctl/internal/config"
	"bastionctl/internal/report"
)

func TestBackupControlFreshAndStaleMarkers(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "backup.ok")
	if err := os.WriteFile(marker, []byte("ok\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.Server.BackupMarkers = []string{marker}
	cfg.Server.BackupRequired = true
	cfg.Server.BackupMaxAgeHours = 2
	ctx := &serverContext{config: cfg}
	results := backupControl().Audit(ctx)
	if len(results) != 2 || results[0].Status != report.Pass || results[1].Status != report.Warn {
		t.Fatalf("fresh marker: %+v", results)
	}
	stale := time.Now().Add(-3 * time.Hour)
	if err := os.Chtimes(marker, stale, stale); err != nil {
		t.Fatal(err)
	}
	results = backupControl().Audit(ctx)
	if results[0].Status != report.Fail {
		t.Fatalf("stale marker was not rejected: %+v", results)
	}
}
