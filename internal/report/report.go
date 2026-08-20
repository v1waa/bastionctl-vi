package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

const Schema = "bastionctl.report.v1"

type Status string

const (
	Pass    Status = "pass"
	Fail    Status = "fail"
	Warn    Status = "warn"
	Info    Status = "info"
	Planned Status = "planned"
	Changed Status = "changed"
	Skipped Status = "skipped"
)

type Result struct {
	Control  string            `json:"control"`
	Status   Status            `json:"status"`
	Severity string            `json:"severity,omitempty"`
	Message  string            `json:"message"`
	Details  map[string]string `json:"details,omitempty"`
	Changed  bool              `json:"changed,omitempty"`
}

type Summary struct {
	Pass    int `json:"pass"`
	Fail    int `json:"fail"`
	Warn    int `json:"warn"`
	Info    int `json:"info"`
	Planned int `json:"planned"`
	Changed int `json:"changed"`
	Skipped int `json:"skipped"`
}

type Report struct {
	Schema      string    `json:"schema"`
	ToolVersion string    `json:"tool_version"`
	Mode        string    `json:"mode"`
	Action      string    `json:"action"`
	Target      string    `json:"target,omitempty"`
	StartedAt   time.Time `json:"started_at"`
	FinishedAt  time.Time `json:"finished_at"`
	Summary     Summary   `json:"summary"`
	Results     []Result  `json:"results"`
	Warnings    []string  `json:"warnings,omitempty"`
	BackupDir   string    `json:"backup_dir,omitempty"`
}

func New(version, mode, action, target string) *Report {
	return &Report{
		Schema: Schema, ToolVersion: version, Mode: mode, Action: action, Target: target,
		StartedAt: time.Now().UTC(), Results: make([]Result, 0),
	}
}

func (r *Report) Add(result Result) {
	r.Results = append(r.Results, result)
}

func (r *Report) Finish() {
	r.FinishedAt = time.Now().UTC()
	r.Summary = Summary{}
	for _, item := range r.Results {
		switch item.Status {
		case Pass:
			r.Summary.Pass++
		case Fail:
			r.Summary.Fail++
		case Warn:
			r.Summary.Warn++
		case Info:
			r.Summary.Info++
		case Planned:
			r.Summary.Planned++
		case Changed:
			r.Summary.Changed++
		case Skipped:
			r.Summary.Skipped++
		}
	}
}

func (r *Report) HasFailures() bool {
	for _, item := range r.Results {
		if item.Status == Fail {
			return true
		}
	}
	return false
}

func (r *Report) ExitCode() int {
	if r.HasFailures() {
		return 2
	}
	return 0
}

func WriteJSON(w io.Writer, r *Report) error {
	r.Finish()
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func WriteText(w io.Writer, r *Report) error {
	r.Finish()
	if _, err := fmt.Fprintf(w, "bastionctl %s — %s %s", r.ToolVersion, r.Mode, r.Action); err != nil {
		return err
	}
	if r.Target != "" {
		if _, err := fmt.Fprintf(w, " (%s)", r.Target); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}
	for _, item := range r.Results {
		if _, err := fmt.Fprintf(w, "%-8s %-22s %s\n", strings.ToUpper(string(item.Status)), item.Control, item.Message); err != nil {
			return err
		}
		if len(item.Details) > 0 {
			keys := make([]string, 0, len(item.Details))
			for key := range item.Details {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				if _, err := fmt.Fprintf(w, "         %-22s %s\n", key+":", item.Details[key]); err != nil {
					return err
				}
			}
		}
	}
	for _, warning := range r.Warnings {
		if _, err := fmt.Fprintf(w, "WARNING  %s\n", warning); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(w, "Итог: pass=%d fail=%d warn=%d changed=%d planned=%d skipped=%d\n",
		r.Summary.Pass, r.Summary.Fail, r.Summary.Warn, r.Summary.Changed, r.Summary.Planned, r.Summary.Skipped)
	return err
}
