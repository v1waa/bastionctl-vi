package workload

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"bastionctl/internal/report"
)

type RuntimePolicy struct {
	AdminUser                   string
	SSHLocalForwardDestinations []string
}

func Run(ctx context.Context, version, module, action string, input io.Reader, yes bool, policy RuntimePolicy) *report.Report {
	reportAction := "workload-" + module + "-" + action
	r := report.New(version, "server", reportAction, "localhost")
	if module != XHTTPModule {
		r.Add(report.Result{Control: "workload", Status: report.Fail, Severity: "critical", Message: "неизвестный модуль сервиса " + module})
		return r
	}
	if !IsXHTTPAction(action) {
		r.Add(report.Result{Control: "workload", Status: report.Fail, Severity: "critical", Message: "XHTTP поддерживает plan, apply и verify"})
		return r
	}
	if action == "apply" && !yes {
		r.Add(report.Result{Control: "confirmation", Status: report.Fail, Severity: "critical", Message: "workload xhttp apply требует отдельный plan и --yes"})
		return r
	}
	request, err := decodeXHTTPConfig(input)
	if err != nil {
		r.Add(report.Result{Control: "request", Status: report.Fail, Severity: "critical", Message: err.Error()})
		return r
	}
	return runXHTTPPlatform(ctx, version, action, request, yes, policy)
}

func decodeXHTTPConfig(input io.Reader) (XHTTPConfig, error) {
	if input == nil {
		return XHTTPConfig{}, errors.New("XHTTP-запрос отсутствует")
	}
	data, err := io.ReadAll(io.LimitReader(input, 64*1024+1))
	if err != nil {
		return XHTTPConfig{}, fmt.Errorf("прочитать XHTTP-запрос: %w", err)
	}
	if len(data) == 0 || len(data) > 64*1024 {
		return XHTTPConfig{}, errors.New("XHTTP-запрос пуст или слишком велик")
	}
	var value XHTTPConfig
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return XHTTPConfig{}, fmt.Errorf("прочитать XHTTP JSON: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return XHTTPConfig{}, errors.New("после XHTTP JSON обнаружены лишние данные")
	}
	if err := value.Validate(); err != nil {
		return XHTTPConfig{}, err
	}
	return value, nil
}
