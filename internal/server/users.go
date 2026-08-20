package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"

	"bastionctl/internal/config"
	"bastionctl/internal/report"
	"bastionctl/internal/sshkey"
)

const userRequestSchema = "bastionctl.user-add.v1"

type UserRequest struct {
	Schema    string `json:"schema"`
	Username  string `json:"username"`
	PublicKey string `json:"public_key"`
	GrantSudo bool   `json:"grant_sudo"`
}

func NewUserRequest(username, publicKey string, grantSudo bool) (UserRequest, error) {
	if err := sshkey.ValidateUsername(username); err != nil {
		return UserRequest{}, err
	}
	normalized, _, err := sshkey.NormalizePublicKey(publicKey)
	if err != nil {
		return UserRequest{}, err
	}
	return UserRequest{Schema: userRequestSchema, Username: username, PublicKey: normalized, GrantSudo: grantSudo}, nil
}

func CreateUser(ctx context.Context, cfg config.Config, version string, input io.Reader, yes bool) *report.Report {
	r := report.New(version, "server", "user-add", "localhost")
	if !yes {
		r.Add(report.Result{Control: "confirmation", Status: report.Fail, Severity: "critical", Message: "server user-add требует --yes"})
		return r
	}
	decoder := json.NewDecoder(io.LimitReader(input, 32<<10))
	decoder.DisallowUnknownFields()
	var request UserRequest
	if err := decoder.Decode(&request); err != nil {
		r.Add(report.Result{Control: "request", Status: report.Fail, Severity: "critical", Message: "некорректный JSON-запрос создания пользователя", Details: map[string]string{"error": err.Error()}})
		return r
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		r.Add(report.Result{Control: "request", Status: report.Fail, Severity: "critical", Message: "после JSON-запроса обнаружены лишние данные"})
		return r
	}
	if request.Schema != userRequestSchema {
		r.Add(report.Result{Control: "request", Status: report.Fail, Severity: "critical", Message: "неподдерживаемая схема запроса"})
		return r
	}
	validated, err := NewUserRequest(request.Username, request.PublicKey, request.GrantSudo)
	if err != nil {
		r.Add(report.Result{Control: "request", Status: report.Fail, Severity: "critical", Message: err.Error()})
		return r
	}
	return createUserPlatform(ctx, cfg, version, validated)
}
