package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/tyj1987/broker/core/auditstore"
)

func validHealthDependencies(t *testing.T, output *bytes.Buffer) healthDependencies {
	t.Helper()
	return healthDependencies{
		loadConfig: func(path string) (auditstore.ServiceConfig, error) {
			if path != healthConfigPath {
				t.Fatalf("config path = %q", path)
			}
			return auditstore.ServiceConfig{StreamID: "broker-production"}, nil
		},
		query: func(_ context.Context, socketPath, streamID string) (auditstore.Health, error) {
			if socketPath != auditstore.DefaultSocketPath || streamID != "broker-production" {
				t.Fatalf("query = %q, %q", socketPath, streamID)
			}
			return auditstore.Health{
				Status: "ready", LockContract: "verified", MirrorState: "in_sync",
				CommonSequence: 7, ReasonCode: "ok",
			}, nil
		},
		output: output,
	}
}

func TestRunHealthEmitsOnlyExactBoundedResult(t *testing.T) {
	var output bytes.Buffer
	code, reason := runHealth(context.Background(), []string{"--socket", auditstore.DefaultSocketPath}, validHealthDependencies(t, &output))
	if code != 0 || reason != "" {
		t.Fatalf("result = %d, %q", code, reason)
	}
	const expected = `{"status":"ready","lock_contract":"verified","mirror_state":"in_sync","common_sequence":7,"reason_code":"ok"}` + "\n"
	if output.String() != expected {
		t.Fatalf("output = %q", output.String())
	}
}

func TestRunHealthFailsClosedWithoutProviderDetails(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"--socket", "/tmp/store.sock"},
		{"--socket", auditstore.DefaultSocketPath, "extra"},
	} {
		var output bytes.Buffer
		if code, reason := runHealth(context.Background(), args, validHealthDependencies(t, &output)); code != 64 || reason != "usage_invalid" || output.Len() != 0 {
			t.Fatalf("args %q result = %d, %q, %q", args, code, reason, output.String())
		}
	}

	var output bytes.Buffer
	dependencies := validHealthDependencies(t, &output)
	dependencies.loadConfig = func(string) (auditstore.ServiceConfig, error) {
		return auditstore.ServiceConfig{}, errors.New("provider detail")
	}
	if code, reason := runHealth(context.Background(), []string{"--socket", auditstore.DefaultSocketPath}, dependencies); code != 78 || reason != "config_invalid" || output.Len() != 0 {
		t.Fatalf("config result = %d, %q, %q", code, reason, output.String())
	}
	dependencies = validHealthDependencies(t, &output)
	dependencies.query = func(context.Context, string, string) (auditstore.Health, error) {
		return auditstore.Health{}, errors.New("provider detail")
	}
	if code, reason := runHealth(context.Background(), []string{"--socket", auditstore.DefaultSocketPath}, dependencies); code != 69 || reason != "store_unavailable" || strings.Contains(reason, "provider detail") || output.Len() != 0 {
		t.Fatalf("query result = %d, %q, %q", code, reason, output.String())
	}
	dependencies = validHealthDependencies(t, &output)
	dependencies.output = nil
	if code, reason := runHealth(context.Background(), []string{"--socket", auditstore.DefaultSocketPath}, dependencies); code != 70 || reason != "runtime_invalid" {
		t.Fatalf("dependency result = %d, %q", code, reason)
	}
	dependencies = validHealthDependencies(t, &output)
	dependencies.query = func(context.Context, string, string) (auditstore.Health, error) {
		return auditstore.Health{Status: "ready", LockContract: "verified", MirrorState: "in_sync", ReasonCode: "not_ok"}, nil
	}
	if code, reason := runHealth(context.Background(), []string{"--socket", auditstore.DefaultSocketPath}, dependencies); code != 70 || reason != "response_invalid" || output.Len() != 0 {
		t.Fatalf("invalid response result = %d, %q, %q", code, reason, output.String())
	}
}
