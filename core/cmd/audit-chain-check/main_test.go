package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/json/jsontext"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeValidAudit(t *testing.T, directory string) {
	t.Helper()
	event := map[string]any{
		"action":    "read",
		"canary":    "never-print-this",
		"prev_hash": strings.Repeat("0", 64),
	}
	unsigned, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	canonical := jsontext.Value(unsigned)
	if err := canonical.Canonicalize(); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(canonical)
	event["hash"] = hex.EncodeToString(digest[:])
	sealed, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "audit-chain-2026-09-13.jsonl"), append(sealed, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func execute(t *testing.T, ctx context.Context, args []string, directory string) (int, string, string) {
	t.Helper()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(ctx, args, func(name string) string {
		if name == "AUDIT_DIR" {
			return directory
		}
		return ""
	}, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestRunVerifiesValidDirectory(t *testing.T) {
	directory := t.TempDir()
	writeValidAudit(t, directory)
	code, stdout, stderr := execute(t, context.Background(), nil, directory)
	if code != 0 || stdout != "audit_chain_verified=yes files=1 events=1\n" || stderr != "" {
		t.Fatalf("run() = (%d, %q, %q)", code, stdout, stderr)
	}
	if strings.Contains(stdout+stderr, directory) || strings.Contains(stdout+stderr, "never-print-this") {
		t.Fatal("output disclosed source data")
	}
}

func TestRunRedactsVerificationFailure(t *testing.T) {
	directory := t.TempDir()
	canary := "canary-secret-value"
	if err := os.WriteFile(filepath.Join(directory, "audit-chain-2026-09-13.jsonl"), []byte(`{"secret":"`+canary+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := execute(t, context.Background(), nil, directory)
	if code != 65 || stdout != "" || stderr != "audit_chain_verified=no\n" {
		t.Fatalf("run() = (%d, %q, %q)", code, stdout, stderr)
	}
	if strings.Contains(stdout+stderr, canary) || strings.Contains(stdout+stderr, directory) {
		t.Fatal("failure output disclosed source data")
	}
}

func TestRunRejectsInvalidUse(t *testing.T) {
	tests := []struct {
		name      string
		ctx       context.Context
		args      []string
		directory string
	}{
		{name: "argument", ctx: context.Background(), args: []string{"unexpected"}, directory: t.TempDir()},
		{name: "relative directory", ctx: context.Background(), directory: "relative"},
		{name: "empty directory", ctx: context.Background(), directory: ""},
		{name: "nil context", ctx: nil, directory: t.TempDir()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			code, _, _ := execute(t, test.ctx, test.args, test.directory)
			if code != 64 {
				t.Fatalf("code = %d, want 64", code)
			}
		})
	}
}

func TestRunMapsCancellationToVerificationFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	code, stdout, stderr := execute(t, ctx, nil, t.TempDir())
	if code != 65 || stdout != "" || stderr != "audit_chain_verified=no\n" {
		t.Fatalf("run() = (%d, %q, %q)", code, stdout, stderr)
	}
}

func TestRunRejectsNilDependencies(t *testing.T) {
	var output bytes.Buffer
	if code := run(context.Background(), nil, nil, &output, &output); code != 64 {
		t.Fatalf("nil getenv code = %d", code)
	}
	if code := run(context.Background(), nil, os.Getenv, nil, &output); code != 64 {
		t.Fatalf("nil stdout code = %d", code)
	}
	if code := run(context.Background(), nil, os.Getenv, &output, nil); code != 64 {
		t.Fatalf("nil stderr code = %d", code)
	}
}
