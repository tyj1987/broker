package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/tyj1987/broker/core/auditstore"
)

const healthConfigPath = "/etc/secret-broker/audit/store.json"

type healthDependencies struct {
	loadConfig func(string) (auditstore.ServiceConfig, error)
	query      func(context.Context, string, string) (auditstore.Health, error)
	output     io.Writer
}

func runHealth(ctx context.Context, args []string, dependencies healthDependencies) (int, string) {
	flags := flag.NewFlagSet("secret-broker-audit-store-health", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	socketPath := flags.String("socket", "", "fixed audit-store socket")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *socketPath != auditstore.DefaultSocketPath {
		return 64, "usage_invalid"
	}
	if ctx == nil || dependencies.loadConfig == nil || dependencies.query == nil || dependencies.output == nil {
		return 70, "runtime_invalid"
	}
	config, err := dependencies.loadConfig(healthConfigPath)
	if err != nil {
		return 78, "config_invalid"
	}
	queryContext, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	health, err := dependencies.query(queryContext, *socketPath, config.StreamID)
	if err != nil {
		return 69, "store_unavailable"
	}
	if !auditstore.ValidHealth(health) {
		return 70, "response_invalid"
	}
	encoded, err := json.Marshal(struct {
		Status         string `json:"status"`
		LockContract   string `json:"lock_contract"`
		MirrorState    string `json:"mirror_state"`
		CommonSequence int64  `json:"common_sequence"`
		ReasonCode     string `json:"reason_code"`
	}{
		Status: health.Status, LockContract: health.LockContract,
		MirrorState: health.MirrorState, CommonSequence: health.CommonSequence,
		ReasonCode: health.ReasonCode,
	})
	if err != nil || len(encoded) > 1023 {
		return 70, "response_invalid"
	}
	encoded = append(encoded, '\n')
	if written, err := dependencies.output.Write(encoded); err != nil || written != len(encoded) {
		return 70, "response_failed"
	}
	return 0, ""
}

func main() {
	code, reason := runHealth(context.Background(), os.Args[1:], healthDependencies{
		loadConfig: auditstore.LoadServiceConfigFile,
		query:      auditstore.QueryHealth,
		output:     os.Stdout,
	})
	if reason != "" {
		_, _ = fmt.Fprintf(os.Stderr, "audit_store_health_failed=%s\n", reason)
	}
	os.Exit(code)
}
