package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"syscall"

	"github.com/tyj1987/broker/core/auditstore"
)

const (
	storeConfigPath = "/etc/secret-broker/audit/store.json"
	exporterUser    = "broker-audit-exporter"
	recoveryUser    = "broker-audit-recovery"
)

type storeDependencies struct {
	loadConfig func(string) (auditstore.ServiceConfig, error)
	lookupUID  func(string) (uint32, error)
	newRuntime func(context.Context, auditstore.ServiceConfig, auditstore.CloudClientFactory) (*auditstore.Runtime, error)
	serve      func(context.Context, *auditstore.Runtime, uint32, uint32, string) error
	factory    auditstore.CloudClientFactory
}

func defaultStoreDependencies() storeDependencies {
	return storeDependencies{
		loadConfig: auditstore.LoadServiceConfigFile,
		lookupUID:  lookupUID,
		newRuntime: auditstore.NewRuntime,
		serve:      auditstore.ServeRuntime,
		factory:    auditstore.UnavailableCloudClientFactory{},
	}
}

func runStore(ctx context.Context, args []string, dependencies storeDependencies) (int, string) {
	flags := flag.NewFlagSet("secret-broker-audit-store", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "", "fixed non-secret service configuration")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *configPath != storeConfigPath {
		return 64, "usage_invalid"
	}
	if ctx == nil || dependencies.loadConfig == nil || dependencies.lookupUID == nil ||
		dependencies.newRuntime == nil || dependencies.serve == nil || dependencies.factory == nil {
		return 70, "runtime_invalid"
	}
	config, err := dependencies.loadConfig(*configPath)
	if err != nil {
		return 78, "config_invalid"
	}
	exporterUID, err := dependencies.lookupUID(exporterUser)
	if err != nil {
		return 78, "identity_unavailable"
	}
	recoveryUID, err := dependencies.lookupUID(recoveryUser)
	if err != nil || recoveryUID == exporterUID {
		return 78, "identity_unavailable"
	}
	runtime, err := dependencies.newRuntime(ctx, config, dependencies.factory)
	if err != nil {
		if errors.Is(err, auditstore.ErrServiceIdentityUnavailable) {
			return 78, "identity_unavailable"
		}
		if errors.Is(err, auditstore.ErrServiceConfigInvalid) {
			return 78, "config_invalid"
		}
		return 70, "runtime_invalid"
	}
	if err = dependencies.serve(ctx, runtime, exporterUID, recoveryUID, auditstore.DefaultSocketPath); err != nil {
		if ctx.Err() != nil {
			return 0, ""
		}
		return 70, "service_failed"
	}
	return 0, ""
}

func lookupUID(name string) (uint32, error) {
	account, err := user.Lookup(name)
	if err != nil || account == nil {
		return 0, errors.New("identity unavailable")
	}
	value, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil || value == 0 {
		return 0, errors.New("identity unavailable")
	}
	return uint32(value), nil
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	code, reason := runStore(ctx, os.Args[1:], defaultStoreDependencies())
	if reason != "" {
		_, _ = fmt.Fprintf(os.Stderr, "audit_store_start_failed=%s\n", reason)
	}
	os.Exit(code)
}
