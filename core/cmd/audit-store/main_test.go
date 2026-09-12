package main

import (
	"context"
	"errors"
	"testing"

	"github.com/tyj1987/broker/core/auditstore"
)

func validStoreDependencies(t *testing.T) storeDependencies {
	t.Helper()
	return storeDependencies{
		loadConfig: func(path string) (auditstore.ServiceConfig, error) {
			if path != storeConfigPath {
				t.Fatalf("config path = %q", path)
			}
			return auditstore.ServiceConfig{Version: 1}, nil
		},
		lookupUID: func(name string) (uint32, error) {
			switch name {
			case exporterUser:
				return 1001, nil
			case recoveryUser:
				return 1002, nil
			default:
				t.Fatalf("unexpected identity %q", name)
				return 0, errors.New("unexpected")
			}
		},
		newRuntime: func(_ context.Context, config auditstore.ServiceConfig, _ auditstore.CloudClientFactory) (*auditstore.Runtime, error) {
			if config.Version != 1 {
				t.Fatalf("config = %#v", config)
			}
			return &auditstore.Runtime{}, nil
		},
		serve: func(_ context.Context, _ *auditstore.Runtime, exporterUID, recoveryUID uint32, socketPath string) error {
			if exporterUID != 1001 || recoveryUID != 1002 || socketPath != auditstore.DefaultSocketPath {
				t.Fatalf("serve arguments = %d, %d, %q", exporterUID, recoveryUID, socketPath)
			}
			return nil
		},
		factory: auditstore.UnavailableCloudClientFactory{},
	}
}

func TestRunStoreUsesFixedConfigIdentityAndSocketBindings(t *testing.T) {
	code, reason := runStore(context.Background(), []string{"--config", storeConfigPath}, validStoreDependencies(t))
	if code != 0 || reason != "" {
		t.Fatalf("result = %d, %q", code, reason)
	}
}

func TestRunStoreFailsClosedWithStableReasons(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"--config", "/tmp/store.json"},
		{"--config", storeConfigPath, "extra"},
		{"--unknown"},
	} {
		if code, reason := runStore(context.Background(), args, validStoreDependencies(t)); code != 64 || reason != "usage_invalid" {
			t.Fatalf("args %q result = %d, %q", args, code, reason)
		}
	}

	tests := map[string]struct {
		mutate func(*storeDependencies)
		code   int
		reason string
	}{
		"config": {func(value *storeDependencies) {
			value.loadConfig = func(string) (auditstore.ServiceConfig, error) {
				return auditstore.ServiceConfig{}, errors.New("detail")
			}
		}, 78, "config_invalid"},
		"exporter identity": {func(value *storeDependencies) {
			value.lookupUID = func(string) (uint32, error) { return 0, errors.New("detail") }
		}, 78, "identity_unavailable"},
		"same identity": {func(value *storeDependencies) {
			value.lookupUID = func(string) (uint32, error) { return 1001, nil }
		}, 78, "identity_unavailable"},
		"cloud identity": {func(value *storeDependencies) {
			value.newRuntime = func(context.Context, auditstore.ServiceConfig, auditstore.CloudClientFactory) (*auditstore.Runtime, error) {
				return nil, auditstore.ErrServiceIdentityUnavailable
			}
		}, 78, "identity_unavailable"},
		"runtime": {func(value *storeDependencies) {
			value.newRuntime = func(context.Context, auditstore.ServiceConfig, auditstore.CloudClientFactory) (*auditstore.Runtime, error) {
				return nil, errors.New("provider detail")
			}
		}, 70, "runtime_invalid"},
		"serve": {func(value *storeDependencies) {
			value.serve = func(context.Context, *auditstore.Runtime, uint32, uint32, string) error {
				return errors.New("provider detail")
			}
		}, 70, "service_failed"},
		"dependencies": {func(value *storeDependencies) { value.loadConfig = nil }, 70, "runtime_invalid"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			dependencies := validStoreDependencies(t)
			test.mutate(&dependencies)
			code, reason := runStore(context.Background(), []string{"--config", storeConfigPath}, dependencies)
			if code != test.code || reason != test.reason || reason == "provider detail" {
				t.Fatalf("result = %d, %q", code, reason)
			}
		})
	}
}

func TestRunStoreTreatsCancellationAsCleanShutdown(t *testing.T) {
	dependencies := validStoreDependencies(t)
	ctx, cancel := context.WithCancel(context.Background())
	dependencies.serve = func(context.Context, *auditstore.Runtime, uint32, uint32, string) error {
		cancel()
		return errors.New("listener closed")
	}
	if code, reason := runStore(ctx, []string{"--config", storeConfigPath}, dependencies); code != 0 || reason != "" {
		t.Fatalf("result = %d, %q", code, reason)
	}
}
