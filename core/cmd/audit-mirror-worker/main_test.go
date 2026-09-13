package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/tyj1987/broker/core/auditanchor"
	"github.com/tyj1987/broker/core/auditmirror"
	"github.com/tyj1987/broker/core/auditmirrorworker"
)

type testListener struct{ closed bool }

func (*testListener) Accept() (net.Conn, error) { return nil, errors.New("unused") }
func (listener *testListener) Close() error     { listener.closed = true; return nil }
func (*testListener) Addr() net.Addr            { return testAddr("test") }

type testAddr string

func (address testAddr) Network() string { return string(address) }
func (address testAddr) String() string  { return string(address) }

type fakeBackend struct{ binding auditmirror.Binding }

func (backend *fakeBackend) Binding() auditmirror.Binding { return backend.binding }
func (*fakeBackend) Inspect(context.Context, auditmirror.InspectRequest) (auditmirror.LockState, error) {
	return auditmirror.LockState{}, nil
}
func (*fakeBackend) Create(context.Context, auditmirror.CreateRequest) (auditmirror.CreateResult, error) {
	return auditmirror.CreateResult{}, nil
}
func (*fakeBackend) Read(context.Context, auditmirror.ReadRequest) (auditmirror.ReadResult, error) {
	return auditmirror.ReadResult{}, nil
}
func (*fakeBackend) List(context.Context, auditmirror.ListRequest) (auditmirror.ListResult, error) {
	return auditmirror.ListResult{}, nil
}
func (*fakeBackend) Retention(context.Context, auditmirror.ReadRequest) (auditmirror.RetentionResult, error) {
	return auditmirror.RetentionResult{}, nil
}

func validDependencies(t *testing.T, listener *testListener) dependencies {
	t.Helper()
	backend, _, _, _ := workerCommandHarness(t)
	return dependencies{
		loadConfig: func(path string) (auditmirrorworker.Config, error) {
			if path != configPath {
				t.Fatalf("config path = %q", path)
			}
			return auditmirrorworker.Config{StreamID: "broker-production"}, nil
		},
		lookupUID: func(name string) (uint32, error) {
			switch name {
			case workerUser:
				return 2204, nil
			case storeUser:
				return 2203, nil
			default:
				t.Fatalf("identity = %q", name)
				return 0, errors.New("unexpected")
			}
		},
		currentUID: func() uint32 { return 2204 },
		newPeer: func(uid uint32) (auditmirror.PeerAuthorizer, error) {
			if uid != 2203 {
				t.Fatalf("uid = %d", uid)
			}
			return auditmirror.PeerAuthorizerFunc(func(context.Context, net.Conn) error { return nil }), nil
		},
		newRuntime: func(context.Context, auditmirrorworker.Config, auditmirrorworker.COSClientFactory) (boundBackend, error) {
			return backend, nil
		},
		factory: auditmirrorworker.UnavailableCOSClientFactory{},
		listener: func(name, path string) (net.Listener, error) {
			if name != socketName || path != socketPath {
				t.Fatalf("socket = %q, %q", name, path)
			}
			return listener, nil
		},
		serve: func(context.Context, *auditmirror.Server, net.Listener) error { return nil },
	}
}

func workerCommandHarness(t *testing.T) (*fakeBackend, auditmirror.Binding, [32]byte, auditmirrorworker.Config) {
	t.Helper()
	var generation [32]byte
	generation[0] = 1
	binding, err := auditmirror.NewBinding("broker-production", "audit-anchors/v1", "tencent-mirror-production", generation)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeBackend{binding: binding}, binding, generation, auditmirrorworker.Config{}
}

func validCommandConfig(t *testing.T) auditmirrorworker.Config {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return auditmirrorworker.Config{
		StreamID: "broker-production", Prefix: "audit-anchors/v1", ProfileID: "tencent-mirror-production",
		Bucket: "broker-audit-mirror-1250000000", Region: "ap-singapore",
		TrustedKeys: map[string]auditanchor.TrustedSigningKey{
			"worker-key": {PublicKey: &privateKey.PublicKey, ValidFromSequence: 1},
		},
	}
}

func TestRunUsesFixedConfigPeerAndActivatedSocket(t *testing.T) {
	listener := &testListener{}
	code, reason := run(context.Background(), []string{"--config", configPath}, validDependencies(t, listener))
	if code != 0 || reason != "" || !listener.closed {
		t.Fatalf("result = %d, %q, closed=%v", code, reason, listener.closed)
	}
}

func TestDefaultCommandFailsClosedWithoutCloudFactory(t *testing.T) {
	deps := defaultDependencies()
	if client, err := deps.factory.NewCOS(context.Background(), auditmirrorworker.COSProviderBinding{}); client != nil || !errors.Is(err, auditmirrorworker.ErrIdentityUnavailable) {
		t.Fatalf("client = %#v, %v", client, err)
	}
	testDeps := validDependencies(t, &testListener{})
	testDeps.newRuntime = func(ctx context.Context, config auditmirrorworker.Config, factory auditmirrorworker.COSClientFactory) (boundBackend, error) {
		return auditmirrorworker.NewRuntime(ctx, config, factory)
	}
	testDeps.factory = auditmirrorworker.UnavailableCOSClientFactory{}
	listenerCalled := false
	testDeps.listener = func(string, string) (net.Listener, error) {
		listenerCalled = true
		return nil, errors.New("must not be called")
	}
	config := validCommandConfig(t)
	testDeps.loadConfig = func(string) (auditmirrorworker.Config, error) { return config, nil }
	if code, reason := run(context.Background(), []string{"--config", configPath}, testDeps); code != 78 || reason != "cloud_identity_unavailable" || listenerCalled {
		t.Fatalf("default boundary = %d, %q, listener=%v", code, reason, listenerCalled)
	}
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"cos-go-sdk", "tencentcloud", "metadata", "credential_file", "os.Getenv"} {
		if strings.Contains(string(source), forbidden) {
			t.Fatalf("command contains forbidden identity capability %q", forbidden)
		}
	}
}

func TestRunFailsClosedWithStableReasons(t *testing.T) {
	base := func() dependencies { return validDependencies(t, &testListener{}) }
	for _, args := range [][]string{nil, {"--config", "/tmp/worker.json"}, {"--config", configPath, "extra"}, {"--unknown"}} {
		if code, reason := run(context.Background(), args, base()); code != 64 || reason != "usage_invalid" {
			t.Fatalf("args %q = %d, %q", args, code, reason)
		}
	}
	tests := map[string]struct {
		mutate func(*dependencies)
		code   int
		reason string
	}{
		"config": {func(value *dependencies) {
			value.loadConfig = func(string) (auditmirrorworker.Config, error) {
				return auditmirrorworker.Config{}, errors.New("detail")
			}
		}, 78, "config_invalid"},
		"worker identity": {func(value *dependencies) {
			value.currentUID = func() uint32 { return 9999 }
		}, 78, "worker_identity_unavailable"},
		"identity": {func(value *dependencies) {
			value.lookupUID = func(name string) (uint32, error) {
				if name == workerUser {
					return 2204, nil
				}
				return 0, errors.New("detail")
			}
		}, 78, "peer_identity_unavailable"},
		"same identity": {func(value *dependencies) {
			value.lookupUID = func(string) (uint32, error) { return 2204, nil }
		}, 78, "peer_identity_unavailable"},
		"peer": {func(value *dependencies) {
			value.newPeer = func(uint32) (auditmirror.PeerAuthorizer, error) { return nil, errors.New("detail") }
		}, 78, "peer_identity_unavailable"},
		"cloud": {func(value *dependencies) {
			value.newRuntime = func(context.Context, auditmirrorworker.Config, auditmirrorworker.COSClientFactory) (boundBackend, error) {
				return nil, errors.New("provider detail")
			}
		}, 78, "cloud_identity_unavailable"},
		"socket": {func(value *dependencies) {
			value.listener = func(string, string) (net.Listener, error) { return nil, errors.New("detail") }
		}, 78, "socket_activation_invalid"},
		"serve": {func(value *dependencies) {
			value.serve = func(context.Context, *auditmirror.Server, net.Listener) error { return errors.New("detail") }
		}, 70, "service_failed"},
		"deps":               {func(value *dependencies) { value.newRuntime = nil }, 70, "runtime_invalid"},
		"factory dependency": {func(value *dependencies) { value.factory = nil }, 70, "runtime_invalid"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			deps := base()
			test.mutate(&deps)
			code, reason := run(context.Background(), []string{"--config", configPath}, deps)
			if code != test.code || reason != test.reason || reason == "provider detail" {
				t.Fatalf("result = %d, %q", code, reason)
			}
		})
	}
}

func TestRunTreatsCancellationAsCleanShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	deps := validDependencies(t, &testListener{})
	deps.serve = func(context.Context, *auditmirror.Server, net.Listener) error {
		cancel()
		return errors.New("closed")
	}
	if code, reason := run(ctx, []string{"--config", configPath}, deps); code != 0 || reason != "" {
		t.Fatalf("result = %d, %q", code, reason)
	}
}
