package main

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/tyj1987/broker/core/githubsigner"
)

type testListener struct{ closed bool }

func (*testListener) Accept() (net.Conn, error) { return nil, errors.New("unused") }
func (listener *testListener) Close() error     { listener.closed = true; return nil }
func (*testListener) Addr() net.Addr            { return testAddr("test") }

type testAddr string

func (address testAddr) Network() string { return string(address) }
func (address testAddr) String() string  { return string(address) }

func validDependencies(listener *testListener) dependencies {
	return dependencies{
		loadConfig: func(string) (githubsigner.ServiceConfig, error) {
			return githubsigner.ServiceConfig{
				Version: 1, ProviderProfileID: "profile",
				Bindings:                  []githubsigner.Binding{{AccountRef: "account", Environment: "staging", ClientID: "123"}},
				AuthorityGenerationSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			}, nil
		},
		lookupUID: func(string) (uint32, error) { return 1000, nil },
		newPeer: func(uint32) (githubsigner.PeerAuthorizer, error) {
			return githubsigner.PeerAuthorizerFunc(func(context.Context, net.Conn) error { return nil }), nil
		},
		newSigner: func(context.Context, githubsigner.ServiceConfig) (githubsigner.DigestSigner, error) {
			return githubsigner.DigestSignerFunc(func(context.Context, githubsigner.DigestRequest) ([]byte, error) {
				return make([]byte, githubsigner.MinSignatureBytes), nil
			}), nil
		},
		listener: func(string, string) (net.Listener, error) { return listener, nil },
		serve:    func(context.Context, *githubsigner.Server, net.Listener) error { return nil },
	}
}

func TestRunServesInjectedBackendAndClosesListener(t *testing.T) {
	listener := &testListener{}
	deps := validDependencies(listener)
	deps.listener = func(name, path string) (net.Listener, error) {
		if name != socketName || path != socketPath {
			t.Fatalf("activation = (%q, %q)", name, path)
		}
		return listener, nil
	}
	code, reason := run(context.Background(), []string{"--config", configPath}, deps)
	if code != 0 || reason != "" || !listener.closed {
		t.Fatalf("run = (%d, %q), closed=%v", code, reason, listener.closed)
	}
}

func TestRunFailsClosedByStage(t *testing.T) {
	base := func() dependencies { return validDependencies(&testListener{}) }
	tests := []struct {
		name   string
		args   []string
		edit   func(*dependencies)
		code   int
		reason string
	}{
		{"usage", nil, func(*dependencies) {}, 64, "usage_invalid"},
		{"runtime", []string{"--config", configPath}, func(value *dependencies) { value.loadConfig = nil }, 70, "runtime_invalid"},
		{"config", []string{"--config", configPath}, func(value *dependencies) {
			value.loadConfig = func(string) (githubsigner.ServiceConfig, error) {
				return githubsigner.ServiceConfig{}, errors.New("no")
			}
		}, 78, "config_invalid"},
		{"uid", []string{"--config", configPath}, func(value *dependencies) {
			value.lookupUID = func(string) (uint32, error) { return 0, errors.New("no") }
		}, 78, "peer_identity_unavailable"},
		{"peer", []string{"--config", configPath}, func(value *dependencies) {
			value.newPeer = func(uint32) (githubsigner.PeerAuthorizer, error) { return nil, errors.New("no") }
		}, 78, "peer_identity_unavailable"},
		{"backend", []string{"--config", configPath}, func(value *dependencies) {
			value.newSigner = func(context.Context, githubsigner.ServiceConfig) (githubsigner.DigestSigner, error) {
				return nil, errors.New("no")
			}
		}, 78, "signing_identity_unavailable"},
		{"activation", []string{"--config", configPath}, func(value *dependencies) {
			value.listener = func(string, string) (net.Listener, error) { return nil, errors.New("no") }
		}, 78, "socket_activation_invalid"},
		{"serve", []string{"--config", configPath}, func(value *dependencies) {
			value.serve = func(context.Context, *githubsigner.Server, net.Listener) error { return errors.New("no") }
		}, 70, "service_failed"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			deps := base()
			test.edit(&deps)
			code, reason := run(context.Background(), test.args, deps)
			if code != test.code || reason != test.reason {
				t.Fatalf("run = (%d, %q)", code, reason)
			}
		})
	}
}

func TestDefaultBackendIsUnavailable(t *testing.T) {
	if signer, err := defaultDependencies().newSigner(context.Background(), githubsigner.ServiceConfig{}); err == nil || signer != nil {
		t.Fatal("default backend did not fail closed")
	}
}
