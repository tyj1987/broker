package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/tyj1987/broker/core/auditanchor"
)

type stubListener struct{ closed bool }

func (*stubListener) Accept() (net.Conn, error) { return nil, errors.New("unused") }
func (listener *stubListener) Close() error     { listener.closed = true; return nil }
func (*stubListener) Addr() net.Addr            { return &net.UnixAddr{Name: signerSocketPath, Net: "unix"} }

func validCommandConfig(t *testing.T) auditanchor.SignerServiceConfig {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	digest := sha256.Sum256(der)
	return auditanchor.SignerServiceConfig{
		Version:           auditanchor.SignerServiceConfigVersion,
		ProviderProfileID: "alibaba-kms-audit-production",
		StateProfileID:    "audit-sequence-state-production",
		ECSRAMRoleName:    "broker-audit-kms",
		KMSEndpoint:       "kst-audit01.cryptoservice.kms.aliyuncs.com",
		KMSCASHA256:       strings.Repeat("a", 64),
		KMSAllowedCIDRs:   []netip.Prefix{netip.MustParsePrefix("10.42.7.8/32")},
		Anchor:            auditanchor.Config{Algorithm: "ecdsa-p256-sha256", KeyID: "kms-audit-key-1", StreamID: "production-audit"},
		KeyVersionID:      "kms-audit-key-version-1",
		PublicKey:         &privateKey.PublicKey,
		PublicKeySHA256:   hex.EncodeToString(digest[:]),
	}
}

func validCommandDependencies(t *testing.T, listener *stubListener) signerDependencies {
	t.Helper()
	return signerDependencies{
		loadConfig: func(path string) (auditanchor.SignerServiceConfig, error) {
			if path != signerConfigPath {
				t.Fatalf("config path = %q", path)
			}
			return validCommandConfig(t), nil
		},
		lookupUID: func(name string) (uint32, error) {
			switch name {
			case signerUser:
				return 2101, nil
			case exporterUser:
				return 2102, nil
			default:
				return 0, errors.New("unexpected identity")
			}
		},
		currentUID: func() uint32 { return 2101 },
		newPeer: func(uid uint32) (auditanchor.PeerAuthorizer, error) {
			if uid != 2102 {
				t.Fatalf("peer uid = %d", uid)
			}
			return auditanchor.PeerAuthorizerFunc(func(context.Context, net.Conn) error { return nil }), nil
		},
		newBackends: func(_ context.Context, config auditanchor.SignerServiceConfig) (auditanchor.Signer, auditanchor.AnchorAuthorizer, error) {
			if config.Anchor.StreamID != "production-audit" || config.KeyVersionID != "kms-audit-key-version-1" {
				t.Fatalf("unexpected backend config: %#v", config)
			}
			return auditanchor.SignerFunc(func(context.Context, auditanchor.SignRequest) ([]byte, error) {
				return make([]byte, 64), nil
			}), auditanchor.AnchorAuthorizerFunc(func(context.Context, auditanchor.SignRequest) error { return nil }), nil
		},
		listener: func(name, path string) (net.Listener, error) {
			if name != signerSocketName || path != signerSocketPath {
				t.Fatalf("socket binding = %q %q", name, path)
			}
			return listener, nil
		},
		serve: func(_ context.Context, server *auditanchor.Server, received net.Listener) error {
			if server == nil || server.Config.StreamID != "production-audit" || received != listener {
				t.Fatal("invalid signer server composition")
			}
			return nil
		},
	}
}

func TestRunAuditSignerComposesExactIsolatedBoundary(t *testing.T) {
	listener := &stubListener{}
	code, reason := runAuditSigner(context.Background(), []string{"--config", signerConfigPath}, validCommandDependencies(t, listener))
	if code != 0 || reason != "" || !listener.closed {
		t.Fatalf("run = (%d, %q), closed=%v", code, reason, listener.closed)
	}
}

func TestRunAuditSignerRejectsArgumentsAndIdentityDrift(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"--config", "/tmp/signer.json"},
		{"--config", signerConfigPath, "extra"},
	} {
		if code, reason := runAuditSigner(context.Background(), args, signerDependencies{}); code != 64 || reason != "usage_invalid" {
			t.Fatalf("args %#v = (%d, %q)", args, code, reason)
		}
	}

	listener := &stubListener{}
	deps := validCommandDependencies(t, listener)
	deps.currentUID = func() uint32 { return 9999 }
	if code, reason := runAuditSigner(context.Background(), []string{"--config", signerConfigPath}, deps); code != 78 || reason != "signer_identity_unavailable" {
		t.Fatalf("wrong signer identity = (%d, %q)", code, reason)
	}

	deps = validCommandDependencies(t, listener)
	deps.lookupUID = func(string) (uint32, error) { return 2101, nil }
	if code, reason := runAuditSigner(context.Background(), []string{"--config", signerConfigPath}, deps); code != 78 || reason != "peer_identity_unavailable" {
		t.Fatalf("colliding identity = (%d, %q)", code, reason)
	}
}

func TestRunAuditSignerFailsClosedBeforeSocketActivation(t *testing.T) {
	listener := &stubListener{}
	deps := validCommandDependencies(t, listener)
	deps.newBackends = func(context.Context, auditanchor.SignerServiceConfig) (auditanchor.Signer, auditanchor.AnchorAuthorizer, error) {
		return nil, nil, errors.New("provider detail")
	}
	if code, reason := runAuditSigner(context.Background(), []string{"--config", signerConfigPath}, deps); code != 78 || reason != "signing_authority_unavailable" {
		t.Fatalf("backend unavailable = (%d, %q)", code, reason)
	}
	if listener.closed {
		t.Fatal("socket listener was touched before signing authority existed")
	}

	defaultDeps := defaultSignerDependencies()
	if signer, anchors, err := defaultDeps.newBackends(context.Background(), validCommandConfig(t)); err == nil || signer != nil || anchors != nil {
		t.Fatal("default command unexpectedly exposes a signing or state authority")
	}
}

func TestRunAuditSignerReturnsStableStartupFailures(t *testing.T) {
	args := []string{"--config", signerConfigPath}
	newDeps := func() signerDependencies { return validCommandDependencies(t, &stubListener{}) }
	tests := map[string]struct {
		mutate func(*signerDependencies) context.Context
		code   int
		reason string
	}{
		"nil context": {
			mutate: func(*signerDependencies) context.Context { return nil }, code: 70, reason: "runtime_invalid",
		},
		"missing dependency": {
			mutate: func(deps *signerDependencies) context.Context { deps.serve = nil; return context.Background() }, code: 70, reason: "runtime_invalid",
		},
		"config load": {
			mutate: func(deps *signerDependencies) context.Context {
				deps.loadConfig = func(string) (auditanchor.SignerServiceConfig, error) {
					return auditanchor.SignerServiceConfig{}, errors.New("detail")
				}
				return context.Background()
			}, code: 78, reason: "config_invalid",
		},
		"config validation": {
			mutate: func(deps *signerDependencies) context.Context {
				deps.loadConfig = func(string) (auditanchor.SignerServiceConfig, error) { return auditanchor.SignerServiceConfig{}, nil }
				return context.Background()
			}, code: 78, reason: "config_invalid",
		},
		"signer lookup": {
			mutate: func(deps *signerDependencies) context.Context {
				deps.lookupUID = func(string) (uint32, error) { return 0, errors.New("detail") }
				return context.Background()
			}, code: 78, reason: "signer_identity_unavailable",
		},
		"exporter lookup": {
			mutate: func(deps *signerDependencies) context.Context {
				deps.lookupUID = func(name string) (uint32, error) {
					if name == signerUser {
						return 2101, nil
					}
					return 0, errors.New("detail")
				}
				return context.Background()
			}, code: 78, reason: "peer_identity_unavailable",
		},
		"peer authorizer": {
			mutate: func(deps *signerDependencies) context.Context {
				deps.newPeer = func(uint32) (auditanchor.PeerAuthorizer, error) { return nil, errors.New("detail") }
				return context.Background()
			}, code: 78, reason: "peer_identity_unavailable",
		},
		"nil signer": {
			mutate: func(deps *signerDependencies) context.Context {
				deps.newBackends = func(context.Context, auditanchor.SignerServiceConfig) (auditanchor.Signer, auditanchor.AnchorAuthorizer, error) {
					return nil, auditanchor.AnchorAuthorizerFunc(func(context.Context, auditanchor.SignRequest) error { return nil }), nil
				}
				return context.Background()
			}, code: 78, reason: "signing_authority_unavailable",
		},
		"socket activation": {
			mutate: func(deps *signerDependencies) context.Context {
				deps.listener = func(string, string) (net.Listener, error) { return nil, errors.New("detail") }
				return context.Background()
			}, code: 78, reason: "socket_activation_invalid",
		},
		"service failure": {
			mutate: func(deps *signerDependencies) context.Context {
				deps.serve = func(context.Context, *auditanchor.Server, net.Listener) error { return errors.New("detail") }
				return context.Background()
			}, code: 70, reason: "service_failed",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			deps := newDeps()
			ctx := test.mutate(&deps)
			code, reason := runAuditSigner(ctx, args, deps)
			if code != test.code || reason != test.reason {
				t.Fatalf("run = (%d, %q), want (%d, %q)", code, reason, test.code, test.reason)
			}
		})
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	deps := newDeps()
	deps.serve = func(context.Context, *auditanchor.Server, net.Listener) error { return errors.New("stopped") }
	if code, reason := runAuditSigner(cancelled, args, deps); code != 0 || reason != "" {
		t.Fatalf("cancelled service = (%d, %q)", code, reason)
	}

	if uid, err := lookupUID("a-user-that-must-not-exist"); err == nil || uid != 0 {
		t.Fatal("unknown local identity was accepted")
	}
}
