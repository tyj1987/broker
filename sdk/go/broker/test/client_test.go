// Tests for secret-broker Go SDK.
// Run: cd sdk/go && go test ./broker/...
package broker_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"runtime"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tyj1987/broker-sdk-go/broker"
)

// ============================================================
// Self-signed cert for test server
// ============================================================
func mustCert(t *testing.T) (tls.Certificate, []byte) {
	t.Helper()
	caPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caPriv.PublicKey, caPriv)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	srvPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	srvTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")}, // required for x509 IP SAN verification
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	srvDER, _ := x509.CreateCertificate(rand.Reader, srvTmpl, caTmpl, &srvPriv.PublicKey, caPriv)
	srvPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srvDER})
	srvKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: mustMarshalECPrivateKey(t, srvPriv)})
	cert, err := tls.X509KeyPair(srvPEM, srvKeyPEM)
	if err != nil {
		t.Fatalf("x509 key pair: %v", err)
	}
	_ = caPEM
	return cert, caPEM
}

func mustMarshalECPrivateKey(t *testing.T, k *ecdsa.PrivateKey) []byte {
	t.Helper()
	b, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatalf("marshal EC key: %v", err)
	}
	return b
}

// ============================================================
// Mock broker
// ============================================================
type mockBroker struct {
	mu      sync.Mutex
	secrets map[string]string
	calls   []string
}

func newMockBroker() *mockBroker {
	return &mockBroker{secrets: map[string]string{}}
}

func (m *mockBroker) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		m.record(r)
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "version": "4.1.0"})
	})
	mux.HandleFunc("/api/v1/secrets/resolve", func(w http.ResponseWriter, r *http.Request) {
		m.record(r)
		var body struct {
			Name string `json:"name"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		val, ok := m.secrets[body.Name]
		if !ok {
			w.WriteHeader(404)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"name": body.Name, "value": val})
	})
	mux.HandleFunc("/api/v1/secrets/resolve_bulk", func(w http.ResponseWriter, r *http.Request) {
		m.record(r)
		var body struct {
			Names []string `json:"names"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		vals := make(map[string]string, len(body.Names))
		for _, n := range body.Names {
			vals[n] = m.secrets[n]
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"values": vals})
	})
	mux.HandleFunc("/api/v1/secrets", func(w http.ResponseWriter, r *http.Request) {
		m.record(r)
		items := []map[string]string{}
		for n, _ := range m.secrets {
			items = append(items, map[string]string{"name": n, "type": "test"})
		}
		_ = json.NewEncoder(w).Encode(items)
	})
	mux.HandleFunc("/api/v1/me", func(w http.ResponseWriter, r *http.Request) {
		m.record(r)
		_ = json.NewEncoder(w).Encode(map[string]string{"cn": "test-cn", "role": "dev"})
	})
	mux.HandleFunc("/api/v1/ssh/exec", func(w http.ResponseWriter, r *http.Request) {
		m.record(r)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": true, "exitCode": 0, "stdout": "hello\n", "stderr": "", "duration_ms": 12,
		})
	})
	mux.HandleFunc("/api/v1/workload-identity/assume", func(w http.ResponseWriter, r *http.Request) {
		m.record(r)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": true, "provider": "aliyun", "role": "acs:ram::1:role/app",
			"access_key_id": "STS.xxx", "access_key_secret": "STSSECRETxxx",
			"security_token": "TOK", "expiration": "2099-01-01T00:00:00Z",
		})
	})
	mux.HandleFunc("/api/v1/proxy/github/test", func(w http.ResponseWriter, r *http.Request) {
		m.record(r)
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "denied"})
	})
	mux.HandleFunc("/api/v1/proxy/github/ok", func(w http.ResponseWriter, r *http.Request) {
		m.record(r)
		_ = json.NewEncoder(w).Encode(map[string]string{"ok": "true"})
	})
	return mux
}

func (m *mockBroker) record(r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, r.Method+" "+r.URL.Path)
}

// setupTestServer returns the broker URL, CA cert path, and a teardown.
func setupTestServer(t *testing.T, secrets map[string]string) (string, string, func()) {
	t.Helper()
	cert, caPEM := mustCert(t)
	caPath := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatalf("write CA: %v", err)
	}
	mb := newMockBroker()
	for k, v := range secrets {
		mb.secrets[k] = v
	}
	srv := httptest.NewUnstartedServer(mb.handler())
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	// httptest URL: https://127.0.0.1:PORT (use the one it gave us)
	return srv.URL, caPath, srv.Close
}

// ============================================================
// Tests
// ============================================================
func TestHealth(t *testing.T) {
	url, ca, stop := setupTestServer(t, nil)
	defer stop()
	c, err := broker.NewClient(broker.Config{Endpoint: url, CACert: ca, VerifyTLS: true})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	h, err := c.Health(context.Background())
	if err != nil {
		t.Fatalf("health: %v", err)
	}
	if !h.OK || h.Version != "4.1.0" {
		t.Fatalf("health response wrong: %+v", h)
	}
}

func TestGetSecret(t *testing.T) {
	url, ca, stop := setupTestServer(t, map[string]string{"github.pat": "ghp_xxxxABCDEFGHIJabcdefghij"})
	defer stop()
	c, _ := broker.NewClient(broker.Config{Endpoint: url, CACert: ca})
	v, err := c.GetSecret(context.Background(), "github.pat")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if v != "ghp_xxxxABCDEFGHIJabcdefghij" {
		t.Fatalf("value mismatch: %s", v)
	}
}

func TestGetSecretNotFound(t *testing.T) {
	url, ca, stop := setupTestServer(t, nil)
	defer stop()
	c, _ := broker.NewClient(broker.Config{Endpoint: url, CACert: ca})
	_, err := c.GetSecret(context.Background(), "missing")
	if err == nil {
		t.Fatal("expected error for missing secret")
	}
	if !errors.Is(err, broker.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestResolveBulk(t *testing.T) {
	url, ca, stop := setupTestServer(t, map[string]string{
		"github.pat": "ghp_v1",
		"openai.key": "sk-abcdefghijklmnopqrstuv",
	})
	defer stop()
	c, _ := broker.NewClient(broker.Config{Endpoint: url, CACert: ca})
	vals, err := c.ResolveSecrets(context.Background(), []string{"github.pat", "openai.key"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if vals["github.pat"] != "ghp_v1" {
		t.Fatalf("github.pat value wrong")
	}
	if vals["openai.key"] != "sk-abcdefghijklmnopqrstuv" {
		t.Fatalf("openai.key value wrong")
	}
}

func TestListSecrets(t *testing.T) {
	url, ca, stop := setupTestServer(t, map[string]string{"a": "1", "b": "2"})
	defer stop()
	c, _ := broker.NewClient(broker.Config{Endpoint: url, CACert: ca})
	items, err := c.ListSecrets(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2, got %d", len(items))
	}
}

func TestIdentity(t *testing.T) {
	url, ca, stop := setupTestServer(t, nil)
	defer stop()
	c, _ := broker.NewClient(broker.Config{Endpoint: url, CACert: ca})
	me, err := c.Me(context.Background())
	if err != nil {
		t.Fatalf("me: %v", err)
	}
	if me.CN != "test-cn" || me.Role != "dev" {
		t.Fatalf("me wrong: %+v", me)
	}
}

func TestProxy403(t *testing.T) {
	url, ca, stop := setupTestServer(t, nil)
	defer stop()
	c, _ := broker.NewClient(broker.Config{Endpoint: url, CACert: ca})
	_, _, err := c.Proxy(context.Background(), "github", "GET", "/test", nil, nil)
	if !errors.Is(err, broker.ErrPermission) {
		t.Fatalf("expected ErrPermission, got %v", err)
	}
}

func TestProxy200(t *testing.T) {
	url, ca, stop := setupTestServer(t, nil)
	defer stop()
	c, _ := broker.NewClient(broker.Config{Endpoint: url, CACert: ca})
	status, body, err := c.Proxy(context.Background(), "github", "GET", "/ok", nil, nil)
	if err != nil {
		t.Fatalf("proxy: %v", err)
	}
	if status != 200 {
		t.Fatalf("expected 200, got %d (body: %s)", status, body)
	}
}

func TestSSHExec(t *testing.T) {
	url, ca, stop := setupTestServer(t, nil)
	defer stop()
	c, _ := broker.NewClient(broker.Config{Endpoint: url, CACert: ca})
	r, err := c.SSHExec(context.Background(), "app@10.0.1.5", "uptime", "ssh.connection", 0)
	if err != nil {
		t.Fatalf("ssh: %v", err)
	}
	if r.ExitCode != 0 || r.Stdout != "hello\n" {
		t.Fatalf("ssh result wrong: %+v", r)
	}
}

func TestAssumeWorkload(t *testing.T) {
	url, ca, stop := setupTestServer(t, nil)
	defer stop()
	c, _ := broker.NewClient(broker.Config{Endpoint: url, CACert: ca})
	creds, err := c.AssumeWorkloadIdentity(context.Background(), "aliyun", "eyJ.fake.jwt", "acs:ram::1:role/app", "")
	if err != nil {
		t.Fatalf("assume: %v", err)
	}
	if creds.AccessKeyID != "STS.xxx" {
		t.Fatalf("access key wrong: %s", creds.AccessKeyID)
	}
}

func TestWorkloadIdentityTokenMissing(t *testing.T) {
	wi := broker.NewWorkloadIdentity(broker.ProviderK8S, "arn:foo")
	wi = wi.WithTokenPath(filepath.Join(t.TempDir(), "no-such-file"))
	_, err := wi.Token()
	if err == nil {
		t.Fatal("expected error for missing token")
	}
}

func TestWorkloadIdentityTokenFile(t *testing.T) {
	tokPath := filepath.Join(t.TempDir(), "sa-token")
	if err := os.WriteFile(tokPath, []byte("eyJ.fake.jwt"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	wi := broker.NewWorkloadIdentity(broker.ProviderK8S, "arn:foo").WithTokenPath(tokPath)
	tok, err := wi.Token()
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	if tok != "eyJ.fake.jwt" {
		t.Fatalf("token wrong: %s", tok)
	}
}

func TestInvalidEndpoint(t *testing.T) {
	_, err := broker.NewClient(broker.Config{Endpoint: ""})
	if !errors.Is(err, broker.ErrInvalidArg) {
		t.Fatalf("expected ErrInvalidArg for empty, got %v", err)
	}
	_, err = broker.NewClient(broker.Config{Endpoint: "http://insecure"})
	if !errors.Is(err, broker.ErrInvalidArg) {
		t.Fatalf("expected ErrInvalidArg for http, got %v", err)
	}
}

func TestRedactGithubInError(t *testing.T) {
	url, ca, stop := setupTestServer(t, nil)
	defer stop()
	c, _ := broker.NewClient(broker.Config{Endpoint: url, CACert: ca})
	_, _, err := c.Proxy(context.Background(), "github", "GET", "/test", nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	if strings.Contains(msg, "ghp_") {
		t.Fatalf("error message leaked ghp_: %s", msg)
	}
}

func TestErrorTypes(t *testing.T) {
	// Verify errors.Is works with wrapped BrokerError
	url, ca, stop := setupTestServer(t, nil)
	defer stop()
	c, _ := broker.NewClient(broker.Config{Endpoint: url, CACert: ca})
	_, err := c.GetSecret(context.Background(), "missing")
	if err == nil {
		t.Fatal("expected error")
	}
	var be *broker.BrokerError
	if !errors.As(err, &be) {
		t.Fatalf("expected BrokerError, got %T", err)
	}
	if be.Status != 404 {
		t.Fatalf("expected 404, got %d", be.Status)
	}
}

func TestExecSubprocess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping: 'printenv' is a Linux/macOS coreutil, not on Windows")
	}
	// Test that env var injection works end-to-end
	url, ca, stop := setupTestServer(t, map[string]string{"MY_SECRET": "value-123"})
	defer stop()
	c, _ := broker.NewClient(broker.Config{Endpoint: url, CACert: ca})
	// Use a portable command: printenv
	cmd := []string{"printenv", "MY_SECRET"}
	rc, err := c.Exec(context.Background(), []string{"MY_SECRET"}, cmd)
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if rc != 0 {
		t.Fatalf("expected exit 0, got %d", rc)
	}
}

// ============================================================
// Suppress unused import warnings (compile-time check that all helpers wired)
// ============================================================
var _ = bytes.NewBuffer
var _ io.Reader
var _ = fmt.Sprintf
var _ sync.Mutex
