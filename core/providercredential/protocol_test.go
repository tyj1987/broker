package providercredential

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

var protocolTestNow = time.Unix(2_000_000_000, 0).UTC()

const (
	testExecutionID    = "12345678-1234-4123-8123-123456789abc"
	testRequestBinding = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

type memoryConn struct {
	input    *bytes.Reader
	output   bytes.Buffer
	deadline time.Time
}

func newMemoryConn(input string) *memoryConn {
	return &memoryConn{input: bytes.NewReader([]byte(input))}
}
func (connection *memoryConn) Read(value []byte) (int, error)  { return connection.input.Read(value) }
func (connection *memoryConn) Write(value []byte) (int, error) { return connection.output.Write(value) }
func (*memoryConn) Close() error                               { return nil }
func (*memoryConn) LocalAddr() net.Addr                        { return testAddr("local") }
func (*memoryConn) RemoteAddr() net.Addr                       { return testAddr("remote") }
func (connection *memoryConn) SetDeadline(value time.Time) error {
	connection.deadline = value
	return nil
}
func (*memoryConn) SetReadDeadline(time.Time) error  { return nil }
func (*memoryConn) SetWriteDeadline(time.Time) error { return nil }

type testAddr string

func (address testAddr) Network() string { return "test" }
func (address testAddr) String() string  { return string(address) }

func requestLine(t *testing.T, mutate func(map[string]any)) string {
	t.Helper()
	request := map[string]any{
		"version": 2, "provider": "deepseek", "operation_id": "models.list",
		"account_ref": "deepseek-primary", "environment": "production",
		"resource_ref": "model-catalog", "execution_id": testExecutionID,
		"request_binding": testRequestBinding,
	}
	if mutate != nil {
		mutate(request)
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded) + "\n"
}

func errorCode(err error) string {
	var protocolError *ProtocolError
	if errors.As(err, &protocolError) {
		return protocolError.Code
	}
	return ""
}

func testServer(t *testing.T, issuer LeaseIssuer, bindings BindingAuthorizer, peers PeerAuthorizer) *Server {
	t.Helper()
	server, err := NewServer(issuer, bindings, peers)
	if err != nil {
		t.Fatal(err)
	}
	server.Clock = func() time.Time { return protocolTestNow }
	return server
}

func TestServeConnIssuesOnlyExactBoundLease(t *testing.T) {
	var backendRequest LeaseRequest
	peerCalls, bindingCalls := 0, 0
	server := testServer(t,
		LeaseIssuerFunc(func(_ context.Context, request LeaseRequest) (Lease, error) {
			backendRequest = request
			return Lease{Token: "ephemeral-token", ExpiresAt: protocolTestNow.Add(4 * time.Minute)}, nil
		}),
		BindingAuthorizerFunc(func(_ context.Context, request LeaseRequest) error {
			bindingCalls++
			if request.ResourceRef != "model-catalog" {
				t.Fatal("unexpected binding")
			}
			return nil
		}),
		PeerAuthorizerFunc(func(_ context.Context, connection net.Conn) error {
			peerCalls++
			if connection.RemoteAddr().String() != "remote" {
				t.Fatal("unexpected peer")
			}
			return nil
		}),
	)
	connection := newMemoryConn(requestLine(t, nil))
	if err := server.ServeConn(context.Background(), connection); err != nil {
		t.Fatal(err)
	}
	if peerCalls != 1 || bindingCalls != 1 || backendRequest.Provider != "deepseek" ||
		backendRequest.OperationID != "models.list" || backendRequest.AccountRef != "deepseek-primary" ||
		backendRequest.Environment != "production" || backendRequest.ResourceRef != "model-catalog" {
		t.Fatal("mandatory exact binding was not preserved")
	}
	if backendRequest.ExecutionID != testExecutionID || backendRequest.RequestBinding != testRequestBinding {
		t.Fatal("execution binding was not preserved")
	}
	if !connection.deadline.Equal(protocolTestNow.Add(DefaultDeadline)) {
		t.Fatal("deadline was not applied")
	}
	var response wireResponse
	if err := json.Unmarshal(connection.output.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Token != "ephemeral-token" || response.ExpiresAt != protocolTestNow.Add(4*time.Minute).Format(time.RFC3339Nano) {
		t.Fatalf("unexpected response %#v", response)
	}
	if response.ExecutionID != testExecutionID || response.RequestBinding != testRequestBinding {
		t.Fatal("response did not echo the execution binding")
	}
}

func TestRequestValidationFailsClosed(t *testing.T) {
	issuerCalls := 0
	issuer := LeaseIssuerFunc(func(context.Context, LeaseRequest) (Lease, error) {
		issuerCalls++
		return Lease{Token: "ephemeral-token", ExpiresAt: protocolTestNow.Add(time.Minute)}, nil
	})
	allowBinding := BindingAuthorizerFunc(func(context.Context, LeaseRequest) error { return nil })
	allowPeer := PeerAuthorizerFunc(func(context.Context, net.Conn) error { return nil })
	tests := map[string]string{
		"no newline":              strings.TrimSuffix(requestLine(t, nil), "\n"),
		"crlf":                    strings.TrimSuffix(requestLine(t, nil), "\n") + "\r\n",
		"trailing":                requestLine(t, nil) + "{}\n",
		"oversized":               strings.Repeat("x", MaxRequestBytes+1) + "\n",
		"unknown field":           requestLine(t, func(value map[string]any) { value["credential"] = "canary" }),
		"wrong version":           requestLine(t, func(value map[string]any) { value["version"] = 1 }),
		"unknown provider":        requestLine(t, func(value map[string]any) { value["provider"] = "github" }),
		"bad operation":           requestLine(t, func(value map[string]any) { value["operation_id"] = "../models" }),
		"unregistered operation":  requestLine(t, func(value map[string]any) { value["operation_id"] = "tokens.issue" }),
		"bad account":             requestLine(t, func(value map[string]any) { value["account_ref"] = "../root" }),
		"bad environment":         requestLine(t, func(value map[string]any) { value["environment"] = "Production" }),
		"bad execution id":        requestLine(t, func(value map[string]any) { value["execution_id"] = "wrong" }),
		"bad request binding":     requestLine(t, func(value map[string]any) { value["request_binding"] = "wrong" }),
		"bad deepseek resource":   requestLine(t, func(value map[string]any) { value["resource_ref"] = "chat" }),
		"bad cloudflare resource": requestLine(t, func(value map[string]any) { value["provider"] = "cloudflare"; value["resource_ref"] = "zone" }),
		"bad docker resource":     requestLine(t, func(value map[string]any) { value["provider"] = "docker"; value["resource_ref"] = "library" }),
	}
	for name, line := range tests {
		t.Run(name, func(t *testing.T) {
			err := testServer(t, issuer, allowBinding, allowPeer).ServeConn(context.Background(), newMemoryConn(line))
			if errorCode(err) != "request_invalid" {
				t.Fatalf("unexpected error %v", err)
			}
		})
	}
	if issuerCalls != 0 {
		t.Fatal("issuer was called for invalid request")
	}
}

func TestSupportedProviderResourceShapes(t *testing.T) {
	tests := []map[string]string{
		{"provider": "deepseek", "resource": "model-catalog"},
		{"provider": "cloudflare", "resource": "0123456789abcdef0123456789abcdef"},
		{"provider": "cloudflare-dns", "resource": "abcdef0123456789abcdef0123456789"},
		{"provider": "docker", "resource": "library/alpine"},
	}
	for _, test := range tests {
		line := requestLine(t, func(value map[string]any) {
			value["provider"], value["resource_ref"] = test["provider"], test["resource"]
			switch test["provider"] {
			case "cloudflare":
				value["operation_id"] = "zones.list"
			case "cloudflare-dns":
				value["provider"] = "cloudflare"
				value["operation_id"] = "dns.records.list"
			case "docker":
				value["operation_id"] = "repository.tags.list"
			}
		})
		server := testServer(t,
			LeaseIssuerFunc(func(context.Context, LeaseRequest) (Lease, error) {
				return Lease{Token: "ephemeral-token", ExpiresAt: protocolTestNow.Add(time.Minute)}, nil
			}),
			BindingAuthorizerFunc(func(context.Context, LeaseRequest) error { return nil }),
			PeerAuthorizerFunc(func(context.Context, net.Conn) error { return nil }),
		)
		if err := server.ServeConn(context.Background(), newMemoryConn(line)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPeerBindingAndIssuerFailuresDoNotLeak(t *testing.T) {
	tests := map[string]struct {
		peer, binding, issuer error
		code                  string
	}{
		"peer":    {peer: errors.New("canary-peer-secret"), code: "peer_denied"},
		"binding": {binding: errors.New("canary-binding-secret"), code: "binding_denied"},
		"issuer":  {issuer: errors.New("canary-vault-secret"), code: "lease_failed"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			server := testServer(t,
				LeaseIssuerFunc(func(context.Context, LeaseRequest) (Lease, error) { return Lease{}, test.issuer }),
				BindingAuthorizerFunc(func(context.Context, LeaseRequest) error { return test.binding }),
				PeerAuthorizerFunc(func(context.Context, net.Conn) error { return test.peer }),
			)
			connection := newMemoryConn(requestLine(t, nil))
			err := server.ServeConn(context.Background(), connection)
			if errorCode(err) != test.code || strings.Contains(err.Error(), "canary") || connection.output.Len() != 0 {
				t.Fatalf("failure leaked detail or returned partial output: %v", err)
			}
		})
	}
}

func TestLeaseValidation(t *testing.T) {
	tests := map[string]Lease{
		"short token":       {Token: "short", ExpiresAt: protocolTestNow.Add(time.Minute)},
		"long token":        {Token: strings.Repeat("x", MaxTokenBytes+1), ExpiresAt: protocolTestNow.Add(time.Minute)},
		"control character": {Token: "token\nvalue", ExpiresAt: protocolTestNow.Add(time.Minute)},
		"expired":           {Token: "valid-token", ExpiresAt: protocolTestNow},
		"overlong":          {Token: "valid-token", ExpiresAt: protocolTestNow.Add(MaxLeaseLifetime + time.Nanosecond)},
	}
	for name, lease := range tests {
		t.Run(name, func(t *testing.T) {
			server := testServer(t,
				LeaseIssuerFunc(func(context.Context, LeaseRequest) (Lease, error) { return lease, nil }),
				BindingAuthorizerFunc(func(context.Context, LeaseRequest) error { return nil }),
				PeerAuthorizerFunc(func(context.Context, net.Conn) error { return nil }),
			)
			connection := newMemoryConn(requestLine(t, nil))
			if err := server.ServeConn(context.Background(), connection); errorCode(err) != "lease_invalid" || connection.output.Len() != 0 {
				t.Fatalf("invalid lease accepted or leaked: %v", err)
			}
		})
	}
}

func TestBindingSetRequiresExactTuple(t *testing.T) {
	binding := Binding{Provider: "deepseek", OperationID: "models.list", AccountRef: "deepseek-primary", Environment: "production", ResourceRef: "model-catalog"}
	set, err := NewBindingSet([]Binding{binding})
	if err != nil {
		t.Fatal(err)
	}
	request := LeaseRequest{
		Provider: binding.Provider, OperationID: binding.OperationID, AccountRef: binding.AccountRef,
		Environment: binding.Environment, ResourceRef: binding.ResourceRef,
		ExecutionID: testExecutionID, RequestBinding: testRequestBinding,
	}
	if err := set.AuthorizeBinding(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	request.Environment = "staging"
	if err := set.AuthorizeBinding(context.Background(), request); err == nil {
		t.Fatal("wrong environment authorized")
	}
	for name, bindings := range map[string][]Binding{
		"empty": {}, "duplicate": {binding, binding},
		"invalid": {{Provider: "deepseek", OperationID: "models.list", AccountRef: "deepseek-primary", Environment: "production", ResourceRef: "chat"}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewBindingSet(bindings); err == nil {
				t.Fatal("invalid set accepted")
			}
		})
	}
	tooMany := make([]Binding, 257)
	for index := range tooMany {
		tooMany[index] = Binding{Provider: "deepseek", OperationID: "models.list", AccountRef: "account-" + strings.Repeat("x", index%100), Environment: "production", ResourceRef: "model-catalog"}
	}
	if _, err := NewBindingSet(tooMany); err == nil {
		t.Fatal("oversized set accepted")
	}
	var nilSet *BindingSet
	if err := nilSet.AuthorizeBinding(context.Background(), LeaseRequest{}); err == nil {
		t.Fatal("nil set authorized")
	}
}

func TestServeLifecycleAndConfigurationFailures(t *testing.T) {
	issuer := LeaseIssuerFunc(func(context.Context, LeaseRequest) (Lease, error) {
		return Lease{Token: "ephemeral-token", ExpiresAt: protocolTestNow.Add(time.Minute)}, nil
	})
	bindings := BindingAuthorizerFunc(func(context.Context, LeaseRequest) error { return nil })
	peers := PeerAuthorizerFunc(func(context.Context, net.Conn) error { return nil })
	if _, err := NewServer(nil, bindings, peers); err == nil {
		t.Fatal("nil issuer accepted")
	}
	if _, err := NewServer(issuer, nil, peers); err == nil {
		t.Fatal("nil bindings accepted")
	}
	if _, err := NewServer(issuer, bindings, nil); err == nil {
		t.Fatal("nil peers accepted")
	}
	server := testServer(t, issuer, bindings, peers)
	if errorCode(server.Serve(context.Background(), nil)) != "server_invalid" {
		t.Fatal("nil listener accepted")
	}
	server.MaxConcurrent = 0
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if errorCode(server.Serve(context.Background(), listener)) != "server_invalid" {
		t.Fatal("invalid concurrency accepted")
	}
	_ = listener.Close()
	server.MaxConcurrent = DefaultConcurrency
	if errorCode(server.ServeConn(context.Background(), nil)) != "server_invalid" {
		t.Fatal("nil connection accepted")
	}
	server.Deadline = 11 * time.Second
	if errorCode(server.ServeConn(context.Background(), newMemoryConn(requestLine(t, nil)))) != "server_invalid" {
		t.Fatal("invalid deadline accepted")
	}
	server.Deadline, server.Clock = DefaultDeadline, nil
	if errorCode(server.ServeConn(context.Background(), newMemoryConn(requestLine(t, nil)))) != "server_invalid" {
		t.Fatal("nil clock accepted")
	}

	server = testServer(t, issuer, bindings, peers)
	listener, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- server.Serve(ctx, listener) }()
	connection, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(connection, requestLine(t, nil)); err != nil {
		t.Fatal(err)
	}
	var response wireResponse
	if err := json.NewDecoder(connection).Decode(&response); err != nil {
		t.Fatal(err)
	}
	_ = connection.Close()
	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not stop")
	}
}

func TestHelpersFailClosed(t *testing.T) {
	var target map[string]any
	if err := decodeStrict([]byte(`{} {}`), &target); err == nil {
		t.Fatal("trailing json accepted")
	}
	if protocolErrorCode(errors.New("canary")) != "internal_error" {
		t.Fatal("unexpected code")
	}
	server := &Server{OnError: func(string) { panic("canary-callback") }}
	server.report("safe_code")
	(&Server{}).report("ignored")
}
