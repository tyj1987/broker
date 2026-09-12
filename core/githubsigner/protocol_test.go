package githubsigner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

var testNow = time.Unix(2_000_000_000, 0).UTC()

const (
	testExecutionID    = "12345678-1234-4123-8123-123456789abc"
	testRequestBinding = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

type memoryConn struct {
	input    io.Reader
	output   bytes.Buffer
	deadline time.Time
	closed   bool
}

func newMemoryConn(input string) *memoryConn {
	return &memoryConn{input: bytes.NewReader([]byte(input))}
}
func (connection *memoryConn) Read(value []byte) (int, error)  { return connection.input.Read(value) }
func (connection *memoryConn) Write(value []byte) (int, error) { return connection.output.Write(value) }
func (connection *memoryConn) Close() error                    { connection.closed = true; return nil }
func (connection *memoryConn) LocalAddr() net.Addr             { return testAddr("local") }
func (connection *memoryConn) RemoteAddr() net.Addr            { return testAddr("remote") }
func (connection *memoryConn) SetDeadline(value time.Time) error {
	connection.deadline = value
	return nil
}
func (connection *memoryConn) SetReadDeadline(time.Time) error  { return nil }
func (connection *memoryConn) SetWriteDeadline(time.Time) error { return nil }

type testAddr string

func (address testAddr) Network() string { return "test" }
func (address testAddr) String() string  { return string(address) }

type countingReader struct {
	reader io.Reader
	read   int
}

func (reader *countingReader) Read(value []byte) (int, error) {
	count, err := reader.reader.Read(value)
	reader.read += count
	return count, err
}

func encodePart(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(encoded)
}

func signingInput(t *testing.T, mutate func(map[string]any, map[string]any)) string {
	t.Helper()
	header := map[string]any{"alg": "RS256", "typ": "JWT"}
	claims := map[string]any{
		"iat": testNow.Unix() - 60,
		"exp": testNow.Unix() + 540,
		"iss": "Iv1.protocol-test",
	}
	if mutate != nil {
		mutate(header, claims)
	}
	return encodePart(t, header) + "." + encodePart(t, claims)
}

func rawSigningInput(header string, claims string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(header)) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(claims))
}

func requestLine(t *testing.T, mutate func(map[string]any)) string {
	t.Helper()
	request := map[string]any{
		"version":         ProtocolVersion,
		"algorithm":       "RS256",
		"signing_input":   signingInput(t, nil),
		"account_ref":     "github-primary",
		"environment":     "production",
		"client_id":       "Iv1.protocol-test",
		"execution_id":    testExecutionID,
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

func protocolCode(errorValue error) string {
	var protocolError *ProtocolError
	if errors.As(errorValue, &protocolError) {
		return protocolError.Code
	}
	return ""
}

func newTestServer(
	t *testing.T,
	signer DigestSigner,
	bindings BindingAuthorizer,
	peers PeerAuthorizer,
) *Server {
	t.Helper()
	server, err := NewServer(signer, bindings, peers)
	if err != nil {
		t.Fatal(err)
	}
	server.Clock = func() time.Time { return testNow }
	return server
}

func TestServeConnSignsOnlyValidatedDigest(t *testing.T) {
	var backendRequest DigestRequest
	peerCalls := 0
	bindingCalls := 0
	signature := bytes.Repeat([]byte{7}, MinSignatureBytes)
	server := newTestServer(t,
		DigestSignerFunc(func(_ context.Context, request DigestRequest) ([]byte, error) {
			backendRequest = request
			return signature, nil
		}),
		BindingAuthorizerFunc(func(_ context.Context, account, environment, clientID string) error {
			bindingCalls++
			if account != "github-primary" || environment != "production" || clientID != "Iv1.protocol-test" {
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
	line := requestLine(t, nil)
	connection := newMemoryConn(line)
	if err := server.ServeConn(context.Background(), connection); err != nil {
		t.Fatal(err)
	}
	if peerCalls != 1 || bindingCalls != 1 {
		t.Fatal("mandatory authorizers were not called")
	}
	if !connection.deadline.Equal(testNow.Add(DefaultDeadline)) {
		t.Fatal("deadline was not applied")
	}
	expectedDigest := sha256.Sum256([]byte(signingInput(t, nil)))
	if backendRequest.Digest != expectedDigest || backendRequest.AccountRef != "github-primary" ||
		backendRequest.Environment != "production" || backendRequest.ClientID != "Iv1.protocol-test" ||
		backendRequest.ExecutionID != testExecutionID || backendRequest.RequestBinding != testRequestBinding {
		t.Fatalf("unexpected digest request %#v", backendRequest)
	}
	var response wireResponse
	if err := json.Unmarshal(connection.output.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Version != ProtocolVersion || response.Signature != base64.RawURLEncoding.EncodeToString(signature) ||
		response.ExecutionID != testExecutionID || response.RequestBinding != testRequestBinding {
		t.Fatalf("unexpected response %#v", response)
	}
	output := connection.output.String()
	for _, excluded := range []string{"github-primary", "production", "Iv1.protocol-test", "signing_input", "private"} {
		if strings.Contains(output, excluded) {
			t.Fatalf("response exposed %q", excluded)
		}
	}
}

func TestServeEndToEndAndStopsWithContext(t *testing.T) {
	server := newTestServer(t,
		DigestSignerFunc(func(context.Context, DigestRequest) ([]byte, error) {
			return bytes.Repeat([]byte{4}, 256), nil
		}),
		BindingAuthorizerFunc(func(context.Context, string, string, string) error { return nil }),
		PeerAuthorizerFunc(func(context.Context, net.Conn) error { return nil }),
	)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
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
	if response.Version != ProtocolVersion || response.Signature == "" {
		t.Fatalf("unexpected response %#v", response)
	}
	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not stop after cancellation")
	}
}

func TestServeConnFailsClosedWithoutLeakingDependencyErrors(t *testing.T) {
	tests := map[string]struct {
		peerError, bindingError, signerError error
		signature                            []byte
		code                                 string
	}{
		"peer":            {peerError: errors.New("canary-peer-secret"), signature: bytes.Repeat([]byte{1}, 256), code: "peer_denied"},
		"binding":         {bindingError: errors.New("canary-binding-secret"), signature: bytes.Repeat([]byte{1}, 256), code: "binding_denied"},
		"backend":         {signerError: errors.New("canary-kms-secret"), signature: bytes.Repeat([]byte{1}, 256), code: "signing_failed"},
		"short signature": {signature: bytes.Repeat([]byte{1}, 255), code: "signature_invalid"},
		"long signature":  {signature: bytes.Repeat([]byte{1}, 1025), code: "signature_invalid"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			server := newTestServer(t,
				DigestSignerFunc(func(context.Context, DigestRequest) ([]byte, error) { return test.signature, test.signerError }),
				BindingAuthorizerFunc(func(context.Context, string, string, string) error { return test.bindingError }),
				PeerAuthorizerFunc(func(context.Context, net.Conn) error { return test.peerError }),
			)
			connection := newMemoryConn(requestLine(t, nil))
			err := server.ServeConn(context.Background(), connection)
			if protocolCode(err) != test.code {
				t.Fatalf("unexpected error %v", err)
			}
			if strings.Contains(err.Error(), "canary") || connection.output.Len() != 0 {
				t.Fatal("failure leaked detail or returned partial output")
			}
		})
	}
}

func TestRequestAndJWTValidation(t *testing.T) {
	validSigner := DigestSignerFunc(func(context.Context, DigestRequest) ([]byte, error) {
		return bytes.Repeat([]byte{2}, 256), nil
	})
	allowBinding := BindingAuthorizerFunc(func(context.Context, string, string, string) error { return nil })
	allowPeer := PeerAuthorizerFunc(func(context.Context, net.Conn) error { return nil })
	tests := map[string]struct{ line, code string }{
		"no newline":          {strings.TrimSuffix(requestLine(t, nil), "\n"), "request_invalid"},
		"crlf":                {strings.TrimSuffix(requestLine(t, nil), "\n") + "\r\n", "request_invalid"},
		"trailing":            {requestLine(t, nil) + "{}\n", "request_invalid"},
		"oversized":           {strings.Repeat("x", MaxRequestBytes+1) + "\n", "request_invalid"},
		"invalid utf8":        {string([]byte{'{', 0xff, '}', '\n'}), "request_invalid"},
		"duplicate field":     {strings.Replace(requestLine(t, nil), `"version":2`, `"version":2,"version":2`, 1), "request_invalid"},
		"wrong field case":    {strings.Replace(requestLine(t, nil), `"account_ref":`, `"ACCOUNT_REF":`, 1), "request_invalid"},
		"case alias":          {strings.Replace(requestLine(t, nil), `"account_ref":`, `"ACCOUNT_REF":"other","account_ref":`, 1), "request_invalid"},
		"null field":          {strings.Replace(requestLine(t, nil), `"account_ref":"github-primary"`, `"account_ref":null`, 1), "request_invalid"},
		"unknown field":       {requestLine(t, func(value map[string]any) { value["private_key"] = "canary" }), "request_invalid"},
		"wrong version":       {requestLine(t, func(value map[string]any) { value["version"] = 1 }), "request_invalid"},
		"wrong algorithm":     {requestLine(t, func(value map[string]any) { value["algorithm"] = "none" }), "request_invalid"},
		"bad account":         {requestLine(t, func(value map[string]any) { value["account_ref"] = "../root" }), "request_invalid"},
		"bad environment":     {requestLine(t, func(value map[string]any) { value["environment"] = "Production" }), "request_invalid"},
		"bad client":          {requestLine(t, func(value map[string]any) { value["client_id"] = "x" }), "request_invalid"},
		"bad execution":       {requestLine(t, func(value map[string]any) { value["execution_id"] = "wrong" }), "request_invalid"},
		"bad request binding": {requestLine(t, func(value map[string]any) { value["request_binding"] = "wrong" }), "request_invalid"},
		"wrong issuer": {requestLine(t, func(value map[string]any) {
			value["signing_input"] = signingInput(t, func(_ map[string]any, claims map[string]any) { claims["iss"] = "Iv1.other" })
		}), "jwt_invalid"},
		"wrong jwt algorithm": {requestLine(t, func(value map[string]any) {
			value["signing_input"] = signingInput(t, func(header map[string]any, _ map[string]any) { header["alg"] = "none" })
		}), "jwt_invalid"},
		"unknown jwt claim": {requestLine(t, func(value map[string]any) {
			value["signing_input"] = signingInput(t, func(_ map[string]any, claims map[string]any) { claims["key"] = "canary" })
		}), "jwt_invalid"},
		"jwt header case alias": {requestLine(t, func(value map[string]any) {
			value["signing_input"] = rawSigningInput(
				`{"Alg":"RS256","typ":"JWT"}`,
				fmt.Sprintf(`{"iat":%d,"exp":%d,"iss":"Iv1.protocol-test"}`, testNow.Unix()-60, testNow.Unix()+540),
			)
		}), "jwt_invalid"},
		"duplicate jwt claim": {requestLine(t, func(value map[string]any) {
			value["signing_input"] = rawSigningInput(
				`{"alg":"RS256","typ":"JWT"}`,
				fmt.Sprintf(`{"iat":%d,"exp":%d,"exp":%d,"iss":"Iv1.protocol-test"}`, testNow.Unix()-60, testNow.Unix()+540, testNow.Unix()+540),
			)
		}), "jwt_invalid"},
		"expired": {requestLine(t, func(value map[string]any) {
			value["signing_input"] = signingInput(t, func(_ map[string]any, claims map[string]any) { claims["exp"] = testNow.Unix() })
		}), "jwt_invalid"},
		"future issued": {requestLine(t, func(value map[string]any) {
			value["signing_input"] = signingInput(t, func(_ map[string]any, claims map[string]any) { claims["iat"] = testNow.Unix() + 31 })
		}), "jwt_invalid"},
		"overlong lifetime": {requestLine(t, func(value map[string]any) {
			value["signing_input"] = signingInput(t, func(_ map[string]any, claims map[string]any) {
				claims["iat"] = testNow.Unix() - 60
				claims["exp"] = testNow.Unix() + 541
			})
		}), "jwt_invalid"},
		"overflow lifetime": {requestLine(t, func(value map[string]any) {
			value["signing_input"] = signingInput(t, func(_ map[string]any, claims map[string]any) {
				claims["exp"] = int64(9_223_372_036_854_775_807)
			})
		}), "jwt_invalid"},
		"padded base64": {requestLine(t, func(value map[string]any) { value["signing_input"] = "e30=.e30" }), "jwt_invalid"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			server := newTestServer(t, validSigner, allowBinding, allowPeer)
			err := server.ServeConn(context.Background(), newMemoryConn(test.line))
			if protocolCode(err) != test.code {
				t.Fatalf("expected %s, got %v", test.code, err)
			}
		})
	}
}

func TestRequestReadAndSignerTimeAreBounded(t *testing.T) {
	reader := &countingReader{reader: strings.NewReader(strings.Repeat("x", MaxRequestBytes*4))}
	dependencyCalls := 0
	server := newTestServer(t,
		DigestSignerFunc(func(context.Context, DigestRequest) ([]byte, error) {
			dependencyCalls++
			return bytes.Repeat([]byte{1}, MinSignatureBytes), nil
		}),
		BindingAuthorizerFunc(func(context.Context, string, string, string) error {
			dependencyCalls++
			return nil
		}),
		PeerAuthorizerFunc(func(context.Context, net.Conn) error { return nil }),
	)
	if err := server.ServeConn(context.Background(), &memoryConn{input: reader}); protocolCode(err) != "request_invalid" {
		t.Fatalf("unexpected oversized request error %v", err)
	}
	if reader.read > MaxRequestBytes+1 || dependencyCalls != 0 {
		t.Fatalf("unbounded read or dependency call: bytes=%d calls=%d", reader.read, dependencyCalls)
	}

	server = newTestServer(t,
		DigestSignerFunc(func(ctx context.Context, _ DigestRequest) ([]byte, error) {
			<-ctx.Done()
			return bytes.Repeat([]byte{1}, MinSignatureBytes), nil
		}),
		BindingAuthorizerFunc(func(context.Context, string, string, string) error { return nil }),
		PeerAuthorizerFunc(func(context.Context, net.Conn) error { return nil }),
	)
	server.Deadline = 20 * time.Millisecond
	started := time.Now()
	connection := newMemoryConn(requestLine(t, nil))
	if err := server.ServeConn(context.Background(), connection); protocolCode(err) != "deadline_exceeded" || time.Since(started) > time.Second || connection.output.Len() != 0 {
		t.Fatalf("signer deadline was not enforced: %v", err)
	}
	signerCalled := false
	server = newTestServer(t,
		DigestSignerFunc(func(context.Context, DigestRequest) ([]byte, error) {
			signerCalled = true
			return bytes.Repeat([]byte{1}, MinSignatureBytes), nil
		}),
		BindingAuthorizerFunc(func(ctx context.Context, _ string, _ string, _ string) error { <-ctx.Done(); return nil }),
		PeerAuthorizerFunc(func(context.Context, net.Conn) error { return nil }),
	)
	server.Deadline = 20 * time.Millisecond
	if err := server.ServeConn(context.Background(), newMemoryConn(requestLine(t, nil))); protocolCode(err) != "deadline_exceeded" || signerCalled {
		t.Fatalf("expired binding advanced to signer: %v", err)
	}
}

func TestBindingSet(t *testing.T) {
	binding := Binding{AccountRef: "github-primary", Environment: "production", ClientID: "Iv1.protocol-test"}
	bindings, err := NewBindingSet([]Binding{binding})
	if err != nil {
		t.Fatal(err)
	}
	if err := bindings.AuthorizeBinding(context.Background(), binding.AccountRef, binding.Environment, binding.ClientID); err != nil {
		t.Fatal(err)
	}
	if err := bindings.AuthorizeBinding(context.Background(), binding.AccountRef, "staging", binding.ClientID); err == nil {
		t.Fatal("wrong environment was authorized")
	}
	for name, values := range map[string][]Binding{
		"empty":       {},
		"duplicate":   {binding, binding},
		"bad account": {{AccountRef: "../root", Environment: "production", ClientID: "Iv1.protocol-test"}},
		"too many": func() []Binding {
			result := make([]Binding, 65)
			for index := range result {
				result[index] = Binding{AccountRef: "account-" + string(rune('A'+index)), Environment: "production", ClientID: "Iv1.protocol-test"}
			}
			return result
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewBindingSet(values); err == nil {
				t.Fatal("invalid bindings accepted")
			}
		})
	}
	var nilSet *BindingSet
	if err := nilSet.AuthorizeBinding(context.Background(), "a", "production", "Iv1.test"); err == nil {
		t.Fatal("nil binding set authorized")
	}
}

func TestServerDependencyAndConnectionFailures(t *testing.T) {
	validSigner := DigestSignerFunc(func(context.Context, DigestRequest) ([]byte, error) { return bytes.Repeat([]byte{1}, 256), nil })
	validBindings := BindingAuthorizerFunc(func(context.Context, string, string, string) error { return nil })
	validPeers := PeerAuthorizerFunc(func(context.Context, net.Conn) error { return nil })
	if _, err := NewServer(nil, validBindings, validPeers); err == nil {
		t.Fatal("nil signer accepted")
	}
	if _, err := NewServer(validSigner, nil, validPeers); err == nil {
		t.Fatal("nil bindings accepted")
	}
	if _, err := NewServer(validSigner, validBindings, nil); err == nil {
		t.Fatal("nil peers accepted")
	}
	server := newTestServer(t, validSigner, validBindings, validPeers)
	if protocolCode(server.Serve(context.Background(), nil)) != "server_invalid" {
		t.Fatal("nil listener accepted")
	}
	server.MaxConcurrent = 0
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if protocolCode(server.Serve(context.Background(), listener)) != "server_invalid" {
		t.Fatal("invalid concurrency accepted")
	}
	server.MaxConcurrent = DefaultConcurrency
	if protocolCode(server.Serve(nil, listener)) != "server_invalid" {
		t.Fatal("nil serve context accepted")
	}
	_ = listener.Close()
	if protocolCode(server.ServeConn(context.Background(), nil)) != "server_invalid" {
		t.Fatal("nil connection accepted")
	}
	if protocolCode(server.ServeConn(nil, newMemoryConn(requestLine(t, nil)))) != "server_invalid" {
		t.Fatal("nil context accepted")
	}
	server.Deadline = 11 * time.Second
	if protocolCode(server.ServeConn(context.Background(), newMemoryConn(requestLine(t, nil)))) != "server_invalid" {
		t.Fatal("invalid deadline accepted")
	}
	server.Deadline = DefaultDeadline
	server.Clock = nil
	if protocolCode(server.ServeConn(context.Background(), newMemoryConn(requestLine(t, nil)))) != "server_invalid" {
		t.Fatal("nil clock accepted")
	}
}

func TestDecodeStrictRejectsTrailingJSON(t *testing.T) {
	var target map[string]any
	if err := decodeStrict([]byte(`{} {}`), &target); err == nil {
		t.Fatal("trailing JSON accepted")
	}
	if _, err := decodeCanonicalBase64URL(""); err == nil {
		t.Fatal("empty base64url accepted")
	}
	if _, err := decodeCanonicalBase64URL("*"); err == nil {
		t.Fatal("invalid base64url accepted")
	}
	if _, err := io.ReadAll(strings.NewReader("ok")); err != nil {
		t.Fatal(err)
	}
	if protocolErrorCode(errors.New("canary")) != "internal_error" {
		t.Fatal("unexpected internal error code")
	}
	server := &Server{OnError: func(string) { panic("canary-callback") }}
	server.report("safe_code")
	(&Server{}).report("ignored")
	for _, value := range [][]byte{
		[]byte(`{"outer":[{"key":1,"key":2}]}`),
		[]byte(`{"outer":[1,true,null,{"ok":2}]} {}`),
	} {
		if err := rejectDuplicateKeys(value); err == nil {
			t.Fatalf("ambiguous JSON accepted: %q", value)
		}
	}
}
