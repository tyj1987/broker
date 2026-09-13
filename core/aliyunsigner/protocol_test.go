package aliyunsigner

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

var testNow = time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)

const (
	testExecutionID    = "12345678-1234-4123-8123-123456789abc"
	testRequestBinding = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testCredentialBind = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
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

type failingListener struct{}

func (failingListener) Accept() (net.Conn, error) { return nil, errors.New("accept failed") }
func (failingListener) Close() error              { return nil }
func (failingListener) Addr() net.Addr            { return testAddr("listener") }

type countingReader struct {
	reader io.Reader
	read   int
}

func (reader *countingReader) Read(value []byte) (int, error) {
	count, err := reader.reader.Read(value)
	reader.read += count
	return count, err
}

func requestDocument(operation string) map[string]any {
	query := map[string]any{}
	if operation == OperationECSInstancesList {
		query = map[string]any{"MaxResults": 20, "RegionId": "cn-hangzhou"}
	}
	return map[string]any{
		"version": ProtocolVersion, "provider": "aliyun", "operation_id": operation,
		"account_ref": "aliyun-primary", "environment": "production",
		"resource_ref": "primary-ecs-inventory", "region_id": "cn-hangzhou",
		"execution_id": testExecutionID, "request_binding": testRequestBinding,
		"method": "POST", "path": "/", "query": query,
	}
}

func requestLine(t *testing.T, operation string, mutate func(map[string]any)) string {
	t.Helper()
	document := requestDocument(operation)
	if mutate != nil {
		mutate(document)
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded) + "\n"
}

func validSigned() SignedRequest {
	return SignedRequest{
		CredentialBinding: testCredentialBind,
		Authorization: "ACS3-HMAC-SHA256 Credential=STS.TEST," +
			"SignedHeaders=host;x-acs-action;x-acs-content-sha256;x-acs-date;x-acs-security-token;x-acs-signature-nonce;x-acs-version," +
			"Signature=" + strings.Repeat("a", 64),
		SecurityToken:  "temporary-security-token",
		Date:           "2026-09-13T00:00:00Z",
		SignatureNonce: "nonce-12345678",
	}
}

func protocolCode(errorValue error) string {
	var protocolError *ProtocolError
	if errors.As(errorValue, &protocolError) {
		return protocolError.Code
	}
	return ""
}

func newTestServer(t *testing.T, signer RequestSigner, bindings BindingAuthorizer, peers PeerAuthorizer) *Server {
	t.Helper()
	server, err := NewServer(signer, bindings, peers)
	if err != nil {
		t.Fatal(err)
	}
	server.Clock = func() time.Time { return testNow }
	return server
}

func TestServeConnSignsOnlyValidatedECSRequest(t *testing.T) {
	var backendRequest SigningRequest
	peerCalls := 0
	bindingCalls := 0
	server := newTestServer(t,
		RequestSignerFunc(func(_ context.Context, request SigningRequest) (SignedRequest, error) {
			backendRequest = request
			return validSigned(), nil
		}),
		BindingAuthorizerFunc(func(_ context.Context, request SigningRequest) error {
			bindingCalls++
			if request.AccountRef != "aliyun-primary" || request.Environment != "production" {
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
	connection := newMemoryConn(requestLine(t, OperationECSInstancesList, func(value map[string]any) {
		value["query"] = map[string]any{
			"MaxResults": 20, "NextToken": "next-page", "RegionId": "cn-hangzhou",
		}
	}))
	if err := server.ServeConn(context.Background(), connection); err != nil {
		t.Fatal(err)
	}
	if peerCalls != 1 || bindingCalls != 1 || !connection.deadline.Equal(testNow.Add(DefaultDeadline)) {
		t.Fatal("mandatory boundary was not applied")
	}
	if backendRequest.OperationID != OperationECSInstancesList || backendRequest.MaxResults != 20 ||
		backendRequest.NextToken == nil || *backendRequest.NextToken != "next-page" ||
		backendRequest.ExecutionID != testExecutionID || backendRequest.RequestBinding != testRequestBinding {
		t.Fatalf("unexpected backend request %#v", backendRequest)
	}
	var response wireResponse
	if err := json.Unmarshal(connection.output.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Version != ProtocolVersion || response.Provider != "aliyun" ||
		response.ExecutionID != testExecutionID || response.RequestBinding != testRequestBinding ||
		response.CredentialBinding != testCredentialBind ||
		response.Headers.Host != "ecs.cn-hangzhou.aliyuncs.com" ||
		response.Headers.Action != "DescribeInstances" || response.Headers.Version != "2014-05-26" {
		t.Fatalf("unexpected response %#v", response)
	}
	if strings.Contains(connection.output.String(), "AccessKeySecret") {
		t.Fatal("response exposed an access-key secret field")
	}
}

func TestCallerIdentityUsesFixedEndpointMetadata(t *testing.T) {
	server := newTestServer(t,
		RequestSignerFunc(func(_ context.Context, request SigningRequest) (SignedRequest, error) {
			if request.OperationID != OperationCallerIdentity || request.MaxResults != 0 || request.NextToken != nil {
				t.Fatal("authority request was not normalized")
			}
			return validSigned(), nil
		}),
		BindingAuthorizerFunc(func(context.Context, SigningRequest) error { return nil }),
		PeerAuthorizerFunc(func(context.Context, net.Conn) error { return nil }),
	)
	connection := newMemoryConn(requestLine(t, OperationCallerIdentity, nil))
	if err := server.ServeConn(context.Background(), connection); err != nil {
		t.Fatal(err)
	}
	var response wireResponse
	if err := json.Unmarshal(connection.output.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Headers.Host != "sts.aliyuncs.com" || response.Headers.Action != "GetCallerIdentity" ||
		response.Headers.Version != "2015-04-01" {
		t.Fatalf("unexpected authority headers %#v", response.Headers)
	}
}

func TestRequestValidationFailsClosed(t *testing.T) {
	validSigner := RequestSignerFunc(func(context.Context, SigningRequest) (SignedRequest, error) {
		return validSigned(), nil
	})
	allowBinding := BindingAuthorizerFunc(func(context.Context, SigningRequest) error { return nil })
	allowPeer := PeerAuthorizerFunc(func(context.Context, net.Conn) error { return nil })
	valid := requestLine(t, OperationECSInstancesList, nil)
	tests := map[string]string{
		"no newline":          strings.TrimSuffix(valid, "\n"),
		"crlf":                strings.TrimSuffix(valid, "\n") + "\r\n",
		"trailing":            valid + "{}\n",
		"oversized":           strings.Repeat("x", MaxRequestBytes+1) + "\n",
		"invalid json":        "{\n",
		"invalid utf8":        string([]byte{'{', 0xff, '}', '\n'}),
		"duplicate field":     strings.Replace(valid, `"version":3`, `"version":3,"version":3`, 1),
		"wrong field case":    strings.Replace(valid, `"account_ref":`, `"ACCOUNT_REF":`, 1),
		"case alias":          strings.Replace(valid, `"account_ref":`, `"ACCOUNT_REF":"other","account_ref":`, 1),
		"unknown field":       requestLine(t, OperationECSInstancesList, func(value map[string]any) { value["AccessKeySecret"] = "canary" }),
		"wrong version":       requestLine(t, OperationECSInstancesList, func(value map[string]any) { value["version"] = 2 }),
		"wrong provider":      requestLine(t, OperationECSInstancesList, func(value map[string]any) { value["provider"] = "other" }),
		"wrong operation":     requestLine(t, OperationECSInstancesList, func(value map[string]any) { value["operation_id"] = "ecs.instances.delete" }),
		"bad account":         requestLine(t, OperationECSInstancesList, func(value map[string]any) { value["account_ref"] = "../root" }),
		"bad environment":     requestLine(t, OperationECSInstancesList, func(value map[string]any) { value["environment"] = "Production" }),
		"bad resource":        requestLine(t, OperationECSInstancesList, func(value map[string]any) { value["resource_ref"] = "../inventory" }),
		"bad region":          requestLine(t, OperationECSInstancesList, func(value map[string]any) { value["region_id"] = "https://evil.example" }),
		"bad execution":       requestLine(t, OperationECSInstancesList, func(value map[string]any) { value["execution_id"] = "wrong" }),
		"bad request binding": requestLine(t, OperationECSInstancesList, func(value map[string]any) { value["request_binding"] = "wrong" }),
		"wrong method":        requestLine(t, OperationECSInstancesList, func(value map[string]any) { value["method"] = "GET" }),
		"wrong path":          requestLine(t, OperationECSInstancesList, func(value map[string]any) { value["path"] = "https://evil.example" }),
		"missing max":         requestLine(t, OperationECSInstancesList, func(value map[string]any) { value["query"] = map[string]any{"RegionId": "cn-hangzhou"} }),
		"large max": requestLine(t, OperationECSInstancesList, func(value map[string]any) {
			value["query"] = map[string]any{"MaxResults": 101, "RegionId": "cn-hangzhou"}
		}),
		"wrong query region": requestLine(t, OperationECSInstancesList, func(value map[string]any) {
			value["query"] = map[string]any{"MaxResults": 20, "RegionId": "cn-shanghai"}
		}),
		"bad next token": requestLine(t, OperationECSInstancesList, func(value map[string]any) {
			value["query"] = map[string]any{"MaxResults": 20, "NextToken": "../bad", "RegionId": "cn-hangzhou"}
		}),
		"empty next token": requestLine(t, OperationECSInstancesList, func(value map[string]any) {
			value["query"] = map[string]any{"MaxResults": 20, "NextToken": "", "RegionId": "cn-hangzhou"}
		}),
		"null next token":  strings.Replace(valid, `"RegionId":"cn-hangzhou"`, `"NextToken":null,"RegionId":"cn-hangzhou"`, 1),
		"wrong query case": strings.Replace(valid, `"MaxResults":20`, `"maxresults":20`, 1),
		"large next token": requestLine(t, OperationECSInstancesList, func(value map[string]any) {
			value["query"] = map[string]any{"MaxResults": 20, "NextToken": strings.Repeat("a", 2049), "RegionId": "cn-hangzhou"}
		}),
		"duplicate query": strings.Replace(valid, `"MaxResults":20`, `"MaxResults":20,"MaxResults":20`, 1),
		"unknown query": requestLine(t, OperationECSInstancesList, func(value map[string]any) {
			value["query"] = map[string]any{"MaxResults": 20, "RegionId": "cn-hangzhou", "Delete": true}
		}),
		"authority query": requestLine(t, OperationCallerIdentity, func(value map[string]any) { value["query"] = map[string]any{"Action": "Other"} }),
		"authority null":  strings.Replace(requestLine(t, OperationCallerIdentity, nil), `"query":{}`, `"query":null`, 1),
	}
	for name, line := range tests {
		t.Run(name, func(t *testing.T) {
			server := newTestServer(t, validSigner, allowBinding, allowPeer)
			errorValue := server.ServeConn(context.Background(), newMemoryConn(line))
			if protocolCode(errorValue) != "request_invalid" || strings.Contains(errorValue.Error(), "canary") {
				t.Fatalf("unexpected error %v", errorValue)
			}
		})
	}
}

func TestRequestReadIsActuallyBounded(t *testing.T) {
	reader := &countingReader{reader: strings.NewReader(strings.Repeat("x", MaxRequestBytes*4))}
	dependencyCalls := 0
	server := newTestServer(t,
		RequestSignerFunc(func(context.Context, SigningRequest) (SignedRequest, error) {
			dependencyCalls++
			return validSigned(), nil
		}),
		BindingAuthorizerFunc(func(context.Context, SigningRequest) error {
			dependencyCalls++
			return nil
		}),
		PeerAuthorizerFunc(func(context.Context, net.Conn) error { return nil }),
	)
	connection := &memoryConn{input: reader}
	if err := server.ServeConn(context.Background(), connection); protocolCode(err) != "request_invalid" {
		t.Fatalf("unexpected error %v", err)
	}
	if reader.read > MaxRequestBytes+1 {
		t.Fatalf("read %d bytes past the %d-byte sentinel", reader.read, MaxRequestBytes+1)
	}
	if dependencyCalls != 0 {
		t.Fatal("oversized request reached a binding or signer dependency")
	}
}

func TestStrictJSONDecoderHandlesNestedValues(t *testing.T) {
	for name, input := range map[string]string{
		"primitive": `null`,
		"array":     `[1,{"nested":[true,false]}]`,
	} {
		t.Run(name, func(t *testing.T) {
			var decoded any
			if err := decodeStrict([]byte(input), &decoded); err != nil {
				t.Fatal(err)
			}
		})
	}
	var decoded any
	if err := decodeStrict([]byte(`{"nested":{"key":1,"key":2}}`), &decoded); err == nil {
		t.Fatal("nested duplicate key was accepted")
	}
	if err := decodeStrict([]byte(`{"nested":[}`), &decoded); err == nil {
		t.Fatal("malformed nested value was accepted")
	}
}

func TestSignedResponseValidationFailsClosed(t *testing.T) {
	tests := map[string]func(*SignedRequest){
		"bad lease":     func(value *SignedRequest) { value.CredentialBinding = "short" },
		"bad auth":      func(value *SignedRequest) { value.Authorization = "Bearer canary" },
		"large auth":    func(value *SignedRequest) { value.Authorization = strings.Repeat("a", 4097) },
		"short token":   func(value *SignedRequest) { value.SecurityToken = "short" },
		"control token": func(value *SignedRequest) { value.SecurityToken = "token-value\n" },
		"bad nonce":     func(value *SignedRequest) { value.SignatureNonce = "short" },
		"bad date":      func(value *SignedRequest) { value.Date = "not-a-date" },
		"stale date":    func(value *SignedRequest) { value.Date = "2026-09-12T23:54:59Z" },
		"future date":   func(value *SignedRequest) { value.Date = "2026-09-13T00:05:01Z" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			server := newTestServer(t,
				RequestSignerFunc(func(context.Context, SigningRequest) (SignedRequest, error) {
					value := validSigned()
					mutate(&value)
					return value, nil
				}),
				BindingAuthorizerFunc(func(context.Context, SigningRequest) error { return nil }),
				PeerAuthorizerFunc(func(context.Context, net.Conn) error { return nil }),
			)
			connection := newMemoryConn(requestLine(t, OperationCallerIdentity, nil))
			errorValue := server.ServeConn(context.Background(), connection)
			if protocolCode(errorValue) != "signed_response_invalid" || connection.output.Len() != 0 {
				t.Fatalf("unexpected error %v", errorValue)
			}
		})
	}
}

func TestSignerReceivesBoundedContext(t *testing.T) {
	server := newTestServer(t,
		RequestSignerFunc(func(ctx context.Context, _ SigningRequest) (SignedRequest, error) {
			<-ctx.Done()
			return validSigned(), nil
		}),
		BindingAuthorizerFunc(func(context.Context, SigningRequest) error { return nil }),
		PeerAuthorizerFunc(func(context.Context, net.Conn) error { return nil }),
	)
	server.Deadline = 20 * time.Millisecond
	started := time.Now()
	errorValue := server.ServeConn(
		context.Background(),
		newMemoryConn(requestLine(t, OperationCallerIdentity, nil)),
	)
	if protocolCode(errorValue) != "deadline_exceeded" || time.Since(started) > time.Second {
		t.Fatalf("signer deadline was not enforced: %v", errorValue)
	}
	signerCalled := false
	server = newTestServer(t,
		RequestSignerFunc(func(context.Context, SigningRequest) (SignedRequest, error) {
			signerCalled = true
			return validSigned(), nil
		}),
		BindingAuthorizerFunc(func(ctx context.Context, _ SigningRequest) error { <-ctx.Done(); return nil }),
		PeerAuthorizerFunc(func(context.Context, net.Conn) error { return nil }),
	)
	server.Deadline = 20 * time.Millisecond
	if err := server.ServeConn(context.Background(), newMemoryConn(requestLine(t, OperationCallerIdentity, nil))); protocolCode(err) != "deadline_exceeded" || signerCalled {
		t.Fatalf("expired binding advanced to signer: %v", err)
	}
}

func TestDependenciesFailClosedWithoutLeakingErrors(t *testing.T) {
	tests := map[string]struct {
		peerError, bindingError, signerError error
		code                                 string
	}{
		"peer":    {peerError: errors.New("canary-peer-secret"), code: "peer_denied"},
		"binding": {bindingError: errors.New("canary-binding-secret"), code: "binding_denied"},
		"signer":  {signerError: errors.New("canary-sts-secret"), code: "signing_failed"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			server := newTestServer(t,
				RequestSignerFunc(func(context.Context, SigningRequest) (SignedRequest, error) {
					return validSigned(), test.signerError
				}),
				BindingAuthorizerFunc(func(context.Context, SigningRequest) error { return test.bindingError }),
				PeerAuthorizerFunc(func(context.Context, net.Conn) error { return test.peerError }),
			)
			connection := newMemoryConn(requestLine(t, OperationCallerIdentity, nil))
			errorValue := server.ServeConn(context.Background(), connection)
			if protocolCode(errorValue) != test.code || strings.Contains(errorValue.Error(), "canary") || connection.output.Len() != 0 {
				t.Fatalf("failure leaked detail or returned output: %v", errorValue)
			}
		})
	}
}

func TestBindingSet(t *testing.T) {
	binding := Binding{
		AccountRef: "aliyun-primary", Environment: "production",
		ResourceRef: "primary-ecs-inventory", RegionID: "cn-hangzhou",
	}
	bindings, err := NewBindingSet([]Binding{binding})
	if err != nil {
		t.Fatal(err)
	}
	request, err := readRequest(strings.NewReader(requestLine(t, OperationCallerIdentity, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if err := bindings.AuthorizeBinding(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	request.Environment = "staging"
	if err := bindings.AuthorizeBinding(context.Background(), request); err == nil {
		t.Fatal("wrong environment was authorized")
	}
	for name, values := range map[string][]Binding{
		"empty":       {},
		"duplicate":   {binding, binding},
		"bad account": {{AccountRef: "../root", Environment: "production", ResourceRef: "inventory", RegionID: "cn-hangzhou"}},
		"too many": func() []Binding {
			result := make([]Binding, 65)
			for index := range result {
				result[index] = Binding{AccountRef: "account-" + string(rune('A'+index)), Environment: "production", ResourceRef: "inventory", RegionID: "cn-hangzhou"}
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
	if err := nilSet.AuthorizeBinding(context.Background(), SigningRequest{}); err == nil {
		t.Fatal("nil binding set authorized")
	}
}

func TestServeEndToEndAndStopsWithContext(t *testing.T) {
	server := newTestServer(t,
		RequestSignerFunc(func(context.Context, SigningRequest) (SignedRequest, error) {
			signed := validSigned()
			signed.Date = time.Now().UTC().Format(time.RFC3339)
			return signed, nil
		}),
		BindingAuthorizerFunc(func(context.Context, SigningRequest) error { return nil }),
		PeerAuthorizerFunc(func(context.Context, net.Conn) error { return nil }),
	)
	server.Clock = time.Now
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
	if _, err := io.WriteString(connection, requestLine(t, OperationCallerIdentity, nil)); err != nil {
		t.Fatal(err)
	}
	var response wireResponse
	if err := json.NewDecoder(connection).Decode(&response); err != nil {
		t.Fatal(err)
	}
	_ = connection.Close()
	if response.OperationID != OperationCallerIdentity {
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

func TestServerConfigurationAndHelpers(t *testing.T) {
	validSigner := RequestSignerFunc(func(context.Context, SigningRequest) (SignedRequest, error) { return validSigned(), nil })
	validBindings := BindingAuthorizerFunc(func(context.Context, SigningRequest) error { return nil })
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
	if protocolCode(server.Serve(nil, failingListener{})) != "server_invalid" {
		t.Fatal("nil serve context accepted")
	}
	if protocolCode(server.ServeConn(context.Background(), nil)) != "server_invalid" {
		t.Fatal("nil connection accepted")
	}
	if protocolCode(server.ServeConn(nil, newMemoryConn(requestLine(t, OperationCallerIdentity, nil)))) != "server_invalid" {
		t.Fatal("nil context accepted")
	}
	server.Deadline = 11 * time.Second
	if protocolCode(server.ServeConn(context.Background(), newMemoryConn(requestLine(t, OperationCallerIdentity, nil)))) != "server_invalid" {
		t.Fatal("invalid deadline accepted")
	}
	server.Deadline = DefaultDeadline
	server.Clock = nil
	if protocolCode(server.ServeConn(context.Background(), newMemoryConn(requestLine(t, OperationCallerIdentity, nil)))) != "server_invalid" {
		t.Fatal("nil clock accepted")
	}
	server = newTestServer(t, validSigner, validBindings, validPeers)
	server.MaxConcurrent = 0
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if protocolCode(server.Serve(context.Background(), listener)) != "server_invalid" {
		t.Fatal("invalid concurrency accepted")
	}
	_ = listener.Close()
	if protocolErrorCode(errors.New("canary")) != "internal_error" {
		t.Fatal("unexpected internal error code")
	}
	server = &Server{OnError: func(string) { panic("canary-callback") }}
	server.report("safe_code")
	(&Server{}).report("ignored")
}
