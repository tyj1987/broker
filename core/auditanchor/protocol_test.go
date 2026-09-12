package auditanchor

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

var testNow = time.Unix(2_000_000_000, 0).UTC()

var testConfig = Config{
	Algorithm: "ecdsa-p256-sha256",
	KeyID:     "audit-anchor-key-2026-01",
	StreamID:  "broker-production",
}

type memoryConn struct {
	input      *bytes.Reader
	output     bytes.Buffer
	deadline   time.Time
	writeError error
}

func newMemoryConn(input string) *memoryConn {
	return &memoryConn{input: bytes.NewReader([]byte(input))}
}
func (connection *memoryConn) Read(value []byte) (int, error) { return connection.input.Read(value) }
func (connection *memoryConn) Write(value []byte) (int, error) {
	if connection.writeError != nil {
		return 0, connection.writeError
	}
	return connection.output.Write(value)
}
func (*memoryConn) Close() error         { return nil }
func (*memoryConn) LocalAddr() net.Addr  { return testAddr("local") }
func (*memoryConn) RemoteAddr() net.Addr { return testAddr("remote") }
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
	payloadDigest := strings.Repeat("a", 64)
	sequence := int64(7)
	previousDigest := strings.Repeat("b", 64)
	signingInput := SignatureContext + "\x00" + testConfig.Algorithm + "\x00" + testConfig.KeyID + "\x00" +
		testConfig.StreamID + "\x00" + strconv.FormatInt(sequence, 10) + "\x00" + previousDigest + "\x00" + payloadDigest
	request := map[string]any{
		"version": ProtocolVersion, "purpose": Purpose, "algorithm": testConfig.Algorithm,
		"key_id": testConfig.KeyID, "stream_id": testConfig.StreamID, "sequence": sequence,
		"previous_anchor_digest": previousDigest,
		"payload_digest":         payloadDigest,
		"signing_input":          base64.RawURLEncoding.EncodeToString([]byte(signingInput)),
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

func testServer(t *testing.T, signer Signer, anchors AnchorAuthorizer, peers PeerAuthorizer) *Server {
	t.Helper()
	server, err := NewServer(testConfig, signer, anchors, peers)
	if err != nil {
		t.Fatal(err)
	}
	server.Clock = func() time.Time { return testNow }
	return server
}

func TestServeConnSignsOnlyBoundAuditAnchorInput(t *testing.T) {
	var authorized, signed SignRequest
	server := testServer(t,
		SignerFunc(func(_ context.Context, request SignRequest) ([]byte, error) {
			signed = request
			return bytes.Repeat([]byte{7}, 72), nil
		}),
		AnchorAuthorizerFunc(func(_ context.Context, request SignRequest) error {
			authorized = request
			return nil
		}),
		PeerAuthorizerFunc(func(_ context.Context, connection net.Conn) error {
			if connection.RemoteAddr().String() != "remote" {
				t.Fatal("wrong peer")
			}
			return nil
		}),
	)
	connection := newMemoryConn(requestLine(t, nil))
	if err := server.ServeConn(context.Background(), connection); err != nil {
		t.Fatal(err)
	}
	if authorized.StreamID != testConfig.StreamID || authorized.Sequence != 7 ||
		authorized.Algorithm != testConfig.Algorithm || authorized.KeyID != testConfig.KeyID {
		t.Fatal("anchor binding was not preserved")
	}
	if authorized.PreviousDigest != [32]byte{0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb} {
		t.Fatal("previous anchor digest was not preserved")
	}
	if !bytes.Equal(authorized.SigningInput, signed.SigningInput) || authorized.Digest != signed.Digest {
		t.Fatal("authorized signing input changed before signing")
	}
	expectedDigest := sha256.Sum256(signed.SigningInput)
	if signed.Digest != expectedDigest || signed.PayloadDigest != [32]byte{0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa} {
		t.Fatal("signer digest was not derived from the validated request")
	}
	if !connection.deadline.Equal(testNow.Add(DefaultDeadline)) {
		t.Fatal("connection deadline was not applied")
	}
	var response wireResponse
	if err := json.Unmarshal(connection.output.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Version != ProtocolVersion || response.Purpose != Purpose ||
		response.Algorithm != testConfig.Algorithm || response.KeyID != testConfig.KeyID ||
		response.PayloadDigest != strings.Repeat("a", 64) ||
		response.Signature != base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 72)) {
		t.Fatalf("unexpected response %#v", response)
	}
}

func TestRequestValidationFailsClosedBeforeAuthorization(t *testing.T) {
	authorizerCalls, signerCalls := 0, 0
	server := testServer(t,
		SignerFunc(func(context.Context, SignRequest) ([]byte, error) {
			signerCalls++
			return bytes.Repeat([]byte{1}, 64), nil
		}),
		AnchorAuthorizerFunc(func(context.Context, SignRequest) error { authorizerCalls++; return nil }),
		PeerAuthorizerFunc(func(context.Context, net.Conn) error { return nil }),
	)
	tests := map[string]string{
		"no newline":            strings.TrimSuffix(requestLine(t, nil), "\n"),
		"crlf":                  strings.TrimSuffix(requestLine(t, nil), "\n") + "\r\n",
		"trailing":              requestLine(t, nil) + "{}\n",
		"oversized":             strings.Repeat("x", MaxRequestBytes+1) + "\n",
		"unknown field":         requestLine(t, func(value map[string]any) { value["private_key"] = "canary" }),
		"wrong version":         requestLine(t, func(value map[string]any) { value["version"] = 1 }),
		"wrong purpose":         requestLine(t, func(value map[string]any) { value["purpose"] = "generic-signing" }),
		"wrong algorithm":       requestLine(t, func(value map[string]any) { value["algorithm"] = "rsa-pss-sha256" }),
		"wrong key":             requestLine(t, func(value map[string]any) { value["key_id"] = "other-key" }),
		"wrong stream":          requestLine(t, func(value map[string]any) { value["stream_id"] = "other-stream" }),
		"zero sequence":         requestLine(t, func(value map[string]any) { value["sequence"] = 0 }),
		"fraction sequence":     requestLine(t, func(value map[string]any) { value["sequence"] = 1.5 }),
		"missing predecessor":   requestLine(t, func(value map[string]any) { delete(value, "previous_anchor_digest") }),
		"short predecessor":     requestLine(t, func(value map[string]any) { value["previous_anchor_digest"] = "bb" }),
		"uppercase predecessor": requestLine(t, func(value map[string]any) { value["previous_anchor_digest"] = strings.Repeat("B", 64) }),
		"genesis after first":   requestLine(t, func(value map[string]any) { value["previous_anchor_digest"] = strings.Repeat("0", 64) }),
		"non-genesis first":     requestLine(t, func(value map[string]any) { value["sequence"] = 1 }),
		"uppercase digest":      requestLine(t, func(value map[string]any) { value["payload_digest"] = strings.Repeat("A", 64) }),
		"short digest":          requestLine(t, func(value map[string]any) { value["payload_digest"] = "aa" }),
		"padded input":          requestLine(t, func(value map[string]any) { value["signing_input"] = value["signing_input"].(string) + "=" }),
		"arbitrary input": requestLine(t, func(value map[string]any) {
			value["signing_input"] = base64.RawURLEncoding.EncodeToString([]byte("arbitrary"))
		}),
		"digest input mismatch": requestLine(t, func(value map[string]any) { value["payload_digest"] = strings.Repeat("b", 64) }),
	}
	for name, line := range tests {
		t.Run(name, func(t *testing.T) {
			if code := errorCode(server.ServeConn(context.Background(), newMemoryConn(line))); code != "request_invalid" {
				t.Fatalf("unexpected code %q", code)
			}
		})
	}
	if authorizerCalls != 0 || signerCalls != 0 {
		t.Fatal("invalid request reached an authority")
	}
}

func TestAuthoritiesFailClosedWithoutLeakingDetails(t *testing.T) {
	tests := map[string]struct {
		peer, anchor, signer error
		code                 string
	}{
		"peer":   {peer: errors.New("canary-peer"), code: "peer_denied"},
		"anchor": {anchor: errors.New("canary-state"), code: "anchor_denied"},
		"signer": {signer: errors.New("canary-kms"), code: "signing_failed"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			server := testServer(t,
				SignerFunc(func(context.Context, SignRequest) ([]byte, error) { return bytes.Repeat([]byte{1}, 64), test.signer }),
				AnchorAuthorizerFunc(func(context.Context, SignRequest) error { return test.anchor }),
				PeerAuthorizerFunc(func(context.Context, net.Conn) error { return test.peer }),
			)
			err := server.ServeConn(context.Background(), newMemoryConn(requestLine(t, nil)))
			if errorCode(err) != test.code || strings.Contains(err.Error(), "canary") {
				t.Fatalf("unsafe error %v", err)
			}
		})
	}
}

func TestConfigurationSignatureAndResponseFailures(t *testing.T) {
	allowAnchor := AnchorAuthorizerFunc(func(context.Context, SignRequest) error { return nil })
	allowPeer := PeerAuthorizerFunc(func(context.Context, net.Conn) error { return nil })
	for _, config := range []Config{
		{}, {Algorithm: "unknown", KeyID: testConfig.KeyID, StreamID: testConfig.StreamID},
		{Algorithm: testConfig.Algorithm, KeyID: "../key", StreamID: testConfig.StreamID},
		{Algorithm: testConfig.Algorithm, KeyID: testConfig.KeyID, StreamID: "../stream"},
	} {
		if _, err := NewServer(config, SignerFunc(func(context.Context, SignRequest) ([]byte, error) { return nil, nil }), allowAnchor, allowPeer); err == nil {
			t.Fatal("invalid configuration was accepted")
		}
	}
	for _, size := range []int{MinSignatureBytes - 1, MaxSignatureBytes + 1} {
		server := testServer(t,
			SignerFunc(func(context.Context, SignRequest) ([]byte, error) { return make([]byte, size), nil }),
			allowAnchor, allowPeer,
		)
		if code := errorCode(server.ServeConn(context.Background(), newMemoryConn(requestLine(t, nil)))); code != "signature_invalid" {
			t.Fatalf("unexpected signature error %q", code)
		}
	}
	connection := newMemoryConn(requestLine(t, nil))
	connection.writeError = errors.New("canary-write")
	server := testServer(t,
		SignerFunc(func(context.Context, SignRequest) ([]byte, error) { return make([]byte, 64), nil }),
		allowAnchor, allowPeer,
	)
	if code := errorCode(server.ServeConn(context.Background(), connection)); code != "response_failed" {
		t.Fatalf("unexpected response error %q", code)
	}
}

type channelListener struct {
	connections chan net.Conn
	closed      chan struct{}
}

func newChannelListener() *channelListener {
	return &channelListener{connections: make(chan net.Conn, 2), closed: make(chan struct{})}
}

func (listener *channelListener) Accept() (net.Conn, error) {
	select {
	case connection := <-listener.connections:
		return connection, nil
	case <-listener.closed:
		return nil, net.ErrClosed
	}
}

func (listener *channelListener) Close() error {
	select {
	case <-listener.closed:
	default:
		close(listener.closed)
	}
	return nil
}

func (*channelListener) Addr() net.Addr { return testAddr("listener") }

func TestServeProcessesRequestAndStopsOnCancellation(t *testing.T) {
	server := testServer(t,
		SignerFunc(func(context.Context, SignRequest) ([]byte, error) { return bytes.Repeat([]byte{9}, 64), nil }),
		AnchorAuthorizerFunc(func(context.Context, SignRequest) error { return nil }),
		PeerAuthorizerFunc(func(context.Context, net.Conn) error { return nil }),
	)
	listener := newChannelListener()
	serverSide, clientSide := net.Pipe()
	listener.connections <- serverSide
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- server.Serve(ctx, listener) }()
	if _, err := clientSide.Write([]byte(requestLine(t, nil))); err != nil {
		t.Fatal(err)
	}
	if err := clientSide.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(clientSide).ReadString('\n')
	if err != nil || !strings.Contains(line, `"signature"`) {
		t.Fatalf("missing response %q: %v", line, err)
	}
	_ = clientSide.Close()
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

type failingListener struct{ err error }

func (listener failingListener) Accept() (net.Conn, error) { return nil, listener.err }
func (failingListener) Close() error                       { return nil }
func (failingListener) Addr() net.Addr                     { return testAddr("failing") }

func TestServeAndReportingBoundaries(t *testing.T) {
	server := testServer(t,
		SignerFunc(func(context.Context, SignRequest) ([]byte, error) { return bytes.Repeat([]byte{1}, 64), nil }),
		AnchorAuthorizerFunc(func(context.Context, SignRequest) error { return nil }),
		PeerAuthorizerFunc(func(context.Context, net.Conn) error { return nil }),
	)
	for name, candidate := range map[string]*Server{
		"nil":                nil,
		"zero concurrency":   {MaxConcurrent: 0},
		"excess concurrency": {MaxConcurrent: 257},
	} {
		t.Run(name, func(t *testing.T) {
			if code := errorCode(candidate.Serve(context.Background(), failingListener{err: errors.New("unused")})); code != "server_invalid" {
				t.Fatalf("unexpected code %q", code)
			}
		})
	}
	if code := errorCode(server.Serve(context.Background(), nil)); code != "server_invalid" {
		t.Fatalf("unexpected nil-listener code %q", code)
	}
	if code := errorCode(server.Serve(context.Background(), failingListener{err: errors.New("canary-accept")})); code != "accept_failed" {
		t.Fatalf("unexpected accept code %q", code)
	}
	reported := ""
	server.OnError = func(code string) { reported = code; panic("callback detail") }
	server.report("stable_code")
	if reported != "stable_code" {
		t.Fatal("stable error code was not reported")
	}
	server.OnError = nil
	server.report("ignored")
	if protocolErrorCode(errors.New("canary")) != "internal_error" {
		t.Fatal("dependency error was exposed")
	}
}

func TestServeConnRejectsInvalidRuntimeAndDeadlineFailure(t *testing.T) {
	allowAnchor := AnchorAuthorizerFunc(func(context.Context, SignRequest) error { return nil })
	allowPeer := PeerAuthorizerFunc(func(context.Context, net.Conn) error { return nil })
	validSigner := SignerFunc(func(context.Context, SignRequest) ([]byte, error) { return make([]byte, 64), nil })
	server := testServer(t, validSigner, allowAnchor, allowPeer)
	for name, mutate := range map[string]func(*Server){
		"config":           func(value *Server) { value.Config.StreamID = "../bad" },
		"signer":           func(value *Server) { value.Signer = nil },
		"anchor authority": func(value *Server) { value.Anchors = nil },
		"peer authority":   func(value *Server) { value.Peers = nil },
		"clock":            func(value *Server) { value.Clock = nil },
		"deadline":         func(value *Server) { value.Deadline = 0 },
		"long deadline":    func(value *Server) { value.Deadline = 11 * time.Second },
	} {
		t.Run(name, func(t *testing.T) {
			copy := *server
			mutate(&copy)
			if code := errorCode(copy.ServeConn(context.Background(), newMemoryConn(requestLine(t, nil)))); code != "server_invalid" {
				t.Fatalf("unexpected code %q", code)
			}
		})
	}
	if code := errorCode(server.ServeConn(context.Background(), nil)); code != "server_invalid" {
		t.Fatalf("unexpected nil connection code %q", code)
	}
	connection := newMemoryConn(requestLine(t, nil))
	connection.deadline = testNow
	deadlineFailure := &deadlineErrorConn{memoryConn: connection}
	if code := errorCode(server.ServeConn(context.Background(), deadlineFailure)); code != "connection_invalid" {
		t.Fatalf("unexpected deadline code %q", code)
	}
}

type deadlineErrorConn struct{ *memoryConn }

func (*deadlineErrorConn) SetDeadline(time.Time) error { return errors.New("canary-deadline") }

func TestNewServerRequiresEveryDependency(t *testing.T) {
	signer := SignerFunc(func(context.Context, SignRequest) ([]byte, error) { return nil, nil })
	anchors := AnchorAuthorizerFunc(func(context.Context, SignRequest) error { return nil })
	peers := PeerAuthorizerFunc(func(context.Context, net.Conn) error { return nil })
	for _, dependencies := range []struct {
		signer Signer
		anchor AnchorAuthorizer
		peer   PeerAuthorizer
	}{
		{nil, anchors, peers}, {signer, nil, peers}, {signer, anchors, nil},
	} {
		if _, err := NewServer(testConfig, dependencies.signer, dependencies.anchor, dependencies.peer); err == nil {
			t.Fatal("missing dependency was accepted")
		}
	}
}
