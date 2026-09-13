package auditstore

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

	"github.com/tyj1987/broker/core/auditanchor"
)

var testNow = time.Unix(2_000_000_000, 0).UTC()

var testConfig = Config{StreamID: "broker-production"}

type memoryConn struct {
	input         io.Reader
	output        bytes.Buffer
	deadline      time.Time
	deadlineError error
	writeError    error
	shortWrite    bool
}

type countingReader struct {
	reader io.Reader
	read   int
}

func (reader *countingReader) Read(value []byte) (int, error) {
	count, err := reader.reader.Read(value)
	reader.read += count
	return count, err
}

func newMemoryConn(input string) *memoryConn {
	return &memoryConn{input: bytes.NewReader([]byte(input))}
}
func (connection *memoryConn) Read(value []byte) (int, error) {
	return connection.input.Read(value)
}
func (connection *memoryConn) Write(value []byte) (int, error) {
	if connection.writeError != nil {
		return 0, connection.writeError
	}
	if connection.shortWrite && len(value) > 0 {
		return len(value) - 1, nil
	}
	return connection.output.Write(value)
}
func (*memoryConn) Close() error         { return nil }
func (*memoryConn) LocalAddr() net.Addr  { return testAddr("local") }
func (*memoryConn) RemoteAddr() net.Addr { return testAddr("remote") }
func (connection *memoryConn) SetDeadline(value time.Time) error {
	connection.deadline = value
	return connection.deadlineError
}
func (*memoryConn) SetReadDeadline(time.Time) error  { return nil }
func (*memoryConn) SetWriteDeadline(time.Time) error { return nil }

type testAddr string

func (address testAddr) Network() string { return "test" }
func (address testAddr) String() string  { return string(address) }

type fakeVerifier struct{ err error }

type fakeEnvelope struct {
	StreamID       string `json:"stream_id"`
	Sequence       int64  `json:"sequence"`
	PreviousDigest string `json:"previous_anchor_digest"`
	PayloadDigest  string `json:"payload_digest"`
}

func (verifier *fakeVerifier) Verify(value []byte) (auditanchor.EnvelopeMetadata, []byte, error) {
	if verifier.err != nil {
		return auditanchor.EnvelopeMetadata{}, nil, verifier.err
	}
	var envelope fakeEnvelope
	if rejectDuplicateJSONKeys(value) != nil || decodeStrict(value, &envelope) != nil {
		return auditanchor.EnvelopeMetadata{}, nil, errors.New("invalid envelope")
	}
	canonical, err := json.Marshal(envelope)
	if err != nil {
		return auditanchor.EnvelopeMetadata{}, nil, err
	}
	return auditanchor.EnvelopeMetadata{
		StreamID: envelope.StreamID, Sequence: envelope.Sequence,
		PreviousAnchorDigest: envelope.PreviousDigest, PayloadDigest: envelope.PayloadDigest,
		CapturedAt: testNow,
	}, canonical, nil
}

type fakeRepository struct {
	publishResult        PublishResult
	publishError         error
	published            *PublishRequest
	head                 Head
	headError            error
	page                 [][]byte
	pageError            error
	pageArgs             [3]int64
	health               Health
	healthError          error
	healthCalled         chan struct{}
	healthWaitForContext bool
}

func (repository *fakeRepository) Publish(_ context.Context, request PublishRequest) (PublishResult, error) {
	copy := request
	copy.Envelope = bytes.Clone(request.Envelope)
	repository.published = &copy
	return repository.publishResult, repository.publishError
}
func (repository *fakeRepository) ReadHead(context.Context) (Head, error) {
	return repository.head, repository.headError
}
func (repository *fakeRepository) ReadPage(_ context.Context, after, through int64, limit int) ([][]byte, error) {
	repository.pageArgs = [3]int64{after, through, int64(limit)}
	return repository.page, repository.pageError
}
func (repository *fakeRepository) Health(ctx context.Context) (Health, error) {
	if repository.healthCalled != nil {
		select {
		case repository.healthCalled <- struct{}{}:
		default:
		}
	}
	if repository.healthWaitForContext {
		<-ctx.Done()
	}
	return repository.health, repository.healthError
}

func allowPeer(role PeerRole) PeerAuthorizer {
	return PeerAuthorizerFunc(func(_ context.Context, connection net.Conn) (PeerRole, error) {
		if connection.RemoteAddr().String() != "remote" {
			return "", errors.New("wrong peer")
		}
		return role, nil
	})
}

func testServer(t *testing.T, repository Repository, verifier EnvelopeVerifier, role PeerRole) *Server {
	t.Helper()
	server, err := NewServer(testConfig, repository, verifier, allowPeer(role))
	if err != nil {
		t.Fatal(err)
	}
	server.Clock = func() time.Time { return testNow }
	return server
}

func testEnvelopeJSON(t *testing.T, sequence int64, previousDigest, payloadDigest string) []byte {
	t.Helper()
	encoded, err := json.Marshal(fakeEnvelope{
		StreamID: testConfig.StreamID, Sequence: sequence,
		PreviousDigest: previousDigest, PayloadDigest: payloadDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func requestLine(t *testing.T, operation string, parameters any, mutate func(map[string]any)) string {
	t.Helper()
	request := map[string]any{
		"version": ProtocolVersion, "purpose": Purpose, "request_id": "req-123",
		"operation": operation, "stream_id": testConfig.StreamID, "parameters": parameters,
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

func protocolCode(err error) string {
	var protocolError *ProtocolError
	if errors.As(err, &protocolError) {
		return protocolError.Code
	}
	return ""
}

func responseDocument(t *testing.T, connection *memoryConn) map[string]any {
	t.Helper()
	var response map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(connection.output.Bytes()), &response); err != nil {
		t.Fatal(err)
	}
	return response
}

func TestExporterPublishesOnlyValidatedEnvelope(t *testing.T) {
	previous := strings.Repeat("a", 64)
	payload := strings.Repeat("b", 64)
	envelope := testEnvelopeJSON(t, 7, previous, payload)
	repository := &fakeRepository{publishResult: PublishResult{Status: "published"}}
	server := testServer(t, repository, &fakeVerifier{}, ExporterRole)
	connection := newMemoryConn(requestLine(t, "publish", map[string]any{
		"expected_previous_digest": previous,
		"envelope":                 json.RawMessage(envelope),
	}, nil))
	if err := server.ServeConn(context.Background(), connection); err != nil {
		t.Fatal(err)
	}
	if repository.published == nil || repository.published.ExpectedPreviousDigest != previous ||
		repository.published.Metadata.Sequence != 7 || !bytes.Equal(repository.published.Envelope, envelope) {
		t.Fatal("validated publish request was not preserved")
	}
	response := responseDocument(t, connection)
	if response["status"] != "ok" || response["operation"] != "publish" ||
		response["stream_id"] != testConfig.StreamID || response["request_id"] != "req-123" {
		t.Fatalf("unexpected response: %#v", response)
	}
}

func TestPublishRejectsBindingMismatchBeforeRepository(t *testing.T) {
	previous := strings.Repeat("a", 64)
	tests := []struct {
		name     string
		envelope []byte
		expected string
	}{
		{"previous mismatch", testEnvelopeJSON(t, 2, strings.Repeat("b", 64), strings.Repeat("c", 64)), previous},
		{"genesis mismatch", testEnvelopeJSON(t, 1, previous, strings.Repeat("c", 64)), previous},
		{"wrong stream", []byte(`{"stream_id":"other","sequence":2,"previous_anchor_digest":"` + previous + `","payload_digest":"` + strings.Repeat("c", 64) + `"}`), previous},
		{"unsafe sequence", testEnvelopeJSON(t, MaxSafeInteger+1, previous, strings.Repeat("c", 64)), previous},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository := &fakeRepository{publishResult: PublishResult{Status: "published"}}
			server := testServer(t, repository, &fakeVerifier{}, ExporterRole)
			connection := newMemoryConn(requestLine(t, "publish", map[string]any{
				"expected_previous_digest": test.expected, "envelope": json.RawMessage(test.envelope),
			}, nil))
			if code := protocolCode(server.ServeConn(context.Background(), connection)); code != "request_invalid" {
				t.Fatalf("error code = %q", code)
			}
			if repository.published != nil {
				t.Fatal("repository was called for invalid publish")
			}
		})
	}
}

func TestPeerRoleMatrixDeniesCrossCapability(t *testing.T) {
	previous := strings.Repeat("a", 64)
	payload := strings.Repeat("b", 64)
	tests := []struct {
		name       string
		role       PeerRole
		operation  string
		parameters any
	}{
		{"recovery publish", RecoveryRole, "publish", map[string]any{
			"expected_previous_digest": previous,
			"envelope":                 json.RawMessage(testEnvelopeJSON(t, 2, previous, payload)),
		}},
		{"exporter page", ExporterRole, "read_page", map[string]any{
			"after_sequence": 0, "through_sequence": 1, "limit": 1,
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository := &fakeRepository{}
			server := testServer(t, repository, &fakeVerifier{}, test.role)
			connection := newMemoryConn(requestLine(t, test.operation, test.parameters, nil))
			if code := protocolCode(server.ServeConn(context.Background(), connection)); code != "operation_denied" {
				t.Fatalf("error code = %q", code)
			}
			response := responseDocument(t, connection)
			if response["status"] != "error" || response["error_code"] != "operation_denied" {
				t.Fatalf("unexpected response: %#v", response)
			}
			if repository.published != nil || repository.pageArgs != [3]int64{} {
				t.Fatal("repository was called for denied operation")
			}
		})
	}
}

func TestReadHeadReturnsOnlyVerifiedContiguousHead(t *testing.T) {
	firstDigest := strings.Repeat("a", 64)
	secondDigest := strings.Repeat("b", 64)
	repository := &fakeRepository{head: Head{
		Current:  testEnvelopeJSON(t, 2, firstDigest, secondDigest),
		Previous: testEnvelopeJSON(t, 1, genesisDigest, firstDigest),
	}}
	server := testServer(t, repository, &fakeVerifier{}, RecoveryRole)
	connection := newMemoryConn(requestLine(t, "read_head", map[string]any{}, nil))
	if err := server.ServeConn(context.Background(), connection); err != nil {
		t.Fatal(err)
	}
	response := responseDocument(t, connection)
	result := response["result"].(map[string]any)
	if result["current"].(map[string]any)["sequence"] != float64(2) ||
		result["previous"].(map[string]any)["sequence"] != float64(1) {
		t.Fatalf("unexpected head: %#v", result)
	}

	repository.head.Previous = testEnvelopeJSON(t, 1, genesisDigest, strings.Repeat("c", 64))
	connection = newMemoryConn(requestLine(t, "read_head", map[string]any{}, nil))
	if code := protocolCode(server.ServeConn(context.Background(), connection)); code != "store_invalid" {
		t.Fatalf("divergent predecessor code = %q", code)
	}
}

func TestReadPageEnforcesBoundsAndContinuity(t *testing.T) {
	repository := &fakeRepository{page: [][]byte{
		testEnvelopeJSON(t, 2, strings.Repeat("a", 64), strings.Repeat("b", 64)),
		testEnvelopeJSON(t, 3, strings.Repeat("b", 64), strings.Repeat("c", 64)),
	}}
	server := testServer(t, repository, &fakeVerifier{}, RecoveryRole)
	connection := newMemoryConn(requestLine(t, "read_page", map[string]any{
		"after_sequence": 1, "through_sequence": 3, "limit": 2,
	}, nil))
	if err := server.ServeConn(context.Background(), connection); err != nil {
		t.Fatal(err)
	}
	if repository.pageArgs != [3]int64{1, 3, 2} {
		t.Fatalf("page args = %#v", repository.pageArgs)
	}

	repository.page[1] = testEnvelopeJSON(t, 4, strings.Repeat("b", 64), strings.Repeat("c", 64))
	connection = newMemoryConn(requestLine(t, "read_page", map[string]any{
		"after_sequence": 1, "through_sequence": 4, "limit": 2,
	}, nil))
	if code := protocolCode(server.ServeConn(context.Background(), connection)); code != "store_invalid" {
		t.Fatalf("non-contiguous page code = %q", code)
	}

	connection = newMemoryConn(requestLine(t, "read_page", map[string]any{
		"after_sequence": 1, "through_sequence": 2, "limit": MaxPageSize + 1,
	}, nil))
	if code := protocolCode(server.ServeConn(context.Background(), connection)); code != "request_invalid" {
		t.Fatalf("oversize page code = %q", code)
	}
}

func TestHealthRequiresFreshBoundedSemantics(t *testing.T) {
	repository := &fakeRepository{health: Health{
		Status: "ready", LockContract: "verified", MirrorState: "in_sync",
		CommonSequence: 7, ReasonCode: "ok",
	}}
	server := testServer(t, repository, &fakeVerifier{}, ExporterRole)
	connection := newMemoryConn(requestLine(t, "health", map[string]any{}, nil))
	if err := server.ServeConn(context.Background(), connection); err != nil {
		t.Fatal(err)
	}
	result := responseDocument(t, connection)["result"].(map[string]any)
	if result["status"] != "ready" || result["lock_contract"] != "verified" ||
		result["mirror_state"] != "in_sync" || result["reason_code"] != "ok" {
		t.Fatalf("unexpected health: %#v", result)
	}

	repository.health.MirrorState = "lagging"
	connection = newMemoryConn(requestLine(t, "health", map[string]any{}, nil))
	if code := protocolCode(server.ServeConn(context.Background(), connection)); code != "store_invalid" {
		t.Fatalf("invalid ready health code = %q", code)
	}
}

func TestStrictRequestsRejectUnknownDuplicateAndMalformedFields(t *testing.T) {
	base := func() map[string]any {
		return map[string]any{
			"version": ProtocolVersion, "purpose": Purpose, "request_id": "req-123",
			"operation": "health", "stream_id": testConfig.StreamID, "parameters": map[string]any{},
		}
	}
	tests := []struct {
		name string
		line string
	}{
		{"unknown root", requestLine(t, "health", map[string]any{}, func(value map[string]any) { value["extra"] = true })},
		{"wrong root case", strings.Replace(requestLine(t, "health", map[string]any{}, nil), `"request_id":`, `"REQUEST_ID":`, 1)},
		{"root case alias", strings.Replace(requestLine(t, "health", map[string]any{}, nil), `"request_id":`, `"REQUEST_ID":"other","request_id":`, 1)},
		{"null parameters", requestLine(t, "health", nil, nil)},
		{"wrong version", requestLine(t, "health", map[string]any{}, func(value map[string]any) { value["version"] = 2 })},
		{"wrong purpose", requestLine(t, "health", map[string]any{}, func(value map[string]any) { value["purpose"] = "other" })},
		{"wrong stream", requestLine(t, "health", map[string]any{}, func(value map[string]any) { value["stream_id"] = "other" })},
		{"bad request id", requestLine(t, "health", map[string]any{}, func(value map[string]any) { value["request_id"] = "bad id" })},
		{"unknown operation", requestLine(t, "delete", map[string]any{}, nil)},
		{"unknown parameter", requestLine(t, "health", map[string]any{"provider": "oss"}, nil)},
		{"duplicate root", `{"version":1,"version":1,"purpose":"` + Purpose + `","request_id":"req-123","operation":"health","stream_id":"` + testConfig.StreamID + `","parameters":{}}\n`},
		{"duplicate parameter", `{"version":1,"purpose":"` + Purpose + `","request_id":"req-123","operation":"read_page","stream_id":"` + testConfig.StreamID + `","parameters":{"after_sequence":0,"after_sequence":0,"through_sequence":1,"limit":1}}\n`},
		{"parameter case alias", requestLine(t, "publish", map[string]any{"EXPECTED_PREVIOUS_DIGEST": strings.Repeat("a", 64), "expected_previous_digest": strings.Repeat("a", 64), "envelope": map[string]any{}}, nil)},
		{"null publish envelope", requestLine(t, "publish", map[string]any{"expected_previous_digest": strings.Repeat("a", 64), "envelope": nil}, nil)},
		{"invalid utf8", string([]byte{'{', 0xff, '}', '\n'})},
		{"carriage return", strings.TrimSuffix(requestLine(t, "health", map[string]any{}, nil), "\n") + "\r\n"},
		{"trailing request", requestLine(t, "health", map[string]any{}, nil) + requestLine(t, "health", map[string]any{}, nil)},
	}
	_ = base
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := testServer(t, &fakeRepository{}, &fakeVerifier{}, ExporterRole)
			connection := newMemoryConn(test.line)
			if code := protocolCode(server.ServeConn(context.Background(), connection)); code != "request_invalid" {
				t.Fatalf("error code = %q", code)
			}
		})
	}
}

func TestRequestReadIsBoundedBeforeRepository(t *testing.T) {
	reader := &countingReader{reader: strings.NewReader(strings.Repeat("x", MaxRequestBytes*4))}
	connection := newMemoryConn("")
	connection.input = reader
	repository := &fakeRepository{}
	server := testServer(t, repository, &fakeVerifier{}, ExporterRole)
	if code := protocolCode(server.ServeConn(context.Background(), connection)); code != "request_invalid" {
		t.Fatalf("error code = %q", code)
	}
	if reader.read > MaxRequestBytes+1 || repository.published != nil || repository.pageArgs != [3]int64{} {
		t.Fatalf("unbounded read or repository call: bytes=%d", reader.read)
	}
}

func TestPeerReceivesRequestDeadline(t *testing.T) {
	var peerContext context.Context
	server, err := NewServer(testConfig, &fakeRepository{health: Health{
		Status: "ready", LockContract: "verified", MirrorState: "in_sync", ReasonCode: "ok",
	}}, &fakeVerifier{}, PeerAuthorizerFunc(func(ctx context.Context, _ net.Conn) (PeerRole, error) {
		peerContext = ctx
		return ExporterRole, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	server.Clock = func() time.Time { return testNow }
	if err := server.ServeConn(context.Background(), newMemoryConn(requestLine(t, "health", map[string]any{}, nil))); err != nil {
		t.Fatal(err)
	}
	deadline, ok := peerContext.Deadline()
	if !ok || time.Until(deadline) > server.Deadline || time.Until(deadline) <= 0 {
		t.Fatal("peer authorizer did not receive bounded request context")
	}
}

func TestExpiredRepositoryCannotProduceSuccess(t *testing.T) {
	repository := &fakeRepository{
		health:               Health{Status: "ready", LockContract: "verified", MirrorState: "in_sync", ReasonCode: "ok"},
		healthWaitForContext: true,
	}
	server := testServer(t, repository, &fakeVerifier{}, ExporterRole)
	connection := newMemoryConn(requestLine(t, "health", map[string]any{}, nil))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := server.ServeConn(ctx, connection); protocolCode(err) != "deadline_exceeded" {
		t.Fatalf("expired repository result was accepted: %v", err)
	}
	response := responseDocument(t, connection)
	if response["status"] != "error" || response["error_code"] != "deadline_exceeded" {
		t.Fatalf("expired repository produced success: %#v", response)
	}
}

func TestRepositoryErrorsAreStableAndDoNotLeak(t *testing.T) {
	tests := []struct {
		err  error
		code string
	}{
		{ErrRepositoryUnavailable, "store_unavailable"},
		{ErrRepositoryInvalid, "store_invalid"},
		{errors.New("provider endpoint and credential detail"), "internal_error"},
		{context.DeadlineExceeded, "deadline_exceeded"},
	}
	for _, test := range tests {
		repository := &fakeRepository{headError: test.err}
		server := testServer(t, repository, &fakeVerifier{}, ExporterRole)
		connection := newMemoryConn(requestLine(t, "read_head", map[string]any{}, nil))
		if code := protocolCode(server.ServeConn(context.Background(), connection)); code != test.code {
			t.Fatalf("error code = %q, want %q", code, test.code)
		}
		if strings.Contains(connection.output.String(), "provider") || strings.Contains(connection.output.String(), "credential") ||
			responseDocument(t, connection)["error_code"] != test.code {
			t.Fatal("repository error leaked or was not mapped")
		}
	}
}

func TestPeerDenialAndRuntimeFailuresFailClosed(t *testing.T) {
	repository := &fakeRepository{}
	denied := PeerAuthorizerFunc(func(context.Context, net.Conn) (PeerRole, error) {
		return "", errors.New("denied")
	})
	server, err := NewServer(testConfig, repository, &fakeVerifier{}, denied)
	if err != nil {
		t.Fatal(err)
	}
	server.Clock = func() time.Time { return testNow }
	connection := newMemoryConn(requestLine(t, "health", map[string]any{}, nil))
	if code := protocolCode(server.ServeConn(nil, connection)); code != "server_invalid" {
		t.Fatalf("nil context code = %q", code)
	}
	if code := protocolCode(server.ServeConn(context.Background(), connection)); code != "peer_denied" || connection.output.Len() != 0 {
		t.Fatal("denied peer received a response")
	}

	connection = newMemoryConn(requestLine(t, "health", map[string]any{}, nil))
	connection.deadlineError = errors.New("deadline failed")
	server.Peers = allowPeer(ExporterRole)
	if code := protocolCode(server.ServeConn(context.Background(), connection)); code != "connection_invalid" {
		t.Fatalf("deadline error code = %q", code)
	}

	connection = newMemoryConn(requestLine(t, "health", map[string]any{}, nil))
	connection.writeError = errors.New("write failed")
	repository.health = Health{Status: "ready", LockContract: "verified", MirrorState: "in_sync", ReasonCode: "ok"}
	if code := protocolCode(server.ServeConn(context.Background(), connection)); code != "response_failed" {
		t.Fatalf("write error code = %q", code)
	}
	connection = newMemoryConn(requestLine(t, "health", map[string]any{}, nil))
	connection.shortWrite = true
	if code := protocolCode(server.ServeConn(context.Background(), connection)); code != "response_failed" {
		t.Fatalf("short write code = %q", code)
	}
}

func TestConstructorsRejectInvalidSecurityConfiguration(t *testing.T) {
	repository := &fakeRepository{}
	verifier := &fakeVerifier{}
	peers := allowPeer(ExporterRole)
	tests := []struct {
		config     Config
		repository Repository
		verifier   EnvelopeVerifier
		peers      PeerAuthorizer
	}{
		{Config{}, repository, verifier, peers},
		{testConfig, nil, verifier, peers},
		{testConfig, repository, nil, peers},
		{testConfig, repository, verifier, nil},
	}
	for _, test := range tests {
		if server, err := NewServer(test.config, test.repository, test.verifier, test.peers); err == nil || server != nil {
			t.Fatal("invalid configuration was accepted")
		}
	}
	server := testServer(t, repository, verifier, ExporterRole)
	if code := protocolCode(server.Serve(nil, &failingListener{})); code != "server_invalid" {
		t.Fatalf("nil serve context code = %q", code)
	}
}

type oneConnectionListener struct {
	connection net.Conn
	accepted   bool
	closed     chan struct{}
}

func (listener *oneConnectionListener) Accept() (net.Conn, error) {
	if !listener.accepted {
		listener.accepted = true
		return listener.connection, nil
	}
	<-listener.closed
	return nil, errors.New("listener closed")
}
func (listener *oneConnectionListener) Close() error {
	select {
	case <-listener.closed:
	default:
		close(listener.closed)
	}
	return nil
}
func (*oneConnectionListener) Addr() net.Addr { return testAddr("listener") }

type failingListener struct{}

func (*failingListener) Accept() (net.Conn, error) { return nil, errors.New("accept failed") }
func (*failingListener) Close() error              { return nil }
func (*failingListener) Addr() net.Addr            { return testAddr("listener") }

func TestServeProcessesConnectionAndStopsWithContext(t *testing.T) {
	repository := &fakeRepository{
		health:       Health{Status: "ready", LockContract: "verified", MirrorState: "in_sync", ReasonCode: "ok"},
		healthCalled: make(chan struct{}, 1),
	}
	server := testServer(t, repository, &fakeVerifier{}, ExporterRole)
	server.Peers = PeerAuthorizerFunc(func(context.Context, net.Conn) (PeerRole, error) {
		return ExporterRole, nil
	})
	serverConnection, clientConnection := net.Pipe()
	listener := &oneConnectionListener{connection: serverConnection, closed: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, listener) }()
	request := requestLine(t, "health", map[string]any{}, nil)
	if _, err := clientConnection.Write([]byte(request)); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 4096)
	if err := clientConnection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	count, err := clientConnection.Read(response)
	if err != nil || !bytes.Contains(response[:count], []byte(`"status":"ok"`)) {
		t.Fatalf("response = %q, error = %v", response[:count], err)
	}
	clientConnection.Close()
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	if code := protocolCode(server.Serve(context.Background(), &failingListener{})); code != "accept_failed" {
		t.Fatalf("accept failure code = %q", code)
	}
	if code := protocolCode(server.Serve(context.Background(), nil)); code != "server_invalid" {
		t.Fatalf("invalid listener code = %q", code)
	}
}

func TestPublishRepositoryResultsFailClosed(t *testing.T) {
	previous := strings.Repeat("a", 64)
	payload := strings.Repeat("b", 64)
	envelope := testEnvelopeJSON(t, 2, previous, payload)
	tests := []struct {
		name   string
		result PublishResult
		err    error
		code   string
	}{
		{"unavailable", PublishResult{}, ErrRepositoryUnavailable, "store_unavailable"},
		{"invalid", PublishResult{}, ErrRepositoryInvalid, "store_invalid"},
		{"unknown status", PublishResult{Status: "unknown"}, nil, "store_invalid"},
		{"published with current", PublishResult{Status: "published", Current: envelope}, nil, "store_invalid"},
		{"conflict missing current", PublishResult{Status: "conflict"}, nil, "store_invalid"},
		{"conflict wrong sequence", PublishResult{Status: "conflict", Current: testEnvelopeJSON(t, 3, previous, payload)}, nil, "store_invalid"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository := &fakeRepository{publishResult: test.result, publishError: test.err}
			server := testServer(t, repository, &fakeVerifier{}, ExporterRole)
			connection := newMemoryConn(requestLine(t, "publish", map[string]any{
				"expected_previous_digest": previous, "envelope": json.RawMessage(envelope),
			}, nil))
			if code := protocolCode(server.ServeConn(context.Background(), connection)); code != test.code {
				t.Fatalf("error code = %q, want %q", code, test.code)
			}
		})
	}

	repository := &fakeRepository{publishResult: PublishResult{Status: "conflict", Current: envelope}}
	server := testServer(t, repository, &fakeVerifier{}, ExporterRole)
	connection := newMemoryConn(requestLine(t, "publish", map[string]any{
		"expected_previous_digest": previous, "envelope": json.RawMessage(envelope),
	}, nil))
	if err := server.ServeConn(context.Background(), connection); err != nil {
		t.Fatal(err)
	}
	result := responseDocument(t, connection)["result"].(map[string]any)
	if result["status"] != "conflict" || result["current"].(map[string]any)["sequence"] != float64(2) {
		t.Fatalf("unexpected conflict: %#v", result)
	}
}

func TestHeadVariantsAndRepositoryFailures(t *testing.T) {
	first := testEnvelopeJSON(t, 1, genesisDigest, strings.Repeat("a", 64))
	tests := []struct {
		name string
		head Head
		err  error
		code string
	}{
		{"empty", Head{}, nil, ""},
		{"empty with previous", Head{Previous: first}, nil, "store_invalid"},
		{"sequence one with previous", Head{Current: first, Previous: first}, nil, "store_invalid"},
		{"sequence two missing previous", Head{Current: testEnvelopeJSON(t, 2, strings.Repeat("a", 64), strings.Repeat("b", 64))}, nil, "store_invalid"},
		{"unavailable", Head{}, ErrRepositoryUnavailable, "store_unavailable"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository := &fakeRepository{head: test.head, headError: test.err}
			server := testServer(t, repository, &fakeVerifier{}, RecoveryRole)
			connection := newMemoryConn(requestLine(t, "read_head", map[string]any{}, nil))
			err := server.ServeConn(context.Background(), connection)
			if code := protocolCode(err); code != test.code {
				t.Fatalf("error code = %q, want %q", code, test.code)
			}
			if test.code == "" {
				result := responseDocument(t, connection)["result"].(map[string]any)
				if result["current"] != nil || result["previous"] != nil {
					t.Fatalf("unexpected empty head: %#v", result)
				}
			}
		})
	}
}

func TestPageAndHealthRepositoryFailures(t *testing.T) {
	pageRequest := func() string {
		return requestLine(t, "read_page", map[string]any{
			"after_sequence": 0, "through_sequence": 2, "limit": 2,
		}, nil)
	}
	for _, repository := range []*fakeRepository{
		{pageError: ErrRepositoryUnavailable},
		{page: [][]byte{
			testEnvelopeJSON(t, 1, genesisDigest, strings.Repeat("a", 64)),
			testEnvelopeJSON(t, 2, strings.Repeat("a", 64), strings.Repeat("b", 64)),
			testEnvelopeJSON(t, 3, strings.Repeat("b", 64), strings.Repeat("c", 64)),
		}},
		{page: [][]byte{[]byte(`{"bad":true}`)}},
	} {
		server := testServer(t, repository, &fakeVerifier{}, RecoveryRole)
		connection := newMemoryConn(pageRequest())
		code := protocolCode(server.ServeConn(context.Background(), connection))
		if code != "store_unavailable" && code != "store_invalid" {
			t.Fatalf("page error code = %q", code)
		}
	}

	for _, health := range []Health{
		{Status: "repair_required", LockContract: "verified", MirrorState: "lagging", CommonSequence: 1, ReasonCode: "mirror_lag"},
		{Status: "blocked", LockContract: "unverified", MirrorState: "invalid", ReasonCode: "lock_invalid"},
	} {
		repository := &fakeRepository{health: health}
		server := testServer(t, repository, &fakeVerifier{}, RecoveryRole)
		connection := newMemoryConn(requestLine(t, "health", map[string]any{}, nil))
		if err := server.ServeConn(context.Background(), connection); err != nil {
			t.Fatal(err)
		}
	}

	repository := &fakeRepository{healthError: ErrRepositoryUnavailable}
	server := testServer(t, repository, &fakeVerifier{}, RecoveryRole)
	connection := newMemoryConn(requestLine(t, "health", map[string]any{}, nil))
	if code := protocolCode(server.ServeConn(context.Background(), connection)); code != "store_unavailable" {
		t.Fatalf("health error code = %q", code)
	}
}

func TestVerifierFailureAndMalformedJSONStructuresFailClosed(t *testing.T) {
	repository := &fakeRepository{
		head: Head{Current: testEnvelopeJSON(t, 1, genesisDigest, strings.Repeat("a", 64))},
	}
	server := testServer(t, repository, &fakeVerifier{err: errors.New("bad signature")}, RecoveryRole)
	connection := newMemoryConn(requestLine(t, "read_head", map[string]any{}, nil))
	if code := protocolCode(server.ServeConn(context.Background(), connection)); code != "store_invalid" {
		t.Fatalf("verifier failure code = %q", code)
	}

	for _, value := range [][]byte{
		[]byte(`[]`),
		[]byte(`{"a":[{"b":1},{"b":2}]}`),
		[]byte(`{"a":{"b":1,"b":2}}`),
		[]byte(`{"a":1} trailing`),
	} {
		_ = rejectDuplicateJSONKeys(value)
	}
	if err := decodeStrict([]byte(`{"unknown":true}`), &emptyParameters{}); err == nil {
		t.Fatal("unknown strict field was accepted")
	}
}

func TestErrorReportingAndInvalidServerState(t *testing.T) {
	if (&ProtocolError{Code: "test"}).Error() != "test" {
		t.Fatal("protocol error did not preserve its code")
	}
	repository := &fakeRepository{
		health: Health{Status: "ready", LockContract: "verified", MirrorState: "in_sync", ReasonCode: "ok"},
	}
	server := testServer(t, repository, &fakeVerifier{}, ExporterRole)
	server.OnError = func(string) { panic("observer failure") }
	server.report("test")
	server.OnError = nil
	server.report("ignored")

	for _, mutate := range []func(*Server){
		func(value *Server) { value.Clock = nil },
		func(value *Server) { value.Deadline = time.Second },
		func(value *Server) { value.MaxConcurrent = maximumConcurrency + 1 },
		func(value *Server) { value.Repository = nil },
	} {
		copy := *server
		mutate(&copy)
		if code := protocolCode(copy.ServeConn(context.Background(), newMemoryConn(requestLine(t, "health", map[string]any{}, nil)))); code != "server_invalid" {
			t.Fatalf("invalid server code = %q", code)
		}
	}

	if roleAllows(PeerRole("unknown"), "health") {
		t.Fatal("unknown peer role was authorized")
	}
	if _, err := server.execute(context.Background(), wireRequest{Operation: "unknown"}); protocolCode(err) != "request_invalid" {
		t.Fatal("unknown operation did not fail closed")
	}
	if protocolErrorCode(errors.New("detail")) != "internal_error" {
		t.Fatal("internal error was not reduced")
	}

	connection := newMemoryConn(requestLine(t, "read_head", map[string]any{}, nil))
	connection.writeError = errors.New("write failed")
	repository.headError = ErrRepositoryUnavailable
	if code := protocolCode(server.ServeConn(context.Background(), connection)); code != "response_failed" {
		t.Fatalf("error response failure code = %q", code)
	}
}
