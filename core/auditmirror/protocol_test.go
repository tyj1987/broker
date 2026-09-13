package auditmirror

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

var protocolTestNow = time.Now().UTC().Truncate(time.Second)

type protocolBackend struct {
	binding   Binding
	inspect   LockState
	create    CreateResult
	read      ReadResult
	list      ListResult
	retention RetentionResult
	err       error
	calls     []string
	mu        sync.Mutex
}

func newProtocolBackend(binding Binding) *protocolBackend {
	return &protocolBackend{
		binding: binding,
		inspect: LockState{
			Compliance: true, Versioning: true, RetentionDays: RetentionDays,
			TrustGeneration: binding.TrustGeneration(),
		},
		create: CreateResult{Status: "created"},
		read:   ReadResult{Envelope: []byte(`{"anchor":"one"}`)},
		list:   ListResult{Sequences: []int64{1, 2}, NextAfter: 2, Truncated: true},
		retention: RetentionResult{
			Mode: "COMPLIANCE", RetainUntil: protocolTestNow.Add(366 * 24 * time.Hour),
		},
	}
}

func (backend *protocolBackend) record(operation string) error {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	backend.calls = append(backend.calls, operation)
	return backend.err
}

func (backend *protocolBackend) Inspect(_ context.Context, request InspectRequest) (LockState, error) {
	if !request.ValidFor(backend.binding) {
		return LockState{}, ErrContractRejected
	}
	return backend.inspect, backend.record("inspect")
}

func (backend *protocolBackend) Create(_ context.Context, request CreateRequest) (CreateResult, error) {
	if !request.ValidAt(backend.binding, protocolTestNow) {
		return CreateResult{}, ErrContractRejected
	}
	return backend.create, backend.record("create")
}

func (backend *protocolBackend) Read(_ context.Context, request ReadRequest) (ReadResult, error) {
	if !request.ValidFor(backend.binding) {
		return ReadResult{}, ErrContractRejected
	}
	return backend.read, backend.record("read")
}

func (backend *protocolBackend) List(_ context.Context, request ListRequest) (ListResult, error) {
	if !request.ValidFor(backend.binding) {
		return ListResult{}, ErrContractRejected
	}
	return backend.list, backend.record("list")
}

func (backend *protocolBackend) Retention(_ context.Context, request ReadRequest) (RetentionResult, error) {
	if !request.ValidFor(backend.binding) {
		return RetentionResult{}, ErrContractRejected
	}
	return backend.retention, backend.record("retention")
}

func protocolServer(t *testing.T, binding Binding, backend Client) *Server {
	t.Helper()
	server, err := NewServer(binding, backend, PeerAuthorizerFunc(func(context.Context, net.Conn) error { return nil }))
	if err != nil {
		t.Fatal(err)
	}
	server.Clock = func() time.Time { return protocolTestNow }
	server.Deadline = time.Second
	return server
}

func protocolDial(t *testing.T, server *Server) dialContextFunc {
	t.Helper()
	return func(context.Context, string, string) (net.Conn, error) {
		client, worker := net.Pipe()
		go func() {
			defer worker.Close()
			_ = server.ServeConn(context.Background(), worker)
		}()
		return client, nil
	}
}

func protocolClient(t *testing.T, server *Server) *TransportClient {
	t.Helper()
	client, err := newTransportClient(server.Binding, "test-mirror.sock", protocolDial(t, server))
	if err != nil {
		t.Fatal(err)
	}
	client.deadline = time.Second
	client.random = bytes.NewReader(bytes.Repeat([]byte{0x42}, 128))
	return client
}

func TestTransportRoundTripAllOperations(t *testing.T) {
	binding := testBinding(t)
	backend := newProtocolBackend(binding)
	client := protocolClient(t, protocolServer(t, binding, backend))
	ctx := context.Background()

	inspectRequest, _ := NewInspectRequest(binding)
	if result, err := client.Inspect(ctx, inspectRequest); err != nil || result != backend.inspect {
		t.Fatalf("Inspect() = %#v, %v", result, err)
	}
	createRequest, _ := NewCreateRequest(binding, 1, backend.read.Envelope, protocolTestNow)
	if result, err := client.Create(ctx, createRequest); err != nil || result.Status != "created" {
		t.Fatalf("Create() = %#v, %v", result, err)
	}
	readRequest, _ := NewReadRequest(binding, 1)
	if result, err := client.Read(ctx, readRequest); err != nil || !bytes.Equal(result.Envelope, backend.read.Envelope) {
		t.Fatalf("Read() = %#v, %v", result, err)
	}
	listRequest, _ := NewListRequest(binding, 0, 2)
	if result, err := client.List(ctx, listRequest); err != nil || len(result.Sequences) != 2 || !result.Truncated {
		t.Fatalf("List() = %#v, %v", result, err)
	}
	if result, err := client.Retention(ctx, readRequest); err != nil || result != backend.retention {
		t.Fatalf("Retention() = %#v, %v", result, err)
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if strings.Join(backend.calls, ",") != "inspect,create,read,list,retention" {
		t.Fatalf("calls = %v", backend.calls)
	}
}

func TestTransportRejectsMismatchedRequestsBeforeDial(t *testing.T) {
	binding := testBinding(t)
	other, _ := NewBinding("audit.other", binding.Prefix(), binding.ProfileID(), binding.TrustGeneration())
	dials := 0
	client, err := newTransportClient(binding, "test.sock", func(context.Context, string, string) (net.Conn, error) {
		dials++
		return nil, errors.New("unexpected")
	})
	if err != nil {
		t.Fatal(err)
	}
	inspect, _ := NewInspectRequest(other)
	create, _ := NewCreateRequest(other, 1, []byte("x"), protocolTestNow)
	read, _ := NewReadRequest(other, 1)
	list, _ := NewListRequest(other, 0, 1)
	if _, err = client.Inspect(context.Background(), inspect); !errors.Is(err, ErrContractRejected) {
		t.Fatalf("Inspect error = %v", err)
	}
	if _, err = client.Create(context.Background(), create); !errors.Is(err, ErrContractRejected) {
		t.Fatalf("Create error = %v", err)
	}
	if _, err = client.Read(context.Background(), read); !errors.Is(err, ErrContractRejected) {
		t.Fatalf("Read error = %v", err)
	}
	if _, err = client.List(context.Background(), list); !errors.Is(err, ErrContractRejected) {
		t.Fatalf("List error = %v", err)
	}
	if _, err = client.Retention(context.Background(), read); !errors.Is(err, ErrContractRejected) {
		t.Fatalf("Retention error = %v", err)
	}
	if dials != 0 {
		t.Fatalf("dials = %d", dials)
	}
}

func TestServerRejectsPeerBeforeReadingRequest(t *testing.T) {
	binding := testBinding(t)
	backend := newProtocolBackend(binding)
	server, _ := NewServer(binding, backend, PeerAuthorizerFunc(func(context.Context, net.Conn) error {
		return errors.New("denied")
	}))
	server.Clock = func() time.Time { return protocolTestNow }
	server.Deadline = 100 * time.Millisecond
	client, worker := net.Pipe()
	defer client.Close()
	done := make(chan error, 1)
	go func() { done <- server.ServeConn(context.Background(), worker); _ = worker.Close() }()
	if err := <-done; protocolErrorCode(err) != "peer_denied" {
		t.Fatalf("ServeConn error = %v", err)
	}
	buffer := make([]byte, 1)
	if _, err := client.Read(buffer); !errors.Is(err, io.EOF) {
		t.Fatalf("unauthorized peer received response: %v", err)
	}
	if len(backend.calls) != 0 {
		t.Fatalf("backend called: %v", backend.calls)
	}
}

func TestServerRejectsMalformedAndMismatchedFrames(t *testing.T) {
	binding := testBinding(t)
	backend := newProtocolBackend(binding)
	server := protocolServer(t, binding, backend)
	valid := wireRequest{
		Version: ContractVersion, Purpose: ProtocolPurpose, RequestID: strings.Repeat("a", 32),
		Operation: "inspect", StreamID: binding.StreamID(), Prefix: binding.Prefix(),
		ProfileID: binding.ProfileID(), TrustGenerationSHA256: trustGenerationHex(binding),
		RetentionDays: RetentionDays, Parameters: json.RawMessage(`{}`),
	}
	validFrame, _ := json.Marshal(valid)
	if decoded, err := decodeWireRequest(validFrame, binding); err != nil || decoded.Operation != "inspect" {
		t.Fatalf("valid request rejected: %s: %v", validFrame, err)
	}
	mutations := map[string]func(*wireRequest){
		"version":         func(value *wireRequest) { value.Version++ },
		"purpose":         func(value *wireRequest) { value.Purpose = "other" },
		"request id":      func(value *wireRequest) { value.RequestID = "bad" },
		"operation":       func(value *wireRequest) { value.Operation = "delete" },
		"stream":          func(value *wireRequest) { value.StreamID = "audit.other" },
		"prefix":          func(value *wireRequest) { value.Prefix = "anchors/v2" },
		"profile":         func(value *wireRequest) { value.ProfileID = "other" },
		"generation":      func(value *wireRequest) { value.TrustGenerationSHA256 = strings.Repeat("0", 64) },
		"retention":       func(value *wireRequest) { value.RetentionDays-- },
		"null parameters": func(value *wireRequest) { value.Parameters = json.RawMessage(`null`) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			value := valid
			mutate(&value)
			frame, _ := json.Marshal(value)
			if _, err := decodeWireRequest(frame, binding); protocolErrorCode(err) != "request_invalid" {
				t.Fatalf("decode error = %v", err)
			}
		})
	}
	for _, frame := range [][]byte{
		[]byte(`{}`), []byte(`{"version":1,"version":1}`), []byte("{}\r\n"),
		bytes.Repeat([]byte("x"), MaxRequestBytes+1),
	} {
		client, worker := net.Pipe()
		done := make(chan error, 1)
		go func() { done <- server.ServeConn(context.Background(), worker); _ = worker.Close() }()
		_, _ = client.Write(append(frame, '\n'))
		_ = client.Close()
		if err := <-done; protocolErrorCode(err) != "request_invalid" {
			t.Fatalf("frame error = %v", err)
		}
	}
	if len(backend.calls) != 0 {
		t.Fatalf("backend called: %v", backend.calls)
	}
}

func TestProtocolMapsBackendErrorsWithoutDetails(t *testing.T) {
	binding := testBinding(t)
	request, _ := NewReadRequest(binding, 1)
	for _, test := range []struct {
		backend error
		want    error
	}{
		{ErrNotFound, ErrNotFound},
		{ErrContractRejected, ErrContractRejected},
		{errors.New("provider response contained sensitive detail"), ErrUnavailable},
	} {
		backend := newProtocolBackend(binding)
		backend.err = test.backend
		client := protocolClient(t, protocolServer(t, binding, backend))
		_, err := client.Read(context.Background(), request)
		if !errors.Is(err, test.want) || strings.Contains(err.Error(), "sensitive") {
			t.Fatalf("Read error = %v, want %v", err, test.want)
		}
	}
}

func TestProtocolRejectsInvalidWorkerResults(t *testing.T) {
	binding := testBinding(t)
	readRequest, _ := NewReadRequest(binding, 1)
	listRequest, _ := NewListRequest(binding, 0, 2)
	inspectRequest, _ := NewInspectRequest(binding)
	createRequest, _ := NewCreateRequest(binding, 1, []byte("x"), protocolTestNow)
	tests := []struct {
		name string
		set  func(*protocolBackend)
		call func(*TransportClient) error
	}{
		{"inspect", func(b *protocolBackend) { b.inspect.Versioning = false }, func(c *TransportClient) error { _, e := c.Inspect(context.Background(), inspectRequest); return e }},
		{"create", func(b *protocolBackend) { b.create.Status = "overwritten" }, func(c *TransportClient) error { _, e := c.Create(context.Background(), createRequest); return e }},
		{"read", func(b *protocolBackend) { b.read.Envelope = nil }, func(c *TransportClient) error { _, e := c.Read(context.Background(), readRequest); return e }},
		{"list", func(b *protocolBackend) { b.list.Sequences = []int64{2, 1} }, func(c *TransportClient) error { _, e := c.List(context.Background(), listRequest); return e }},
		{"retention mode", func(b *protocolBackend) { b.retention.Mode = "GOVERNANCE" }, func(c *TransportClient) error { _, e := c.Retention(context.Background(), readRequest); return e }},
		{"retention time", func(b *protocolBackend) { b.retention.RetainUntil = time.Time{} }, func(c *TransportClient) error { _, e := c.Retention(context.Background(), readRequest); return e }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			backend := newProtocolBackend(binding)
			test.set(backend)
			if err := test.call(protocolClient(t, protocolServer(t, binding, backend))); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestTransportRejectsMalformedResponses(t *testing.T) {
	binding := testBinding(t)
	inspect, _ := NewInspectRequest(binding)
	responses := []string{
		`{}`,
		`{"version":1,"purpose":"secret-broker.audit-mirror","request_id":"wrong","operation":"inspect","status":"ok","stream_id":"audit.prod","profile_id":"tencent-mirror","trust_generation_sha256":"` + trustGenerationHex(binding) + `","result":{}}`,
		`{"version":1,"purpose":"secret-broker.audit-mirror","request_id":"` + strings.Repeat("42", 16) + `","operation":"inspect","status":"ok","stream_id":"audit.prod","prefix":"anchors/v1","profile_id":"tencent-mirror","trust_generation_sha256":"` + trustGenerationHex(binding) + `","retention_days":365,"result":{}}`,
		strings.Repeat("x", MaxResponseBytes+1),
	}
	for _, response := range responses {
		client, err := newTransportClient(binding, "test.sock", func(context.Context, string, string) (net.Conn, error) {
			left, right := net.Pipe()
			go func() {
				defer right.Close()
				_, _ = readBoundedFrame(right, MaxRequestBytes)
				_, _ = io.WriteString(right, response+"\n")
			}()
			return left, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		client.deadline = time.Second
		client.random = bytes.NewReader(bytes.Repeat([]byte{0x42}, 16))
		if _, err = client.Inspect(context.Background(), inspect); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("response %q error = %v", response[:min(len(response), 40)], err)
		}
	}
}

func TestConstructorsAndHelpersFailClosed(t *testing.T) {
	binding := testBinding(t)
	if client, err := newTransportClient(Binding{}, "test.sock", func(context.Context, string, string) (net.Conn, error) { return nil, nil }); client != nil || !errors.Is(err, ErrContractRejected) {
		t.Fatalf("invalid client = %#v, %v", client, err)
	}
	if client, err := newTransportClient(binding, "", func(context.Context, string, string) (net.Conn, error) { return nil, nil }); client != nil || !errors.Is(err, ErrContractRejected) {
		t.Fatalf("empty address client = %#v, %v", client, err)
	}
	if server, err := NewServer(Binding{}, newProtocolBackend(binding), PeerAuthorizerFunc(func(context.Context, net.Conn) error { return nil })); server != nil || !errors.Is(err, ErrContractRejected) {
		t.Fatalf("invalid server = %#v, %v", server, err)
	}
	if server, err := NewServer(binding, nil, nil); server != nil || !errors.Is(err, ErrContractRejected) {
		t.Fatalf("nil server = %#v, %v", server, err)
	}
	if validListResult(ListResult{Sequences: []int64{1, 1}}, 0, 2) ||
		validListResult(ListResult{Sequences: []int64{1, 3}}, 0, 2) ||
		validListResult(ListResult{Sequences: []int64{1}, Truncated: true}, 0, 2) ||
		validListResult(ListResult{Sequences: []int64{1}, NextAfter: 1}, 0, 2) ||
		validListResult(ListResult{Sequences: []int64{MaxSequence + 1}}, 0, 2) {
		t.Fatal("invalid list accepted")
	}
	if _, err := decodeCanonicalBase64("%%%", 10); err == nil {
		t.Fatal("invalid base64 accepted")
	}
	for code, want := range map[string]error{"not_found": ErrNotFound, "request_invalid": ErrContractRejected, "bad-code": ErrUnavailable} {
		if err := mapRemoteError(code); !errors.Is(err, want) {
			t.Fatalf("mapRemoteError(%q) = %v", code, err)
		}
	}
}

func TestServerServeAcceptsConnectionsAndStopsOnCancellation(t *testing.T) {
	binding := testBinding(t)
	backend := newProtocolBackend(binding)
	server := protocolServer(t, binding, backend)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, listener) }()
	client, err := newTransportClient(binding, "test.sock", func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
	})
	if err != nil {
		t.Fatal(err)
	}
	client.deadline = time.Second
	inspect, _ := NewInspectRequest(binding)
	if _, err = client.Inspect(context.Background(), inspect); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err = <-done; err != nil {
		t.Fatalf("Serve() = %v", err)
	}
	if err = server.Serve(context.Background(), nil); protocolErrorCode(err) != "server_invalid" {
		t.Fatalf("invalid Serve() = %v", err)
	}
}

func TestServerReportsStableErrors(t *testing.T) {
	binding := testBinding(t)
	backend := newProtocolBackend(binding)
	server := protocolServer(t, binding, backend)
	reported := make(chan string, 1)
	server.OnError = func(code string) { reported <- code }
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, listener) }()
	connection, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(connection, "{}\n")
	_ = connection.Close()
	select {
	case code := <-reported:
		if code != "request_invalid" {
			t.Fatalf("reported = %q", code)
		}
	case <-time.After(time.Second):
		t.Fatal("error was not reported")
	}
	cancel()
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	server.OnError = func(string) { panic("ignored") }
	server.report("request_invalid")
}

func TestExecuteRejectsMalformedOperationParameters(t *testing.T) {
	binding := testBinding(t)
	backend := newProtocolBackend(binding)
	server := protocolServer(t, binding, backend)
	tests := []wireRequest{
		{Operation: "inspect", Parameters: json.RawMessage(`{"extra":true}`)},
		{Operation: "create", Parameters: json.RawMessage(`{}`)},
		{Operation: "create", Parameters: json.RawMessage(`{"sequence":1,"envelope_base64":"%%%","issued_at":"bad"}`)},
		{Operation: "create", Parameters: json.RawMessage(`{"sequence":0,"envelope_base64":"eA==","issued_at":"2026-09-13T00:00:00Z"}`)},
		{Operation: "read", Parameters: json.RawMessage(`{}`)},
		{Operation: "read", Parameters: json.RawMessage(`{"sequence":0}`)},
		{Operation: "retention", Parameters: json.RawMessage(`{"sequence":0}`)},
		{Operation: "list", Parameters: json.RawMessage(`{}`)},
		{Operation: "list", Parameters: json.RawMessage(`{"after_sequence":-1,"limit":1}`)},
		{Operation: "delete", Parameters: json.RawMessage(`{}`)},
	}
	for _, request := range tests {
		if _, err := server.execute(context.Background(), request, protocolTestNow); protocolErrorCode(err) != "request_invalid" {
			t.Fatalf("execute(%s, %s) = %v", request.Operation, request.Parameters, err)
		}
	}
	if len(backend.calls) != 0 {
		t.Fatalf("backend called: %v", backend.calls)
	}
}

type immediateErrorReader struct{}

func (immediateErrorReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }

type oneByteWriter struct{ bytes.Buffer }

func (writer *oneByteWriter) Write(value []byte) (int, error) {
	return writer.Buffer.Write(value[:1])
}

type zeroWriter struct{}

func (zeroWriter) Write([]byte) (int, error) { return 0, nil }

func TestProtocolUtilityFailurePaths(t *testing.T) {
	if _, err := readBoundedFrame(immediateErrorReader{}, 10); err == nil {
		t.Fatal("reader failure accepted")
	}
	if err := decodeStrict([]byte("{} {}"), &struct{}{}); err == nil {
		t.Fatal("trailing json accepted")
	}
	if err := rejectDuplicateKeys([]byte(`{"a":[{"b":1}],"a":2}`)); err == nil {
		t.Fatal("duplicate nested key accepted")
	}
	if code := protocolErrorCode(errors.New("provider detail")); code != "internal_error" {
		t.Fatalf("code = %q", code)
	}
	if (&ProtocolError{Code: "request_invalid"}).Error() != "request_invalid" {
		t.Fatal("protocol error string changed")
	}
	if resultKeys("delete") != nil {
		t.Fatal("unknown result contract accepted")
	}
	short := &oneByteWriter{}
	if err := writeBoundedFrame(short, []byte("{}"), 10); err != nil || short.String() != "{}\n" {
		t.Fatalf("short write = %q, %v", short.String(), err)
	}
	if err := writeBoundedFrame(zeroWriter{}, []byte("{}"), 10); err == nil {
		t.Fatal("zero write accepted")
	}
	if err := writeBoundedFrame(io.Discard, nil, 10); err == nil {
		t.Fatal("empty frame accepted")
	}
}

func TestTransportFailsClosedOnContextRandomAndDialFailures(t *testing.T) {
	binding := testBinding(t)
	inspect, _ := NewInspectRequest(binding)
	client, _ := newTransportClient(binding, "test.sock", func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("dial failed")
	})
	if _, err := client.Inspect(context.Background(), inspect); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("dial error = %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.Inspect(cancelled, inspect); !errors.Is(err, ErrContractRejected) {
		t.Fatalf("context error = %v", err)
	}
	client.random = immediateErrorReader{}
	if _, err := client.Inspect(context.Background(), inspect); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("random error = %v", err)
	}
	var nilClient *TransportClient
	if _, err := nilClient.Inspect(context.Background(), inspect); !errors.Is(err, ErrContractRejected) {
		t.Fatalf("nil client error = %v", err)
	}
}

type lateBackend struct{ *protocolBackend }

func (backend *lateBackend) Inspect(ctx context.Context, request InspectRequest) (LockState, error) {
	<-ctx.Done()
	return backend.protocolBackend.Inspect(context.Background(), request)
}

func TestLateBackendSuccessCannotBecomeProtocolSuccess(t *testing.T) {
	binding := testBinding(t)
	backend := &lateBackend{newProtocolBackend(binding)}
	server := protocolServer(t, binding, backend)
	server.Deadline = 25 * time.Millisecond
	client := protocolClient(t, server)
	client.deadline = 25 * time.Millisecond
	request, _ := NewInspectRequest(binding)
	if _, err := client.Inspect(context.Background(), request); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("late success error = %v", err)
	}
}

func TestServerCancellationInterruptsIdleAuthenticatedConnection(t *testing.T) {
	binding := testBinding(t)
	backend := newProtocolBackend(binding)
	authorized := make(chan struct{})
	server, err := NewServer(binding, backend, PeerAuthorizerFunc(func(context.Context, net.Conn) error {
		close(authorized)
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	server.Clock = time.Now
	server.Deadline = time.Second
	ctx, cancel := context.WithCancel(context.Background())
	client, worker := net.Pipe()
	defer client.Close()
	done := make(chan error, 1)
	go func() { done <- server.ServeConn(ctx, worker) }()
	<-authorized
	started := time.Now()
	cancel()
	select {
	case err = <-done:
		if protocolErrorCode(err) != "deadline_exceeded" || time.Since(started) > 250*time.Millisecond {
			t.Fatalf("cancelled ServeConn() = %v after %v", err, time.Since(started))
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("cancelled idle connection did not stop")
	}
	if len(backend.calls) != 0 {
		t.Fatalf("backend called: %v", backend.calls)
	}
}
