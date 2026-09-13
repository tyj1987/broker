package auditmirror

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	ProtocolPurpose       = "secret-broker.audit-mirror"
	DefaultSocketPath     = "/run/secret-broker-audit-mirror/mirror.sock"
	MaxRequestBytes       = 24 * 1024
	MaxResponseBytes      = 32 * 1024
	DefaultDeadline       = 20 * time.Second
	DefaultMaxConcurrency = 8
	maximumConcurrency    = 16
)

var (
	requestIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
	errorCodePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{1,63}$`)
)

var requestKeys = []string{
	"version", "purpose", "request_id", "operation", "stream_id", "prefix",
	"profile_id", "trust_generation_sha256", "retention_days", "parameters",
}

type dialContextFunc func(context.Context, string, string) (net.Conn, error)

type PeerAuthorizer interface {
	AuthorizePeer(context.Context, net.Conn) error
}

type PeerAuthorizerFunc func(context.Context, net.Conn) error

func (function PeerAuthorizerFunc) AuthorizePeer(ctx context.Context, connection net.Conn) error {
	return function(ctx, connection)
}

type ProtocolError struct{ Code string }

func (protocolError *ProtocolError) Error() string { return protocolError.Code }

func protocolFail(code string) error { return &ProtocolError{Code: code} }

// TransportClient implements Client over a one-request-per-connection bounded
// transport. The dial function is supplied by trusted process bootstrap code;
// request callers cannot choose a network, address, endpoint or credential.
type TransportClient struct {
	binding  Binding
	dial     dialContextFunc
	address  string
	deadline time.Duration
	random   io.Reader
}

func newTransportClient(binding Binding, address string, dial dialContextFunc) (*TransportClient, error) {
	if !binding.valid() || address == "" || len(address) > 256 || dial == nil {
		return nil, ErrContractRejected
	}
	return &TransportClient{
		binding: binding, address: address, dial: dial,
		deadline: DefaultDeadline, random: rand.Reader,
	}, nil
}

// NewOSUnixClient creates the production fixed-path client and verifies the
// mirror worker's kernel peer UID before any request bytes are written.
func NewOSUnixClient(binding Binding, workerUID uint32) (*TransportClient, error) {
	dial, err := newOSDialer(workerUID)
	if err != nil {
		return nil, ErrContractRejected
	}
	return newTransportClient(binding, DefaultSocketPath, dial)
}

func (client *TransportClient) Inspect(ctx context.Context, request InspectRequest) (LockState, error) {
	if !request.ValidFor(clientBinding(client)) {
		return LockState{}, ErrContractRejected
	}
	var result LockState
	err := client.exchange(ctx, "inspect", struct{}{}, &result)
	if err != nil {
		return LockState{}, err
	}
	if !result.Compliance || !result.Versioning || result.RetentionDays != RetentionDays ||
		result.TrustGeneration != client.binding.TrustGeneration() {
		return LockState{}, ErrUnavailable
	}
	return result, nil
}

func (client *TransportClient) Create(ctx context.Context, request CreateRequest) (CreateResult, error) {
	if !request.ValidFor(clientBinding(client)) {
		return CreateResult{}, ErrContractRejected
	}
	parameters := createParameters{
		Sequence: request.Sequence(), EnvelopeBase64: base64.StdEncoding.EncodeToString(request.Envelope()),
		IssuedAt: request.IssuedAt().Format(time.RFC3339Nano),
	}
	var result CreateResult
	err := client.exchange(ctx, "create", parameters, &result)
	if err != nil {
		return CreateResult{}, err
	}
	if result.Status != "created" && result.Status != "exists" {
		return CreateResult{}, ErrUnavailable
	}
	return result, nil
}

func (client *TransportClient) Read(ctx context.Context, request ReadRequest) (ReadResult, error) {
	if !request.ValidFor(clientBinding(client)) {
		return ReadResult{}, ErrContractRejected
	}
	var result readWireResult
	err := client.exchange(ctx, "read", sequenceParameters{Sequence: request.Sequence()}, &result)
	if err != nil {
		return ReadResult{}, err
	}
	envelope, err := decodeCanonicalBase64(result.EnvelopeBase64, MaxEnvelopeBytes)
	if err != nil || len(envelope) == 0 {
		return ReadResult{}, ErrUnavailable
	}
	return ReadResult{Envelope: envelope}, nil
}

func (client *TransportClient) List(ctx context.Context, request ListRequest) (ListResult, error) {
	if !request.ValidFor(clientBinding(client)) {
		return ListResult{}, ErrContractRejected
	}
	var result ListResult
	err := client.exchange(ctx, "list", listParameters{After: request.After(), Limit: request.Limit()}, &result)
	if err != nil {
		return ListResult{}, err
	}
	if !validListResult(result, request.After(), request.Limit()) {
		return ListResult{}, ErrUnavailable
	}
	result.Sequences = append([]int64(nil), result.Sequences...)
	return result, nil
}

func (client *TransportClient) Retention(ctx context.Context, request ReadRequest) (RetentionResult, error) {
	if !request.ValidFor(clientBinding(client)) {
		return RetentionResult{}, ErrContractRejected
	}
	var result retentionWireResult
	err := client.exchange(ctx, "retention", sequenceParameters{Sequence: request.Sequence()}, &result)
	if err != nil {
		return RetentionResult{}, err
	}
	retainUntil, err := time.Parse(time.RFC3339Nano, result.RetainUntil)
	if err != nil || result.Mode != "COMPLIANCE" || !validUTC(retainUntil) {
		return RetentionResult{}, ErrUnavailable
	}
	return RetentionResult{Mode: result.Mode, RetainUntil: retainUntil}, nil
}

func clientBinding(client *TransportClient) Binding {
	if client == nil {
		return Binding{}
	}
	return client.binding
}

func (client *TransportClient) exchange(ctx context.Context, operation string, parameters any, target any) error {
	if client == nil || !client.binding.valid() || client.dial == nil || client.random == nil ||
		client.address == "" || ctx == nil || ctx.Err() != nil ||
		client.deadline <= 0 || client.deadline > MaxMirrorWriteDuration {
		return ErrContractRejected
	}
	requestIDBytes := make([]byte, 16)
	if _, err := io.ReadFull(client.random, requestIDBytes); err != nil {
		return ErrUnavailable
	}
	requestID := hex.EncodeToString(requestIDBytes)
	parameterJSON, err := json.Marshal(parameters)
	if err != nil {
		return ErrContractRejected
	}
	request := wireRequest{
		Version: ContractVersion, Purpose: ProtocolPurpose, RequestID: requestID,
		Operation: operation, StreamID: client.binding.StreamID(), Prefix: client.binding.Prefix(),
		ProfileID:             client.binding.ProfileID(),
		TrustGenerationSHA256: trustGenerationHex(client.binding),
		RetentionDays:         client.binding.RequiredRetentionDays(), Parameters: parameterJSON,
	}
	operationContext, cancel := context.WithTimeout(ctx, client.deadline)
	defer cancel()
	connection, err := client.dial(operationContext, "unix", client.address)
	if err != nil || connection == nil {
		return ErrUnavailable
	}
	defer connection.Close()
	stopCancellation := context.AfterFunc(operationContext, func() { _ = connection.Close() })
	defer stopCancellation()
	deadline, ok := operationContext.Deadline()
	if !ok || operationContext.Err() != nil || connection.SetDeadline(deadline) != nil {
		return ErrUnavailable
	}
	encoded, err := json.Marshal(request)
	if err != nil || len(encoded)+1 > MaxRequestBytes {
		return ErrContractRejected
	}
	if err = writeBoundedFrame(connection, encoded, MaxRequestBytes); err != nil || operationContext.Err() != nil {
		return ErrUnavailable
	}
	frame, err := readBoundedFrame(connection, MaxResponseBytes)
	if err != nil || operationContext.Err() != nil {
		return ErrUnavailable
	}
	var response wireResponse
	if decodeStrict(frame, &response) != nil || decodeExactObject(frame, &response, response.keys()) != nil ||
		response.Version != ContractVersion ||
		response.Purpose != ProtocolPurpose || response.RequestID != requestID ||
		response.Operation != operation || response.StreamID != client.binding.StreamID() ||
		response.Prefix != client.binding.Prefix() || response.ProfileID != client.binding.ProfileID() ||
		response.RetentionDays != client.binding.RequiredRetentionDays() ||
		response.TrustGenerationSHA256 != request.TrustGenerationSHA256 {
		return ErrUnavailable
	}
	if response.Status == "error" {
		return mapRemoteError(response.ErrorCode)
	}
	if response.Status != "ok" || len(response.Result) == 0 || string(response.Result) == "null" || response.ErrorCode != "" {
		return ErrUnavailable
	}
	if decodeExactObject(response.Result, target, resultKeys(operation)) != nil || operationContext.Err() != nil {
		return ErrUnavailable
	}
	return nil
}

type Server struct {
	Binding       Binding
	Backend       Client
	Peers         PeerAuthorizer
	Clock         func() time.Time
	Deadline      time.Duration
	MaxConcurrent int
	OnError       func(string)
}

func NewServer(binding Binding, backend Client, peers PeerAuthorizer) (*Server, error) {
	if !binding.valid() || backend == nil || peers == nil {
		return nil, ErrContractRejected
	}
	return &Server{
		Binding: binding, Backend: backend, Peers: peers, Clock: time.Now,
		Deadline: DefaultDeadline, MaxConcurrent: DefaultMaxConcurrency,
	}, nil
}

func (server *Server) Serve(ctx context.Context, listener net.Listener) error {
	if !server.valid() || ctx == nil || listener == nil {
		return protocolFail("server_invalid")
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = listener.Close()
		case <-done:
		}
	}()
	defer close(done)
	semaphore := make(chan struct{}, server.MaxConcurrent)
	var workers sync.WaitGroup
	defer workers.Wait()
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return protocolFail("accept_failed")
		}
		select {
		case semaphore <- struct{}{}:
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer func() { <-semaphore }()
				defer connection.Close()
				if err := server.ServeConn(ctx, connection); err != nil {
					server.report(protocolErrorCode(err))
				}
			}()
		default:
			_ = connection.Close()
			server.report("server_busy")
		}
	}
}

func (server *Server) ServeConn(ctx context.Context, connection net.Conn) error {
	if !server.valid() || ctx == nil || connection == nil {
		return protocolFail("server_invalid")
	}
	now := server.Clock().UTC()
	// The policy clock may be fixed by a trusted verifier. Socket deadlines
	// must retain the process clock's monotonic component and must not inherit a
	// historical policy timestamp.
	if !validUTC(now) || connection.SetDeadline(time.Now().Add(server.Deadline)) != nil {
		return protocolFail("connection_invalid")
	}
	requestContext, cancel := context.WithTimeout(ctx, server.Deadline)
	defer cancel()
	stopCancellation := context.AfterFunc(requestContext, func() { _ = connection.Close() })
	defer stopCancellation()
	if err := server.Peers.AuthorizePeer(requestContext, connection); err != nil {
		return protocolFail("peer_denied")
	}
	if requestContext.Err() != nil {
		return protocolFail("deadline_exceeded")
	}
	frame, err := readBoundedFrame(connection, MaxRequestBytes)
	if requestContext.Err() != nil {
		return protocolFail("deadline_exceeded")
	}
	if err != nil {
		return protocolFail("request_invalid")
	}
	request, err := decodeWireRequest(frame, server.Binding)
	if err != nil {
		return err
	}
	result, err := server.execute(requestContext, request, now)
	if err != nil {
		code := protocolErrorCode(err)
		_ = server.writeResponse(connection, request, nil, code)
		return err
	}
	if requestContext.Err() != nil {
		return protocolFail("deadline_exceeded")
	}
	return server.writeResponse(connection, request, result, "")
}

func (server *Server) valid() bool {
	return server != nil && server.Binding.valid() && server.Backend != nil && server.Peers != nil &&
		server.Clock != nil && server.Deadline > 0 && server.Deadline <= MaxMirrorWriteDuration &&
		server.MaxConcurrent > 0 && server.MaxConcurrent <= maximumConcurrency
}

func (server *Server) execute(ctx context.Context, request wireRequest, now time.Time) (any, error) {
	switch request.Operation {
	case "inspect":
		if decodeEmpty(request.Parameters) != nil {
			return nil, protocolFail("request_invalid")
		}
		typed, _ := NewInspectRequest(server.Binding)
		result, err := server.Backend.Inspect(ctx, typed)
		if err != nil {
			return nil, backendError(err)
		}
		if ctx.Err() != nil {
			return nil, protocolFail("deadline_exceeded")
		}
		if !result.Compliance || !result.Versioning || result.RetentionDays != RetentionDays ||
			result.TrustGeneration != server.Binding.TrustGeneration() {
			return nil, protocolFail("worker_invalid")
		}
		return result, nil
	case "create":
		var parameters createParameters
		if decodeExactObject(request.Parameters, &parameters, []string{"sequence", "envelope_base64", "issued_at"}) != nil {
			return nil, protocolFail("request_invalid")
		}
		envelope, err := decodeCanonicalBase64(parameters.EnvelopeBase64, MaxEnvelopeBytes)
		issuedAt, timeErr := time.Parse(time.RFC3339Nano, parameters.IssuedAt)
		if err != nil || timeErr != nil {
			return nil, protocolFail("request_invalid")
		}
		typed, err := NewCreateRequest(server.Binding, parameters.Sequence, envelope, issuedAt)
		if err != nil || !typed.ValidAt(server.Binding, now) {
			return nil, protocolFail("request_invalid")
		}
		writeContext, cancel := context.WithTimeout(ctx, MaxMirrorWriteDuration)
		defer cancel()
		result, err := server.Backend.Create(writeContext, typed)
		if err != nil {
			return nil, backendError(err)
		}
		if writeContext.Err() != nil || (result.Status != "created" && result.Status != "exists") {
			return nil, protocolFail("worker_invalid")
		}
		return result, nil
	case "read", "retention":
		var parameters sequenceParameters
		if decodeExactObject(request.Parameters, &parameters, []string{"sequence"}) != nil {
			return nil, protocolFail("request_invalid")
		}
		typed, err := NewReadRequest(server.Binding, parameters.Sequence)
		if err != nil {
			return nil, protocolFail("request_invalid")
		}
		if request.Operation == "read" {
			result, backendErr := server.Backend.Read(ctx, typed)
			if backendErr != nil {
				return nil, backendError(backendErr)
			}
			if ctx.Err() != nil {
				return nil, protocolFail("deadline_exceeded")
			}
			if len(result.Envelope) == 0 || len(result.Envelope) > MaxEnvelopeBytes {
				return nil, protocolFail("worker_invalid")
			}
			return readWireResult{EnvelopeBase64: base64.StdEncoding.EncodeToString(result.Envelope)}, nil
		}
		result, backendErr := server.Backend.Retention(ctx, typed)
		if backendErr != nil {
			return nil, backendError(backendErr)
		}
		if ctx.Err() != nil {
			return nil, protocolFail("deadline_exceeded")
		}
		if result.Mode != "COMPLIANCE" || !validUTC(result.RetainUntil) {
			return nil, protocolFail("worker_invalid")
		}
		return retentionWireResult{Mode: result.Mode, RetainUntil: result.RetainUntil.Format(time.RFC3339Nano)}, nil
	case "list":
		var parameters listParameters
		if decodeExactObject(request.Parameters, &parameters, []string{"after_sequence", "limit"}) != nil {
			return nil, protocolFail("request_invalid")
		}
		typed, err := NewListRequest(server.Binding, parameters.After, parameters.Limit)
		if err != nil {
			return nil, protocolFail("request_invalid")
		}
		result, err := server.Backend.List(ctx, typed)
		if err != nil {
			return nil, backendError(err)
		}
		if ctx.Err() != nil {
			return nil, protocolFail("deadline_exceeded")
		}
		if !validListResult(result, parameters.After, parameters.Limit) {
			return nil, protocolFail("worker_invalid")
		}
		result.Sequences = append([]int64(nil), result.Sequences...)
		return result, nil
	default:
		return nil, protocolFail("request_invalid")
	}
}

func (server *Server) writeResponse(connection net.Conn, request wireRequest, result any, code string) error {
	response := wireResponse{
		Version: ContractVersion, Purpose: ProtocolPurpose, RequestID: request.RequestID,
		Operation: request.Operation, StreamID: server.Binding.StreamID(), Prefix: server.Binding.Prefix(),
		ProfileID: server.Binding.ProfileID(), TrustGenerationSHA256: trustGenerationHex(server.Binding),
		RetentionDays: server.Binding.RequiredRetentionDays(),
	}
	if code == "" {
		response.Status = "ok"
		response.Result, _ = json.Marshal(result)
	} else {
		response.Status = "error"
		response.ErrorCode = code
	}
	encoded, err := json.Marshal(response)
	if err != nil || len(encoded)+1 > MaxResponseBytes {
		return protocolFail("response_failed")
	}
	if err = writeBoundedFrame(connection, encoded, MaxResponseBytes); err != nil {
		return protocolFail("response_failed")
	}
	return nil
}

func decodeWireRequest(frame []byte, binding Binding) (wireRequest, error) {
	var request wireRequest
	if decodeExactObject(frame, &request, requestKeys) != nil || request.Version != ContractVersion ||
		request.Purpose != ProtocolPurpose || !requestIDPattern.MatchString(request.RequestID) ||
		request.Operation == "" || request.StreamID != binding.StreamID() || request.Prefix != binding.Prefix() ||
		request.ProfileID != binding.ProfileID() || request.RetentionDays != binding.RequiredRetentionDays() ||
		request.TrustGenerationSHA256 != trustGenerationHex(binding) ||
		len(request.Parameters) == 0 || string(request.Parameters) == "null" {
		return wireRequest{}, protocolFail("request_invalid")
	}
	switch request.Operation {
	case "inspect", "create", "read", "list", "retention":
		return request, nil
	default:
		return wireRequest{}, protocolFail("request_invalid")
	}
}

type wireRequest struct {
	Version               int             `json:"version"`
	Purpose               string          `json:"purpose"`
	RequestID             string          `json:"request_id"`
	Operation             string          `json:"operation"`
	StreamID              string          `json:"stream_id"`
	Prefix                string          `json:"prefix"`
	ProfileID             string          `json:"profile_id"`
	TrustGenerationSHA256 string          `json:"trust_generation_sha256"`
	RetentionDays         int             `json:"retention_days"`
	Parameters            json.RawMessage `json:"parameters"`
}

type wireResponse struct {
	Version               int             `json:"version"`
	Purpose               string          `json:"purpose"`
	RequestID             string          `json:"request_id"`
	Operation             string          `json:"operation"`
	Status                string          `json:"status"`
	StreamID              string          `json:"stream_id"`
	Prefix                string          `json:"prefix"`
	ProfileID             string          `json:"profile_id"`
	TrustGenerationSHA256 string          `json:"trust_generation_sha256"`
	RetentionDays         int             `json:"retention_days"`
	Result                json.RawMessage `json:"result,omitempty"`
	ErrorCode             string          `json:"error_code,omitempty"`
}

func (response wireResponse) keys() []string {
	if response.Status == "error" {
		return []string{"version", "purpose", "request_id", "operation", "status", "stream_id", "prefix", "profile_id", "trust_generation_sha256", "retention_days", "error_code"}
	}
	return []string{"version", "purpose", "request_id", "operation", "status", "stream_id", "prefix", "profile_id", "trust_generation_sha256", "retention_days", "result"}
}

func trustGenerationHex(binding Binding) string {
	generation := binding.TrustGeneration()
	return hex.EncodeToString(generation[:])
}

type createParameters struct {
	Sequence       int64  `json:"sequence"`
	EnvelopeBase64 string `json:"envelope_base64"`
	IssuedAt       string `json:"issued_at"`
}

type sequenceParameters struct {
	Sequence int64 `json:"sequence"`
}

type listParameters struct {
	After int64 `json:"after_sequence"`
	Limit int   `json:"limit"`
}

type readWireResult struct {
	EnvelopeBase64 string `json:"envelope_base64"`
}

type retentionWireResult struct {
	Mode        string `json:"mode"`
	RetainUntil string `json:"retain_until"`
}

func validListResult(result ListResult, after int64, limit int) bool {
	if len(result.Sequences) > limit || result.NextAfter < 0 || result.NextAfter > MaxSequence {
		return false
	}
	previous := after
	for _, sequence := range result.Sequences {
		if previous >= MaxSequence || sequence != previous+1 || sequence > MaxSequence {
			return false
		}
		previous = sequence
	}
	if result.Truncated {
		return len(result.Sequences) > 0 && result.NextAfter == previous
	}
	return result.NextAfter == 0
}

func resultKeys(operation string) []string {
	switch operation {
	case "inspect":
		return []string{"compliance", "versioning", "retention_days", "trust_generation"}
	case "create":
		return []string{"status"}
	case "read":
		return []string{"envelope_base64"}
	case "list":
		return []string{"sequences", "next_after", "truncated"}
	case "retention":
		return []string{"mode", "retain_until"}
	default:
		return nil
	}
}

func backendError(err error) error {
	switch {
	case errors.Is(err, ErrNotFound):
		return protocolFail("not_found")
	case errors.Is(err, ErrContractRejected):
		return protocolFail("contract_rejected")
	default:
		return protocolFail("unavailable")
	}
}

func mapRemoteError(code string) error {
	if !errorCodePattern.MatchString(code) {
		return ErrUnavailable
	}
	switch code {
	case "not_found":
		return ErrNotFound
	case "contract_rejected", "request_invalid":
		return ErrContractRejected
	default:
		return ErrUnavailable
	}
}

func decodeEmpty(value []byte) error {
	var target struct{}
	return decodeExactObject(value, &target, nil)
}

func decodeCanonicalBase64(value string, limit int) ([]byte, error) {
	if value == "" || len(value) > base64.StdEncoding.EncodedLen(limit) {
		return nil, errors.New("invalid base64")
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) > limit || base64.StdEncoding.EncodeToString(decoded) != value {
		return nil, errors.New("invalid base64")
	}
	return decoded, nil
}

func readBoundedFrame(reader io.Reader, limit int) ([]byte, error) {
	buffered := bufio.NewReaderSize(reader, limit+1)
	line, err := buffered.ReadSlice('\n')
	if err != nil || len(line) > limit || buffered.Buffered() > 0 || len(line) < 2 || line[len(line)-2] == '\r' {
		return nil, errors.New("invalid frame")
	}
	return bytes.Clone(line[:len(line)-1]), nil
}

func writeBoundedFrame(writer io.Writer, payload []byte, limit int) error {
	if writer == nil || len(payload) == 0 || len(payload)+1 > limit {
		return errors.New("invalid frame")
	}
	frame := append(bytes.Clone(payload), '\n')
	for len(frame) > 0 {
		written, err := writer.Write(frame)
		if err != nil || written <= 0 || written > len(frame) {
			return errors.New("write failed")
		}
		frame = frame[written:]
	}
	return nil
}

func decodeStrict(value []byte, target any) error {
	if !utf8.Valid(value) || rejectDuplicateKeys(value) != nil {
		return errors.New("invalid json")
	}
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("trailing json")
	}
	return nil
}

func decodeExactObject(value []byte, target any, required []string) error {
	if err := decodeStrict(value, target); err != nil {
		return err
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(value, &object) != nil || object == nil || len(object) != len(required) {
		return errors.New("invalid object")
	}
	for _, key := range required {
		if raw, present := object[key]; !present || string(raw) == "null" {
			return errors.New("invalid object")
		}
	}
	return nil
}

func rejectDuplicateKeys(value []byte) error {
	decoder := json.NewDecoder(strings.NewReader(string(value)))
	if err := walkJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing json")
	}
	return nil
}

func walkJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, structured := token.(json.Delim)
	if !structured {
		return nil
	}
	switch delimiter {
	case '{':
		keys := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("invalid object key")
			}
			if _, exists := keys[key]; exists {
				return errors.New("duplicate object key")
			}
			keys[key] = struct{}{}
			if err := walkJSONValue(decoder); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := walkJSONValue(decoder); err != nil {
				return err
			}
		}
	default:
		return errors.New("invalid json")
	}
	_, err = decoder.Token()
	return err
}

func protocolErrorCode(err error) string {
	var protocolError *ProtocolError
	if errors.As(err, &protocolError) && errorCodePattern.MatchString(protocolError.Code) {
		return protocolError.Code
	}
	return "internal_error"
}

func (server *Server) report(code string) {
	if server.OnError == nil {
		return
	}
	defer func() { _ = recover() }()
	server.OnError(code)
}
