// Package auditstore implements the bounded Unix-socket protocol exposed by
// the independently isolated audit-anchor storage workload. It accepts only
// fixed audit-envelope operations and never accepts provider endpoints,
// credentials, headers, retention mutations, delete operations, or audit event
// content.
package auditstore

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/tyj1987/broker/core/auditanchor"
)

const (
	ProtocolVersion          = 1
	Purpose                  = "secret-broker.audit-anchor-store"
	MaxRequestBytes          = 24 * 1024
	MaxResponseBytes         = 576 * 1024
	MaxPageSize              = 32
	MaxSafeInteger     int64 = 9_007_199_254_740_991
	DefaultDeadline          = 35 * time.Second
	DefaultConcurrency       = 8
	maximumConcurrency       = 16
	readDeadline             = 10 * time.Second
	writeDeadline            = 30 * time.Second
)

const genesisDigest = "0000000000000000000000000000000000000000000000000000000000000000"

var (
	idPattern         = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	digestPattern     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	reasonCodePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{1,63}$`)
)

var (
	ErrRepositoryUnavailable = errors.New("audit anchor repository unavailable")
	ErrRepositoryInvalid     = errors.New("audit anchor repository invalid")
)

type PeerRole string

const (
	ExporterRole PeerRole = "exporter"
	RecoveryRole PeerRole = "recovery"
)

type PeerAuthorizer interface {
	AuthorizePeer(context.Context, net.Conn) (PeerRole, error)
}

type PeerAuthorizerFunc func(context.Context, net.Conn) (PeerRole, error)

func (function PeerAuthorizerFunc) AuthorizePeer(ctx context.Context, connection net.Conn) (PeerRole, error) {
	return function(ctx, connection)
}

type EnvelopeVerifier interface {
	Verify([]byte) (auditanchor.EnvelopeMetadata, []byte, error)
}

type PublishRequest struct {
	ExpectedPreviousDigest string
	Envelope               []byte
	Metadata               auditanchor.EnvelopeMetadata
}

type PublishResult struct {
	Status  string
	Current []byte
}

type Head struct {
	Current  []byte
	Previous []byte
}

type Health struct {
	Status         string
	LockContract   string
	MirrorState    string
	CommonSequence int64
	ReasonCode     string
}

type Repository interface {
	Publish(context.Context, PublishRequest) (PublishResult, error)
	ReadHead(context.Context) (Head, error)
	ReadPage(context.Context, int64, int64, int) ([][]byte, error)
	Health(context.Context) (Health, error)
}

type ProtocolError struct{ Code string }

func (protocolError *ProtocolError) Error() string { return protocolError.Code }

func fail(code string) error { return &ProtocolError{Code: code} }

type Config struct {
	StreamID string
}

type Server struct {
	Config        Config
	Repository    Repository
	Verifier      EnvelopeVerifier
	Peers         PeerAuthorizer
	Clock         func() time.Time
	Deadline      time.Duration
	MaxConcurrent int
	OnError       func(string)
}

func NewServer(config Config, repository Repository, verifier EnvelopeVerifier, peers PeerAuthorizer) (*Server, error) {
	if !validConfig(config) || repository == nil || verifier == nil || peers == nil {
		return nil, errors.New("audit anchor store configuration is invalid")
	}
	return &Server{
		Config: config, Repository: repository, Verifier: verifier, Peers: peers,
		Clock: time.Now, Deadline: DefaultDeadline, MaxConcurrent: DefaultConcurrency,
	}, nil
}

func validConfig(config Config) bool { return idPattern.MatchString(config.StreamID) }

func (server *Server) Serve(ctx context.Context, listener net.Listener) error {
	if server == nil || listener == nil || server.MaxConcurrent < 1 || server.MaxConcurrent > maximumConcurrency {
		return fail("server_invalid")
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
			return fail("accept_failed")
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
	if server == nil || !validConfig(server.Config) || server.Repository == nil ||
		server.Verifier == nil || server.Peers == nil || connection == nil ||
		server.Clock == nil || server.Deadline < writeDeadline || server.Deadline > 60*time.Second ||
		server.MaxConcurrent < 1 || server.MaxConcurrent > maximumConcurrency {
		return fail("server_invalid")
	}
	if err := connection.SetDeadline(server.Clock().UTC().Add(server.Deadline)); err != nil {
		return fail("connection_invalid")
	}
	role, err := server.Peers.AuthorizePeer(ctx, connection)
	if err != nil || (role != ExporterRole && role != RecoveryRole) {
		return fail("peer_denied")
	}
	request, err := readRequest(connection, server.Config)
	if err != nil {
		return err
	}
	if !roleAllows(role, request.Operation) {
		err = fail("operation_denied")
		_ = server.writeError(connection, request, protocolErrorCode(err))
		return err
	}

	operationDeadline := readDeadline
	if request.Operation == "publish" || request.Operation == "read_page" {
		operationDeadline = writeDeadline
	}
	operationContext, cancel := context.WithTimeout(ctx, operationDeadline)
	defer cancel()
	result, err := server.execute(operationContext, request)
	if err != nil {
		code := protocolErrorCode(err)
		if writeErr := server.writeError(connection, request, code); writeErr != nil {
			return writeErr
		}
		return err
	}
	return writeResponse(connection, wireSuccessResponse{
		Version: ProtocolVersion, Purpose: Purpose, RequestID: request.RequestID,
		Operation: request.Operation, Status: "ok", StreamID: server.Config.StreamID,
		Result: result,
	})
}

type wireRequest struct {
	Version    int             `json:"version"`
	Purpose    string          `json:"purpose"`
	RequestID  string          `json:"request_id"`
	Operation  string          `json:"operation"`
	StreamID   string          `json:"stream_id"`
	Parameters json.RawMessage `json:"parameters"`
}

type emptyParameters struct{}

type publishParameters struct {
	ExpectedPreviousDigest string          `json:"expected_previous_digest"`
	Envelope               json.RawMessage `json:"envelope"`
}

type readPageParameters struct {
	AfterSequence   int64 `json:"after_sequence"`
	ThroughSequence int64 `json:"through_sequence"`
	Limit           int   `json:"limit"`
}

type wireSuccessResponse struct {
	Version   int    `json:"version"`
	Purpose   string `json:"purpose"`
	RequestID string `json:"request_id"`
	Operation string `json:"operation"`
	Status    string `json:"status"`
	StreamID  string `json:"stream_id"`
	Result    any    `json:"result"`
}

type wireErrorResponse struct {
	Version   int    `json:"version"`
	Purpose   string `json:"purpose"`
	RequestID string `json:"request_id"`
	Operation string `json:"operation"`
	Status    string `json:"status"`
	ErrorCode string `json:"error_code"`
}

func readRequest(reader io.Reader, config Config) (wireRequest, error) {
	buffered := bufio.NewReaderSize(reader, MaxRequestBytes+1)
	line, err := buffered.ReadString('\n')
	if err != nil || len(line) > MaxRequestBytes || buffered.Buffered() > 0 {
		return wireRequest{}, fail("request_invalid")
	}
	line = strings.TrimSuffix(line, "\n")
	if line == "" || strings.HasSuffix(line, "\r") || rejectDuplicateJSONKeys([]byte(line)) != nil {
		return wireRequest{}, fail("request_invalid")
	}
	var request wireRequest
	if decodeStrict([]byte(line), &request) != nil || request.Version != ProtocolVersion ||
		request.Purpose != Purpose || !idPattern.MatchString(request.RequestID) ||
		request.StreamID != config.StreamID || !validOperation(request.Operation) ||
		len(request.Parameters) == 0 {
		return wireRequest{}, fail("request_invalid")
	}
	return request, nil
}

func validOperation(operation string) bool {
	switch operation {
	case "publish", "read_head", "read_page", "health":
		return true
	default:
		return false
	}
}

func roleAllows(role PeerRole, operation string) bool {
	if role == ExporterRole {
		return operation == "publish" || operation == "read_head" || operation == "health"
	}
	if role == RecoveryRole {
		return operation == "read_head" || operation == "read_page" || operation == "health"
	}
	return false
}

func (server *Server) execute(ctx context.Context, request wireRequest) (any, error) {
	switch request.Operation {
	case "publish":
		return server.publish(ctx, request.Parameters)
	case "read_head":
		if err := decodeEmptyParameters(request.Parameters); err != nil {
			return nil, fail("request_invalid")
		}
		return server.readHead(ctx)
	case "read_page":
		return server.readPage(ctx, request.Parameters)
	case "health":
		if err := decodeEmptyParameters(request.Parameters); err != nil {
			return nil, fail("request_invalid")
		}
		return server.health(ctx)
	default:
		return nil, fail("request_invalid")
	}
}

func decodeEmptyParameters(value []byte) error {
	var parameters emptyParameters
	if rejectDuplicateJSONKeys(value) != nil || decodeStrict(value, &parameters) != nil || string(value) != "{}" {
		return fail("request_invalid")
	}
	return nil
}

func (server *Server) publish(ctx context.Context, value []byte) (any, error) {
	var parameters publishParameters
	if rejectDuplicateJSONKeys(value) != nil || decodeStrict(value, &parameters) != nil ||
		!digestPattern.MatchString(parameters.ExpectedPreviousDigest) {
		return nil, fail("request_invalid")
	}
	metadata, canonical, err := server.Verifier.Verify(parameters.Envelope)
	if err != nil || metadata.StreamID != server.Config.StreamID || metadata.Sequence < 1 ||
		metadata.Sequence > MaxSafeInteger || metadata.PreviousAnchorDigest != parameters.ExpectedPreviousDigest ||
		(metadata.Sequence == 1 && metadata.PreviousAnchorDigest != genesisDigest) ||
		(metadata.Sequence > 1 && metadata.PreviousAnchorDigest == genesisDigest) {
		return nil, fail("request_invalid")
	}
	result, err := server.Repository.Publish(ctx, PublishRequest{
		ExpectedPreviousDigest: parameters.ExpectedPreviousDigest,
		Envelope:               bytes.Clone(canonical),
		Metadata:               metadata,
	})
	if err != nil {
		return nil, repositoryError(ctx, err)
	}
	switch result.Status {
	case "published":
		if len(result.Current) != 0 {
			return nil, fail("store_invalid")
		}
		return struct {
			Status string `json:"status"`
		}{Status: "published"}, nil
	case "conflict":
		currentMetadata, current, verifyErr := server.verifyEnvelope(result.Current)
		if verifyErr != nil || currentMetadata.Sequence != metadata.Sequence ||
			currentMetadata.PreviousAnchorDigest != parameters.ExpectedPreviousDigest {
			return nil, fail("store_invalid")
		}
		return struct {
			Status  string          `json:"status"`
			Current json.RawMessage `json:"current"`
		}{Status: "conflict", Current: current}, nil
	default:
		return nil, fail("store_invalid")
	}
}

func (server *Server) readHead(ctx context.Context) (any, error) {
	head, err := server.Repository.ReadHead(ctx)
	if err != nil {
		return nil, repositoryError(ctx, err)
	}
	if len(head.Current) == 0 {
		if len(head.Previous) != 0 {
			return nil, fail("store_invalid")
		}
		return struct {
			Current  json.RawMessage `json:"current"`
			Previous json.RawMessage `json:"previous"`
		}{Current: nil, Previous: nil}, nil
	}
	currentMetadata, current, err := server.verifyEnvelope(head.Current)
	if err != nil {
		return nil, err
	}
	var previous json.RawMessage
	if currentMetadata.Sequence == 1 {
		if len(head.Previous) != 0 {
			return nil, fail("store_invalid")
		}
	} else {
		previousMetadata, canonicalPrevious, previousErr := server.verifyEnvelope(head.Previous)
		if previousErr != nil || previousMetadata.Sequence != currentMetadata.Sequence-1 ||
			previousMetadata.PayloadDigest != currentMetadata.PreviousAnchorDigest {
			return nil, fail("store_invalid")
		}
		previous = canonicalPrevious
	}
	return struct {
		Current  json.RawMessage `json:"current"`
		Previous json.RawMessage `json:"previous"`
	}{Current: current, Previous: previous}, nil
}

func (server *Server) readPage(ctx context.Context, value []byte) (any, error) {
	var parameters readPageParameters
	if rejectDuplicateJSONKeys(value) != nil || decodeStrict(value, &parameters) != nil ||
		parameters.AfterSequence < 0 || parameters.AfterSequence > MaxSafeInteger ||
		parameters.ThroughSequence < 1 || parameters.ThroughSequence > MaxSafeInteger ||
		parameters.AfterSequence >= parameters.ThroughSequence || parameters.Limit < 1 ||
		parameters.Limit > MaxPageSize {
		return nil, fail("request_invalid")
	}
	anchors, err := server.Repository.ReadPage(
		ctx, parameters.AfterSequence, parameters.ThroughSequence, parameters.Limit,
	)
	if err != nil {
		return nil, repositoryError(ctx, err)
	}
	if len(anchors) > parameters.Limit {
		return nil, fail("store_invalid")
	}
	canonicalAnchors := make([]json.RawMessage, 0, len(anchors))
	expectedSequence := parameters.AfterSequence + 1
	for _, anchor := range anchors {
		metadata, canonical, verifyErr := server.verifyEnvelope(anchor)
		if verifyErr != nil || metadata.Sequence != expectedSequence || metadata.Sequence > parameters.ThroughSequence {
			return nil, fail("store_invalid")
		}
		canonicalAnchors = append(canonicalAnchors, canonical)
		expectedSequence++
	}
	return struct {
		AfterSequence   int64             `json:"after_sequence"`
		ThroughSequence int64             `json:"through_sequence"`
		Anchors         []json.RawMessage `json:"anchors"`
	}{
		AfterSequence: parameters.AfterSequence, ThroughSequence: parameters.ThroughSequence,
		Anchors: canonicalAnchors,
	}, nil
}

func (server *Server) health(ctx context.Context) (any, error) {
	health, err := server.Repository.Health(ctx)
	if err != nil {
		return nil, repositoryError(ctx, err)
	}
	if !validHealthResult(health) {
		return nil, fail("store_invalid")
	}
	return struct {
		Status         string `json:"status"`
		LockContract   string `json:"lock_contract"`
		MirrorState    string `json:"mirror_state"`
		CommonSequence int64  `json:"common_sequence"`
		ReasonCode     string `json:"reason_code"`
	}{
		Status: health.Status, LockContract: health.LockContract, MirrorState: health.MirrorState,
		CommonSequence: health.CommonSequence, ReasonCode: health.ReasonCode,
	}, nil
}

func (server *Server) verifyEnvelope(value []byte) (auditanchor.EnvelopeMetadata, json.RawMessage, error) {
	if len(value) == 0 {
		return auditanchor.EnvelopeMetadata{}, nil, fail("store_invalid")
	}
	metadata, canonical, err := server.Verifier.Verify(value)
	if err != nil || metadata.StreamID != server.Config.StreamID || metadata.Sequence < 1 ||
		metadata.Sequence > MaxSafeInteger || !bytes.Equal(value, canonical) {
		return auditanchor.EnvelopeMetadata{}, nil, fail("store_invalid")
	}
	return metadata, json.RawMessage(bytes.Clone(canonical)), nil
}

func repositoryError(ctx context.Context, err error) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return fail("deadline_exceeded")
	}
	if errors.Is(ctx.Err(), context.Canceled) || errors.Is(err, context.Canceled) {
		return fail("deadline_exceeded")
	}
	if errors.Is(err, ErrRepositoryUnavailable) {
		return fail("store_unavailable")
	}
	if errors.Is(err, ErrRepositoryInvalid) {
		return fail("store_invalid")
	}
	return fail("internal_error")
}

func (server *Server) writeError(writer io.Writer, request wireRequest, code string) error {
	allowed := map[string]struct{}{
		"request_invalid": {}, "operation_denied": {}, "store_unavailable": {},
		"store_invalid": {}, "deadline_exceeded": {}, "server_busy": {}, "internal_error": {},
	}
	if _, ok := allowed[code]; !ok {
		code = "internal_error"
	}
	return writeResponse(writer, wireErrorResponse{
		Version: ProtocolVersion, Purpose: Purpose, RequestID: request.RequestID,
		Operation: request.Operation, Status: "error", ErrorCode: code,
	})
}

func writeResponse(writer io.Writer, response any) error {
	encoded, err := json.Marshal(response)
	if err != nil || len(encoded)+1 > MaxResponseBytes {
		return fail("response_invalid")
	}
	payload := append(encoded, '\n')
	written, err := writer.Write(payload)
	if err != nil || written != len(payload) {
		return fail("response_failed")
	}
	return nil
}

func decodeStrict(value []byte, target any) error {
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

func rejectDuplicateJSONKeys(value []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.UseNumber()
	if err := scanJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing json")
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object key is invalid")
			}
			if _, duplicate := seen[key]; duplicate {
				return errors.New("duplicate object key")
			}
			seen[key] = struct{}{}
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("object is invalid")
		}
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("array is invalid")
		}
	default:
		return errors.New("json value is invalid")
	}
	return nil
}

func protocolErrorCode(err error) string {
	var protocolError *ProtocolError
	if errors.As(err, &protocolError) {
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
