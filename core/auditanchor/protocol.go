// Package auditanchor validates the local protocol used by an independently
// administered audit-anchor signer. The protocol is purpose-bound and never
// accepts a private key, provider credential, audit event body, or arbitrary
// signing input.
package auditanchor

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	ProtocolVersion    = 2
	Purpose            = "secret-broker.audit-chain-head"
	SignatureContext   = "secret-broker.audit-anchor-signature.v2"
	MaxRequestBytes    = 8 * 1024
	MaxResponseBytes   = 8 * 1024
	MinSignatureBytes  = 32
	MaxSignatureBytes  = 3 * 1024
	DefaultDeadline    = 2 * time.Second
	DefaultConcurrency = 16
)

var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

var supportedAlgorithms = map[string]struct{}{
	"ed25519":           {},
	"ecdsa-p256-sha256": {},
	"rsa-pss-sha256":    {},
}

type wireRequest struct {
	Version        int    `json:"version"`
	Purpose        string `json:"purpose"`
	Algorithm      string `json:"algorithm"`
	KeyID          string `json:"key_id"`
	StreamID       string `json:"stream_id"`
	Sequence       int64  `json:"sequence"`
	PreviousDigest string `json:"previous_anchor_digest"`
	PayloadDigest  string `json:"payload_digest"`
	SigningInput   string `json:"signing_input"`
}

type wireResponse struct {
	Version       int    `json:"version"`
	Purpose       string `json:"purpose"`
	Algorithm     string `json:"algorithm"`
	KeyID         string `json:"key_id"`
	PayloadDigest string `json:"payload_digest"`
	Signature     string `json:"signature"`
}

// SignRequest contains public audit-chain-head metadata and a purpose-bound
// signing input. Digest is provided for KMS APIs that sign a SHA-256 digest.
// Implementations must use a key dedicated to audit anchors.
type SignRequest struct {
	Algorithm      string
	KeyID          string
	StreamID       string
	Sequence       int64
	PreviousDigest [sha256.Size]byte
	PayloadDigest  [sha256.Size]byte
	SigningInput   []byte
	Digest         [sha256.Size]byte
}

type Signer interface {
	Sign(context.Context, SignRequest) ([]byte, error)
}

type SignerFunc func(context.Context, SignRequest) ([]byte, error)

func (function SignerFunc) Sign(ctx context.Context, request SignRequest) ([]byte, error) {
	return function(ctx, request)
}

// AnchorAuthorizer is the independent authority for stream and sequence
// policy. A production implementation must prevent conflicting signatures for
// the same stream sequence and persist that decision outside the Broker host.
type AnchorAuthorizer interface {
	AuthorizeAnchor(context.Context, SignRequest) error
}

type AnchorAuthorizerFunc func(context.Context, SignRequest) error

func (function AnchorAuthorizerFunc) AuthorizeAnchor(ctx context.Context, request SignRequest) error {
	return function(ctx, request)
}

type PeerAuthorizer interface {
	AuthorizePeer(context.Context, net.Conn) error
}

type PeerAuthorizerFunc func(context.Context, net.Conn) error

func (function PeerAuthorizerFunc) AuthorizePeer(ctx context.Context, connection net.Conn) error {
	return function(ctx, connection)
}

type ProtocolError struct{ Code string }

func (protocolError *ProtocolError) Error() string { return protocolError.Code }

func fail(code string) error { return &ProtocolError{Code: code} }

type Config struct {
	Algorithm string
	KeyID     string
	StreamID  string
}

type Server struct {
	Config        Config
	Signer        Signer
	Anchors       AnchorAuthorizer
	Peers         PeerAuthorizer
	Clock         func() time.Time
	Deadline      time.Duration
	MaxConcurrent int
	OnError       func(string)
}

func NewServer(config Config, signer Signer, anchors AnchorAuthorizer, peers PeerAuthorizer) (*Server, error) {
	if !validConfig(config) || signer == nil || anchors == nil || peers == nil {
		return nil, errors.New("audit anchor signer configuration is invalid")
	}
	return &Server{
		Config: config, Signer: signer, Anchors: anchors, Peers: peers,
		Clock: time.Now, Deadline: DefaultDeadline, MaxConcurrent: DefaultConcurrency,
	}, nil
}

func validConfig(config Config) bool {
	_, algorithmAllowed := supportedAlgorithms[config.Algorithm]
	return algorithmAllowed && idPattern.MatchString(config.KeyID) && idPattern.MatchString(config.StreamID)
}

func (server *Server) Serve(ctx context.Context, listener net.Listener) error {
	if server == nil || listener == nil || server.MaxConcurrent < 1 || server.MaxConcurrent > 256 {
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
	if server == nil || !validConfig(server.Config) || server.Signer == nil ||
		server.Anchors == nil || server.Peers == nil || connection == nil ||
		server.Clock == nil || server.Deadline <= 0 || server.Deadline > 10*time.Second {
		return fail("server_invalid")
	}
	if err := connection.SetDeadline(server.Clock().UTC().Add(server.Deadline)); err != nil {
		return fail("connection_invalid")
	}
	if err := server.Peers.AuthorizePeer(ctx, connection); err != nil {
		return fail("peer_denied")
	}
	wire, request, err := readRequest(connection, server.Config)
	if err != nil {
		return err
	}
	if err := server.Anchors.AuthorizeAnchor(ctx, request); err != nil {
		return fail("anchor_denied")
	}
	signature, err := server.Signer.Sign(ctx, cloneRequest(request))
	if err != nil {
		return fail("signing_failed")
	}
	if len(signature) < MinSignatureBytes || len(signature) > MaxSignatureBytes {
		return fail("signature_invalid")
	}
	response := wireResponse{
		Version: ProtocolVersion, Purpose: Purpose, Algorithm: server.Config.Algorithm,
		KeyID: server.Config.KeyID, PayloadDigest: wire.PayloadDigest,
		Signature: base64.RawURLEncoding.EncodeToString(signature),
	}
	encoded, err := json.Marshal(response)
	if err != nil || len(encoded)+1 > MaxResponseBytes {
		return fail("response_invalid")
	}
	if _, err := connection.Write(append(encoded, '\n')); err != nil {
		return fail("response_failed")
	}
	return nil
}

func readRequest(reader io.Reader, config Config) (wireRequest, SignRequest, error) {
	buffered := bufio.NewReaderSize(reader, MaxRequestBytes+1)
	line, err := buffered.ReadString('\n')
	if err != nil || len(line) > MaxRequestBytes || buffered.Buffered() > 0 {
		return wireRequest{}, SignRequest{}, fail("request_invalid")
	}
	line = strings.TrimSuffix(line, "\n")
	if line == "" || strings.HasSuffix(line, "\r") {
		return wireRequest{}, SignRequest{}, fail("request_invalid")
	}
	var request wireRequest
	if decodeStrict([]byte(line), &request) != nil || request.Version != ProtocolVersion ||
		request.Purpose != Purpose || request.Algorithm != config.Algorithm ||
		request.KeyID != config.KeyID || request.StreamID != config.StreamID || request.Sequence < 1 {
		return wireRequest{}, SignRequest{}, fail("request_invalid")
	}
	payloadDigestBytes, err := decodeHexDigest(request.PayloadDigest)
	if err != nil {
		return wireRequest{}, SignRequest{}, fail("request_invalid")
	}
	previousDigestBytes, err := decodeHexDigest(request.PreviousDigest)
	if err != nil || (request.Sequence == 1 && previousDigestBytes != [sha256.Size]byte{}) ||
		(request.Sequence > 1 && previousDigestBytes == [sha256.Size]byte{}) {
		return wireRequest{}, SignRequest{}, fail("request_invalid")
	}
	signingInput, err := decodeCanonicalBase64URL(request.SigningInput)
	if err != nil {
		return wireRequest{}, SignRequest{}, fail("request_invalid")
	}
	expected := []byte(SignatureContext + "\x00" + config.Algorithm + "\x00" + config.KeyID + "\x00" +
		config.StreamID + "\x00" + strconv.FormatInt(request.Sequence, 10) + "\x00" + request.PreviousDigest + "\x00" + request.PayloadDigest)
	if !equalBytes(signingInput, expected) {
		return wireRequest{}, SignRequest{}, fail("request_invalid")
	}
	return request, SignRequest{
		Algorithm: config.Algorithm, KeyID: config.KeyID, StreamID: config.StreamID,
		Sequence: request.Sequence, PreviousDigest: previousDigestBytes, PayloadDigest: payloadDigestBytes,
		SigningInput: append([]byte(nil), signingInput...), Digest: sha256.Sum256(signingInput),
	}, nil
}

func decodeHexDigest(value string) ([sha256.Size]byte, error) {
	var digest [sha256.Size]byte
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return digest, errors.New("digest is invalid")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size {
		return digest, errors.New("digest is invalid")
	}
	copy(digest[:], decoded)
	return digest, nil
}

func decodeCanonicalBase64URL(value string) ([]byte, error) {
	if value == "" || strings.Contains(value, "=") {
		return nil, errors.New("base64url is invalid")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, errors.New("base64url is invalid")
	}
	return decoded, nil
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var difference byte
	for index := range left {
		difference |= left[index] ^ right[index]
	}
	return difference == 0
}

func cloneRequest(request SignRequest) SignRequest {
	request.SigningInput = append([]byte(nil), request.SigningInput...)
	return request
}

func decodeStrict(value []byte, target any) error {
	decoder := json.NewDecoder(strings.NewReader(string(value)))
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
