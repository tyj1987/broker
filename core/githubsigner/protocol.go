// Package githubsigner validates the local GitHub App signing protocol.
// It passes only a SHA-256 digest to an injected non-exportable signing backend.
package githubsigner

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
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
	ProtocolVersion    = 2
	MaxRequestBytes    = 8 * 1024
	MaxSignatureBytes  = 1024
	MinSignatureBytes  = 256
	MaxJWTLifetime     = 10 * time.Minute
	DefaultDeadline    = 2 * time.Second
	DefaultConcurrency = 32
)

var (
	accountRefPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	environmentPattern    = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
	clientIDPattern       = regexp.MustCompile(`^[A-Za-z0-9._-]{3,128}$`)
	executionIDPattern    = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	requestBindingPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	wireRequestKeys       = []string{
		"version", "algorithm", "signing_input", "account_ref", "environment",
		"client_id", "execution_id", "request_binding",
	}
	jwtHeaderKeys = []string{"alg", "typ"}
	jwtClaimsKeys = []string{"iat", "exp", "iss"}
)

type wireRequest struct {
	Version        int    `json:"version"`
	Algorithm      string `json:"algorithm"`
	SigningInput   string `json:"signing_input"`
	AccountRef     string `json:"account_ref"`
	Environment    string `json:"environment"`
	ClientID       string `json:"client_id"`
	ExecutionID    string `json:"execution_id"`
	RequestBinding string `json:"request_binding"`
}

type jwtHeader struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
}

type jwtClaims struct {
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
	Issuer    string `json:"iss"`
}

type wireResponse struct {
	Version        int    `json:"version"`
	Signature      string `json:"signature"`
	ExecutionID    string `json:"execution_id"`
	RequestBinding string `json:"request_binding"`
}

// DigestRequest deliberately has no plaintext signing-input or private-key field.
type DigestRequest struct {
	AccountRef     string
	Environment    string
	ClientID       string
	ExecutionID    string
	RequestBinding string
	Digest         [sha256.Size]byte
}

type DigestSigner interface {
	SignDigest(context.Context, DigestRequest) ([]byte, error)
}

type DigestSignerFunc func(context.Context, DigestRequest) ([]byte, error)

func (function DigestSignerFunc) SignDigest(ctx context.Context, request DigestRequest) ([]byte, error) {
	return function(ctx, request)
}

type BindingAuthorizer interface {
	AuthorizeBinding(context.Context, string, string, string) error
}

type BindingAuthorizerFunc func(context.Context, string, string, string) error

func (function BindingAuthorizerFunc) AuthorizeBinding(
	ctx context.Context,
	accountRef string,
	environment string,
	clientID string,
) error {
	return function(ctx, accountRef, environment, clientID)
}

type PeerAuthorizer interface {
	AuthorizePeer(context.Context, net.Conn) error
}

type PeerAuthorizerFunc func(context.Context, net.Conn) error

func (function PeerAuthorizerFunc) AuthorizePeer(ctx context.Context, connection net.Conn) error {
	return function(ctx, connection)
}

type ProtocolError struct {
	Code string
}

func (protocolError *ProtocolError) Error() string { return protocolError.Code }

func fail(code string) error { return &ProtocolError{Code: code} }

type Server struct {
	Signer        DigestSigner
	Bindings      BindingAuthorizer
	Peers         PeerAuthorizer
	Clock         func() time.Time
	Deadline      time.Duration
	MaxConcurrent int
	OnError       func(string)
}

func NewServer(signer DigestSigner, bindings BindingAuthorizer, peers PeerAuthorizer) (*Server, error) {
	if signer == nil || bindings == nil || peers == nil {
		return nil, errors.New("signer dependencies are required")
	}
	return &Server{
		Signer: signer, Bindings: bindings, Peers: peers,
		Clock: time.Now, Deadline: DefaultDeadline, MaxConcurrent: DefaultConcurrency,
	}, nil
}

// Serve accepts bounded concurrent connections until the context is cancelled.
// It reports only stable error codes; dependency details never reach the callback.
func (server *Server) Serve(ctx context.Context, listener net.Listener) error {
	if server == nil || listener == nil || ctx == nil || server.MaxConcurrent < 1 || server.MaxConcurrent > 256 {
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

// ServeConn accepts exactly one newline-delimited request and writes one response.
// Callers retain ownership of the connection and must close it after this method.
func (server *Server) ServeConn(ctx context.Context, connection net.Conn) error {
	if server == nil || server.Signer == nil || server.Bindings == nil || server.Peers == nil || connection == nil || ctx == nil {
		return fail("server_invalid")
	}
	deadline := server.Deadline
	if deadline <= 0 || deadline > 10*time.Second {
		return fail("server_invalid")
	}
	clock := server.Clock
	if clock == nil {
		return fail("server_invalid")
	}
	now := clock()
	requestContext, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	if err := connection.SetDeadline(now.Add(deadline)); err != nil {
		return fail("connection_invalid")
	}
	if err := server.Peers.AuthorizePeer(requestContext, connection); err != nil {
		return fail("peer_denied")
	}
	if requestContext.Err() != nil {
		return fail("deadline_exceeded")
	}
	request, err := readRequest(connection, now)
	if err != nil {
		return err
	}
	if requestContext.Err() != nil {
		return fail("deadline_exceeded")
	}
	if err := server.Bindings.AuthorizeBinding(
		requestContext, request.AccountRef, request.Environment, request.ClientID,
	); err != nil {
		return fail("binding_denied")
	}
	if requestContext.Err() != nil {
		return fail("deadline_exceeded")
	}
	digest := sha256.Sum256([]byte(request.SigningInput))
	signature, err := server.Signer.SignDigest(requestContext, DigestRequest{
		AccountRef: request.AccountRef, Environment: request.Environment,
		ClientID: request.ClientID, ExecutionID: request.ExecutionID,
		RequestBinding: request.RequestBinding, Digest: digest,
	})
	if err != nil {
		return fail("signing_failed")
	}
	if requestContext.Err() != nil {
		return fail("deadline_exceeded")
	}
	if len(signature) < MinSignatureBytes || len(signature) > MaxSignatureBytes {
		return fail("signature_invalid")
	}
	response := wireResponse{
		Version:        ProtocolVersion,
		Signature:      base64.RawURLEncoding.EncodeToString(signature),
		ExecutionID:    request.ExecutionID,
		RequestBinding: request.RequestBinding,
	}
	if err := json.NewEncoder(connection).Encode(response); err != nil {
		return fail("response_failed")
	}
	return nil
}

func readRequest(reader io.Reader, now time.Time) (wireRequest, error) {
	buffered := bufio.NewReaderSize(reader, MaxRequestBytes+1)
	lineBytes, err := buffered.ReadSlice('\n')
	if err != nil || len(lineBytes) > MaxRequestBytes || buffered.Buffered() > 0 {
		return wireRequest{}, fail("request_invalid")
	}
	line := string(lineBytes)
	line = strings.TrimSuffix(line, "\n")
	if strings.HasSuffix(line, "\r") || line == "" {
		return wireRequest{}, fail("request_invalid")
	}
	var request wireRequest
	if err := decodeExactObject([]byte(line), &request, wireRequestKeys); err != nil {
		return wireRequest{}, fail("request_invalid")
	}
	if request.Version != ProtocolVersion || request.Algorithm != "RS256" ||
		!accountRefPattern.MatchString(request.AccountRef) ||
		!environmentPattern.MatchString(request.Environment) ||
		!clientIDPattern.MatchString(request.ClientID) ||
		!executionIDPattern.MatchString(request.ExecutionID) ||
		!requestBindingPattern.MatchString(request.RequestBinding) {
		return wireRequest{}, fail("request_invalid")
	}
	if err := validateSigningInput(request.SigningInput, request.ClientID, now); err != nil {
		return wireRequest{}, err
	}
	return request, nil
}

func validateSigningInput(value string, clientID string, now time.Time) error {
	parts := strings.Split(value, ".")
	if len(parts) != 2 || len(value) < 20 || len(value) > 4096 {
		return fail("jwt_invalid")
	}
	headerBytes, err := decodeCanonicalBase64URL(parts[0])
	if err != nil {
		return fail("jwt_invalid")
	}
	claimsBytes, err := decodeCanonicalBase64URL(parts[1])
	if err != nil {
		return fail("jwt_invalid")
	}
	var header jwtHeader
	var claims jwtClaims
	if decodeExactObject(headerBytes, &header, jwtHeaderKeys) != nil ||
		decodeExactObject(claimsBytes, &claims, jwtClaimsKeys) != nil ||
		header.Algorithm != "RS256" || header.Type != "JWT" || claims.Issuer != clientID {
		return fail("jwt_invalid")
	}
	nowUnix := now.Unix()
	maximumLifetimeSeconds := int64(MaxJWTLifetime / time.Second)
	if claims.IssuedAt < nowUnix-120 || claims.IssuedAt > nowUnix+30 ||
		claims.ExpiresAt <= nowUnix || claims.ExpiresAt <= claims.IssuedAt ||
		claims.IssuedAt > int64(^uint64(0)>>1)-maximumLifetimeSeconds ||
		claims.ExpiresAt > claims.IssuedAt+maximumLifetimeSeconds {
		return fail("jwt_invalid")
	}
	return nil
}

func decodeCanonicalBase64URL(value string) ([]byte, error) {
	if value == "" || strings.Contains(value, "=") {
		return nil, errors.New("invalid base64url")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, errors.New("invalid base64url")
	}
	return decoded, nil
}

func decodeStrict(value []byte, target any) error {
	if !utf8.Valid(value) || rejectDuplicateKeys(value) != nil {
		return errors.New("invalid json")
	}
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
			if _, duplicate := keys[key]; duplicate {
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
		return errors.New("invalid json delimiter")
	}
	closing, err := decoder.Token()
	if err != nil {
		return err
	}
	expected := json.Delim('}')
	if delimiter == '[' {
		expected = ']'
	}
	if closing != expected {
		return errors.New("invalid json delimiter")
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

type Binding struct {
	AccountRef  string
	Environment string
	ClientID    string
}

type BindingSet struct {
	allowed map[Binding]struct{}
}

func NewBindingSet(bindings []Binding) (*BindingSet, error) {
	if len(bindings) == 0 || len(bindings) > 64 {
		return nil, errors.New("binding set size is invalid")
	}
	set := &BindingSet{allowed: make(map[Binding]struct{}, len(bindings))}
	for _, binding := range bindings {
		if !accountRefPattern.MatchString(binding.AccountRef) ||
			!environmentPattern.MatchString(binding.Environment) ||
			!clientIDPattern.MatchString(binding.ClientID) {
			return nil, errors.New("binding is invalid")
		}
		if _, exists := set.allowed[binding]; exists {
			return nil, errors.New("binding is duplicated")
		}
		set.allowed[binding] = struct{}{}
	}
	return set, nil
}

func (bindings *BindingSet) AuthorizeBinding(
	_ context.Context,
	accountRef string,
	environment string,
	clientID string,
) error {
	if bindings == nil {
		return errors.New("binding denied")
	}
	if _, allowed := bindings.allowed[Binding{
		AccountRef: accountRef, Environment: environment, ClientID: clientID,
	}]; !allowed {
		return errors.New("binding denied")
	}
	return nil
}
