// Package providercredential validates the local short-lived provider credential protocol.
// It never accepts caller-supplied endpoints or credentials and delegates lease issuance to
// an injected authority after exact peer and resource binding checks.
package providercredential

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	ProtocolVersion    = 2
	MaxRequestBytes    = 4 * 1024
	MaxResponseBytes   = 8 * 1024
	MaxTokenBytes      = 4096
	MaxLeaseLifetime   = 5 * time.Minute
	DefaultDeadline    = 2 * time.Second
	DefaultConcurrency = 32
)

var (
	idPattern                = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	environmentPattern       = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
	cloudflareAccountPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)
	dockerComponentPattern   = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*$`)
	executionIDPattern       = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	requestBindingPattern    = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
)

type wireRequest struct {
	Version        int    `json:"version"`
	Provider       string `json:"provider"`
	OperationID    string `json:"operation_id"`
	AccountRef     string `json:"account_ref"`
	Environment    string `json:"environment"`
	ResourceRef    string `json:"resource_ref"`
	ExecutionID    string `json:"execution_id"`
	RequestBinding string `json:"request_binding"`
}

type wireResponse struct {
	Version        int    `json:"version"`
	Provider       string `json:"provider"`
	OperationID    string `json:"operation_id"`
	AccountRef     string `json:"account_ref"`
	Environment    string `json:"environment"`
	ResourceRef    string `json:"resource_ref"`
	ExecutionID    string `json:"execution_id"`
	RequestBinding string `json:"request_binding"`
	Token          string `json:"token"`
	ExpiresAt      string `json:"expires_at"`
}

// LeaseRequest contains only the exact binding authorized by the Broker runtime.
type LeaseRequest struct {
	Provider       string
	OperationID    string
	AccountRef     string
	Environment    string
	ResourceRef    string
	ExecutionID    string
	RequestBinding string
}

// Lease is a short-lived capability. Backends must not return a long-lived provider secret.
type Lease struct {
	Token     string
	ExpiresAt time.Time
}

type LeaseIssuer interface {
	IssueLease(context.Context, LeaseRequest) (Lease, error)
}

type LeaseIssuerFunc func(context.Context, LeaseRequest) (Lease, error)

func (function LeaseIssuerFunc) IssueLease(ctx context.Context, request LeaseRequest) (Lease, error) {
	return function(ctx, request)
}

type BindingAuthorizer interface {
	AuthorizeBinding(context.Context, LeaseRequest) error
}

type BindingAuthorizerFunc func(context.Context, LeaseRequest) error

func (function BindingAuthorizerFunc) AuthorizeBinding(ctx context.Context, request LeaseRequest) error {
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

type Server struct {
	Issuer        LeaseIssuer
	Bindings      BindingAuthorizer
	Peers         PeerAuthorizer
	Clock         func() time.Time
	Deadline      time.Duration
	MaxConcurrent int
	OnError       func(string)
}

func NewServer(issuer LeaseIssuer, bindings BindingAuthorizer, peers PeerAuthorizer) (*Server, error) {
	if issuer == nil || bindings == nil || peers == nil {
		return nil, errors.New("credential service dependencies are required")
	}
	return &Server{
		Issuer: issuer, Bindings: bindings, Peers: peers,
		Clock: time.Now, Deadline: DefaultDeadline, MaxConcurrent: DefaultConcurrency,
	}, nil
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
	if server == nil || server.Issuer == nil || server.Bindings == nil || server.Peers == nil || connection == nil {
		return fail("server_invalid")
	}
	if server.Deadline <= 0 || server.Deadline > 10*time.Second || server.Clock == nil {
		return fail("server_invalid")
	}
	now := server.Clock().UTC()
	if err := connection.SetDeadline(now.Add(server.Deadline)); err != nil {
		return fail("connection_invalid")
	}
	if err := server.Peers.AuthorizePeer(ctx, connection); err != nil {
		return fail("peer_denied")
	}
	request, err := readRequest(connection)
	if err != nil {
		return err
	}
	leaseRequest := LeaseRequest{
		Provider: request.Provider, OperationID: request.OperationID,
		AccountRef: request.AccountRef, Environment: request.Environment,
		ResourceRef: request.ResourceRef,
		ExecutionID: request.ExecutionID, RequestBinding: request.RequestBinding,
	}
	if err := server.Bindings.AuthorizeBinding(ctx, leaseRequest); err != nil {
		return fail("binding_denied")
	}
	lease, err := server.Issuer.IssueLease(ctx, leaseRequest)
	if err != nil {
		return fail("lease_failed")
	}
	if err := validateLease(lease, now); err != nil {
		return err
	}
	response := wireResponse{
		Version: ProtocolVersion, Provider: request.Provider, OperationID: request.OperationID,
		AccountRef: request.AccountRef, Environment: request.Environment,
		ResourceRef: request.ResourceRef, Token: lease.Token,
		ExecutionID: request.ExecutionID, RequestBinding: request.RequestBinding,
		ExpiresAt: lease.ExpiresAt.UTC().Format(time.RFC3339Nano),
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

func readRequest(reader io.Reader) (wireRequest, error) {
	buffered := bufio.NewReaderSize(reader, MaxRequestBytes+1)
	line, err := buffered.ReadString('\n')
	if err != nil || len(line) > MaxRequestBytes || buffered.Buffered() > 0 {
		return wireRequest{}, fail("request_invalid")
	}
	line = strings.TrimSuffix(line, "\n")
	if line == "" || strings.HasSuffix(line, "\r") {
		return wireRequest{}, fail("request_invalid")
	}
	var request wireRequest
	if err := decodeStrict([]byte(line), &request); err != nil ||
		request.Version != ProtocolVersion || !validRequest(request) {
		return wireRequest{}, fail("request_invalid")
	}
	return request, nil
}

func validRequest(request wireRequest) bool {
	if !idPattern.MatchString(request.OperationID) || !idPattern.MatchString(request.AccountRef) ||
		!environmentPattern.MatchString(request.Environment) ||
		!executionIDPattern.MatchString(request.ExecutionID) ||
		!requestBindingPattern.MatchString(request.RequestBinding) {
		return false
	}
	return validStaticBinding(request.Provider, request.OperationID, request.AccountRef, request.Environment, request.ResourceRef)
}

func validStaticBinding(provider, operationID, accountRef, environment, resourceRef string) bool {
	if !idPattern.MatchString(operationID) || !idPattern.MatchString(accountRef) ||
		!environmentPattern.MatchString(environment) {
		return false
	}
	switch provider {
	case "cloudflare":
		return (operationID == "zones.list" || operationID == "dns.records.list") &&
			cloudflareAccountPattern.MatchString(resourceRef)
	case "deepseek":
		return operationID == "models.list" && resourceRef == "model-catalog"
	case "openai":
		return operationID == "models.list" && idPattern.MatchString(resourceRef)
	case "docker":
		parts := strings.Split(resourceRef, "/")
		return operationID == "repository.tags.list" && len(resourceRef) < 256 && len(parts) == 2 &&
			dockerComponentPattern.MatchString(parts[0]) && dockerComponentPattern.MatchString(parts[1])
	default:
		return false
	}
}

func validateLease(lease Lease, now time.Time) error {
	if len(lease.Token) < 8 || len(lease.Token) > MaxTokenBytes ||
		strings.IndexFunc(lease.Token, func(character rune) bool { return character < 0x21 || character > 0x7e }) >= 0 ||
		lease.ExpiresAt.IsZero() || !lease.ExpiresAt.After(now) || lease.ExpiresAt.After(now.Add(MaxLeaseLifetime)) {
		return fail("lease_invalid")
	}
	return nil
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

type Binding struct {
	Provider, OperationID, AccountRef, Environment, ResourceRef string
}

type BindingSet struct{ allowed map[Binding]struct{} }

func NewBindingSet(bindings []Binding) (*BindingSet, error) {
	if len(bindings) == 0 || len(bindings) > 256 {
		return nil, errors.New("binding set size is invalid")
	}
	set := &BindingSet{allowed: make(map[Binding]struct{}, len(bindings))}
	for _, binding := range bindings {
		if !validStaticBinding(binding.Provider, binding.OperationID, binding.AccountRef, binding.Environment, binding.ResourceRef) {
			return nil, errors.New("binding is invalid")
		}
		if _, exists := set.allowed[binding]; exists {
			return nil, errors.New("binding is duplicated")
		}
		set.allowed[binding] = struct{}{}
	}
	return set, nil
}

func (bindings *BindingSet) AuthorizeBinding(_ context.Context, request LeaseRequest) error {
	if bindings == nil {
		return errors.New("binding denied")
	}
	binding := Binding{
		Provider: request.Provider, OperationID: request.OperationID, AccountRef: request.AccountRef,
		Environment: request.Environment, ResourceRef: request.ResourceRef,
	}
	if _, allowed := bindings.allowed[binding]; !allowed {
		return errors.New("binding denied")
	}
	return nil
}
