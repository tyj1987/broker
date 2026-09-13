// Package aliyunsigner validates the local Alibaba Cloud Signature V3 protocol.
// It accepts only fixed read-only operations and never returns long-term credential material.
package aliyunsigner

import (
	"bufio"
	"context"
	"crypto/sha256"
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
	ProtocolVersion    = 3
	ProbeVersion       = 1
	ProbeOperation     = "authority_generation.read"
	MaxRequestBytes    = 8 * 1024
	DefaultDeadline    = 2 * time.Second
	DefaultConcurrency = 32
	MaxClockSkew       = 5 * time.Minute
)

const (
	OperationECSInstancesList = "ecs.instances.list"
	OperationCallerIdentity   = "sts.caller-identity.read"
)

var (
	accountRefPattern          = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	environmentPattern         = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
	regionPattern              = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+){1,4}$`)
	executionIDPattern         = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	requestBindingPattern      = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	credentialBindingPattern   = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	nextTokenPattern           = regexp.MustCompile(`^[A-Za-z0-9._~-]+$`)
	noncePattern               = regexp.MustCompile(`^[A-Za-z0-9-]{8,128}$`)
	authorityGenerationPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
	probeChallengePattern      = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	authorizationPattern       = regexp.MustCompile(`^ACS3-HMAC-SHA256 Credential=[^,\s]+,SignedHeaders=host;x-acs-action;x-acs-content-sha256;x-acs-date;x-acs-security-token;x-acs-signature-nonce;x-acs-version,Signature=[0-9a-f]{64}$`)
	emptyPayloadDigest         = sha256.Sum256(nil)
	emptyPayloadHash           = hex.EncodeToString(emptyPayloadDigest[:])
	wireRequestRequiredKeys    = []string{
		"version", "provider", "operation_id", "account_ref", "environment",
		"resource_ref", "region_id", "execution_id", "request_binding", "method", "path", "query",
	}
	ecsQueryRequiredKeys = []string{"MaxResults", "RegionId"}
	ecsQueryOptionalKeys = []string{"NextToken"}
)

type authorityProbeRequest struct {
	Version   int    `json:"version"`
	Operation string `json:"operation"`
	Challenge string `json:"challenge"`
}

type authorityProbeResponse struct {
	Version                   int    `json:"version"`
	Operation                 string `json:"operation"`
	Challenge                 string `json:"challenge"`
	AuthorityGenerationSHA256 string `json:"authority_generation_sha256"`
}

type wireRequest struct {
	Version        int             `json:"version"`
	Provider       string          `json:"provider"`
	OperationID    string          `json:"operation_id"`
	AccountRef     string          `json:"account_ref"`
	Environment    string          `json:"environment"`
	ResourceRef    string          `json:"resource_ref"`
	RegionID       string          `json:"region_id"`
	ExecutionID    string          `json:"execution_id"`
	RequestBinding string          `json:"request_binding"`
	Method         string          `json:"method"`
	Path           string          `json:"path"`
	Query          json.RawMessage `json:"query"`
}

type responseHeaders struct {
	Authorization  string `json:"Authorization"`
	Host           string `json:"host"`
	Action         string `json:"x-acs-action"`
	ContentSHA256  string `json:"x-acs-content-sha256"`
	Date           string `json:"x-acs-date"`
	SecurityToken  string `json:"x-acs-security-token"`
	SignatureNonce string `json:"x-acs-signature-nonce"`
	Version        string `json:"x-acs-version"`
}

type wireResponse struct {
	Version           int             `json:"version"`
	Provider          string          `json:"provider"`
	OperationID       string          `json:"operation_id"`
	AccountRef        string          `json:"account_ref"`
	Environment       string          `json:"environment"`
	ResourceRef       string          `json:"resource_ref"`
	RegionID          string          `json:"region_id"`
	ExecutionID       string          `json:"execution_id"`
	RequestBinding    string          `json:"request_binding"`
	CredentialBinding string          `json:"credential_binding"`
	Headers           responseHeaders `json:"headers"`
}

// SigningRequest is the fully validated, typed request visible to the isolated backend.
type SigningRequest struct {
	OperationID    string
	AccountRef     string
	Environment    string
	ResourceRef    string
	RegionID       string
	ExecutionID    string
	RequestBinding string
	MaxResults     int
	NextToken      *string
}

// SignedRequest contains only short-lived signed request material and an opaque lease binding.
// It deliberately has no access-key secret field.
type SignedRequest struct {
	CredentialBinding string
	Authorization     string
	SecurityToken     string
	Date              string
	SignatureNonce    string
}

type RequestSigner interface {
	Sign(context.Context, SigningRequest) (SignedRequest, error)
}

type RequestSignerFunc func(context.Context, SigningRequest) (SignedRequest, error)

func (function RequestSignerFunc) Sign(ctx context.Context, request SigningRequest) (SignedRequest, error) {
	return function(ctx, request)
}

type BindingAuthorizer interface {
	AuthorizeBinding(context.Context, SigningRequest) error
}

type BindingAuthorizerFunc func(context.Context, SigningRequest) error

func (function BindingAuthorizerFunc) AuthorizeBinding(ctx context.Context, request SigningRequest) error {
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
	Signer                    RequestSigner
	Bindings                  BindingAuthorizer
	Peers                     PeerAuthorizer
	AuthorityGenerationSHA256 string
	Clock                     func() time.Time
	Deadline                  time.Duration
	MaxConcurrent             int
	OnError                   func(string)
}

func NewServer(signer RequestSigner, bindings BindingAuthorizer, peers PeerAuthorizer, authorityGenerationSHA256 string) (*Server, error) {
	if signer == nil || bindings == nil || peers == nil || !authorityGenerationPattern.MatchString(authorityGenerationSHA256) {
		return nil, errors.New("signer dependencies are required")
	}
	return &Server{
		Signer: signer, Bindings: bindings, Peers: peers,
		AuthorityGenerationSHA256: authorityGenerationSHA256,
		Clock:                     time.Now, Deadline: DefaultDeadline, MaxConcurrent: DefaultConcurrency,
	}, nil
}

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

func (server *Server) ServeConn(ctx context.Context, connection net.Conn) error {
	if server == nil || server.Signer == nil || server.Bindings == nil || server.Peers == nil ||
		!authorityGenerationPattern.MatchString(server.AuthorityGenerationSHA256) || connection == nil || ctx == nil {
		return fail("server_invalid")
	}
	if server.Deadline <= 0 || server.Deadline > 10*time.Second || server.Clock == nil {
		return fail("server_invalid")
	}
	now := server.Clock()
	requestContext, cancel := context.WithTimeout(ctx, server.Deadline)
	defer cancel()
	if err := connection.SetDeadline(now.Add(server.Deadline)); err != nil {
		return fail("connection_invalid")
	}
	if err := server.Peers.AuthorizePeer(requestContext, connection); err != nil {
		return fail("peer_denied")
	}
	if requestContext.Err() != nil {
		return fail("deadline_exceeded")
	}
	frame, err := readFrame(connection)
	if err != nil {
		return err
	}
	if probe, matched, probeErr := decodeAuthorityProbe(frame); matched {
		if probeErr != nil {
			return probeErr
		}
		if requestContext.Err() != nil {
			return fail("deadline_exceeded")
		}
		if err := json.NewEncoder(connection).Encode(authorityProbeResponse{
			Version: ProbeVersion, Operation: ProbeOperation, Challenge: probe.Challenge,
			AuthorityGenerationSHA256: server.AuthorityGenerationSHA256,
		}); err != nil {
			return fail("response_failed")
		}
		return nil
	}
	request, err := decodeRequest(frame)
	if err != nil {
		return err
	}
	if requestContext.Err() != nil {
		return fail("deadline_exceeded")
	}
	if err := server.Bindings.AuthorizeBinding(requestContext, request); err != nil {
		return fail("binding_denied")
	}
	if requestContext.Err() != nil {
		return fail("deadline_exceeded")
	}
	signed, err := server.Signer.Sign(requestContext, request)
	if err != nil {
		return fail("signing_failed")
	}
	if requestContext.Err() != nil {
		return fail("deadline_exceeded")
	}
	response, err := buildResponse(request, signed, now)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(connection).Encode(response); err != nil {
		return fail("response_failed")
	}
	return nil
}

func readRequest(reader io.Reader) (SigningRequest, error) {
	frame, err := readFrame(reader)
	if err != nil {
		return SigningRequest{}, err
	}
	return decodeRequest(frame)
}

func readFrame(reader io.Reader) ([]byte, error) {
	buffered := bufio.NewReaderSize(reader, MaxRequestBytes+1)
	lineBytes, err := buffered.ReadSlice('\n')
	if err != nil || len(lineBytes) > MaxRequestBytes || buffered.Buffered() > 0 {
		return nil, fail("request_invalid")
	}
	line := string(lineBytes)
	line = strings.TrimSuffix(line, "\n")
	if strings.HasSuffix(line, "\r") || line == "" {
		return nil, fail("request_invalid")
	}
	return []byte(line), nil
}

func decodeRequest(frame []byte) (SigningRequest, error) {
	var request wireRequest
	if decodeStrict(frame, &request) != nil ||
		!hasExactObjectKeys(frame, wireRequestRequiredKeys, nil) ||
		request.Version != ProtocolVersion || request.Provider != "aliyun" ||
		(request.OperationID != OperationECSInstancesList && request.OperationID != OperationCallerIdentity) ||
		!accountRefPattern.MatchString(request.AccountRef) ||
		!environmentPattern.MatchString(request.Environment) ||
		!accountRefPattern.MatchString(request.ResourceRef) ||
		!regionPattern.MatchString(request.RegionID) ||
		!executionIDPattern.MatchString(request.ExecutionID) ||
		!requestBindingPattern.MatchString(request.RequestBinding) ||
		request.Method != "POST" || request.Path != "/" {
		return SigningRequest{}, fail("request_invalid")
	}
	result := SigningRequest{
		OperationID: request.OperationID, AccountRef: request.AccountRef,
		Environment: request.Environment, ResourceRef: request.ResourceRef,
		RegionID: request.RegionID, ExecutionID: request.ExecutionID,
		RequestBinding: request.RequestBinding,
	}
	if request.OperationID == OperationCallerIdentity {
		if decodeStrict(request.Query, &map[string]json.RawMessage{}) != nil ||
			!hasExactObjectKeys(request.Query, nil, nil) {
			return SigningRequest{}, fail("request_invalid")
		}
		return result, nil
	}
	var query map[string]json.RawMessage
	if decodeStrict(request.Query, &query) != nil ||
		!hasExactObjectKeys(request.Query, ecsQueryRequiredKeys, ecsQueryOptionalKeys) {
		return SigningRequest{}, fail("request_invalid")
	}
	var maxResults int
	var regionID string
	if decodeStrict(query["MaxResults"], &maxResults) != nil || maxResults < 1 || maxResults > 100 ||
		decodeStrict(query["RegionId"], &regionID) != nil || regionID != request.RegionID {
		return SigningRequest{}, fail("request_invalid")
	}
	var nextToken *string
	if rawNextToken, present := query["NextToken"]; present {
		var value string
		if decodeStrict(rawNextToken, &value) != nil || len(value) > 2048 || !nextTokenPattern.MatchString(value) {
			return SigningRequest{}, fail("request_invalid")
		}
		nextToken = &value
	}
	result.MaxResults = maxResults
	result.NextToken = nextToken
	return result, nil
}

func decodeAuthorityProbe(frame []byte) (authorityProbeRequest, bool, error) {
	var object map[string]json.RawMessage
	if decodeStrict(frame, &object) != nil || object == nil {
		return authorityProbeRequest{}, false, nil
	}
	if _, present := object["operation"]; !present {
		return authorityProbeRequest{}, false, nil
	}
	var probe authorityProbeRequest
	if decodeStrict(frame, &probe) != nil ||
		!hasExactObjectKeys(frame, []string{"version", "operation", "challenge"}, nil) ||
		probe.Version != ProbeVersion || probe.Operation != ProbeOperation ||
		!probeChallengePattern.MatchString(probe.Challenge) {
		return authorityProbeRequest{}, true, fail("request_invalid")
	}
	return probe, true, nil
}

func buildResponse(request SigningRequest, signed SignedRequest, now time.Time) (wireResponse, error) {
	date, err := time.Parse("2006-01-02T15:04:05Z", signed.Date)
	if err != nil || date.Before(now.Add(-MaxClockSkew)) || date.After(now.Add(MaxClockSkew)) ||
		!credentialBindingPattern.MatchString(signed.CredentialBinding) ||
		len(signed.Authorization) > 4096 ||
		!authorizationPattern.MatchString(signed.Authorization) ||
		!noncePattern.MatchString(signed.SignatureNonce) ||
		len(signed.SecurityToken) < 8 || len(signed.SecurityToken) > 4096 ||
		strings.IndexFunc(signed.SecurityToken, func(value rune) bool { return value < 0x20 || value == 0x7f }) >= 0 {
		return wireResponse{}, fail("signed_response_invalid")
	}
	host := "sts.aliyuncs.com"
	action := "GetCallerIdentity"
	version := "2015-04-01"
	if request.OperationID == OperationECSInstancesList {
		host = "ecs." + request.RegionID + ".aliyuncs.com"
		action = "DescribeInstances"
		version = "2014-05-26"
	}
	return wireResponse{
		Version: ProtocolVersion, Provider: "aliyun", OperationID: request.OperationID,
		AccountRef: request.AccountRef, Environment: request.Environment,
		ResourceRef: request.ResourceRef, RegionID: request.RegionID,
		ExecutionID: request.ExecutionID, RequestBinding: request.RequestBinding,
		CredentialBinding: signed.CredentialBinding,
		Headers: responseHeaders{
			Authorization: signed.Authorization, Host: host, Action: action,
			ContentSHA256: emptyPayloadHash, Date: signed.Date,
			SecurityToken: signed.SecurityToken, SignatureNonce: signed.SignatureNonce,
			Version: version,
		},
	}, nil
}

func decodeStrict(value []byte, target any) error {
	if !utf8.Valid(value) {
		return errors.New("invalid utf-8")
	}
	if err := rejectDuplicateKeys(value); err != nil {
		return err
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

func hasExactObjectKeys(value []byte, required []string, optional []string) bool {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(value, &object); err != nil || object == nil ||
		len(object) < len(required) || len(object) > len(required)+len(optional) {
		return false
	}
	allowed := make(map[string]struct{}, len(required)+len(optional))
	for _, key := range required {
		allowed[key] = struct{}{}
		if _, present := object[key]; !present {
			return false
		}
	}
	for _, key := range optional {
		allowed[key] = struct{}{}
	}
	for key := range object {
		if _, permitted := allowed[key]; !permitted {
			return false
		}
	}
	return true
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
	ResourceRef string
	RegionID    string
}

type BindingSet struct{ allowed map[Binding]struct{} }

func NewBindingSet(bindings []Binding) (*BindingSet, error) {
	if len(bindings) == 0 || len(bindings) > 64 {
		return nil, errors.New("binding set size is invalid")
	}
	set := &BindingSet{allowed: make(map[Binding]struct{}, len(bindings))}
	for _, binding := range bindings {
		if !accountRefPattern.MatchString(binding.AccountRef) ||
			!environmentPattern.MatchString(binding.Environment) ||
			!accountRefPattern.MatchString(binding.ResourceRef) ||
			!regionPattern.MatchString(binding.RegionID) {
			return nil, errors.New("binding is invalid")
		}
		if _, exists := set.allowed[binding]; exists {
			return nil, errors.New("binding is duplicated")
		}
		set.allowed[binding] = struct{}{}
	}
	return set, nil
}

func (bindings *BindingSet) AuthorizeBinding(_ context.Context, request SigningRequest) error {
	if bindings == nil {
		return errors.New("binding denied")
	}
	if _, allowed := bindings.allowed[Binding{
		AccountRef: request.AccountRef, Environment: request.Environment,
		ResourceRef: request.ResourceRef, RegionID: request.RegionID,
	}]; !allowed {
		return errors.New("binding denied")
	}
	return nil
}
