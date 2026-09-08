// Package broker — V4.1 Go SDK
// Zero hard dependencies: stdlib only.
// Compatible with Go 1.21+.
//
// 8 calling surfaces:
//  1. GetSecret / ListSecrets / ResolveSecrets
//  2. Proxy
//  3. Exec (subprocess with secrets in env)
//  4. SSHExec / SSHTunnel
//  5. AssumeWorkloadIdentity
//  6. Login
//  7. Identity / Health
//  8. Subscribe (WebSocket, requires optional nhooyr.io/websocket OR custom; we provide SubscribeEvents via WSClient)
package broker

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Version of the SDK.
const Version = "4.2.0"

// ============================================================
// Client
// ============================================================

// Client is a synchronous mTLS client for Secret Broker V4.
type Client struct {
	endpoint         string
	http             *http.Client
	workloadIdentity *WorkloadIdentity
	sessionCookie    string
}

// Config holds Client configuration.
type Config struct {
	// Endpoint e.g. "https://broker.example.com:8443"
	Endpoint string
	// ClientCert / ClientKey: paths to PEM-encoded mTLS client cert + key.
	// Optional if using password login (mTLS still recommended for app certs).
	ClientCert string
	ClientKey  string
	// CACert: path to PEM-encoded CA cert (broker CA). Defaults to system trust store.
	CACert string
	// InsecureSkipVerify disables TLS certificate validation. Test-only.
	// The secure default is false.
	InsecureSkipVerify bool
	// Timeout: request timeout. Default 30s.
	Timeout time.Duration
	// WorkloadIdentity: optional K8s/ECS/GKE binding for STS exchange.
	WorkloadIdentity *WorkloadIdentity
}

// NewClient creates a new BrokerClient.
func NewClient(cfg Config) (*Client, error) {
	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("%w: endpoint required", ErrInvalidArg)
	}
	if !strings.HasPrefix(cfg.Endpoint, "https://") {
		return nil, fmt.Errorf("%w: endpoint must be https://", ErrInvalidArg)
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.CACert != "" {
		pem, err := os.ReadFile(cfg.CACert)
		if err != nil {
			return nil, fmt.Errorf("read CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("parse CA: %w", err)
		}
		tlsCfg.RootCAs = pool
	}
	if cfg.ClientCert != "" && cfg.ClientKey != "" {
		cert, err := tls.LoadX509KeyPair(cfg.ClientCert, cfg.ClientKey)
		if err != nil {
			return nil, fmt.Errorf("load client cert: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}
	if cfg.InsecureSkipVerify {
		tlsCfg.InsecureSkipVerify = true
	}

	tr := &http.Transport{
		TLSClientConfig:       tlsCfg,
		MaxIdleConns:          10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DisableCompression:    true,
	}

	return &Client{
		endpoint: strings.TrimRight(cfg.Endpoint, "/"),
		http: &http.Client{
			Transport: tr,
			Timeout:   cfg.Timeout,
		},
		workloadIdentity: cfg.WorkloadIdentity,
	}, nil
}

// ============================================================
// HTTP core
// ============================================================

type apiResponse struct {
	Status int
	Body   []byte
	Header http.Header
}

func (c *Client) do(ctx context.Context, method, path string, body any, query url.Values) (*apiResponse, error) {
	u := c.endpoint + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	var bodyReader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal body: %w", err)
		}
		bodyReader = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "secret-broker-go/"+Version)
	if c.sessionCookie != "" {
		req.AddCookie(&http.Cookie{Name: "broker_session", Value: c.sessionCookie})
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, newConnError(method+" "+path, err)
	}
	defer resp.Body.Close()
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "broker_session" {
			c.sessionCookie = cookie.Value
		}
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, newConnError(method+" "+path, err)
	}
	return &apiResponse{Status: resp.StatusCode, Body: raw, Header: resp.Header.Clone()}, nil
}

func (c *Client) doAndCheck(ctx context.Context, op, method, path string, body any, query url.Values, out any) error {
	resp, err := c.do(ctx, method, path, body, query)
	if err != nil {
		return err
	}
	if resp.Status >= 400 {
		return newError(op, resp.Status, string(resp.Body))
	}
	if out != nil && len(resp.Body) > 0 {
		if err := json.Unmarshal(resp.Body, out); err != nil {
			return fmt.Errorf("decode %s response: %w", op, err)
		}
	}
	return nil
}

// ============================================================
// 1. Secrets
// ============================================================

// SecretListItem is one entry from list secrets.
type SecretListItem struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// GetSecret resolves a single secret by name. Returns the value.
func (c *Client) GetSecret(ctx context.Context, name string) (string, error) {
	type req struct {
		Name string `json:"name"`
	}
	type resp struct {
		Name  string          `json:"name"`
		Value json.RawMessage `json:"value"`
	}
	var r resp
	if err := c.doAndCheck(ctx, "get_secret", "POST", "/api/v1/secrets/resolve", req{Name: name}, nil, &r); err != nil {
		return "", err
	}
	// value can be string OR object
	if len(r.Value) == 0 {
		return "", nil
	}
	var s string
	if err := json.Unmarshal(r.Value, &s); err == nil {
		return s, nil
	}
	return string(r.Value), nil
}

// ResolveSecrets bulk-resolves multiple secrets.
func (c *Client) ResolveSecrets(ctx context.Context, names []string) (map[string]string, error) {
	type req struct {
		Names []string `json:"names"`
	}
	type resp struct {
		Values map[string]string `json:"values"`
	}
	var r resp
	if err := c.doAndCheck(ctx, "resolve_secrets", "POST", "/api/v1/secrets/resolve_bulk", req{Names: names}, nil, &r); err != nil {
		return nil, err
	}
	return r.Values, nil
}

// ListSecrets returns the list of secrets visible to the client.
func (c *Client) ListSecrets(ctx context.Context) ([]SecretListItem, error) {
	var items []SecretListItem
	if err := c.doAndCheck(ctx, "list_secrets", "GET", "/api/v1/secrets", nil, nil, &items); err != nil {
		return nil, err
	}
	return items, nil
}

// ============================================================
// 2. Proxy
// ============================================================

// Proxy forwards a request to an upstream service through the broker.
func (c *Client) Proxy(ctx context.Context, service, method, subPath string, body any, query url.Values) (int, []byte, error) {
	if !strings.HasPrefix(subPath, "/") {
		subPath = "/" + subPath
	}
	u := fmt.Sprintf("/api/v1/proxy/%s", url.PathEscape(service))
	wrappedBody := map[string]any{"method": strings.ToUpper(method), "path": subPath}
	if body != nil {
		wrappedBody["body"] = body
	}
	if len(query) > 0 {
		wrappedBody["query"] = query
	}
	resp, err := c.do(ctx, "POST", u, wrappedBody, nil)
	if err != nil {
		return 0, nil, err
	}
	if resp.Status >= 400 {
		return resp.Status, resp.Body, newError("proxy", resp.Status, string(resp.Body))
	}
	return resp.Status, resp.Body, nil
}

// OperationRequest is the policy input for a typed V2 operation. It never
// contains a URL, authentication header, or long-lived credential.
type OperationRequest struct {
	Provider          string         `json:"provider"`
	OperationID       string         `json:"operation_id"`
	AccountRef        string         `json:"account_ref"`
	Environment       string         `json:"environment"`
	TypedParameters   map[string]any `json:"typed_parameters"`
	OTP               map[string]any `json:"otp,omitempty"`
	ApprovalRequestID string         `json:"approval_request_id,omitempty"`
}

// Operation is the redacted state returned by the broker.
type Operation struct {
	ID          string         `json:"id"`
	Provider    string         `json:"provider"`
	OperationID string         `json:"operation_id"`
	AccountRef  string         `json:"account_ref"`
	Environment string         `json:"environment"`
	Status      string         `json:"status"`
	Result      map[string]any `json:"result,omitempty"`
	Error       map[string]any `json:"error,omitempty"`
}

// ApprovalRequest is bound to the exact operation dimensions and parameter hash.
type ApprovalRequest struct {
	Provider        string         `json:"provider"`
	OperationID     string         `json:"operation_id"`
	AccountRef      string         `json:"account_ref"`
	Environment     string         `json:"environment"`
	TypedParameters map[string]any `json:"typed_parameters"`
}

// Approval is the public state of a short-lived separation-of-duties request.
type Approval struct {
	ID                string           `json:"id"`
	Requester         string           `json:"requester"`
	Provider          string           `json:"provider"`
	OperationID       string           `json:"operation_id"`
	AccountRef        string           `json:"account_ref"`
	Environment       string           `json:"environment"`
	ResourceRef       string           `json:"resource_ref"`
	RequiredApprovals int              `json:"required_approvals"`
	Approvals         []map[string]any `json:"approvals"`
	Status            string           `json:"status"`
	CreatedAt         string           `json:"created_at"`
	ExpiresAt         string           `json:"expires_at"`
}

// CreateOperation requests one allowlisted provider operation.
func (c *Client) CreateOperation(ctx context.Context, request OperationRequest) (*Operation, error) {
	var operation Operation
	if err := c.doAndCheck(ctx, "create_operation", "POST", "/api/v2/operations", request, nil, &operation); err != nil {
		return nil, err
	}
	return &operation, nil
}

// GetOperation reads the redacted state of a previously created operation.
func (c *Client) GetOperation(ctx context.Context, id string) (*Operation, error) {
	if id == "" {
		return nil, fmt.Errorf("%w: operation id required", ErrInvalidArg)
	}
	var operation Operation
	path := "/api/v2/operations/" + url.PathEscape(id)
	if err := c.doAndCheck(ctx, "get_operation", "GET", path, nil, nil, &operation); err != nil {
		return nil, err
	}
	return &operation, nil
}

// CreateApproval requests human approval for one exact operation.
func (c *Client) CreateApproval(ctx context.Context, request ApprovalRequest) (*Approval, error) {
	var approval Approval
	if err := c.doAndCheck(ctx, "create_approval", "POST", "/api/v2/approvals", request, nil, &approval); err != nil {
		return nil, err
	}
	return &approval, nil
}

// ListApprovals returns only requests visible to the current identity.
func (c *Client) ListApprovals(ctx context.Context) ([]Approval, error) {
	var response struct {
		Approvals []Approval `json:"approvals"`
	}
	if err := c.doAndCheck(ctx, "list_approvals", "GET", "/api/v2/approvals", nil, nil, &response); err != nil {
		return nil, err
	}
	return response.Approvals, nil
}

// DecideApproval requires the caller to already hold a WebAuthn-stepped-up session.
func (c *Client) DecideApproval(ctx context.Context, id, decision string) (*Approval, error) {
	if id == "" || (decision != "approve" && decision != "reject") {
		return nil, fmt.Errorf("%w: approval id and valid decision required", ErrInvalidArg)
	}
	var approval Approval
	path := "/api/v2/approvals/" + url.PathEscape(id) + "/decision"
	if err := c.doAndCheck(ctx, "decide_approval", "POST", path, map[string]string{"decision": decision}, nil, &approval); err != nil {
		return nil, err
	}
	return &approval, nil
}

// ============================================================
// 3. Exec
// ============================================================

// Exec runs a subprocess with the given secrets bound as environment variables.
// The secret values are passed via env; callers are responsible for not logging
// the resulting env.
func (c *Client) Exec(ctx context.Context, envNames []string, command []string, extraEnv ...string) (int, error) {
	if len(command) == 0 {
		return -1, fmt.Errorf("%w: command required", ErrInvalidArg)
	}
	resolved, err := c.ResolveSecrets(ctx, envNames)
	if err != nil {
		return -1, err
	}
	cmd := exec.CommandContext(ctx, command[0], command[1:]...)
	env := os.Environ()
	for k, v := range resolved {
		env = append(env, fmt.Sprintf("%s=%s", k, v))
	}
	for _, e := range extraEnv {
		env = append(env, e)
	}
	cmd.Env = env
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	err = cmd.Run()
	if err == nil {
		return cmd.ProcessState.ExitCode(), nil
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode(), nil
	}
	return -1, err
}

// ============================================================
// 4. SSH proxy
// ============================================================

// SSHExecResult is the response from /api/v1/ssh/exec.
type SSHExecResult struct {
	OK         bool   `json:"ok"`
	ExitCode   int    `json:"exitCode"`
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	DurationMS int    `json:"duration_ms"`
	Target     string `json:"target"`
}

// SSHExec runs a command on a remote host via broker-managed SSH.
func (c *Client) SSHExec(ctx context.Context, target, command, secretName string, timeoutMs int) (*SSHExecResult, error) {
	body := map[string]any{
		"target":      target,
		"command":     command,
		"secret_name": secretName,
	}
	if timeoutMs > 0 {
		body["timeout_ms"] = timeoutMs
	}
	var r SSHExecResult
	if err := c.doAndCheck(ctx, "ssh_exec", "POST", "/api/v1/ssh/exec", body, nil, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// SSHTunnelResult is the response from /api/v1/ssh/tunnel.
type SSHTunnelResult struct {
	OK        bool   `json:"ok"`
	ID        string `json:"id"`
	LocalPort int    `json:"localPort"`
	Remote    string `json:"remote"`
	Target    string `json:"target"`
}

// SSHTunnel opens a local port forward via broker-managed SSH.
func (c *Client) SSHTunnel(ctx context.Context, target string, localPort int, remoteHost string, remotePort int, secretName string) (*SSHTunnelResult, error) {
	body := map[string]any{
		"target":      target,
		"local_port":  localPort,
		"remote_host": remoteHost,
		"remote_port": remotePort,
		"secret_name": secretName,
	}
	var r SSHTunnelResult
	if err := c.doAndCheck(ctx, "ssh_tunnel", "POST", "/api/v1/ssh/tunnel", body, nil, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// SSHTunnelStop closes a tunnel by ID.
func (c *Client) SSHTunnelStop(ctx context.Context, id string) error {
	return c.doAndCheck(ctx, "ssh_tunnel_stop", "POST", "/api/v1/ssh/tunnel/stop", map[string]any{"id": id}, nil, nil)
}

// ============================================================
// 5. Workload identity
// ============================================================

// WorkloadCreds is the short-lived STS response.
type WorkloadCreds struct {
	OK              bool   `json:"ok"`
	Provider        string `json:"provider"`
	Role            string `json:"role"`
	AccessKeyID     string `json:"access_key_id"`
	AccessKeySecret string `json:"access_key_secret"`
	SecurityToken   string `json:"security_token"`
	Expiration      string `json:"expiration"`
	ExpiresInMs     int    `json:"expires_in_ms"`
}

// AssumeWorkloadIdentity exchanges an OIDC token for STS credentials.
func (c *Client) AssumeWorkloadIdentity(ctx context.Context, provider, oidcToken, roleArn, audience string) (*WorkloadCreds, error) {
	wi := c.workloadIdentity
	if oidcToken == "" && wi != nil {
		t, err := wi.Token()
		if err != nil {
			return nil, fmt.Errorf("read workload token: %w", err)
		}
		oidcToken = t
	}
	if roleArn == "" && wi != nil {
		roleArn = wi.RoleArn
	}
	if audience == "" && wi != nil {
		audience = wi.Audience
	}
	if oidcToken == "" {
		return nil, fmt.Errorf("%w: oidcToken (or workloadIdentity) required", ErrInvalidArg)
	}
	body := map[string]any{
		"provider":   provider,
		"oidc_token": oidcToken,
		"role_arn":   roleArn,
		"audience":   audience,
	}
	var r WorkloadCreds
	if err := c.doAndCheck(ctx, "assume_workload_identity", "POST", "/api/v1/workload-identity/assume", body, nil, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// ============================================================
// 6. Login
// ============================================================

// Login authenticates with username + password (+ optional MFA).
func (c *Client) Login(ctx context.Context, username, password, mfaToken, mfaCode string) error {
	if (mfaToken == "") != (mfaCode == "") {
		return fmt.Errorf("%w: mfaToken and mfaCode must be provided together", ErrInvalidArg)
	}
	if mfaToken != "" {
		return c.doAndCheck(ctx, "login_mfa", "POST", "/api/v1/login/mfa", map[string]any{
			"mfa_token": mfaToken, "code": mfaCode,
		}, nil, nil)
	}
	return c.doAndCheck(ctx, "login", "POST", "/api/v1/login", map[string]any{
		"client": username, "password": password,
	}, nil, nil)
}

// Logout drops the current session.
func (c *Client) Logout(ctx context.Context) error {
	if c.sessionCookie == "" {
		return nil
	}
	defer func() { c.sessionCookie = "" }()
	return c.doAndCheck(ctx, "logout", "POST", "/api/v1/logout", map[string]any{}, nil, nil)
}

// ============================================================
// 7. Identity / Health
// ============================================================

// Identity represents the current client's view of itself.
type Identity struct {
	CN   string `json:"cn"`
	Role string `json:"role"`
}

// Me returns the current client's identity.
func (c *Client) Me(ctx context.Context) (*Identity, error) {
	var r Identity
	if err := c.doAndCheck(ctx, "me", "GET", "/api/v1/me", nil, nil, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Health returns the broker's health check response.
type Health struct {
	OK      bool   `json:"ok"`
	Version string `json:"version"`
}

// Health calls /health.
func (c *Client) Health(ctx context.Context) (*Health, error) {
	var r Health
	if err := c.doAndCheck(ctx, "health", "GET", "/health", nil, nil, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// ============================================================
// Zero-touch: scrub error message
// ============================================================
