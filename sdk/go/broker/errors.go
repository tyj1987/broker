// Package broker provides a zero-dependency Go SDK for Secret Broker V4.
//
// Compatible with Go 1.21+. Pure stdlib (net/http, crypto/tls, encoding/json).
package broker

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"strconv"
)

// Typed errors. Wrap the underlying error.
var (
	ErrAuth        = errors.New("broker: authentication failed (401)")
	ErrPermission  = errors.New("broker: permission denied (403)")
	ErrNotFound    = errors.New("broker: resource not found (404)")
	ErrRateLimit   = errors.New("broker: rate limited (429)")
	ErrServer      = errors.New("broker: server error (5xx)")
	ErrConnection  = errors.New("broker: connection error")
	ErrInvalidArg  = errors.New("broker: invalid argument (400)")
)

// BrokerError is a typed error that includes the HTTP status, response body,
// and request metadata. It satisfies the standard error interface and
// supports errors.Is / errors.As / errors.Unwrap.
type BrokerError struct {
	Status     int    // HTTP status code (0 for connection errors before response)
	Code       string // Broker-specific error code from response (e.g. "secret_not_found")
	Body       string // Raw response body (already redacted)
	Op         string // Logical operation, e.g. "get_secret" or "list_secrets"
	RequestID  string // X-Request-Id from response headers (for log correlation)
	RetryAfter int    // Seconds to wait before retry (from Retry-After header)
	Err        error  // Wrapped error (one of the typed errors above)
}

// Error returns a human-readable string with status + code + request_id +
// retry_after. Example: "broker: get_secret: secret not found (status=404,
// code=secret_not_found, request_id=req_xyz)"
func (e *BrokerError) Error() string {
	var buf bytes.Buffer
	buf.WriteString("broker: ")
	if e.Op != "" {
		buf.WriteString(e.Op)
		buf.WriteString(": ")
	}
	if e.Err != nil {
		buf.WriteString(e.Err.Error())
	}
	meta := []string{}
	if e.Status != 0 {
		meta = append(meta, fmt.Sprintf("status=%d", e.Status))
	}
	if e.Code != "" {
		meta = append(meta, fmt.Sprintf("code=%s", e.Code))
	}
	if e.RequestID != "" {
		meta = append(meta, fmt.Sprintf("request_id=%s", e.RequestID))
	}
	if e.RetryAfter > 0 {
		meta = append(meta, fmt.Sprintf("retry_after=%ds", e.RetryAfter))
	}
	if len(meta) > 0 {
		buf.WriteString(" (")
		for i, m := range meta {
			if i > 0 {
				buf.WriteString(", ")
			}
			buf.WriteString(m)
		}
		buf.WriteString(")")
	}
	return buf.String()
}

// Unwrap returns the wrapped typed error. Enables errors.Is(err, ErrAuth).
func (e *BrokerError) Unwrap() error { return e.Err }

// Is supports errors.Is(err, ErrAuth) etc.
func (e *BrokerError) Is(target error) bool {
	return errors.Is(e.Err, target)
}

// IsRetryable returns true if this error is worth retrying.
//
// Retryable conditions:
//   - 5xx server errors (transient, broker may recover)
//   - 429 rate limits (transient, will reset)
//   - Connection errors (no HTTP response, network/TLS/timeout)
//
// NOT retryable:
//   - 4xx client errors (bad request, auth, permission, not found)
//   - Configuration errors (ErrInvalidArg)
func (e *BrokerError) IsRetryable() bool {
	if e.Status == 0 {
		// No status = request never reached server = connection error
		return true
	}
	if e.Status == 429 {
		return true
	}
	if e.Status >= 500 && e.Status < 600 {
		return true
	}
	return false
}

// ToMap returns a structured representation for logging / audit export.
// The Body field is intentionally omitted (may contain sensitive data;
// redact upstream if needed).
func (e *BrokerError) ToMap() map[string]any {
	return map[string]any{
		"error_type":   "BrokerError",
		"op":           e.Op,
		"status":       e.Status,
		"code":         e.Code,
		"request_id":   e.RequestID,
		"retry_after":  e.RetryAfter,
		"is_retryable": e.IsRetryable(),
		"message":      e.Error(),
		// body intentionally omitted
	}
}

// newError constructs a typed BrokerError from HTTP response.
func newError(op string, status int, body string, headers map[string][]string) error {
	var typed error
	switch {
	case status == 400:
		typed = ErrInvalidArg
	case status == 401:
		typed = ErrAuth
	case status == 403:
		typed = ErrPermission
	case status == 404:
		typed = ErrNotFound
	case status == 429:
		typed = ErrRateLimit
	case status >= 500:
		typed = ErrServer
	default:
		typed = fmt.Errorf("http %d", status)
	}

	requestID := ""
	if vals, ok := headers["X-Request-Id"]; ok && len(vals) > 0 {
		requestID = vals[0]
	}

	retryAfter := 0
	if vals, ok := headers["Retry-After"]; ok && len(vals) > 0 {
		if n, err := strconv.Atoi(vals[0]); err == nil {
			retryAfter = n
		}
	}

	return &BrokerError{
		Status:     status,
		Code:       extractCode(body),
		Body:       redact(body),
		Op:         op,
		RequestID:  requestID,
		RetryAfter: retryAfter,
		Err:        typed,
	}
}

func newConnError(op string, err error) error {
	return &BrokerError{Op: op, Err: fmt.Errorf("%w: %v", ErrConnection, err)}
}

// extractCode parses the broker-specific error code from a JSON response body.
// Example: {"error":{"code":"secret_not_found","message":"..."}} -> "secret_not_found"
// Returns "" if the body doesn't have the expected structure.
func extractCode(body string) string {
	if body == "" {
		return ""
	}
	// Simple substring search (avoids pulling in encoding/json here).
	// The broker always returns errors as {"error":{"code":"...","message":"..."}}
	// so we look for `"code":"..."` pattern.
	const prefix = `"code":"`
	idx := -1
	for i := 0; i+len(prefix) < len(body); i++ {
		if body[i:i+len(prefix)] == prefix {
			idx = i + len(prefix)
			break
		}
	}
	if idx == -1 {
		return ""
	}
	// Find closing quote
	for j := idx; j < len(body); j++ {
		if body[j] == '"' {
			return body[idx:j]
		}
	}
	return ""
}

// ============================================================
// Credential zero-touch: redact known token formats in error messages
// ============================================================

// redactRule pairs a regex pattern with a replacement string.
type redactRule struct {
	name    string
	pattern *regexp.Regexp
	repl    string
}

var redactPatterns = []*redactRule{
	{name: "github_pat", pattern: regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{20,}`), repl: "[REDACTED_GITHUB]"},
	{name: "openai_sk", pattern: regexp.MustCompile(`sk-[A-Za-z0-9]{20,}`), repl: "[REDACTED_OPENAI]"},
	{name: "anthropic", pattern: regexp.MustCompile(`sk-ant-[A-Za-z0-9_\-]{20,}`), repl: "[REDACTED_ANTHROPIC]"},
	{name: "aws_akia", pattern: regexp.MustCompile(`AKIA[A-Z0-9]{12,}`), repl: "[REDACTED_AWS]"},
	{name: "aws_asia", pattern: regexp.MustCompile(`ASIA[A-Z0-9]{12,}`), repl: "[REDACTED_AWS_STS]"},
	{name: "jwt", pattern: regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`), repl: "[REDACTED_JWT]"},
	{name: "password_kv", pattern: regexp.MustCompile(`(?i)(password\s*=\s*)\S+`), repl: "${1}[REDACTED]"},
	{name: "token_kv", pattern: regexp.MustCompile(`(?i)(token\s*=\s*)\S+`), repl: "${1}[REDACTED]"},
}

// redact replaces known secret formats with placeholders to prevent
// accidental leakage in error messages.
func redact(s string) string {
	if s == "" {
		return s
	}
	for _, rule := range redactPatterns {
		s = rule.pattern.ReplaceAllString(s, rule.repl)
	}
	return s
}
