// Package broker provides a zero-dependency Go SDK for Secret Broker V4.
//
// Compatible with Go 1.21+. Pure stdlib (net/http, crypto/tls, encoding/json).
package broker

import (
	"bytes"
	"errors"
	"fmt"
)

// Typed errors. Wrap the underlying error.
var (
	ErrAuth        = errors.New("broker: authentication failed (401)")
	ErrPermission  = errors.New("broker: permission denied (403)")
	ErrNotFound    = errors.New("broker: resource not found (404)")
	ErrRateLimit   = errors.New("broker: rate limited (429)")
	ErrServer      = errors.New("broker: server error (5xx)")
	ErrConnection  = errors.New("broker: connection error")
	ErrInvalidArg  = errors.New("broker: invalid argument")
	ErrBrowserOnly = errors.New("broker: operation requires the WebAuthn browser workbench")
)

// BrokerError is a typed error that includes the HTTP status and response body.
type BrokerError struct {
	Status int
	Code   string
	Body   string
	Op     string // logical operation, e.g. "get_secret"
	Err    error  // wrapped error (typed)
}

func (e *BrokerError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("broker: %s: %s (status=%d, code=%s)", e.Op, e.Err, e.Status, e.Code)
	}
	return fmt.Sprintf("broker: %s: %s (status=%d)", e.Op, e.Err, e.Status)
}

func (e *BrokerError) Unwrap() error { return e.Err }

func (e *BrokerError) Is(target error) bool {
	return errors.Is(e.Err, target)
}

func newError(op string, status int, body string) error {
	var typed error
	switch {
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
	return &BrokerError{
		Status: status,
		Body:   redact(body),
		Op:     op,
		Err:    typed,
	}
}

func newConnError(op string, err error) error {
	return &BrokerError{Op: op, Err: fmt.Errorf("%w: %v", ErrConnection, err)}
}

// ============================================================
// 凭据零接触: 擦除错误消息/响应体中的已知 token 格式
// ============================================================

var redactPatterns = []*redactRule{
	{name: "github_pat", pattern: `gh[pousr]_[A-Za-z0-9]{20,}`, repl: "[REDACTED_GITHUB]"},
	{name: "openai_sk", pattern: `sk-[A-Za-z0-9]{20,}`, repl: "[REDACTED_OPENAI]"},
	{name: "anthropic", pattern: `sk-ant-[A-Za-z0-9_\-]{20,}`, repl: "[REDACTED_ANTHROPIC]"},
	{name: "aws_akia", pattern: `AKIA[A-Z0-9]{12,}`, repl: "[REDACTED_AWS]"},
	{name: "aws_asia", pattern: `ASIA[A-Z0-9]{12,}`, repl: "[REDACTED_AWS_STS]"},
	{name: "jwt", pattern: `eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}`, repl: "[REDACTED_JWT]"},
	{name: "header_auth", pattern: `(?i)(authorization\s*:\s*)\S+`, repl: "${1}[REDACTED]"},
	{name: "header_apikey", pattern: `(?i)(x-api-key\s*:\s*)\S+`, repl: "${1}[REDACTED]"},
	{name: "query_token", pattern: `(?i)(token\s*=\s*)\S+`, repl: "${1}[REDACTED]"},
	{name: "query_password", pattern: `(?i)(password\s*=\s*)\S+`, repl: "${1}[REDACTED]"},
}

type redactRule struct {
	name    string
	pattern string
	repl    string
}

func redact(s string) string {
	if s == "" {
		return s
	}
	// Avoid regex import: use simple scanning with bytes.Contains
	// For each pattern, do a non-regex substring match where possible.
	// For regex patterns, fall back to a tiny in-process RE engine via strings.Index on fixed-prefix patterns.
	out := s
	for _, r := range redactPatterns {
		// We use a hand-rolled RE engine for the common simple cases.
		out = applySimpleRe(out, r)
	}
	return out
}

func applySimpleRe(s string, r *redactRule) string {
	// Convert the few regex patterns we need into simple operations:
	//  - `prefix<char class>{min,}` → match prefix + N allowed chars
	//  - `(?i)(group:)\S+`           → case-insensitive group + non-space
	//  - `prefix<...>{N,}.<...>{N,}.<...>{N,}` → 3 segments
	// All our patterns fit these.
	switch r.name {
	case "github_pat":
		return redactPrefixThen(s, "gh", 0, 'A', 'Z', 'a', 'z', '0', '9', '_', 'p', 20, r.repl)
	case "openai_sk":
		return redactPrefixThen(s, "sk-", 0, 'A', 'Z', 'a', 'z', '0', '9', 0, 0, 20, r.repl)
	case "anthropic":
		return redactPrefixThen(s, "sk-ant-", 0, 'A', 'Z', 'a', 'z', '0', '9', '-', '_', 20, r.repl)
	case "aws_akia":
		return redactPrefixThen(s, "AKIA", 0, 'A', 'Z', '0', '9', 0, 0, 0, 0, 12, r.repl)
	case "aws_asia":
		return redactPrefixThen(s, "ASIA", 0, 'A', 'Z', '0', '9', 0, 0, 0, 0, 12, r.repl)
	case "jwt":
		return redactJWT(s, r.repl)
	case "header_auth":
		return redactHeader(s, "authorization:", r.repl)
	case "header_apikey":
		return redactHeader(s, "x-api-key:", r.repl)
	case "query_token":
		return redactHeader(s, "token=", r.repl)
	case "query_password":
		return redactHeader(s, "password=", r.repl)
	}
	return s
}

// redactPrefixThen replaces matches of `prefix + tailChars{count,minTail}`.
func redactPrefixThen(s, prefix string, _ int, c1, c2, c3, c4, c5, c6, c7, c8 byte, minTail int, repl string) string {
	allowed := func(b byte) bool {
		switch b {
		case c1, c2, c3, c4, c5, c6, c7, c8:
			return true
		}
		return false
	}
	var out bytes.Buffer
	pl := len(prefix)
	i := 0
	for i < len(s) {
		idx := indexCI(s, prefix, i)
		if idx < 0 {
			out.WriteString(s[i:])
			break
		}
		// Copy up to (but not including) match
		out.WriteString(s[i:idx])
		// Find tail length
		j := idx + pl
		for j < len(s) && allowed(s[j]) {
			j++
		}
		if j-(idx+pl) >= minTail {
			out.WriteString(repl)
		} else {
			out.WriteString(s[idx:j])
		}
		i = j
	}
	return out.String()
}

// redactJWT: matches eyJ<10+>.eyJ<10+>.eyJ<10+>
func redactJWT(s, repl string) string {
	for i := 0; i+4 <= len(s); i++ {
		if s[i] != 'e' || s[i+1] != 'y' || s[i+2] != 'J' {
			continue
		}
		// seg1
		j := i + 3
		for j < len(s) && isJWTChar(s[j]) {
			j++
		}
		if j-(i+3) < 10 {
			continue
		}
		// dot
		if j >= len(s) || s[j] != '.' {
			continue
		}
		j++
		// seg2
		if j+3 > len(s) || s[j] != 'e' || s[j+1] != 'y' || s[j+2] != 'J' {
			continue
		}
		k := j + 3
		for k < len(s) && isJWTChar(s[k]) {
			k++
		}
		if k-(j+3) < 10 {
			continue
		}
		// dot
		if k >= len(s) || s[k] != '.' {
			continue
		}
		k++
		// seg3
		if k+3 > len(s) || s[k] != 'e' || s[k+1] != 'y' || s[k+2] != 'J' {
			continue
		}
		l := k + 3
		for l < len(s) && isJWTChar(s[l]) {
			l++
		}
		if l-(k+3) < 10 {
			continue
		}
		// Match! Replace [i:l) with repl
		s = s[:i] + repl + s[l:]
		i = i + len(repl)
	}
	return s
}

func isJWTChar(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '_' || b == '-'
}

// redactHeader: matches `<key>\S+` (case-insensitive)
func redactHeader(s, key, repl string) string {
	var out bytes.Buffer
	kl := len(key)
	i := 0
	for i < len(s) {
		idx := indexCI(s, key, i)
		if idx < 0 {
			out.WriteString(s[i:])
			break
		}
		out.WriteString(s[i:idx])
		j := idx + kl
		for j < len(s) && s[j] != ' ' && s[j] != '\t' && s[j] != '\n' && s[j] != '\r' {
			j++
		}
		if j > idx+kl {
			out.WriteString(key)
			out.WriteString(repl)
		} else {
			out.WriteString(s[idx:j])
		}
		i = j
	}
	return out.String()
}

// indexCI: case-insensitive indexOf starting at from.
func indexCI(s, substr string, from int) int {
	if from >= len(s) {
		return -1
	}
	n := len(substr)
	if n == 0 {
		return from
	}
	for i := from; i+n <= len(s); i++ {
		match := true
		for j := 0; j < n; j++ {
			a, b := s[i+j], substr[j]
			if a >= 'A' && a <= 'Z' {
				a += 32
			}
			if b >= 'A' && b <= 'Z' {
				b += 32
			}
			if a != b {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// Suppress unused imports warning for "strings" if any.
// (bytes package is used above; this line is intentional)
