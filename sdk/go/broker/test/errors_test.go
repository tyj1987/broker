// Tests for V4.1.1 BrokerError improvements.
//
// V4.1.1 added:
//   - RequestID parsed from X-Request-Id response header
//   - RetryAfter parsed from Retry-After response header
//   - IsRetryable() method (5xx + 429 + connection -> true; 4xx -> false)
//   - ToMap() for structured logging
//   - extractCode() parses broker error code from JSON body
//
// V4.1.0 errors.go only had: Status, Code, Body, Op, Err + Error()/Unwrap()/Is().
// These tests verify the new fields and methods.
package broker_test

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	broker "github.com/tyj1987/broker-sdk-go/broker"
)

// =====================================================================
// Test helpers
// =====================================================================

// makeBrokerError constructs a BrokerError via a fake HTTPS server.
// Verifies that newError() correctly parses headers into RequestID/RetryAfter.
// Uses httptest.NewUnstartedServer + StartTLS (mirrors client_test.go pattern).
func makeBrokerError(t *testing.T, status int, body string, headers map[string]string) *broker.BrokerError {
	t.Helper()
	cert, caPEM := mustCert(t)
	caPath := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatalf("write CA: %v", err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		for k, v := range headers {
			rw.Header().Set(k, v)
		}
		rw.WriteHeader(status)
		rw.Write([]byte(body))
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	defer srv.Close()

	cfg := broker.Config{
		Endpoint: srv.URL,
		CACert:   caPath,
		Timeout:  5 * time.Second,
	}
	c, err := broker.NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = c.GetSecret(context.Background(), "test")
	if err == nil {
		t.Fatalf("expected error from %d response", status)
	}
	var be *broker.BrokerError
	if !errors.As(err, &be) {
		t.Fatalf("expected BrokerError, got %T: %v", err, err)
	}
	return be
}

// =====================================================================
// Test IsRetryable
// =====================================================================

func TestIsRetryable_4xx_NotRetryable(t *testing.T) {
	for _, status := range []int{400, 401, 403, 404, 422} {
		be := makeBrokerError(t, status, `{"error":{"code":"x","message":"y"}}`, nil)
		if be.IsRetryable() {
			t.Errorf("status=%d should NOT be retryable", status)
		}
	}
}

func TestIsRetryable_429_Retryable(t *testing.T) {
	be := makeBrokerError(t, 429, `{"error":{"code":"rate_limit","message":"slow down"}}`, nil)
	if !be.IsRetryable() {
		t.Error("status=429 should be retryable")
	}
}

func TestIsRetryable_5xx_Retryable(t *testing.T) {
	for _, status := range []int{500, 502, 503, 504, 599} {
		be := makeBrokerError(t, status, `{"error":{"code":"server_error","message":"crashed"}}`, nil)
		if !be.IsRetryable() {
			t.Errorf("status=%d should be retryable", status)
		}
	}
}

// =====================================================================
// Test RequestID + RetryAfter parsing
// =====================================================================

func TestRequestID_ParsedFromHeader(t *testing.T) {
	be := makeBrokerError(t, 404, `{"error":{"code":"secret_not_found","message":"x"}}`,
		map[string]string{"X-Request-Id": "req_abc123"})
	if be.RequestID != "req_abc123" {
		t.Errorf("RequestID = %q, want req_abc123", be.RequestID)
	}
}

func TestRequestID_MissingHeader(t *testing.T) {
	be := makeBrokerError(t, 404, `{"error":{"code":"x","message":"y"}}`, nil)
	if be.RequestID != "" {
		t.Errorf("RequestID should be empty when header missing, got %q", be.RequestID)
	}
}

func TestRetryAfter_ParsedFromHeader(t *testing.T) {
	be := makeBrokerError(t, 429, `{"error":{"code":"rate_limit","message":"slow down"}}`,
		map[string]string{"Retry-After": "30"})
	if be.RetryAfter != 30 {
		t.Errorf("RetryAfter = %d, want 30", be.RetryAfter)
	}
}

func TestRetryAfter_MissingHeader(t *testing.T) {
	be := makeBrokerError(t, 429, `{"error":{"code":"rate_limit","message":"slow down"}}`, nil)
	if be.RetryAfter != 0 {
		t.Errorf("RetryAfter should be 0 when header missing, got %d", be.RetryAfter)
	}
}

func TestRetryAfter_InvalidValue(t *testing.T) {
	be := makeBrokerError(t, 429, `{"error":{"code":"x","message":"y"}}`,
		map[string]string{"Retry-After": "not-a-number"})
	if be.RetryAfter != 0 {
		t.Errorf("RetryAfter should be 0 for invalid value, got %d", be.RetryAfter)
	}
}

// =====================================================================
// Test Code parsing from JSON body
// =====================================================================

func TestCode_ParsedFromBody(t *testing.T) {
	be := makeBrokerError(t, 404, `{"error":{"code":"secret_not_found","message":"..."}}`, nil)
	if be.Code != "secret_not_found" {
		t.Errorf("Code = %q, want secret_not_found", be.Code)
	}
}

func TestCode_MissingInBody(t *testing.T) {
	be := makeBrokerError(t, 500, `internal server error`, nil)
	if be.Code != "" {
		t.Errorf("Code should be empty when not in body, got %q", be.Code)
	}
}

func TestCode_EmptyBody(t *testing.T) {
	be := makeBrokerError(t, 500, ``, nil)
	if be.Code != "" {
		t.Errorf("Code should be empty for empty body, got %q", be.Code)
	}
}

// =====================================================================
// Test ToMap (structured logging)
// =====================================================================

func TestToMap_IncludesExpectedFields(t *testing.T) {
	be := makeBrokerError(t, 404, `{"error":{"code":"secret_not_found","message":"x"}}`,
		map[string]string{"X-Request-Id": "req_xyz"})
	m := be.ToMap()

	if m["error_type"] != "BrokerError" {
		t.Errorf("error_type = %v, want BrokerError", m["error_type"])
	}
	if m["op"] == "" {
		t.Error("op should be set")
	}
	if m["status"] != 404 {
		t.Errorf("status = %v, want 404", m["status"])
	}
	if m["code"] != "secret_not_found" {
		t.Errorf("code = %v, want secret_not_found", m["code"])
	}
	if m["request_id"] != "req_xyz" {
		t.Errorf("request_id = %v, want req_xyz", m["request_id"])
	}
	if m["is_retryable"] != false {
		t.Error("is_retryable should be false for 404")
	}
}

func TestToMap_OmitsBody(t *testing.T) {
	// body may contain sensitive data; must NOT be in ToMap
	be := makeBrokerError(t, 500, `{"secret":"should-not-leak"}`, nil)
	m := be.ToMap()
	if _, hasBody := m["body"]; hasBody {
		t.Error("ToMap must not include body field")
	}
}

// =====================================================================
// Test Error() format
// =====================================================================

func TestError_IncludesStatusAndCode(t *testing.T) {
	be := makeBrokerError(t, 404, `{"error":{"code":"secret_not_found","message":"x"}}`, nil)
	msg := be.Error()
	if !strings.Contains(msg, "404") {
		t.Errorf("Error() should include status=404, got %q", msg)
	}
	if !strings.Contains(msg, "secret_not_found") {
		t.Errorf("Error() should include code, got %q", msg)
	}
}

func TestError_IncludesRequestID(t *testing.T) {
	be := makeBrokerError(t, 404, `{"error":{"code":"x","message":"y"}}`,
		map[string]string{"X-Request-Id": "req_abc"})
	msg := be.Error()
	if !strings.Contains(msg, "req_abc") {
		t.Errorf("Error() should include request_id, got %q", msg)
	}
}

func TestError_IncludesRetryAfter(t *testing.T) {
	be := makeBrokerError(t, 429, `{"error":{"code":"rate_limit","message":"x"}}`,
		map[string]string{"Retry-After": "60"})
	msg := be.Error()
	if !strings.Contains(msg, "60s") {
		t.Errorf("Error() should include retry_after=60s, got %q", msg)
	}
}

// =====================================================================
// Test errors.Is / errors.As (typed errors)
// =====================================================================

func TestErrorsIs_AuthError(t *testing.T) {
	be := makeBrokerError(t, 401, `{"error":{"code":"auth_failed","message":"x"}}`, nil)
	if !errors.Is(be, broker.ErrAuth) {
		t.Error("errors.Is(be, ErrAuth) should be true for 401")
	}
	if errors.Is(be, broker.ErrNotFound) {
		t.Error("errors.Is(be, ErrNotFound) should be false for 401")
	}
}

func TestErrorsIs_NotFoundError(t *testing.T) {
	be := makeBrokerError(t, 404, `{"error":{"code":"secret_not_found","message":"x"}}`, nil)
	if !errors.Is(be, broker.ErrNotFound) {
		t.Error("errors.Is(be, ErrNotFound) should be true for 404")
	}
}

func TestErrorsIs_RateLimitError(t *testing.T) {
	be := makeBrokerError(t, 429, `{"error":{"code":"rate_limit","message":"x"}}`, nil)
	if !errors.Is(be, broker.ErrRateLimit) {
		t.Error("errors.Is(be, ErrRateLimit) should be true for 429")
	}
}

func TestErrorsAs_BrokerError(t *testing.T) {
	be := makeBrokerError(t, 500, `{"error":{"code":"internal","message":"x"}}`, nil)
	var target *broker.BrokerError
	if !errors.As(be, &target) {
		t.Error("errors.As should match *BrokerError")
	}
	if target.Status != 500 {
		t.Errorf("target.Status = %d, want 500", target.Status)
	}
}
