// Package main demonstrates V4.1.1 SDK error handling (Go).
//
// Run:
//   cd sdk/go/examples/v4.1.1_error_handling
//   go run main.go
//
// Requires:
//   - broker running on https://127.0.0.1:8443
//   - pki setup: secrets/clients.json + pki/{ca.crt, clients/admin.{crt,key}}
//
// Note: This example is documentation / template code. It does not actually
// call a live broker — the broker is offline in dev. See README for setup.
package main

import (
	"errors"
	"fmt"

	broker "github.com/tyj1987/broker-sdk-go"
)

func main() {
	// === 1. Construct client with V4.1.1 retry config ===
	c := broker.New("https://127.0.0.1:8443", broker.Config{
		CACert:       "../../pki/ca.crt",
		ClientCert:   "../../pki/clients/admin.crt",
		ClientKey:    "../../pki/clients/admin.key",
		MaxRetries:   3,    // V4.1.1: built-in retry (default 2)
		RetryBackoffMs: 1000, // V4.1.1: start with 1s, doubled each retry
	})

	// === 2. Call surface and catch V4.1.1 errors ===
	val, err := c.GetSecret("github.pat")
	if err != nil {
		// V4.1.1: use errors.As with *broker.BrokerError (single typed error)
		var berr *broker.BrokerError
		if errors.As(err, &berr) {
			fmt.Printf("broker error: %s\n", berr)
			fmt.Printf("  status     = %d\n", berr.Status())
			fmt.Printf("  code       = %q\n", berr.Code())
			fmt.Printf("  request_id = %q\n", berr.RequestID())
			fmt.Printf("  retry_after= %d\n", berr.RetryAfter())
			fmt.Printf("  is_retryable = %v\n", berr.IsRetryable())
			// V4.1.1: body auto-redacted on construction
			fmt.Printf("  body       = %q\n", berr.Body())

			switch {
			case berr.Status() == 401 || berr.Code() == "auth_failed":
				fmt.Println("  → auth failed, re-login required")
			case berr.Status() == 404 || berr.Code() == "not_found":
				fmt.Println("  → secret not found, check name")
			case berr.IsRetryable():
				// SDK already retried up to MaxRetries; this is the final attempt
				fmt.Printf("  → retryable, last attempt after %ds wait\n", berr.RetryAfter())
			default:
				fmt.Println("  → permanent error, do not retry")
			}
		}

		// V4.1.1: separate class for network-level failures (always retryable)
		var cerr *broker.BrokerConnectionError
		if errors.As(err, &cerr) {
			fmt.Printf("connection failed: %s\n", cerr)
			fmt.Printf("  op        = %s\n", cerr.Op())
			fmt.Printf("  cause     = %v\n", cerr.Cause())
			fmt.Printf("  request_id= %q\n", cerr.RequestID())
			// SDK already retried; surface for ops team.
		}
		return
	}
	fmt.Printf("Got secret: %s...\n", val[:8])

	// === 3. ParseBrokerError factory (V4.1.1 new) ===
	// Useful for middleware that needs to convert raw responses to typed
	// errors without actually making a request.
	factoryErr := broker.ParseBrokerError(
		429,
		map[string][]string{
			"x-request-id": {"req-abc-123"},
			"retry-after":  {"30"},
		},
		[]byte(`{"error":{"code":"rate_limited","message":"slow down"}}`),
		"get_secret",
	)
	fmt.Printf("\nfactory example: %s\n", factoryErr)
	fmt.Printf("  status=%d code=%q request_id=%q retry_after=%d is_retryable=%v\n",
		factoryErr.Status(), factoryErr.Code(), factoryErr.RequestID(),
		factoryErr.RetryAfter(), factoryErr.IsRetryable())

	// === 4. ToMap (V4.1.1 new; body omitted for safety) ===
	m := factoryErr.ToMap()
	if _, hasBody := m["body"]; hasBody {
		panic("ToMap() must omit body")
	}
	fmt.Printf("to_map: %+v\n", m)

	// === 5. When NOT to use V4.1.1 retry (MaxRetries=0) ===
	// If you have your own retry logic, disable SDK retry to avoid double-retry.
	_ = broker.New("https://127.0.0.1:8443", broker.Config{
		CACert:     "../../pki/ca.crt",
		MaxRetries: 0, // SDK does not retry; your code handles it
	})

	// === 6. Migrating from V4.1.0 6-class model ===
	// If you had:
	//   if errors.Is(err, broker.ErrAuth) { ... }
	// V4.1.1 equivalent:
	//   var berr *broker.BrokerError
	//   if errors.As(err, &berr) && berr.Status() == 401 { ... }
	//
	// The old sentinels (ErrAuth, ErrPermission, ErrNotFound, etc.) are
	// still exported in V4.1.1 for one release, but documented as
	// deprecated in godoc. Plan to migrate before V4.2.0 (Q2 2027).
}
