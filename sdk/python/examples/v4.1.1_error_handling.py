#!/usr/bin/env python3
"""
Example: V4.1.1 SDK error handling (Python).

Demonstrates:
  1. Single BrokerError contract (replaces 6 typed classes from V4.1.0).
  2. parse_broker_error factory (typed error from raw response).
  3. Built-in retry (5xx / 429 / connection) with exponential backoff.
  4. Auto-redact body on construction.
  5. is_retryable + retry_after + request_id accessors.

Run:
  python examples/v4.1.1_error_handling.py

Requires:
  - broker running on https://127.0.0.1:8443 (or change endpoint)
  - pki setup: secrets/clients.json + pki/{ca.crt, clients/admin.{crt,key}}

Note: This example is documentation / template code. It does not actually
call a live broker — the broker is offline in dev. See README for setup.
"""

import sys
sys.path.insert(0, "../..")  # so `import secret_broker` works from sdk/python/

# === V4.1.1 imports ===
from secret_broker import (
    BrokerClient,
    BrokerError,             # V4.1.1: single typed error (replaces BrokerAuthError etc.)
    BrokerConnectionError,   # V4.1.1: network-level failures (always retryable)
    parse_broker_error,      # V4.1.1: factory: raw response → typed error
)

# === 1. Construct client with V4.1.1 retry config ===
c = BrokerClient(
    "https://127.0.0.1:8443",
    ca_cert="../../pki/ca.crt",
    client_cert="../../pki/clients/admin.crt",
    client_key="../../pki/clients/admin.key",
    # V4.1.1: built-in retry (defaults: max_retries=2, retry_backoff_ms=500)
    max_retries=3,           # retry up to 3 times (4 total attempts)
    retry_backoff_ms=1000,   # start with 1s, doubled each retry (1s → 2s → 4s)
)

# === 2. Call surface and catch V4.1.1 errors ===
try:
    secret = c.get_secret("github.pat")
    print(f"Got secret: {secret[:8]}...")

except BrokerError as e:
    # V4.1.1: single BrokerError, regardless of HTTP status.
    # Check status / code / is_retryable to branch.
    print(f"broker error: {e}")
    print(f"  status     = {e.status}")
    print(f"  code       = {e.code!r}")
    print(f"  request_id = {e.request_id!r}")
    print(f"  retry_after= {e.retry_after}s")
    print(f"  is_retryable = {e.is_retryable}")
    # V4.1.1: body is auto-redacted on construction; safe to log
    print(f"  body       = {e.body}")

    if e.status == 401 or e.code == "auth_failed":
        print("  → auth failed, re-login required")
    elif e.status == 404 or e.code == "not_found":
        print("  → secret not found, check name")
    elif e.is_retryable:
        # SDK already retried up to max_retries; this is the final attempt
        print(f"  → retryable, last attempt after {e.retry_after}s wait")
        # Maybe surface to user: "service degraded, please try again"
    else:
        print("  → permanent error, do not retry")

except BrokerConnectionError as e:
    # V4.1.1: separate class for network-level failures
    # Always retryable (is_retryable = True).
    print(f"connection failed: {e}")
    print(f"  op        = {e.op}")
    print(f"  cause     = {e.cause!r}")  # underlying OSError
    print(f"  request_id= {e.request_id!r}")
    # SDK already retried; surface for ops team.
    # Common causes: TLS handshake fail, ECONNREFUSED, ETIMEDOUT, EAI_AGAIN.

# === 3. parse_broker_error factory (V4.1.1 new) ===
# Useful for middleware that needs to convert raw responses to typed errors
# without actually making a request.

err = parse_broker_error(
    status=429,
    headers={"x-request-id": "req-abc-123", "retry-after": "30"},
    body={"error": {"code": "rate_limited", "message": "slow down"}},
    op="get_secret",
)

assert err.status == 429
assert err.code == "rate_limited"
assert err.request_id == "req-abc-123"
assert err.retry_after == 30
assert err.is_retryable is True
assert "request_id=req-abc-123" in str(err)
assert "retry_after=30s" in str(err)
print(f"\nfactory example: {err}")

# === 4. to_dict() and __repr__ (V4.1.1 new) ===
d = err.to_dict()
assert "body" not in d, "to_dict() must omit body (may contain secrets)"
print(f"to_dict(): {d}")
print(f"repr: {err!r}")

# === 5. When NOT to use V4.1.1 retry (max_retries=0) ===
# If you have your own retry logic, disable SDK retry to avoid double-retry:
c_no_retry = BrokerClient(
    "https://127.0.0.1:8443",
    ca_cert="../../pki/ca.crt",
    max_retries=0,  # SDK does not retry; your code handles it
)

# === 6. Migrating from V4.1.0 6-class model ===
# If you had:
#     except BrokerAuthError as e: ...
# V4.1.1 equivalent:
#     except BrokerError as e:
#         if e.status == 401 or e.code == "auth_failed": ...
#
# The old classes (BrokerAuthError, BrokerPermissionError, etc.) are
# still exported in V4.1.1 for one release, but emit DeprecationWarning
# on import. Plan to migrate to BrokerError + status/code checks before
# V4.2.0 (Q2 2027).
