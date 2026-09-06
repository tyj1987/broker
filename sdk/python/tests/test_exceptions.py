"""Tests for V4.1.1 exception improvements.

V4.1.1 added:
- `__repr__` for all 7 exception classes
- `to_dict()` for structured logging
- `__str__` includes status + code
- `is_retryable` property
- `retry_after` from Retry-After header

V4.1.0 had no `__repr__` (only `__str__` via base Exception) — debugging was
hard. These tests verify the improvements work.
"""

import pytest
from secret_broker.exceptions import (
    BrokerError,
    BrokerAuthError,
    BrokerNotFoundError,
    BrokerPermissionError,
    BrokerRateLimitError,
    BrokerServerError,
    BrokerConnectionError,
)


# === Test __str__ includes status + code ===

def test_broker_error_str_basic():
    err = BrokerError("something failed")
    s = str(err)
    assert "BrokerError" in s
    assert "something failed" in s


def test_broker_error_str_with_status():
    err = BrokerError("bad request", status=400, code="invalid_param")
    s = str(err)
    assert "BrokerError" in s
    assert "bad request" in s
    assert "status=400" in s
    assert "code=invalid_param" in s


def test_broker_error_str_with_retry_after():
    err = BrokerError("rate limited", status=429, code="rate_limit", retry_after=30)
    s = str(err)
    assert "retry_after=30s" in s
    assert "request_id" not in s  # not set


def test_broker_error_str_with_request_id():
    err = BrokerError("server error", status=500, request_id="req_abc123")
    s = str(err)
    assert "request_id=req_abc123" in s


def test_broker_auth_error_str():
    err = BrokerAuthError("invalid mTLS cert", status=401, code="auth_failed")
    s = str(err)
    assert "BrokerAuthError" in s
    assert "invalid mTLS cert" in s
    assert "status=401" in s
    assert "code=auth_failed" in s


# === Test __repr__ (developer-friendly) ===

def test_broker_error_repr():
    err = BrokerError("oops", status=500, code="internal")
    r = repr(err)
    assert r.startswith("BrokerError(")
    assert "message='oops'" in r
    assert "status=500" in r
    assert "code='internal'" in r
    assert "request_id=None" in r
    assert "retry_after=None" in r


def test_broker_rate_limit_error_repr():
    err = BrokerRateLimitError("too many requests", status=429, retry_after=60)
    r = repr(err)
    assert "BrokerRateLimitError" in r
    assert "status=429" in r
    assert "retry_after=60" in r


# === Test is_retryable property ===

def test_is_retryable_4xx_client_error():
    # 4xx (except 429) is NOT retryable
    err = BrokerError("not found", status=404)
    assert err.is_retryable is False


def test_is_retryable_429_rate_limit():
    err = BrokerError("rate limited", status=429)
    assert err.is_retryable is True


def test_is_retryable_5xx_server_error():
    err = BrokerError("server down", status=503)
    assert err.is_retryable is True


def test_is_retryable_no_status_connection_error():
    err = BrokerConnectionError("connection refused")
    assert err.is_retryable is True


def test_is_retryable_400_bad_request():
    err = BrokerError("bad input", status=400)
    assert err.is_retryable is False


def test_is_retryable_401_unauthorized():
    err = BrokerAuthError("bad cert", status=401)
    assert err.is_retryable is False


def test_is_retryable_403_forbidden():
    err = BrokerPermissionError("not allowed", status=403)
    assert err.is_retryable is False


# === Test to_dict (structured logging) ===

def test_to_dict_basic():
    err = BrokerError("failed", status=500, code="internal")
    d = err.to_dict()
    assert d["error_type"] == "BrokerError"
    assert d["message"] == "failed"
    assert d["status"] == 500
    assert d["code"] == "internal"
    assert d["request_id"] is None
    assert d["retry_after"] is None
    assert d["is_retryable"] is True  # 5xx


def test_to_dict_omits_body():
    # body may contain sensitive data; must NOT be in to_dict
    err = BrokerError("failed", status=500, body={"secret": "should-not-leak"})
    d = err.to_dict()
    assert "body" not in d
    assert "should-not-leak" not in str(d)


def test_to_dict_serialization_roundtrip():
    # to_dict should be JSON-serializable for structured loggers
    import json
    err = BrokerRateLimitError("too many", status=429, retry_after=30, request_id="req_xyz")
    d = err.to_dict()
    json_str = json.dumps(d)  # should not raise
    assert "BrokerRateLimitError" in json_str
    assert "429" in json_str


# === Test inheritance ===

def test_broker_auth_error_is_broker_error():
    err = BrokerAuthError("bad", status=401)
    assert isinstance(err, BrokerError)
    assert isinstance(err, BrokerAuthError)


def test_broker_permission_error_is_broker_auth_error():
    # BrokerPermissionError subclasses BrokerAuthError (both are auth-related)
    err = BrokerPermissionError("forbidden", status=403)
    assert isinstance(err, BrokerError)
    assert isinstance(err, BrokerAuthError)
    assert isinstance(err, BrokerPermissionError)


def test_broker_rate_limit_error_retryable():
    # BrokerRateLimitError explicitly marks is_retryable=True (overrides default)
    err = BrokerRateLimitError("slow down", status=429)
    assert err.is_retryable is True


def test_broker_server_error_retryable():
    # BrokerServerError explicitly marks is_retryable=True (overrides default)
    err = BrokerServerError("crashed", status=500)
    assert err.is_retryable is True


def test_broker_connection_error_forces_status_none():
    # BrokerConnectionError should always have status=None (no HTTP response)
    err = BrokerConnectionError("connection refused")
    assert err.status is None
    assert err.code == "connection_error"  # auto-set default


def test_broker_connection_error_with_request_id():
    # request_id can still be set even when no response (from client-side UUID)
    err = BrokerConnectionError("timeout", request_id="req_abc123")
    s = str(err)
    assert "request_id=req_abc123" in s


# === Test exception chaining (raise X from Y) ===

def test_exception_chaining_preserves_cause():
    try:
        try:
            raise ValueError("underlying network error")
        except ValueError as e:
            raise BrokerConnectionError("failed to reach broker") from e
    except BrokerConnectionError as e:
        assert e.__cause__ is not None
        assert isinstance(e.__cause__, ValueError)


# === Test usage in real scenarios ===

def test_catch_specific_exception():
    # User code: try: ... except BrokerNotFoundError: ...
    raised = False
    try:
        raise BrokerNotFoundError("secret 'github-pat' not found", status=404, code="secret_not_found")
    except BrokerNotFoundError as e:
        raised = True
        assert e.status == 404
        assert e.code == "secret_not_found"
        assert e.is_retryable is False
    assert raised


def test_catch_base_exception():
    # User code: except BrokerError: ... (catches all)
    raised = False
    try:
        raise BrokerServerError("crashed", status=500)
    except BrokerError as e:  # catches BrokerServerError (subclass)
        raised = True
        assert e.is_retryable is True
    assert raised
