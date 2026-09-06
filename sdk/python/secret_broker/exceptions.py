"""Typed exceptions raised by secret-broker SDK.

V4.1.1 improvements:
- `__repr__` for all 7 exception classes (developer-friendly debug output)
- `to_dict()` for structured logging + audit export
- `__str__` includes status + code (not just message)
- `is_retryable` property (5xx / 429 / connection → True, 4xx → False)
- `retry_after` from Retry-After header (5xx / 429 only)
"""

from typing import Any, Dict, Optional


class BrokerError(Exception):
    """Base exception for all broker errors.

    Attributes:
        message: Human-readable error description
        status: HTTP status code (None for network errors before response)
        body: Raw response body (None if request never reached server)
        code: Broker-specific error code from response (e.g. "secret_not_found")
        request_id: X-Request-Id from response headers (for log correlation)
        retry_after: Seconds to wait before retry (from Retry-After header)
    """

    def __init__(
        self,
        message: str,
        status: Optional[int] = None,
        body: Optional[Any] = None,
        code: Optional[str] = None,
        request_id: Optional[str] = None,
        retry_after: Optional[int] = None,
    ):
        super().__init__(message)
        self.message = message
        self.status = status
        self.body = body
        self.code = code
        self.request_id = request_id
        self.retry_after = retry_after

    @property
    def is_retryable(self) -> bool:
        """Whether this error is worth retrying.

        Returns:
            True for 5xx server errors, 429 rate limits, and connection errors
            (no status code). False for 4xx client errors.
        """
        if self.status is None:
            # Network / TLS / timeout — broker never responded
            return True
        if self.status == 429:
            return True
        if 500 <= self.status < 600:
            return True
        return False

    def to_dict(self) -> Dict[str, Any]:
        """Structured representation for logging / audit export.

        Returns:
            Dict with message, status, code, request_id, retry_after, is_retryable
            Suitable for JSON serialization in structured loggers.
        """
        return {
            "error_type": self.__class__.__name__,
            "message": self.message,
            "status": self.status,
            "code": self.code,
            "request_id": self.request_id,
            "retry_after": self.retry_after,
            "is_retryable": self.is_retryable,
            # body intentionally omitted (may contain sensitive data; redact upstream)
        }

    def __str__(self) -> str:
        """Human-readable error with status + code (not just message).

        Example:
            BrokerAuthError("invalid mTLS cert")  ->  "BrokerAuthError: invalid mTLS cert [status=401 code=auth_failed]"
        """
        parts = [self.__class__.__name__, self.message]
        metadata = []
        if self.status is not None:
            metadata.append(f"status={self.status}")
        if self.code:
            metadata.append(f"code={self.code}")
        if self.request_id:
            metadata.append(f"request_id={self.request_id}")
        if self.retry_after is not None:
            metadata.append(f"retry_after={self.retry_after}s")
        if metadata:
            parts.append("[" + " ".join(metadata) + "]")
        return " ".join(parts)

    def __repr__(self) -> str:
        """Developer-friendly repr (for debugging, not user-facing).

        Example:
            BrokerAuthError("invalid mTLS cert", status=401, code="auth_failed")
            -> BrokerAuthError(message='invalid mTLS cert', status=401, code='auth_failed', request_id=None, retry_after=None)
        """
        attrs = ["message", "status", "code", "request_id", "retry_after"]
        kwargs = ", ".join(f"{a}={getattr(self, a)!r}" for a in attrs)
        return f"{self.__class__.__name__}({kwargs})"


class BrokerAuthError(BrokerError):
    """401 — authentication failure (bad cert / bad password / bad MFA)."""


class BrokerNotFoundError(BrokerError):
    """404 — resource not found (secret / service / client)."""


class BrokerPermissionError(BrokerAuthError):
    """403 — caller is authenticated but lacks permission (RBAC / ABAC)."""


class BrokerRateLimitError(BrokerError):
    """429 — caller is being rate-limited (per-client or per-tenant)."""

    @property
    def is_retryable(self) -> bool:
        # 429 is always retryable (rate limit will reset)
        return True


class BrokerServerError(BrokerError):
    """5xx — server-side failure (broker bug / dependency down)."""

    @property
    def is_retryable(self) -> bool:
        # 5xx is always retryable (transient server error)
        return True


class BrokerConnectionError(BrokerError):
    """Network / TLS / timeout — failure to reach broker (no HTTP response)."""

    @property
    def is_retryable(self) -> bool:
        # No status code = request never reached server = transient
        return True

    def __init__(self, message: str, **kwargs):
        # Force status=None + code="connection_error" for consistency
        kwargs.setdefault("status", None)
        kwargs.setdefault("code", "connection_error")
        super().__init__(message, **kwargs)
