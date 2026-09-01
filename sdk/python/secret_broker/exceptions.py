"""Typed exceptions raised by secret-broker SDK."""


class BrokerError(Exception):
    """Base exception for all broker errors."""
    def __init__(self, message, status=None, body=None, code=None):
        super().__init__(message)
        self.status = status
        self.body = body
        self.code = code


class BrokerAuthError(BrokerError):
    """401 / 403 — authentication or permission failure."""


class BrokerNotFoundError(BrokerError):
    """404 — resource not found."""


class BrokerPermissionError(BrokerAuthError):
    """403 — caller is authenticated but lacks permission."""


class BrokerRateLimitError(BrokerError):
    """429 — caller is being rate-limited."""


class BrokerServerError(BrokerError):
    """5xx — server-side failure."""


class BrokerConnectionError(BrokerError):
    """Network / TLS / timeout — failure to reach broker."""
