"""
secret-broker: Official Python SDK for Secret Broker V4
Zero new hard deps: stdlib ssl + urllib + json only.
Compatible with Python 3.9+.
"""
from .client import (
    BrokerClient,
    WorkloadIdentity,
    AsyncBrokerClient,
    __version__,
)
from .exceptions import (
    BrokerError,
    BrokerAuthError,
    BrokerNotFoundError,
    BrokerPermissionError,
    BrokerRateLimitError,
    BrokerServerError,
    BrokerConnectionError,
)

__version__ = "4.1.1"
__all__ = [
    "BrokerClient",
    "AsyncBrokerClient",
    "WorkloadIdentity",
    "BrokerError",
    "BrokerAuthError",
    "BrokerNotFoundError",
    "BrokerPermissionError",
    "BrokerRateLimitError",
    "BrokerServerError",
    "BrokerConnectionError",
    "__version__",
]
