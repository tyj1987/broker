"""
secret_broker.client — sync + async mTLS client for Secret Broker V4.

Zero hard dependencies: stdlib only (ssl, urllib, asyncio).
Compatible with Python 3.9+.

8 calling surfaces:
  1. get_secret(name) / list_secrets()
  2. resolve_secrets(names) — bulk + env-var binding
  3. proxy(service, method, path, body?, query?)
  4. exec(env_names, command, args) — spawn subprocess with secrets in env
  5. ssh_exec / ssh_tunnel — broker-side SSH proxy
  6. workload_identity(provider, oidc_token, opts) — K8s/ECS/GKE STS
  7. login(username, password, mfa_token?, mfa_code?) — session cookie
  8. subscribe_ws(events) — async WS event stream
"""
from __future__ import annotations

import asyncio
import json
import os
import socket
import ssl
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from http.cookies import SimpleCookie
import uuid
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union

from .exceptions import (
    BrokerAuthError,
    BrokerConnectionError,
    BrokerError,
    BrokerNotFoundError,
    BrokerPermissionError,
    BrokerRateLimitError,
    BrokerServerError,
)

__version__ = "4.2.0"

# ============================================================
# 凭据零接触: redact 任何错误消息
# ============================================================
_REDACT_PATTERNS = [
    # bearer / basic / value=...
    (r'(?i)(authorization\s*:\s*)\S+', r'\1[REDACTED]'),
    (r'(?i)(x-api-key\s*:\s*)\S+', r'\1[REDACTED]'),
    (r'(?i)(token\s*=\s*)\S+', r'\1[REDACTED]'),
    (r'(?i)(password\s*=\s*)\S+', r'\1[REDACTED]'),
    (r'\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b', '[REDACTED_GITHUB]'),
    (r'\bsk-[A-Za-z0-9]{20,}\b', '[REDACTED_OPENAI]'),
    (r'\bsk-ant-[A-Za-z0-9_\-]{20,}\b', '[REDACTED_ANTHROPIC]'),
    (r'\bAKIA[A-Z0-9]{12,}\b', '[REDACTED_AWS]'),
    (r'\bASIA[A-Z0-9]{12,}\b', '[REDACTED_AWS_STS]'),
    (r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}', '[REDACTED_JWT]'),
]

import re
_REDACT_RE = [(re.compile(p), r) for p, r in _REDACT_PATTERNS]


def _redact(s: str) -> str:
    if not s:
        return s
    for rx, repl in _REDACT_RE:
        s = rx.sub(repl, s)
    return s


# ============================================================
# WorkloadIdentity
# ============================================================
class WorkloadIdentity:
    """Represents a workload identity binding (K8s SA / ECS task / GKE SA).

    Constructed from cluster metadata or env vars. The SDK reads the OIDC
    token and lets the broker exchange it for short-lived STS credentials.
    """
    K8S = "k8s"
    ECS = "ecs"
    GKE = "gke"
    GENERIC = "generic"

    def __init__(
        self,
        provider: str,
        role_arn: str,
        token_path: Optional[str] = None,
        audience: Optional[str] = None,
        session_name: Optional[str] = None,
    ):
        if provider not in (self.K8S, self.ECS, self.GKE, self.GENERIC):
            raise ValueError(f"unknown workload identity provider: {provider}")
        self.provider = provider
        self.role_arn = role_arn
        self.audience = audience
        self.session_name = session_name or f"broker-{uuid.uuid4().hex[:8]}"
        if token_path:
            self._explicit_token_path = token_path
        elif provider == self.K8S:
            self._explicit_token_path = "/var/run/secrets/tokens/broker-oidc"
        else:
            self._explicit_token_path = None

    def token(self) -> str:
        """Read the projected SA token. Raises BrokerConnectionError if not found."""
        # 1. Explicit path
        if self._explicit_token_path and os.path.isfile(self._explicit_token_path):
            with open(self._explicit_token_path, "r", encoding="utf-8") as f:
                return f.read().strip()
        # 2. AWS_WEB_IDENTITY_TOKEN_FILE (EKS / IRSA)
        aws_path = os.environ.get("AWS_WEB_IDENTITY_TOKEN_FILE")
        if aws_path and os.path.isfile(aws_path):
            with open(aws_path, "r", encoding="utf-8") as f:
                return f.read().strip()
        # 3. GCP: read from metadata server (not implemented in SDK to keep stdlib-only;
        #    deployers should mount the token file)
        # 4. ECS: relative path
        ecs_path = os.environ.get("ECS_CONTAINER_METADATA_FILE") or ""
        if ecs_path and os.path.isfile(ecs_path):
            try:
                with open(ecs_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                return data.get("CredentialProviders", [{}])[0].get("Credentials", "")
            except (json.JSONDecodeError, IndexError, KeyError):
                pass
        raise BrokerConnectionError(
            f"no projected token found for {self.provider} workload identity"
        )


# ============================================================
# BrokerClient
# ============================================================
class BrokerClient:
    """Synchronous mTLS client for Secret Broker V4.

    Example:
        >>> c = BrokerClient(
        ...     endpoint="https://broker.example.com:8443",
        ...     client_cert="client.crt", client_key="client.key",
        ...     ca_cert="ca.crt",
        ... )
        >>> token = c.get_secret("github.pat")
        >>> c.proxy("github", "GET", "/repos/owner/repo")
    """

    def __init__(
        self,
        endpoint: str,
        client_cert: Optional[str] = None,
        client_key: Optional[str] = None,
        ca_cert: Optional[str] = None,
        ca_key: Optional[str] = None,
        verify: bool = True,
        timeout: float = 30.0,
        workload_identity: Optional[WorkloadIdentity] = None,
    ):
        if not endpoint:
            raise ValueError("endpoint required (e.g. https://broker.example.com:8443)")
        if not endpoint.startswith("https://"):
            raise ValueError("endpoint must be https://")
        self.endpoint = endpoint.rstrip("/")
        self.verify = verify
        self.timeout = timeout
        self.workload_identity = workload_identity
        self._session_cookie: Optional[str] = None
        self._ctx = self._build_ssl_context(client_cert, client_key, ca_cert, ca_key, verify)
        # PKI ops
        self._ca_cert = ca_cert
        self._ca_key = ca_key

    # ------------------------------------------------------------------
    # TLS
    # ------------------------------------------------------------------
    @staticmethod
    def _build_ssl_context(client_cert, client_key, ca_cert, ca_key, verify):
        # Client cert/key (mTLS)
        if client_cert and client_key:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        else:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        # Minimum TLS 1.2
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        if verify and ca_cert:
            ctx.load_verify_locations(ca_cert)
            ctx.verify_mode = ssl.CERT_REQUIRED
        elif verify:
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
        else:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        if client_cert and client_key:
            try:
                ctx.load_cert_chain(client_cert, keyfile=client_key)
            except FileNotFoundError as e:
                raise BrokerConnectionError(f"client cert/key not found: {e}")
        return ctx

    # ------------------------------------------------------------------
    # HTTP core
    # ------------------------------------------------------------------
    def _request(
        self,
        method: str,
        path: str,
        body: Optional[Mapping[str, Any]] = None,
        query: Optional[Mapping[str, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
        timeout: Optional[float] = None,
    ) -> Tuple[int, Any]:
        url = self.endpoint + path
        if query:
            url += "?" + urllib.parse.urlencode({k: v for k, v in query.items() if v is not None})
        data = None
        hdrs = dict(headers or {})
        if body is not None:
            data = json.dumps(body, separators=(",", ":")).encode("utf-8")
            hdrs.setdefault("content-type", "application/json")
        hdrs.setdefault("accept", "application/json")
        hdrs.setdefault("user-agent", f"secret-broker-py/{__version__}")
        hdrs.setdefault("x-request-id", f"py-{uuid.uuid4().hex}")
        if self._session_cookie:
            hdrs["cookie"] = f"broker_session={self._session_cookie}"
        req = urllib.request.Request(url=url, data=data, method=method.upper(), headers=hdrs)
        try:
            with urllib.request.urlopen(req, timeout=timeout or self.timeout, context=self._ctx) as resp:
                raw = resp.read()
                status = resp.getcode()
                self._capture_session_cookie(resp.headers)
        except urllib.error.HTTPError as e:
            raw = e.read() if e.fp else b""
            status = e.code
            self._capture_session_cookie(e.headers)
        except (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError, OSError) as e:
            raise BrokerConnectionError(f"connection failed: {_redact(str(e))}") from e
        return status, self._parse_body(raw, status)

    def _capture_session_cookie(self, headers: Any) -> None:
        if not headers:
            return
        value = headers.get("Set-Cookie")
        if not value:
            return
        jar = SimpleCookie()
        jar.load(value)
        morsel = jar.get("broker_session")
        if morsel is not None:
            self._session_cookie = morsel.value or None

    @staticmethod
    def _parse_body(raw: bytes, status: int) -> Any:
        if not raw:
            return None
        try:
            return json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return raw.decode("utf-8", errors="replace")

    def _check(self, status: int, body: Any, action: str) -> Any:
        if 200 <= status < 300:
            return body
        msg = ""
        code = None
        if isinstance(body, dict):
            msg = body.get("error") or body.get("message") or ""
            code = body.get("code")
        if not msg:
            msg = f"HTTP {status}"
        msg = _redact(str(msg))
        if status == 401:
            raise BrokerAuthError(msg, status=status, body=body, code=code)
        if status == 403:
            raise BrokerPermissionError(msg, status=status, body=body, code=code)
        if status == 404:
            raise BrokerNotFoundError(msg, status=status, body=body, code=code)
        if status == 429:
            raise BrokerRateLimitError(msg, status=status, body=body, code=code)
        if 500 <= status < 600:
            raise BrokerServerError(msg, status=status, body=body, code=code)
        raise BrokerError(msg, status=status, body=body, code=code)

    # ------------------------------------------------------------------
    # 1. Secrets
    # ------------------------------------------------------------------
    def get_secret(self, name: str, version: Optional[str] = None) -> str:
        """Resolve a single secret. Returns the value (string).

        Note: This is the ONE place where the secret value crosses SDK boundary.
        The caller must use it immediately and not log/store it long-term.
        """
        status, body = self._request("POST", "/api/v1/secrets/resolve", body={"name": name, "version": version})
        self._check(status, body, "get_secret")
        if isinstance(body, dict) and "value" in body:
            return body["value"]
        if isinstance(body, dict) and "values" in body:
            return body["values"]
        raise BrokerError(f"unexpected resolve response: {type(body).__name__}")

    def resolve_secrets(self, names: Sequence[str]) -> Dict[str, str]:
        """Resolve multiple secrets in one call. Returns a dict."""
        if not names:
            return {}
        status, body = self._request("POST", "/api/v1/secrets/resolve_bulk", body={"names": list(names)})
        self._check(status, body, "resolve_secrets")
        if not isinstance(body, dict):
            raise BrokerError("unexpected bulk response")
        return {k: (v if isinstance(v, str) else json.dumps(v)) for k, v in body.get("values", body).items()}

    def list_secrets(self) -> List[Dict[str, Any]]:
        status, body = self._request("GET", "/api/v1/secrets")
        self._check(status, body, "list_secrets")
        if isinstance(body, list):
            return body
        if isinstance(body, dict):
            return body.get("secrets", [])
        return []

    # ------------------------------------------------------------------
    # 2. Proxy
    # ------------------------------------------------------------------
    def proxy(
        self,
        service: str,
        method: str,
        path: str,
        body: Optional[Any] = None,
        query: Optional[Mapping[str, Any]] = None,
        *,
        raise_on_error: bool = True,
    ) -> Tuple[int, Any]:
        sub_path = path if path.startswith("/") else "/" + path
        req_body: Dict[str, Any] = {"method": method.upper(), "path": sub_path}
        if query:
            req_body["query"] = dict(query)
        if body is not None:
            req_body["body"] = body
        status, resp = self._request(
            "POST", f"/api/v1/proxy/{urllib.parse.quote(service, safe='')}", body=req_body
        )
        if raise_on_error:
            self._check(status, resp, "proxy")
        return status, resp

    # ------------------------------------------------------------------
    # V2 typed operations (preferred for automation)
    # ------------------------------------------------------------------
    def create_operation(
        self,
        provider: str,
        operation_id: str,
        account_ref: str,
        environment: str,
        typed_parameters: Mapping[str, Any],
        otp: Optional[Mapping[str, Any]] = None,
        approval_request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a policy-bound operation without exposing a credential."""
        request_body: Dict[str, Any] = {
            "provider": provider,
            "operation_id": operation_id,
            "account_ref": account_ref,
            "environment": environment,
            "typed_parameters": dict(typed_parameters),
        }
        if otp is not None:
            request_body["otp"] = dict(otp)
        if approval_request_id is not None:
            request_body["approval_request_id"] = approval_request_id
        status, body = self._request("POST", "/api/v2/operations", body=request_body)
        self._check(status, body, "create_operation")
        if not isinstance(body, dict):
            raise BrokerError("unexpected operation response")
        return body

    def create_approval(
        self,
        provider: str,
        operation_id: str,
        account_ref: str,
        environment: str,
        typed_parameters: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """Create an approval request bound to an exact typed operation."""
        request_body = {
            "provider": provider,
            "operation_id": operation_id,
            "account_ref": account_ref,
            "environment": environment,
            "typed_parameters": dict(typed_parameters),
        }
        status, body = self._request("POST", "/api/v2/approvals", body=request_body)
        self._check(status, body, "create_approval")
        if not isinstance(body, dict):
            raise BrokerError("unexpected approval response")
        return body

    def list_approvals(self) -> Sequence[Mapping[str, Any]]:
        """List requests visible to the current requester or approver."""
        status, body = self._request("GET", "/api/v2/approvals")
        self._check(status, body, "list_approvals")
        if not isinstance(body, dict) or not isinstance(body.get("approvals"), list):
            raise BrokerError("unexpected approval list response")
        return body["approvals"]

    def decide_approval(self, approval_id: str, decision: str) -> Dict[str, Any]:
        """Approve or reject using an already WebAuthn-stepped-up session."""
        if decision not in ("approve", "reject"):
            raise ValueError("decision must be approve or reject")
        path = f"/api/v2/approvals/{urllib.parse.quote(approval_id, safe='')}/decision"
        status, body = self._request("POST", path, body={"decision": decision})
        self._check(status, body, "decide_approval")
        if not isinstance(body, dict):
            raise BrokerError("unexpected approval response")
        return body

    def get_operation(self, operation_id: str) -> Dict[str, Any]:
        """Read only the redacted result allowed by the operation policy."""
        status, body = self._request(
            "GET", f"/api/v2/operations/{urllib.parse.quote(operation_id, safe='')}"
        )
        self._check(status, body, "get_operation")
        if not isinstance(body, dict):
            raise BrokerError("unexpected operation response")
        return body

    # ------------------------------------------------------------------
    # 3. exec — spawn subprocess with secrets in env
    # ------------------------------------------------------------------
    def exec(
        self,
        env_names: Sequence[str],
        command: Sequence[str],
        *,
        env_passthrough: bool = True,
        cwd: Optional[str] = None,
    ) -> int:
        if not command:
            raise ValueError("command required")
        secrets = self.resolve_secrets(env_names)
        env: Dict[str, str] = os.environ.copy() if env_passthrough else {}
        env.update(secrets)
        result = subprocess.run(list(command), env=env, cwd=cwd)
        return result.returncode

    # ------------------------------------------------------------------
    # 4. SSH proxy
    # ------------------------------------------------------------------
    def ssh_exec(
        self,
        target: str,
        command: str,
        *,
        secret_name: str = "ssh.connection",
        timeout_ms: Optional[int] = None,
    ) -> Dict[str, Any]:
        status, body = self._request("POST", "/api/v1/ssh/exec", body={
            "target": target,
            "command": command,
            "secret_name": secret_name,
            "timeout_ms": timeout_ms,
        })
        self._check(status, body, "ssh_exec")
        return body

    def ssh_tunnel(
        self,
        target: str,
        local_port: int,
        remote_host: str,
        remote_port: int,
        *,
        secret_name: str = "ssh.connection",
    ) -> Dict[str, Any]:
        status, body = self._request("POST", "/api/v1/ssh/tunnel", body={
            "target": target,
            "local_port": local_port,
            "remote_host": remote_host,
            "remote_port": remote_port,
            "secret_name": secret_name,
        })
        self._check(status, body, "ssh_tunnel")
        return body

    def ssh_tunnel_stop(self, tunnel_id: str) -> bool:
        status, body = self._request("POST", "/api/v1/ssh/tunnel/stop", body={"id": tunnel_id})
        self._check(status, body, "ssh_tunnel_stop")
        return True

    # ------------------------------------------------------------------
    # 5. Workload identity
    # ------------------------------------------------------------------
    def assume_workload_identity(
        self,
        provider: str,
        oidc_token: Optional[str] = None,
        role_arn: Optional[str] = None,
        audience: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Exchange an OIDC token for short-lived STS credentials via broker."""
        wi = self.workload_identity
        if oidc_token is None:
            if wi is None:
                raise BrokerError("oidc_token or workload_identity required")
            oidc_token = wi.token()
        if role_arn is None:
            if wi is None:
                raise BrokerError("role_arn or workload_identity required")
            role_arn = wi.role_arn
        if audience is None and wi is not None:
            audience = wi.audience
        status, body = self._request("POST", "/api/v1/workload-identity/assume", body={
            "provider": provider,
            "oidc_token": oidc_token,
            "role_arn": role_arn,
            "audience": audience,
        })
        self._check(status, body, "assume_workload_identity")
        return body

    # ------------------------------------------------------------------
    # 6. Login (password/MFA)
    # ------------------------------------------------------------------
    def login(
        self,
        username: str,
        password: str,
        mfa_token: Optional[str] = None,
        mfa_code: Optional[str] = None,
    ) -> Dict[str, Any]:
        if mfa_token or mfa_code:
            if not mfa_token or not mfa_code:
                raise ValueError("mfa_token and mfa_code must be provided together")
            status, resp = self._request(
                "POST", "/api/v1/login/mfa", body={"mfa_token": mfa_token, "code": mfa_code}
            )
        else:
            status, resp = self._request(
                "POST", "/api/v1/login", body={"client": username, "password": password}
            )
        self._check(status, resp, "login")
        return resp

    def logout(self) -> None:
        if not self._session_cookie:
            return
        try:
            self._request("POST", "/api/v1/logout", body={})
        finally:
            self._session_cookie = None

    # ------------------------------------------------------------------
    # 7. Identity
    # ------------------------------------------------------------------
    def identity(self) -> Dict[str, Any]:
        status, body = self._request("GET", "/api/v1/me")
        self._check(status, body, "identity")
        return body

    def health(self) -> Dict[str, Any]:
        status, body = self._request("GET", "/health")
        self._check(status, body, "health")
        return body

    # ------------------------------------------------------------------
    # 8. WebSocket (async, returns AsyncBrokerClient for this surface)
    # ------------------------------------------------------------------
    def async_client(self) -> "AsyncBrokerClient":
        return AsyncBrokerClient(self.endpoint, ctx=self._ctx, session_cookie=self._session_cookie, timeout=self.timeout)


# ============================================================
# Async (for WebSocket subscription)
# ============================================================
class AsyncBrokerClient:
    """Minimal async surface for WebSocket subscriptions.

    The sync BrokerClient covers 7 of 8 calling surfaces; this thin async
    layer exists for the WebSocket event stream.
    """
    def __init__(self, endpoint, ctx, session_cookie=None, timeout=30.0):
        self.endpoint = endpoint
        self._ctx = ctx
        self._session_cookie = session_cookie
        self._timeout = timeout
        self._ws = None
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None

    async def __aenter__(self) -> "AsyncBrokerClient":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.close()

    async def connect_ws(self, path: str = "/ws") -> "AsyncBrokerClient":
        """Open a WebSocket connection. Requires Python 3.11+ stdlib `websockets` style is NOT used;
        we use a hand-rolled minimal WS client to keep zero hard deps.
        """
        from ._ws_client import connect
        self._ws = await connect(self.endpoint, path, self._ctx, self._session_cookie, self._timeout)
        return self

    async def subscribe(self, events: Sequence[str], filter: Optional[Dict[str, Any]] = None) -> None:
        msg = {"action": "subscribe", "events": list(events)}
        if filter:
            msg["filter"] = filter
        await self._ws.send_json(msg)

    async def recv(self) -> Dict[str, Any]:
        return await self._ws.recv_json()

    async def close(self) -> None:
        if self._ws:
            await self._ws.close()
            self._ws = None


# ============================================================
# Public exports
# ============================================================
__all__ = [
    "BrokerClient",
    "AsyncBrokerClient",
    "WorkloadIdentity",
    "__version__",
]
