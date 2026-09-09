"""
Tests for secret-broker Python SDK.
Run: cd sdk/python && python -m pytest tests/
"""
from __future__ import annotations

import json
import os
import socket
import ssl
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

# Add parent dir to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from secret_broker import (
    AsyncBrokerClient,
    BrokerAuthError,
    BrokerClient,
    BrokerConnectionError,
    BrokerError,
    BrokerNotFoundError,
    BrokerPermissionError,
    BrokerRateLimitError,
    BrokerServerError,
    WorkloadIdentity,
)


# ============================================================
# Mock broker
# ============================================================
class MockBrokerHandler(BaseHTTPRequestHandler):
    routes = {}
    log_level = 0  # 0 = quiet, 1 = verbose

    def log_message(self, format, *args):
        if self.log_level >= 1:
            super().log_message(format, *args)

    def _send_json(self, status, body, headers=None):
        body_bytes = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body_bytes)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body_bytes)

    def _read_body(self):
        n = int(self.headers.get("content-length", "0"))
        if n == 0:
            return {}
        raw = self.rfile.read(n)
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {}

    def do_GET(self):
        if self.path == "/health":
            return self._send_json(200, {"ok": True, "version": "4.1.0"})
        if self.path == "/api/v1/me":
            return self._send_json(200, {"cn": "test-client", "role": "developer"})
        if self.path == "/api/v1/secrets":
            return self._send_json(200, [
                {"name": "github.pat", "type": "github_pat"},
                {"name": "openai.key", "type": "openai_key"},
            ])
        if self.path == "/api/v2/operations/op-123":
            return self._send_json(200, {
                "id": "op-123", "provider": "github", "operation_id": "repo.read", "status": "completed"
            })
        if self.path == "/api/v2/approvals":
            return self._send_json(200, {"approvals": [{"id": "approval-123", "status": "APPROVED"}]})
        if self.path == "/api/v2/tasks/task-123":
            return self._send_json(200, {"id": "task-123", "state": "SUCCEEDED", "result": {"name": "github.repository.read"}})
        if self.path == "/api/v2/tasks/task-123/events":
            return self._send_json(200, {"events": [{"sequence": 1, "state": "REQUESTED", "reason": "task_created"}]})
        return self._send_json(404, {"error": "not found"})

    def do_POST(self):
        body = self._read_body()
        if self.path == "/api/v1/secrets/resolve":
            name = body.get("name", "")
            return self._send_json(200, {"name": name, "value": f"VALUE-FOR-{name}"})
        if self.path == "/api/v1/secrets/resolve_bulk":
            return self._send_json(200, {"values": {n: f"V-{n}" for n in body.get("names", [])}})
        if self.path == "/api/v1/login":
            if body.get("client") == "good" and body.get("password") == "ok":
                return self._send_json(200, {"ok": True}, {
                    "Set-Cookie": "broker_session=sess-abc-123; HttpOnly; Secure; SameSite=Strict; Path=/"
                })
            return self._send_json(401, {"error": "bad credentials"})
        if self.path == "/api/v1/proxy/github":
            path = body.get("path")
            if path == "/forbidden":
                return self._send_json(403, {"error": "denied"})
            if path == "/ratelimit":
                return self._send_json(429, {"error": "too many requests"})
            if path == "/oops":
                return self._send_json(500, {"error": "internal"})
            return self._send_json(200, {"ok": True, "data": [], "request": body})
        if self.path == "/api/v2/operations":
            return self._send_json(202, {
                "id": "op-123", "provider": body.get("provider"),
                "operation_id": body.get("operation_id"), "status": "waiting",
                "request": body,
            })
        if self.path == "/api/v2/approvals":
            return self._send_json(201, {
                "id": "approval-123", "requester": "test-client", "provider": body.get("provider"),
                "operation_id": body.get("operation_id"), "account_ref": body.get("account_ref"),
                "environment": body.get("environment"), "resource_ref": body.get("typed_parameters", {}).get("resource_ref"),
                "required_approvals": 2, "approvals": [], "status": "REQUESTED",
                "created_at": "2026-09-09T00:00:00Z", "expires_at": "2026-09-09T00:05:00Z",
            })
        if self.path == "/api/v2/approvals/approval-123/decision":
            return self._send_json(200, {"id": "approval-123", "status": body.get("decision", "approve") + "d"})
        if self.path == "/api/v2/approvals/approval-123/cancel":
            return self._send_json(200, {"id": "approval-123", "status": "CANCELLED"})
        if self.path == "/api/v2/tasks":
            return self._send_json(202, {"id": "task-123", "tool": body.get("tool"), "state": "READY", "request": body})
        if self.path == "/api/v2/tasks/task-123/run":
            return self._send_json(200, {"id": "task-123", "state": "SUCCEEDED", "result": {"name": "github.repository.read"}})
        if self.path == "/api/v2/tasks/task-123/cancel":
            return self._send_json(200, {"id": "task-123", "state": "CANCELLED"})
        if self.path == "/api/v1/ssh/exec":
            return self._send_json(200, {"ok": True, "exitCode": 0, "stdout": "hello\n", "stderr": "", "duration_ms": 12})
        if self.path == "/api/v1/ssh/tunnel":
            return self._send_json(200, {"ok": True, "id": "t-1", "localPort": 5432, "remote": "db:5432"})
        if self.path == "/api/v1/ssh/tunnel/stop":
            return self._send_json(200, {"ok": True})
        if self.path == "/api/v1/workload-identity/assume":
            return self._send_json(200, {
                "ok": True,
                "provider": body.get("provider"),
                "role": body.get("role_arn"),
                "access_key_id": "STS.xxx",
                "access_key_secret": "STSSECRETxxx",
                "security_token": "TOK",
                "expiration": "2099-01-01T00:00:00Z",
            })
        return self._send_json(404, {"error": "no route"})


def _make_self_signed():
    """Generate ephemeral self-signed cert for HTTPS mock."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    import datetime

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.IPAddress(__import__("ipaddress").IPv4Address("127.0.0.1"))]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    return cert_pem, key_pem


def _start_mock_broker():
    """Spin up an HTTPS mock broker on a random port. Returns (port, server_thread, ca_cert_pem)."""
    import tempfile
    cert_pem, key_pem = _make_self_signed()
    # Write to temp files
    fd_cert, cert_path = tempfile.mkstemp(suffix=".crt")
    fd_key, key_path = tempfile.mkstemp(suffix=".key")
    os.write(fd_cert, cert_pem)
    os.write(fd_key, key_pem)
    os.close(fd_cert)
    os.close(fd_key)

    # Find free port
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()

    httpd = HTTPServer(("127.0.0.1", port), MockBrokerHandler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_path, keyfile=key_path)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return port, cert_path, key_path, httpd


# ============================================================
# Tests
# ============================================================
import pytest


@pytest.fixture(scope="module")
def mock_broker():
    port, cert_path, key_path, httpd = _start_mock_broker()
    yield port, cert_path, key_path
    httpd.shutdown()


def _client(endpoint, ca, cert, key):
    return BrokerClient(endpoint, ca_cert=ca, client_cert=cert, client_key=key)


def test_health(mock_broker):
    port, cert_path, key_path = mock_broker
    c = _client(f"https://127.0.0.1:{port}", cert_path, cert_path, key_path)
    r = c.health()
    assert r["ok"] is True
    assert r["version"] == "4.1.0"


def test_identity(mock_broker):
    port, cert_path, key_path = mock_broker
    c = _client(f"https://127.0.0.1:{port}", cert_path, cert_path, key_path)
    me = c.identity()
    assert me["cn"] == "test-client"
    assert me["role"] == "developer"


def test_list_secrets(mock_broker):
    port, cert_path, key_path = mock_broker
    c = _client(f"https://127.0.0.1:{port}", cert_path, cert_path, key_path)
    items = c.list_secrets()
    assert len(items) == 2
    assert items[0]["name"] == "github.pat"


def test_get_secret(mock_broker):
    port, cert_path, key_path = mock_broker
    c = _client(f"https://127.0.0.1:{port}", cert_path, cert_path, key_path)
    v = c.get_secret("github.pat")
    assert v == "VALUE-FOR-github.pat"


def test_resolve_bulk(mock_broker):
    port, cert_path, key_path = mock_broker
    c = _client(f"https://127.0.0.1:{port}", cert_path, cert_path, key_path)
    out = c.resolve_secrets(["github.pat", "openai.key"])
    assert out == {"github.pat": "V-github.pat", "openai.key": "V-openai.key"}


def test_proxy(mock_broker):
    port, cert_path, key_path = mock_broker
    c = _client(f"https://127.0.0.1:{port}", cert_path, cert_path, key_path)
    status, body = c.proxy("github", "GET", "/repos/owner/repo")
    assert status == 200
    assert body["ok"] is True


def test_typed_operations_accept_202_and_preserve_contract(mock_broker):
    port, cert_path, key_path = mock_broker
    c = _client(f"https://127.0.0.1:{port}", cert_path, cert_path, key_path)
    created = c.create_operation(
        "github", "repo.read", "personal", "development", {"owner": "o", "repo": "r"},
        approval_request_id="approval-123",
    )
    assert created["status"] == "waiting"
    assert created["request"]["typed_parameters"] == {"owner": "o", "repo": "r"}
    assert created["request"]["approval_request_id"] == "approval-123"
    result = c.get_operation("op-123")
    assert result["status"] == "completed"


def test_bound_approval_workflow(mock_broker):
    port, cert_path, key_path = mock_broker
    c = _client(f"https://127.0.0.1:{port}", cert_path, cert_path, key_path)
    approval = c.create_approval(
        "github", "repo.read", "personal", "production", {"resource_ref": "repository"}
    )
    assert approval["status"] == "REQUESTED"
    assert c.list_approvals()[0]["id"] == "approval-123"
    assert c.cancel_approval("approval-123")["status"] == "CANCELLED"
    c._request = lambda *args, **kwargs: pytest.fail("decision attempted a network request")
    with pytest.raises(BrokerError, match="WebAuthn browser workbench"):
        c.decide_approval("approval-123", "approve")
    with pytest.raises(ValueError):
        c.decide_approval("approval-123", "maybe")


def test_automation_task_loop(mock_broker):
    port, cert_path, key_path = mock_broker
    c = _client(f"https://127.0.0.1:{port}", cert_path, cert_path, key_path)
    task = c.create_task(
        "broker.tools.inspect", "1.0.0", "control-plane", "production",
        {"resource_ref": "tool-registry"}, "python-sdk-task-0001",
    )
    assert task["state"] == "READY"
    assert task["request"]["idempotency_key"] == "python-sdk-task-0001"
    assert c.get_task(task["id"])["state"] == "SUCCEEDED"
    assert c.task_events(task["id"])[0]["sequence"] == 1
    assert c.run_task(task["id"])["state"] == "SUCCEEDED"
    assert c.cancel_task(task["id"])["state"] == "CANCELLED"
    with pytest.raises(ValueError):
        c.get_task("")


def test_proxy_403(mock_broker):
    port, cert_path, key_path = mock_broker
    c = _client(f"https://127.0.0.1:{port}", cert_path, cert_path, key_path)
    with pytest.raises(BrokerPermissionError):
        c.proxy("github", "GET", "/forbidden")


def test_proxy_429(mock_broker):
    port, cert_path, key_path = mock_broker
    c = _client(f"https://127.0.0.1:{port}", cert_path, cert_path, key_path)
    with pytest.raises(BrokerRateLimitError):
        c.proxy("github", "GET", "/ratelimit")


def test_proxy_500(mock_broker):
    port, cert_path, key_path = mock_broker
    c = _client(f"https://127.0.0.1:{port}", cert_path, cert_path, key_path)
    with pytest.raises(BrokerServerError):
        c.proxy("github", "GET", "/oops")


def test_login(mock_broker):
    port, cert_path, key_path = mock_broker
    c = _client(f"https://127.0.0.1:{port}", cert_path, cert_path, key_path)
    r = c.login("good", "ok")
    assert r["ok"] is True
    assert c._session_cookie == "sess-abc-123"
    c.logout()
    assert c._session_cookie is None


def test_login_bad_creds(mock_broker):
    port, cert_path, key_path = mock_broker
    c = _client(f"https://127.0.0.1:{port}", cert_path, cert_path, key_path)
    with pytest.raises(BrokerAuthError):
        c.login("bad", "wrong")


def test_ssh_exec(mock_broker):
    port, cert_path, key_path = mock_broker
    c = _client(f"https://127.0.0.1:{port}", cert_path, cert_path, key_path)
    r = c.ssh_exec("app@10.0.1.5", "uptime")
    assert r["exitCode"] == 0
    assert r["stdout"] == "hello\n"


def test_ssh_tunnel(mock_broker):
    port, cert_path, key_path = mock_broker
    c = _client(f"https://127.0.0.1:{port}", cert_path, cert_path, key_path)
    r = c.ssh_tunnel("app@db", 5432, "db.internal", 5432)
    assert r["id"] == "t-1"
    assert r["localPort"] == 5432
    c.ssh_tunnel_stop(r["id"])


def test_assume_workload(mock_broker):
    port, cert_path, key_path = mock_broker
    c = _client(f"https://127.0.0.1:{port}", cert_path, cert_path, key_path)
    creds = c.assume_workload_identity("aliyun", oidc_token="eyJ.fake.jwt", role_arn="acs:ram::1:role/app")
    assert creds["access_key_id"] == "STS.xxx"
    assert creds["access_key_secret"] == "STSSECRETxxx"


def test_assume_workload_with_wi(mock_broker):
    port, cert_path, key_path = mock_broker
    c = BrokerClient(
        f"https://127.0.0.1:{port}", ca_cert=cert_path, client_cert=cert_path, client_key=key_path,
        workload_identity=WorkloadIdentity("k8s", "acs:ram::1:role/app", audience="broker.example.com"),
    )
    creds = c.assume_workload_identity("aliyun", oidc_token="eyJ.fake.jwt")
    assert creds["role"] == "acs:ram::1:role/app"


def test_workload_identity_token_missing(tmp_path):
    wi = WorkloadIdentity("k8s", "acs:ram::1:role/app", token_path=str(tmp_path / "no-such-file"))
    with pytest.raises(BrokerConnectionError):
        wi.token()


def test_workload_identity_token_file(tmp_path):
    tok_path = tmp_path / "sa-token"
    tok_path.write_text("eyJ.fake.jwt", encoding="utf-8")
    wi = WorkloadIdentity("k8s", "acs:ram::1:role/app", token_path=str(tok_path))
    assert wi.token() == "eyJ.fake.jwt"


def test_workload_identity_invalid_provider():
    with pytest.raises(ValueError):
        WorkloadIdentity("azure-aks", "arn:foo")


def test_redact_in_error_message():
    """SDK must scrub credential-like strings in exception messages."""
    from secret_broker.client import _redact
    s = "Authorization: Bearer ghp_xxxxABCDEFGHIJabcdefghij"
    out = _redact(s)
    assert "ghp_" not in out
    assert "REDACTED" in out.upper()


def test_redact_sk():
    from secret_broker.client import _redact
    s = "openai key=sk-abcdefghijklmnopqrstuvwxyz"
    out = _redact(s)
    assert "sk-abcdef" not in out
    assert "REDACTED" in out


def test_redact_aws():
    from secret_broker.client import _redact
    s = "found AKIAIOSFODNN7EXAMPLE in response"
    out = _redact(s)
    assert "AKIAIOSFODNN7EXAMPLE" not in out


def test_redact_jwt():
    from secret_broker.client import _redact
    # JWT pattern requires 3 segments, each 10+ chars
    s = "Authorization: Bearer eyJAbcdefghijklmnop.eyJqrstuvwxyzABCDEFG.eyJqrstuvwxyzABCDEFG signature"
    out = _redact(s)
    assert "eyJAbcdefghijklmnop" not in out
    assert "REDACTED" in out.upper()


def test_invalid_endpoint():
    with pytest.raises(ValueError):
        BrokerClient("http://insecure.example.com")
    with pytest.raises(ValueError):
        BrokerClient("")
    with pytest.raises(ValueError):
        BrokerClient("ftp://nope")


def test_connection_error():
    # Port 1 = privileged + likely closed
    c = BrokerClient("https://127.0.0.1:1", verify=False, timeout=2.0)
    with pytest.raises(BrokerConnectionError):
        c.health()


def test_exec_subprocess():
    """End-to-end test: exec() spawns a subprocess with secrets in env."""
    port, cert_path, key_path = _start_mock_broker_for_test()
    c = BrokerClient(f"https://127.0.0.1:{port}", ca_cert=cert_path, client_cert=cert_path, client_key=key_path)
    if os.name == "nt":
        cmd = ["cmd", "/c", "echo", "token=%github.pat%"]
    else:
        cmd = ["sh", "-c", "echo token=$github.pat"]
    rc = c.exec(["github.pat"], cmd)
    assert rc == 0


def _start_mock_broker_for_test():
    port, cert_path, key_path, httpd = _start_mock_broker()
    return port, cert_path, key_path


def test_async_client_imports():
    """Async client surface exists and is importable."""
    from secret_broker.client import AsyncBrokerClient as A
    assert A is not None


def test_ws_module_imports():
    """_ws_client module is importable (real test would need a WS server)."""
    from secret_broker import _ws_client
    assert hasattr(_ws_client, "WSConnection")
    assert hasattr(_ws_client, "connect")


def test_error_types_hierarchy():
    assert issubclass(BrokerAuthError, BrokerError)
    assert issubclass(BrokerPermissionError, BrokerAuthError)
    assert issubclass(BrokerRateLimitError, BrokerError)
    assert issubclass(BrokerServerError, BrokerError)
    assert issubclass(BrokerConnectionError, BrokerError)
