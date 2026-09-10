"""
secret_broker._ws_client — Minimal WebSocket client (stdlib only).
Implements RFC 6455 text/binary frames + ping/pong + close.
No external deps.

NOTE: This is sufficient for broker /ws subscriptions.
For production high-throughput usage, install `websockets` (optional).
"""
from __future__ import annotations

import asyncio
import base64
import json
import os
import secrets
import socket
import ssl
import struct
import urllib.parse
from typing import Any, Dict, Optional


class WSError(Exception):
    pass


class WSConnection:
    """Minimal WebSocket client. Created by `connect()`."""
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self._reader = reader
        self._writer = writer

    async def send_json(self, obj: Any) -> None:
        data = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        await self._send_frame(0x1, data)  # 0x1 = text

    async def recv_json(self) -> Any:
        frame = await self._recv_frame()
        if frame is None:
            return None
        op, data = frame
        if op == 0x8:  # close
            return None
        if op == 0x9:  # ping
            await self._send_frame(0xA, data)  # pong
            return await self.recv_json()
        if op == 0xA:  # pong
            return await self.recv_json()
        if op in (0x1, 0x2):
            return json.loads(data.decode("utf-8"))
        return None

    async def close(self) -> None:
        try:
            await self._send_frame(0x8, b"")
        except Exception:
            pass
        try:
            self._writer.close()
            await self._writer.wait_closed()
        except Exception:
            pass

    async def _send_frame(self, opcode: int, data: bytes) -> None:
        header = bytes([0x80 | opcode])  # FIN=1
        ln = len(data)
        if ln < 126:
            header += bytes([ln])
        elif ln < 65536:
            header += bytes([126]) + struct.pack(">H", ln)
        else:
            header += bytes([127]) + struct.pack(">Q", ln)
        mask = secrets.token_bytes(4)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
        self._writer.write(header + mask + masked)
        await self._writer.drain()

    async def _recv_exact(self, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = await self._reader.read(n - len(buf))
            if not chunk:
                raise WSError("connection closed")
            buf += chunk
        return buf

    async def _recv_frame(self) -> Optional[tuple]:
        hdr = await self._recv_exact(2)
        b1, b2 = hdr[0], hdr[1]
        fin = b1 & 0x80
        op = b1 & 0x0F
        masked = b2 & 0x80
        ln = b2 & 0x7F
        if ln == 126:
            ln = struct.unpack(">H", await self._recv_exact(2))[0]
        elif ln == 127:
            ln = struct.unpack(">Q", await self._recv_exact(8))[0]
        mask_key = await self._recv_exact(4) if masked else None
        data = await self._recv_exact(ln) if ln > 0 else b""
        if mask_key:
            data = bytes(b ^ mask_key[i % 4] for i, b in enumerate(data))
        if op == 0x8:  # close
            return (op, data)
        return (op, data)


async def connect(endpoint: str, path: str, ssl_ctx: ssl.SSLContext, session_cookie: Optional[str], timeout: float) -> WSConnection:
    """Open a WebSocket connection to wss://host:port/path."""
    u = urllib.parse.urlparse(endpoint)
    host = u.hostname
    port = u.port or 443
    if path.startswith("/"):
        path = path[1:]
    # 1. TCP + TLS
    reader, writer = await asyncio.open_connection(host=host, port=port, ssl=ssl_ctx)
    # 2. HTTP Upgrade
    key = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
    req_lines = [
        f"GET /{path} HTTP/1.1",
        f"Host: {host}:{port}",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Key: {key}",
        "Sec-WebSocket-Version: 13",
        "User-Agent: secret-broker-py/4.2.0",
    ]
    if session_cookie:
        req_lines.append(f"Cookie: broker_session={session_cookie}")
    req_lines.append("", "")
    writer.write("\r\n".join(req_lines).encode("ascii"))
    await writer.drain()
    # 3. Read response
    status_line = await reader.readline()
    if not status_line:
        raise WSError("no response from server")
    parts = status_line.decode("ascii", errors="replace").rstrip("\r\n").split(" ", 2)
    if len(parts) < 2 or parts[1] != "101":
        raise WSError(f"upgrade failed: {status_line!r}")
    # 4. Drain headers
    while True:
        line = await reader.readline()
        if line in (b"\r\n", b"\n", b""):
            break
    return WSConnection(reader, writer)
