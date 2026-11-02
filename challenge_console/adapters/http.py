"""Bounded, GET-only HTTP for health endpoints and the NetBox read API.

There is deliberately no method parameter: this module cannot send POST / PUT / PATCH / DELETE.  Failures become fixed codes; the
URL, headers and exception text are never returned (a header can carry a token).
"""

from __future__ import annotations

import json
import socket
import ssl
import time
from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener

DEFAULT_MAX_BYTES = 262_144


@dataclass(frozen=True)
class HttpResult:
    status: int | None              # None when no HTTP response was received
    body: bytes = b""
    elapsed_ms: float | None = None
    error: str = ""                 # "" / TIMEOUT / CONNECTION_REFUSED / TLS_ERROR / UNREACHABLE / RESPONSE_TOO_LARGE / INVALID_URL

    @property
    def ok(self) -> bool:
        return self.status is not None and 200 <= self.status < 300 and not self.error

    def json(self):
        try:
            return json.loads(self.body.decode("utf-8"))
        except (ValueError, UnicodeError):
            return None


def get(url: str, *, timeout: float = 4.0, headers: dict | None = None, verify_tls: bool = True,
        max_bytes: int = DEFAULT_MAX_BYTES) -> HttpResult:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password:
        return HttpResult(None, error="INVALID_URL")
    handlers = [ProxyHandler({})]
    if parts.scheme == "https" and not verify_tls:   # lab services use self-signed certificates; this is a liveness read, not a trust decision
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        handlers.append(HTTPSHandler(context=context))
    request = Request(url, headers={"Accept": "application/json", **(headers or {})}, method="GET")
    started = time.monotonic()
    try:
        with build_opener(*handlers).open(request, timeout=timeout) as response:
            body = response.read(max_bytes + 1)
            status = response.status
    except HTTPError as exc:
        return HttpResult(exc.code, elapsed_ms=(time.monotonic() - started) * 1000.0)
    except URLError as exc:
        return HttpResult(None, error=_classify(exc.reason))
    except (TimeoutError, socket.timeout):
        return HttpResult(None, error="TIMEOUT")
    except (OSError, ValueError) as exc:
        return HttpResult(None, error=_classify(exc))
    elapsed = (time.monotonic() - started) * 1000.0
    if len(body) > max_bytes:
        return HttpResult(status, elapsed_ms=elapsed, error="RESPONSE_TOO_LARGE")
    return HttpResult(status, body=body, elapsed_ms=elapsed)


def _classify(reason) -> str:
    if isinstance(reason, (TimeoutError, socket.timeout)):
        return "TIMEOUT"
    if isinstance(reason, ConnectionRefusedError):
        return "CONNECTION_REFUSED"
    if isinstance(reason, ssl.SSLError):
        return "TLS_ERROR"
    return "UNREACHABLE"
