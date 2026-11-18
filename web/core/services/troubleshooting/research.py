"""Constrained public-document retrieval for Troubleshooter investigations.

Research is deliberately not a device-management transport.  The broker only
performs bounded HTTPS GET/HEAD requests to an operator-curated hostname set.
It resolves and validates every address twice, connects to a validated IP
literal, verifies TLS for the original hostname, and repeats the complete
decision for every redirect.  Proxy environment variables are never used.

Returned bytes are labelled untrusted external content.  Nothing in this
module writes a file, invokes a shell, imports downloaded code, supplies
credentials, or changes target authorization.
"""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import socket
import ssl
from dataclasses import dataclass
from typing import Callable, Iterable, Mapping
from urllib.parse import parse_qsl, urljoin, urlsplit


class ResearchRefused(RuntimeError):
    def __init__(self, code: str, message: str = ""):
        self.code = code
        super().__init__(f"{code}: {message}" if message else code)


@dataclass(frozen=True)
class ResearchResult:
    url: str
    status: int
    content_type: str
    body: str
    sha256: str
    bytes_read: int
    untrusted_external_content: bool = True


_BLOCKED = tuple(ipaddress.ip_network(v) for v in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
    "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15",
    "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
    "::/128", "::1/128", "::ffff:0:0/96", "64:ff9b::/96", "100::/64",
    "2001:db8::/32", "2001:10::/28", "2002::/16", "fc00::/7",
    "fe80::/10", "ff00::/8",
))
_SECRET_QUERY_PARTS = ("token", "key", "secret", "password", "passwd", "credential", "signature", "sig", "auth")
_TEXT_TYPES = frozenset({"text/plain", "text/html", "text/markdown", "text/csv", "application/json",
                         "application/xml", "application/xhtml+xml", "application/problem+json"})
_EXECUTABLE_TYPES = frozenset({"application/javascript", "application/x-javascript", "application/wasm",
                               "application/x-executable", "application/x-sharedlib", "text/javascript",
                               "text/x-python", "text/x-shellscript"})


def _canonical_ip(value: str) -> ipaddress._BaseAddress:
    ip = ipaddress.ip_address(value)
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip


def _public(value: str) -> bool:
    ip = _canonical_ip(value)
    return bool(ip.is_global and not any(ip in network for network in _BLOCKED))


def system_resolver(host: str, families: Iterable[int] = (socket.AF_INET, socket.AF_INET6)) -> tuple[str, ...]:
    """Resolve only address families present in the reviewed destination set.

    A disabled/unapproved family is not a connection candidate. Querying it and
    then treating its answers as candidates would make an IPv4-only policy
    unusable whenever an otherwise-approved hostname also publishes AAAA.
    """
    answers = {row[4][0] for family in families
               for row in socket.getaddrinfo(host, 443, family=family, type=socket.SOCK_STREAM)}
    return tuple(sorted(answers))


class _PinnedHTTPS:
    """One request over TLS connected to an already-authorized IP literal."""

    def __init__(self, *, timeout: float, context: ssl.SSLContext | None = None):
        self.timeout = timeout
        self.context = context or ssl.create_default_context()

    def request(self, *, host: str, ip: str, method: str, target: str, max_bytes: int) -> tuple[int, dict[str, str], bytes]:
        raw = socket.create_connection((ip, 443), timeout=self.timeout)
        tls = None
        try:
            tls = self.context.wrap_socket(raw, server_hostname=host)
            raw = None
            request = (f"{method} {target} HTTP/1.1\r\nHost: {host}\r\n"
                       "User-Agent: NMAS-Research-Broker/1\r\nAccept: text/html,text/plain,application/json,application/xml;q=0.8\r\n"
                       "Accept-Encoding: identity\r\nConnection: close\r\n\r\n").encode("ascii")
            tls.sendall(request)
            response = http.client.HTTPResponse(tls)
            response.begin()
            headers = {k.lower(): v for k, v in response.getheaders()}
            declared = headers.get("content-length")
            if declared and int(declared) > max_bytes:
                raise ResearchRefused("RESPONSE_TOO_LARGE", "declared response exceeds broker limit")
            body = response.read(max_bytes + 1) if method == "GET" else b""
            if len(body) > max_bytes:
                raise ResearchRefused("RESPONSE_TOO_LARGE", "response exceeds broker limit")
            return response.status, headers, body
        finally:
            if tls is not None:
                tls.close()
            if raw is not None:
                raw.close()


class ResearchBroker:
    """Fetch curated public documentation without exposing a general HTTP client."""

    def __init__(self, *, allowed_destinations: Mapping[str, Iterable[str]],
                 resolver: Callable[[str], Iterable[str]] = system_resolver,
                 transport=None, timeout: float = 8.0, max_bytes: int = 262_144, max_redirects: int = 3,
                 audit: Callable[[dict], None] | None = None):
        destinations = {}
        for raw_host, raw_addresses in (allowed_destinations or {}).items():
            host = str(raw_host).lower().rstrip(".")
            if not host or "/" in host or ":" in host:
                raise ValueError("research destination hostnames must be exact DNS names")
            try:
                addresses = frozenset(str(_canonical_ip(value)) for value in raw_addresses)
            except ValueError as exc:
                raise ValueError("research destination addresses must be literal IP addresses") from exc
            if not addresses or any(not _public(value) for value in addresses):
                raise ValueError("every research hostname needs a non-empty public IP allowlist")
            destinations[host] = addresses
        if not destinations:
            raise ValueError("an explicit non-empty research hostname and IP allowlist is required")
        self.allowed_destinations = destinations
        self.allowed_hosts = frozenset(destinations)
        if not 1024 <= int(max_bytes) <= 2_000_000:
            raise ValueError("max_bytes must be 1024..2000000")
        if not 0 <= int(max_redirects) <= 5:
            raise ValueError("max_redirects must be 0..5")
        self.resolver, self.transport = resolver, transport or _PinnedHTTPS(timeout=float(timeout))
        self.max_bytes, self.max_redirects = int(max_bytes), int(max_redirects)
        self.audit = audit or (lambda _event: None)

    def _resolve(self, host: str) -> Iterable[str]:
        if self.resolver is system_resolver:
            versions = {ipaddress.ip_address(value).version for value in self.allowed_destinations[host]}
            families = tuple(family for version, family in ((4, socket.AF_INET), (6, socket.AF_INET6)) if version in versions)
            return system_resolver(host, families)
        return self.resolver(host)

    def _event(self, *, principal: str, purpose: str, url: str, decision: str, result: str = "") -> None:
        parsed = urlsplit(url)
        self.audit({"event": "research_egress", "principal": principal[:96], "purpose": purpose[:160],
                    "destination": f"{parsed.scheme}://{parsed.hostname or ''}{parsed.path[:256]}",
                    "decision": decision, "result": result[:80]})

    def _validate_url(self, url: str) -> tuple[str, str]:
        try:
            parsed = urlsplit(url)
            port = parsed.port
        except ValueError as exc:
            raise ResearchRefused("INVALID_URL", "invalid port or authority") from exc
        host = (parsed.hostname or "").lower().rstrip(".")
        if parsed.scheme.lower() != "https" or not host or port not in (None, 443):
            raise ResearchRefused("DESTINATION_REFUSED", "HTTPS on port 443 is required")
        if parsed.username is not None or parsed.password is not None or parsed.fragment:
            raise ResearchRefused("INVALID_URL", "userinfo and fragments are forbidden")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            raise ResearchRefused("DESTINATION_REFUSED", "IP-literal URLs are forbidden")
        if host not in self.allowed_hosts:
            raise ResearchRefused("DESTINATION_REFUSED", "hostname is not in the operator-curated research set")
        for key, _value in parse_qsl(parsed.query, keep_blank_values=True):
            lowered = key.lower()
            if any(lowered == part or lowered.startswith(part + "_") or lowered.endswith("_" + part)
                   for part in _SECRET_QUERY_PARTS):
                raise ResearchRefused("CREDENTIAL_MATERIAL_REFUSED", "credential-like query parameter")
        target = parsed.path or "/"
        if parsed.query:
            target += "?" + parsed.query
        return host, target

    def _pin(self, host: str) -> str:
        first = {_canonical_ip(v) for v in self._resolve(host)}
        second = {_canonical_ip(v) for v in self._resolve(host)}
        if not first or not second or first != second:
            raise ResearchRefused("DNS_CHANGED", "DNS answers changed before connection")
        if any(not _public(str(ip)) for ip in first):
            raise ResearchRefused("NON_PUBLIC_DESTINATION", "DNS returned a blocked or non-public address")
        approved = {_canonical_ip(v) for v in self.allowed_destinations[host]}
        if not first.issubset(approved):
            raise ResearchRefused("DNS_ADDRESS_NOT_APPROVED", "DNS returned an address outside the reviewed destination set")
        return str(sorted(first, key=lambda v: (v.version, int(v)))[0])

    def fetch(self, url: str, *, purpose: str, principal: str, method: str = "GET") -> ResearchResult:
        if method not in {"GET", "HEAD"}:
            raise ResearchRefused("METHOD_REFUSED", "only GET and HEAD are permitted")
        if not isinstance(purpose, str) or not 8 <= len(purpose.strip()) <= 300:
            raise ResearchRefused("PURPOSE_REQUIRED", "a bounded troubleshooting purpose is required")
        current = str(url)
        for redirects in range(self.max_redirects + 1):
            try:
                host, target = self._validate_url(current)
                pinned = self._pin(host)
                status, headers, body = self.transport.request(host=host, ip=pinned, method=method,
                                                                target=target, max_bytes=self.max_bytes)
                declared = headers.get("content-length")
                if declared and int(declared) > self.max_bytes:
                    raise ResearchRefused("RESPONSE_TOO_LARGE", "declared response exceeds broker limit")
                if len(body) > self.max_bytes:
                    raise ResearchRefused("RESPONSE_TOO_LARGE", "response exceeds broker limit")
                if status in {301, 302, 303, 307, 308}:
                    location = headers.get("location", "")
                    if not location or redirects >= self.max_redirects:
                        raise ResearchRefused("REDIRECT_REFUSED", "redirect limit or missing location")
                    current = urljoin(current, location)
                    continue
                if not 200 <= status < 300:
                    raise ResearchRefused("UPSTREAM_STATUS", f"public documentation returned HTTP {status}")
                content_type = headers.get("content-type", "").split(";", 1)[0].strip().lower()
                disposition = headers.get("content-disposition", "").lower()
                if method == "GET" and (content_type in _EXECUTABLE_TYPES or "attachment" in disposition):
                    raise ResearchRefused("EXECUTABLE_CONTENT_REFUSED", "downloadable or executable content is forbidden")
                if method == "GET" and content_type not in _TEXT_TYPES:
                    raise ResearchRefused("CONTENT_TYPE_REFUSED", "only textual documentation is accepted")
                text = body.decode("utf-8", errors="replace")
                result = ResearchResult(current, status, content_type, text, hashlib.sha256(body).hexdigest(), len(body))
                self._event(principal=principal, purpose=purpose, url=current, decision="ALLOWED", result=str(status))
                return result
            except ResearchRefused as exc:
                self._event(principal=principal, purpose=purpose, url=current, decision="DENIED", result=exc.code)
                raise
            except Exception as exc:
                self._event(principal=principal, purpose=purpose, url=current, decision="FAILED", result=type(exc).__name__)
                raise ResearchRefused("FETCH_FAILED", type(exc).__name__) from exc
        raise ResearchRefused("REDIRECT_REFUSED")


def broker_from_settings() -> ResearchBroker:
    """Django deployment factory; empty allowlist is intentionally unusable."""
    from django.conf import settings
    cfg = getattr(settings, "NMAS_TS_RESEARCH", {}) or {}
    if not isinstance(cfg, dict):
        raise ValueError("NMAS_TS_RESEARCH must be a mapping")
    return ResearchBroker(allowed_destinations=cfg.get("allowed_destinations", {}), timeout=cfg.get("timeout", 8),
                          max_bytes=cfg.get("max_bytes", 262_144), max_redirects=cfg.get("max_redirects", 3))
