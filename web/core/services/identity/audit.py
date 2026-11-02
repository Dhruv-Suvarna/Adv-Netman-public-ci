"""Website request / identity audit -- written into the ONE existing AuditEvent ledger.

Policy (deliberate, not "log everything"):

* identity events: login success / failure / throttled, logout, website-MFA enroll / verify / fail / reset;
* every state-changing request (POST/PUT/PATCH/DELETE) on an NMAS route -> WEB_ACTION, with its action category;
* every GET on a SENSITIVE_READ route (exports, reports, running-config, credential status) -> SENSITIVE_READ;
* every refusal (anonymous / no permission / wrong method / unknown route) -> ACCESS_DENIED;
* NEVER: static assets, ordinary read-only page views, request bodies, cookies, header values, passwords or OTPs.

Only field NAMES of a submitted form are kept (values never), route kwargs (object ids) and a redacted query string.
Domain events written by services keep their own richer semantics; they are correlated to the request through
core.services.identity.context rather than duplicated here.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
import uuid
from datetime import timedelta

from django.conf import settings
from django.utils import timezone

from ... import models
from .. import secret_policy
from . import context as audit_context

REQUEST_ID_HEADER = "HTTP_X_REQUEST_ID"
_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{8,64}$")

OUTCOME_SUCCESS = "SUCCESS"
OUTCOME_FAILURE = "FAILURE"
OUTCOME_DENIED = "DENIED"


def new_request_id(request) -> str:
    """Reuse a well-formed upstream X-Request-ID (Apache / Cloudflare correlation) or mint one."""
    supplied = request.META.get(REQUEST_ID_HEADER, "")
    return supplied if _REQUEST_ID_RE.match(supplied) else uuid.uuid4().hex


def source_ip(request) -> str | None:
    """The client address.  X-Forwarded-For is trusted ONLY when the direct peer is a configured local proxy."""
    remote = request.META.get("REMOTE_ADDR", "")
    trusted = set(getattr(settings, "NMAS_TRUSTED_PROXY_IPS", ()))
    if remote in trusted:
        forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
        if forwarded:
            remote = forwarded.split(",")[0].strip()
    try:
        return str(ipaddress.ip_address(remote))
    except ValueError:
        return None


def session_fingerprint(request) -> str:
    """A privacy-preserving session correlator: a truncated HMAC-like digest, never the session key itself."""
    key = getattr(getattr(request, "session", None), "session_key", None) or ""
    if not key:
        return ""
    return hashlib.sha256(f"{settings.SECRET_KEY}:{key}".encode()).hexdigest()[:16]


def username_of(user) -> str:
    return user.get_username() if user is not None and getattr(user, "is_authenticated", False) else ""


def actor_for(request) -> str:
    """The acting principal for a browser-originated action: the authenticated username (never a hard-coded label)."""
    name = username_of(getattr(request, "user", None))
    if not name:
        # The middleware guarantees authentication before any view runs; reaching here is a programming error.
        raise PermissionError("No authenticated website user for this action.")
    return name


def build_context(request, route: str) -> audit_context.RequestAuditContext:
    user = getattr(request, "user", None)
    authenticated = bool(user is not None and user.is_authenticated)
    return audit_context.RequestAuditContext(
        request_id=getattr(request, "nmas_request_id", "") or new_request_id(request),
        user_id=user.pk if authenticated else None,
        username=username_of(user),
        http_method=(request.method or "")[:8],
        route=route[:128],
        source_ip=source_ip(request),
        user_agent=request.META.get("HTTP_USER_AGENT", "")[:255],
    )


def request_details(request) -> dict:
    """Redacted, value-free description of what was submitted."""
    details: dict = {"path": request.path[:255]}
    match = getattr(request, "resolver_match", None)
    if match is not None and match.kwargs:
        details["object"] = secret_policy.redact({k: str(v) for k, v in match.kwargs.items()}, max_string=128)
    if request.GET:
        details["query"] = secret_policy.redact({k: request.GET.get(k, "") for k in list(request.GET)[:20]}, max_string=128)
    if request.method not in ("GET", "HEAD") and request.POST:
        details["fields"] = sorted(k for k in request.POST.keys() if not secret_policy.is_secret_key(k))[:40]
        hidden = sum(1 for k in request.POST.keys() if secret_policy.is_secret_key(k))
        if hidden:
            details["redacted_fields"] = hidden
    fingerprint = session_fingerprint(request)
    if fingerprint:
        details["session"] = fingerprint
    return details


def record(event_type: str, summary: str, *, request=None, user=None, actor: str = "", outcome: str = "",
           status_code: int | None = None, route: str = "", metadata: dict | None = None,
           object_type: str = "", object_id: str = "", change=None) -> models.AuditEvent:
    """Write one redacted website audit event.  Request fields are filled from ``request`` when given (the pre_save
    context receiver fills the rest for requests already bound by the middleware)."""
    meta = secret_policy.redact(metadata or {})
    fields: dict = {
        "event_type": event_type, "summary": summary[:255], "metadata": meta, "outcome": outcome[:16],
        "status_code": status_code, "object_type": object_type[:64], "object_id": str(object_id)[:64], "change": change,
    }
    if user is None and request is not None:
        candidate = getattr(request, "user", None)
        user = candidate if candidate is not None and candidate.is_authenticated else None
    if user is not None and getattr(user, "is_authenticated", False):
        fields["actor_user"] = user
    fields["actor"] = (actor or username_of(user))[:150]
    if request is not None:
        fields.update(
            request_id=getattr(request, "nmas_request_id", "") or "",
            http_method=(request.method or "")[:8],
            route=(route or _route_name(request))[:128],
            source_ip=source_ip(request),
            user_agent=request.META.get("HTTP_USER_AGENT", "")[:255],
        )
    elif route:
        fields["route"] = route[:128]
    return models.AuditEvent.objects.create(**fields)


def _route_name(request) -> str:
    match = getattr(request, "resolver_match", None)
    return (match.view_name or "") if match is not None else ""


# --- login throttling (durable: counted from the audit ledger itself, so it holds across Gunicorn workers) ---------

def login_throttled(username: str, ip: str | None) -> bool:
    window = timezone.now() - timedelta(seconds=settings.NMAS_LOGIN_FAILURE_WINDOW_SECONDS)
    recent = models.AuditEvent.objects.filter(event_type=models.AuditEventType.AUTH_LOGIN_FAILED, created_at__gte=window)
    by_user = recent.filter(metadata__attempted_username=username[:150].lower()).count() if username else 0
    by_ip = recent.filter(source_ip=ip).count() if ip else 0
    limit = settings.NMAS_LOGIN_FAILURE_LIMIT
    return by_user >= limit or by_ip >= limit * 3
