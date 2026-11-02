"""Per-request audit context (a ContextVar, safe under threads and async).

core.middleware sets it for every routed NMAS request; a ``pre_save`` receiver on AuditEvent (core.signals) copies the
request id and the authenticated initiator onto EVERY audit row written while the request runs -- including the
richer domain events services already write (validation / plan / execution / bundle / soak ...).  Outside a request
(scheduler, collector, management command) the context is empty and nothing is filled in.
"""

from __future__ import annotations

import contextvars
from dataclasses import dataclass


@dataclass(frozen=True)
class RequestAuditContext:
    request_id: str
    user_id: int | None
    username: str
    http_method: str
    route: str
    source_ip: str | None
    user_agent: str


_current: contextvars.ContextVar[RequestAuditContext | None] = contextvars.ContextVar("nmas_request_audit", default=None)


def current() -> RequestAuditContext | None:
    return _current.get()


def bind(ctx: RequestAuditContext):
    return _current.set(ctx)


def reset(token) -> None:
    _current.reset(token)
