"""Identity signal receivers and the AuditEvent request-correlation filler (V2 Phase 1).

Login / logout auditing hangs off Django's own auth signals, so the NMAS login page AND the Django admin login are
covered by the same code path.  The ``pre_save`` receiver stamps every AuditEvent written inside an NMAS request
with the request id and authenticated initiator (see core.services.identity.context).
"""

from __future__ import annotations

from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from django.db.models.signals import pre_save
from django.dispatch import receiver

from .models import AuditEvent, AuditEventType
from .services.identity import audit, mfa
from .services.identity import context as audit_context


@receiver(pre_save, sender=AuditEvent)
def stamp_request_context(sender, instance, **kwargs):
    ctx = audit_context.current()
    if ctx is None or instance.pk:
        return
    if not instance.request_id:
        instance.request_id = ctx.request_id
    if instance.actor_user_id is None and ctx.user_id is not None:
        instance.actor_user_id = ctx.user_id
    if not instance.actor and ctx.username:
        instance.actor = ctx.username
    if not instance.http_method:
        instance.http_method = ctx.http_method
    if not instance.route:
        instance.route = ctx.route
    if instance.source_ip is None:
        instance.source_ip = ctx.source_ip
    if not instance.user_agent:
        instance.user_agent = ctx.user_agent


def _is_http_request(request) -> bool:
    """A website sign-in always arrives as an HTTP request; programmatic logins (test force_login) do not."""
    return request is not None and bool(getattr(request, "method", None))


@receiver(user_logged_in)
def audit_login(sender, request, user, **kwargs):
    if not _is_http_request(request):
        return
    if hasattr(request, "session"):
        # A fresh password login always requires a fresh website-MFA step, even on a reused session.
        request.session.pop(mfa.SESSION_VERIFIED_KEY, None)
    audit.record(AuditEventType.AUTH_LOGIN_SUCCEEDED, f"Login succeeded for {user.get_username()}", request=request,
                 user=user, outcome=audit.OUTCOME_SUCCESS, metadata={"mfa_enrolled": mfa.is_enrolled(user)})


@receiver(user_login_failed)
def audit_login_failure(sender, credentials, request=None, **kwargs):
    attempted = str((credentials or {}).get("username", ""))[:150]
    audit.record(AuditEventType.AUTH_LOGIN_FAILED, "Login failed", request=request, actor=attempted,
                 outcome=audit.OUTCOME_FAILURE, metadata={"attempted_username": attempted.lower()})


@receiver(user_logged_out)
def audit_logout(sender, request, user, **kwargs):
    if not _is_http_request(request):
        return
    name = user.get_username() if user is not None else ""
    audit.record(AuditEventType.AUTH_LOGOUT, f"Logout for {name or 'anonymous session'}", request=request,
                 user=user, outcome=audit.OUTCOME_SUCCESS)
