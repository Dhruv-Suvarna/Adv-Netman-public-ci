"""NmasAccessMiddleware -- the single server-side enforcement point for the NMAS website (V2 Phase 1).

For every routed request it (1) assigns a correlation id (``X-Request-ID``), (2) binds the request audit context so
every AuditEvent written during the request is attributed to the authenticated initiator, (3) requires an
authenticated session, (4) requires completed website MFA, (5) checks the route's action permission
(core.services.identity.policy) and (6) audits state-changing requests, sensitive reads and refusals.

Not routed through here: static files (never audited) and Django admin's own staff check, which stays in force --
admin additionally requires website MFA once a user is logged in.
"""

from __future__ import annotations

from django.conf import settings
from django.contrib.auth.views import redirect_to_login
from django.http import HttpResponseNotAllowed, JsonResponse
from django.shortcuts import redirect, render
from django.urls import reverse
from django.utils.http import urlencode

from .models import AuditEventType
from .services.identity import audit, mfa, policy
from .services.identity import context as audit_context

_JSON_SUFFIXES = (".json",)
_JSON_ROUTES = frozenset({"topology_data"})
_ADMIN_MFA_EXEMPT = frozenset({"login", "logout"})


def _wants_json(request, url_name: str) -> bool:
    return url_name in _JSON_ROUTES or request.path.endswith(_JSON_SUFFIXES)


class NmasAccessMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        request.nmas_request_id = audit.new_request_id(request)
        request.nmas_audit_category = None
        request._nmas_ctx_token = None
        try:
            response = self.get_response(request)
            self._audit_response(request, response)
        finally:
            if request._nmas_ctx_token is not None:
                audit_context.reset(request._nmas_ctx_token)
                request._nmas_ctx_token = None
        response["X-Request-ID"] = request.nmas_request_id
        return response

    # -- enforcement ----------------------------------------------------------------------------------------------

    def process_view(self, request, view_func, view_args, view_kwargs):
        match = request.resolver_match
        if match is None or match.namespace not in ("core", "admin"):
            return None
        name = match.url_name or ""
        request._nmas_ctx_token = audit_context.bind(audit.build_context(request, match.view_name or name))

        if match.namespace == "admin":
            return self._admin_gate(request, name)
        if name in policy.PUBLIC_ROUTES:
            return None

        user = request.user
        if not user.is_authenticated:
            return self._unauthenticated(request, name)
        if name in policy.MFA_PENDING_ROUTES:
            return None
        if settings.NMAS_APP_MFA_REQUIRED and not mfa.session_verified(request.session):
            return self._mfa_redirect(request)

        decision, action = policy.required_action(name, request.method)
        if decision == policy.Decision.METHOD_NOT_ALLOWED:
            self._deny(request, name, "method not allowed on a read-only route", 405)
            return HttpResponseNotAllowed(["GET", "HEAD"])
        if decision == policy.Decision.DENY:
            return self._forbidden(request, name, "route is not classified by the access policy")
        if not policy.user_can(user, action):
            return self._forbidden(request, name, f"missing permission {policy.permission_name(action)}")
        request.nmas_audit_category = policy.action_category(name, request.method)
        return None

    def _admin_gate(self, request, name):
        user = request.user
        if request.method not in policy.SAFE_METHODS:
            request.nmas_audit_category = "admin"
        if (user.is_authenticated and name not in _ADMIN_MFA_EXEMPT and settings.NMAS_APP_MFA_REQUIRED
                and not mfa.session_verified(request.session)):
            return self._mfa_redirect(request)
        return None

    def _unauthenticated(self, request, name):
        if request.method not in policy.SAFE_METHODS or name in policy.SENSITIVE_READ_ROUTES:
            self._deny(request, name, "not authenticated", 401)
        if _wants_json(request, name):
            return JsonResponse({"status": "unauthenticated", "message": "Sign in to NMAS."}, status=401)
        return redirect_to_login(request.get_full_path(), reverse("core:login"))

    def _mfa_redirect(self, request):
        target = "core:mfa_verify" if mfa.is_enrolled(request.user) else "core:mfa_enroll"
        return redirect(f"{reverse(target)}?{urlencode({'next': request.get_full_path()})}")

    def _forbidden(self, request, name, reason):
        self._deny(request, name, reason, 403)
        if _wants_json(request, name):
            return JsonResponse({"status": "forbidden", "message": "You do not have permission for this action."}, status=403)
        return render(request, "core/auth/forbidden.html", {"page_title": "Access denied"}, status=403)

    def _deny(self, request, name, reason, status):
        audit.record(
            AuditEventType.ACCESS_DENIED, f"Denied {request.method} {name or request.path}: {reason}"[:255],
            request=request, outcome=audit.OUTCOME_DENIED, status_code=status,
            metadata={"reason": reason, **audit.request_details(request)},
        )

    # -- response-phase audit ---------------------------------------------------------------------------------------

    def _audit_response(self, request, response):
        category = getattr(request, "nmas_audit_category", None)
        if category in (None, "read", "denied"):
            return
        status = response.status_code
        if status == 405:
            return  # a protocol-level method refusal: no action was attempted (like a CSRF refusal, never audited)
        outcome = audit.OUTCOME_SUCCESS if status < 400 else audit.OUTCOME_FAILURE
        event = AuditEventType.SENSITIVE_READ if category == "sensitive_read" else AuditEventType.WEB_ACTION
        match = request.resolver_match
        label = (match.view_name if match else "") or request.path
        audit.record(
            event, f"{category}: {request.method} {label} -> {status}"[:255], request=request, outcome=outcome,
            status_code=status, metadata={"category": category, **audit.request_details(request)},
        )
