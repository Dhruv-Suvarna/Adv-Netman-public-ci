"""NMAS website authentication views (V2 Phase 1): login / logout, website MFA, audit review, health probe.

Built on django.contrib.auth (users, password hashing, sessions) -- no parallel user database.  Website MFA lives in
core.services.identity.mfa and is unrelated to network-device MFA.
"""

from __future__ import annotations

from django import forms
from django.contrib import messages
from django.contrib.auth import logout as auth_logout
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.views import LoginView, LogoutView
from django.core.paginator import Paginator
from django.http import HttpResponse
from django.shortcuts import redirect, render
from django.urls import reverse
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET, require_http_methods

from . import models
from .services.identity import audit, mfa, policy

MFA_MAX_FAILURES = 5


def _safe_next(request, default: str = "core:home") -> str:
    candidate = request.POST.get("next") or request.GET.get("next") or ""
    if candidate and url_has_allowed_host_and_scheme(candidate, allowed_hosts={request.get_host()},
                                                     require_https=request.is_secure()):
        return candidate
    return reverse(default)


class ThrottledAuthenticationForm(AuthenticationForm):
    """Django's AuthenticationForm, refusing (before checking the password) once recent failures exceed the limit."""

    error_messages = {
        **AuthenticationForm.error_messages,
        "throttled": "Too many failed sign-in attempts. Wait a few minutes and try again.",
    }

    def clean(self):
        username = (self.cleaned_data.get("username") or "").strip()
        if audit.login_throttled(username.lower(), audit.source_ip(self.request)):
            audit.record(models.AuditEventType.AUTH_LOGIN_THROTTLED, "Login refused: failure limit reached",
                         request=self.request, actor=username[:150], outcome=audit.OUTCOME_DENIED,
                         metadata={"attempted_username": username[:150].lower()})
            raise forms.ValidationError(self.error_messages["throttled"], code="throttled")
        return super().clean()


class NmasLoginView(LoginView):
    template_name = "core/auth/login.html"
    authentication_form = ThrottledAuthenticationForm
    redirect_authenticated_user = True
    extra_context = {"page_title": "Sign in"}


class NmasLogoutView(LogoutView):
    http_method_names = ["post", "options"]


@never_cache
@require_http_methods(["GET", "POST"])
def mfa_verify(request):
    if not mfa.is_enrolled(request.user):
        return redirect(f"{reverse('core:mfa_enroll')}?next={request.GET.get('next', '')}")
    error = ""
    if request.method == "POST":
        try:
            ok = mfa.verify(request.user, request.POST.get("otp_code", ""))
        except mfa.MfaError as exc:
            ok, error = False, str(exc)
        if ok:
            request.session.cycle_key()
            mfa.mark_session_verified(request.session)
            audit.record(models.AuditEventType.APP_MFA_VERIFIED, f"Website MFA verified for {request.user.get_username()}",
                         request=request, outcome=audit.OUTCOME_SUCCESS)
            return redirect(_safe_next(request))
        failures = mfa.register_failure(request.session)
        audit.record(models.AuditEventType.APP_MFA_FAILED, f"Website MFA verification failed for {request.user.get_username()}",
                     request=request, outcome=audit.OUTCOME_FAILURE, metadata={"stage": "verify", "session_failures": failures})
        if failures >= MFA_MAX_FAILURES:
            auth_logout(request)
            messages.error(request, "Too many invalid authenticator codes. Sign in again.")
            return redirect("core:login")
        error = error or "That code is not valid (or was already used). Enter the current code from the authenticator app."
    return render(request, "core/auth/mfa_verify.html", {
        "page_title": "Verify sign-in", "error": error, "next": request.POST.get("next") or request.GET.get("next", ""),
    })


@never_cache
@require_http_methods(["GET", "POST"])
def mfa_enroll(request):
    if mfa.is_enrolled(request.user):
        return redirect(f"{reverse('core:mfa_verify')}?next={request.GET.get('next', '')}")
    error = ""
    if request.method == "POST":
        try:
            mfa.complete_enrollment(request.user, request.session, request.POST.get("otp_code", ""))
        except mfa.MfaError as exc:
            error = str(exc)
            audit.record(models.AuditEventType.APP_MFA_FAILED, f"Website MFA enrollment code rejected for {request.user.get_username()}",
                         request=request, outcome=audit.OUTCOME_FAILURE, metadata={"stage": "enroll"})
        else:
            request.session.cycle_key()
            mfa.mark_session_verified(request.session)
            audit.record(models.AuditEventType.APP_MFA_ENROLLED, f"Website MFA enrolled for {request.user.get_username()}",
                         request=request, outcome=audit.OUTCOME_SUCCESS, object_type="AppMfaDevice",
                         object_id=str(request.user.pk))
            messages.success(request, "Microsoft Authenticator is now required for every NMAS sign-in.")
            return redirect(_safe_next(request))
    seed = mfa.begin_enrollment(request.session)
    uri = mfa.provisioning_uri(request.user, seed)
    response = render(request, "core/auth/mfa_enroll.html", {
        "page_title": "Set up Microsoft Authenticator",
        "qr_data_uri": mfa.qr_svg_data_uri(uri),
        "manual_key": " ".join(seed[i:i + 4] for i in range(0, len(seed), 4)),
        "issuer": mfa.ISSUER, "account": request.user.get_username(), "error": error,
        "next": request.POST.get("next") or request.GET.get("next", ""),
    })
    response["Cache-Control"] = "no-store"
    return response


@require_GET
def mfa_status(request):
    device = mfa.device_for(request.user)
    return render(request, "core/auth/mfa_status.html", {
        "page_title": "Account security", "device": device, "actions": policy.user_actions(request.user),
        "groups": sorted(request.user.groups.values_list("name", flat=True)),
    })


AUDIT_PAGE_SIZE = 50


@require_GET
def audit_log(request):
    """Security-admin review of the audit ledger (newest first).  Metadata is already redacted at write time."""
    events = models.AuditEvent.objects.select_related("actor_user").all()
    event_type = request.GET.get("type", "").strip()
    actor = request.GET.get("actor", "").strip()
    if event_type:
        events = events.filter(event_type=event_type)
    if actor:
        events = events.filter(actor__icontains=actor)
    page = Paginator(events, AUDIT_PAGE_SIZE).get_page(request.GET.get("page"))
    return render(request, "core/auth/audit_log.html", {
        "page_title": "Audit log", "page_obj": page, "events": page.object_list,
        "event_types": models.AuditEventType.choices, "type_filter": event_type, "actor_filter": actor,
    })


@require_GET
def healthz(request):
    """Constant liveness answer for the reverse proxy / tunnel: no data, no database access."""
    return HttpResponse("ok\n", content_type="text/plain")
