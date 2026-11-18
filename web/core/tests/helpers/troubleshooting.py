"""Sign-in helpers for the troubleshooting view tests.

The troubleshooting views sit behind two independent checks:

1. ``core.middleware.NmasAccessMiddleware`` -- website MFA plus the NMAS action permission that
   ``core.services.identity.policy`` assigns to the route (VIEW / EDIT / VALIDATE / APPROVE / EXECUTE);
2. the view itself -- a ``ts-*`` troubleshooting role, tenant (``ts-tenant:<name>``) and device scope (``ts-device:<name>``).

``ts_user`` creates a user holding the ``ts-*`` groups AND the NMAS permissions a person in that troubleshooting role is expected
to hold, granted as real Django permissions.  A user with no ``ts-*`` role gets NMAS VIEW only, so the view's own role check
(not the middleware) is what refuses them.  ``nmas=`` overrides the NMAS permissions to test the middleware layer directly.
``ts_sign_in`` signs in through the real session + MFA marker and disables the suite-wide auto-login operator, so the request
is made as exactly this user.
"""

from __future__ import annotations

from django.contrib.auth.models import Group, Permission, User

from core.services.identity.policy import Action
from core.tests.runner import sign_in

TS_ROLE_NMAS = {
    "ts-viewer": (Action.VIEW,),
    "ts-operator": (Action.VIEW, Action.EDIT, Action.VALIDATE, Action.PLAN),
    "ts-approver": (Action.VIEW, Action.EDIT, Action.VALIDATE, Action.PLAN, Action.APPROVE, Action.EXECUTE),
    "ts-admin": tuple(Action),
}


def ts_user(name, *groups, nmas=None):
    u = User.objects.create(username=name)   # no password hashing: keeps the suite fast; login is via force_login
    for g in groups:
        u.groups.add(Group.objects.get_or_create(name=g)[0])
    if nmas is None:
        nmas = {a for g in groups for a in TS_ROLE_NMAS.get(g, ())} or {Action.VIEW}
    u.user_permissions.set(Permission.objects.filter(content_type__app_label="core", codename__in=[a.value for a in nmas]))
    return User.objects.get(pk=u.pk)   # drop the cached permission set


def ts_sign_in(client, user, *, mfa_verified=True):
    client.nmas_auto_login = False
    client._nmas_signed_in = True
    sign_in(client, user, mfa_verified=mfa_verified)


def anonymous(client):
    """Make ``client`` anonymous without letting the suite-wide auto-login sign the test operator in."""
    client.logout()
    client.nmas_auto_login = False
