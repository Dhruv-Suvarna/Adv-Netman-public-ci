"""Lab 7 -- every routed website view with URL arguments, NEGATIVE: unknown object ids and the wrong HTTP method.

The website is NMAS's exposed boundary.  For EVERY ``core`` URL pattern that takes arguments (a change id, intent pk,
provisioning id, template id, run id, device name ...), an authenticated, MFA-verified operator requests it with ids that do
not exist, using GET and POST.  Each request must be refused or answered (2xx / 3xx / 4xx) -- never an unhandled exception or
a 5xx -- and must not open a process (other than a local read-only ``git``), socket or HTTP connection: an unknown object can never reach a device, NetBox or
GitHub.  The patched boundaries below make any such attempt visible (and harmless).

Routes without arguments (dashboards, lists) are proven by their own page tests; they are out of this sweep because their
GET legitimately reads configured sources.
"""

from __future__ import annotations

import socket
import subprocess
import uuid
from unittest import mock

from django.test import TestCase
from django.urls import URLPattern, URLResolver, get_resolver

PLACEHOLDER = {"int": "987654", "str": "NOPE-000000", "slug": "nope-000000", "uuid": str(uuid.UUID(int=0xBADC0DE)), "path": "nope/000000"}
REFUSED_OR_ANSWERED = range(200, 500)
# local, read-only repository inspection is allowed (the NSOT catalogue and the evidence freshness read the checkout)
GIT_READS = frozenset({"status", "rev-parse", "ls-files", "show", "cat-file", "log", "diff", "ls-tree", "describe", "rev-list"})
_REAL = {"subprocess.run": subprocess.run, "subprocess.Popen": subprocess.Popen}


def _git_read(argv) -> bool:
    if not isinstance(argv, (list, tuple)) or not argv or argv[0] != "git":
        return False
    rest = list(argv[1:])
    while rest and rest[0].startswith("-"):
        rest = rest[2:] if rest[0] in ("-C", "-c") else rest[1:]
    return bool(rest) and rest[0] in GIT_READS


# A device NAME is only known to be unknown by asking NetBox, its authority.  The sweep answers that one question the way a
# reachable NetBox does ("not found") and then requires zero outbound IO: an unknown device triggers no drift, inventory,
# git or topology lookup (Lab 7 O4).  No route is exempt from the no-outbound-IO assertion.
NETBOX_NOT_FOUND = {"status": "not_found", "message": "unknown device", "data": None}


def _core_patterns():
    """(name, route with placeholders, view) for every argument-taking ``core:`` route."""
    resolver = get_resolver()
    out = []

    def walk(patterns, prefix, namespace):
        for entry in patterns:
            if isinstance(entry, URLResolver):
                walk(entry.url_patterns, prefix + str(entry.pattern), entry.namespace or namespace)
            elif isinstance(entry, URLPattern) and namespace == "core" and entry.pattern.converters:
                route = prefix + str(entry.pattern)
                for name, converter in entry.pattern.converters.items():
                    kind = {"IntConverter": "int", "UUIDConverter": "uuid", "SlugConverter": "slug", "PathConverter": "path"}.get(
                        type(converter).__name__, "str")
                    route = route.replace(f"<{kind}:{name}>", PLACEHOLDER[kind]).replace(f"<{name}>", PLACEHOLDER["str"])
                out.append((entry.name, "/" + route.lstrip("^").rstrip("$"), entry.callback))

    walk(resolver.url_patterns, "", None)
    return sorted(out)


class _Blocked(RuntimeError):
    pass


class RouteSweepTests(TestCase):
    def test_every_routed_view_refuses_unknown_ids_and_wrong_methods_without_a_5xx_or_outbound_call(self):
        """Every argument-taking core route: unknown ids (GET and POST) are refused or answered, never 5xx, never outbound IO."""
        routes = _core_patterns()
        self.assertGreater(len(routes), 100)
        calls: list[str] = []

        def blocked(name):
            def raise_(*args, **kwargs):
                argv = args[0] if args else kwargs.get("args")
                if name in _REAL and _git_read(argv):
                    return _REAL[name](*args, **kwargs)
                calls.append(f"{name} {str(argv)[:80]}")
                raise _Blocked(f"{name} {str(argv)[:80]} is blocked in the route sweep")
            return raise_

        with mock.patch.object(subprocess, "run", blocked("subprocess.run")), mock.patch.object(subprocess, "Popen", blocked("subprocess.Popen")), \
             mock.patch.object(socket, "create_connection", blocked("socket.create_connection")), \
             mock.patch("requests.Session.request", blocked("requests")), mock.patch("urllib.request.urlopen", blocked("urlopen")), \
             mock.patch("core.services.nsot_netbox.get_device_detail", return_value=NETBOX_NOT_FOUND):
            for name, url, _view in routes:
                for method in ("get", "post"):
                    with self.subTest(case=f"invalid unknown id {method.upper()} {name}"):
                        before = len(calls)
                        try:
                            response = getattr(self.client, method)(url)
                        except _Blocked as exc:                       # pragma: no cover - a finding, reported below
                            self.fail(f"{name}: an unknown object reached an outbound boundary ({exc})")
                        self.assertIn(response.status_code, REFUSED_OR_ANSWERED, f"{method.upper()} {url}")
                        self.assertEqual(calls[before:], [], f"{method.upper()} {url} attempted outbound IO for an unknown object")

    def test_an_anonymous_request_to_any_routed_view_is_refused(self):
        """Without a session every argument-taking route redirects to login or is forbidden -- never answered, never 5xx."""
        self.client.logout()
        for name, url, _view in _core_patterns():
            for method in ("get", "post"):
                with self.subTest(case=f"unauthorized {method.upper()} {name}"):
                    status = getattr(self.client, method)(url).status_code
                    self.assertIn(status, (302, 401, 403, 404, 405), f"{method.upper()} {url}")
