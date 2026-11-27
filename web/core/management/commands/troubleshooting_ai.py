"""Explicitly continue an existing, authorized AI handoff with the configured model provider.

    manage.py troubleshooting_ai continue --handoff TSAI-... --tenant acme --actor alice [--provider pkg.mod.factory] [--deps pkg.mod.factory]
    manage.py troubleshooting_ai dispatch --handoff TSAI-... --tenant acme --actor alice     (global lease, Codex -> ClaudeA -> ClaudeB failover)
    manage.py troubleshooting_ai agents                                                      (broker health and lease; no credential)

Never opens a handoff, never reads credentials, never writes to a device.  With no configured provider the command exits non-zero with status
PROVIDER_UNAVAILABLE and leaves the handoff OPEN.
"""

from __future__ import annotations

import importlib
import json
import os
import re

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import connection

from core.services.troubleshooting import ai_runtime
from core.services.troubleshooting import repository as repo
from core.services.troubleshooting import runtime as rt


class _TroubleshootingSqlBoundary:
    """Permit runtime writes only to the troubleshooting evidence journal.

    This is defence in depth for the dedicated runtime.  The systemd unit also
    denies network/filesystem escape.  It prevents normal Django code in this
    process from altering device identity, ManagementPath, credential, change
    approval or authorization tables.
    """

    _TX = ("BEGIN", "COMMIT", "ROLLBACK", "SAVEPOINT", "RELEASE")
    _WRITE = re.compile(r'^(?:INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+["`]?(core_ts[a-z0-9_]+)["`]?', re.I)

    def __call__(self, execute, sql, params, many, context):
        statement = str(sql).lstrip()
        upper = statement.upper()
        if upper.startswith(("SELECT", "EXPLAIN")) or upper.startswith(self._TX):
            return execute(sql, params, many, context)
        match = self._WRITE.match(statement)
        if match and match.group(1).lower().startswith("core_ts"):
            return execute(sql, params, many, context)
        raise RuntimeError("Troubleshooter runtime database scope refused the statement")


class Command(BaseCommand):
    help = "Continue an OPEN troubleshooting AI handoff via the runtime-bound model gateway (read-only)."

    def add_arguments(self, parser):
        sub = parser.add_subparsers(dest="action", required=True)
        p = sub.add_parser("continue", help="continue an existing handoff")
        p.add_argument("--handoff", required=True)
        p.add_argument("--tenant", required=True)
        p.add_argument("--actor", required=True, help="human/operator name authorizing the continuation")
        p.add_argument("--device", action="append", default=None, help="restrict the operator's visible devices (repeatable)")
        p.add_argument("--provider", default=None, help="dotted path of a provider factory (default settings.TROUBLESHOOTING_AI_PROVIDER)")
        p.add_argument("--deps", default=None, help="dotted path of a RuntimeDeps factory (default settings.TROUBLESHOOTING_RUNTIME_DEPS, else fail-closed)")
        p.add_argument("--runbook", default=None)
        d = sub.add_parser("dispatch", help="continue a handoff under the global Codex/ClaudeA/ClaudeB lease with failover")
        d.add_argument("--handoff", required=True)
        d.add_argument("--tenant", required=True)
        d.add_argument("--actor", required=True, help="human/operator name authorizing the continuation")
        d.add_argument("--device", action="append", default=None)
        d.add_argument("--deps", default=None)
        d.add_argument("--runbook", default=None)
        sub.add_parser("agents", help="print the credential-free health each fixed model broker reports, and the global lease")

    def _dispatch(self, opts, actor, deps):
        from core.services.troubleshooting import agent_dispatch

        def run():
            return agent_dispatch.dispatch(actor, opts["handoff"], deps=deps, runbook=opts["runbook"])

        if os.environ.get("NMAS_TS_RUNTIME_DB_RESTRICTED") == "1":
            with connection.execute_wrapper(_TroubleshootingSqlBoundary()):
                res = run()
        else:
            res = run()
        self.stdout.write(json.dumps(res.as_dict(), sort_keys=True, default=str))
        if res.status in (agent_dispatch.ST_PAUSED, agent_dispatch.ST_BUSY, agent_dispatch.ST_SUPERSEDED,
                          ai_runtime.ST_NOT_AUTHORIZED, ai_runtime.ST_NOT_OPEN, "HANDOFF_NOT_OPEN"):
            raise CommandError(f"{res.status}: {res.reason}")

    def _agents(self):
        from dataclasses import asdict

        from core import models as m
        from core.services.troubleshooting import agent_dispatch
        from core.services.troubleshooting.model_provider import PROVIDER_FACTORIES

        statuses, _providers = agent_dispatch.probe_all(dict(PROVIDER_FACTORIES))
        decision = agent_dispatch.orch.select_agent(statuses, agent_dispatch.DEFAULT_ESTIMATE)
        lease = m.TsGlobalAgentLease.objects.filter(singleton_key=1).first()
        self.stdout.write(json.dumps({
            "agents": [asdict(status) for status in statuses], "eligible": list(decision.eligible), "rejected": decision.rejected,
            "lease": {"state": lease.state if lease else "IDLE", "active_agent": lease.active_agent if lease else "",
                      "fencing_token": lease.fencing_token if lease else 0}}, sort_keys=True, default=str))

    def handle(self, *args, **opts):
        if opts["action"] == "agents":
            return self._agents()
        actor = repo.Actor(opts["actor"], "user", tenant=opts["tenant"], devices=frozenset(opts["device"]) if opts["device"] else None)
        deps = None
        path = opts["deps"] or getattr(settings, "TROUBLESHOOTING_RUNTIME_DEPS", "")
        if path:
            mod, _, attr = path.replace(":", ".").rpartition(".")
            try:
                deps = getattr(importlib.import_module(mod), attr)()
            except Exception as exc:  # noqa: BLE001
                raise CommandError(f"runtime deps {path!r} failed to load: {type(exc).__name__}") from exc
            if not isinstance(deps, rt.RuntimeDeps):
                raise CommandError("runtime deps factory must return RuntimeDeps")
        if opts["action"] == "dispatch":
            return self._dispatch(opts, actor, deps)
        if os.environ.get("NMAS_TS_RUNTIME_DB_RESTRICTED") == "1":
            with connection.execute_wrapper(_TroubleshootingSqlBoundary()):
                res = ai_runtime.continue_handoff(actor, opts["handoff"], provider_path=opts["provider"], deps=deps, runbook=opts["runbook"])
        else:
            res = ai_runtime.continue_handoff(actor, opts["handoff"], provider_path=opts["provider"], deps=deps, runbook=opts["runbook"])
        self.stdout.write(json.dumps(res.as_dict(), sort_keys=True, default=str))
        if res.status in (ai_runtime.ST_PROVIDER_UNAVAILABLE, ai_runtime.ST_NOT_AUTHORIZED, ai_runtime.ST_NOT_OPEN):
            raise CommandError(f"{res.status}: {res.reason}")
        return None
