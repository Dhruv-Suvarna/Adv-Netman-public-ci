"""Persistent production-flow soak sampling for applied troubleshooting remediation plans (read-only; never writes to a device).

    manage.py troubleshooting_monitor sample --tenant acme --actor nmas-monitor [--flow-source pkg.mod.factory] [--iterations N --sleep S]
    manage.py troubleshooting_monitor status --tenant acme --actor alice --plan RPL-...
    manage.py troubleshooting_monitor reset-window --tenant acme --actor alice --plan RPL-... --reason "why"

``sample`` is restart-safe: every pass reads/appends the ledger persisted on the plan, so a killed process leaves a visible monitoring gap
(which can fail the window) instead of invented continuity.  With no flow source configured the samples are recorded UNUSABLE and the
window can never pass.  ``reset-window`` is a human, audited decision and the only way past a degraded/interrupted window.
"""

from __future__ import annotations

import importlib
import json
import time
from datetime import timedelta

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from core.services.troubleshooting import governance as gov
from core.services.troubleshooting import repository as repo
from core.services.troubleshooting import runtime_ports as rp


def _load(path: str):
    mod, _, attr = path.replace(":", ".").rpartition(".")
    try:
        return getattr(importlib.import_module(mod), attr)
    except Exception as exc:  # noqa: BLE001
        raise CommandError(f"{path!r} failed to load: {type(exc).__name__}") from exc


class Command(BaseCommand):
    help = "Sample named production flows for active troubleshooting soak windows (persistent, restart-safe, read-only)."

    def add_arguments(self, parser):
        sub = parser.add_subparsers(dest="action", required=True)
        for name in ("sample", "status", "reset-window"):
            p = sub.add_parser(name)
            p.add_argument("--tenant", required=True)
            p.add_argument("--actor", required=True)
            if name != "sample":
                p.add_argument("--plan", required=True)
        s = sub.choices["sample"]
        s.add_argument("--flow-source", default=None, help="dotted path of a factory returning source(flow)->{loss_pct,coverage}|None "
                                                          "(default settings.TROUBLESHOOTING_FLOW_SOURCE, else none => unusable samples)")
        s.add_argument("--window-minutes", type=float, default=rp.DEFAULT_WINDOW.total_seconds() / 60)
        s.add_argument("--interval", type=int, default=rp.DEFAULT_INTERVAL_S)
        s.add_argument("--max-gap", type=int, default=rp.DEFAULT_MAX_GAP_S)
        s.add_argument("--iterations", type=int, default=1, help="passes to run in this process (0 = until interrupted)")
        s.add_argument("--sleep", type=float, default=None, help="seconds between passes (default --interval)")
        sub.choices["reset-window"].add_argument("--reason", required=True)

    def handle(self, *args, **opts):
        actor_type = "user" if opts["action"] == "reset-window" else "system"
        actor = repo.Actor(opts["actor"], actor_type, tenant=opts["tenant"])
        try:
            if opts["action"] == "sample":
                return self._sample(actor, opts)
            plan = opts["plan"]
            if opts["action"] == "status":
                p = gov.get_plan(actor, plan)
                out = rp.plan_soak_status(p, rp._now())
            else:
                out = {"reset": True, "resets": rp.reset_window(actor, plan, reason=opts["reason"]).get("resets", [])[-1:]}
            self.stdout.write(json.dumps(out, sort_keys=True, default=str))
            return None
        except (gov.GovernanceRefused, repo.AccessDenied) as exc:
            raise CommandError(str(exc)) from exc

    def _sample(self, actor, opts):
        path = opts["flow_source"] or getattr(settings, "TROUBLESHOOTING_FLOW_SOURCE", "")
        source = _load(path)() if path else None
        n, i = opts["iterations"], 0
        pause = opts["sleep"] if opts["sleep"] is not None else opts["interval"]
        while True:
            res = rp.monitor_once(actor, source, window=timedelta(minutes=opts["window_minutes"]), interval_s=opts["interval"],
                                  max_gap_s=opts["max_gap"])
            self.stdout.write(json.dumps({"flow_source": bool(source), "plans": res}, sort_keys=True, default=str))
            i += 1
            if n and i >= n:
                break
            time.sleep(pause)
