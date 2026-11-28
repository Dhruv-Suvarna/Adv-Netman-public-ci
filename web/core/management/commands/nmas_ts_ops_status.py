"""Read-only operational status of the unattended Troubleshooter (no device, broker or credential is contacted; nothing is written).

    manage.py nmas_ts_ops_status [--json]

Reports:
- services
- AI provider pool and disabled providers
- recent dispatch outcomes (PAUSED = no eligible / quota-exhausted provider)
- standing recovery policies (validity, executions)
- intake configuration and open or idle monitoring cases
- stale execution locks and leases, in-flight plans
- audit-chain integrity
- last structured route-intent pass of the running intake (from its journal; no device is read)
"""
from __future__ import annotations

import json
import subprocess
from datetime import datetime, timedelta, timezone

from django.core.management.base import BaseCommand

from core import models as m
from core.services.troubleshooting import agent_dispatch, intake, recovery
from core.services.troubleshooting import agent_orchestrator as orch
from core.services.troubleshooting import repository as repo

SERVICES = ("nmas-web", "nmas-ts-intake", "nmas-ts-auto-recover", "nmas-troubleshooter-device-worker", "nmas-ts-model-broker@codex",
            "nmas-ts-model-broker@claude-a", "nmas-ts-model-broker@claude-b", "ai-dispatcher", "nmas-research-broker",
            "nmas-ts-worker-credential-sync.path", "nmas-ts-worker-credential-sync.timer")


def _unit(name: str) -> dict:
    def q(*args):
        return subprocess.run(["systemctl", *args, name], capture_output=True, text=True, timeout=10, check=False).stdout.strip()
    return {"active": q("is-active"), "enabled": q("is-enabled")}


def last_route_intent_pass(reader=None) -> dict:
    """Most recent ``route_intent_pass`` record the running intake wrote to its journal (read-only, bounded window)."""
    def journal() -> str:
        return subprocess.run(["journalctl", "-u", "nmas-ts-intake.service", "-o", "cat", "-n", "400", "--no-pager"],
                              capture_output=True, text=True, timeout=10, check=False).stdout
    try:
        lines = (reader or journal)().splitlines()
    except (OSError, subprocess.SubprocessError):
        return {"available": False, "error_code": "JOURNAL_UNAVAILABLE"}
    for line in reversed(lines):
        body = line[line.find("{"):] if "{" in line else ""
        if intake.ROUTE_INTENT_PASS_SCHEMA not in body:
            continue
        try:
            rec = json.loads(body)
        except ValueError:
            continue
        if rec.get("schema") != intake.ROUTE_INTENT_PASS_SCHEMA:
            continue
        try:
            age = int((datetime.now(timezone.utc) - datetime.fromisoformat(rec["at"])).total_seconds())
        except (KeyError, TypeError, ValueError):
            age = None
        keep = ("pass_id", "at", "state", "severity", "error_code", "intent_revision", "topology_revision", "routes",
                "confirmed_fingerprints", "items_truncated")
        return {"available": True, "age_seconds": age, **{k: rec.get(k) for k in keep},
                "non_healthy_items": rec.get("items", [])}
    return {"available": False, "error_code": "NO_ROUTE_INTENT_PASS_IN_JOURNAL"}


def _route_intent_status() -> dict:
    binding = intake.unit_route_intent_binding()
    return {**binding, "last_pass": last_route_intent_pass() if binding.get("bound") else None}


def status() -> dict:
    now = datetime.now(timezone.utc)
    pool = agent_dispatch.provider_pool()
    handoffs = m.TsAIHandoff.objects.filter(created_at__gte=now - timedelta(days=1)) if hasattr(m.TsAIHandoff, "created_at") else m.TsAIHandoff.objects.none()
    outcomes: dict[str, int] = {}
    for h in handoffs:
        outcomes[str(getattr(h, "status", ""))] = outcomes.get(str(getattr(h, "status", "")), 0) + 1
    open_cases = []
    for case in m.TsCase.objects.filter(trigger_source=intake.TRIGGER_SOURCE).exclude(state__in=list(m.TS_TERMINAL_CASE_STATES)):
        last = m.TsAuditEvent.objects.filter(case=case).order_by("-occurred_at").values_list("occurred_at", flat=True).first()
        open_cases.append({"case": case.case_id, "state": case.state, "fingerprint": case.trigger_ref,
                           "idle_seconds": int((now - last).total_seconds()) if last else None})
    cfg = intake.IntakeConfig.from_settings()
    broken = [c.case_id for c in m.TsCase.objects.filter(opened_at__gte=now - timedelta(days=7)) if repo.verify_audit_chain(c)]
    lease = m.TsGlobalAgentLease.objects.values("state", "active_agent", "handoff_id", "lease_expires_at").first() \
        if hasattr(m, "TsGlobalAgentLease") else None
    return {
        "at": now.isoformat(),
        "services": {s: _unit(s) for s in SERVICES},
        "ai_providers": {"pool": list(pool), "disabled_by_policy": [a for a in orch.AGENTS if a not in pool],
                         "handoff_outcomes_24h": outcomes,
                         "note": "PAUSED = no eligible provider (broker down, unauthenticated or quota exhausted); idle cases are emailed"},
        "global_ai_lease": lease,
        "recovery_policies": recovery.policy_status(),
        "intake": {"devices": list(cfg.devices), "confirm_seconds": cfg.confirm_seconds, "cooldown_seconds": cfg.cooldown_seconds,
                   "max_cases_per_hour": cfg.max_cases_per_hour, "open_monitoring_cases": open_cases,
                   "monitoring_cases_last_hour": m.TsCase.objects.filter(trigger_source=intake.TRIGGER_SOURCE,
                                                                          opened_at__gte=now - timedelta(hours=1)).count(),
                   "route_intent": _route_intent_status()},
        "execution": {"device_locks": list(m.ExecutionDeviceLock.objects.values_list("device", flat=True)),
                      "stale_locks": list(m.ExecutionDeviceLock.objects.filter(run__lease_expires_at__lte=now).values_list("device", flat=True)),
                      "plans_in_flight": list(m.TsRemediationPlan.objects.filter(
                          status__in=["DRY_RUN_PASS", "PREAUTHORIZED", "PRECHECK_PASS", "EXECUTING", "VERIFYING"]).values_list("record_id", "status")),
                      "actions_executing": m.TsActionExecution.objects.filter(status="EXECUTING").count()},
        "audit_chain_broken_cases_7d": broken,
    }


class Command(BaseCommand):
    help = "Read-only operational status of the unattended Troubleshooter."

    def add_arguments(self, parser):
        parser.add_argument("--json", action="store_true")

    def handle(self, *args, **opts):
        self.stdout.write(json.dumps(status(), indent=None if opts["json"] else 2, sort_keys=True, default=str))
