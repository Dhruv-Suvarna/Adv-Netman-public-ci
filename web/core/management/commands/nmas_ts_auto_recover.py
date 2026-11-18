"""Unattended PREAUTHORIZED_AUTOMATED_RECOVERY watcher: hands policy-covered Troubleshooter plans to recovery.recover().

Restart-safe: on start it sweeps anything a previous process left mid-pipeline (never re-executed, see recovery.sweep_interrupted);
an unexpected error fails the plan closed instead of retrying; policy expiry/exhaustion warnings are logged and emailed once.

    manage.py nmas_ts_auto_recover --watch [--interval 3]
    manage.py nmas_ts_auto_recover --status          # JSON policy status (validity, executions used/remaining, cooldown, warnings)
"""
import json
import time

from django.core.management.base import BaseCommand

from core.services.troubleshooting import notify, recovery

STATUS_EVERY_S = 3600


class Command(BaseCommand):
    help = "Execute exact-scoped, policy-authorized recovery plans through the Change Engine (no other plan is touched)."

    def add_arguments(self, parser):
        parser.add_argument("--watch", action="store_true")
        parser.add_argument("--interval", type=float, default=3.0)
        parser.add_argument("--status", action="store_true", help="print standing-policy status as JSON and exit")

    def handle(self, *args, **opts):
        if opts["status"]:
            self.stdout.write(json.dumps(recovery.policy_status(), indent=2, sort_keys=True))
            return
        for row in recovery.sweep_interrupted():
            self.stderr.write(f"interrupted plan swept (not re-executed): {row}")
        warned: set[tuple[str, str]] = set()
        next_status = 0.0
        while True:
            if time.monotonic() >= next_status:
                next_status = time.monotonic() + STATUS_EVERY_S
                self._policy_warnings(warned)
            for plan_id in recovery.pending_plans():
                try:
                    self.stdout.write(f"{plan_id}: {recovery.recover(plan_id)}")
                except recovery.RecoveryRefused as exc:
                    self.stdout.write(f"{plan_id}: refused {exc}")
                except Exception as exc:  # noqa: BLE001 - the watcher must keep running; the plan is failed closed for a human
                    self.stderr.write(f"{plan_id}: error {type(exc).__name__}: {exc}")
                    try:
                        self.stderr.write(f"{plan_id}: {recovery.fail_closed(plan_id, f'{type(exc).__name__}: {exc}')}")
                    except Exception as inner:  # noqa: BLE001
                        self.stderr.write(f"{plan_id}: fail_closed error {type(inner).__name__}: {inner}")
            for plan_id in recovery.undecided_plans():
                try:
                    self.stdout.write(f"{plan_id}: decision {recovery.record_plan_decision(plan_id)['outcome']}")
                except Exception as exc:  # noqa: BLE001 - recording a decision never stops the watcher
                    self.stderr.write(f"{plan_id}: decision error {type(exc).__name__}: {exc}")
            self.stdout.flush()
            if not opts["watch"]:
                return
            time.sleep(opts["interval"])

    def _policy_warnings(self, warned: set) -> None:
        rows = recovery.policy_status()
        active_scopes = {r.get("scope") for r in rows if r.get("active")}
        for row in rows:
            self.stdout.write(f"policy {row['id']}: active={row.get('active')} used={row.get('executions_used')}/{row.get('max_executions')} "
                              f"expires={row.get('expires_at')} warnings={row.get('warnings')}")
            if not row.get("active") and row.get("scope") in active_scopes:
                continue                      # superseded by an active successor for the same scope: nothing to act on
            new = [w for w in row.get("warnings", []) if (row["id"], w) not in warned]
            if new:
                warned.update((row["id"], w) for w in new)
                notify.send(f"[NMAS] Recovery policy {row['id']}: {', '.join(new)}",
                            f"Standing recovery policy {row['id']} ({row.get('scope')}) needs attention: {', '.join(new)}.\n"
                            f"Executions {row.get('executions_used')}/{row.get('max_executions')}, expires {row.get('expires_at')}.\n"
                            "Policies are never extended automatically; renewal needs a new owner authorization.\n")
