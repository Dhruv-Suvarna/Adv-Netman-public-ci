"""Unattended PREAUTHORIZED_AUTOMATED_RECOVERY watcher: hands policy-covered Troubleshooter plans to recovery.recover()."""
import time

from django.core.management.base import BaseCommand

from core.services.troubleshooting import recovery


class Command(BaseCommand):
    help = "Execute exact-scoped, policy-authorized recovery plans through the Change Engine (no other plan is touched)."

    def add_arguments(self, parser):
        parser.add_argument("--watch", action="store_true")
        parser.add_argument("--interval", type=float, default=3.0)

    def handle(self, *args, **opts):
        while True:
            for plan_id in recovery.pending_plans():
                try:
                    self.stdout.write(f"{plan_id}: {recovery.recover(plan_id)}")
                except recovery.RecoveryRefused as exc:
                    self.stdout.write(f"{plan_id}: refused {exc}")
                except Exception as exc:  # noqa: BLE001 - the watcher must keep running; the plan stays for a human
                    self.stderr.write(f"{plan_id}: error {type(exc).__name__}: {exc}")
            self.stdout.flush()
            if not opts["watch"]:
                return
            time.sleep(opts["interval"])
