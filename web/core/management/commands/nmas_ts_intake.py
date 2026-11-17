"""Unattended incident intake: monitoring -> correlated incident -> Troubleshooter case -> Codex dispatch (read-only; never writes).

    manage.py nmas_ts_intake --watch [--interval 10]
    manage.py nmas_ts_intake --once                 # one detection pass (still opens a case if a confirmed incident exists)
    manage.py nmas_ts_intake --observe              # print current intent violations only; opens nothing
"""
import json
import time
from dataclasses import asdict

from django.core.management.base import BaseCommand

from core.services.troubleshooting import intake


class Command(BaseCommand):
    help = "Detect managed-device interface intent violations and open/dispatch Troubleshooter cases automatically."

    def add_arguments(self, parser):
        parser.add_argument("--watch", action="store_true")
        parser.add_argument("--once", action="store_true")
        parser.add_argument("--observe", action="store_true")
        parser.add_argument("--interval", type=float, default=10.0)

    def handle(self, *args, **opts):
        engine = intake.Intake()
        if opts["observe"]:
            obs = []
            for d in engine.cfg.devices:
                obs += engine.reader(d, engine.cfg) or []
            self.stdout.write(json.dumps({"devices": engine.cfg.devices, "interfaces_read": len(obs),
                                          "violations": [asdict(o) for o in intake.violations(obs, engine.intent).values()]}))
            return
        self.stdout.write(f"intake: devices={engine.cfg.devices} confirm={engine.cfg.confirm_seconds}s cooldown={engine.cfg.cooldown_seconds}s "
                          f"budget={engine.cfg.max_cases_per_hour}/h")
        while True:
            for row in engine.poll():
                self.stdout.write(json.dumps(row, default=str))
            self.stdout.flush()
            if not opts["watch"]:
                return
            time.sleep(opts["interval"])
