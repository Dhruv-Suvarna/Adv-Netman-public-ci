"""Unattended incident intake: monitoring -> correlated incident -> Troubleshooter case -> Codex dispatch (read-only; never writes).

    manage.py nmas_ts_intake --watch [--interval 10]
    manage.py nmas_ts_intake --once                 # one detection pass (still opens a case if a confirmed incident exists)
    manage.py nmas_ts_intake --observe              # print current deterministic classifications only; opens nothing
"""
import json
import time
from datetime import datetime, timezone

from django.core.management.base import BaseCommand

from core.services.troubleshooting import faults, intake


class Command(BaseCommand):
    help = "Detect managed-device interface intent violations and open/dispatch Troubleshooter cases automatically."

    def add_arguments(self, parser):
        parser.add_argument("--watch", action="store_true")
        parser.add_argument("--once", action="store_true")
        parser.add_argument("--observe", action="store_true")
        parser.add_argument("--interval", type=float, default=10.0)

    def handle(self, *args, **opts):
        engine = intake.Intake(config_admin=intake.read_config_admin, deps=intake.IntakeDeps(topology_paths=True))
        if opts["observe"]:
            engine._peers = intake.peers(set(engine.cfg.devices))                     # pylint: disable=protected-access
            incidents, samples, unread = engine._interface_incidents(datetime.now(timezone.utc))   # pylint: disable=protected-access
            abnormal = {f"{k[0]}:{k[1]}": cl.as_dict() for k, cl in engine.last_classes.items() if cl.category != faults.NO_FAULT}
            self.stdout.write(json.dumps({"devices": engine.cfg.devices, "interfaces_read": len(samples), "unreadable": sorted(unread),
                                          "non_healthy_classifications": abnormal,
                                          "incidents": [{"fingerprint": i.fingerprint, "category": i.category,
                                                         "decision": faults.decide(i.classification)["outcome"] if i.classification else None}
                                                        for i in incidents]}, default=str))
            return
        self.stdout.write(f"intake: devices={engine.cfg.devices} confirm={engine.cfg.confirm_seconds}s cooldown={engine.cfg.cooldown_seconds}s "
                          f"budget={engine.cfg.max_cases_per_hour}/h routing={engine.cfg.routing_devices} flap>={faults.FLAP_MIN_TRANSITIONS}/{faults.FLAP_WINDOW_SECONDS}s")
        while True:
            for row in engine.poll():
                self.stdout.write(json.dumps(row, default=str))
            self.stdout.flush()
            if not opts["watch"]:
                return
            time.sleep(opts["interval"])
