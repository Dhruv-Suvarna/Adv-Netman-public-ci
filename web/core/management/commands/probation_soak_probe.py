"""Read-only evidence PROBE for a Probation bundle: which soak evidence is available RIGHT NOW, and what would block a soak?

    python web/manage.py probation_soak_probe BND-PROB-000001 [--no-live] [--json]

It starts nothing and persists nothing: no soak run, no sample, no audit event, no notification.  It runs the same guard (bundle integrity,
later-execution interference) and the same read-only evidence collection a real sample would, then prints the classified result -- so an
operator can see, before Phase-20B, whether telemetry is fresh, the devices answer the read-only allowlist and nothing blocks the start.
``--no-live`` skips the device reads (telemetry only).  It never configures a device and never calls the SNMP poller.
"""

from __future__ import annotations

import json

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from core.services import bundle_service, soak_service
from core.services.soak import sampling


class Command(BaseCommand):
    help = "Read-only probe of the soak evidence for a Probation bundle (starts nothing, persists nothing)."

    def add_arguments(self, parser):
        parser.add_argument("bundle_id", help="A Probation bundle id, for example BND-PROB-000001.")
        parser.add_argument("--no-live", action="store_true", help="Skip the read-only device queries (telemetry only).")
        parser.add_argument("--json", action="store_true", help="Print one JSON document.")

    def handle(self, *args, **options):
        bundle = bundle_service.get_bundle(options["bundle_id"])
        if bundle is None:
            raise CommandError("No such bundle.")
        now = timezone.now()
        start = soak_service.check_soak_start(bundle)
        document = {"bundle_id": bundle.bundle_id, "kind": bundle.kind, "probed_at": now.isoformat(), "start_eligible": start.eligible,
                    "start_blockers": [{"code": b["code"], "message": b["message"]} for b in start.blockers], "policy": soak_service.current_policy().to_dict()}
        if bundle.kind == "PROBATION" and start.integrity is not None and start.integrity.ok and not start.interference:
            sample = sampling.collect(bundle, now=now, live_reads=not options["no_live"])
            document["sample"] = {
                "result": sample.result, "expected_state_result": sample.expected_state_result, "telemetry_freshness": sample.telemetry_freshness,
                "monitoring_state": sample.monitoring_state, "device_health": sample.device_health, "counts": sample.counts,
                "findings": sample.findings, "devices": sample.evidence.get("devices", {}),
            }
        if options["json"]:
            self.stdout.write(json.dumps(document, indent=2, sort_keys=True, default=str))
            return
        self.stdout.write(f"{bundle.bundle_id} ({bundle.kind}): a soak {'CAN' if start.eligible else 'can NOT'} start now")
        for row in document["start_blockers"]:
            self.stdout.write(f"  blocker {row['code']}: {row['message']}")
        sample = document.get("sample")
        if sample:
            self.stdout.write(f"  evidence sample would be {sample['result']}: expected state {sample['expected_state_result']}, "
                              f"telemetry {sample['telemetry_freshness']}, monitoring {sample['monitoring_state']}")
            for name, facts in sorted(sample["devices"].items()):
                self.stdout.write(f"    {name}: telemetry {facts['freshness']} ({facts['age_seconds']}s), cpu {facts['cpu_percent']}, memory {facts['memory_percent']}, live {facts['live']}")
            for finding in sample["findings"][:10]:
                self.stdout.write(f"    finding {finding.get('class')}: {finding.get('device', '')} {finding.get('check_code')} {finding.get('message', '')}")
