"""Read-only validation of host-key pin evidence (``core.services.devices.host_key_pins``).

    manage.py host_key_pin_check --evidence <file.json> --enroller <name> [--claimed-pin SHA256:...] [--json]

Computes the pin from the captured device-side public key, checks channel independence, collector/enroller separation and freshness,
and compares the result with every pin NMAS already holds for the device.  It never writes, connects or approves anything; the
validated pin is then recorded only through the existing route it prints (Management page path registration + independent
approval for cEOS; a reviewed inventory change for Ubuntu/FRR).  Exit status is non-zero unless the evidence is acceptable AND no
registered pin conflicts with it.
"""

from __future__ import annotations

import json
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError

from core.services.devices import host_key_pins, resolver

MAX_EVIDENCE_BYTES = 64 * 1024


class Command(BaseCommand):
    help = "Validate host-key pin evidence captured over an independent device-side channel (read-only)."

    def add_arguments(self, parser):
        parser.add_argument("--evidence", required=True)
        parser.add_argument("--enroller", required=True, help="person validating the capture (must not be its collector)")
        parser.add_argument("--claimed-pin", default="", dest="claimed_pin")
        parser.add_argument("--json", action="store_true")

    def handle(self, *args, **opts):
        path = Path(opts["evidence"])
        try:
            if path.stat().st_size > MAX_EVIDENCE_BYTES:
                raise CommandError("EVIDENCE_INVALID: evidence file too large")
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            raise CommandError("EVIDENCE_INVALID: evidence file unreadable or not JSON") from None
        verdict = host_key_pins.validate_evidence(document, enroller=opts["enroller"], claimed_pin=opts["claimed_pin"])
        target = resolver.resolve(str(document.get("device") or "")) if isinstance(document, dict) else None
        report = {"ok": verdict.ok and not verdict.registered.get("conflict"), "codes": verdict.codes, "pin": verdict.pin,
                  "key_type": verdict.key_type, "evidence_sha256": verdict.evidence_digest, "registered": verdict.registered,
                  "enrollment_route": host_key_pins.enrollment_route(target.platform) if target else ""}
        if verdict.registered.get("conflict"):
            report["codes"] = [*verdict.codes, "REGISTERED_PIN_CONFLICT"]
        if opts["json"]:
            self.stdout.write(json.dumps(report, indent=2, sort_keys=True))
        else:
            for key in ("ok", "codes", "pin", "key_type", "evidence_sha256", "registered", "enrollment_route"):
                self.stdout.write(f"  {key}: {report[key]}")
        if not report["ok"]:
            raise CommandError("pin evidence NOT acceptable: " + ("; ".join(report["codes"]) or "unknown"))
