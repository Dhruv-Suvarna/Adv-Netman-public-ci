#!/usr/bin/env python3
"""Read-only Phase-23 IPAM evidence; exits nonzero on any coverage conflict."""
from __future__ import annotations

import json
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(BASE))

from modules import ipam_evidence  # noqa: E402
from modules import netbox_ipam as nb  # noqa: E402


def main() -> int:
    try:
        evidence = ipam_evidence.collect_live_evidence()
    except nb.NetboxError as exc:
        print(json.dumps({"status": "FAIL", "error": exc.__class__.__name__}, sort_keys=True))
        return 1
    failures = ipam_evidence.validate(evidence)
    print(json.dumps({"status": "FAIL" if failures else "PASS", "failures": failures, "evidence": evidence}, sort_keys=True))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
