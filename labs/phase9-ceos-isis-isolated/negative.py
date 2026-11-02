"""Non-mutating live negative controls for the disposable cEOS SSH path."""

import json
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(ROOT / "web")]
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")

import django  # noqa: E402

django.setup()

from core.services.capabilities import fixture_ceos_ssh as transport  # noqa: E402


def main():
    if not os.environ.get("NMAS_CAP_CEOS_PASSWORD"):
        raise SystemExit("NMAS_CAP_CEOS_PASSWORD is required in the environment.")
    actual_run = transport._run

    def wrong_key(argv, **kwargs):
        if argv[-1] == "show management ssh hostkey ed25519 public":
            return subprocess.CompletedProcess(argv, 0, "ssh-ed25519 d3Jvbmc=\n", "")
        return actual_run(argv, **kwargs)

    def wrong_route(argv, **kwargs):
        if argv[:3] == ["ip", "route", "get"]:
            return subprocess.CompletedProcess(argv, 0, "172.31.248.11 dev eth0 src 192.0.2.1\n", "")
        return actual_run(argv, **kwargs)

    checks = {}
    for name, replacement in (("wrong_pinned_host_key", wrong_key), ("wrong_management_route", wrong_route)):
        try:
            with patch.object(transport, "_run", side_effect=replacement):
                session = transport.FixtureCeosSsh()
                session.close()
            checks[name] = False
        except Exception:  # pylint: disable=broad-exception-caught  # any transport exception is an expected refusal
            checks[name] = True
    if not all(checks.values()):
        raise RuntimeError(f"IS-IS management negative control failed: {checks}")
    path = ROOT / "docs/evidence/v2-phase9-closure/ceos-isis/negative-transport.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"schema": "nmas.v2.phase9.ceos-isis-negative/1", "device_mutated": False,
                                "checks": checks}, indent=2, sort_keys=True) + "\n")
    print(json.dumps(checks, sort_keys=True))


if __name__ == "__main__":
    main()
