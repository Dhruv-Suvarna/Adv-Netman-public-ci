#!/usr/bin/env python3
"""Live Grafana provisioning, datasource, dashboard, query, and data checks."""
from __future__ import annotations

import sys
from pathlib import Path

BASE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(BASE))

from modules.grafana import verify_grafana  # noqa: E402
from modules.nmas import NmasError  # noqa: E402


if __name__ == "__main__":
    try:
        verify_grafana(verbose="--verbose" in sys.argv)
    except (NmasError, OSError, ValueError, KeyError) as exc:
        raise SystemExit(f"GRAFANA VERIFICATION FAIL: {exc}") from exc
