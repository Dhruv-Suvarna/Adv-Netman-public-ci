"""Thin composition of gNMI streaming telemetry and NETCONF verification into
one entry point, so master.py/modules/nmas.py has a single
`ensure_telemetry_infrastructure()` call for `--telemetry-only` and full-mode
runs, while keeping the gNMI and NETCONF implementations in their own
modules (modules/gnmi.py, modules/netconf.py) per AGENTS.md's IaC guidance.
"""
from __future__ import annotations

from modules.gnmi import ensure_gnmi_infrastructure
from modules.netconf import verify_netconf
from modules.nmas import verify_nmas


def ensure_telemetry_infrastructure(verbose=False):
    items = ensure_gnmi_infrastructure(verbose)
    verify_netconf(items)
    return verify_nmas(verbose)
