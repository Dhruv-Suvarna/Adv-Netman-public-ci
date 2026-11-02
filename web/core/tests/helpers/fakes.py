"""Shared fakes for external sources.

Unit/view tests must never reach a real NetBox, device, Grafana, or Git
server: an unmocked call turns a millisecond test into a multi-second network
wait and makes the suite depend on the lab being up.  Import a fake from here
rather than re-inventing one per test module.
"""

from __future__ import annotations

from unittest.mock import patch


def netbox_unreachable():
    """Patch context: every ``nsot_netbox`` adapter call degrades to ``unavailable`` immediately.

    Each adapter function builds its client through ``nsot_netbox._client`` and
    converts any exception into an "unavailable" result, so one patch point
    covers the whole NSOT read surface without a real connection attempt.
    """
    return patch("core.services.nsot_netbox._client", side_effect=RuntimeError("NetBox unreachable (test fake)"))
