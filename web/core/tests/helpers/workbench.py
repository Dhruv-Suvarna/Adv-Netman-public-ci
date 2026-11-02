"""Automation-workbench test helpers: a fake NetBox management scope (no test ever reads NetBox)."""
from __future__ import annotations

from unittest import mock

from core.services.config_workbench import scope

# What NetBox marks IaC-managed in the frozen Lab-1 baseline (R5 / WebServer are unmanaged).
LAB_MANAGED = ("R1", "R2", "R3", "R4", "S1", "S2", "S3", "S4", "mgmt_swt")


def managed(names=LAB_MANAGED):
    return lambda: {"status": "available", "source": "NETBOX", "data": sorted(names)}


def unavailable():
    return {"status": "unavailable", "source": "NETBOX", "message": "NetBox temporarily unavailable (ConnectionError).", "data": []}


def use_scope(testcase, provider=None) -> None:
    """Patch the workbench's NetBox scope read for the duration of ``testcase``."""
    patcher = mock.patch.object(scope, "NETBOX_MANAGED", provider or managed())
    patcher.start()
    testcase.addCleanup(patcher.stop)
