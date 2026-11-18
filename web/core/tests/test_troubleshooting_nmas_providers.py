"""Authoritative NMAS providers for troubleshooting admission (adapters/nmas_providers.py).

NP-* tests bind DeploymentAdmission to the real managed-device lifecycle registry and Maintenance Mode records.  Devices are adopted
through the real ``adopt_existing`` workflow (tracked inventory.yml), then moved between registry states.  No device is contacted.
"""

from __future__ import annotations

from unittest import mock

from django.test import TestCase, override_settings
from django.utils import timezone

from core import models
from core.services.devices import lifecycle as device_lifecycle
from core.services.devices import resolver
from core.services.maintenance_mode import lifecycle as mm
from core.services.troubleshooting import deployment as dep
from core.services.troubleshooting.adapters import nmas_providers as npv

P = "core.services.troubleshooting.adapters.nmas_providers"
OPERATOR = "nmas-test-operator"


def version_stub(device, entry):   # a stand-in for the missing authoritative version record, used only to reach the later gates
    return "4.36.2F"


def adopt(name="R1"):
    result = device_lifecycle.adopt_existing(name, role="router", actor=OPERATOR)
    assert result.ok, result
    return models.ManagedDevice.objects.get(name=name)


def set_row(row, **fields):
    """Move a registration to a state the lifecycle workflows can reach, through the registry's own versioned write primitive
    (the guarded ``update()`` refuses lifecycle fields outside core.services.devices.lifecycle)."""
    fresh = models.ManagedDevice.objects.get(pk=row.pk)
    assert models.ManagedDevice.objects.compare_and_swap(fresh.pk, fresh.version, **fields) == 1


VERIFIED = {"identity_state": models.IdentityVerificationState.VERIFIED, "identity_verified_by": OPERATOR,
            "identity_verified_at": timezone.now(), "verified_serial": "TESTSERIAL01"}


def admission(devices, *, version=version_stub):
    return dep.DeploymentAdmission(inventory=npv.inventory, lifecycle=npv.lifecycle, version=version).resolve(devices)


class NmasProviderTests(TestCase):
    def setUp(self):
        for cls in ("EosSession", "LinuxSession", "DockerEosSession", "SrLinuxSession", "IosXeSession"):
            patcher = mock.patch(f"core.services.health.live.{cls}", side_effect=AssertionError("no device may be contacted"))
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_NP01_inventory_is_the_engines_device_dictionary(self):
        inv = npv.inventory()
        self.assertEqual(inv, resolver.engine_devices())
        self.assertIn("R1", inv)

    def test_NP02_unregistered_inventory_device_is_refused_not_assumed_healthy(self):
        life = npv.lifecycle("R1")
        self.assertEqual((life["state"], life["withdrawn"]), ("UNREGISTERED", False))
        a = admission(["R1"])["R1"]
        self.assertEqual(a.state, "UNREGISTERED")
        self.assertIn("not admitted", a.reason)

    def test_NP03_adopted_but_identity_unverified_is_refused(self):
        row = adopt()
        self.assertEqual((row.lifecycle_state, row.admission_state), (models.DeviceLifecycleState.IN_SERVICE,
                                                                       models.ProductionAdmissionState.LEGACY_PREEXISTING))
        self.assertEqual(npv.lifecycle("R1")["state"], "IDENTITY_UNVERIFIED")
        self.assertEqual(admission(["R1"])["R1"].state, "IDENTITY_UNVERIFIED")
        set_row(row, identity_state=models.IdentityVerificationState.MISMATCH)
        self.assertEqual(admission(["R1"])["R1"].state, "IDENTITY_MISMATCH")

    def test_NP04_verified_in_service_device_is_admitted_only_with_an_authoritative_version(self):
        set_row(adopt(), **VERIFIED)
        life = npv.lifecycle("R1")
        self.assertEqual((life["state"], life["source"]), ("IN_SERVICE", "lifecycle-registry"))
        ok = admission(["R1"])["R1"]
        self.assertEqual((ok.state, ok.os_version, ok.source), ("VERIFIED", "4.36.2F", "inventory+lifecycle+version"))
        # NMAS has no authoritative per-device version record: without a version provider every device stays refused
        self.assertEqual(admission(["R1"], version=None)["R1"].state, "VERSION_UNKNOWN")

    def test_NP05_withdrawn_pending_and_retired_registrations_are_refused(self):
        row = adopt()
        set_row(row, **VERIFIED, admission_state=models.ProductionAdmissionState.WITHDRAWN)
        self.assertEqual((admission(["R1"])["R1"].state, npv.lifecycle("R1")["withdrawn"]), ("WITHDRAWN", True))
        set_row(row, admission_state=models.ProductionAdmissionState.LEGACY_PREEXISTING,
                lifecycle_state=models.DeviceLifecycleState.DECOMMISSION_PENDING)
        self.assertEqual(admission(["R1"])["R1"].state, "DECOMMISSION_PENDING")
        set_row(row, lifecycle_state=models.DeviceLifecycleState.DECOMMISSIONED)
        life = npv.lifecycle("R1")
        self.assertEqual((life["state"], life["withdrawn"]), ("DECOMMISSIONED", True))
        self.assertEqual(admission(["R1"])["R1"].state, "WITHDRAWN")

    def test_NP06_not_admitted_to_production_is_refused(self):
        set_row(adopt(), **VERIFIED,
                admission_state=models.ProductionAdmissionState.NOT_ADMITTED)
        self.assertEqual(admission(["R1"])["R1"].state, "NOT_ADMITTED")

    def test_NP07_active_maintenance_is_flagged_but_read_only_diagnosis_continues(self):
        set_row(adopt(), **VERIFIED)
        models.MaintenanceRecord.objects.create(device_name="R1", state=mm.ACTIVE, requested_by=OPERATOR, reason="test window",
                                                requested_at=timezone.now(), requested_duration_seconds=3600, snapshot={})
        a = admission(["R1"])["R1"]
        self.assertEqual((a.state, a.maintenance), ("VERIFIED", True))
        models.MaintenanceRecord.objects.filter(device_name="R1").update(state=mm.RESTORED)
        self.assertFalse(admission(["R1"])["R1"].maintenance)

    def test_NP08_unknown_name_is_refused_before_lifecycle(self):
        self.assertEqual(admission(["NOT-A-DEVICE"])["NOT-A-DEVICE"].state, "UNKNOWN")

    @override_settings(NMAS_TS_DEPLOYMENT={"inventory": f"{P}.inventory", "lifecycle_provider": f"{P}.lifecycle"},
                       NMAS_TS_RUNTIME_FACTORY=dep.FACTORY_PATH, TROUBLESHOOTING_RUNTIME_DEPS=dep.FACTORY_PATH)
    def test_NP09_settings_binding_resolves_through_the_shared_factory(self):
        set_row(adopt(), **VERIFIED)
        deps = dep.runtime_deps()
        self.assertEqual(dep.consistency_problems(), [])
        got = deps.admission.resolve(["R1", "R2"])
        # lifecycle is authoritative and bound; version is not configured, so nothing is admitted for probing
        self.assertEqual(got["R1"].state, "VERSION_UNKNOWN")
        self.assertEqual(got["R2"].state, "UNREGISTERED")
