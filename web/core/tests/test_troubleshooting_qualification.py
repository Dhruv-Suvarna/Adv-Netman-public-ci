"""Per-device troubleshooting qualification (services/troubleshooting/qualification.py, adapters/nmas_providers.version).

QL-* tests are LOCAL tests: they prove fail-closed behaviour of the providers and the matrix over the tracked inventory/topology and the
lifecycle registry.  They are not fixture or production evidence and contact no device.
"""

from __future__ import annotations

import contextlib
import io
import json
import sys
import types
from unittest import mock

from django.core.management import call_command
from django.test import TestCase

import core.services.devices as devices_pkg
from core import models
from core.services.troubleshooting import deployment as dep
from core.services.troubleshooting import qualification as ql
from core.services.troubleshooting.adapters import nmas_providers as npv


_OBS = "core.services.devices.observations"


@contextlib.contextmanager
def _observations_module(mod):
    """Install ``mod`` (None = import fails) as ``core.services.devices.observations`` for both import paths.

    ``from core.services.devices import observations`` returns the *package attribute* once any earlier test has imported the real
    module, so patching ``sys.modules`` alone is order-dependent; the attribute is swapped (or removed) too and always restored."""
    missing = object()
    previous = devices_pkg.__dict__.get("observations", missing)
    with mock.patch.dict(sys.modules, {_OBS: mod}):
        if mod is None:
            devices_pkg.__dict__.pop("observations", None)
        else:
            devices_pkg.observations = mod
        try:
            yield
        finally:
            if previous is missing:
                devices_pkg.__dict__.pop("observations", None)
            else:
                devices_pkg.observations = previous


def fake_observations(fn):
    mod = types.ModuleType(_OBS)
    mod.observed_version = fn
    return _observations_module(mod)


def no_observations():
    return _observations_module(None)


class VersionProviderTests(TestCase):
    def test_QL01_version_provider_fails_closed(self):
        with no_observations():   # import raises ImportError
            self.assertIsNone(npv.version("R1"))
        with fake_observations(lambda n: "4.36.2F"):
            self.assertEqual(npv.version("R1", {"platform": "ceos"}), "4.36.2F")
        with fake_observations(lambda n: None):
            self.assertIsNone(npv.version("R1"))
        with fake_observations(lambda n: "unknown"):
            self.assertIsNone(npv.version("R1"))

        def boom(name):
            raise RuntimeError("secret detail")
        with fake_observations(boom):
            self.assertIsNone(npv.version("R1"))

    def test_QL02_recommended_binding_loads_without_problems_and_unknown_version_refuses(self):
        deps = dep.runtime_deps(dict(npv.RECOMMENDED_BINDING))
        self.assertEqual(list(deps.deployment_problems), [])
        with fake_observations(lambda n: None):
            self.assertNotEqual(deps.admission.resolve(["R1"])["R1"].state, "VERIFIED")


class CollectorQualificationTests(TestCase):
    def test_QL03_baselines_and_limits(self):
        ceos = ql.collector_qualification("ceos", "4.36.2F")
        self.assertEqual(ceos["status"], "BASELINE")
        keys = {c["key"] for c in ceos["read_only_commands"]}
        self.assertIn("interfaces", keys)
        self.assertNotIn("running_config", keys)
        frr = ql.collector_qualification("linux", "8.4.4")
        self.assertEqual(frr["status"], "BASELINE")
        self.assertTrue(all(isinstance(c["command"], str) for c in frr["read_only_commands"]))

    def test_QL04_unknown_or_foreign_versions_qualify_nothing_or_flag_limits(self):
        self.assertEqual(ql.collector_qualification("ceos", "")["read_only_commands"], [])
        self.assertEqual(ql.collector_qualification("ceos", "")["status"], "VERSION_UNKNOWN")
        newer = ql.collector_qualification("ceos", "5.1.0")
        self.assertEqual(newer["status"], "NON_BASELINE")
        self.assertTrue(any("version-gated" in x for x in newer["limits"]))
        self.assertEqual(ql.collector_qualification("srlinux", "24.10.1")["status"], "UNSUPPORTED_PLATFORM")


class MatrixTests(TestCase):
    def setUp(self):
        for cls in ("EosSession", "LinuxSession", "DockerEosSession", "SrLinuxSession", "IosXeSession"):
            p = mock.patch(f"core.services.health.live.{cls}", side_effect=AssertionError("no device may be contacted"))
            p.start()
            self.addCleanup(p.stop)

    def matrix(self):
        with no_observations():
            return ql.device_matrix(dict(npv.RECOMMENDED_BINDING))

    def test_QL05_classification_preserves_exclusions_and_never_invents_peers(self):
        rows = {r["device"]: r for r in self.matrix()["devices"]}
        self.assertEqual(rows["R5"]["classification"], ql.EXCLUDED)
        self.assertIsNone(rows["R5"]["admission"])
        for host in ("H1", "H2", "H3", "H4", "WebServer"):
            self.assertEqual(rows[host]["classification"], ql.HOST)
        for name in ("R1", "R2", "R3", "R4", "S1", "S2", "S3", "S4", "mgmt_swt"):
            self.assertEqual(rows[name]["classification"], ql.MANAGED)
        self.assertEqual(self.matrix()["counts"][ql.PEER], 0)

    def test_QL06_unknown_stays_unknown_and_nothing_is_admitted(self):
        for row in self.matrix()["devices"]:
            self.assertEqual(row["operational_state"], "UNKNOWN")
            if row["classification"] == ql.MANAGED:
                self.assertIsNone(row["observed_version"])
                self.assertFalse(row["admission"]["admitted"])
                self.assertEqual(row["collector"]["status"], "VERSION_UNKNOWN")
                self.assertTrue(row["gates"])
                self.assertTrue(any("observed OS version" in m for m in row["missing_evidence"]))
                self.assertIsNotNone(row["declared_baseline"])

    def test_QL07_no_containerlab_management_candidate_and_approved_failover_order(self):
        m = self.matrix()
        for row in m["devices"]:
            for cand in row["management"]["declared_candidates"]:
                self.assertTrue(cand["address"].startswith(("192.168.200.", "2001:db8:200:")), cand)
            self.assertEqual(row["management"]["production_failover_order"], ["DIRECT_OOB", "VLAN_ADJACENT_SWITCH", "ROUTED_VRF"])
            self.assertIn("CONTAINERLAB_MANAGEMENT", row["management"]["prohibited"])

    def test_QL08_observed_version_is_shown_but_does_not_admit(self):
        with fake_observations(lambda n: "4.36.2F"):
            rows = {r["device"]: r for r in ql.device_matrix(dict(npv.RECOMMENDED_BINDING))["devices"]}
        self.assertEqual(rows["R1"]["observed_version"], "4.36.2F")
        self.assertEqual(rows["R1"]["collector"]["status"], "BASELINE")
        self.assertFalse(rows["R1"]["admission"]["admitted"])        # unregistered / identity unverified still blocks
        self.assertIsNone(rows["H1"]["observed_version"])            # hosts are never queried

    def test_QL09_command_matrix_is_read_only_json(self):
        before = (models.ManagedDevice.objects.count(), models.DeviceObservation.objects.count())
        out = io.StringIO()
        call_command("troubleshooting_readiness", "--matrix", "--with-nmas-providers", stdout=out)
        data = json.loads(out.getvalue())
        self.assertEqual(data["version"], ql.MATRIX_VERSION)
        self.assertEqual((models.ManagedDevice.objects.count(), models.DeviceObservation.objects.count()), before)
