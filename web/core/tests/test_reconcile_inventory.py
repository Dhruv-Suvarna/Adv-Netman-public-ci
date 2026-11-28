"""Read-only inventory/registry reconciliation: idempotence, identity preservation, exclusions, fail-closed cases."""

from __future__ import annotations

from io import StringIO
from unittest import mock

from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import DatabaseError
from django.test import TestCase

from core import models
from core.services.devices import reconciliation as rec
from core.tests.helpers import lifecycle as L


def by_name(report):
    return {r["name"]: r for r in report["devices"]}


class ReconciliationTests(TestCase):
    def snapshot(self):
        return (list(models.ManagedDevice.objects.order_by("pk").values()), models.DeviceLifecycleEvent.objects.count()
                if hasattr(models, "DeviceLifecycleEvent") else 0, models.ManagementPath.objects.count())

    def test_empty_registry_lists_every_eligible_original_and_excludes_r5(self):
        report = rec.build_report()
        self.assertEqual(report["missing_eligible"], ["R1", "R2", "R3", "R4", "S1", "S2", "S3", "S4", "mgmt_swt"])
        self.assertEqual(report["excluded"], ["R5"])
        rows = by_name(report)
        self.assertNotIn("H1", rows)
        self.assertFalse(report["admission_granted_any"])
        self.assertTrue(all(r["admission_granted"] is False for r in report["devices"]))
        self.assertIn("NO_LIFECYCLE_ROW", rows["R1"]["evidence"]["gaps"])

    def test_read_only_and_idempotent(self):
        L.adopt("S1")
        before = self.snapshot()
        first, second = rec.build_report(), rec.build_report()
        self.assertEqual(first["digest"], second["digest"])
        self.assertEqual(before, self.snapshot())
        call_command("nmas_reconcile_inventory", stdout=StringIO())
        self.assertEqual(before, self.snapshot())

    def test_adopted_legacy_identity_preserved_and_gaps_exposed(self):
        L.adopt("S1")
        row = models.ManagedDevice.objects.get(name="S1")
        report = rec.build_report()
        s1 = by_name(report)["S1"]
        self.assertEqual(s1["classification"], rec.REGISTERED)
        self.assertNotIn("S1", report["missing_eligible"])
        self.assertEqual(s1["lifecycle"]["device_id"], row.device_id)
        self.assertEqual(s1["lifecycle"]["admission_state"], "LEGACY_PREEXISTING")
        self.assertEqual(s1["lifecycle"]["identity_state"], "UNVERIFIED")
        for gap in ("IDENTITY_UNVERIFIED", "NO_APPROVED_MANAGEMENT_PATH", "NO_BROKER_REFERENCE", "NO_HOST_KEY_PIN",
                    "NO_INDEPENDENT_IDENTITY_APPROVAL"):
            self.assertIn(gap, s1["evidence"]["gaps"])
        self.assertFalse(s1["admission_granted"])
        self.assertEqual(models.ManagedDevice.objects.get(name="S1").device_id, row.device_id)

    def test_registered_new_device_without_authority_has_unknown_provenance(self):
        L.adopt("S1")
        L.register("NEW1")
        report = rec.build_report()
        new1 = by_name(report)["NEW1"]
        self.assertEqual(new1["classification"], rec.REGISTRY_ONLY)
        self.assertEqual(new1["provenance"], "UNKNOWN")
        self.assertEqual(new1["current_management_status"], "UNKNOWN")
        self.assertEqual(new1["lifecycle"]["admission_state"], "NOT_ADMITTED")
        self.assertEqual(new1["scope"], "NOT_MANAGED_YET")
        self.assertNotIn("NEW1", report["missing_eligible"])

    def test_registry_row_for_excluded_host_is_conflict(self):
        L.adopt("S1")
        models.ManagedDevice.objects.filter(name="S1").update(name="R5")   # simulate a stray row for an excluded host
        r5 = by_name(rec.build_report())["R5"]
        self.assertEqual(r5["classification"], rec.CONFLICT)
        self.assertIn("EXCLUDED_HOST_HAS_REGISTRY_ROW", r5["conflicts"])

    def test_platform_mismatch_is_conflict_not_rewritten(self):
        L.adopt("S1")
        models.ManagedDevice.objects.filter(name="S1").update(platform=models.Platform.UBUNTU_FRR)
        s1 = by_name(rec.build_report())["S1"]
        self.assertEqual(s1["classification"], rec.CONFLICT)
        self.assertIn("PLATFORM_MISMATCH", s1["conflicts"])
        self.assertEqual(models.ManagedDevice.objects.get(name="S1").platform, models.Platform.UBUNTU_FRR)

    def test_non_adopted_origin_shadowing_inventory_name_is_conflict(self):
        L.register("NEW1")
        models.ManagedDevice.objects.filter(name="NEW1").update(name="S1")
        s1 = by_name(rec.build_report())["S1"]
        self.assertEqual(s1["classification"], rec.CONFLICT)
        self.assertIn("NAME_COLLISION", s1["conflicts"])

    def test_adopted_device_removed_from_inventory_is_registry_only(self):
        L.adopt("S1")
        doc = {"lab_name": "no-such-lab", "management": {}, "network_devices": {}}
        s1 = by_name(rec.build_report(document=doc))["S1"]
        self.assertEqual(s1["classification"], rec.REGISTRY_ONLY)
        self.assertIn("NOT_IN_CURRENT_AUTHORITY", s1["conflicts"])
        self.assertEqual(s1["lifecycle"]["admission_state"], "LEGACY_PREEXISTING")

    def test_unreadable_registry_fails_closed(self):
        with mock.patch.object(rec.resolver.models.ManagedDevice.objects, "exclude", side_effect=DatabaseError("boom")):
            report = rec.build_report()
        self.assertFalse(report["registry_readable"])
        self.assertTrue(all(r["classification"] == rec.UNKNOWN for r in report["devices"]))
        self.assertEqual(report["missing_eligible"], [])
        self.assertTrue(report["conflicts"])
        with mock.patch.object(rec, "build_report", return_value=report), self.assertRaises(CommandError):
            call_command("nmas_reconcile_inventory", "--fail-on-gap", stdout=StringIO())

    def test_command_json_and_fail_on_gap(self):
        out = StringIO()
        call_command("nmas_reconcile_inventory", "--json", stdout=out)
        self.assertIn('"missing_eligible"', out.getvalue())
        with self.assertRaises(CommandError):
            call_command("nmas_reconcile_inventory", "--fail-on-gap", stdout=StringIO())

    def test_report_cannot_claim_live_or_production_evidence(self):
        report = rec.build_report()
        self.assertEqual(report["evidence_class"], "LOCAL")
        self.assertFalse(report["live_observation"])
        self.assertFalse(report["production_registry_validated"])
        self.assertIn("GATEWAY_ATTESTED", report["evidence_classes"])

    def test_netbox_reference_is_not_comparison(self):
        L.adopt("S1")
        models.ManagedDevice.objects.filter(name="S1").update(netbox_device_id=123)
        evidence = by_name(rec.build_report())["S1"]["evidence"]
        self.assertIn("NETBOX_NOT_CHECKED", evidence["gaps"])
        self.assertFalse(evidence["netbox_compared"])

    def test_second_registry_read_failure_discards_snapshot(self):
        original = rec.models.ManagedDevice.objects.exclude
        calls = 0
        def fail_second(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise DatabaseError("second read failed")
            return original(*args, **kwargs)
        with mock.patch.object(rec.models.ManagedDevice.objects, "exclude", side_effect=fail_second):
            report = rec.build_report()
        self.assertFalse(report["registry_readable"])
        self.assertEqual(report["missing_eligible"], [])
        self.assertTrue(report["has_gaps"])

    def test_historical_record_does_not_validate_current_identity(self):
        L.adopt("S1")
        with mock.patch.object(rec.lifecycle, "_linked_history", return_value={"commissioning": 1}):
            row = by_name(rec.build_report())["S1"]
        self.assertEqual(row["linked_history"], {"commissioning": 1})
        self.assertFalse(row["evidence"]["current_identity_validated"])
        self.assertEqual(row["provenance"], "UNKNOWN")

    def test_fail_on_gap_includes_evidence_only_gaps(self):
        report = rec.build_report()
        report.update(missing_eligible=[], conflicts=[], registry_readable=True, has_gaps=True)
        with mock.patch.object(rec, "build_report", return_value=report), self.assertRaises(CommandError):
            call_command("nmas_reconcile_inventory", "--fail-on-gap", stdout=StringIO())

    def test_resolver_conflict_cannot_be_classified_registered(self):
        L.adopt("S1")
        original = rec.resolver.resolve_all
        def conflicting(**kwargs):
            result = original(**kwargs)
            return rec.resolver.Resolution(result.targets, result.discrepancies + (
                rec.resolver.Discrepancy("TEST_CONFLICT", "S1", "conflicting source"),))
        with mock.patch.object(rec.resolver, "resolve_all", side_effect=conflicting):
            row = by_name(rec.build_report())["S1"]
        self.assertEqual(row["classification"], rec.CONFLICT)
        self.assertIn("TEST_CONFLICT", row["conflicts"])
