"""Test-governance closure for the V2 Phase 7-9 helpers the scenario suites only reached indirectly: the EOS block parser of
``decommission.eos`` (positive, direct), the Phase 9 option-82 ledger row without evidence and the Phase 8 fact reader without a
fact (negative, direct), and the Phase 7 evidence models' own methods."""

from __future__ import annotations

import hashlib
from types import SimpleNamespace

from django.test import SimpleTestCase, TestCase

from core import models
from core.services.capabilities import phase9_ledger as P
from core.services.capabilities.vocabulary import ClosureClass
from core.services.commissioning import outbox
from core.services.decommission import eos
from core.services.infrastructure import facts
from core.tests.helpers import decommission as H
from core.tests.helpers import lifecycle as L


class EosParserClosureTests(SimpleTestCase):
    def setUp(self):
        self.text = H.router_config()

    def test_eos_config_sections_and_paths_parses_configuration(self):
        found = eos.blocks(self.text)
        self.assertEqual(found["router ospf 1"][0], "router ospf 1")
        self.assertIn("   router-id 10.254.255.2", found["router ospf 1"])
        self.assertNotIn("end", found)
        self.assertEqual(eos.paths(found["ipv6 router ospf 1"]), ["ipv6 router ospf 1", "ipv6 router ospf 1 > router-id 10.254.255.2"])

    def test_eos_op_builds_a_transaction_operation(self):
        built = eos.op("k", "ADD", ["interface Ethernet1", "   shutdown"], ["interface Ethernet1", "   no shutdown"],
                       ["interface Ethernet1 > shutdown"], "Ethernet1 down")
        self.assertEqual(built, {"key": "k", "kind": "ADD", "lines": ["interface Ethernet1", "   shutdown"],
                                 "inverse": ["interface Ethernet1", "   no shutdown"], "paths": ["interface Ethernet1 > shutdown"],
                                 "description": "Ethernet1 down"})

    def test_eos_routing_and_ospf_processes_are_found(self):
        self.assertEqual(eos.routing_processes(self.text), ["router ospf 1", "ipv6 router ospf 1"])
        self.assertEqual(eos.ospf_processes(self.text), {"IPV4": "router ospf 1", "IPV6": "ipv6 router ospf 1"})

    def test_eos_interface_addresses_and_management_interfaces(self):
        self.assertEqual(eos.interface_address(["interface Ethernet5", "   ip address 10.254.70.2/24", "   ipv6 address 2001:db8::2/64"]),
                         ["10.254.70.2", "2001:db8::2"])
        management = eos.management_interfaces(self.text, [H.MGMT + "/24"])
        self.assertEqual(management, ["Ethernet5"])
        self.assertEqual(eos.production_interfaces(self.text, management), ["Ethernet1", "Ethernet2"])

    def test_eos_plan_exception_carries_code_and_bounded_detail(self):
        error = eos.PlanError("RESTORE_CONFLICT", "x" * 400)
        self.assertEqual((error.code, str(error), len(error.detail)), ("RESTORE_CONFLICT", "RESTORE_CONFLICT", 300))


class LedgerAndFactClosureTests(SimpleTestCase):
    def test_option82_row_without_evidence_is_not_implemented(self):
        row = P.option82_row(None)
        self.assertEqual(row["closure_class"], ClosureClass.NOT_IMPLEMENTED.value)
        self.assertIn("renderer", row["missing_stages"])
        self.assertFalse(row["stages"]["live"])

    def test_fact_of_missing_payload_fact_is_empty(self):
        self.assertEqual(facts.fact_of(SimpleNamespace(topic=outbox.FACT_TOPICS[0], payload=None)), "")
        self.assertEqual(facts.fact_of(SimpleNamespace(topic="NSOT_ADMITTED", payload={"fact": "IGNORED"})), outbox.ADMITTED)


class EvidenceModelClosureTests(TestCase):
    """The Phase 7 evidence rows, driven directly: identifiers, open-ness, immutability of snapshots and closed records."""

    def setUp(self):
        self.device = L.adopt("R1", role="router").device

    def snap(self, text="hostname R1\n", **overrides):
        values = {"device": self.device, "purpose": models.DeviceConfigSnapshot.Purpose.DECOMMISSION_BASELINE,
                  "platform": models.Platform.ARISTA_CEOS, "text": text, "sha256": hashlib.sha256(text.encode()).hexdigest(),
                  "state_digest": "d" * 64, "captured_by": "olivia", "source": "test"}
        values.update(overrides)
        row = models.DeviceConfigSnapshot(**values)
        row.save()
        return row

    def record(self, **overrides):
        row = models.DecommissionRecord(device=self.device, reason="retire", requested_by="olivia", **overrides)
        row.save()
        return row

    def restoration(self, record, **overrides):
        row = models.RestorationRecord(decommission=record, device=self.device, snapshot=record.baseline, requested_by="olivia", **overrides)
        row.save()
        return row

    def test_snapshot_save_assigns_the_snapshot_id(self):
        self.assertEqual(models.DeviceConfigSnapshot(text="").snapshot_id, "SNP-NEW")
        row = self.snap()
        self.assertEqual(row.snapshot_id, f"SNP-{row.pk:06d}")

    def test_snapshot_save_refuses_a_mismatched_digest_or_an_edit(self):
        with self.assertRaises(ValueError):
            self.snap(sha256="0" * 64)
        with self.assertRaises(ValueError):
            self.snap(platform="unknown")
        row = self.snap()
        row.text = "hostname R2\n"
        with self.assertRaises(ValueError):
            row.save()

    def test_snapshot_delete_keeps_the_evidence_row(self):
        row = self.snap()
        with self.assertRaises(ValueError):
            row.delete()
        self.assertTrue(models.DeviceConfigSnapshot.objects.filter(pk=row.pk).exists())

    def test_decommission_record_save_and_is_open_track_the_state(self):
        row = self.record()
        self.assertEqual(row.record_id, f"DCM-{row.pk:06d}")
        self.assertTrue(row.is_open)
        row.state = models.DecommissionState.CANCELLED
        row.save()
        self.assertFalse(models.DecommissionRecord.objects.get(pk=row.pk).is_open)

    def test_decommission_record_delete_keeps_the_history_row(self):
        row = self.record()
        with self.assertRaises(ValueError):
            row.delete()
        self.assertTrue(models.DecommissionRecord.objects.filter(pk=row.pk).exists())

    def test_restoration_record_save_assigns_the_record_id(self):
        record = self.record(state=models.DecommissionState.DECOMMISSIONED, baseline=self.snap())
        row = self.restoration(record)
        self.assertEqual(row.record_id, f"RST-{row.pk:06d}")
        row.state = models.RestorationState.CANCELLED
        row.save()
        self.assertEqual(models.RestorationRecord.objects.get(pk=row.pk).state, models.RestorationState.CANCELLED)

    def test_restoration_record_save_refuses_reopening_or_unknown_state(self):
        record = self.record(state=models.DecommissionState.DECOMMISSIONED, baseline=self.snap())
        with self.assertRaises(ValueError):
            self.restoration(record, state="NOPE")
        row = self.restoration(record, state=models.RestorationState.CANCELLED)
        row.state = models.RestorationState.REQUESTED
        with self.assertRaises(ValueError):
            row.save()

    def test_restoration_record_delete_keeps_the_history_row(self):
        record = self.record(state=models.DecommissionState.DECOMMISSIONED, baseline=self.snap())
        row = self.restoration(record)
        with self.assertRaises(ValueError):
            row.delete()
        self.assertTrue(models.RestorationRecord.objects.filter(pk=row.pk).exists())
