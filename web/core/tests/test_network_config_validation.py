"""Version 2 Phase 2 network-configuration validation (not hosted Tier-3)."""

from django.test import TestCase
from django.utils import timezone

from core import models
from core.services import network_config_validation as ncv, workbench_service
from core.tests.helpers.validation import Dev, make_sources, nb_ip, nb_prefix, netbox_data


def sources(*, managed=("R1",), prefixes=(), addresses=()):
    return make_sources(netbox=netbox_data(
        managed_devices=list(managed), prefixes=list(prefixes), ip_addresses=list(addresses),
    ))


class CandidateNetworkConfigValidationTests(TestCase):
    def test_valid_candidate_persists_attributed_evidence_and_capability_evidence(self):
        dev = Dev(models.Change.objects.create(change_id="CHG-20261002-0001", title="valid"), "R1")
        interface = dev.iface("Ethernet1")
        dev.address(interface, "192.0.2.1/24")

        run = ncv.validate_candidate(
            dev.change, actor="alice",
            sources=sources(prefixes=[nb_prefix("192.0.2.0/24")]),
        )

        self.assertEqual(run.status, models.NetworkConfigValidationStatus.PASS)
        self.assertEqual(run.created_by, "alice")
        self.assertTrue(run.checks)
        self.assertEqual(
            models.AuditEvent.objects.filter(
                event_type=models.AuditEventType.NETWORK_CONFIG_VALIDATED,
                object_id=str(run.run_id), actor="alice",
            ).count(),
            1,
        )
        self.assertTrue(models.CapabilityEvidence.objects.filter(
            platform=models.Platform.ARISTA_CEOS,
            feature="interface.ROUTED_PHYSICAL",
            axis="CONFIG_VALIDATION",
            status="VERIFIED",
            recorded_by="alice",
        ).exists())

    def test_unrepresented_valid_address_warns_but_authoritative_conflict_blocks(self):
        warning_dev = Dev(models.Change.objects.create(change_id="CHG-20261002-0002", title="warning"), "R1")
        warning_iface = warning_dev.iface("Ethernet1")
        warning_dev.address(warning_iface, "203.0.113.1/24")
        warning = ncv.validate_candidate(
            warning_dev.change,
            sources=sources(prefixes=[nb_prefix("192.0.2.0/24")]),
        )
        self.assertEqual(warning.status, models.NetworkConfigValidationStatus.WARNING)
        self.assertIn("NETBOX_PREFIX_RELATIONSHIP", [row["check"] for row in warning.warnings])

        blocked_dev = Dev(models.Change.objects.create(change_id="CHG-20261002-0003", title="blocked"), "R1")
        blocked_iface = blocked_dev.iface("Ethernet1")
        blocked_dev.address(blocked_iface, "192.0.2.1/24")
        blocked = ncv.validate_candidate(
            blocked_dev.change,
            sources=sources(
                prefixes=[nb_prefix("192.0.2.0/24")],
                addresses=[nb_ip("192.0.2.1/24", device="R2", interface="Ethernet1")],
            ),
        )
        self.assertEqual(blocked.status, models.NetworkConfigValidationStatus.BLOCKED)
        conflicts = next(row for row in blocked.checks if row["check"] == "ADDRESS_CONFLICTS")
        self.assertEqual(conflicts["status"], "BLOCKED")

    def test_duplicate_address_and_unmanaged_target_block(self):
        duplicate_dev = Dev(models.Change.objects.create(change_id="CHG-20261002-0004", title="duplicate"), "R1")
        duplicate_dev.address(duplicate_dev.iface("Ethernet1"), "192.0.2.1/24")
        duplicate_dev.address(duplicate_dev.iface("Ethernet2"), "192.0.2.1/24")
        duplicate = ncv.validate_candidate(
            duplicate_dev.change,
            sources=sources(prefixes=[nb_prefix("192.0.2.0/24")]),
        )
        self.assertEqual(duplicate.status, models.NetworkConfigValidationStatus.BLOCKED)

        unmanaged_dev = Dev(models.Change.objects.create(change_id="CHG-20261002-0005", title="scope"), "R5")
        unmanaged = ncv.validate_candidate(unmanaged_dev.change, sources=sources(managed=("R1",)))
        self.assertEqual(unmanaged.status, models.NetworkConfigValidationStatus.BLOCKED)
        scope = next(row for row in unmanaged.checks if row["check"] == "MANAGED_SCOPE")
        self.assertEqual(scope["evidence"]["outside_scope"], ["R5"])


class RunningNetworkConfigValidationTests(TestCase):
    def test_on_demand_running_validation_blocks_vlan200_dhcp_and_duplicates_without_remediation(self):
        text = """hostname R1
interface Vlan200
   ip address dhcp
interface Ethernet1
   ip address 192.0.2.1/24
interface Ethernet2
   ip address 192.0.2.1/24
"""
        snapshot = models.RunningConfigSnapshot.objects.create(
            device_name="R1", platform=models.Platform.ARISTA_CEOS,
            digest="a" * 64, text=text, line_count=6, source="test", captured_at=timezone.now(),
        )
        run = ncv.validate_running(snapshot, actor="bob", sources=sources())
        self.assertEqual(run.status, models.NetworkConfigValidationStatus.BLOCKED)
        self.assertEqual(run.created_by, "bob")
        self.assertFalse(run.semantic_result["auto_remediation"])
        states = {row["check"]: row["status"] for row in run.checks}
        self.assertEqual(states["VLAN200_PROTECTION"], "BLOCKED")
        self.assertEqual(states["ADDRESS_CONFLICTS"], "BLOCKED")
        with self.assertRaises(ValueError):
            run.save()
        with self.assertRaises(ValueError):
            run.delete()


class WorkbenchRevisionArchiveTests(TestCase):
    def test_revision_clones_accepted_state_and_archive_retains_history(self):
        change = models.Change.objects.create(
            change_id="CHG-20261002-0006", title="draft",
            metadata={"workflow": models.ChangeWorkflow.CONFIGURATION_CHANGES},
        )
        dev = Dev(change, "R1")
        dev.iface("Loopback102", kind="LOOPBACK", description="phase2")
        old = dev.revision

        revisions = workbench_service.revise_change(change=change, actor="alice", title="revised")
        new = revisions[0]
        self.assertEqual((old.revision, new.revision), (1, 2))
        self.assertEqual(new.metadata["revised_from_revision"], 1)
        self.assertEqual(new.sections, old.sections)
        self.assertEqual(new.field_states.count(), old.field_states.count())
        self.assertEqual(change.device_intents.get().latest_revision(), new)

        workbench_service.archive_change(change=change, actor="alice")
        change.refresh_from_db()
        self.assertEqual(change.metadata["archived_by"], "alice")
        self.assertTrue(models.AuditEvent.objects.filter(
            event_type=models.AuditEventType.CHANGE_ARCHIVED, change=change, actor="alice"
        ).exists())
        self.assertNotIn(change, workbench_service.workflow_changes(models.ChangeWorkflow.CONFIGURATION_CHANGES))
