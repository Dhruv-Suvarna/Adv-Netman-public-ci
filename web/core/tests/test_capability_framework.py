"""Binary Phase-4 capability evidence, precedence, command, resolution, and UI."""

from io import StringIO
from unittest import mock

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase
from django.urls import reverse

from core import models
from core.services import platform_drivers
from core.services.capabilities import evidence, features, registry
from core.services.capabilities.axes import Axis, EvidenceKind, EvidenceStatus, EvidenceType, Summary, TerminalStatus
from core.services.capabilities.live_verify import LiveVerification
from core.services.execution import capability as execution_capability


class CatalogueTests(TestCase):
    def test_catalogue_covers_every_registry_key(self):
        keys = features.by_key()
        self.assertEqual(len(keys), len(features.catalogue()), "feature keys are unique")
        for protocol in platform_drivers.RoutingProtocol:
            self.assertIn(f"routing.{protocol.value}", keys)
        for kind in platform_drivers.PLATFORM_CAPABILITIES["arista_ceos"]:
            self.assertIn(f"interface.{kind}", keys)
        self.assertEqual(features.platforms(), tuple(platform_drivers.PLATFORM_DRIVERS))

    def test_every_cell_has_every_axis(self):
        for platform in features.platforms():
            for feature in features.catalogue():
                self.assertEqual(set(registry.registry_axes(platform, feature)), set(Axis), (platform, feature.key))


class DerivationTests(TestCase):
    def test_renderer_support_never_implies_live_support(self):
        # IOS XR renders but has no executor; the IOS XE executor is never inherited by it.
        rec = registry.capability_record("cisco_iosxr", "interface.LOOPBACK")
        self.assertEqual(rec.axes[Axis.RENDERER].status, EvidenceStatus.IMPLEMENTED)
        self.assertEqual(rec.axes[Axis.LIVE_WRITE].status, EvidenceStatus.NOT_IMPLEMENTED)
        self.assertEqual(rec.summary, Summary.RENDER_ONLY)

    def test_live_axes_follow_the_execution_registry(self):
        for platform in features.platforms():
            for feature in features.catalogue():
                rec = registry.capability_record(platform, feature, evidence={})
                if not feature.object_type or rec.axes[Axis.RENDERER].status != EvidenceStatus.IMPLEMENTED:
                    self.assertNotEqual(rec.axes[Axis.LIVE_WRITE].status, EvidenceStatus.IMPLEMENTED, (platform, feature.key))
                    continue
                cap = execution_capability.capability_for(platform, feature.object_type)
                self.assertEqual(rec.axes[Axis.LIVE_WRITE].status == EvidenceStatus.IMPLEMENTED, cap.apply == "SUPPORTED", (platform, feature.key))

    def test_platforms_without_executor_are_never_live(self):
        for platform in ("cisco_iosxr", "sonic"):
            for feature in features.catalogue():
                self.assertNotIn(registry.capability_record(platform, feature, evidence={}).summary,
                                 (Summary.LIVE_IMPLEMENTED, Summary.LIVE_VERIFIED), (platform, feature.key))

    def test_srlinux_and_iosxe_are_live_only_for_what_their_executors_can_invert(self):
        for platform in ("nokia_srlinux", "cisco_c8000v_iosxe"):
            live = {feature.key for feature in features.catalogue()
                    if registry.capability_record(platform, feature, evidence={}).summary == Summary.LIVE_IMPLEMENTED}
            self.assertEqual(live, {"interface.LOOPBACK", "interface.MANAGEMENT", "interface.ROUTED_PHYSICAL",
                                    "interface.SUBINTERFACE", "routing.STATIC_IPV4", "routing.STATIC_IPV6"}, platform)

    def test_ceos_routed_interface_has_phase2_config_validation_but_live_is_unverified(self):
        rec = registry.capability_record("arista_ceos", "interface.ROUTED_PHYSICAL")
        self.assertEqual(rec.summary, Summary.LIVE_IMPLEMENTED)
        self.assertEqual(rec.axes[Axis.RUNTIME_VALIDATION].status, EvidenceStatus.NOT_ASSESSED)
        self.assertEqual(rec.axes[Axis.CONFIG_VALIDATION].status, EvidenceStatus.IMPLEMENTED)
        self.assertEqual(rec.status, TerminalStatus.UNSUPPORTED)

    def test_ospf_process_is_not_falsely_marked_post_write_verifiable(self):
        rec = registry.capability_record("arista_ceos", "routing.OSPFV2", evidence={})
        self.assertEqual(rec.axes[Axis.LIVE_WRITE].status, EvidenceStatus.IMPLEMENTED)
        self.assertEqual(rec.axes[Axis.LIVE_POST_WRITE_VALIDATION].status, EvidenceStatus.NOT_IMPLEMENTED)


class EvidenceTests(TestCase):
    def record(self, axis, status, source="test", evidence_type=None):
        if evidence_type is None:
            evidence_type = EvidenceType.LIVE if axis in {
                Axis.LIVE_READ, Axis.LIVE_WRITE, Axis.LIVE_POST_WRITE_VALIDATION, Axis.COMPENSATION,
                Axis.RUNTIME_VALIDATION,
            } else EvidenceType.STATIC
        return evidence.record_evidence(platform="arista_ceos", feature="interface.ROUTED_PHYSICAL", axis=axis, status=status,
                                        source=source, recorded_by="phase4-runner", evidence_type=evidence_type)

    def test_empirical_evidence_upgrades_and_downgrades(self):
        self.record(Axis.LIVE_WRITE, EvidenceStatus.VERIFIED)
        self.assertEqual(registry.capability_record("arista_ceos", "interface.ROUTED_PHYSICAL").summary, Summary.LIVE_IMPLEMENTED)
        self.record(Axis.LIVE_POST_WRITE_VALIDATION, EvidenceStatus.VERIFIED, source="run-42")
        rec = registry.capability_record("arista_ceos", "interface.ROUTED_PHYSICAL")
        self.assertEqual(rec.summary, Summary.LIVE_VERIFIED)
        self.assertEqual((rec.axes[Axis.LIVE_WRITE].kind, rec.axes[Axis.LIVE_WRITE].registry_status),
                         (EvidenceKind.EMPIRICAL, EvidenceStatus.IMPLEMENTED))
        self.record(Axis.COMPENSATION, EvidenceStatus.FAILED)
        self.assertEqual(registry.capability_record("arista_ceos", "interface.ROUTED_PHYSICAL").summary, Summary.LIVE_FAILED)

    def test_newest_evidence_wins(self):
        self.record(Axis.AUTOMATED_TESTS, EvidenceStatus.FAILED)
        self.record(Axis.AUTOMATED_TESTS, EvidenceStatus.VERIFIED)
        rec = registry.capability_record("arista_ceos", "interface.ROUTED_PHYSICAL")
        self.assertEqual(rec.axes[Axis.AUTOMATED_TESTS].status, EvidenceStatus.VERIFIED)

    def test_stronger_evidence_wins_over_newer_weaker_evidence(self):
        self.record(Axis.AUTOMATED_TESTS, EvidenceStatus.FAILED, evidence_type=EvidenceType.FIXTURE)
        self.record(Axis.AUTOMATED_TESTS, EvidenceStatus.VERIFIED, evidence_type=EvidenceType.STATIC)
        rec = registry.capability_record("arista_ceos", "interface.ROUTED_PHYSICAL")
        self.assertEqual(rec.axes[Axis.AUTOMATED_TESTS].status, EvidenceStatus.FAILED)
        self.assertEqual(rec.axes[Axis.AUTOMATED_TESTS].evidence_type, EvidenceType.FIXTURE)

    def test_only_complete_empirical_workflow_resolves_supported(self):
        for axis in (Axis.AUTOMATED_TESTS, Axis.LIVE_READ, Axis.LIVE_WRITE, Axis.LIVE_POST_WRITE_VALIDATION,
                     Axis.COMPENSATION, Axis.RUNTIME_VALIDATION):
            self.record(axis, EvidenceStatus.VERIFIED,
                        evidence_type=EvidenceType.FIXTURE if axis == Axis.AUTOMATED_TESTS else EvidenceType.LIVE)
        self.assertEqual(registry.capability_record("arista_ceos", "interface.ROUTED_PHYSICAL").status,
                         TerminalStatus.SUPPORTED)

    def test_evidence_validation_and_audit(self):
        for bad in ({"status": EvidenceStatus.IMPLEMENTED}, {"platform": "junos"}, {"feature": "interface.NOPE"}, {"source": " "}):
            kwargs = {"platform": "arista_ceos", "feature": "interface.ROUTED_PHYSICAL", "axis": Axis.LIVE_READ,
                      "status": EvidenceStatus.VERIFIED, "source": "t", "evidence_type": EvidenceType.LIVE, **bad}
            with self.assertRaises(ValueError):
                evidence.record_evidence(**kwargs)
        row = self.record(Axis.LIVE_READ, EvidenceStatus.VERIFIED)
        self.assertTrue(models.AuditEvent.objects.filter(event_type=models.AuditEventType.CAPABILITY_EVIDENCE_RECORDED, object_id=str(row.pk)).exists())
        with self.assertRaises(ValueError):
            row.save()

    def test_capabilities_page_renders_the_evidence_matrix(self):
        response = self.client.get(reverse("core:device_builder_capabilities"))
        self.assertContains(response, 'id="evidence-matrix"')
        self.assertContains(response, 'data-status="UNSUPPORTED"')
        self.assertContains(response, "SUPPORTED")
        self.assertContains(response, "Resolution:")
        self.assertContains(response, "No empirical evidence recorded yet.")
        self.assertNotContains(response, "badge--info")
        self.assertNotContains(response, "badge--neutral")
        self.assertNotContains(response, "· None")
        self.assertNotContains(response, "yet..")


class VerificationCommandTests(TestCase):
    def test_fixture_verification_records_typed_audited_evidence(self):
        call_command(
            "nmas_capabilities", "verify", "--platform", "arista_ceos", "--feature", "interface.LOOPBACK",
            "--test-type", "fixture", "--runtime-version", "ceos:test", stdout=StringIO(),
        )
        row = models.CapabilityEvidence.objects.get(axis="AUTOMATED_TESTS")
        self.assertEqual((row.axis, row.status, row.evidence_type, row.runtime_version),
                         ("AUTOMATED_TESTS", "VERIFIED", "FIXTURE", ""))
        self.assertTrue(row.repository_head)
        self.assertTrue(models.AuditEvent.objects.filter(object_id=str(row.pk)).exists())
        self.assertEqual(models.CapabilityAssessment.objects.count(), 1)
        self.assertEqual(len(models.CapabilityAssessment.objects.get().probes), 14)

    def test_live_verification_is_explicit_and_feature_restricted(self):
        with self.assertRaises(CommandError):
            call_command(
                "nmas_capabilities", "verify", "--platform", "arista_ceos", "--feature", "interface.LOOPBACK",
                "--live", stdout=StringIO(),
            )
        self.assertFalse(models.CapabilityEvidence.objects.exists())

    @mock.patch("core.services.capabilities.live_verify.verify_loopback")
    def test_successful_live_verification_records_all_operational_axes(self, verify):
        verify.return_value = LiveVerification(
            platform="arista_ceos", device="R1", interface="Loopback444", address="198.18.44.1/32",
            write_verified=True, post_write_verified=True, compensation_verified=True, restored=True,
            detail="created, read back, removed, and proved absent",
        )
        call_command(
            "nmas_capabilities", "verify", "--platform", "arista_ceos", "--feature", "interface.LOOPBACK",
            "--live", "--allow-write", "--device", "R1", stdout=StringIO(),
        )
        self.assertEqual(
            set(models.CapabilityEvidence.objects.values_list("axis", flat=True)),
            {"LIVE_READ", "LIVE_WRITE", "LIVE_POST_WRITE_VALIDATION", "COMPENSATION", "RUNTIME_VALIDATION"},
        )
        self.assertEqual(set(models.CapabilityEvidence.objects.values_list("evidence_type", flat=True)), {"LIVE"})
