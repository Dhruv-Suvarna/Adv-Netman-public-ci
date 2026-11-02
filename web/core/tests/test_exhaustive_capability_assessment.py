"""Fail-closed completeness and real per-cell probe contracts."""

from io import StringIO
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase
from django.urls import reverse

from core import models
from core.services.capabilities import assessment, features, registry
from core.services.capabilities.offline_verify import _descriptors, _parse, _parsed_contains, verify_cell

HEAD = "4adec06ef04161d01340a1b94e5e1b2440a7e37c"


class AssessmentContractTests(TestCase):
    def test_catalogue_has_exactly_396_deliberate_samples(self):
        from core.services.capabilities.probe_cases import sample

        self.assertEqual(len(features.platforms()) * len(features.catalogue()), 396)
        for platform in features.platforms():
            for feature in features.catalogue():
                with self.subTest(platform=platform, feature=feature.key):
                    case = sample(platform, feature)
                    self.assertTrue(case.field_path)
                    self.assertNotEqual(case.sections, case.baseline)

    def test_offline_probe_is_real_but_does_not_claim_complete(self):
        cell = verify_cell("arista_ceos", features.by_key()["interface.LOOPBACK"], head=HEAD)
        self.assertEqual(set(cell.probes), set(assessment.PROBES))
        for name in ("semantic_model", "device_builder_ui", "field_validation", "renderer", "candidate_generation",
                     "config_validation", "parser_import", "automated_tests", "executor"):
            self.assertEqual(cell.probes[name]["outcome"], "PASS", (name, cell.probes[name]))
        self.assertEqual(cell.probes["live_write"]["outcome"], "PENDING")
        self.assertFalse(cell.complete)
        self.assertEqual(cell.status, "UNSUPPORTED")
        self.assertEqual(models.Change.objects.count(), 0)
        self.assertEqual(models.NetworkConfigValidationRun.objects.count(), 0)

    def test_routing_import_must_include_neighbors_networks_and_interface_binding(self):
        from core.services.capabilities.probe_cases import sample

        for key in ("routing.OSPFV2", "routing.OSPFV3", "routing.BGP_IPV4", "routing.BGP_IPV6"):
            with self.subTest(feature=key):
                feature = features.by_key()[key]
                case = sample("arista_ceos", feature)
                parsed = _parse("arista_ceos", _descriptors("arista_ceos", case.sections), case)
                self.assertTrue(_parsed_contains(parsed, feature, case))
                matching = next(i for i in parsed.routing_instances if i.family == ("ospf" if "OSPF" in key else "bgp"))
                if "OSPF" in key:
                    matching.bindings.clear()
                else:
                    matching.networks.clear()
                self.assertFalse(_parsed_contains(parsed, feature, case))

    def test_ceos_ospfv3_renderer_uses_matching_ipv6_interface_commands(self):
        from core.services.capabilities.probe_cases import sample

        feature = features.by_key()["routing.OSPFV3"]
        case = sample("arista_ceos", feature)
        lines = _descriptors("arista_ceos", case.sections)
        self.assertIn("   ipv6 ospf cost 10", lines)
        self.assertIn("   ipv6 ospf network point-to-point", lines)
        self.assertNotIn("   ospf cost 10", lines)
        parsed = _parse("arista_ceos", lines, case)
        self.assertTrue(_parsed_contains(parsed, feature, case))
        binding = next(i for i in parsed.routing_instances if i.fields.get("version") == "OSPFV3").bindings[0]
        self.assertEqual((binding["cost"], binding["network_type"]), (10, "POINT_TO_POINT"))

    def test_srlinux_ospf_import_matches_interface_area_without_a_network_statement(self):
        from core.services.capabilities.probe_cases import sample

        for key in ("routing.OSPFV2", "routing.OSPFV3"):
            with self.subTest(feature=key):
                feature = features.by_key()[key]
                case = sample("nokia_srlinux", feature)
                parsed = _parse("nokia_srlinux", _descriptors("nokia_srlinux", case.sections), case)
                self.assertTrue(_parsed_contains(parsed, feature, case))
                binding = next(i for i in parsed.routing_instances if i.family == "ospf").bindings[0]
                binding["area"] = "1.0.0.0"
                self.assertFalse(_parsed_contains(parsed, feature, case))

    def test_ceos_rip_renderer_enables_process_and_refuses_unsupported_passive(self):
        from core.services.capabilities.probe_cases import sample

        feature = features.by_key()["routing.RIPV2"]
        case = sample("arista_ceos", feature)
        lines = _descriptors("arista_ceos", case.sections)
        self.assertIn("   no shutdown", lines)
        self.assertIn("   network 198.18.0.0/30", lines)
        self.assertTrue(_parsed_contains(_parse("arista_ceos", lines, case), feature, case))
        stopped = ["   shutdown" if line == "   no shutdown" else line for line in lines]
        self.assertFalse(_parsed_contains(_parse("arista_ceos", stopped, case), feature, case))
        next(iter(case.sections["routing"]["rip"].values()))["interfaces"]["bind_0000000000000003"]["passive"] = True
        self.assertTrue(any("UNSUPPORTED CANDIDATE OBJECT" in line for line in _descriptors("arista_ceos", case.sections)))

    def test_ceos_tagged_child_fixture_has_unique_addresses_and_refuses_child_mtu(self):
        from core.services.capabilities.probe_cases import IF, PARENT, sample

        feature = features.by_key()["interface.SUBINTERFACE"]
        case = sample("arista_ceos", feature)
        self.assertFalse(case.sections["interfaces"][PARENT]["addresses"])
        self.assertEqual(case.sections["interfaces"][IF]["mtu"], None)
        self.assertEqual(verify_cell("arista_ceos", feature, head=HEAD).probes["config_validation"]["outcome"], "PASS")
        case.sections["interfaces"][IF]["mtu"] = 1500
        self.assertTrue(any("UNSUPPORTED CANDIDATE OBJECT" in line for line in _descriptors("arista_ceos", case.sections)))

    def test_isolated_routing_writes_require_fixed_target_and_explicit_flag(self):
        for action, feature in (("verify-isolated-ceos-bgp", "routing.BGP_IPV4"),
                                ("verify-isolated-ceos-bgp", "routing.BGP_IPV6"),
                                ("verify-isolated-ceos-ospf3", "routing.OSPFV3"),
                                ("verify-isolated-ceos-rip", "routing.RIPV2"),
                                ("verify-isolated-ceos-ripng", "routing.RIPNG"),
                                ("verify-isolated-ceos-isis", "routing.ISIS"),
                                ("verify-isolated-ceos-eigrp", "routing.EIGRP_IPV4"),
                                ("verify-isolated-ceos-eigrp", "routing.EIGRP_IPV6"),
                                ("verify-isolated-ceos-routed", "interface.ROUTED_PHYSICAL"),
                                ("verify-isolated-ceos-switchport", "interface.ACCESS"),
                                ("verify-isolated-ceos-switchport", "interface.TRUNK"),
                                ("verify-isolated-ceos-subinterface", "interface.SUBINTERFACE"),
                                ("verify-isolated-ceos-svi", "interface.SVI"),
                                ("verify-isolated-ceos-management", "interface.MANAGEMENT")):
            with self.subTest(action=action, feature=feature):
                with self.assertRaises(CommandError):
                    call_command("nmas_capabilities", action, "--platform", "arista_ceos", "--feature", feature,
                                 stdout=StringIO())
                with self.assertRaises(CommandError):
                    call_command("nmas_capabilities", action, "--platform", "arista_ceos", "--feature", feature,
                                 "--allow-write", "--device", "R1", stdout=StringIO())

    def test_completion_requires_all_cells_and_live_witness(self):
        cell = verify_cell("arista_ceos", features.by_key()["interface.LOOPBACK"], head=HEAD)
        with self.assertRaises(ValueError):
            assessment.require_complete(assessment.report([cell]))
        self.assertEqual(assessment.report([cell])["unassessed"], 396)
        cell.runtime_version = "ceos:4.36.2F"
        for name in assessment.LIVE_PROBES:
            cell.probes[name] = assessment.probe("FAIL", "Observed isolated test failure", reason="FUNCTIONAL_TEST_FAILED",
                                                  test_type="LIVE", reference="live:cap-ceos-2026-10-03")
        self.assertTrue(cell.complete)
        self.assertEqual(cell.status, "UNSUPPORTED")
        partial = assessment.report([cell])
        self.assertEqual((partial["assessed"], partial["unassessed"]), (1, 395))

    def test_negative_operational_static_evidence_does_not_turn_cell_green(self):
        cell = verify_cell("cisco_iosxr", features.by_key()["interface.LOOPBACK"], head=HEAD)
        assessment.persist(cell, actor="test")
        rec = next(c for row in registry.evidence_matrix()["rows"] if row["feature"].key == cell.feature
                   for c in row["cells"] if c.platform == cell.platform)
        self.assertEqual(rec.status.value, "UNSUPPORTED")
        self.assertFalse(rec.assessment.complete)
        self.assertTrue(models.CapabilityEvidence.objects.filter(platform=cell.platform, feature=cell.feature).exists())

    def test_missing_reason_or_fake_live_probe_is_refused(self):
        with self.assertRaises(ValueError):
            assessment.probe("FAIL", "Observed failure")
        cell = verify_cell("arista_ceos", features.by_key()["interface.LOOPBACK"], head=HEAD)
        cell.runtime_version = "ceos:4.36.2F"
        for name in assessment.LIVE_PROBES:
            cell.probes[name] = assessment.probe("PASS", "Claim", test_type="FIXTURE")
        self.assertFalse(cell.complete)

    def test_verify_matrix_enumerates_selected_cell_and_fails_closed(self):
        with self.assertRaises(CommandError):
            call_command("nmas_capabilities", "verify-matrix", "--platform", "arista_ceos",
                         "--feature", "interface.LOOPBACK", stdout=StringIO())
        self.assertEqual(models.CapabilityAssessment.objects.count(), 1)
        self.assertEqual(models.CapabilityEvidence.objects.filter(feature="interface.LOOPBACK").count(), 6)

    def test_matrix_detail_stays_binary_and_shows_assessment_progress(self):
        assessment.persist(verify_cell("arista_ceos", features.by_key()["interface.LOOPBACK"], head=HEAD), actor="test")
        response = self.client.get(reverse("core:device_builder_capabilities"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'data-status="UNSUPPORTED"')
        self.assertContains(response, "Assessment complete:")
        self.assertContains(response, "strongest attempted:")
        self.assertContains(response, "assessment #1")
        self.assertNotContains(response, 'data-status="UNKNOWN"')
        self.assertNotContains(response, "badge--info")
        self.assertNotContains(response, "badge--neutral")
