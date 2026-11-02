from __future__ import annotations

from unittest import mock

from django.test import SimpleTestCase, TestCase

from core.services.validation import engine
from core.services.validation.findings import (
    CODE_CATALOG, Category, Finding, MAX_FINDINGS, Severity, Status, derive_status,
)
from core.tests.helpers.validation import (
    Dev, codes, link, make_sources, nb_ip, netbox_data, new_change, topology_data, validate,
)


class StatusVocabularyTests(TestCase):
    def test_pass(self):
        change = new_change()
        r1 = Dev(change, "R1"); r1.address(r1.iface("Ethernet1"), "192.0.2.0/31")
        run = validate(change)
        self.assertEqual((run.status, run.summary["errors"], run.summary["warnings"]), ("PASS", 0, 0))

    def test_info_findings_alone_do_not_prevent_pass(self):
        change = new_change()
        r1 = Dev(change, "R1"); a = r1.iface("Ethernet1"); r1.address(a, "192.0.2.0/31")
        Dev(change, "R2").iface("Ethernet1")
        o = r1.ospf(); r1.bind("ospf", o, a)
        run = validate(change, make_sources(topology=topology_data(links=[link("R1", "Ethernet1", "R2", "Ethernet1")], nodes=("R1", "R2"))))
        self.assertIn("OSPF_ONE_SIDED", codes(run))
        self.assertEqual(run.status, "PASS")

    def test_pass_with_warnings(self):
        change = new_change()
        r1 = Dev(change, "R1"); r1.static_route("10.9.0.0/24", next_hop="172.16.9.9")
        self.assertEqual(validate(change).status, "PASS_WITH_WARNINGS")

    def test_blocked(self):
        change = new_change()
        for name in ("R1", "R2"):
            dev = Dev(change, name); dev.address(dev.iface("Ethernet1"), "192.0.2.1/24")
        self.assertEqual(validate(change).status, "BLOCKED")

    def test_incomplete_when_required_source_is_missing(self):
        change = new_change()
        r1 = Dev(change, "R1"); r1.address(r1.iface("Ethernet1"), "192.0.2.0/31")
        run = validate(change, make_sources(netbox=None))
        self.assertEqual(run.status, "INCOMPLETE")
        (finding,) = [f for f in run.report["findings"] if f["code"] == "SOURCE_NETBOX_UNAVAILABLE"]
        self.assertEqual((finding["severity"], finding["incomplete"], finding["blocking"]), ("ERROR", True, False))

    def test_blocked_outranks_incomplete_but_still_reports_the_gap(self):
        change = new_change()
        for name in ("R1", "R2"):
            dev = Dev(change, name); dev.address(dev.iface("Ethernet1"), "192.0.2.1/24")
        run = validate(change, make_sources(netbox=None))
        self.assertEqual(run.status, "BLOCKED")
        self.assertIn("SOURCE_NETBOX_UNAVAILABLE", codes(run))
        self.assertGreater(run.summary["incomplete_findings"], 0)

    def test_source_failure_never_becomes_pass(self):
        change = new_change()
        r1 = Dev(change, "R1"); r1.address(r1.iface("Ethernet1"), "192.0.2.0/31")
        for kwargs in ({"netbox": None}, {"topology": None}, {"inventory": None}):
            self.assertNotEqual(validate(change, make_sources(**kwargs)).status, "PASS", kwargs)

    def test_unneeded_source_outage_is_only_a_warning(self):
        change = new_change()
        Dev(change, "R1")  # hostname only: no addresses, no interfaces
        run = validate(change, make_sources(netbox=None, topology=None))
        self.assertEqual(run.status, "PASS_WITH_WARNINGS")
        for f in run.report["findings"]:
            self.assertEqual((f["severity"], f["incomplete"]), ("WARNING", False))

    def test_inventory_outage_incomplete_for_existing_devices(self):
        change = new_change()
        Dev(change, "R1")
        self.assertEqual(validate(change, make_sources(inventory=None)).status, "INCOMPLETE")

    def test_empty_change_is_pass(self):
        self.assertEqual(validate(new_change()).status, "PASS")

    def test_derive_status_precedence_unit(self):
        blocking = Finding(code="IP_DUPLICATE", message="x")
        gap = Finding(code="SOURCE_NETBOX_UNAVAILABLE", message="x")
        warn = Finding(code="LINK_MTU_MISMATCH", message="x")
        info = Finding(code="OSPF_ONE_SIDED", message="x")
        self.assertEqual(derive_status([info]), Status.PASS)
        self.assertEqual(derive_status([info, warn]), Status.PASS_WITH_WARNINGS)
        self.assertEqual(derive_status([warn, gap]), Status.INCOMPLETE)
        self.assertEqual(derive_status([gap, blocking, warn]), Status.BLOCKED)


class PartialFailureAndIsolationTests(TestCase):
    def test_partial_checks_continue_after_a_source_failure(self):
        change = new_change()
        r1, r2 = Dev(change, "R1"), Dev(change, "R2")
        r1.address(r1.iface("Ethernet1"), "192.0.2.0/31"); r2.address(r2.iface("Ethernet1"), "192.0.3.1/31")
        run = validate(change, make_sources(
            netbox=None, topology=topology_data(links=[link("R1", "Ethernet1", "R2", "Ethernet1")], nodes=("R1", "R2"))))
        self.assertIn("SOURCE_NETBOX_UNAVAILABLE", codes(run))
        self.assertIn("LINK_PREFIX_MISMATCH", codes(run))     # independent topology check still ran
        self.assertEqual(run.summary["validators_failed"], [])

    def test_all_independent_validators_contribute_findings(self):
        change = new_change()
        r1, r2 = Dev(change, "R1"), Dev(change, "R2")
        a = r1.iface("Ethernet1"); r1.address(a, "192.0.2.1/31")
        z = r2.iface("Ethernet1"); r2.address(z, "192.0.2.1/31")                 # addressing
        r1.static_route("10.9.0.0/24", next_hop="172.16.9.9")                      # routing
        r1.switch_platform("sonic")                                                # platform
        r2.relay(r2.iface("Vlan10", kind="SVI", vlan_id=10), "203.0.113.50")       # dhcp
        route = r2.static_route("10.8.0.0/24", interface=r2.iface("Ethernet4"))
        r2.force(f"routing.static_routes.{route['id']}.next_hop_interface_id", "if_0000000000000000")  # dependency
        run = validate(change, make_sources(topology=topology_data(links=[link("R1", "Ethernet1", "R2", "Ethernet1")], nodes=("R1", "R2"))))
        categories = {f["category"] for f in run.report["findings"]}
        self.assertTrue({"ADDRESSING", "PLATFORM", "DEPENDENCY", "DHCP"} <= categories, categories)
        self.assertEqual(run.summary["validators_failed"], [])

    def test_unexpected_validator_error_never_becomes_pass_and_is_sanitized(self):
        change = new_change()
        r1 = Dev(change, "R1"); r1.address(r1.iface("Ethernet1"), "192.0.2.0/31")

        def boom(ctx):
            raise RuntimeError("Authorization: Bearer super-secret-token-123 at /etc/private")

        patched = tuple((n, boom if n == "routing" else fn) for n, fn in engine.VALIDATORS)
        with mock.patch.object(engine, "VALIDATORS", patched), self.assertLogs("core.services.validation.engine", level="ERROR") as logs:
            run = validate(change)
        self.assertEqual(run.status, "INCOMPLETE")
        self.assertNotEqual(run.status, "PASS")
        (finding,) = [f for f in run.report["findings"] if f["code"] == "INTERNAL_VALIDATION_ERROR"]
        self.assertEqual(finding["evidence"]["validator"], "routing")
        self.assertEqual(finding["evidence"]["error_type"], "RuntimeError")
        self.assertIn("routing", run.summary["validators_failed"])
        self.assertIn("addressing", run.summary["validators_completed"])      # the others still ran
        blob = repr(run.report) + "".join(logs.output)
        self.assertNotIn("super-secret-token", blob)
        self.assertNotIn("Traceback", repr(run.report))

    def test_one_validator_failure_alongside_a_blocking_finding_is_blocked(self):
        change = new_change()
        for name in ("R1", "R2"):
            dev = Dev(change, name); dev.address(dev.iface("Ethernet1"), "192.0.2.1/24")
        patched = tuple((n, (lambda ctx: 1 / 0) if n == "routing" else fn) for n, fn in engine.VALIDATORS)
        with mock.patch.object(engine, "VALIDATORS", patched), self.assertLogs(level="ERROR"):
            self.assertEqual(validate(change).status, "BLOCKED")


class DeterminismTests(TestCase):
    def build(self):
        change = new_change()
        r1, r2 = Dev(change, "R1"), Dev(change, "R2")
        a = r1.iface("Ethernet1"); r1.address(a, "192.0.2.0/31"); r1.auto_address(r1.iface("Ethernet2"), "198.51.100.0/29")
        z = r2.iface("Ethernet1"); r2.address(z, "192.0.3.1/31")
        r1.static_route("10.9.0.0/24", next_hop="172.16.9.9")
        src = make_sources(
            netbox=netbox_data(prefixes=[{"prefix": "198.51.100.0/29", "family": 4, "vlan": None, "relay_targets": []}],
                               ip_addresses=[nb_ip("198.51.100.1/29", "R9", "Ethernet1")]),
            topology=topology_data(links=[link("R1", "Ethernet1", "R2", "Ethernet1")], nodes=("R1", "R2")))
        return change, src

    def test_same_semantic_inputs_produce_identical_output(self):
        change, src = self.build()
        first, second = validate(change, src), validate(change, src)
        self.assertNotEqual(first.run_id, second.run_id)
        self.assertEqual(first.status, second.status)
        self.assertEqual(first.report["findings"], second.report["findings"])
        self.assertEqual(first.derived_facts, second.derived_facts)
        self.assertEqual(first.dependency_graph, second.dependency_graph)
        self.assertEqual((first.input_hash, first.source_hash), (second.input_hash, second.source_hash))
        self.assertEqual(first.report["provenance"]["semantic_digest"], second.report["provenance"]["semantic_digest"])

    def test_findings_are_sorted_errors_first(self):
        change, src = self.build()
        findings = validate(change, src).report["findings"]
        ranks = [Severity.RANK[f["severity"]] for f in findings]
        self.assertEqual(ranks, sorted(ranks))

    def test_finding_ids_are_stable(self):
        change, src = self.build()
        a = [f["finding_id"] for f in validate(change, src).report["findings"]]
        b = [f["finding_id"] for f in validate(change, src).report["findings"]]
        self.assertEqual(a, b)
        self.assertEqual(len(a), len(set(a)))


class FindingSchemaTests(SimpleTestCase):
    REQUIRED = ("code", "severity", "category", "message", "blocking", "device", "object_type", "object_id", "field_path",
                "related_devices", "related_objects", "source", "evidence", "remediation")

    def test_every_finding_has_the_machine_readable_schema(self):
        data = Finding(code="IP_DUPLICATE", message="m").to_dict()
        for key in self.REQUIRED:
            self.assertIn(key, data)

    def test_codes_are_stable_and_categorised(self):
        for code, (category, severity, _blocking, _incomplete, meaning) in CODE_CATALOG.items():
            self.assertRegex(code, r"^[A-Z0-9_]+$")
            self.assertIn(category, Category.ALL)
            self.assertIn(severity, Severity.ALL)
            self.assertTrue(meaning)

    def test_required_codes_from_the_brief_exist(self):
        required = """SOURCE_NETBOX_UNAVAILABLE SOURCE_TOPOLOGY_UNAVAILABLE SOURCE_INVENTORY_UNAVAILABLE PLATFORM_FEATURE_UNSUPPORTED
        PLATFORM_FEATURE_NOT_IMPLEMENTED PLATFORM_FEATURE_UNKNOWN PLATFORM_RENDERER_INCONSISTENT IP_DUPLICATE IP_NETBOX_COLLISION
        IP_DHCP_POOL_CONFLICT IP_RESERVATION_CONFLICT AUTO_IP_UNRESOLVED AUTO_IP_NO_AVAILABLE_ADDRESS LINK_PREFIX_MISMATCH
        LINK_MODE_MISMATCH LINK_ACCESS_VLAN_MISMATCH LINK_NATIVE_VLAN_MISMATCH LINK_TRUNK_VLAN_MISSING LINK_MTU_MISMATCH
        ROUTER_ID_DUPLICATE BGP_PEER_UNRESOLVED BGP_REMOTE_AS_MISMATCH BGP_AF_MISMATCH OSPF_AREA_MISMATCH OSPF_VERSION_MISMATCH
        FHRP_VIP_CONFLICT FHRP_GROUP_MISMATCH FHRP_VIRTUAL_MAC_MISMATCH NAT_INTERFACE_ROLE_CONFLICT NAT_POOL_CONFLICT
        DHCP_VLAN200_FORBIDDEN DHCP_POOL_OVERLAP DHCP_RELAY_UNRESOLVED DNS_RESOLVER_UNRESOLVED ACL_REQUIRED_FLOW_DENIED
        ACL_EFFECT_UNKNOWN PBR_NEXT_HOP_UNRESOLVED DEPENDENCY_MISSING DEPENDENCY_CYCLE INTERNAL_VALIDATION_ERROR""".split()
        self.assertEqual([c for c in required if c not in CODE_CATALOG], [])

    def test_unknown_code_and_bad_severity_are_rejected(self):
        with self.assertRaises(ValueError):
            Finding(code="MADE_UP", message="x")
        with self.assertRaises(ValueError):
            Finding(code="IP_DUPLICATE", message="x", severity="FATAL")

    def test_softening_an_error_code_to_warning_drops_blocking(self):
        f = Finding(code="IP_NETBOX_COLLISION", message="x", severity="WARNING")
        self.assertFalse(f.blocking)

    def test_source_gap_findings_are_incomplete_not_blocking_by_default(self):
        f = Finding(code="SOURCE_TOPOLOGY_UNAVAILABLE", message="x")
        self.assertEqual((f.blocking, f.incomplete), (False, True))

    def test_finding_list_is_bounded_and_says_so(self):
        many = [Finding(code="LINK_MTU_MISMATCH", message=f"m{i}", object_id=f"o{i}") for i in range(MAX_FINDINGS + 25)]
        bounded, dropped = engine._dedupe_and_bound(many)
        self.assertEqual(dropped, 25)
        self.assertTrue(any(f.code == "REPORT_TRUNCATED" for f in bounded))
        self.assertLessEqual(len(bounded), MAX_FINDINGS + 1)
