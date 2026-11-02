"""Lab 7 closure -- every Tier-2 validator called directly on a context built from a real accepted snapshot, plus the
validation engine and its pure helpers (ACL evaluation, findings, sources, snapshot statistics, topology pairs).

The engine runs these validators in a loop, which never counted as a direct test.  POSITIVE: the PASS fixture (and the
richer plan fixture) produce exactly no finding -- or exactly the documented warnings -- from each validator.  NEGATIVE:
a candidate with one defect per area produces exactly that area's blocking codes, with and without NetBox.
"""

from __future__ import annotations

import ipaddress

from django.test import SimpleTestCase, TestCase

from core import models
from core.services import network_config_validation as ncv
from core.services.validation import acl, addressing, capabilities, composition, dependency_graph, engine, fhrp, findings
from core.services.validation import raw_configlets, removals, routing, services_policy, snapshot, sources, topology
from core.services.validation.context import AddressRecord, ProjectModel, ValidationContext
from core.tests.helpers import validation as vh


def ctx_for(change, bundle):
    snap = snapshot.build_change_snapshot(change)
    return ValidationContext(snapshot=snap, model=ProjectModel(snap), sources=bundle)


def codes_of(validator, ctx):
    validator(ctx)
    return sorted({f.code for f in ctx.findings})


POOL = {"family": 4, "start": "192.168.10.10", "end": "192.168.10.20", "server": "R9", "prefix": "192.168.10.0/24"}
VALIDATORS = dict(engine.VALIDATORS)


def defective_change():
    """One defect per area: a duplicate /31, an SVI address inside a DHCP pool and owned in NetBox by another device, a
    duplicate OSPF router id, an unresolved static next hop, an off-subnet VIP, an unresolvable relay and a shadowed ACE."""
    change = vh.new_change("defects")
    r1, r2 = vh.Dev(change, "R1"), vh.Dev(change, "R2")
    e1 = r1.iface("Ethernet1"); r1.address(e1, "192.0.2.0/31")
    e2 = r1.iface("Ethernet2"); r1.address(e2, "192.0.2.0/31")
    svi = r1.iface("Vlan10", kind="SVI", vlan_id=10); r1.address(svi, "192.168.10.11/24"); r1.fhrp(svi, vips=["10.99.0.1"])
    r1.ospf(router_id="10.0.0.1"); r2.ospf(router_id="10.0.0.1")
    r1.static_route("10.9.0.0/24", next_hop="203.0.113.9")
    rules = r1.acl("X"); r1.ace(rules, "DENY", "IP"); r1.ace(rules, "PERMIT", "TCP", destination_port="22"); r1.attach_acl(rules, svi)
    r1.relay(svi, "203.0.113.200")
    netbox = vh.netbox_data(ip_addresses=[vh.nb_ip("192.168.10.11/24", device="R2", interface="Ethernet9")], dhcp_ranges=[POOL])
    return change, vh.make_sources(netbox=netbox)


def misplaced_change():
    """A cEOS intent for the Linux R3, a device in no inventory or topology, and VARP left on a device moved to FRR."""
    change = vh.new_change("identity defects")
    vh.Dev(change, "R3")
    r9 = vh.Dev(change, "R9"); r9.address(r9.iface("Ethernet1"), "192.0.2.4/31")
    r4 = vh.Dev(change, "R4"); svi = r4.iface("Vlan10", kind="SVI", vlan_id=10); r4.address(svi, "192.168.10.4/24"); r4.fhrp(svi, vips=["192.168.10.1"])
    r4.switch_platform(models.Platform.UBUNTU_FRR)
    return change, vh.make_sources(topology=vh.topology_data(links=[vh.link("R1", "Ethernet1", "R2", "Ethernet1")], nodes=vh.DEFAULT_NODES))


class ValidatorTests(TestCase):
    def test_each_validator_finds_nothing_on_the_simple_pass_change(self):
        fixture = vh.simple_pass_change()
        for name, validator in engine.VALIDATORS:
            with self.subTest(case=f"clean {name}"):
                self.assertEqual(codes_of(validator, ctx_for(fixture.change, fixture.sources)), [])

    def test_the_rich_change_raises_only_its_documented_warnings(self):
        fixture = vh.rich_change()
        expected = {"routing": ["BGP_NETWORK_NO_EVIDENCE", "BGP_PEER_NO_RECIPROCAL"], "services_policy": ["NAT_ROLE_UNVERIFIED"]}
        for name, validator in engine.VALIDATORS:
            with self.subTest(case=f"accepted {name}"):
                self.assertEqual(codes_of(validator, ctx_for(fixture.change, fixture.sources)), expected.get(name, []))

    def test_each_area_reports_its_defects(self):
        change, bundle = defective_change()
        expected = {"addressing": ["IP_DHCP_POOL_CONFLICT", "IP_DUPLICATE", "IP_NETBOX_COLLISION"], "routing": ["ROUTER_ID_DUPLICATE", "ROUTE_NEXT_HOP_UNRESOLVED"],
                    "fhrp": ["FHRP_VIP_OFF_SUBNET"], "services_policy": ["DHCP_RELAY_UNRESOLVED"], "acl": ["ACL_ENTRY_SHADOWED", "ACL_REQUIRED_FLOW_DENIED"]}
        for name, codes in expected.items():
            with self.subTest(case=f"failure {name}"):
                self.assertEqual(codes_of(VALIDATORS[name], ctx_for(change, bundle)), codes)

    def test_defects_without_netbox_are_still_reported_from_the_intent(self):
        change, _bundle = defective_change()
        down = vh.make_sources(netbox=None, topology=None, inventory=None)
        for name, codes in (("addressing", ["IP_DUPLICATE"]), ("routing", ["ROUTER_ID_DUPLICATE", "ROUTE_NEXT_HOP_UNRESOLVED"]), ("services_policy", []),
                            ("topology", [])):
            with self.subTest(case=f"unavailable {name}"):
                self.assertEqual(codes_of(VALIDATORS[name], ctx_for(change, down)), codes)

    def test_identity_capability_and_topology_defects_are_refused(self):
        change, bundle = misplaced_change()
        for name, codes in (("platform_identity", ["DEVICE_NOT_IN_INVENTORY", "PLATFORM_INVENTORY_MISMATCH"]), ("capabilities", ["PLATFORM_FEATURE_NOT_IMPLEMENTED"]),
                            ("topology", ["TOPOLOGY_DEVICE_UNKNOWN"])):
            with self.subTest(case=f"failure {name}"):
                self.assertEqual(codes_of(VALIDATORS[name], ctx_for(change, bundle)), codes)

    def test_fhrp_members_list_each_instance_with_its_vlan_and_vips(self):
        fixture = vh.rich_change()
        members = fhrp._Members(ctx_for(fixture.change, fixture.sources))
        self.assertEqual([(m["device"], m["vlan"], [str(ip) for ip in m["vips"]]) for m in members.items], [("R1", 10, ["192.168.10.1"])])

    def test_fhrp_members_of_a_change_without_fhrp_are_none(self):
        fixture = vh.simple_pass_change()
        self.assertEqual(fhrp._Members(ctx_for(fixture.change, fixture.sources)).items, [])

    def test_addressing_helpers_find_pool_reservation_and_netbox_owner(self):
        change, bundle = defective_change()
        bundle.netbox.data["interface_modes"] = [{"device": "R2", "interface": "Ethernet9", "ipv4_mode": "dhcp-reserved"}]
        ctx = ctx_for(change, bundle)
        ip = ipaddress.ip_address("192.168.10.11")
        self.assertEqual(addressing.pool_conflict(ctx, ip), POOL)
        self.assertEqual(addressing.reservation_index(ctx), ({"192.168.10.11": ("R2", "ethernet9")}, {("R2", "ethernet9", 4): "192.168.10.11"}))
        found = addressing.netbox_conflicts(ctx, ip, device="R1", interface_name="Vlan10", shared_ok=False)
        self.assertEqual([(c["kind"], c["row"]["device"]) for c in found], [("assigned", "R2")])

    def test_addressing_helpers_without_netbox_or_outside_pools_find_nothing(self):
        change, bundle = defective_change()
        ctx = ctx_for(change, bundle)
        self.assertIsNone(addressing.pool_conflict(ctx, ipaddress.ip_address("192.168.10.99")))
        self.assertEqual(addressing.netbox_conflicts(ctx, ipaddress.ip_address("192.168.10.11"), device="R2", interface_name="ethernet9", shared_ok=False), [])
        down = ctx_for(change, vh.make_sources(netbox=None))
        self.assertEqual((addressing.pool_conflict(down, ipaddress.ip_address("192.168.10.11")), addressing.reservation_index(down)), (None, ({}, {})))

    def test_object_capabilities_and_probe_of_a_supported_static_route(self):
        fixture = vh.rich_change()
        device = ctx_for(fixture.change, fixture.sources).model.devices["R1"]
        entries = capabilities.enumerate_object_capabilities(device)
        static = next(entry for entry in entries if entry.object_type == "static_route")
        self.assertEqual(static.status, "SUPPORTED")
        found = capabilities.probe_object(device, static)
        self.assertEqual((found["markers"], found["deployable"]), (0, ["ip route 10.9.0.0/24 192.0.2.1"]))

    def test_object_capabilities_of_an_unimplemented_feature_and_an_empty_device(self):
        change, bundle = misplaced_change()
        model = ctx_for(change, bundle).model
        statuses = {entry.object_type: entry.status for entry in capabilities.enumerate_object_capabilities(model.devices["R4"])}
        self.assertIn("NOT_IMPLEMENTED", statuses.values())
        refused = next(entry for entry in capabilities.enumerate_object_capabilities(model.devices["R4"]) if entry.status != "SUPPORTED" and entry.probe is not None)
        self.assertEqual(capabilities.probe_object(model.devices["R4"], refused), {"markers": 1, "deployable": [], "emitted": 2})
        self.assertEqual(capabilities.enumerate_object_capabilities(model.devices["R3"]), [])


class RemovalAndRawTests(SimpleTestCase):
    def ctx(self, *, items=(), raw=(), targets=("R1",), devices=("R1",)):
        snap = {"targets": list(targets), "devices": [{"device_name": d, "platform": "arista_ceos", "target_type": "device"} for d in devices],
                "config_removals": {"items": list(items)}, "raw_configlets": {"items": list(raw)}}
        return ValidationContext(snapshot=snap, model=ProjectModel(snap), sources=None)

    def removal(self, **overrides):
        return {"device": "R1", "platform": "arista_ceos", "snapshot_id": "abcdef0123456789", "mode": "LINE_RANGE",
                "text": "hostname R1\nip route 10.9.0.0/24 192.0.2.1\n", "selection": {"from_line": 2, "to_line": 2}, **overrides}

    def test_analysis_for_a_whole_static_route_line(self):
        found = removals.analysis_for(self.removal())
        self.assertEqual((found["blockers"], len(found["items"])), ([], 1))

    def test_analysis_for_an_unsupported_platform_or_empty_selection_is_blocked(self):
        self.assertEqual([b["code"] for b in removals.analysis_for(self.removal(platform="cisco_iosxe"))["blockers"]], ["UNSUPPORTED_PLATFORM"])
        self.assertEqual([b["code"] for b in removals.analysis_for(self.removal(mode="OBJECTS", selection={}))["blockers"]], ["EMPTY_SELECTION"])

    def test_validate_removals_of_an_executable_removal(self):
        ctx = self.ctx(items=[self.removal()])
        removals.validate_removals(ctx)
        self.assertEqual((ctx.checked["config_removals"], [f.code for f in ctx.findings if f.blocking]), (1, []))

    def test_validate_removals_refuses_a_foreign_target_and_an_empty_removal(self):
        ctx = self.ctx(items=[self.removal(device="R2"), self.removal(mode="OBJECTS", selection={})])
        removals.validate_removals(ctx)
        self.assertEqual(sorted(f.code for f in ctx.findings), ["REMOVAL_EMPTY", "REMOVAL_TARGET_UNKNOWN"])

    def raw(self, **overrides):
        return {"device": "R1", "raw_id": "RAW-0001", "name": "banner", "revision": 1, "platform": "arista_ceos", "current_platform": "arista_ceos",
                "priority": models.DeploymentPriority.values[0], "node_id": "n1", "dependencies": [],
                "verification": {"currency": "CURRENT", "result": "PASS", "run_id": "r", "reasons": []}, **overrides}

    def test_validate_raw_configlets_of_a_current_verified_revision(self):
        ctx = self.ctx(raw=[self.raw()])
        raw_configlets.validate_raw_configlets(ctx)
        self.assertEqual((ctx.checked["raw_configlets"], [f.code for f in ctx.findings]), (1, []))

    def test_validate_raw_configlets_refuses_unknown_targets_stale_or_self_dependent_revisions(self):
        ctx = self.ctx(raw=[self.raw(device="R9"), self.raw(verification={"currency": "NEVER_RUN", "result": "", "run_id": "", "reasons": []}, node_id="n2", dependencies=["n2"]),
                            self.raw(current_platform="ubuntu_frr", priority="NOPE")])
        raw_configlets.validate_raw_configlets(ctx)
        self.assertEqual(sorted({f.code for f in ctx.findings}), ["RAW_DEPENDENCY_SELF", "RAW_NOT_VERIFIED", "RAW_PLATFORM_MISMATCH", "RAW_PRIORITY_INVALID", "RAW_TARGET_UNKNOWN"])


class CompositionTests(TestCase):
    def test_validate_composition_of_a_composable_candidate(self):
        fixture = vh.rich_change()
        ctx = ctx_for(fixture.change, fixture.sources)
        composition.validate_composition(ctx)
        self.assertEqual(ctx.findings, [])

    def test_validate_composition_reports_conflicting_contributions(self):
        fixture = vh.simple_pass_change()
        ctx = ctx_for(fixture.change, fixture.sources)
        ctx.model.devices["R1"].interfaces["dup"] = {**next(iter(ctx.model.devices["R1"].interfaces.values())), "id": "dup", "description": "conflicting"}
        ctx.model.devices["R1"].interfaces[next(iter(ctx.model.devices["R1"].interfaces))]["description"] = "original"
        composition.validate_composition(ctx)
        self.assertEqual({f.code for f in ctx.findings}, {"CANDIDATE_COMPOSITION_CONFLICT"})


class AclEvaluationTests(SimpleTestCase):
    RULES = {"entries": {"b": {"id": "b", "sequence": 20, "action": "PERMIT", "protocol": "TCP", "source_type": "ANY", "destination_type": "ANY", "destination_port": "22"},
                         "a": {"id": "a", "sequence": 10, "action": "DENY", "protocol": "TCP", "source_type": "HOST", "source_value": "10.0.0.9", "destination_type": "ANY"}}}

    def flow(self, **kw):
        return {"proto": "TCP", "family": 4, "src": ipaddress.ip_address("10.0.0.1"), "dst": ipaddress.ip_address("10.0.0.2"), "sport": None, "dport": 22, **kw}

    def test_entry_match_ordered_entries_and_first_match_evaluation(self):
        self.assertEqual([e["id"] for e in acl.ordered_entries(self.RULES)], ["a", "b"])
        self.assertEqual(acl.entry_match(self.RULES["entries"]["b"], self.flow()), acl.MATCH)
        self.assertEqual(acl.evaluate(self.RULES, self.flow())["verdict"], acl.PERMIT)

    def test_entry_match_and_evaluate_for_unmatched_or_unknown_flows(self):
        self.assertEqual(acl.entry_match(self.RULES["entries"]["b"], self.flow(proto="UDP")), acl.NO_MATCH)
        self.assertEqual(acl.evaluate(self.RULES, self.flow(dport=80))["verdict"], acl.IMPLICIT_DENY)
        self.assertEqual(acl.evaluate(self.RULES, self.flow(src=None))["verdict"], acl.UNKNOWN)
        self.assertEqual(acl.evaluate(self.RULES, self.flow(src=ipaddress.ip_address("10.0.0.9")))["verdict"], acl.DENY)
        self.assertEqual(acl.ordered_entries({}), [])


def finding(code="IP_DUPLICATE", **kw):
    return findings.Finding(code=code, message="m", **kw)


class FindingsTests(SimpleTestCase):
    def test_finding_id_and_sort_key_are_stable(self):
        a, b = finding(device="R1"), finding(device="R1")
        self.assertEqual(a.finding_id(), b.finding_id())
        self.assertRegex(a.finding_id(), r"^[0-9a-f]{12}$")
        self.assertEqual(a.sort_key()[2:4], ("IP_DUPLICATE", "R1"))
        self.assertEqual(findings.canonical_json({"b": [1], "a": None}), '{"a":null,"b":[1]}')

    def test_derive_status_blocked_incomplete_or_warning(self):
        self.assertEqual(findings.derive_status([finding()]), findings.Status.BLOCKED)
        self.assertEqual(findings.derive_status([finding(blocking=False, incomplete=True)]), findings.Status.INCOMPLETE)
        self.assertEqual(findings.derive_status([finding(blocking=False, incomplete=False, severity="WARNING")]), findings.Status.PASS_WITH_WARNINGS)

    def test_sanitize_bounds_rounds_and_keeps_plain_values(self):
        self.assertEqual(findings.sanitize({"n": 1.23456789, "s": {"b", "a"}, "ok": True}), {"n": 1.234568, "ok": True, "s": ["a", "b"]})

    def test_sanitize_never_keeps_secret_keys_or_unbounded_depth(self):
        deep = {}
        cursor = deep
        for _ in range(findings.MAX_DEPTH + 2):
            cursor["x"] = {}
            cursor = cursor["x"]
        self.assertEqual(findings.sanitize({"password": "p"}), {"password": "[REDACTED]"})
        self.assertIn("[TRUNCATED]", str(findings.sanitize(deep)))


class EngineAndSourceTests(TestCase):
    def test_requirements_run_and_semantic_digest_of_the_pass_change(self):
        fixture = vh.simple_pass_change()
        snap = snapshot.build_change_snapshot(fixture.change)
        self.assertEqual(engine.compute_requirements(ProjectModel(snap)), {"NETBOX": "addresses, DHCP or NAT objects need NetBox collision/pool evidence",
                                                                     "TOPOLOGY": "interfaces need link evidence",
                                                                     "INVENTORY": "existing-device intents are checked against project inventory"})
        report = engine.run_validation(snap, fixture.sources)
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(engine.semantic_digest(report), engine.semantic_digest(engine.run_validation(snap, fixture.sources)))

    def test_run_validation_without_sources_is_incomplete_and_its_digest_differs(self):
        fixture = vh.simple_pass_change()
        snap = snapshot.build_change_snapshot(fixture.change)
        self.assertEqual(engine.compute_requirements(ProjectModel({"devices": []})), {"NETBOX": "", "TOPOLOGY": "", "INVENTORY": ""})
        down = engine.run_validation(snap, vh.make_sources(netbox=None, topology=None, inventory=None))
        self.assertEqual(down["status"], "INCOMPLETE")
        self.assertNotEqual(engine.semantic_digest(down), engine.semantic_digest(engine.run_validation(snap, fixture.sources)))

    def test_snapshot_revision_map_and_stats(self):
        fixture = vh.simple_pass_change()
        self.assertEqual(set(snapshot.revision_map(fixture.change)), {"R1", "R2"})
        self.assertEqual(snapshot.snapshot_stats(snapshot.build_change_snapshot(fixture.change))["devices"], 2)

    def test_snapshot_stats_of_an_empty_snapshot_and_revision_map_of_an_empty_change(self):
        self.assertEqual(snapshot.snapshot_stats({"devices": []})["devices"], 0)
        self.assertEqual(snapshot.revision_map(vh.new_change("empty")), {})

    def test_source_results_and_bundle_views(self):
        bundle = vh.make_sources()
        self.assertEqual([r.available for r in bundle.all()], [True, True, True, bundle.capability.available])
        self.assertEqual(bundle.netbox.provenance()["source"], "NETBOX")
        self.assertEqual(bundle.netbox.provenance()["status"], "available")

    def test_topology_pairs_and_labels(self):
        fixture = vh.simple_pass_change()
        bundle = vh.make_sources(topology=vh.topology_data(links=[vh.link("R1", "Ethernet1", "R2", "Ethernet1")], nodes=vh.DEFAULT_NODES))
        ctx = ctx_for(fixture.change, bundle)
        pairs = topology.get_link_pairs(ctx)
        self.assertEqual(topology.link_label(pairs[0]), "R1:Ethernet1 <-> R2:Ethernet1")
        self.assertIs(topology.get_link_pairs(ctx), pairs)                         # cached

    def test_topology_pairs_none_without_topology_and_label_refuses_a_malformed_pair(self):
        fixture = vh.simple_pass_change()
        self.assertEqual(topology.get_link_pairs(ctx_for(fixture.change, vh.make_sources(topology=None))), [])
        with self.assertRaises(KeyError):
            topology.link_label({"a": {}})

    def test_add_derived_without_an_interface_and_node_id_of_empty_parts(self):
        model = ProjectModel({"devices": []})
        record = AddressRecord("R9", "x", "", "", "d", ipaddress.ip_interface("::1/128"), "DERIVED")
        model.add_derived(record)
        self.assertEqual((model.addresses, dependency_graph.node_id("", "", "")), ([record], "//"))

    def test_serialize_of_a_run_without_a_change(self):
        snap = models.RunningConfigSnapshot.objects.create(device_name="R1", platform=models.Platform.ARISTA_CEOS, digest="c" * 64, text="hostname R1\n", line_count=1,
                                                           source="test", captured_at=__import__("django.utils.timezone", fromlist=["now"]).now())
        found = ncv.serialize(ncv.validate_running(snap, sources=vh.make_sources(netbox=None)))
        self.assertEqual((found["change_id"], found["device"]), ("", "R1"))
