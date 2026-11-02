"""Lab 7 -- planning Configlet factory (core.services.planning.configlet_factory), positive + negative per public function.

The factory turns a validated dependency graph into the Configlets that are later pushed to devices, so the NEGATIVE
cases prove that it REFUSES (PlanGenerationError with a fixed code) rather than guessing: an AUTO address without its
validated value, an unknown graph node type, a node for a device without intent, a Raw node without its pinned revision;
and that hostile values (a line break in a description) never become an extra configuration line.  Pure: no device.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest import mock

from django.test import TestCase

from core.services.planning import configlet_factory as cf
from core.services.planning.errors import PlanGenerationError
from core.tests.helpers.validation import simple_pass_change, validate


class ConfigletFactoryUnitTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.f = simple_pass_change()
        cls.validation_run = validate(cls.f.change, cls.f.sources)

    def _ctx(self, dev=None):
        dev = dev or self.f.r1
        return cf.DeviceContext(dev.intent, dev.intent.latest_revision(), {})

    def _graph(self):
        return self.validation_run.dependency_graph

    # -- DeviceContext ------------------------------------------------------------------------------------
    def test_device_context_hydrates_the_accepted_intent(self):
        ctx = self._ctx()
        self.assertEqual((ctx.name, ctx.platform, ctx.hostname), ("R1", "arista_ceos", "R1"))
        self.assertEqual([i["name"] for i in ctx.interfaces], ["Ethernet1"])

    def test_device_context_refuses_an_auto_address_without_a_validated_value(self):
        state = {"field_values": {}, "interfaces": [{"id": "i1", "name": "Ethernet1", "addresses": {"a1": {"id": "a1", "source": "AUTO"}}}],
                 "routing": {}, "phase12": {}}
        with mock.patch.object(cf.candidate_renderer, "hydrate_state", return_value=state), self.assertRaises(PlanGenerationError) as caught:
            cf.DeviceContext(self.f.r1.intent, self.f.r1.intent.latest_revision(), {})
        self.assertEqual(caught.exception.code, "AUTO_VALUE_MISSING")

    def test_iface_and_ifaces_return_known_interfaces(self):
        ctx = self._ctx()
        interface_id = ctx.interfaces[0]["id"]
        self.assertEqual(ctx.iface(interface_id)["name"], "Ethernet1")
        self.assertEqual([i["name"] for i in ctx.ifaces([interface_id, interface_id])], ["Ethernet1"])

    def test_iface_and_ifaces_of_unknown_or_empty_ids_return_nothing(self):
        ctx = self._ctx()
        self.assertIsNone(ctx.iface("no-such-id"))
        self.assertEqual(ctx.ifaces(["no-such-id", "", None]), [])

    def test_stripped_returns_the_interface_without_addresses(self):
        ctx = self._ctx()
        stripped = cf.DeviceContext.stripped(ctx.interfaces[0])
        self.assertEqual(stripped["addresses"], {})
        self.assertTrue(ctx.interfaces[0]["addresses"])                    # the original is not mutated

    def test_stripped_refuses_a_non_mapping(self):
        with self.assertRaises(TypeError):
            cf.DeviceContext.stripped(None)

    def test_shell_returns_a_routing_process_without_children(self):
        ctx = self._ctx()
        self.assertEqual(ctx.shell("bgp", {"id": "b", "neighbors": {"n": {}}, "networks": {"x": {}}}), {"id": "b", "neighbors": {}, "networks": {}})
        self.assertEqual(ctx.shell("ospf", {"id": "o", "interfaces": {"x": {}}}), {"id": "o", "interfaces": {}})

    def test_shell_skips_malformed_bound_addresses_on_frr(self):
        ctx = self._ctx()
        ctx.platform = "ubuntu_frr"
        ctx.interfaces = [{"id": "i1", "addresses": {"a": {"cidr": "not-an-address"}, "b": {}, "c": {"cidr": "10.0.0.1/30"}}}]
        shell = ctx.shell("ospf", {"id": "o", "interfaces": {"x": {"interface_id": "i1"}, "y": {"interface_id": "missing"}}})
        self.assertEqual(shell["_bound_networks"], ["10.0.0.0/30"])

    def test_render_and_added_return_the_object_lines(self):
        ctx = self._ctx()
        lines = ctx.render(interfaces=ctx.interfaces)
        self.assertTrue(any(line.startswith("interface Ethernet1") for line in lines))
        added = ctx.added({"interfaces": [ctx.stripped(i) for i in ctx.interfaces]}, {"interfaces": ctx.interfaces})
        self.assertTrue(any("192.0.2.0/31" in line for line in added))

    def test_render_never_emits_an_injected_line_and_added_of_identical_state_is_empty(self):
        ctx = self._ctx()
        hostile = [{**ctx.interfaces[0], "description": "uplink\nusername evil privilege 15"}]
        self.assertFalse([line for line in ctx.render(interfaces=hostile) if "username evil" in line])
        self.assertEqual(ctx.added({"interfaces": ctx.interfaces}, {"interfaces": ctx.interfaces}), [])

    # -- build_specs ----------------------------------------------------------------------------------------
    def test_build_specs_returns_one_configlet_per_graph_node(self):
        contexts = {"R1": self._ctx(self.f.r1), "R2": self._ctx(self.f.r2)}
        specs, node_to_key, warnings = cf.build_specs(contexts, self._graph())
        self.assertTrue(specs)
        self.assertEqual({s.device for s in specs}, {"R1", "R2"})
        self.assertTrue(all(s.lines for s in specs))
        self.assertTrue(set(node_to_key.values()) <= {s.key for s in specs})
        self.assertEqual(sorted(specs, key=lambda s: s.sort_key)[0].object_class.priority, min(s.object_class.priority for s in specs))
        self.assertIsInstance(warnings, list)

    def test_build_specs_refuses_unknown_nodes_missing_devices_and_unpinned_raw_nodes(self):
        contexts = {"R1": self._ctx(self.f.r1)}
        for label, node, code in (
            ("unknown type", {"id": "R1/teleporter/x", "type": "teleporter", "device": "R1"}, "UNKNOWN_OBJECT_TYPE"),
            ("missing device", {"id": "R9/interface/x", "type": "interface", "device": "R9"}, "DEPENDENCY_MISSING"),
            ("raw without revision", {"id": "R1/raw_configlet/RAW-1", "type": "raw_configlet", "device": "R1"}, "RAW_REVISION_MISMATCH"),
            ("removal without snapshot", {"id": "R1/config_removal/x", "type": "config_removal", "device": "R1"}, "DEPENDENCY_MISSING"),
        ):
            with self.subTest(case=f"invalid {label}"), self.assertRaises(PlanGenerationError) as caught:
                cf.build_specs(contexts, {"nodes": [node]})
            self.assertEqual(caught.exception.code, code)

    # -- raw / removal specs and verification ---------------------------------------------------------------
    def _raw(self, priority=6, **item):
        revision = SimpleNamespace(revision=2, content_hash="h" * 64, priority=priority, assertions=[], name="banner", content="banner motd x\n")
        run = SimpleNamespace(run_id="r-1", result="PASS", policy_version="1", adapter_id="eos", adapter_version="1", backend="parser")
        return cf.raw_spec({"raw_id": "RAW-1", "node_id": "R1/raw_configlet/RAW-1", "device": "R1", "platform": "arista_ceos", **item}, revision, run)

    def test_raw_spec_pins_the_exact_revision_and_declared_priority(self):
        spec = self._raw()
        self.assertEqual((spec.origin, spec.lines, spec.raw["revision"], int(spec.object_class.priority)), ("RAW", ["banner motd x"], 2, 6))

    def test_raw_spec_refuses_an_incomplete_item_or_an_undeclared_priority(self):
        revision = SimpleNamespace(revision=1, content_hash="h", priority=6, assertions=[], name="n", content="")
        run = SimpleNamespace(run_id="r", result="PASS", policy_version="1", adapter_id="a", adapter_version="1", backend="b")
        with self.assertRaises(KeyError):                      # no node id / device / platform in the snapshot item
            cf.raw_spec({"raw_id": "RAW-1"}, revision, run)
        with self.assertRaises(ValueError):                    # priority 40 is not one of the nine deployment priorities
            _ = self._raw(priority=40).object_class

    def test_removal_spec_carries_restore_lines_and_snapshot_provenance(self):
        item = {"operation": "DEACTIVATE_DETACH", "label": "Loopback9", "removal_lines": ["no interface Loopback9"], "kind": "interface",
                "absent_paths": ["interfaces/Loopback9"], "id": "rm-1", "restore_lines": ["interface Loopback9"], "restorable": True,
                "lines": ["interface Loopback9"]}
        spec = cf.removal_spec({"id": "R1/config_removal/rm-1", "object_id": "rm-1"},
                               {"device": "R1", "platform": "arista_ceos", "snapshot_id": "s", "snapshot_digest": "d"}, item)
        self.assertEqual((spec.object_type, spec.origin, spec.removal["restore_lines"]), ("config_removal_detach", "REMOVAL", ["interface Loopback9"]))

    def test_removal_spec_refuses_an_item_without_removal_lines(self):
        with self.assertRaises(KeyError):
            cf.removal_spec({"id": "n", "object_id": "o"}, {"device": "R1", "platform": "arista_ceos"}, {"operation": "DELETE", "label": "x"})

    def test_verification_requirements_describe_the_expected_facts(self):
        contexts = {"R1": self._ctx(self.f.r1), "R2": self._ctx(self.f.r2)}
        spec = cf.build_specs(contexts, self._graph())[0][0]
        (requirement,) = cf.verification_requirements(spec)
        self.assertEqual((requirement["schema_version"], requirement["status"], requirement["device"]), (2, "DEFERRED", spec.device))
        self.assertEqual(requirement["expected"], spec.facts)

    def test_verification_requirements_of_a_raw_configlet_without_assertions_are_unverifiable(self):
        descriptors = cf.verification_requirements(self._raw())
        self.assertEqual(len(descriptors), 1)
        self.assertIn("RAW_CONFIG_APPLIED", str(descriptors[0]))

    # -- V2 Phase 6: ``ip routing`` for a natively onboarded cEOS (the ZTP bootstrap configures ``no ip routing``) -------------
    def test_routing_prerequisite_returns_ip_routing_for_a_new_ceos_ipv4_process(self):
        ctx = SimpleNamespace(platform="arista_ceos", intent=SimpleNamespace(target_type="NEW_DEVICE"))
        self.assertEqual(cf._routing_prerequisite(ctx, "ospf", {"version": "OSPFV2"}), "ip routing")
        self.assertEqual(cf._routing_prerequisite(ctx, "ospf", {}), "ip routing")          # OSPFv2 is the default version
        self.assertEqual(cf._routing_prerequisite(ctx, "rip", {"address_family": "IPV4"}), "ip routing")
        self.assertEqual(cf._routing_prerequisite(ctx, "bgp", {"local_asn": 65001}), "ip routing")
        self.assertEqual(cf._routing_prerequisite(ctx, "isis", {}), "ip routing")

    def test_routing_prerequisite_returns_ipv6_unicast_routing_for_a_new_ceos_ipv6_process(self):
        """V2 Phase 9: OSPFv3 forms no adjacency on a bootstrapped cEOS until IPv6 routing is on (live platform probe)."""
        new_ceos = SimpleNamespace(platform="arista_ceos", intent=SimpleNamespace(target_type="NEW_DEVICE"))
        self.assertEqual(cf._routing_prerequisite(new_ceos, "ospf", {"version": "OSPFV3"}), "ipv6 unicast-routing")
        self.assertEqual(cf._routing_prerequisite(new_ceos, "rip", {"address_family": "IPV6"}), "ipv6 unicast-routing")

    def test_routing_prerequisite_is_empty_for_existing_devices_other_platforms_and_non_routing_objects(self):
        new_ceos = SimpleNamespace(platform="arista_ceos", intent=SimpleNamespace(target_type="NEW_DEVICE"))
        self.assertEqual(cf._routing_prerequisite(new_ceos, "static", {}), "")
        self.assertEqual(cf._routing_prerequisite(new_ceos, "rip", {"address_family": "BOGUS"}), "")
        existing_v6 = SimpleNamespace(platform="arista_ceos", intent=SimpleNamespace(target_type="EXISTING_DEVICE"))
        self.assertEqual(cf._routing_prerequisite(existing_v6, "ospf", {"version": "OSPFV3"}), "")
        existing = SimpleNamespace(platform="arista_ceos", intent=SimpleNamespace(target_type="EXISTING_DEVICE"))
        self.assertEqual(cf._routing_prerequisite(existing, "ospf", {"version": "OSPFV2"}), "")
        frr = SimpleNamespace(platform="ubuntu_frr", intent=SimpleNamespace(target_type="NEW_DEVICE"))
        self.assertEqual(cf._routing_prerequisite(frr, "ospf", {"version": "OSPFV2"}), "")

    def _ospf_node(self, target_type, version="OSPFV2"):
        from core import models
        from core.tests.helpers.validation import Dev, new_change

        dev = Dev(new_change(f"ip routing prerequisite ({target_type}, {version})"), "EDGE9", target_type=target_type)
        loopback = dev.iface("Loopback0", kind="LOOPBACK")
        dev.address(loopback, "10.9.9.9/32" if version == "OSPFV2" else "2001:db8:9::9/128")
        instance = dev.ospf(version=version, router_id="10.9.9.9", process_id=1)
        dev.bind("ospf", instance, dev.current_iface(loopback["id"]), area="0.0.0.0")
        ctx = cf.DeviceContext(dev.intent, dev.refresh(), {})
        node = {"id": f"EDGE9/routing_ospf/{instance['id']}", "type": "routing_ospf", "object_id": instance["id"]}
        self.assertEqual(dev.intent.platform, models.Platform.ARISTA_CEOS)
        return cf._routing_instance(ctx, node)

    def test_routing_instance_of_a_new_ceos_device_renders_ip_routing_before_the_process(self):
        (spec,) = self._ospf_node("NEW_DEVICE")
        self.assertEqual(spec.lines[0], "ip routing")
        self.assertEqual(spec.lines.count("ip routing"), 1)
        self.assertTrue(any(line.startswith("router ospf 1") for line in spec.lines[1:]), spec.lines)

    def test_routing_instance_of_a_new_ceos_device_renders_ipv6_unicast_routing_before_the_ospfv3_process(self):
        (spec,) = self._ospf_node("NEW_DEVICE", "OSPFV3")
        self.assertEqual(spec.lines[0], "ipv6 unicast-routing")
        self.assertNotIn("ip routing", spec.lines)
        self.assertTrue(any(line.startswith("ipv6 router ospf 1") for line in spec.lines[1:]), spec.lines)

    def test_routing_instance_of_an_existing_device_never_renders_ip_routing(self):
        (spec,) = self._ospf_node("EXISTING_DEVICE")
        self.assertNotIn("ip routing", spec.lines)
        self.assertTrue(any(line.startswith("router ospf 1") for line in spec.lines), spec.lines)

    # -- V2 Phase 6: exact Phase-4 capability labels for routing processes, bindings and DHCP relays ---------------------------
    def test_routing_feature_matches_the_declared_version_or_address_family(self):
        self.assertEqual(cf.routing_feature("ospf", {"version": "OSPFV2"}), "routing.OSPFV2")
        self.assertEqual(cf.routing_feature("ospf", {"version": "OSPFV3"}), "routing.OSPFV3")
        self.assertEqual(cf.routing_feature("rip", {"address_family": "IPV4"}), "routing.RIPV2")
        self.assertEqual(cf.routing_feature("rip", {"address_family": "IPV6"}), "routing.RIPNG")

    def test_routing_feature_unknown_missing_or_unmapped_is_empty(self):
        self.assertEqual(cf.routing_feature("bgp", {"local_asn": 65001}), "")      # never inferred: provisioning refuses it
        self.assertEqual(cf.routing_feature("isis", {}), "")
        self.assertEqual(cf.routing_feature("ospf", {}), "")
        self.assertEqual(cf.routing_feature("ospf", {"version": "OSPFV9"}), "")
        self.assertEqual(cf.routing_feature("rip", None), "")

    def test_ospf_process_binding_and_relay_configlets_carry_their_exact_features(self):
        from core.tests.helpers.validation import Dev, new_change

        dev = Dev(new_change("capability labels"), "EDGE8", target_type="NEW_DEVICE")
        port = dev.iface("Ethernet2")
        dev.address(port, "10.8.8.1/24")
        relay = dev.relay(port, "10.8.9.2")
        instance = dev.ospf(router_id="10.8.8.8", process_id=1)
        binding = dev.bind("ospf", instance, dev.current_iface(port["id"]), area="0.0.0.0")
        ctx = cf.DeviceContext(dev.intent, dev.refresh(), {})
        (process,) = cf._routing_instance(ctx, {"id": f"EDGE8/routing_ospf/{instance['id']}", "type": "routing_ospf", "object_id": instance["id"]})
        (bound,) = cf._binding(ctx, {"id": f"EDGE8/routing_binding/{binding['id']}", "type": "routing_binding", "object_id": binding["id"]})
        (relayed,) = cf._dhcp_relay(ctx, {"id": f"EDGE8/dhcp_relay/{relay['id']}", "type": "dhcp_relay", "object_id": relay["id"]})
        self.assertEqual((process.capability_feature, bound.capability_feature, relayed.capability_feature),
                         ("routing.OSPFV2", "routing.OSPFV2", "service_policy.DHCP_RELAY_IPV4"))
