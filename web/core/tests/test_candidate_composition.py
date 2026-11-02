"""Scope-aware candidate composition and its deployment-safety invariants."""

from __future__ import annotations

from django.test import TestCase
from django.urls import reverse

from core import models
from core.services import (
    candidate_composition,
    candidate_renderer,
    interface_intent_service,
    platform_drivers,
    routing_intent_service,
)
from core.tests.helpers.validation import Dev, codes, make_sources, new_change, validate


def interface_block(text: str, name: str) -> list[str]:
    lines = text.splitlines()
    start = lines.index(f"interface {name}")
    end = next((index for index in range(start + 1, len(lines)) if lines[index] == "!"), len(lines))
    return lines[start:end]


class CandidateCompositionTests(TestCase):
    def device(self, name="R1"):
        return Dev(new_change("candidate composition"), name)

    def render(self, device: Dev) -> dict:
        device.refresh()
        return candidate_renderer.render(device.intent, device.revision)

    def test_base_and_ospf_share_one_interface_scope_and_process_stays_separate(self):
        device = self.device()
        ethernet = device.iface("Ethernet1")
        ospf = device.ospf(router_id="1.1.1.1", process_id=1)
        device.bind("ospf", ospf, ethernet, area="0.0.0.0")

        candidate = self.render(device)
        block = interface_block(candidate["text"], "Ethernet1")
        self.assertEqual(candidate["text"].splitlines().count("interface Ethernet1"), 1)
        self.assertIn("   no switchport", block)
        self.assertIn("   no shutdown", block)
        self.assertIn("   ip ospf area 0.0.0.0", block)
        self.assertIn("router ospf 1\n   router-id 1.1.1.1", candidate["text"])

    def test_all_supported_interface_features_are_in_one_canonical_block(self):
        device = self.device()
        ethernet = device.iface("Ethernet1", mtu=9000)
        device.address(ethernet, "192.0.2.1/31")
        device.address(ethernet, "2001:db8:100::1/64")
        ospf = device.ospf(router_id="1.1.1.1")
        device.bind("ospf", ospf, ethernet, area="0.0.0.0", network_type="POINT_TO_POINT")
        acl = device.acl("EDGE-IN")
        device.ace(acl, "PERMIT", "IP")
        device.attach_acl(acl, ethernet)
        device.relay(ethernet, "192.168.200.100")
        device.fhrp(
            ethernet,
            vips=("192.0.2.254",),
            virtual_mac="00:1c:73:00:00:99",
        )

        candidate = self.render(device)
        block = interface_block(candidate["text"], "Ethernet1")
        self.assertEqual(candidate["text"].splitlines().count("interface Ethernet1"), 1)
        for line in (
            "   mtu 9000",
            "   ip address 192.0.2.1/31",
            "   ipv6 address 2001:db8:100::1/64",
            "   ip ospf area 0.0.0.0",
            "   ip ospf network point-to-point",
            "   ip access-group EDGE-IN in",
            "   ip helper-address 192.168.200.100",
            "   ip virtual-router address 192.0.2.254",
        ):
            self.assertIn(line, block)

    def test_multiple_interfaces_do_not_cross_contaminate(self):
        device = self.device()
        first, second = device.iface("Ethernet1"), device.iface("Ethernet2")
        ospf = device.ospf()
        device.bind("ospf", ospf, first)
        acl = device.acl("SECOND-OUT")
        device.attach_acl(acl, second, direction="OUT")

        text = self.render(device)["text"]
        first_block, second_block = interface_block(text, "Ethernet1"), interface_block(text, "Ethernet2")
        self.assertEqual(text.splitlines().count("interface Ethernet1"), 1)
        self.assertEqual(text.splitlines().count("interface Ethernet2"), 1)
        self.assertTrue(any("ip ospf area" in line for line in first_block))
        self.assertFalse(any("access-group" in line for line in first_block))
        self.assertIn("   ip access-group SECOND-OUT out", second_block)
        self.assertFalse(any("ip ospf area" in line for line in second_block))

    def test_feature_removal_removes_only_its_contribution(self):
        device = self.device()
        ethernet = device.iface("Ethernet1")
        device.address(ethernet, "192.0.2.1/31")
        ospf = device.ospf()
        binding = device.bind("ospf", ospf, ethernet)
        acl = device.acl("EDGE-IN")
        device.attach_acl(acl, ethernet)

        routing_intent_service.remove_interface_binding(
            revision=device.revision,
            family="ospf",
            instance_id=ospf["id"],
            binding_id=binding["id"],
            confirmation="REMOVE",
        )
        block = interface_block(self.render(device)["text"], "Ethernet1")
        self.assertIn("   ip address 192.0.2.1/31", block)
        self.assertIn("   ip access-group EDGE-IN in", block)
        self.assertFalse(any("ip ospf" in line for line in block))

    def test_draft_interface_removal_cleans_attachments_but_preserves_definitions(self):
        device = self.device()
        ethernet = device.iface("Ethernet1")
        ospf = device.ospf()
        device.bind("ospf", ospf, ethernet)
        acl = device.acl("EDGE-IN")
        device.attach_acl(acl, ethernet)
        device.relay(ethernet, "192.168.200.100")

        interface_intent_service.remove_interface(
            revision=device.revision, interface_id=ethernet["id"], confirmation="REMOVE"
        )
        device.refresh()
        text = self.render(device)["text"]
        self.assertNotIn("interface Ethernet1", text)
        self.assertIn("ip access-list EDGE-IN", text)
        self.assertFalse(device.revision.sections["routing"]["ospf"][ospf["id"]]["interfaces"])
        self.assertFalse(device.revision.sections["security"]["attachments"])
        self.assertFalse(device.revision.sections["services"]["dhcp"]["relays"])

    def test_draft_interface_removal_clears_nat_role_without_deleting_global_rule(self):
        device = Dev(
            new_change("NAT interface removal"), "R3", platform=models.Platform.UBUNTU_FRR
        )
        inside, outside = device.iface("eth1"), device.iface("eth2")
        rule = device.nat_rule(inside=inside, outside=outside, source="10.0.0.0/8")

        interface_intent_service.remove_interface(
            revision=device.revision, interface_id=outside["id"], confirmation="REMOVE"
        )
        device.refresh()
        retained = device.revision.sections["nat"]["rules"][rule["id"]]
        self.assertEqual(retained["outside_interface_id"], "")
        self.assertEqual(retained["inside_interface_id"], inside["id"])
        candidate = self.render(device)
        self.assertNotIn("eth2", candidate["text"])
        self.assertIn(rule["id"], candidate["phase12"]["nat"]["rules"])

    def test_same_semantics_are_deterministic_across_field_edit_order(self):
        texts = []
        for order in (("description", "mtu"), ("mtu", "description")):
            device = self.device()
            ethernet = device.iface("Ethernet1")
            values = {"description": "edge", "mtu": 9000}
            for field in order:
                device.set(f"interfaces.{ethernet['id']}.{field}", values[field])
            ospf = device.ospf(router_id="1.1.1.1")
            device.bind("ospf", ospf, ethernet)
            texts.append(self.render(device)["text"])
        self.assertEqual(texts[0], texts[1])

    def test_identical_duplicate_attachment_is_idempotent(self):
        device = self.device()
        ethernet = device.iface("Ethernet1")
        acl = device.acl("EDGE-IN")
        device.attach_acl(acl, ethernet)
        device.attach_acl(acl, ethernet)

        candidate = self.render(device)
        self.assertEqual(candidate["text"].count("ip access-group EDGE-IN in"), 1)
        self.assertEqual(candidate["composition_conflicts"], [])

    def test_incompatible_single_valued_contributions_are_explicit_conflicts(self):
        device = self.device()
        ethernet = device.iface("Ethernet1")
        first, second = device.acl("EDGE-A"), device.acl("EDGE-B")
        device.attach_acl(first, ethernet)
        device.attach_acl(second, ethernet)

        candidate = self.render(device)
        self.assertEqual(len(candidate["composition_conflicts"]), 1)
        self.assertIn("COMPOSITION CONFLICT", candidate["text"])
        run = validate(device.change, make_sources())
        self.assertEqual(run.status, "BLOCKED")
        self.assertIn("CANDIDATE_COMPOSITION_CONFLICT", codes(run))

    def test_process_scope_is_also_deduplicated(self):
        device = self.device()
        ethernet = device.iface("Ethernet1")
        for _ in range(2):
            ospf = device.ospf(router_id="1.1.1.1", process_id=1)
            device.bind("ospf", ospf, ethernet)
        candidate = self.render(device)
        self.assertEqual(candidate["text"].splitlines().count("router ospf 1"), 1)
        self.assertEqual(candidate["text"].splitlines().count("interface Ethernet1"), 1)

    def test_vlan_and_named_policy_scopes_are_not_rendered_twice(self):
        device = self.device()
        device.iface("Vlan10", kind="SVI", vlan_id=10)
        device.iface("Vlan10-Backup", kind="SVI", vlan_id=10)
        first, second = device.acl("EDGE-IN"), device.acl("EDGE-IN")
        device.ace(first, "PERMIT", "IP")
        device.ace(second, "DENY", "IP")

        candidate = self.render(device)
        self.assertEqual(candidate["text"].splitlines().count("vlan 10"), 1)
        self.assertEqual(candidate["text"].splitlines().count("ip access-list EDGE-IN"), 1)
        self.assertTrue(any(
            item["scope_kind"] == "NAMED_POLICY" for item in candidate["composition_conflicts"]
        ))

    def test_eos_global_vlan_syntax_does_not_leak_into_ubuntu_rendering(self):
        device = Dev(
            new_change("Ubuntu SVI scope"), "R3", platform=models.Platform.UBUNTU_FRR
        )
        device.iface("vlan10", kind="SVI", vlan_id=10)

        text = self.render(device)["text"]
        self.assertNotIn("\nvlan 10\n", text)

    def test_unsupported_fhrp_does_not_leak_varp_commands(self):
        device = self.device()
        ethernet = device.iface("Ethernet1")
        device.inject(lambda sections: sections["fhrp"]["instances"].update({
            "legacy-vrrp": {
                "id": "legacy-vrrp", "sequence": 10, "protocol": "VRRP",
                "interface_id": ethernet["id"], "address_family": "IPV4",
                "virtual_mac": "00:00:5e:00:01:01",
                "virtual_ips": {"vip-1": {
                    "id": "vip-1", "sequence": 10, "address": "192.0.2.254",
                }},
            },
        }))

        candidate = self.render(device)
        block = interface_block(candidate["text"], "Ethernet1")
        self.assertFalse(any("virtual-router" in line for line in block))
        self.assertNotIn("ip virtual-router mac-address", candidate["text"])
        self.assertIn("VRRP legacy-vrrp is NOT_IMPLEMENTED", candidate["text"])


class NormalizedCompositionUnitTests(TestCase):
    def test_pbr_and_nat_contribute_to_interface_scope_without_owning_cli(self):
        normalized = candidate_composition.compose(
            field_values={"device.hostname": "R1"},
            interfaces=[{
                "id": "if-1", "sequence": 10, "name": "Ethernet1",
                "kind": "ROUTED_PHYSICAL", "addresses": {},
            }],
            routing={},
            phase12={
                "policy": {"pbr": {
                    "policies": {"pbr-1": {
                        "id": "pbr-1", "sequence": 10, "name": "PBR-WEB",
                        "family": "IPV4", "sequences": {},
                    }},
                    "attachments": {"attach-1": {
                        "id": "attach-1", "sequence": 10,
                        "policy_id": "pbr-1", "interface_id": "if-1", "direction": "IN",
                    }},
                }},
                "nat": {"pools": {}, "rules": {"nat-1": {
                    "id": "nat-1", "sequence": 10, "family": "NAT44", "mode": "PAT",
                    "inside_interface_id": "if-1", "outside_interface_id": "",
                }}},
            },
            process_scope_key=platform_drivers.CeosDriver().routing_process_scope_key,
        )

        interface = normalized["interfaces"][0]
        self.assertEqual(
            [item["policy_name"] for item in interface["_scope"]["pbr_attachments"]],
            ["PBR-WEB"],
        )
        self.assertEqual(interface["_scope"]["nat_roles"], [{
            "role": "INSIDE", "rule_id": "nat-1", "path": "nat.rules.nat-1",
        }])
        self.assertEqual(normalized["conflicts"], [])


class IncompleteCandidateTests(TestCase):
    def test_missing_ceos_ospf_process_id_stays_visible_and_blocks_validation(self):
        device = Dev(new_change("incomplete OSPF"), "R1")
        ethernet = device.iface("Ethernet1")
        ospf = device.ospf(process_id=None)
        device.bind("ospf", ospf, ethernet)

        candidate = candidate_renderer.render(device.intent, device.refresh())
        self.assertIn("router ospf <process-id-required>", candidate["text"])
        run = validate(device.change, make_sources())
        self.assertEqual(run.status, "BLOCKED")
        self.assertIn("OSPF_PROCESS_ID_REQUIRED", codes(run))


class DjangoPreviewPathTests(TestCase):
    def test_editor_bootstrap_uses_the_composed_candidate(self):
        device = Dev(new_change("Django preview composition"), "R11", target_type="NEW_DEVICE")
        ethernet = device.iface("Ethernet1")
        ospf = device.ospf(router_id="1.1.1.1")
        device.bind("ospf", ospf, ethernet)
        acl = device.acl("EDGE-IN")
        device.attach_acl(acl, ethernet)

        response = self.client.get(
            reverse("core:device_builder_edit", args=[device.change.change_id, device.intent.pk])
        )
        self.assertEqual(response.status_code, 200)
        candidate = response.context["bootstrap"]["candidate"]
        self.assertEqual(candidate["text"].splitlines().count("interface Ethernet1"), 1)
        block = interface_block(candidate["text"], "Ethernet1")
        self.assertIn("   ip ospf area 0.0.0.0", block)
        self.assertIn("   ip access-group EDGE-IN in", block)
