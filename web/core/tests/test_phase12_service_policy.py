from __future__ import annotations

from copy import deepcopy

from django.test import TestCase

from core import models
from core.services import candidate_renderer, field_registry, platform_drivers
from core.services import interface_intent_service
from core.services import service_policy_intent_service as service
from core.tests.helpers.candidates import add_acl, add_fhrp, add_interface, commit, make_candidate


class NamespaceAndCapabilityTests(TestCase):
    def test_all_namespaces_default_without_persisting_override(self):
        _, _, revision = make_candidate()
        structured = service.structured_sections(revision)
        self.assertEqual(set(structured), {"fhrp", "nat", "services", "security", "policy"})
        self.assertEqual(structured["services"]["dhcp"]["mode"], "INHERIT")
        self.assertEqual(structured["services"]["dns"]["mode"], "INHERIT")
        revision.refresh_from_db()
        self.assertNotIn("services", revision.sections)

    def test_honest_support_boundary(self):
        self.assertTrue(platform_drivers.is_service_policy_feature_selectable("arista_ceos", "FHRP_VARP_IPV4"))
        self.assertFalse(platform_drivers.is_service_policy_feature_selectable("arista_ceos", "FHRP_HSRP_IPV4"))
        self.assertTrue(platform_drivers.is_service_policy_feature_selectable("ubuntu_frr", "NAT_NAT44_PAT"))
        self.assertFalse(platform_drivers.is_service_policy_feature_selectable("ubuntu_frr", "NAT_NAT64_STATIC"))
        cap = platform_drivers.capability_for_service_policy("arista_ceos", "NAT_NAT_PT_STATIC")
        self.assertEqual(cap.status, platform_drivers.CapabilityStatus.UNSUPPORTED)
        self.assertIn("deprecated", cap.evidence.lower())


class FhrpTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.change, cls.intent, cls.revision = make_candidate()
        cls.interface = add_interface(cls.revision, kind="SVI", name="Vlan10")

    def test_stable_ids_multiple_instances_and_vips(self):
        first = add_fhrp(self.revision, self.interface["id"])
        second = add_fhrp(self.revision, self.interface["id"], family="IPV6")
        vip = service.add_fhrp_vip(revision=self.revision, instance_id=first["id"], address="192.0.2.1")
        self.assertRegex(first["id"], r"^fhrp_[0-9a-f]{16}$")
        self.assertRegex(vip["id"], r"^vip_[0-9a-f]{16}$")
        self.assertNotEqual(first["id"], second["id"])

    def test_hsrp_vrrp_glbp_anycast_not_selectable(self):
        for protocol in ("HSRP", "VRRP", "GLBP", "ANYCAST_GATEWAY"):
            with self.assertRaisesRegex(service.CollectionMutationError, "not implemented"):
                service.add_fhrp_instance(revision=self.revision, protocol=protocol, interface_id=self.interface["id"])

    def test_cross_candidate_interface_rejected(self):
        _, _, other = make_candidate(device_name="R2")
        foreign = add_interface(other, kind="SVI", name="Vlan20")
        with self.assertRaises(service.CollectionOwnershipError):
            add_fhrp(self.revision, foreign["id"])

    def test_priority_group_preempt_and_secret_ref_validation(self):
        obj = add_fhrp(self.revision, self.interface["id"])
        self.assertEqual(commit(self.change, self.intent, self.revision, f"fhrp.instances.{obj['id']}.priority", 255).accepted_value, 255)
        self.assertEqual(commit(self.change, self.intent, self.revision, f"fhrp.instances.{obj['id']}.group_id", 4095).accepted_value, 4095)
        self.assertTrue(commit(self.change, self.intent, self.revision, f"fhrp.instances.{obj['id']}.preempt", "true").accepted_value)
        self.assertEqual(commit(self.change, self.intent, self.revision, f"fhrp.instances.{obj['id']}.auth_secret_ref", "vault/fhrp-10").accepted_value, "vault/fhrp-10")
        self.assertIsNone(field_registry.resolve_field_spec(f"fhrp.instances.{obj['id']}.password", revision=self.revision))

    def test_invalid_vip_family_and_ranges_rejected(self):
        obj = add_fhrp(self.revision, self.interface["id"])
        with self.assertRaises(service.CollectionMutationError):
            service.add_fhrp_vip(revision=self.revision, instance_id=obj["id"], address="2001:db8::1")
        state = commit(self.change, self.intent, self.revision, f"fhrp.instances.{obj['id']}.priority", 256)
        self.assertEqual(state.validation_state, models.FieldValidationState.INVALID)


class NatTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.change, cls.intent, cls.revision = make_candidate(platform=models.Platform.UBUNTU_FRR, device_name="R3")
        cls.inside = add_interface(cls.revision, name="eth1")
        cls.outside = add_interface(cls.revision, name="eth2")

    def test_nat44_pat_stable_rule_and_render(self):
        rule = service.add_nat_rule(revision=self.revision, family="NAT44", mode="PAT")
        self.assertRegex(rule["id"], r"^nat_[0-9a-f]{16}$")
        commit(self.change, self.intent, self.revision, f"nat.rules.{rule['id']}.original_source", "192.168.10.0/24")
        commit(self.change, self.intent, self.revision, f"nat.rules.{rule['id']}.outside_interface_id", self.outside["id"])
        text = candidate_renderer.render(self.intent, self.revision)["text"]
        self.assertIn('oifname "eth2" ip saddr 192.168.10.0/24 masquerade', text)

    def test_nat_vocabularies_exist_without_false_support(self):
        self.assertEqual(set(service.NAT_FAMILIES), {"NAT44", "NAT64", "NAT66", "NPTV6", "NAT_PT"})
        self.assertIn("STATIC", service.NAT_MODES)
        self.assertIn("DYNAMIC", service.NAT_MODES)
        self.assertIn("TWICE_NAT", service.NAT_MODES)
        self.assertIn("POLICY_NAT", service.NAT_MODES)
        with self.assertRaises(service.CollectionMutationError):
            service.add_nat_rule(revision=self.revision, family="NAT64", mode="STATIC")

    def test_cross_candidate_interface_commit_rolls_back_field_only(self):
        rule = service.add_nat_rule(revision=self.revision, family="NAT44", mode="PAT")
        _, _, other = make_candidate(platform=models.Platform.UBUNTU_FRR, device_name="R4")
        foreign = add_interface(other, name="eth9")
        path = f"nat.rules.{rule['id']}.outside_interface_id"
        state = commit(self.change, self.intent, self.revision, path, foreign["id"])
        self.assertEqual(state.validation_state, models.FieldValidationState.INVALID)
        self.assertEqual(state.accepted_value, "")


class ServiceTests(TestCase):
    def test_dhcp_and_dns_inherit_by_default_and_ceos_relays_without_a_local_server(self):
        change, intent, revision = make_candidate()
        summary = service.editor_summary(revision=revision, platform="arista_ceos")
        self.assertEqual((summary["dhcp"]["mode"], summary["dns"]["mode"]), ("INHERIT", "INHERIT"))
        interface = add_interface(revision, kind="SVI", name="Vlan10")
        relay = service.add_dhcp_relay(revision=revision, family="IPV4", interface_id=interface["id"], destination="192.168.200.100")
        self.assertRegex(relay["id"], r"^dhcp_[0-9a-f]{16}$")
        self.assertIn("ip helper-address 192.168.200.100", candidate_renderer.render(intent, revision)["text"])
        with self.assertRaises(service.CollectionMutationError):
            service.set_service_mode(revision=revision, service="dns", mode="OVERRIDE")

    def test_vlan200_dhcp_and_dhcpv6_clients_rejected_even_if_capability_is_forced(self):
        _, _, revision = make_candidate()
        interface = add_interface(revision, kind="MANAGEMENT", name="Vlan200")
        original = platform_drivers.SERVICE_POLICY_CAPABILITIES["arista_ceos"]
        for family in ("IPV4", "IPV6"):
            feature = platform_drivers.ServicePolicyFeature[f"DHCP_CLIENT_{family}"]
            patched = dict(original)
            patched[feature] = platform_drivers.PlatformCapability(platform_drivers.CapabilityStatus.SUPPORTED, "test")
            platform_drivers.SERVICE_POLICY_CAPABILITIES["arista_ceos"] = patched
            try:
                with self.assertRaisesRegex(service.CollectionMutationError, "statically managed"):
                    service.add_dhcp_client(revision=revision, family=family, interface_id=interface["id"])
            finally:
                platform_drivers.SERVICE_POLICY_CAPABILITIES["arista_ceos"] = original


class AclTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.change, cls.intent, cls.revision = make_candidate()
        cls.interface = add_interface(cls.revision, name="Ethernet1")
        cls.acl = add_acl(cls.revision)

    def test_acl_ace_and_attachment_ids_and_separation(self):
        ace1 = service.add_ace(revision=self.revision, acl_id=self.acl["id"], action="PERMIT", protocol="TCP")
        ace2 = service.add_ace(revision=self.revision, acl_id=self.acl["id"], action="DENY", protocol="IP")
        attachment = service.add_acl_attachment(revision=self.revision, acl_id=self.acl["id"], interface_id=self.interface["id"], direction="IN")
        self.assertRegex(self.acl["id"], r"^acl_[0-9a-f]{16}$")
        self.assertRegex(ace1["id"], r"^ace_[0-9a-f]{16}$")
        self.assertGreater(ace2["sequence"], ace1["sequence"])
        self.assertRegex(attachment["id"], r"^attach_[0-9a-f]{16}$")
        self.assertNotIn("interface_id", self.acl)

    def test_structured_matches_ports_and_protocol_rules(self):
        ace = service.add_ace(revision=self.revision, acl_id=self.acl["id"], action="PERMIT", protocol="TCP")
        base = f"security.acls.{self.acl['id']}.entries.{ace['id']}"
        self.assertEqual(commit(self.change, self.intent, self.revision, f"{base}.source_type", "HOST").accepted_value, "HOST")
        self.assertEqual(commit(self.change, self.intent, self.revision, f"{base}.source_value", "192.0.2.10").accepted_value, "192.0.2.10")
        self.assertEqual(commit(self.change, self.intent, self.revision, f"{base}.destination_port", "443").accepted_value, "443")
        commit(self.change, self.intent, self.revision, f"{base}.protocol", "ICMP")
        state = commit(self.change, self.intent, self.revision, f"{base}.destination_port", "80")
        self.assertEqual(state.validation_state, models.FieldValidationState.INVALID)

    def test_definition_then_attachment_render_and_warning(self):
        service.add_ace(revision=self.revision, acl_id=self.acl["id"], action="DENY", protocol="IP")
        service.add_acl_attachment(revision=self.revision, acl_id=self.acl["id"], interface_id=self.interface["id"], direction="OUT")
        text = candidate_renderer.render(self.intent, self.revision)["text"]
        self.assertIn("ip access-list EDGE-IN", text)
        self.assertIn("ip access-group EDGE-IN out", text)
        self.assertIn("Traffic-impact validation has not run", text)

    def test_definition_cannot_be_removed_but_interface_removal_cascades_only_the_attachment(self):
        service.add_acl_attachment(
            revision=self.revision,
            acl_id=self.acl["id"],
            interface_id=self.interface["id"],
            direction="IN",
        )
        with self.assertRaisesRegex(service.CollectionMutationError, "Detach"):
            service.remove_object(
                revision=self.revision,
                kind="acl",
                object_id=self.acl["id"],
                confirmation="REMOVE",
            )
        interface_intent_service.remove_interface(
            revision=self.revision,
            interface_id=self.interface["id"],
            confirmation="REMOVE",
        )
        self.revision.refresh_from_db()
        self.assertIn(self.acl["id"], self.revision.sections["security"]["acls"])
        self.assertFalse(self.revision.sections["security"]["attachments"])


class PbrAndRendererTests(TestCase):
    def test_unimplemented_objects_are_refused_not_faked(self):
        _, _, revision = make_candidate()
        cases = {
            "PBR policy": lambda: service.add_pbr_policy(revision=revision, name="PBR-IN", family="IPV4"),
            # V2 Phase 9 made IPv6 ACLs selectable on cEOS; a NAT44 pool is still not implemented there.
            "NAT44 pool (not implemented on cEOS)": lambda: service.add_nat_pool(revision=revision, family="NAT44", name="POOL"),
        }
        for label, attempt in cases.items():
            with self.subTest(object=label), self.assertRaises(service.CollectionMutationError):
                attempt()

    def test_platform_change_preserves_all_phase12_sections(self):
        _, intent, revision = make_candidate()
        interface = add_interface(revision, kind="SVI", name="Vlan10")
        obj = add_fhrp(revision, interface["id"])
        before = deepcopy(revision.sections["fhrp"])
        intent.platform = models.Platform.UBUNTU_FRR
        intent.save(update_fields=["platform"])
        revision.refresh_from_db()
        self.assertEqual(revision.sections["fhrp"], before)
        self.assertIn("UNSUPPORTED CANDIDATE OBJECT", candidate_renderer.render(intent, revision)["text"])
        self.assertEqual(obj["id"], next(iter(revision.sections["fhrp"]["instances"])))
