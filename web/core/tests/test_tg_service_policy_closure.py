"""Lab 7 closure -- ``core.services.service_policy_intent_service`` (FHRP / NAT / DHCP / DNS / ACL / PBR candidate
collections), each public function called directly against a real draft candidate in the test database.

Draft-only, database-local: nothing is rendered, deployed or sent to NetBox.  Several collections (NAT pools, DHCP
client, DNS override, PBR) are not selectable on any current platform; their collection mechanics are exercised
with the platform capability gate patched open (``gate_open``), and a sibling negative asserts that the real gate
refuses them.  POSITIVE: exact stored objects, stable IDs, conventional sequences, seeded field states, mirrored
fields, editor paths.  NEGATIVE: non-draft changes, unknown / foreign IDs, unknown families / directions / paths,
collection limits, invalid addresses / domains, and unsupported intent are refused, leaving the revision unchanged.
"""
from __future__ import annotations

from unittest import mock

from django.test import TestCase

from core import models
from core.services import interface_intent_service
from core.services import service_policy_intent_service as service
from core.tests.helpers.candidates import add_interface, make_candidate

ID = r"^{}_[0-9a-f]{{16}}$"


def gate_open(*_args):
    return True


class CandidateTestCase(TestCase):
    def setUp(self):
        self.change, self.intent, self.revision = make_candidate()
        self.svi = add_interface(self.revision, kind="SVI", name="Vlan10")

    def reload(self):
        self.revision.refresh_from_db()
        return self.revision

    def seeded_paths(self, prefix):
        return set(self.revision.field_states.filter(path__startswith=prefix).values_list("path", flat=True))

    def add_policy(self, name="PBR-A"):
        with mock.patch.object(service, "_supported", gate_open):
            return service.add_pbr_policy(revision=self.revision, name=name, family="IPV4")

    def seed(self, **objects):
        """Write collections straight into the revision (bypassing the add_* gates) for read/derive tests."""
        sections = service.structured_sections(self.revision)
        for dotted, value in objects.items():
            target = sections
            *parents, leaf = dotted.split(".")
            for key in parents:
                target = target[key]
            target[leaf] = value
        self.revision.sections = sections
        self.revision.save(update_fields=["sections"])
        return sections


class DraftAndSectionTests(CandidateTestCase):
    def test_require_draft_returns_for_a_draft_change(self):
        self.assertIsNone(service.require_draft(self.revision))

    def test_require_draft_refuses_a_change_that_is_not_draft_and_nothing_is_added(self):
        models.Change.objects.filter(pk=self.change.pk).update(lifecycle_state=models.ChangeLifecycleState.VALIDATED)
        revision = models.DeviceIntentRevision.objects.get(pk=self.revision.pk)
        with self.assertRaises(interface_intent_service.DraftOnlyError):
            service.require_draft(revision)
        with self.assertRaises(interface_intent_service.DraftOnlyError):
            service.add_acl(revision=revision, name="EDGE-IN")
        self.assertEqual(service.structured_sections(revision)["security"]["acls"], {})

    def test_structured_sections_returns_defaults_and_repairs_malformed_namespaces(self):
        self.revision.sections = {"fhrp": [], "nat": {"pools": "x"}, "services": {"dhcp": "x", "dns": {"mode": "OVERRIDE"}},
                                  "policy": {}, "interfaces": self.revision.sections.get("interfaces", {})}
        self.revision.save(update_fields=["sections"])
        structured = service.structured_sections(self.revision)
        self.assertEqual(set(structured), {"fhrp", "nat", "services", "security", "policy"})
        self.assertEqual(structured["fhrp"], {"instances": {}})
        self.assertEqual(structured["nat"], {"pools": {}, "rules": {}})
        self.assertEqual(structured["services"]["dhcp"], {"mode": "INHERIT", "relays": {}, "clients": {}, "local_server_override": False})
        self.assertEqual(structured["services"]["dns"], {"mode": "OVERRIDE", "resolvers": {}, "search_domains": {}, "domain_name": ""})
        self.assertEqual(structured["services"]["monitoring"], {"mode": "INHERIT"})
        self.assertEqual(structured["policy"], {"pbr": {"policies": {}, "attachments": {}}})

    def test_ordered_returns_rows_by_sequence_then_id(self):
        rows = {"b": {"id": "b", "sequence": 2}, "a": {"id": "a", "sequence": 2}, "c": {"id": "c", "sequence": 1}, "d": {"id": "d"}}
        self.assertEqual([row["id"] for row in service.ordered(rows)], ["d", "c", "a", "b"])

    def test_ordered_of_an_empty_mapping_is_empty(self):
        self.assertEqual(service.ordered({}), [])


class GetterTests(CandidateTestCase):
    def setUp(self):
        super().setUp()
        self.seed(**{
            "fhrp.instances": {"fhrp_1": {"id": "fhrp_1", "virtual_ips": {"vip_1": {"id": "vip_1"}}}},
            "nat.pools": {"pool_1": {"id": "pool_1"}}, "nat.rules": {"nat_1": {"id": "nat_1"}},
            "services.dhcp.relays": {"dhcp_r": {"id": "dhcp_r"}}, "services.dhcp.clients": {"dhcp_c": {"id": "dhcp_c"}},
            "services.dns.resolvers": {"dns_r": {"id": "dns_r"}}, "services.dns.search_domains": {"dns_d": {"id": "dns_d"}},
            "security.acls": {"acl_1": {"id": "acl_1", "entries": {"ace_1": {"id": "ace_1"}}}},
            "security.attachments": {"attach_a": {"id": "attach_a"}},
            "policy.pbr.policies": {"pbr_1": {"id": "pbr_1", "sequences": {"pbrseq_1": {"id": "pbrseq_1"}}}},
            "policy.pbr.attachments": {"attach_p": {"id": "attach_p"}},
            "nat.pools.pool_x": {"id": "pool_other"},
        })
        self.getters = {
            "fhrp instance": (service.get_fhrp_instance, ("fhrp_1",)), "fhrp vip": (service.get_fhrp_vip, ("fhrp_1", "vip_1")),
            "nat pool": (service.get_nat_pool, ("pool_1",)), "nat rule": (service.get_nat_rule, ("nat_1",)),
            "dhcp relay": (service.get_dhcp_relay, ("dhcp_r",)), "dhcp client": (service.get_dhcp_client, ("dhcp_c",)),
            "dns resolver": (service.get_dns_resolver, ("dns_r",)), "dns domain": (service.get_dns_domain, ("dns_d",)),
            "acl": (service.get_acl, ("acl_1",)), "ace": (service.get_ace, ("acl_1", "ace_1")),
            "acl attachment": (service.get_acl_attachment, ("attach_a",)),
            "pbr policy": (service.get_pbr_policy, ("pbr_1",)), "pbr sequence": (service.get_pbr_sequence, ("pbr_1", "pbrseq_1")),
            "pbr attachment": (service.get_pbr_attachment, ("attach_p",)),
        }

    def test_getters_return_the_owned_object(self):
        for label, (getter, args) in self.getters.items():
            with self.subTest(case=f"returns {label}"):
                self.assertEqual(getter(self.revision, *args)["id"], args[-1])

    def test_getters_refuse_unknown_or_mismatched_ids(self):
        for label, (getter, args) in self.getters.items():
            with self.subTest(case=f"refused unknown {label}"):
                with self.assertRaises(service.CollectionOwnershipError):
                    getter(self.revision, *args[:-1], "unknown_id")
        with self.subTest(case="refused mismatched stored id"):
            with self.assertRaisesRegex(service.CollectionOwnershipError, "NAT pool ID does not belong"):
                service.get_nat_pool(self.revision, "pool_x")
        with self.subTest(case="refused child of an unknown parent"):
            with self.assertRaises(service.CollectionOwnershipError):
                service.get_ace(self.revision, "acl_unknown", "ace_1")


class NatAndServiceTests(CandidateTestCase):
    def test_add_nat_pool_returns_a_seeded_pool(self):
        with mock.patch.object(service, "_supported", gate_open):
            first = service.add_nat_pool(revision=self.revision, family="NAT44", name="POOL-A")
            second = service.add_nat_pool(revision=self.revision, family="NAT44", name="POOL-B")
        self.assertRegex(first["id"], ID.format("pool"))
        self.assertEqual({k: v for k, v in first.items() if k != "id"},
                         {"sequence": 1, "name": "POOL-A", "family": "NAT44", "start_address": "", "end_address": "",
                          "prefix_length": None, "description": ""})
        self.assertEqual(second["sequence"], 2)
        self.assertEqual(self.seeded_paths(f"nat.pools.{first['id']}."), {f"nat.pools.{first['id']}.{f}" for f in service.NAT_POOL_FIELDS})
        self.assertEqual(set(self.reload().sections["nat"]["pools"]), {first["id"], second["id"]})

    def test_add_nat_pool_refuses_unknown_unsupported_or_full_collections(self):
        with self.subTest(case="refused unknown family"):
            with self.assertRaisesRegex(service.CollectionMutationError, "Unknown NAT translation family"):
                service.add_nat_pool(revision=self.revision, family="NAT99")
        with self.subTest(case="refused unsupported by the real gate"):
            with self.assertRaisesRegex(service.CollectionMutationError, "not implemented"):
                service.add_nat_pool(revision=self.revision, family="NAT44")
        self.seed(**{"nat.pools": {f"pool_{i}": {"id": f"pool_{i}"} for i in range(service.MAX_NAT_POOLS)}})
        with self.subTest(case="refused limit exceeded"):
            with mock.patch.object(service, "_supported", gate_open), self.assertRaises(service.CollectionLimitError):
                service.add_nat_pool(revision=self.revision, family="NAT44")
        self.assertEqual(len(self.reload().sections["nat"]["pools"]), service.MAX_NAT_POOLS)

    def test_set_service_mode_returns_the_updated_service(self):
        dhcp = service.set_service_mode(revision=self.revision, service="dhcp", mode="OVERRIDE")
        self.assertEqual(dhcp["mode"], "OVERRIDE")
        self.assertEqual(service.set_service_mode(revision=self.revision, service="dns", mode="INHERIT")["mode"], "INHERIT")
        self.assertEqual(self.reload().sections["services"]["dhcp"]["mode"], "OVERRIDE")
        self.assertEqual(self.seeded_paths("services.dhcp.mode"), {"services.dhcp.mode"})

    def test_add_dhcp_client_returns_an_override_client(self):
        with mock.patch.object(service, "_supported", gate_open):
            client = service.add_dhcp_client(revision=self.revision, family="IPV4", interface_id=self.svi["id"])
        self.assertRegex(client["id"], ID.format("dhcp"))
        self.assertEqual((client["family"], client["interface_id"], client["sequence"]), ("IPV4", self.svi["id"], 1))
        self.assertEqual(self.reload().sections["services"]["dhcp"]["mode"], "OVERRIDE")

    def test_add_dns_resolver_returns_ipv4_and_ipv6_resolvers(self):
        with mock.patch.object(service, "_supported", gate_open):
            v4 = service.add_dns_resolver(revision=self.revision, address="192.0.2.53")
            v6 = service.add_dns_resolver(revision=self.revision, address="2001:db8::53")
        self.assertEqual((v4["family"], v4["address"], v4["sequence"]), ("IPV4", "192.0.2.53", 1))
        self.assertEqual((v6["family"], v6["address"], v6["sequence"]), ("IPV6", "2001:db8::53", 2))
        self.assertEqual(self.reload().sections["services"]["dns"]["mode"], "OVERRIDE")

    def test_add_dns_resolver_refuses_invalid_unsupported_or_full(self):
        with self.subTest(case="refused unsupported by the real gate"):
            with self.assertRaisesRegex(service.CollectionMutationError, "not implemented"):
                service.add_dns_resolver(revision=self.revision, address="192.0.2.53")
        with mock.patch.object(service, "_supported", gate_open):
            for label, address in (("invalid address", "999.1.1.1"), ("missing address", "")):
                with self.subTest(case=f"refused {label}"):
                    with self.assertRaises(service.CollectionMutationError):
                        service.add_dns_resolver(revision=self.revision, address=address)
            self.seed(**{"services.dns.resolvers": {f"dns_{i}": {"id": f"dns_{i}"} for i in range(service.MAX_DNS_RESOLVERS)}})
            with self.subTest(case="refused limit exceeded"):
                with self.assertRaises(service.CollectionLimitError):
                    service.add_dns_resolver(revision=self.revision, address="192.0.2.54")

    def test_add_dns_search_domain_returns_the_normalized_domain(self):
        with mock.patch.object(service, "_supported", gate_open):
            domain = service.add_dns_search_domain(revision=self.revision, domain="lab.example")
        self.assertEqual((domain["domain"], domain["sequence"]), ("lab.example", 1))
        self.assertEqual(self.seeded_paths("services.dns.search_domains."), {f"services.dns.search_domains.{domain['id']}.domain"})

    def test_add_dns_search_domain_refuses_invalid_unsupported_or_full(self):
        with self.subTest(case="refused unsupported by the real gate"):
            with self.assertRaisesRegex(service.CollectionMutationError, "not implemented"):
                service.add_dns_search_domain(revision=self.revision, domain="lab.example")
        with mock.patch.object(service, "_supported", gate_open):
            with self.subTest(case="refused invalid domain"):
                with self.assertRaises(service.CollectionMutationError):
                    service.add_dns_search_domain(revision=self.revision, domain="bad domain!")
            self.seed(**{"services.dns.search_domains": {f"d_{i}": {"id": f"d_{i}"} for i in range(service.MAX_SEARCH_DOMAINS)}})
            with self.subTest(case="refused limit exceeded"):
                with self.assertRaises(service.CollectionLimitError):
                    service.add_dns_search_domain(revision=self.revision, domain="lab.example")
        self.assertEqual(len(self.reload().sections["services"]["dns"]["search_domains"]), service.MAX_SEARCH_DOMAINS)


class PbrTests(CandidateTestCase):
    def test_add_pbr_policy_returns_a_seeded_policy(self):
        policy = self.add_policy()
        self.assertRegex(policy["id"], ID.format("pbr"))
        self.assertEqual((policy["name"], policy["family"], policy["sequences"], policy["sequence"]), ("PBR-A", "IPV4", {}, 1))
        self.assertEqual(len(self.seeded_paths(f"policy.pbr.policies.{policy['id']}.")), len(service.PBR_POLICY_FIELDS))

    def test_add_pbr_sequence_returns_conventional_rule_numbers(self):
        policy = self.add_policy()
        first = service.add_pbr_sequence(revision=self.revision, policy_id=policy["id"])
        second = service.add_pbr_sequence(revision=self.revision, policy_id=policy["id"])
        self.assertRegex(first["id"], ID.format("pbrseq"))
        self.assertEqual((first["sequence"], second["sequence"]), (10, 20))
        self.assertEqual(set(service.get_pbr_policy(self.revision, policy["id"])["sequences"]), {first["id"], second["id"]})

    def test_add_pbr_sequence_refuses_an_unknown_policy_or_a_full_policy(self):
        with self.subTest(case="refused unknown policy"):
            with self.assertRaises(service.CollectionOwnershipError):
                service.add_pbr_sequence(revision=self.revision, policy_id="pbr_unknown")
        policy = self.add_policy()
        full = {f"s{i}": {"id": f"s{i}", "sequence": i} for i in range(service.MAX_PBR_SEQUENCES)}
        self.seed(**{f"policy.pbr.policies.{policy['id']}": {**policy, "sequences": full}})
        with self.subTest(case="refused limit exceeded"):
            with self.assertRaises(service.CollectionLimitError):
                service.add_pbr_sequence(revision=self.revision, policy_id=policy["id"])

    def test_add_pbr_attachment_returns_an_inbound_attachment(self):
        policy = self.add_policy()
        with mock.patch.object(service, "_supported", gate_open):
            attachment = service.add_pbr_attachment(revision=self.revision, policy_id=policy["id"], interface_id=self.svi["id"])
        self.assertRegex(attachment["id"], ID.format("attach"))
        self.assertEqual((attachment["policy_id"], attachment["interface_id"], attachment["direction"]),
                         (policy["id"], self.svi["id"], "IN"))

    def test_add_pbr_attachment_refuses_outbound_unsupported_or_foreign_interfaces(self):
        policy = self.add_policy()
        with self.subTest(case="refused outbound direction"):
            with self.assertRaisesRegex(service.CollectionMutationError, "must be IN"):
                service.add_pbr_attachment(revision=self.revision, policy_id=policy["id"], interface_id=self.svi["id"], direction="OUT")
        with self.subTest(case="refused unsupported by the real gate"):
            with self.assertRaisesRegex(service.CollectionMutationError, "not implemented"):
                service.add_pbr_attachment(revision=self.revision, policy_id=policy["id"], interface_id=self.svi["id"])
        with self.subTest(case="refused unknown interface"):
            with self.assertRaises(service.CollectionOwnershipError):
                service.add_pbr_attachment(revision=self.revision, policy_id=policy["id"], interface_id="if_unknown")
        self.assertEqual(self.reload().sections["policy"]["pbr"]["attachments"], {})


class RemoveMirrorSummaryTests(CandidateTestCase):
    def build(self):
        acl = service.add_acl(revision=self.revision, name="EDGE-IN", family="IPV4", acl_type="EXTENDED")
        ace = service.add_ace(revision=self.revision, acl_id=acl["id"], action="DENY", protocol="TCP")
        fhrp = service.add_fhrp_instance(revision=self.revision, protocol="VARP", interface_id=self.svi["id"])
        vip = service.add_fhrp_vip(revision=self.revision, instance_id=fhrp["id"], address="192.0.2.1")
        return acl, ace, fhrp, vip

    def test_remove_object_returns_after_deleting_the_object_and_its_field_states(self):
        acl, ace, fhrp, vip = self.build()
        policy = self.add_policy()
        seq = service.add_pbr_sequence(revision=self.revision, policy_id=policy["id"])
        cases = (("ace", ace["id"], acl["id"], f"security.acls.{acl['id']}.entries.{ace['id']}."),
                 ("fhrp_vip", vip["id"], fhrp["id"], f"fhrp.instances.{fhrp['id']}.virtual_ips.{vip['id']}."),
                 ("pbr_sequence", seq["id"], policy["id"], f"policy.pbr.policies.{policy['id']}.sequences.{seq['id']}."),
                 ("acl", acl["id"], "", f"security.acls.{acl['id']}."))
        for kind, object_id, parent_id, prefix in cases:
            with self.subTest(case=f"removes {kind}"):
                self.assertTrue(self.seeded_paths(prefix))
                self.assertIsNone(service.remove_object(revision=self.revision, kind=kind, object_id=object_id,
                                                        confirmation="REMOVE", parent_id=parent_id))
                self.assertEqual(self.seeded_paths(prefix), set())
        sections = service.structured_sections(self.reload())
        self.assertEqual(sections["security"]["acls"], {})
        self.assertEqual(sections["fhrp"]["instances"][fhrp["id"]]["virtual_ips"], {})
        self.assertEqual(sections["policy"]["pbr"]["policies"][policy["id"]]["sequences"], {})

    def test_mirror_accepted_field_returns_after_writing_the_target_field(self):
        acl, ace, fhrp, vip = self.build()
        cases = ((f"security.acls.{acl['id']}.description", "edge filter", lambda s: s["security"]["acls"][acl["id"]]["description"]),
                 (f"security.acls.{acl['id']}.entries.{ace['id']}.logging", True,
                  lambda s: s["security"]["acls"][acl["id"]]["entries"][ace["id"]]["logging"]),
                 (f"fhrp.instances.{fhrp['id']}.virtual_ips.{vip['id']}.address", "192.0.2.9",
                  lambda s: s["fhrp"]["instances"][fhrp["id"]]["virtual_ips"][vip["id"]]["address"]),
                 ("services.dns.domain_name", "lab.example", lambda s: s["services"]["dns"]["domain_name"]),
                 ("services.monitoring.mode", "OVERRIDE", lambda s: s["services"]["monitoring"]["mode"]))
        for path, value, read in cases:
            with self.subTest(case=f"mirrors {path.split('.')[-1]}"):
                self.assertIsNone(service.mirror_accepted_field(revision=self.revision, path=path, value=value))
                self.assertEqual(read(self.reload().sections), value)

    def test_mirror_accepted_field_refuses_unknown_or_foreign_paths(self):
        acl, *_ = self.build()
        before = self.reload().sections
        for label, path in (("unknown field", f"security.acls.{acl['id']}.colour"), ("unknown acl", "security.acls.acl_x.name"),
                            ("arbitrary path", "interfaces.x.name"), ("unknown service", "services.ntp.mode")):
            with self.subTest(case=f"refused {label}"):
                with self.assertRaises(service.CollectionOwnershipError):
                    service.mirror_accepted_field(revision=self.revision, path=path, value="x")
        self.assertEqual(self.reload().sections, before)

    def test_editor_summary_returns_ordered_rows_with_field_paths(self):
        acl, ace, fhrp, vip = self.build()
        relay = service.add_dhcp_relay(revision=self.revision, family="IPV4", interface_id=self.svi["id"], destination="192.0.2.67")
        summary = service.editor_summary(revision=self.revision, platform="arista_ceos")
        self.assertEqual(set(summary), {"sections", "interfaces", "fhrp", "nat_pools", "nat_rules", "dhcp", "dns", "monitoring",
                                        "acls", "acl_attachments", "pbr_policies", "pbr_attachments", "platform"})
        self.assertEqual(summary["platform"], "arista_ceos")
        self.assertEqual(summary["acls"][0]["paths"]["name"], f"security.acls.{acl['id']}.name")
        self.assertEqual(summary["acls"][0]["entries_ordered"][0]["paths"]["action"], f"security.acls.{acl['id']}.entries.{ace['id']}.action")
        self.assertEqual(summary["fhrp"][0]["virtual_ips_ordered"][0]["paths"]["address"],
                         f"fhrp.instances.{fhrp['id']}.virtual_ips.{vip['id']}.address")
        self.assertEqual(summary["dhcp"]["relays_ordered"][0]["paths"]["destination"], f"services.dhcp.relays.{relay['id']}.destination")
        self.assertEqual((summary["nat_pools"], summary["pbr_policies"], summary["dns"]["resolvers_ordered"]), ([], [], []))
        self.assertEqual([row["id"] for row in summary["interfaces"]], [self.svi["id"]])

    def test_has_incompatible_intent_returns_false_for_selectable_intent(self):
        acl, *_ = self.build()
        service.add_acl_attachment(revision=self.revision, acl_id=acl["id"], interface_id=self.svi["id"])
        self.assertIs(service.has_incompatible_intent(revision=self.revision, platform="arista_ceos"), False)

    def test_has_incompatible_intent_flags_unsupported_platform_intent(self):
        self.build()
        cases = {"fhrp on frr": ("ubuntu_frr", {}),
                 "nat rule on ceos": ("arista_ceos", {"nat.rules": {"nat_1": {"id": "nat_1", "family": "NAT44", "mode": "PAT"}}}),
                 "dns override on ceos": ("arista_ceos", {"services.dns.mode": "OVERRIDE"}),
                 "pbr on ceos": ("arista_ceos", {"policy.pbr.policies": {"pbr_1": {"id": "pbr_1", "family": "IPV4"}}})}
        for label, (platform, extra) in cases.items():
            with self.subTest(case=f"unsupported {label}"):
                if extra:
                    self.seed(**extra)
                self.assertIs(service.has_incompatible_intent(revision=self.revision, platform=platform), True)
