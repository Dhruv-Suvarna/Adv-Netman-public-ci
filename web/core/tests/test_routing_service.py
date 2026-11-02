"""Routing intent service: static routes, RIP, OSPF, IS-IS, EIGRP and BGP.

Table-driven by design.  Most routing behavior is "commit VALUE to FIELD of an
object and expect VALID or INVALID"; that is one matrix (``FIELD_CASES``) with a
label per row, not one method per row.  Structural rules that genuinely differ
in shape (capability gating, ownership, confirmation, limits, isolation) each
get one method over their own table.

A failing row names itself: ``subTest(case="ospf area 0 normalizes")``.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest import mock

from django.test import TestCase

from core import models
from core.services import interface_intent_service, platform_drivers, routing_intent_service as service
from core.tests.helpers.candidates import (
    add_bgp_neighbor,
    add_bgp_network,
    add_binding,
    add_instance,
    add_interface,
    add_static_route,
    commit,
    make_candidate,
)

VALID, INVALID = models.FieldValidationState.VALID, models.FieldValidationState.INVALID
ANY = object()  # "the accepted value is not asserted for this row"
RoutingProtocol, CapabilityStatus = platform_drivers.RoutingProtocol, platform_drivers.CapabilityStatus


def supported(protocol, platform="arista_ceos"):
    """Exercise a structural schema whose real capability is (honestly) not SUPPORTED, in isolation."""
    cap = platform_drivers.PlatformCapability(CapabilityStatus.SUPPORTED, "test-only patch")
    return mock.patch.dict(platform_drivers.ROUTING_CAPABILITIES[platform], {protocol: cap})


def build_target(kind: str):
    """A fresh candidate + one routing object -> (context, ``path(field)``)."""
    change, intent, revision = make_candidate()
    ctx = SimpleNamespace(change=change, intent=intent, revision=revision)
    if kind in ("route4", "route6"):
        route = add_static_route(revision, family="IPV4" if kind == "route4" else "IPV6")
        return ctx, lambda field: service._route_path(route["id"], field)
    if kind == "bgp":
        instance = add_instance(revision, family="bgp", local_asn=65000)
        return ctx, lambda field: service._instance_path("bgp", instance["id"], field)
    if kind in ("bgp_neighbor", "bgp_neighbor_iface"):
        instance = add_instance(revision, family="bgp", local_asn=65000)
        neighbor = add_bgp_neighbor(revision, instance_id=instance["id"], peer_address="192.0.2.1", remote_asn=65001)
        ctx.interface = add_interface(revision)
        return ctx, lambda field: service._bgp_neighbor_path(instance["id"], neighbor["id"], field)
    protocol_by_family = {"ospf": RoutingProtocol.OSPFV2, "rip": RoutingProtocol.RIPV2, "eigrp": RoutingProtocol.EIGRP_IPV4,
                          "isis": RoutingProtocol.ISIS}
    family, _, level = kind.partition("_")  # "ospf" or "ospf_binding"
    kwargs = {"ospf": {"version": "OSPFV2"}, "rip": {"address_family": "IPV4"}, "eigrp": {"address_family": "IPV4"}, "isis": {}}[family]
    with supported(protocol_by_family[family]):
        instance = add_instance(revision, family=family, **kwargs)
        if level == "binding":
            interface = add_interface(revision)
            binding = add_binding(revision, family=family, instance_id=instance["id"], interface_id=interface["id"])
            return ctx, lambda field: service._binding_path(family, instance["id"], binding["id"], field)
    return ctx, lambda field: service._instance_path(family, instance["id"], field)


# (case label, target kind, field, value, expected validation state, expected accepted value)
FIELD_CASES = [
    ("static IPv4 destination", "route4", "destination", "192.0.2.0/24", VALID, ANY),
    ("static IPv6 destination", "route6", "destination", "2001:db8::/64", VALID, ANY),
    ("static destination is not a prefix", "route4", "destination", "not-a-prefix", INVALID, ANY),
    ("static destination has host bits", "route4", "destination", "192.0.2.5/24", INVALID, ANY),
    ("static IPv4 next hop", "route4", "next_hop_address", "192.0.2.1", VALID, ANY),
    ("static IPv6 next hop", "route6", "next_hop_address", "2001:db8::1", VALID, ANY),
    ("static next-hop family mismatch", "route4", "next_hop_address", "2001:db8::1", INVALID, ANY),
    ("static distance 1", "route4", "distance", 1, VALID, ANY),
    ("static distance 999", "route4", "distance", 999, INVALID, ANY),

    ("bgp router-id valid", "bgp", "router_id", "192.168.255.1", VALID, ANY),
    ("bgp router-id bogus", "bgp", "router_id", "bogus", INVALID, ANY),
    ("bgp local ASN 4-byte max", "bgp", "local_asn", 4200000000, VALID, ANY),
    ("bgp local ASN 0", "bgp", "local_asn", 0, INVALID, ANY),
    ("bgp neighbor IPv4 peer", "bgp_neighbor", "peer_address", "192.0.2.99", VALID, ANY),
    ("bgp neighbor family flip on commit", "bgp_neighbor", "peer_address", "2001:db8::1", INVALID, ANY),
    ("bgp neighbor description", "bgp_neighbor", "description", "R5 eBGP", VALID, ANY),
    ("bgp neighbor activates IPv6", "bgp_neighbor", "activate_ipv6", "true", VALID, True),
    ("bgp ebgp-multihop 2", "bgp_neighbor", "ebgp_multihop", 2, VALID, ANY),
    ("bgp ebgp-multihop 500", "bgp_neighbor", "ebgp_multihop", 500, INVALID, ANY),
    ("bgp next-hop-self", "bgp_neighbor", "next_hop_self", "true", VALID, True),
    ("bgp route-reflector-client", "bgp_neighbor", "route_reflector_client", "true", VALID, True),
    ("bgp shutdown", "bgp_neighbor", "shutdown", "true", VALID, True),
    ("bgp password is a reference", "bgp_neighbor", "password_ref", "vault:bgp/r1-r5", VALID, "vault:bgp/r1-r5"),

    ("ospf router-id valid", "ospf", "router_id", "192.168.255.1", VALID, ANY),
    ("ospf router-id invalid", "ospf", "router_id", "not-an-ip", INVALID, ANY),
    ("ospf area 0 normalizes to dotted", "ospf_binding", "area", "0", VALID, "0.0.0.0"),
    ("ospf dotted area", "ospf_binding", "area", "0.0.0.1", VALID, ANY),
    ("ospf invalid area", "ospf_binding", "area", "not-an-area", INVALID, ANY),
    ("ospf passive", "ospf_binding", "passive", "true", VALID, True),
    ("ospf cost 100", "ospf_binding", "cost", 100, VALID, ANY),
    ("ospf cost 99999", "ospf_binding", "cost", 99999, INVALID, ANY),
    ("ospf network type point-to-point", "ospf_binding", "network_type", "POINT_TO_POINT", VALID, ANY),
    ("ospf network type unknown", "ospf_binding", "network_type", "BROADCAST_INVALID", INVALID, ANY),

    ("rip passive", "rip_binding", "passive", "true", VALID, True),
    ("eigrp ASN 100", "eigrp", "asn", 100, VALID, ANY),
    ("eigrp ASN 999999", "eigrp", "asn", 999999, INVALID, ANY),
    ("eigrp passive", "eigrp_binding", "passive", "true", VALID, True),
    ("isis NET valid", "isis", "net", "49.0001.0000.0000.0001.00", VALID, ANY),
    ("isis NET invalid", "isis", "net", "not-a-net", INVALID, ANY),
    ("isis level 1-2", "isis", "level", "LEVEL_1_2", VALID, ANY),
    ("isis level 9", "isis", "level", "LEVEL_9", INVALID, ANY),
    ("isis IPv6 family flag", "isis", "address_family_ipv6", "true", VALID, True),
    ("isis passive", "isis_binding", "passive", "true", VALID, True),
]


class RoutingFieldValidationMatrixTests(TestCase):
    def test_field_commit_matrix(self):
        # One target object per kind; its rows run in table order (as the per-protocol tests did on one object).
        targets = {}
        for label, kind, field, value, expected_state, expected_value in FIELD_CASES:
            with self.subTest(case=label):
                if kind not in targets:
                    targets[kind] = build_target(kind)
                ctx, path = targets[kind]
                result = commit(ctx.change, ctx.intent, ctx.revision, path(field), value)
                self.assertEqual(result.validation_state, expected_state, result.validation_message)
                if expected_value is not ANY:
                    self.assertEqual(result.accepted_value, expected_value)

    def test_invalid_commit_keeps_the_last_accepted_value(self):
        ctx, path = build_target("route4")
        commit(ctx.change, ctx.intent, ctx.revision, path("destination"), "192.0.2.0/24")
        rejected = commit(ctx.change, ctx.intent, ctx.revision, path("destination"), "not-a-prefix")
        self.assertEqual(rejected.validation_state, INVALID)
        self.assertEqual(rejected.accepted_value, "192.0.2.0/24")


class RoutingObjectCreationTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.change, cls.intent, cls.revision = make_candidate()

    def test_every_object_gets_a_stable_opaque_id(self):
        rev = self.revision
        bgp = add_instance(rev, family="bgp", local_asn=65000)
        ospf = add_instance(rev, family="ospf", version="OSPFV2")
        interface = add_interface(rev)
        objects = {
            "route": add_static_route(rev),
            "bgp": bgp,
            "peer": add_bgp_neighbor(rev, instance_id=bgp["id"], peer_address="192.0.2.1", remote_asn=65001),
            "net": add_bgp_network(rev, instance_id=bgp["id"], family="IPV4", cidr="192.0.2.0/24"),
            "ospf": ospf,
            "bind": add_binding(rev, family="ospf", instance_id=ospf["id"], interface_id=interface["id"]),
            "rip": add_instance(rev, family="rip", address_family="IPV4"),
        }
        with supported(RoutingProtocol.ISIS):
            objects["isis"] = add_instance(rev, family="isis")
        for prefix, obj in objects.items():
            with self.subTest(prefix=prefix):
                self.assertRegex(obj["id"], rf"^{prefix}_[0-9a-f]{{16}}$")
        self.assertNotEqual(add_static_route(rev)["id"], add_static_route(rev)["id"])

    def test_valid_objects_are_represented_with_their_derived_defaults(self):
        rev = self.revision
        bgp = add_instance(rev, family="bgp", local_asn=65000)
        v4 = add_bgp_neighbor(rev, instance_id=bgp["id"], peer_address="192.0.2.1", remote_asn=65001)
        v6 = add_bgp_neighbor(rev, instance_id=bgp["id"], peer_address="2001:db8::1", remote_asn=65001)
        cases = {
            "bgp local ASN": (bgp["local_asn"], 65000),
            "bgp IPv4 peer family": (v4["family"], "IPV4"),
            "bgp IPv4 peer activates only IPv4": ((v4["activate_ipv4"], v4["activate_ipv6"]), (True, False)),
            "bgp IPv6 peer family": (v6["family"], "IPV6"),
            "bgp IPv6 peer activates IPv6": (v6["activate_ipv6"], True),
            "bgp remote ASN": (v4["remote_asn"], 65001),
            "bgp IPv4 network": (add_bgp_network(rev, instance_id=bgp["id"], family="IPV4", cidr="192.0.2.0/24")["cidr"], "192.0.2.0/24"),
            "bgp IPv6 network": (add_bgp_network(rev, instance_id=bgp["id"], family="IPV6", cidr="2001:db8::/32")["cidr"], "2001:db8::/32"),
            "ospfv2": (add_instance(rev, family="ospf", version="OSPFV2")["version"], "OSPFV2"),
            "ospfv3": (add_instance(rev, family="ospf", version="OSPFV3")["version"], "OSPFV3"),
            "ripv2 is an IPv4 instance": (add_instance(rev, family="rip", address_family="IPV4")["address_family"], "IPV4"),
        }
        with supported(RoutingProtocol.ISIS):
            isis = add_instance(rev, family="isis")
        cases["isis defaults to IPv4 only"] = ((isis["address_family_ipv4"], isis["address_family_ipv6"]), (True, False))
        with supported(RoutingProtocol.RIPNG):
            cases["ripng is an IPv6 instance"] = (add_instance(rev, family="rip", address_family="IPV6")["address_family"], "IPV6")
        with supported(RoutingProtocol.EIGRP_IPV6):
            cases["eigrp IPv6 instance"] = (add_instance(rev, family="eigrp", address_family="IPV6")["address_family"], "IPV6")
        for label, (actual, expected) in cases.items():
            with self.subTest(case=label):
                self.assertEqual(actual, expected)

    def test_invalid_creation_input_is_rejected(self):
        rev = self.revision
        bgp = add_instance(rev, family="bgp", local_asn=65000)
        rejected = {
            "bgp local ASN too large": lambda: add_instance(rev, family="bgp", local_asn=99999999999),
            "bgp local ASN not a number": lambda: add_instance(rev, family="bgp", local_asn="not-a-number"),
            "bgp peer not an address": lambda: add_bgp_neighbor(rev, instance_id=bgp["id"], peer_address="not-an-address", remote_asn=65001),
            "bgp remote ASN 0": lambda: add_bgp_neighbor(rev, instance_id=bgp["id"], peer_address="192.0.2.1", remote_asn=0),
            "bgp network not a network": lambda: add_bgp_network(rev, instance_id=bgp["id"], family="IPV4", cidr="not-a-network"),
            "bgp network has host bits": lambda: add_bgp_network(rev, instance_id=bgp["id"], family="IPV4", cidr="192.0.2.5/24"),
        }
        for label, attempt in rejected.items():
            with self.subTest(case=label), self.assertRaises(service.CollectionMutationError):
                attempt()

    def test_rip_has_no_version_field_so_ripv1_can_never_be_enabled(self):
        self.assertNotIn("version", service.INSTANCE_FIELDS["rip"])

    def test_bgp_neighbor_authentication_is_reference_only(self):
        self.assertNotIn("password", service.BGP_NEIGHBOR_FIELDS)
        self.assertIn("password_ref", service.BGP_NEIGHBOR_FIELDS)


class RoutingCapabilityGateTests(TestCase):
    """New objects are refused where the registry says NOT_IMPLEMENTED / UNSUPPORTED; real status is asserted unpatched."""

    def test_new_objects_are_refused_on_platforms_that_cannot_render_them(self):
        # (label, platform, device, family, kwargs, protocol whose registry status is asserted, expected status)
        cases = [
            ("IS-IS on SR Linux (NOT_IMPLEMENTED)", models.Platform.NOKIA_SRLINUX, "family", "isis", {},
             RoutingProtocol.ISIS, CapabilityStatus.NOT_IMPLEMENTED),
            ("OSPF on SONiC (no verified config_db schema)", models.Platform.SONIC, "family", "ospf", {"version": "OSPFV2"},
             RoutingProtocol.OSPFV2, CapabilityStatus.NOT_IMPLEMENTED),
            ("RIPng on cEOS (no evidence)", models.Platform.ARISTA_CEOS, "family", "rip", {"address_family": "IPV6"},
             RoutingProtocol.RIPNG, CapabilityStatus.NOT_IMPLEMENTED),
            ("EIGRP on cEOS (Cisco-proprietary)", models.Platform.ARISTA_CEOS, "family", "eigrp", {"address_family": "IPV4"},
             RoutingProtocol.EIGRP_IPV4, CapabilityStatus.UNSUPPORTED),
            ("EIGRP on Ubuntu/FRR (no eigrpd)", models.Platform.UBUNTU_FRR, "family", "eigrp", {"address_family": "IPV4"},
             RoutingProtocol.EIGRP_IPV4, CapabilityStatus.NOT_IMPLEMENTED),
            ("IS-IS on Ubuntu/FRR", models.Platform.UBUNTU_FRR, "family", "isis", {}, RoutingProtocol.ISIS, CapabilityStatus.NOT_IMPLEMENTED),
        ]
        for label, platform, mode, family, kwargs, protocol, status in cases:
            with self.subTest(case=label):
                _, _, revision = make_candidate(platform=platform, device_name="X1")
                if protocol is not None:
                    self.assertEqual(platform_drivers.capability_for_routing(platform, protocol).status, status)
                with self.assertRaises(service.CollectionMutationError):
                    if mode == "static":
                        add_static_route(revision)
                    else:
                        add_instance(revision, family=family, **kwargs)

    def test_supported_platform_allows_creation(self):
        _, _, revision = make_candidate()
        self.assertIsNotNone(add_instance(revision, family="rip", address_family="IPV4"))
        _, _, frr_revision = make_candidate(platform=models.Platform.UBUNTU_FRR, device_name="R3")
        self.assertIsNotNone(add_instance(frr_revision, family="rip", address_family="IPV4"))
        self.assertIsNotNone(add_instance(frr_revision, family="rip", address_family="IPV6"))

    def test_platform_switch_preserves_routing_intent_but_blocks_new_objects(self):
        change, intent, revision = make_candidate()
        ospf = add_instance(revision, family="ospf", version="OSPFV2")
        bgp = add_instance(revision, family="bgp", local_asn=65001)
        commit(change, intent, revision, "device.platform", "sonic")
        revision.refresh_from_db()
        routing = service.routing_map(revision)
        self.assertIn(ospf["id"], routing["ospf"])
        self.assertIn(bgp["id"], routing["bgp"])
        # Phase 20.5: SONiC now implements BGP (config_db BGP_GLOBALS/BGP_NEIGHBOR), so a
        # NEW BGP instance is legitimately allowed post-switch; OSPF has no verified
        # config_db schema yet, so it remains the genuinely-blocked case here.
        self.assertIsNotNone(add_instance(revision, family="bgp", local_asn=65099))
        with self.assertRaises(service.CollectionMutationError):
            add_instance(revision, family="ospf", version="OSPFV2")


class RoutingOwnershipAndLifecycleTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.change, cls.intent, cls.revision = make_candidate()
        _, _, cls.foreign_revision = make_candidate(device_name="R2")
        cls.foreign_interface = add_interface(cls.foreign_revision)

    def test_interface_bindings_must_reference_this_candidates_interfaces(self):
        for label, family, protocol, kwargs in (
            ("ospf", "ospf", RoutingProtocol.OSPFV2, {"version": "OSPFV2"}),
            ("rip", "rip", RoutingProtocol.RIPV2, {"address_family": "IPV4"}),
            ("isis", "isis", RoutingProtocol.ISIS, {}),
        ):
            with self.subTest(protocol=label), supported(protocol):
                instance = add_instance(self.revision, family=family, **kwargs)
                own = add_interface(self.revision, name=f"Ethernet-{label}")
                self.assertEqual(
                    add_binding(self.revision, family=family, instance_id=instance["id"], interface_id=own["id"])["interface_id"],
                    own["id"],
                )
                with self.assertRaises(service.CollectionOwnershipError):
                    add_binding(self.revision, family=family, instance_id=instance["id"], interface_id=self.foreign_interface["id"])

    def test_interface_references_on_fields_must_be_local(self):
        route = add_static_route(self.revision)
        commit(self.change, self.intent, self.revision, service._route_path(route["id"], "next_hop_type"), "INTERFACE")
        ctx, neighbor_path = build_target("bgp_neighbor")
        own = ctx.interface
        cases = {
            "static exit interface (local)": (self.change, self.intent, self.revision, service._route_path(route["id"], "next_hop_interface_id"),
                                              add_interface(self.revision, name="Ethernet9")["id"], VALID),
            "static exit interface (foreign)": (self.change, self.intent, self.revision, service._route_path(route["id"], "next_hop_interface_id"),
                                                self.foreign_interface["id"], INVALID),
            "bgp update source (local)": (ctx.change, ctx.intent, ctx.revision, neighbor_path("update_source_interface_id"), own["id"], VALID),
            "bgp update source (foreign)": (ctx.change, ctx.intent, ctx.revision, neighbor_path("update_source_interface_id"),
                                            self.foreign_interface["id"], INVALID),
        }
        for label, (change, intent, revision, path, value, expected) in cases.items():
            with self.subTest(case=label):
                self.assertEqual(commit(change, intent, revision, path, value).validation_state, expected)

    def test_removal_requires_the_explicit_confirmation_word(self):
        rev = self.revision
        bgp = add_instance(rev, family="bgp", local_asn=65000)
        route = add_static_route(rev)
        neighbor = add_bgp_neighbor(rev, instance_id=bgp["id"], peer_address="192.0.2.1", remote_asn=65001)
        network = add_bgp_network(rev, instance_id=bgp["id"], family="IPV4", cidr="192.0.2.0/24")
        cases = {
            "static route": (lambda c: service.remove_static_route(revision=rev, route_id=route["id"], confirmation=c),
                             lambda: route["id"] in service.routing_map(rev)["static_routes"]),
            "bgp neighbor": (lambda c: service.remove_bgp_neighbor(revision=rev, instance_id=bgp["id"], peer_id=neighbor["id"], confirmation=c),
                             lambda: neighbor["id"] in service.routing_map(rev)["bgp"][bgp["id"]]["neighbors"]),
            "bgp network": (lambda c: service.remove_bgp_network(revision=rev, instance_id=bgp["id"], net_id=network["id"], confirmation=c),
                            lambda: network["id"] in service.routing_map(rev)["bgp"][bgp["id"]]["networks"]),
        }
        for label, (remove, still_present) in cases.items():
            with self.subTest(object=label):
                with self.assertRaises(service.CollectionMutationError):
                    remove("no")
                self.assertTrue(still_present())
                remove("REMOVE")
                self.assertFalse(still_present())

    def test_mutation_requires_a_draft_change_and_respects_collection_limits(self):
        with mock.patch.object(service, "MAX_STATIC_ROUTES_PER_REVISION", 1):
            add_static_route(self.revision)
            with self.assertRaises(service.CollectionLimitError):
                add_static_route(self.revision)
        bgp = add_instance(self.revision, family="bgp", local_asn=65000)
        with mock.patch.object(service, "MAX_BGP_NEIGHBORS_PER_INSTANCE", 1):
            add_bgp_neighbor(self.revision, instance_id=bgp["id"], peer_address="192.0.2.1", remote_asn=65001)
            with self.assertRaises(service.CollectionLimitError):
                add_bgp_neighbor(self.revision, instance_id=bgp["id"], peer_address="192.0.2.2", remote_asn=65002)
        route = add_static_route(self.revision)
        self.change.lifecycle_state = models.ChangeLifecycleState.VALIDATED
        self.change.save(update_fields=["lifecycle_state", "updated_at"])
        with self.assertRaises(service.DraftOnlyError):
            add_static_route(self.revision)
        with self.assertRaises(service.DraftOnlyError):
            service.mirror_accepted_field(
                revision=self.revision, path=f"routing.static_routes.{route['id']}.destination", value="10.0.0.0/24"
            )

    def test_mirror_accepted_field_rejects_unknown_objects_and_fields(self):
        route = add_static_route(self.revision)
        for label, path in (
            ("unknown object", "routing.static_routes.route_doesnotexist.destination"),
            ("unknown field", f"routing.static_routes.{route['id']}.not_a_real_field"),
        ):
            with self.subTest(case=label), self.assertRaises(service.CollectionOwnershipError):
                service.mirror_accepted_field(revision=self.revision, path=path, value="x")


class RoutingNamespaceAndOrderingTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.change, cls.intent, cls.revision = make_candidate()

    def test_routing_namespace_is_created_safely_and_leaves_other_namespaces_alone(self):
        routing = service.routing_map(self.revision)
        self.assertEqual(set(routing), set(service.PROTOCOL_FAMILIES))
        self.assertTrue(all(routing[family] == {} for family in service.PROTOCOL_FAMILIES))
        interface = add_interface(self.revision)
        self.revision.sections = {**self.revision.sections, "nat": {"marker": True}}
        self.revision.save(update_fields=["sections"])
        add_static_route(self.revision)
        self.revision.refresh_from_db()
        self.assertIn(interface["id"], self.revision.sections["interfaces"])
        self.assertEqual(self.revision.sections["nat"], {"marker": True})
        self.assertEqual(self.revision._meta.get_field("sections").get_internal_type(), "JSONField")  # no schema migration

    def test_objects_are_ordered_by_sequence(self):
        routes = [add_static_route(self.revision), add_static_route(self.revision)]
        self.assertEqual([r["id"] for r in service.ordered_static_routes(self.revision)], [r["id"] for r in routes])
        instances = [add_instance(self.revision, family="ospf", version="OSPFV2"), add_instance(self.revision, family="ospf", version="OSPFV3")]
        self.assertEqual([r["id"] for r in service.ordered_instances(self.revision, "ospf")], [i["id"] for i in instances])

    def test_editing_one_object_does_not_alter_siblings_or_interfaces(self):
        interface = add_interface(self.revision, name="Ethernet1")
        first, second = add_static_route(self.revision), add_static_route(self.revision)
        commit(self.change, self.intent, self.revision, service._route_path(first["id"], "destination"), "10.0.0.0/24")
        self.revision.refresh_from_db()
        routes = service.routing_map(self.revision)["static_routes"]
        self.assertEqual((routes[first["id"]]["destination"], routes[second["id"]]["destination"]), ("10.0.0.0/24", ""))
        self.assertEqual(interface_intent_service.get_interface(self.revision, interface["id"])["name"], "Ethernet1")
