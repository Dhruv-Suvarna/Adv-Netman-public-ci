"""Platform capability registries (interface kinds and routing protocols).

The registry is the single capability truth the UI, the renderer and Tier-2
validation all read.  Per-platform / per-feature expectations are tables here;
Phase-13 checks that validation *reuses* these registries (test_phase13_capabilities).
Service/policy features are covered by ``test_phase12_service_policy``.
"""

from __future__ import annotations

from django.test import SimpleTestCase, TestCase

from core import models
from core.services import interface_intent_service, platform_drivers
from core.tests.helpers.candidates import add_interface, commit, make_candidate

Status = platform_drivers.CapabilityStatus
Protocol = platform_drivers.RoutingProtocol

CEOS_KINDS = {"ROUTED_PHYSICAL", "ACCESS", "TRUNK", "SUBINTERFACE", "SVI", "MANAGEMENT", "LOOPBACK"}
UBUNTU_KINDS = {"ROUTED_PHYSICAL", "SUBINTERFACE", "SVI", "MANAGEMENT", "LOOPBACK"}
# Phase 20.5: routed physical/subinterface/loopback/mgmt are real, fixture-tested NMAS
# implementations (see test_srlinux_driver.py); access/trunk/SVI remain NOT_IMPLEMENTED
# pending a MAC-VRF/IRB bridging model.
SRLINUX_KINDS = {"ROUTED_PHYSICAL", "SUBINTERFACE", "LOOPBACK", "MANAGEMENT"}
# Phase 20.5: same scope as SR Linix -- routed/subinterface/loopback/mgmt are real,
# fixture-tested NMAS implementations (see test_ios8000v_driver.py); access/trunk/SVI
# remain NOT_IMPLEMENTED pending a bridge-group/BVI model.
IOS_KINDS = {"ROUTED_PHYSICAL", "SUBINTERFACE", "LOOPBACK", "MANAGEMENT"}
# Phase 20.5: ConfigDB's routed-interface and VLAN/VLAN_MEMBER/VLAN_INTERFACE
# tables are real, fixture-tested NMAS implementations (see test_sonic_driver.py).
SONIC_KINDS = {"ROUTED_PHYSICAL", "SUBINTERFACE", "LOOPBACK", "MANAGEMENT", "ACCESS", "TRUNK", "SVI"}


class CapabilityRegistryTests(SimpleTestCase):
    def test_registry_shape_vocabulary_and_evidence(self):
        platforms = set(models.Platform.values)
        for registry in ("PLATFORM_CAPABILITIES", "ROUTING_CAPABILITIES", "SERVICE_POLICY_CAPABILITIES"):
            with self.subTest(registry=registry):
                self.assertEqual(set(getattr(platform_drivers, registry)), platforms)
        self.assertEqual({status.value for status in Status}, {"SUPPORTED", "NOT_IMPLEMENTED", "UNSUPPORTED", "UNKNOWN"})
        for platform, capabilities in platform_drivers.PLATFORM_CAPABILITIES.items():
            with self.subTest(platform=platform):
                self.assertEqual(set(capabilities), set(interface_intent_service.INTERFACE_KINDS))
        interface_matrix = platform_drivers.capability_matrix()
        routing_matrix = platform_drivers.routing_capability_matrix()
        for label, matrix in (("interface", interface_matrix), ("routing", routing_matrix)):
            with self.subTest(matrix=label):
                self.assertEqual({p.name for p in matrix["platforms"]}, platforms)
        self.assertTrue(any(row["kind"] == "ROUTED_PHYSICAL" for row in interface_matrix["rows"]))
        cells = [cell for row in routing_matrix["rows"] for cell in row["cells"]]
        self.assertTrue(all(cell["evidence"] for cell in cells), "every routing cell must carry evidence")
        self.assertNotIn(Status.UNKNOWN.value, {cell["status"] for cell in cells})  # every cell is classified

    def test_unknown_platform_or_kind_is_rejected(self):
        with self.assertRaises(ValueError):
            platform_drivers.capability_for("junos", "ROUTED_PHYSICAL")

    def test_selectable_interface_kinds_per_platform(self):
        all_kinds = interface_intent_service.INTERFACE_KINDS
        expected = {
            models.Platform.ARISTA_CEOS: CEOS_KINDS,
            models.Platform.UBUNTU_FRR: UBUNTU_KINDS,
            models.Platform.NOKIA_SRLINUX: SRLINUX_KINDS,
            models.Platform.CISCO_C8000V_IOSXE: IOS_KINDS,
            models.Platform.CISCO_IOSXR: IOS_KINDS,
            models.Platform.SONIC: SONIC_KINDS,
        }
        for platform, kinds in expected.items():
            with self.subTest(platform=platform):
                self.assertEqual({k for k in all_kinds if platform_drivers.is_interface_kind_selectable(platform, k)}, kinds)
                self.assertEqual({c["value"] for c in platform_drivers.implemented_interface_choices(platform)}, kinds)

    def test_status_semantics_are_distinct(self):
        """(platform, feature lookup, expected status): NOT_IMPLEMENTED != UNSUPPORTED != SUPPORTED."""
        interface = platform_drivers.capability_for
        routing = platform_drivers.capability_for_routing
        cases = [
            ("cEOS LAG", interface(models.Platform.ARISTA_CEOS, "LAG"), Status.NOT_IMPLEMENTED),
            ("cEOS BOND", interface(models.Platform.ARISTA_CEOS, "BOND"), Status.UNSUPPORTED),
            ("cEOS OSPFv2", routing("arista_ceos", Protocol.OSPFV2), Status.SUPPORTED),
            ("cEOS IS-IS", routing("arista_ceos", Protocol.ISIS), Status.SUPPORTED),
            ("FRR IS-IS", routing("ubuntu_frr", Protocol.ISIS), Status.NOT_IMPLEMENTED),
            ("cEOS EIGRP (vendor mismatch)", routing("arista_ceos", Protocol.EIGRP_IPV4), Status.UNSUPPORTED),
        ]
        for label, capability, expected in cases:
            with self.subTest(feature=label):
                self.assertEqual(capability.status, expected)

    def test_only_supported_features_are_selectable(self):
        cases = [
            ("interface: cEOS routed port", platform_drivers.is_interface_kind_selectable("arista_ceos", "ROUTED_PHYSICAL"), True),
            ("interface: cEOS LAG", platform_drivers.is_interface_kind_selectable("arista_ceos", "LAG"), False),
            ("routing: cEOS BGP", platform_drivers.is_routing_protocol_selectable("arista_ceos", Protocol.BGP_IPV4), True),
            ("routing: cEOS IS-IS", platform_drivers.is_routing_protocol_selectable("arista_ceos", Protocol.ISIS), True),
            ("routing: FRR IS-IS", platform_drivers.is_routing_protocol_selectable("ubuntu_frr", Protocol.ISIS), False),
            ("routing: SONiC OSPFv2", platform_drivers.is_routing_protocol_selectable("sonic", Protocol.OSPFV2), False),
        ]
        for label, actual, expected in cases:
            with self.subTest(feature=label):
                self.assertIs(actual, expected)
        self.assertFalse({"LAG", "BOND", "VIRTUAL"} & {
            c["value"] for c in platform_drivers.implemented_interface_choices(models.Platform.ARISTA_CEOS)
        })


class PlatformSwitchPreservationTests(TestCase):
    def test_incompatible_interface_intent_is_preserved_flagged_and_not_newly_selectable(self):
        change, intent, revision = make_candidate()
        interface = add_interface(revision, kind="ACCESS")
        commit(change, intent, revision, "device.platform", models.Platform.UBUNTU_FRR)
        revision.refresh_from_db()
        self.assertIn(interface["id"], interface_intent_service.interface_map(revision))
        editor = interface_intent_service.editor_interfaces(revision=revision, platform=models.Platform.UBUNTU_FRR)
        self.assertFalse(editor[0]["is_compatible"])
        self.assertEqual(editor[0]["capability_status"], "NOT_IMPLEMENTED")

        choices = platform_drivers.implemented_interface_choices(models.Platform.UBUNTU_FRR, preserve_kind=interface["kind"])
        preserved = next(choice for choice in choices if choice["value"] == "ACCESS")
        self.assertFalse(preserved["compatible"])
        self.assertIn("preserved", preserved["label"])

        new_only = {c["value"] for c in platform_drivers.implemented_interface_choices(models.Platform.UBUNTU_FRR)}
        self.assertNotIn("ACCESS", new_only)
        self.assertIn("SUBINTERFACE", new_only)
