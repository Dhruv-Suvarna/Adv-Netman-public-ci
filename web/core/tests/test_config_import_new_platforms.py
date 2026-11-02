"""SR Linix / IOS XR / SONiC existing-config import (Phase 20.5 continuation).

No SR Linix, IOS XR, or SONiC node is deployed in this lab, so there is no
live capture transport for these platforms -- but that is a LIVE
VERIFICATION limitation, not a software-implementation limitation. These
tests exercise the exact same canonical-apply pipeline
(``config_import.service._apply_parsed_config``) that the live cEOS/FRR
import already uses, fed by ``import_from_fixture`` instead of a live fetch.
Every assertion here is therefore IMPLEMENTED / FIXTURE TESTED, never LIVE
TESTED.
"""

from __future__ import annotations

from django.test import TestCase

from core import models
from core.services import candidate_renderer
from core.services.config_import import service as import_service
from core.services.config_import import parser_iosxr, parser_sonic, parser_srlinux
from core.services.execution.writers import srlinux_gnmi
from core.tests.helpers.candidates import make_candidate

SRL_FIXTURE = {
    "system": {"name": {"host-name": "SRL1"}},
    "interface": {
        "ethernet-1/1": {
            "admin-state": "enable", "description": "to R2", "mtu": 9000,
            "subinterface": [{"index": 0, "type": "routed", "admin-state": "enable",
                               "ipv4": {
                                   "address": [{"ip-prefix": "192.0.2.1/31"}],
                                   "dhcp-relay": {"server": ["192.0.2.53"]},
                               }}],
        },
        "ethernet-1/2": {
            "admin-state": "enable", "vlan-tagging": True,
            "subinterface": [{"index": 100, "type": "routed", "admin-state": "enable",
                               "vlan": {"encap": {"single-tagged": {"vlan-id": 100}}},
                               "ipv6": {"address": [{"ip-prefix": "2001:db8::1/64"}]}}],
        },
    },
    "network-instance": [
        {"name": "default", "interface": [{"name": "ethernet-1/1.0"}],
         "static-routes": {"route": [{"prefix": "10.0.0.0/8", "next-hop-group": "nhg-1", "preference": 110}]},
         "next-hop-groups": {"group": [{"name": "nhg-1", "next-hop": [{"index": 1, "ip-address": "192.0.2.0"}]}]},
         "protocols": {
             "ospf": {"instance": [{"name": "10", "version": "ospf-v2", "router-id": "1.1.1.1",
                                     "area": [{"area-id": "0.0.0.0", "interface": [{"interface-name": "ethernet-1/1.0"}]}]}]},
             "bgp": {"autonomous-system": 65010, "router-id": "1.1.1.1",
                     "group": [{"name": "peer-1", "ipv4-unicast": {"admin-state": "enable"}}],
                     "neighbor": [{"peer-address": "192.0.2.5", "peer-group": "peer-1", "peer-as": 65020}]}}},
    ],
    "acl": {"ipv4-filter": [{"name": "EDGE-IN", "entry": [
        {"sequence-id": 10, "match": {"source-ip": {"prefix": "10.0.0.0/8"}}, "action": {"accept": {}}}]}]},
    "system-security": {"unmodeled": True},
}

IOSXR_FIXTURE = """
hostname XR1
!
interface GigabitEthernet0/0/0/0
 description to R2
 mtu 9000
 no shutdown
 ipv4 address 192.0.2.1 255.255.255.254
!
router static
 address-family ipv4 unicast
  10.0.0.0/8 192.0.2.0 110
!
router ospf 10
 router-id 1.1.1.1
 area 0.0.0.0
  interface GigabitEthernet0/0/0/0
   network point-to-point
!
router rip
 interface GigabitEthernet0/0/0/0
  passive-interface
!
router bgp 65010
 bgp router-id 1.1.1.1
 neighbor 192.0.2.5
  remote-as 65020
  address-family ipv4 unicast
!
ipv4 access-list EDGE-IN
 10 permit tcp 10.0.0.0/8 any
!
dhcp ipv4
 profile relay4 relay
  helper-address vrf default 192.0.2.53
 interface GigabitEthernet0/0/0/0 relay profile relay4
!
dhcp ipv6
 profile relay6 relay
  helper-address vrf default 2001:db8::53
 interface GigabitEthernet0/0/0/0 relay profile relay6
!
telemetry model-driven
 sensor-group SG1
!
"""

SONIC_FIXTURE = {
    "DEVICE_METADATA": {"localhost": {"hostname": "SONIC1"}},
    "INTERFACE": {"Ethernet0": {}, "Ethernet0|192.0.2.1/31": {}},
    "STATIC_ROUTE": {"default|10.0.0.0/8": {"nexthop": "192.0.2.0", "distance": "110"}},
    "BGP_GLOBALS": {"default": {"local_asn": "65010", "router_id": "1.1.1.1"}},
    "BGP_NEIGHBOR": {"default|192.0.2.5": {"asn": "65020"}},
    "BGP_NEIGHBOR_AF": {"default|192.0.2.5|ipv4_unicast": {"admin_status": "true"}},
    "ACL_TABLE": {"EDGE-IN": {"type": "L3", "policy_desc": "EDGE-IN", "ports": ["Ethernet0"], "stage": "ingress"}},
    "ACL_RULE": {"EDGE-IN|RULE_10": {"PRIORITY": "10", "PACKET_ACTION": "FORWARD", "SRC_IP": "10.0.0.0/8"}},
    "VXLAN_TUNNEL": {"unmodeled": {"foo": "bar"}},
}


class ImportSoftwareExistsButIsFixtureOnlyTests(TestCase):
    """No live node exists for these platforms -- confirm the software itself
    (parser + canonical-apply pipeline) genuinely works, fixture-tested."""

    def test_srlinux_semantic_round_trip(self):
        change, intent, revision = make_candidate(
            platform=models.Platform.NOKIA_SRLINUX, target_type=models.DeviceIntentTargetType.EXISTING_DEVICE)
        result = import_service.import_from_fixture(
            change=change, intent=intent, revision=revision, device_name="SRL1",
            platform="nokia_srlinux", source=SRL_FIXTURE)
        self.assertEqual(result.status, "imported")
        # Two physical parents plus the explicitly modeled tagged child.
        self.assertEqual(result.feature_counts["interfaces"], 3)
        self.assertEqual(result.provenance["parser_version"], "srlinux-json-1.0")
        self.assertIn("no live capture transport", result.provenance["source"])
        revision.refresh_from_db()
        text = candidate_renderer.render(intent, revision)["text"]
        self.assertIn("set system name host-name SRL1", text)
        self.assertIn("set interface ethernet-1/1 subinterface 0 ipv4 address 192.0.2.1/31", text)
        self.assertIn("set interface ethernet-1/2 subinterface 100 ipv6 address 2001:db8::1/64", text)
        self.assertIn("set network-instance default static-routes route 10.0.0.0/8", text)
        self.assertIn("set network-instance default protocols ospf instance 10 area 0.0.0.0 interface ethernet-1/1.0", text)
        self.assertIn("set network-instance default protocols bgp neighbor 192.0.2.5 peer-as 65020", text)
        self.assertIn("set acl ipv4-filter EDGE-IN entry 10 match source-ip prefix 10.0.0.0/8", text)
        self.assertIn("set interface ethernet-1/1 subinterface 0 ipv4 dhcp-relay server [ 192.0.2.53 ]", text)
        self.assertEqual(result.feature_counts["dhcp_relays"], 1)
        writer_plan = srlinux_gnmi.build_set_plan(text)
        self.assertTrue(writer_plan.atomic)
        self.assertIn("/network-instance default protocols bgp neighbor 192.0.2.5 peer-as 65020",
                      writer_plan.update[0][1])
        unmanaged = revision.sections["_import"]["unmanaged"]
        self.assertTrue(any("system-security" in b["label"] for b in unmanaged))

    def test_iosxr_semantic_round_trip(self):
        change, intent, revision = make_candidate(
            platform=models.Platform.CISCO_IOSXR, target_type=models.DeviceIntentTargetType.EXISTING_DEVICE)
        result = import_service.import_from_fixture(
            change=change, intent=intent, revision=revision, device_name="XR1",
            platform="cisco_iosxr", source=IOSXR_FIXTURE)
        self.assertEqual(result.status, "imported")
        self.assertEqual(result.provenance["parser_version"], "iosxr-1.0")
        revision.refresh_from_db()
        text = candidate_renderer.render(intent, revision)["text"]
        self.assertIn("hostname XR1", text)
        self.assertIn("ipv4 address 192.0.2.1 255.255.255.254", text)
        self.assertIn("router ospf 10", text)
        self.assertIn("network point-to-point", text)
        self.assertIn("router rip", text)
        self.assertIn("  passive-interface", text)
        self.assertIn("router bgp 65010", text)
        self.assertIn("remote-as 65020", text)
        self.assertIn("ipv4 access-list EDGE-IN", text)
        self.assertIn("dhcp ipv4", text)
        self.assertIn("helper-address vrf default 192.0.2.53", text)
        self.assertIn("dhcp ipv6", text)
        self.assertIn("helper-address vrf default 2001:db8::53", text)
        self.assertEqual(result.feature_counts["dhcp_relays"], 2)
        unmanaged = revision.sections["_import"]["unmanaged"]
        self.assertTrue(any("Telemetry" in b["label"] for b in unmanaged))

    def test_sonic_semantic_round_trip_is_byte_identical_json(self):
        change, intent, revision = make_candidate(
            platform=models.Platform.SONIC, target_type=models.DeviceIntentTargetType.EXISTING_DEVICE)
        result = import_service.import_from_fixture(
            change=change, intent=intent, revision=revision, device_name="SONIC1",
            platform="sonic", source=SONIC_FIXTURE)
        self.assertEqual(result.status, "imported")
        self.assertEqual(result.provenance["parser_version"], "sonic-configdb-1.0")
        revision.refresh_from_db()
        text = candidate_renderer.render(intent, revision)["text"]
        body = "\n".join(line for line in text.splitlines() if not line.startswith("!") and line.strip())
        import json
        self.assertEqual(json.loads(body), {k: v for k, v in SONIC_FIXTURE.items() if k != "VXLAN_TUNNEL"})
        unmanaged = revision.sections["_import"]["unmanaged"]
        self.assertTrue(any("VXLAN_TUNNEL" in b["label"] for b in unmanaged))

    def test_no_platform_gets_a_fabricated_live_import(self):
        """import_from_fixture never claims live status, and platforms with a
        real live transport are untouched by this fixture-only entrypoint."""
        for platform, source in (
            ("nokia_srlinux", SRL_FIXTURE), ("cisco_iosxr", IOSXR_FIXTURE), ("sonic", SONIC_FIXTURE),
        ):
            with self.subTest(platform=platform):
                change, intent, revision = make_candidate(
                    platform=platform, target_type=models.DeviceIntentTargetType.EXISTING_DEVICE)
                result = import_service.import_from_fixture(
                    change=change, intent=intent, revision=revision, device_name="X",
                    platform=platform, source=source)
                self.assertIn("fixture", result.provenance["source"])
                self.assertNotIn("live", result.provenance["source"].lower().replace("no live", ""))

    def test_unavailable_platform_is_refused_not_fabricated(self):
        change, intent, revision = make_candidate(platform=models.Platform.ARISTA_CEOS)
        result = import_service.import_from_fixture(
            change=change, intent=intent, revision=revision, device_name="R1",
            platform="made_up_platform", source="")
        self.assertEqual(result.status, "unavailable")

    def test_fixture_platform_must_match_candidate_before_any_mutation(self):
        change, intent, revision = make_candidate(platform=models.Platform.SONIC)
        before = revision.sections.copy()
        result = import_service.import_from_fixture(
            change=change, intent=intent, revision=revision, device_name="wrong-platform",
            platform="nokia_srlinux", source=SRL_FIXTURE)
        self.assertEqual(result.status, "unavailable")
        self.assertIn("does not match", result.message)
        revision.refresh_from_db()
        self.assertEqual(revision.sections, before)


class UnmanagedPreservationNewPlatformsTests(TestCase):
    def test_srlinux_unmanaged_survives_editing_a_supported_feature(self):
        change, intent, revision = make_candidate(
            platform=models.Platform.NOKIA_SRLINUX, target_type=models.DeviceIntentTargetType.EXISTING_DEVICE)
        import_service.import_from_fixture(
            change=change, intent=intent, revision=revision, device_name="SRL1",
            platform="nokia_srlinux", source=SRL_FIXTURE)
        revision.refresh_from_db()
        from core.services import interface_intent_service
        interfaces = interface_intent_service.ordered_interfaces(revision)
        eth1 = next(i for i in interfaces if i["name"] == "ethernet-1/1")
        interface_intent_service.add_address(revision=revision, interface_id=eth1["id"], family="IPV6", source="MANUAL")
        revision.refresh_from_db()
        unmanaged_after = revision.sections["_import"]["unmanaged"]
        self.assertTrue(any("system-security" in b["label"] for b in unmanaged_after))

    def test_unknown_fields_inside_known_structured_tables_are_preserved(self):
        sonic = parser_sonic.parse({
            "DEVICE_METADATA": {"localhost": {"hostname": "S1"}},
            "STATIC_ROUTE": {"default|10.0.0.0/8": {"nexthop": "192.0.2.1", "blackhole": "false"}},
        })
        self.assertTrue(any("unmodeled fields" in block.label and "blackhole" in "".join(block.lines)
                            for block in sonic.unmanaged_blocks))

        srl = parser_srlinux.parse({
            "system": {"name": {"host-name": "SRL1"}},
            "interface": {"ethernet-1/1": {"admin-state": "enable", "lldp": {"admin-state": "enable"}}},
            "network-instance": [],
        })
        self.assertTrue(any("unmodeled fields" in block.label and "lldp" in "".join(block.lines)
                            for block in srl.unmanaged_blocks))

    def test_iosxr_standard_acl_and_unknown_subcommand_are_both_handled(self):
        parsed = parser_iosxr.parse("""
ipv4 access-list MGMT
 10 permit 203.0.113.5/32
 20 deny tcp any any eq 22
!
""")
        self.assertEqual(len(parsed.acls), 1)
        self.assertEqual(parsed.acls[0].acl_type, "STANDARD")
        self.assertEqual(parsed.acls[0].entries[0]["source_type"], "HOST")
        self.assertIn("eq 22", "\n".join(parsed.acls[0].preserved_lines))

    def test_sonic_vlan_tables_import_access_trunk_and_svi(self):
        source = {
            "DEVICE_METADATA": {"localhost": {"hostname": "S1"}},
            "VLAN": {"Vlan10": {"vlanid": "10"}, "Vlan20": {"vlanid": "20"}},
            "VLAN_MEMBER": {
                "Vlan10|Ethernet0": {"tagging_mode": "untagged"},
                "Vlan10|Ethernet4": {"tagging_mode": "untagged"},
                "Vlan20|Ethernet4": {"tagging_mode": "tagged"},
            },
            "VLAN_INTERFACE": {"Vlan20": {}, "Vlan20|192.0.2.1/24": {}},
        }
        parsed = parser_sonic.parse(source)
        by_name = {interface.name: interface for interface in parsed.interfaces}
        self.assertEqual(by_name["Ethernet0"].kind, "ACCESS")
        self.assertEqual(by_name["Ethernet0"].access_vlan, 10)
        self.assertEqual(by_name["Ethernet4"].kind, "TRUNK")
        self.assertEqual(by_name["Ethernet4"].trunk_allowed_vlans, [10, 20])
        self.assertEqual(by_name["Ethernet4"].native_vlan, 10)
        self.assertEqual(by_name["Vlan20"].kind, "SVI")
        self.assertEqual(by_name["Vlan20"].vlan_id, 20)

    def test_sonic_orphan_structured_objects_are_preserved(self):
        parsed = parser_sonic.parse({
            "DEVICE_METADATA": {"localhost": {"hostname": "S1"}},
            "VLAN": {"Vlan999": {"vlanid": "999"}},
            "BGP_GLOBALS": {"default": {"local_asn": "65000"}},
            "BGP_NEIGHBOR_AF": {
                "default|192.0.2.9|ipv4_unicast": {"admin_status": "true"},
            },
            "ACL_TABLE": {
                "EDGE": {"type": "L3", "ports": ["Ethernet88"], "stage": "ingress"},
            },
        })
        labels = [block.label for block in parsed.unmanaged_blocks]
        self.assertTrue(any("standalone VLAN" in label for label in labels))
        self.assertTrue(any("neighbor entry is missing" in label for label in labels))
        self.assertTrue(any("interface 'Ethernet88' is missing" in label for label in labels))

    def test_unresolved_cross_references_are_preserved_by_shared_apply(self):
        source = {
            "system": {"name": {"host-name": "SRL1"}},
            "interface": {
                "ethernet-1/1": {
                    "subinterface": [{
                        "index": 0,
                        "acl": {"input": {"ipv4-filter": "MISSING-ACL"}},
                    }],
                },
            },
            "network-instance": [{
                "name": "default",
                "protocols": {"ospf": {"instance": [{
                    "name": "10", "version": "ospf-v2",
                    "area": [{
                        "area-id": "0.0.0.0",
                        "interface": [{"interface-name": "ethernet-9/9.0"}],
                    }],
                }]}},
            }],
        }
        change, intent, revision = make_candidate(platform=models.Platform.NOKIA_SRLINUX)
        import_service.import_from_fixture(
            change=change, intent=intent, revision=revision, device_name="SRL1",
            platform="nokia_srlinux", source=source)
        revision.refresh_from_db()
        unmanaged = revision.sections["_import"]["unmanaged"]
        self.assertTrue(any("ACL attachment" in block["label"] for block in unmanaged))
        self.assertTrue(any("OSPF interface binding" in block["label"] for block in unmanaged))
