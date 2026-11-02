"""Phase 20.5 Objective 1: cEOS running-config -> canonical structured intent.

See core/services/config_import/parser_ceos.py.
"""

from __future__ import annotations

from django.test import SimpleTestCase

from core.services.config_import import parser_ceos as p

CONFIG = """! Command: show running-config
!
hostname R1
!
interface Ethernet1
   description uplink to R2
   mtu 9000
   no switchport
   ip address 192.0.2.1/31
   ipv6 address 2001:db8:100::1/64
!
interface Ethernet2
   shutdown
   ip ospf message-digest-key 1 md5 <REDACTED>
!
interface Port-Channel1
   description LAG uplink
   no switchport
!
router ospf 10
   router-id 1.1.1.1
   network 192.0.2.0/31 area 0
!
ip access-list EDGE-IN
   10 permit ip any any
!
vlan 10
   name USERS
!
snmp-server community <REDACTED> ro
!
monitor session 1 source Ethernet3
   destination Ethernet4
!
end
"""


class ParseHostnameTests(SimpleTestCase):
    def test_hostname_is_parsed(self):
        parsed = p.parse(CONFIG)
        self.assertEqual(parsed.hostname, "R1")


class ParseInterfaceTests(SimpleTestCase):
    def setUp(self):
        self.parsed = p.parse(CONFIG)
        self.by_name = {i.name: i for i in self.parsed.interfaces}

    def test_supported_fields_are_extracted(self):
        eth1 = self.by_name["Ethernet1"]
        self.assertEqual(eth1.description, "uplink to R2")
        self.assertEqual(eth1.mtu, 9000)
        self.assertEqual(eth1.admin_state, "ENABLED")
        self.assertEqual(eth1.addresses, [
            {"family": "IPV4", "cidr": "192.0.2.1/31", "role": "PRIMARY"},
            {"family": "IPV6", "cidr": "2001:db8:100::1/64", "role": "PRIMARY"},
        ])

    def test_no_switchport_is_preserved_not_dropped_silently(self):
        eth1 = self.by_name["Ethernet1"]
        self.assertIn("   no switchport", eth1.preserved_lines)

    def test_shutdown_sets_disabled(self):
        eth2 = self.by_name["Ethernet2"]
        self.assertEqual(eth2.admin_state, "DISABLED")

    def test_default_access_mode_is_inferred_from_vlan(self):
        # EOS omits "switchport mode access" from show running-config when it is the default.
        parsed = p.parse("interface Ethernet2\n   switchport access vlan 44\n!\n")
        self.assertEqual([(row.kind, row.access_vlan) for row in parsed.interfaces], [("ACCESS", 44)])

    def test_eos_tagged_subinterface_encapsulation_is_imported(self):
        parsed = p.parse("interface Ethernet2.44\n   encapsulation dot1q vlan 44\n!\n")
        self.assertEqual([(row.kind, row.parent_name, row.encapsulation_vlan) for row in parsed.interfaces],
                         [("SUBINTERFACE", "Ethernet2", 44)])

    def test_unrecognized_interface_sub_line_is_preserved(self):
        eth2 = self.by_name["Ethernet2"]
        self.assertTrue(any("md5" in line for line in eth2.preserved_lines))

    def test_port_channel_is_not_imported_as_a_structured_interface(self):
        self.assertNotIn("Port-Channel1", self.by_name)

    def test_port_channel_is_preserved_as_an_unmanaged_block(self):
        block = next(b for b in self.parsed.unmanaged_blocks if "Port-Channel1" in b.lines[0])
        self.assertEqual(block.classification, "RECOGNIZED_UNSUPPORTED")
        self.assertIn("   description LAG uplink", block.lines)


class StructuredAndUnmanagedTests(SimpleTestCase):
    def setUp(self):
        self.parsed = p.parse(CONFIG)
        self.by_first_word = {b.lines[0].split()[0]: b for b in self.parsed.unmanaged_blocks}

    def test_ospf_is_structured_and_only_unsupported_subcommands_are_preserved(self):
        ospf = next(row for row in self.parsed.routing_instances if row.family == "ospf")
        self.assertEqual(ospf.fields["process_id"], 10)
        self.assertEqual(ospf.fields["router_id"], "1.1.1.1")
        self.assertEqual(ospf.networks, [{"prefix": "192.0.2.0/31", "area": "0"}])
        self.assertNotIn("   network 192.0.2.0/31 area 0", ospf.preserved_lines)

    def test_acl_is_structured_and_vlan_is_preserved(self):
        acl = self.parsed.acls[0]
        self.assertEqual(acl.name, "EDGE-IN")
        self.assertEqual(acl.entries[0]["action"], "PERMIT")
        vlan = self.by_first_word["vlan"]
        self.assertEqual(vlan.label, "VLAN definition")

    def test_a_genuinely_unknown_stanza_is_labelled_unknown_not_guessed(self):
        monitor = self.by_first_word["monitor"]
        self.assertEqual(monitor.classification, "UNKNOWN")

    def test_nothing_is_dropped(self):
        # Every construct not represented structurally remains opaque. OSPF
        # and ACL are intentionally absent here because they are structured.
        seen_first_words = {b.lines[0].split()[0] for b in self.parsed.unmanaged_blocks}
        for expected in ("vlan", "snmp-server", "monitor"):
            with self.subTest(keyword=expected):
                self.assertIn(expected, seen_first_words)
        self.assertTrue(any(row.family == "ospf" for row in self.parsed.routing_instances))
        self.assertEqual(len(self.parsed.acls), 1)


class ParserIsPureAndSafeTests(SimpleTestCase):
    def test_parser_never_raises_on_malformed_or_empty_input(self):
        for text in ("", "   \n\n!\n", "not even close to a config\n   with an indented line first"):
            with self.subTest(text=repr(text)):
                p.parse(text)  # must not raise

    def test_redacted_placeholder_survives_as_opaque_text(self):
        parsed = p.parse(CONFIG)
        eth2 = next(i for i in parsed.interfaces if i.name == "Ethernet2")
        self.assertTrue(any("<REDACTED>" in line for line in eth2.preserved_lines))
