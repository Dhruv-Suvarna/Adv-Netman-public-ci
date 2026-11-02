"""Lab 7 closure -- remaining ``modules/netbox_ipam.py`` reconcile and read helpers, called directly.

Uses the in-memory fake NetBox fixtures of ``test_netbox_ipam`` (no HTTP, no live NetBox).  POSITIVE: a reconcile
result defaults to empty changes and is ok unless it conflicts, a dry-run tag reports CHECK-CREATE, a p2p peer is
derived from the shared prefix.  NEGATIVE: a custom-field type mismatch is a CONFLICT that writes nothing, an unknown
device or an address-less interface raises a model error, an unknown device is not managed, an empty NetBox has no
prefixes, and an unreachable NetBox is a connection error naming the action.
"""
from __future__ import annotations

import unittest
from unittest.mock import MagicMock

import requests

import test_netbox_ipam as base  # sibling fixture module (discover -s monitoring/tests)
from modules import netbox_ipam


class ReconcileResultTests(unittest.TestCase):
    def test_reconcile_result_defaults_to_empty_changes_and_is_ok(self):
        result = netbox_ipam.ReconcileResult(netbox_ipam.UNCHANGED)
        self.assertEqual((result.obj, result.changes, result.conflicts, result.ok), (None, {}, {}, True))
        self.assertTrue(netbox_ipam.ReconcileResult(netbox_ipam.CHECK_UPDATE, changes={"description": "x"}).ok)

    def test_a_conflict_result_is_refused_as_not_usable(self):
        self.assertFalse(netbox_ipam.ReconcileResult(netbox_ipam.CONFLICT, conflicts={"type": {}}).ok)


class EnsureDefinitionsTests(unittest.TestCase):
    def client(self):
        client = MagicMock()
        client.extras.tags, client.extras.custom_fields = base._FakeEndpoint(), base._FakeEndpoint()
        return client

    def test_ensure_tag_dry_run_never_writes_a_tag(self):
        client = self.client()
        result = netbox_ipam.ensure_tag(client, "CSCI 5840 IaC", color="00ff00", apply=False)
        self.assertEqual((result.action, result.obj, result.changes), (netbox_ipam.CHECK_CREATE, None,
                                                                       {"name": "CSCI 5840 IaC", "description": "", "color": "00ff00"}))
        self.assertEqual(client.extras.tags.records, [])

    def test_ensure_custom_field_type_mismatch_is_a_conflict_without_update(self):
        client = self.client()
        netbox_ipam.ensure_custom_field(client, "iac_managed", field_type="boolean", content_types=["dcim.device"])
        result = netbox_ipam.ensure_custom_field(client, "iac_managed", field_type="text", content_types=["dcim.device"])
        self.assertEqual((result.action, result.ok, result.conflicts), (netbox_ipam.CONFLICT, False,
                                                                        {"type": {"existing": "boolean", "desired": "text"}}))
        self.assertEqual(client.extras.custom_fields.records[0].type, "boolean")

    def test_ensure_custom_field_updates_only_safe_label_and_types(self):
        client = self.client()
        netbox_ipam.ensure_custom_field(client, "iac_managed", field_type="boolean", content_types=["dcim.device"])
        result = netbox_ipam.ensure_custom_field(client, "iac_managed", field_type="boolean", content_types=["dcim.interface", "dcim.device"],
                                                 label="IaC managed")
        self.assertEqual((result.action, result.changes), (netbox_ipam.UPDATE, {"object_types": ["dcim.device", "dcim.interface"], "label": "IaC managed"}))


class ReadHelperTests(unittest.TestCase):
    def test_get_peer_addresses_returns_the_other_end_of_the_p2p_prefix(self):
        peers = netbox_ipam.get_peer_addresses("R1", "Ethernet2", 4, base.FakeNetboxClient())
        self.assertEqual([(p["address"], p["cidr"], p["family"]) for p in peers], [("192.168.110.1", "192.168.110.1/31", 4)])

    def test_get_peer_addresses_without_an_anchor_address_raises(self):
        client = base.FakeNetboxClient()
        for name, args in (("no address", ("R1", "Vlan101", None)), ("no ipv6", ("R1", "Ethernet2", 6))):
            with self.subTest(case=f"refused {name}"), self.assertRaisesRegex(netbox_ipam.NetboxModelError, "no address to derive a peer from"):
                netbox_ipam.get_peer_addresses(*args, client)

    def test_unknown_devices_are_not_managed_and_have_no_interfaces(self):
        client = base.FakeNetboxClient()
        self.assertFalse(netbox_ipam.is_device_managed("R9", client))
        with self.assertRaisesRegex(netbox_ipam.NetboxModelError, "No IaC-owned device named 'R9'"):
            netbox_ipam.get_device_interface_names("R9", client)

    def test_list_all_prefix_cidrs_of_an_empty_or_unreachable_netbox(self):
        client = MagicMock()
        client.ipam.prefixes.filter.return_value = []
        self.assertEqual(netbox_ipam.list_all_prefix_cidrs(client), set())
        client.ipam.prefixes.filter.side_effect = requests.exceptions.ConnectTimeout("token=fake")
        with self.assertRaisesRegex(netbox_ipam.NetboxConnectionError, "^NetBox timed out while attempting to list$"):
            netbox_ipam.list_all_prefix_cidrs(client)


if __name__ == "__main__":
    unittest.main()
