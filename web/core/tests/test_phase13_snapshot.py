from __future__ import annotations

import json

from django.test import TestCase

from core.services import change_validation_service as cvs
from core.services.validation import snapshot as snap
from core.services.validation.findings import Currency
from core.tests.helpers.validation import (
    Dev, link, make_sources, netbox_data, nb_ip, new_change, topology_data, validate,
)


class SnapshotContentTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.change = new_change()
        cls.r1 = Dev(cls.change, "R1")
        cls.i1 = cls.r1.iface("Ethernet1")
        cls.addr = cls.r1.address(cls.i1, "192.0.2.0/31")

    def snapshot(self):
        return cvs.build_change_snapshot(self.change)

    def test_only_accepted_values_included(self):
        device = self.snapshot()["devices"][0]
        row = device["interfaces"][self.i1["id"]]
        self.assertEqual(row["addresses"][self.addr["id"]]["cidr"], "192.0.2.0/31")

    def test_uncommitted_draft_excluded_and_hash_unchanged(self):
        before = cvs.hash_snapshot(self.snapshot())
        self.r1.draft(f"interfaces.{self.i1['id']}.description", "typed but never committed")
        self.r1.draft(f"interfaces.{self.i1['id']}.addresses.{self.addr['id']}.cidr", "203.0.113.9/24")
        snapshot = self.snapshot()
        self.assertEqual(cvs.hash_snapshot(snapshot), before)
        self.assertNotIn("203.0.113.9", json.dumps(snapshot))
        self.assertNotIn("typed but never committed", json.dumps(snapshot))

    def test_accepted_change_produces_new_hash(self):
        before = cvs.hash_snapshot(self.snapshot())
        self.r1.set(f"interfaces.{self.i1['id']}.description", "uplink")
        self.assertNotEqual(cvs.hash_snapshot(self.snapshot()), before)

    def test_same_input_same_hash_and_sha256_shape(self):
        first, second = cvs.hash_snapshot(self.snapshot()), cvs.hash_snapshot(self.snapshot())
        self.assertEqual(first, second)
        self.assertRegex(first, r"^[0-9a-f]{64}$")

    def test_device_ordering_is_deterministic_regardless_of_creation_order(self):
        change = new_change()
        for name in ("S2", "R2", "S1", "R1"):
            Dev(change, name)
        names = [d["device_name"] for d in cvs.build_change_snapshot(change)["devices"]]
        self.assertEqual(names, ["R1", "R2", "S1", "S2"])

    def test_object_ordering_and_key_order_do_not_change_hash(self):
        a = json.loads(json.dumps(self.snapshot()))
        reordered = {"devices": a["devices"], "targets": a["targets"], "schema_version": a["schema_version"]}
        self.assertEqual(cvs.hash_snapshot(a), cvs.hash_snapshot(reordered))

    def test_vlan_set_is_sorted_set_semantics(self):
        r2 = Dev(self.change, "R2")
        trunk = r2.iface("Ethernet2", kind="TRUNK", trunk_allowed_vlans="20,10,30")
        vlans = cvs.build_change_snapshot(self.change)["devices"][1]["interfaces"][trunk["id"]]["trunk_allowed_vlans"]
        self.assertEqual(vlans, sorted(vlans))

    def test_display_sequence_is_not_hashed(self):
        for device in self.snapshot()["devices"]:
            for row in device["interfaces"].values():
                self.assertNotIn("sequence", row)

    def test_secret_shaped_manual_edit_is_redacted_not_leaked(self):
        revision = self.r1.refresh()
        revision.sections["interfaces"][self.i1["id"]]["password"] = "hunter2-manual-db-edit"
        revision.sections["interfaces"][self.i1["id"]]["auth_secret_ref"] = "vault:r1"
        revision.save(update_fields=["sections"])
        text = json.dumps(self.snapshot())
        self.assertNotIn("hunter2", text)
        self.assertIn("[REDACTED]", text)
        self.assertIn("vault:r1", text)  # *_ref keys are safe references

    def test_revision_map_is_provenance_not_hash(self):
        mapping = snap.revision_map(self.change)
        self.assertEqual(mapping["R1"]["revision"], 1)


class SourceFingerprintTests(TestCase):
    def test_source_change_changes_source_hash(self):
        a = make_sources()
        b = make_sources(netbox=netbox_data(ip_addresses=[nb_ip("192.0.2.9/24", "R9", "Ethernet1")]))
        c = make_sources(topology=topology_data(links=[link("R1", "Ethernet1", "R2", "Ethernet1")]))
        self.assertNotEqual(a.source_hash(), b.source_hash())
        self.assertNotEqual(a.source_hash(), c.source_hash())
        self.assertEqual(a.source_hash(), make_sources().source_hash())

    def test_repository_head_is_provenance_only(self):
        self.assertEqual(make_sources(head="aaa").source_hash(), make_sources(head="bbb").source_hash())
        self.assertEqual(make_sources(head="aaa").provenance()["repository_head"], "aaa")

    def test_unavailable_source_has_distinct_fingerprint(self):
        self.assertNotEqual(make_sources().source_hash(), make_sources(netbox=None).source_hash())


class CurrencyTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.change = new_change()
        cls.r1 = Dev(cls.change, "R1")
        cls.i1 = cls.r1.iface("Ethernet1")
        cls.src = make_sources()

    def currency(self, **kw):
        return cvs.get_validation_currency(self.change, **kw)

    def test_never_run(self):
        result = self.currency()
        self.assertEqual(result["state"], Currency.NEVER_RUN)
        self.assertIsNone(result["last_status"])

    def test_current_after_run(self):
        validate(self.change, self.src)
        self.assertEqual(self.currency()["state"], Currency.CURRENT)

    def test_accepted_field_change_makes_it_stale(self):
        run = validate(self.change, self.src)
        self.r1.set(f"interfaces.{self.i1['id']}.description", "changed")
        result = self.currency()
        self.assertEqual(result["state"], Currency.STALE)
        self.assertIn("ACCEPTED_INTENT_CHANGED", result["reasons"])
        self.assertEqual(result["last_status"], run.status)  # the old result is remembered, not current

    def test_collection_add_and_remove_make_it_stale(self):
        validate(self.change, self.src)
        row = self.r1.address(self.i1, "192.0.2.0/31")
        self.assertEqual(self.currency()["state"], Currency.STALE)
        validate(self.change, self.src)
        self.assertEqual(self.currency()["state"], Currency.CURRENT)
        from core.services import interface_intent_service as iis
        iis.remove_address(revision=self.r1.refresh(), interface_id=self.i1["id"], address_id=row["id"], confirmation="REMOVE")
        self.assertEqual(self.currency()["state"], Currency.STALE)

    def test_draft_only_edit_does_not_stale(self):
        validate(self.change, self.src)
        self.r1.draft(f"interfaces.{self.i1['id']}.description", "typing")
        self.assertEqual(self.currency()["state"], Currency.CURRENT)

    def test_netbox_fingerprint_change_makes_it_stale(self):
        validate(self.change, self.src)
        changed = make_sources(netbox=netbox_data(ip_addresses=[nb_ip("192.0.2.9/24", "R9", "Ethernet1")]))
        result = self.currency(sources=changed)
        self.assertEqual(result["state"], Currency.STALE)
        self.assertIn("SOURCE_CHANGED:NETBOX", result["reasons"])

    def test_topology_fingerprint_change_makes_it_stale(self):
        validate(self.change, self.src)
        changed = make_sources(topology=topology_data(links=[link("R1", "Ethernet1", "R2", "Ethernet1")]))
        self.assertIn("SOURCE_CHANGED:TOPOLOGY", self.currency(sources=changed)["reasons"])

    def test_source_now_unavailable_cannot_be_confirmed_so_stale(self):
        validate(self.change, self.src)
        self.assertIn("SOURCE_UNVERIFIABLE:NETBOX", self.currency(sources=make_sources(netbox=None))["reasons"])

    def test_unchanged_sources_stay_current(self):
        validate(self.change, self.src)
        self.assertEqual(self.currency(sources=make_sources())["state"], Currency.CURRENT)

    def test_source_freshness_is_not_read_unless_requested(self):
        validate(self.change, self.src)
        from unittest import mock
        with mock.patch("core.services.validation.sources.build_source_bundle", side_effect=AssertionError("no source read")):
            self.assertEqual(self.currency()["state"], Currency.CURRENT)

    def test_stale_pass_is_not_presented_as_current_pass(self):
        run = validate(self.change, self.src)
        self.assertEqual(run.status, "PASS")
        self.r1.set(f"interfaces.{self.i1['id']}.description", "changed")
        result = self.currency()
        self.assertEqual((result["state"], result["last_status"]), (Currency.STALE, "PASS"))
        self.assertNotEqual(result["state"], Currency.CURRENT)
