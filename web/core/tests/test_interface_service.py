"""Interface and address collections (Phase 10): stable IDs, ordering, limits, removal, ownership.

Interface-field VALUE validation is in ``test_field_commit`` / ``test_field_validators``;
HTTP add/remove behavior is in ``test_view_boundaries``.
"""

from __future__ import annotations

from unittest import mock

from django.test import TestCase

from core import models
from core.services import interface_intent_service as service
from core.tests.helpers.candidates import add_interface, commit, make_candidate


class InterfaceCollectionTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.change, cls.intent, cls.revision = make_candidate()

    def test_interfaces_have_stable_ids_deterministic_order_and_versioned_state(self):
        first = add_interface(self.revision, name="Ethernet9")
        second = add_interface(self.revision, name="Ethernet1")
        self.assertRegex(first["id"], r"^if_[0-9a-f]{16}$")
        self.assertNotEqual(first["id"], second["id"])
        ordered = service.ordered_interfaces(self.revision)
        self.assertEqual([first["id"], second["id"]], [row["id"] for row in ordered])  # insertion order, not name order
        self.assertEqual([1, 2], [row["sequence"] for row in ordered])
        self.revision.refresh_from_db()
        self.assertEqual(self.revision.sections["interfaces"][first["id"]]["id"], first["id"])
        self.assertGreaterEqual(service.MAX_INTERFACES_PER_REVISION, 32)  # not a tiny demo bound

    def test_editing_one_interface_does_not_alter_its_sibling(self):
        first, second = add_interface(self.revision, name="Ethernet1"), add_interface(self.revision, name="Ethernet2")
        commit(self.change, self.intent, self.revision, f"interfaces.{first['id']}.description", "changed")
        self.revision.refresh_from_db()
        rows = service.interface_map(self.revision)
        self.assertEqual((rows[first["id"]]["description"], rows[second["id"]]["description"]), ("changed", ""))

    def test_invalid_creation_is_rejected(self):
        for label, kwargs in (("invalid name", {"name": "bad name"}),
                              ("unknown type", {"kind": "MAGIC", "name": "Ethernet1"}),
                              ("NOT_IMPLEMENTED type", {"kind": "LAG", "name": "Port-Channel1"})):
            with self.subTest(case=label), self.assertRaises(service.CollectionMutationError):
                add_interface(self.revision, **kwargs)

    def test_limit_and_draft_only_rules(self):
        with mock.patch.object(service, "MAX_INTERFACES_PER_REVISION", 1):
            add_interface(self.revision)
            with self.assertRaises(service.CollectionLimitError):
                add_interface(self.revision, name="Ethernet2")
        self.change.lifecycle_state = models.ChangeLifecycleState.VALIDATED
        self.change.save(update_fields=["lifecycle_state", "updated_at"])
        with self.assertRaises(service.DraftOnlyError):
            add_interface(self.revision, name="Ethernet3")

    def test_removal_needs_exact_confirmation_and_removes_only_the_selected_interface(self):
        first, second = add_interface(self.revision, name="Ethernet1"), add_interface(self.revision, name="Ethernet2")
        with self.assertRaises(service.CollectionMutationError):
            service.remove_interface(revision=self.revision, interface_id=first["id"], confirmation="yes")
        self.assertEqual(len(service.ordered_interfaces(self.revision)), 2)
        service.remove_interface(revision=self.revision, interface_id=first["id"], confirmation="REMOVE")
        self.revision.refresh_from_db()
        self.assertEqual([second["id"]], [row["id"] for row in service.ordered_interfaces(self.revision)])
        self.assertFalse(self.revision.field_states.filter(path__startswith=f"interfaces.{first['id']}.").exists())

    def test_a_parent_with_a_child_cannot_be_removed(self):
        parent = add_interface(self.revision)
        child = add_interface(self.revision, kind="SUBINTERFACE", name="Ethernet1.10")
        commit(self.change, self.intent, self.revision, f"interfaces.{child['id']}.parent_id", parent["id"])
        with self.assertRaises(service.CollectionMutationError):
            service.remove_interface(revision=self.revision, interface_id=parent["id"], confirmation="REMOVE")

    def test_another_candidates_interface_id_is_rejected(self):
        _, _, other_revision = make_candidate(device_name="R2")
        foreign = add_interface(other_revision)
        with self.assertRaises(service.CollectionOwnershipError):
            service.get_interface(self.revision, foreign["id"])


class AddressCollectionTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.change, cls.intent, cls.revision = make_candidate()
        cls.interface = add_interface(cls.revision)

    def add(self, **kwargs):
        return service.add_address(revision=self.revision, interface_id=self.interface["id"], **kwargs)

    def test_addresses_have_stable_ids_and_ordering_and_edits_do_not_touch_siblings(self):
        first, second = self.add(family="IPV4"), self.add(family="IPV6")
        self.assertRegex(first["id"], r"^addr_[0-9a-f]{16}$")
        self.assertEqual((1, 2), (first["sequence"], second["sequence"]))
        self.assertGreaterEqual(service.MAX_ADDRESSES_PER_INTERFACE, 8)
        commit(self.change, self.intent, self.revision, f"interfaces.{self.interface['id']}.addresses.{first['id']}.cidr", "192.0.2.1/31")
        self.revision.refresh_from_db()
        self.assertEqual(service.get_address(self.revision, self.interface["id"], second["id"])["cidr"], "")

    def test_limit_and_draft_only_rules(self):
        with mock.patch.object(service, "MAX_ADDRESSES_PER_INTERFACE", 1):
            self.add()
            with self.assertRaises(service.CollectionLimitError):
                self.add()
        self.change.lifecycle_state = models.ChangeLifecycleState.VALIDATED
        self.change.save(update_fields=["lifecycle_state", "updated_at"])
        with self.assertRaises(service.DraftOnlyError):
            self.add()

    def test_removal_needs_confirmation_and_removes_only_that_addresss_state(self):
        address = self.add()
        with self.assertRaises(service.CollectionMutationError):
            service.remove_address(revision=self.revision, interface_id=self.interface["id"], address_id=address["id"], confirmation="")
        service.remove_address(revision=self.revision, interface_id=self.interface["id"], address_id=address["id"], confirmation="REMOVE")
        self.revision.refresh_from_db()
        self.assertFalse(self.revision.field_states.filter(path__contains=address["id"]).exists())
        self.assertIn(self.interface["id"], service.interface_map(self.revision))

    def test_another_candidates_address_id_is_rejected(self):
        _, _, other_revision = make_candidate(device_name="R2")
        other_interface = add_interface(other_revision)
        foreign = service.add_address(revision=other_revision, interface_id=other_interface["id"])
        with self.assertRaises(service.CollectionOwnershipError):
            service.get_address(self.revision, self.interface["id"], foreign["id"])
