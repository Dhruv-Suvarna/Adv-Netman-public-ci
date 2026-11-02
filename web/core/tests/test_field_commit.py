"""The explicit field-commit service: accepted vs draft, field-local rollback, ownership.

Table-driven (identity fields, interface/address/WAN fields), plus the
structural rules that differ in shape: path allowlist, record ownership,
sibling isolation, revision reuse and "commit has no side effects".
"""

from __future__ import annotations

from django.test import TestCase

from core import models
from core.services import field_commit_service, field_registry, interface_intent_service, intent_service
from core.tests.helpers.candidates import add_interface, commit, make_candidate

VALID, INVALID = models.FieldValidationState.VALID, models.FieldValidationState.INVALID
NEW, EXISTING = models.DeviceIntentTargetType.NEW_DEVICE, models.DeviceIntentTargetType.EXISTING_DEVICE
ANY = object()

# (label, target type, path, raw value, state, accepted value, draft value)
IDENTITY_CASES = [
    ("hostname accepted", EXISTING, "device.hostname", "R1-new", VALID, "R1-new", ANY),
    ("hostname rejected -> rolls back to the previous value", EXISTING, "device.hostname", "%%%bad%%%", INVALID, "R1", "R1"),
    ("hostname is trimmed before persisting", EXISTING, "device.hostname", "  R1-trimmed  ", VALID, "R1-trimmed", "R1-trimmed"),
    ("platform accepted", EXISTING, "device.platform", models.Platform.SONIC, VALID, ANY, ANY),
    ("unknown platform rejected", EXISTING, "device.platform", "junos", INVALID, ANY, ANY),
    ("image reference safe (new device)", NEW, "device.image_reference", "sonic:2024.05", VALID, ANY, ANY),
    ("image reference unsafe (new device)", NEW, "device.image_reference", "ceos;rm -rf /", INVALID, ANY, ANY),
    ("existing device does not need an image reference", EXISTING, "device.image_reference", "", VALID, ANY, ANY),
]


class IdentityCommitTests(TestCase):
    def test_identity_commit_matrix(self):
        for label, target_type, path, raw, state, accepted, draft in IDENTITY_CASES:
            with self.subTest(case=label):
                change, intent, revision = make_candidate(target_type=target_type)
                result = commit(change, intent, revision, path, raw)
                self.assertEqual(result.validation_state, state)
                if accepted is not ANY:
                    self.assertEqual(result.accepted_value, accepted)
                if draft is not ANY:
                    self.assertEqual(result.draft_value, draft)

    def test_platform_commit_mirrors_to_the_intent_and_a_rejected_one_does_not(self):
        change, intent, revision = make_candidate()
        commit(change, intent, revision, "device.platform", "junos")
        intent.refresh_from_db()
        self.assertEqual(intent.platform, models.Platform.ARISTA_CEOS)
        commit(change, intent, revision, "device.platform", models.Platform.SONIC)
        intent.refresh_from_db()
        self.assertEqual(intent.platform, models.Platform.SONIC)

    def test_platform_change_never_deletes_intent_sections(self):
        change, intent, revision = make_candidate()
        revision.sections = {"interfaces": {"Ethernet1": {"note": "kept"}}}
        revision.save(update_fields=["sections"])
        commit(change, intent, revision, "device.platform", models.Platform.SONIC)
        revision.refresh_from_db()
        self.assertEqual(revision.sections, {"interfaces": {"Ethernet1": {"note": "kept"}}})

    def test_seeding_makes_draft_equal_accepted_for_every_device_field(self):
        _, _, revision = make_candidate(device_name="R2")
        for path in ("device.hostname", "device.description", "device.target_type", "device.platform", "device.image_reference"):
            with self.subTest(path=path):
                state = models.IntentFieldState.objects.get(revision=revision, path=path)
                self.assertEqual(state.draft_value, state.accepted_value)
        self.assertEqual(models.IntentFieldState.objects.get(revision=revision, path="device.hostname").accepted_value, "R2")


class CommitBoundaryTests(TestCase):
    def test_unknown_paths_are_rejected_without_persisting_anything(self):
        change, intent, revision = make_candidate()
        before = models.IntentFieldState.objects.filter(revision=revision).count()
        for path in ("interfaces.Ethernet1.ipv4", "device.secret_ref"):
            with self.subTest(path=path), self.assertRaises(field_commit_service.UnknownFieldPathError):
                field_commit_service.commit_field(change=change, intent=intent, revision=revision, path=path, raw_value="x")
        self.assertEqual(models.IntentFieldState.objects.filter(revision=revision).count(), before)

    def test_records_must_belong_together(self):
        change_a, intent_a, _ = make_candidate(device_name="R1")
        _, intent_b, revision_b = make_candidate(device_name="R2")
        for label, intent, revision in (("intent from another change", intent_b, revision_b),
                                        ("revision from another intent", intent_a, revision_b)):
            with self.subTest(case=label), self.assertRaises(field_commit_service.RecordOwnershipError):
                field_commit_service.commit_field(
                    change=change_a, intent=intent, revision=revision, path="device.hostname", raw_value="x"
                )

    def test_a_rejected_commit_rolls_back_only_that_field(self):
        change, intent, revision = make_candidate()
        commit(change, intent, revision, "device.description", "Core router")
        commit(change, intent, revision, "device.image_reference", "ceos:4.36.2F")
        commit(change, intent, revision, "device.hostname", "%%%bad%%%")
        accepted = {s.path: s.accepted_value for s in revision.field_states.all()}
        self.assertEqual(
            (accepted["device.hostname"], accepted["device.description"], accepted["device.image_reference"]),
            ("R1", "Core router", "ceos:4.36.2F"),
        )
        interface = add_interface(revision)
        base = f"interfaces.{interface['id']}.addresses.{interface_intent_service.add_address(revision=revision, interface_id=interface['id'])['id']}"
        commit(change, intent, revision, f"{base}.role", "SECONDARY")
        rejected = commit(change, intent, revision, f"{base}.cidr", "invalid")
        self.assertEqual(rejected.accepted_value, "")
        self.assertEqual(revision.field_states.get(path=f"{base}.role").accepted_value, "SECONDARY")

    def test_commits_reuse_the_active_revision_and_have_no_side_effects(self):
        change, intent, revision = make_candidate()
        for path, value in (("device.hostname", "A"), ("device.hostname", "B"), ("device.description", "C")):
            commit(change, intent, revision, path, value)
        self.assertEqual(models.DeviceIntentRevision.objects.filter(device_intent=intent).count(), 1)
        new_change, _, _ = make_candidate(device_name="N1", target_type=NEW)
        for c in (change, new_change):
            c.refresh_from_db()
            self.assertEqual(c.lifecycle_state, models.ChangeLifecycleState.DRAFT)
            self.assertEqual(c.execution_mode, models.ExecutionMode.COMPLETE)
            self.assertEqual(models.Configlet.objects.filter(change=c).count(), 0)
        for absent in ("GoldenBundle", "ProbationRecord", "SoakTimer"):
            with self.subTest(model=absent):
                self.assertFalse(hasattr(models, absent))


class DraftAcceptedFieldStateTests(TestCase):
    """The Phase-8 contract: a draft never changes the accepted value until it is accepted; rollback is per field."""

    def test_draft_accept_and_rollback_semantics(self):
        _, _, revision = make_candidate()
        path = "interfaces.Ethernet1.ipv4"
        state = intent_service.set_draft_field(revision=revision, path=path, draft_value="192.0.2.1/31")
        self.assertEqual(state.draft_value, state.accepted_value)
        self.assertFalse(state.dirty)
        # an invalid draft is stored verbatim and unvalidated (no automatic network validation) ...
        state = intent_service.set_draft_field(revision=revision, path=path, draft_value="300.300.300.300")
        self.assertEqual((state.draft_value, state.accepted_value, state.dirty), ("300.300.300.300", "192.0.2.1/31", True))
        self.assertEqual(state.validation_state, models.FieldValidationState.UNVALIDATED)
        # ... and rolling back reverts the draft to the accepted value
        state = intent_service.rollback_draft_to_accepted(revision=revision, path=path)
        self.assertEqual((state.draft_value, state.dirty), ("192.0.2.1/31", False))
        # accepting a new draft updates accepted and stamps the commit time
        intent_service.set_draft_field(revision=revision, path=path, draft_value="192.0.2.2/31")
        state = intent_service.accept_field_value(revision=revision, path=path)
        self.assertEqual((state.accepted_value, state.dirty), ("192.0.2.2/31", False))
        self.assertIsNotNone(state.last_committed_at)

    def test_reverting_one_field_preserves_its_siblings(self):
        _, _, revision = make_candidate()
        path_a, path_b = "interfaces.Ethernet1.ipv4", "interfaces.Ethernet2.ipv4"
        for path, value in ((path_a, "192.0.2.1/31"), (path_b, "192.0.2.5/31")):
            intent_service.set_draft_field(revision=revision, path=path, draft_value=value)
            intent_service.accept_field_value(revision=revision, path=path)
        intent_service.set_draft_field(revision=revision, path=path_a, draft_value="bad")
        intent_service.set_draft_field(revision=revision, path=path_b, draft_value="192.0.2.6/31")
        intent_service.rollback_draft_to_accepted(revision=revision, path=path_a)
        field_a = models.IntentFieldState.objects.get(revision=revision, path=path_a)
        field_b = models.IntentFieldState.objects.get(revision=revision, path=path_b)
        self.assertEqual(field_a.draft_value, "192.0.2.1/31")
        self.assertEqual((field_b.draft_value, field_b.dirty), ("192.0.2.6/31", True))


class InterfaceFieldCommitTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.change, cls.intent, cls.revision = make_candidate()
        cls.interface = add_interface(cls.revision)

    def base(self, iid=None):
        return f"interfaces.{iid or self.interface['id']}"

    def new_address(self, **kwargs):
        return interface_intent_service.add_address(revision=self.revision, interface_id=self.interface["id"], **kwargs)

    def test_dynamic_interface_paths_resolve_only_owned_ids(self):
        self.assertIsNotNone(field_registry.resolve_field_spec(f"{self.base()}.name", revision=self.revision))
        with self.assertRaises(interface_intent_service.CollectionOwnershipError):
            field_registry.resolve_field_spec("interfaces.if_0000000000000000.name", revision=self.revision)

    def test_interface_field_commit_matrix(self):
        _, _, foreign_revision = make_candidate(device_name="R2")
        foreign = add_interface(foreign_revision)
        child = add_interface(self.revision, kind="SUBINTERFACE", name="Ethernet1.100")
        auto = self.new_address(source="AUTO")
        v4 = self.new_address()
        # (label, path, value, state, accepted value asserted after the commit); rows run in order on shared objects
        cases = [
            ("admin state not an enum -> keeps ENABLED", f"{self.base()}.admin_state", "MAYBE", INVALID, "ENABLED"),
            ("admin state DISABLED", f"{self.base()}.admin_state", "DISABLED", VALID, "DISABLED"),
            ("subinterface parent (local)", f"{self.base(child['id'])}.parent_id", self.interface["id"], VALID, self.interface["id"]),
            ("subinterface parent missing", f"{self.base(child['id'])}.parent_id", "", INVALID, ANY),
            ("subinterface parent (another candidate's)", f"{self.base(child['id'])}.parent_id", foreign["id"], INVALID, ANY),
            ("encapsulation VLAN 100", f"{self.base(child['id'])}.encapsulation_vlan", 100, VALID, 100),
            ("encapsulation VLAN 5000 -> keeps 100", f"{self.base(child['id'])}.encapsulation_vlan", 5000, INVALID, 100),
            ("AUTO address refuses a manual CIDR", f"{self.base()}.addresses.{auto['id']}.cidr", "192.0.2.1/24", INVALID, ANY),
            ("IPv4 address", f"{self.base()}.addresses.{v4['id']}.cidr", "192.0.2.1/24", VALID, "192.0.2.1/24"),
            ("address family cannot flip under an existing CIDR", f"{self.base()}.addresses.{v4['id']}.family", "IPV6", INVALID, "IPV4"),
        ]
        cases += [
            (f"WAN {field}", f"{self.base()}.wan.{field}", value, VALID, ANY)
            for field, value in {
                "provider_name": "Example Transit", "peer_label": "edge-a", "peer_ipv4": "192.0.2.2", "peer_ipv6": "2001:db8::2",
                "gateway_ipv4": "192.0.2.3", "gateway_ipv6": "2001:db8::3", "mtu": 9000, "description": "WAN circuit",
            }.items()
        ]
        for label, path, value, state, accepted in cases:
            with self.subTest(case=label):
                result = commit(self.change, self.intent, self.revision, path, value)
                self.assertEqual(result.validation_state, state)
                if accepted is not ANY:
                    self.assertEqual(result.accepted_value, accepted)

    def test_address_families_sources_and_dual_stack(self):
        ipv4, ipv6 = self.new_address(), self.new_address(family="IPV6")
        manual, auto = self.new_address(source="MANUAL"), self.new_address(source="AUTO")
        self.assertEqual((manual["source"], auto["source"]), ("MANUAL", "AUTO"))
        for address, cidr in ((ipv4, "192.0.2.1/31"), (ipv6, "2001:db8::1/64")):
            state = commit(self.change, self.intent, self.revision, f"{self.base()}.addresses.{address['id']}.cidr", cidr)
            self.assertEqual(state.accepted_value, cidr)
        self.revision.refresh_from_db()
        families = {row["family"] for row in interface_intent_service.get_interface(self.revision, self.interface["id"])["addresses"].values()}
        self.assertEqual(families, {"IPV4", "IPV6"})
