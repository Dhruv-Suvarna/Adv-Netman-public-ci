"""Change / DeviceIntent / revision / Configlet / lifecycle model and service contracts (Phase 8).

Structure only: identifiers, immutability, uniqueness, lifecycle history and
secret handling.  Draft/accepted field semantics live in ``test_field_commit``;
the "no forbidden imports" rule for these modules lives in ``test_contracts``.
"""

from __future__ import annotations

from django.db import IntegrityError, models as django_models, transaction
from django.http import Http404
from django.test import TestCase

from core import models
from core.services import change_service, configlet_service, intent_service, lifecycle_service


def make_change(**overrides):
    return change_service.create_change(**{"title": "Test change", **overrides})


def make_configlet(change, **overrides):
    defaults = dict(
        target_device="R1", feature_namespace=models.FeatureNamespace.INTERFACES,
        operation_type=models.ConfigletOperationType.CREATE_DEFINE,
        deployment_priority=models.DeploymentPriority.INTERFACE_CONSTRUCTION,
    )
    return configlet_service.create_configlet(change=change, **{**defaults, **overrides})


def make_intent(change, name="R1", platform=models.Platform.ARISTA_CEOS, **kwargs):
    intent, _ = intent_service.create_or_get_device_intent(change=change, device_name=name, platform=platform, **kwargs)
    return intent


class ChangeContractTests(TestCase):
    def test_change_id_format_uniqueness_and_immutability(self):
        first, second = make_change(title="A"), make_change(title="B")
        for change in (first, second):
            self.assertRegex(change.change_id, r"^CHG-\d{8}-\d{4}$")
        self.assertNotEqual(first.change_id, second.change_id)
        first.change_id = "CHG-19990101-0001"
        with self.assertRaises(ValueError):
            first.save()
        with self.assertRaises(IntegrityError), transaction.atomic():
            models.Change.objects.create(change_id=second.change_id, title="Duplicate")

    def test_execution_mode_and_uat_acknowledgements_default_to_unacknowledged_and_deploy_nothing(self):
        self.assertEqual(make_change().execution_mode, models.ExecutionMode.COMPLETE)
        change = make_change(execution_mode=models.ExecutionMode.PARTIAL_UAT)
        self.assertEqual(change.get_execution_mode_display(), "Partial (UAT)")
        self.assertEqual(models.Change.objects.get(pk=change.pk).execution_mode, models.ExecutionMode.PARTIAL_UAT)
        for field in ("uat_ack_target_is_authorized_nonprod", "uat_ack_partial_success_may_remain_applied",
                      "uat_ack_dependent_stages_may_stop", "uat_ack_adjacent_traffic_may_be_affected", "uat_ack_operator_accepts_risk"):
            with self.subTest(field=field):
                self.assertFalse(getattr(change, field))
        self.assertEqual((change.uat_acknowledged_by, change.uat_acknowledged_at), ("", None))
        self.assertEqual(change.lifecycle_state, models.ChangeLifecycleState.DRAFT)
        self.assertFalse(models.Configlet.objects.filter(change=change).exists())

    def test_change_service_helpers_and_input_validation(self):
        change = make_change(title="X")
        target = change_service.add_target(change=change, device_name="R1", site="lab")
        self.assertEqual((target.device_name, change.targets.count()), ("R1", 1))
        self.assertEqual(change_service.get_change_or_404(change.change_id), change)
        with self.assertRaises(Http404):
            change_service.get_change_or_404("CHG-00000000-9999")
        newest = make_change(title="Second")
        self.assertEqual(change_service.list_changes().first(), newest)
        for label, kwargs in (("unknown category", {"category": "NOT_REAL"}), ("unknown execution mode", {"execution_mode": "NOT_REAL"}),
                              ("empty title", {"title": ""})):
            with self.subTest(case=label), self.assertRaises(ValueError):
                change_service.create_change(**{"title": "X", **kwargs})


class LifecycleContractTests(TestCase):
    def test_transitions_are_explicit_recorded_and_ordered(self):
        change = make_change()
        self.assertEqual(change.lifecycle_state, models.ChangeLifecycleState.DRAFT)
        make_configlet(change)  # creating work never advances the lifecycle
        change.refresh_from_db()
        self.assertEqual(change.lifecycle_state, models.ChangeLifecycleState.DRAFT)
        event = lifecycle_service.record_lifecycle_event(
            change=change, to_state=models.ChangeLifecycleState.VALIDATED, reason="structural checks passed")
        lifecycle_service.record_lifecycle_event(change=change, to_state=models.ChangeLifecycleState.READY_TO_DEPLOY)
        change.refresh_from_db()
        self.assertEqual(change.lifecycle_state, models.ChangeLifecycleState.READY_TO_DEPLOY)
        self.assertEqual((event.from_state, event.to_state), (models.ChangeLifecycleState.DRAFT, models.ChangeLifecycleState.VALIDATED))
        self.assertEqual([e.to_state for e in lifecycle_service.list_lifecycle_history(change)], ["DRAFT", "VALIDATED", "READY_TO_DEPLOY"])

    def test_invalid_transitions_are_refused(self):
        change = make_change()
        with self.assertRaises(ValueError):
            lifecycle_service.record_lifecycle_event(change=change, to_state="NOT_REAL")
        with self.assertRaises(ValueError):
            lifecycle_service.record_lifecycle_event(change=change, to_state=models.ChangeLifecycleState.VALIDATED, metadata={"token": "x"})

    def test_lifecycle_and_audit_history_is_append_only(self):
        change = make_change()
        lifecycle_event = change.lifecycle_events.first()
        lifecycle_event.reason = "rewritten"
        audit_event = models.AuditEvent.objects.filter(change=change).first()
        audit_event.summary = "rewritten"
        for row in (lifecycle_event, audit_event):
            with self.subTest(model=type(row).__name__), self.assertRaises(ValueError):
                row.save()


class DeviceIntentContractTests(TestCase):
    def test_targets_platforms_and_image_reference(self):
        change = make_change()
        existing = make_intent(change)
        self.assertEqual(existing.target_type, models.DeviceIntentTargetType.EXISTING_DEVICE)
        new = make_intent(change, "R99-proposed", models.Platform.SONIC,
                          target_type=models.DeviceIntentTargetType.NEW_DEVICE, image_reference="sonic:2024.05")
        self.assertEqual((new.target_type, new.image_reference), (models.DeviceIntentTargetType.NEW_DEVICE, "sonic:2024.05"))
        for platform in models.Platform.values:
            with self.subTest(platform=platform):
                self.assertEqual(make_intent(change, f"dev-{platform}", platform).platform, platform)
        with self.assertRaises(ValueError):
            make_intent(change, "R1", "junos")

    def test_schema_shape_no_netbox_foreign_key_no_image_binary(self):
        device_name = models.DeviceIntent._meta.get_field("device_name")
        self.assertIsInstance(device_name, django_models.CharField)
        self.assertNotIsInstance(device_name, django_models.ForeignKey)
        self.assertEqual(models.DEVICE_NAME_VALIDATOR.regex.pattern, r"^[A-Za-z0-9_-]{1,64}$")
        field_types = {type(f).__name__ for f in models.DeviceIntent._meta.get_fields()}
        self.assertFalse({"FileField", "BinaryField"} & field_types)
        self.assertIsInstance(models.DeviceIntent._meta.get_field("image_reference"), django_models.CharField)

    def test_revisions_are_numbered_immutable_and_never_overwritten(self):
        intent = make_intent(make_change())
        rev1 = intent_service.create_candidate_revision(device_intent=intent, schema_version=1, sections={"interfaces": {"v": 1}})
        self.assertEqual((rev1.revision, rev1.schema_version), (1, 1))
        rev2 = intent_service.create_candidate_revision(device_intent=intent, sections={"interfaces": {"v": 2}})
        self.assertEqual(rev2.revision, rev1.revision + 1)
        self.assertEqual(models.DeviceIntentRevision.objects.get(pk=rev1.pk).sections, {"interfaces": {"v": 1}})
        with self.assertRaises(IntegrityError), transaction.atomic():
            models.DeviceIntentRevision.objects.create(device_intent=intent, revision=1)
        rev1.revision = 99
        with self.assertRaises(ValueError):
            rev1.save()
        with self.assertRaises(Exception):
            models.DeviceIntentRevision(device_intent=intent, revision=0).full_clean()


class ConfigletContractTests(TestCase):
    def test_identity_sequence_and_immutability(self):
        change = make_change()
        first, second = make_configlet(change), make_configlet(change)
        self.assertEqual((first.cfg_id, first.sequence, second.cfg_id, second.sequence), ("CFG-001", 1, "CFG-002", 2))
        self.assertEqual(first.full_identifier, f"{change.change_id} / CFG-001")
        with self.assertRaises(IntegrityError), transaction.atomic():
            models.Configlet.objects.create(
                change=change, cfg_id="CFG-999", sequence=1, target_device="R1",
                feature_namespace=models.FeatureNamespace.INTERFACES, operation_type=models.ConfigletOperationType.CREATE_DEFINE,
                deployment_priority=models.DeploymentPriority.INTERFACE_CONSTRUCTION)
        first.cfg_id = "CFG-999"
        with self.assertRaises(ValueError):
            first.save()

    def test_fields_and_the_define_vs_attach_taxonomy(self):
        change = make_change()
        configlet = make_configlet(change, target_device="S1", feature_namespace=models.FeatureNamespace.ROUTING,
                                   deployment_priority=models.DeploymentPriority.DYNAMIC_ROUTING)
        self.assertEqual((configlet.target_device, configlet.feature_namespace), ("S1", models.FeatureNamespace.ROUTING))
        self.assertEqual((configlet.deployment_priority, configlet.get_deployment_priority_display()), (5, "Dynamic routing"))
        attach = make_configlet(change, operation_type=models.ConfigletOperationType.ACTIVATE_ATTACH)
        self.assertNotEqual(configlet.operation_type, attach.operation_type)

    def test_dependency_rules(self):
        change, other = make_change(), make_change(title="Other")
        a, b, foreign = make_configlet(change), make_configlet(change), make_configlet(other)
        self.assertEqual(configlet_service.add_configlet_dependency(configlet=b, depends_on=a).depends_on, a)
        for label, configlet, depends_on in (("self-dependency", a, a), ("cross-Change", foreign, a), ("duplicate edge", b, a)):
            with self.subTest(case=label), self.assertRaises(ValueError):
                configlet_service.add_configlet_dependency(configlet=configlet, depends_on=depends_on)


class SecretHandlingTests(TestCase):
    def test_raw_secrets_are_refused_and_references_are_allowed(self):
        with self.assertRaises(ValueError):
            change_service.create_change(title="X", metadata={"password": "hunter2"})
        self.assertEqual(models.Change.objects.filter(title="X").count(), 0)
        change = make_change(metadata={"ticket_ref": "JIRA-123"})
        with self.assertRaises(ValueError):
            make_configlet(change, metadata={"api_token": "abc123"})
        configlet = make_configlet(change, metadata={"secret_ref": "device/R1/admin"})
        self.assertEqual((change.metadata["ticket_ref"], configlet.metadata["secret_ref"]), ("JIRA-123", "device/R1/admin"))
