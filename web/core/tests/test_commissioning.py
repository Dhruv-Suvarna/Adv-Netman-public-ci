"""V2 Phase 6: governed commissioning and controlled production admission of an ISOLATED, natively onboarded device.

The device is taken through the real Phase 3 / 4 / 5 services (ZTP behind an enforced policy, identity verification, BCRED, the
ISOLATE edge); its production configuration through the ordinary provisioning run and execution engine; its admission through the
isolation release on the in-memory upstream driven by the real cEOS executor.  NetBox is the provisioning tests' fake gateway."""

from __future__ import annotations

from django.test import TestCase, override_settings

from core import models
from core.services import provisioning_service as ps
from core.services.commissioning import admission as A
from core.services.commissioning import outbox, service as C, transport
from core.services.devices import lifecycle
from core.services.isolation import service as iso
from core.tests.helpers import isolation as I
from core.tests.helpers import lifecycle as L
from core.tests.helpers import ztp as Z

St, ASt = models.CommissioningState, models.AdmissionState
S = models.DeviceLifecycleState
EXPECT = {"routing": "OSPF", "ospf_neighbors": ["10.255.0.9"], "routes_v4": ["10.9.0.0/16"], "reachable": ["10.9.0.1"]}


@override_settings(NMAS_ADMISSION_SETTLE_SECONDS=0)
class Base(Z.ZtpTestMixin, TestCase):
    real_isolation_gate = True

    def ready(self):
        self.flow = I.Flow(self).ready_for_commissioning()
        self.device = self.flow.device
        return self.flow

    def opened(self):
        self.ready()
        result = C.open_commissioning(self.device, actor=L.OPERATOR)
        self.assertTrue(result.ok, result.codes)
        self.record = result.record
        self.lab = I.commissioning_lab(self.record.provisioning_run)
        return result

    def assessed(self):
        self.opened()
        I.candidate_ready(self.lab)
        result = C.assess(C.get_record(self.record.pk), actor=L.OPERATOR)
        self.assertTrue(result.ok, result.codes)
        self.record = result.record
        return result

    def approved(self):
        self.assessed()
        result = C.approve(self.record, actor=L.APPROVER, confirmation=self.record.evidence_digest)
        self.assertTrue(result.ok, result.codes)
        self.record = C.get_record(self.record.pk)
        return result

    def configured(self):
        self.approved()
        provisioned = self.lab.provision(actor=L.APPROVER)
        self.assertTrue(provisioned.ok, provisioned.codes)
        result = C.record_configuration(C.get_record(self.record.pk), actor=L.APPROVER, access=self.flow.access)
        self.assertTrue(result.ok, result.codes)
        self.record = result.record
        return result

    def admission_approved(self, expectations=None):
        self.configured()
        planned = A.plan(self.record, actor=L.OPERATOR, expectations=expectations or EXPECT)
        self.assertTrue(planned.ok, planned.codes)
        checked = A.precheck(planned.admission, actor=L.OPERATOR, access=self.flow.access)
        self.assertTrue(checked.ok, checked.codes)
        approved = A.approve(checked.admission, actor=L.APPROVER, confirmation=checked.admission.evidence_digest)
        self.assertTrue(approved.ok, approved.codes)
        self.admission = approved.admission
        return approved

    def device_state(self):
        self.device.refresh_from_db()
        return self.device.lifecycle_state


class OpenTests(Base):
    def test_open_creates_a_commissioning_provisioning_run(self):
        result = self.opened()
        run = result.record.provisioning_run
        self.assertEqual((result.record.state, run.bootstrap_transport), (St.OPEN, models.BootstrapTransport.ZTP_MANAGEMENT))
        self.assertEqual(run.bootstrap_target, {"device": self.device.device_id})
        self.assertEqual(run.management["interface"], self.flow.attachment.local_interface)
        self.assertEqual(run.management["ipv4"].split("/")[0], self.flow.ztp.reserved_address)
        self.assertTrue(self.device.lifecycle_events.filter(action="COM_OPEN", outcome="RECORDED").exists())

    def test_open_refuses_a_second_commissioning(self):
        self.opened()
        self.assertEqual(C.open_commissioning(self.device, actor=L.OPERATOR).codes, ["COMMISSIONING_OPEN_EXISTS"])

    def test_open_refuses_a_device_that_is_not_isolated_or_has_no_transport(self):
        flow = I.Flow(self)
        flow.verified()
        flow.bootstrapped()
        codes = C.open_commissioning(flow.device, actor=L.OPERATOR).codes
        self.assertIn("COMMISSIONING_DEVICE_NOT_ISOLATED", codes)
        self.assertIn("COMMISSIONING_TRANSPORT_UNAVAILABLE", codes)          # identity unverified, bootstrap credential live

    def test_open_refuses_a_legacy_device(self):
        L.adopt("S2")
        self.assertEqual(C.open_commissioning(models.ManagedDevice.objects.get(name="S2"), actor=L.OPERATOR).codes,
                         ["COMMISSIONING_STATE_INVALID"])


class ReadinessTests(Base):
    def test_assess_without_a_prechecked_candidate_stays_open(self):
        self.opened()
        result = C.assess(self.record, actor=L.OPERATOR)
        self.assertFalse(result.ok)
        self.assertEqual(result.record.state, St.OPEN)
        self.assertIn("COMMISSIONING_CONFIG_NOT_APPLIED", result.codes)
        self.assertEqual(self.device_state(), S.ISOLATED)

    def test_assess_ready_freezes_evidence_and_moves_lifecycle(self):
        result = self.assessed()
        self.assertEqual(result.record.state, St.READY)
        self.assertEqual(len(result.record.evidence_digest), 64)
        self.assertEqual(result.record.evidence["candidate"]["prov_id"], result.record.provisioning_run.prov_id)
        self.assertEqual(self.device_state(), S.READY_FOR_COMMISSIONING)
        self.assertNotIn("[REDACTED]", str(self.device.lifecycle_events.filter(action="COMMISSION_READY").first().evidence))

    def test_isolation_drift_withdraws_readiness(self):
        self.assessed()
        self.flow.session.send_config_set(["interface Ethernet7", f"no ip access-group NMAS-ISO-{self.device.device_id}-V4 in"])
        iso.check_drift(self.flow.refresh(), actor=L.APPROVER, access=self.flow.access)
        result = C.assess(self.record, actor=L.OPERATOR)
        self.assertEqual(result.record.state, St.OPEN)
        self.assertIn("ISOLATION_DRIFTED", result.codes)
        self.assertEqual(self.device_state(), S.ISOLATED)

    def test_operator_revoked_authorization_blocks_readiness_but_completion_closure_does_not(self):
        self.opened()
        auth = self.flow.ztp.authorization
        self.assertTrue(C.authorization_intact(auth))
        models.BootstrapAuthorization.objects.filter(pk=auth.pk).update(state=models.BootstrapAuthorizationState.REVOKED, revoked_by=L.OPERATOR)
        auth.refresh_from_db()
        self.assertFalse(C.authorization_intact(auth))
        self.assertFalse(C.authorization_intact(None))

    def test_bare_lifecycle_transition_cannot_skip_commissioning(self):
        self.ready()
        result = lifecycle.transition(self.device, S.READY_FOR_COMMISSIONING, actor=L.APPROVER)
        self.assertEqual(result.codes, ["COMMISSIONING_STATE_INVALID"])
        self.assertEqual(lifecycle.transition(self.device, S.IN_SERVICE, actor=L.APPROVER).codes, ["TRANSITION_INVALID"])


class ApprovalTests(Base):
    def test_requester_cannot_approve_and_confirmation_must_match(self):
        self.assessed()
        self.assertEqual(C.approve(self.record, actor=L.OPERATOR, confirmation=self.record.evidence_digest).codes, ["COMMISSIONING_SELF_APPROVAL"])
        self.assertEqual(C.approve(self.record, actor=L.APPROVER, confirmation="0" * 64).codes, ["COMMISSIONING_CONFIRMATION_MISMATCH"])
        self.assertEqual(C.get_record(self.record.pk).state, St.READY)

    def test_stale_evidence_is_refused(self):
        self.assessed()
        models.DeviceAttachment.objects.filter(pk=self.flow.attachment.pk).update(verification_state=models.AttachmentVerification.UNVERIFIED)
        result = C.approve(C.get_record(self.record.pk), actor=L.APPROVER, confirmation=self.record.evidence_digest)
        self.assertFalse(result.ok)
        self.assertIn("ISOLATION_DEVICE_NOT_OBSERVED", result.codes)

    def test_provisioning_run_cannot_be_approved_outside_commissioning(self):
        self.assessed()
        run = self.record.provisioning_run
        result = ps.approve(run, actor=L.APPROVER, confirm_candidate_hash=run.candidate_hash)
        self.assertEqual(result.codes, ["COMMISSIONING_NOT_APPROVED"])
        self.assertEqual(ps.approve(run, actor=L.OPERATOR, confirm_candidate_hash=run.candidate_hash).codes, ["APPROVAL_SELF"])

    def test_approval_approves_the_run_and_moves_lifecycle(self):
        self.approved()
        self.assertEqual(self.record.state, St.APPROVED)
        self.assertEqual(self.record.provisioning_run.status, models.ProvisioningStatus.APPROVED)
        self.assertEqual(self.device_state(), S.COMMISSIONING)
        self.assertEqual(C.staleness(self.record), [])
        self.assertEqual(transport.problems(self.device, purpose="WRITE"), [])

    def test_expired_approval_blocks_execution_and_nothing_is_written(self):
        self.approved()
        with override_settings(NMAS_COMMISSIONING_APPROVAL_MAX_AGE_SECONDS=0):
            self.assertIn("COMMISSIONING_EVIDENCE_STALE", [b["code"] for b in C.staleness(self.record)])
            result = self.lab.provision(actor=L.APPROVER)
        self.assertFalse(result.ok)
        self.assertIn("COMMISSIONING_STALE", result.codes)
        self.assertEqual(C.get_record(self.record.pk).state, St.APPROVED)


class ConfigurationTests(Base):
    def test_configuration_through_the_engine_marks_configuring_then_configured(self):
        self.approved()
        self.lab.provision(actor=L.APPROVER)
        self.assertEqual(C.get_record(self.record.pk).state, St.CONFIGURING)       # write-ahead before the first device write
        result = C.record_configuration(C.get_record(self.record.pk), actor=L.APPROVER, access=self.flow.access)
        self.assertEqual(result.record.state, St.CONFIGURED)
        self.assertEqual(self.device_state(), S.COMMISSIONING)
        self.assertEqual(self.device.admission_state, models.ProductionAdmissionState.NOT_ADMITTED)

    def test_isolation_drift_after_configuration_is_uncertain(self):
        self.approved()
        self.lab.provision(actor=L.APPROVER)
        self.flow.session.send_config_set(["router ospf 1", f"no passive-interface {I.PORT}"])
        result = C.record_configuration(C.get_record(self.record.pk), actor=L.APPROVER, access=self.flow.access)
        self.assertEqual((result.ok, result.record.state), (False, St.UNCERTAIN))

    def test_record_configuration_before_execution_is_refused(self):
        self.approved()
        self.assertEqual(C.record_configuration(self.record, actor=L.APPROVER, access=self.flow.access).codes,
                         ["COMMISSIONING_CONFIG_NOT_APPLIED"])

    def test_reconcile_configuring_folds_the_recorded_run_outcome(self):
        self.approved()
        self.lab.provision(actor=L.APPROVER)
        result = C.reconcile(C.get_record(self.record.pk), actor=L.APPROVER, access=self.flow.access)
        self.assertEqual(result.record.state, St.CONFIGURED)
        self.assertEqual(C.reconcile(result.record, actor=L.APPROVER).codes, ["COMMISSIONING_STATE_INVALID"])

    def test_abort_returns_the_device_to_isolated_and_cancels_the_run(self):
        self.approved()
        self.assertEqual(C.abort(self.record, actor=L.OPERATOR, reason="").codes, ["COMMISSIONING_STATE_INVALID"])
        result = C.abort(self.record, actor=L.OPERATOR, reason="wrong role")
        self.assertEqual(result.record.state, St.ABORTED)
        self.assertEqual(self.device_state(), S.ISOLATED)
        self.assertEqual(models.ProvisioningRun.objects.get(pk=self.record.provisioning_run_id).status, models.ProvisioningStatus.CANCELLED)
        self.assertTrue(C.open_commissioning(self.device, actor=L.OPERATOR).ok)    # a fresh commissioning may start

    def test_nsot_activation_waits_for_admission(self):
        self.configured()
        self.assertEqual(ps.sync_nsot(self.record.provisioning_run, actor=L.APPROVER, gateway=self.lab.gateway).codes,
                         ["COMMISSIONING_NOT_ADMITTED"])

    def test_status_summary(self):
        self.configured()
        found = C.status(self.record)
        self.assertEqual((found["state"], found["isolation_state"]), (St.CONFIGURED, models.IsolationState.VERIFIED))


class AdmissionTests(Base):
    def test_expectations_are_validated(self):
        clean, problems = A.validate_expectations(EXPECT)
        self.assertEqual(problems, [])
        self.assertEqual(clean["routing"], "OSPF")
        for bad in ({"routing": "BGP", "routes_v4": ["10.9.0.0/16"]}, {"routing": "OSPF", "routes_v4": ["10.9.0.0/16"]},
                    {"routing": "RIP", "ospf_neighbors": ["1.1.1.1"], "routes_v4": ["10.9.0.0/16"]}, {"routing": "RIP"},
                    {"routing": "RIP", "routes_v4": ["10.9.0.1/16"]}, {"routing": "RIP", "routes_v4": ["2001:db8::/32"]},
                    {"routing": "RIP", "routes_v4": ["10.9.0.0/16"], "reachable": ["router-a"]},
                    {"routing": "RIP", "routes_v4": ["10.9.0.0/16"], "extra": 1}):
            with self.subTest(bad=bad):
                self.assertTrue(A.validate_expectations(bad)[1])
        self.assertEqual(A.validate_expectations({"routing": "rip", "routes_v6": ["2001:db8:9::/48"]})[1], [])

    def test_plan_refused_before_configuration(self):
        self.approved()
        self.assertIn("ADMISSION_STATE_INVALID", A.plan(self.record, actor=L.OPERATOR, expectations=EXPECT).codes)

    def test_plan_refused_with_invalid_expectations_creates_nothing(self):
        self.configured()
        self.assertIn("ADMISSION_EXPECTATIONS_INVALID", A.plan(self.record, actor=L.OPERATOR, expectations={"routing": "OSPF"}).codes)
        self.assertFalse(models.ProductionAdmission.objects.exists())
        self.assertIsNone(self.flow.refresh().release_change)

    def test_approval_is_separated_and_bound_to_the_evidence(self):
        self.configured()
        planned = A.plan(self.record, actor=L.OPERATOR, expectations=EXPECT).admission
        A.precheck(planned, actor=L.OPERATOR, access=self.flow.access)
        admission = A.get_admission(planned.pk)
        self.assertEqual(A.approve(admission, actor=L.OPERATOR, confirmation=admission.evidence_digest).codes, ["ADMISSION_SELF_APPROVAL"])
        self.assertEqual(A.approve(admission, actor=L.APPROVER, confirmation="0" * 64).codes, ["COMMISSIONING_CONFIRMATION_MISMATCH"])
        self.assertEqual(A.open_admission(self.device).pk, admission.pk)
        self.assertIn("ADMISSION_OPEN_EXISTS", A.plan(self.record, actor=L.OPERATOR, expectations=EXPECT).codes)

    def test_admission_releases_isolation_and_admits(self):
        self.admission_approved()
        I.admitted_outputs(self.flow.session)
        result = A.execute(self.admission, actor=L.APPROVER, access=self.flow.access, gateway=self.lab.gateway)
        self.assertTrue(result.ok, result.codes)
        self.assertEqual(result.admission.state, ASt.ADMITTED)
        self.assertEqual((self.device_state(), self.device.admission_state), (S.IN_SERVICE, models.ProductionAdmissionState.ADMITTED))
        self.assertEqual(self.flow.refresh().state, models.IsolationState.RELEASED)
        self.assertEqual(C.get_record(self.record.pk).state, St.ADMITTED)
        self.assertEqual(self.flow.session.config.text(), I.FakeEosSession(I.upstream_config()).config.text())
        self.assertEqual(sorted(models.LifecycleOutboxEvent.objects.filter(topic__endswith="_ADMITTED").values_list("topic", flat=True)),
                         sorted(t for t in models.OutboxTopic.values if t.endswith("_ADMITTED")))
        self.assertTrue(result.detail["nsot_sync"])
        self.assertEqual(models.ProvisioningRun.objects.get(pk=self.record.provisioning_run_id).status, models.ProvisioningStatus.NSOT_SYNCED)
        self.assertEqual(transport.problems(self.device, purpose="WRITE"), [])         # an admitted device stays writable
        self.assertEqual(A.status(result.admission)["state"], ASt.ADMITTED)

    def test_failed_verification_restores_isolation(self):
        self.admission_approved()
        enforced = self.flow.session.config.text()                       # no adjacency ever forms
        result = A.execute(self.admission, actor=L.APPROVER, access=self.flow.access, gateway=self.lab.gateway)
        self.assertFalse(result.ok)
        self.assertEqual(result.admission.state, ASt.RESTORED)
        self.assertEqual(result.codes, ["ADMISSION_VERIFICATION_FAILED"])
        self.assertEqual(self.flow.session.config.text(), enforced)
        self.assertEqual(self.flow.refresh().state, models.IsolationState.ENFORCED)
        self.assertEqual(C.get_record(self.record.pk).state, St.CONFIGURED)
        self.assertEqual((self.device_state(), self.device.admission_state), (S.COMMISSIONING, models.ProductionAdmissionState.NOT_ADMITTED))
        self.assertFalse(models.LifecycleOutboxEvent.objects.filter(topic__endswith="_ADMITTED").exists())   # lifecycle facts (DISCOVER, ISOLATE, ...) legitimately exist

    def test_execute_refused_when_unapproved_or_stale(self):
        self.configured()
        planned = A.plan(self.record, actor=L.OPERATOR, expectations=EXPECT).admission
        self.assertEqual(A.execute(planned, actor=L.APPROVER, access=self.flow.access).codes, ["ADMISSION_STATE_INVALID"])
        self.assertEqual(A.cancel(planned, actor=L.OPERATOR, reason="").codes, ["ADMISSION_STATE_INVALID"])
        self.assertEqual(A.cancel(planned, actor=L.OPERATOR, reason="window closed").admission.state, ASt.CANCELLED)

    def test_failures_reads_adjacency_routes_and_reachability(self):
        self.admission_approved()
        executor = self.flow.access.executor_factory({"name": "S1", "platform": "ceos"})
        executor.connect()
        found = {row["check"] for row in A.failures(executor, self.flow.refresh(), self.admission.expectations)}
        self.assertEqual(found, {"ospf_adjacency", "routes_v4", "reachability"})
        traffic = lambda admission: [{"flow": "svc -> device", "expect": "PERMIT", "observed": "DENY"}]    # noqa: E731
        self.assertIn("traffic", {row["check"] for row in A.failures(executor, self.flow.refresh(), {"routing": "RIP"}, traffic=traffic)})

    def test_reconcile_after_a_crash_proves_the_upstream_state(self):
        self.admission_approved()
        admission = A._save(self.admission, state=ASt.RELEASING)
        A._record_state(admission.commissioning, St.ADMITTING)
        iso._save(self.flow.refresh(), state=models.IsolationState.RELEASE_PENDING)
        result = A.reconcile(A.get_admission(admission.pk), actor=L.APPROVER, access=self.flow.access)
        self.assertEqual(result.admission.state, ASt.RESTORED)                            # nothing was removed
        self.assertEqual(C.get_record(self.record.pk).state, St.CONFIGURED)
        self.assertEqual(A.reconcile(result.admission, actor=L.APPROVER).codes, ["ADMISSION_STATE_INVALID"])


class OutboxTests(Base):
    PAYLOAD = {"device_id": "DEV-000001", "name": "NEW1", "admission": "ADM-000001", "links": [], "dependencies": []}

    def test_validate_contracts(self):
        topic = models.OutboxTopic.TOPOLOGY_DEVICE_ADMITTED
        self.assertEqual(outbox.validate(topic, self.PAYLOAD), [])
        self.assertTrue(outbox.validate("NOPE", self.PAYLOAD))
        self.assertTrue(outbox.validate(topic, {"name": "NEW1"}))
        self.assertTrue(outbox.validate(topic, {**self.PAYLOAD, "extra": 1}))
        self.assertIn("secret-shaped content", outbox.validate(topic, {**self.PAYLOAD, "links": [{"password": "x"}]}))

    def test_record_is_idempotent_and_facts_never_change(self):
        device = L.register().device
        topic = models.OutboxTopic.TOPOLOGY_DEVICE_ADMITTED
        first = outbox.record(device, topic, self.PAYLOAD, subject="ADM-000001", actor=L.APPROVER)
        self.assertEqual(outbox.record(device, topic, self.PAYLOAD, subject="ADM-000001", actor=L.APPROVER).pk, first.pk)
        with self.assertRaises(outbox.OutboxError):
            outbox.record(device, topic, {**self.PAYLOAD, "name": "OTHER"}, subject="ADM-000001", actor=L.APPROVER)
        with self.assertRaises(outbox.OutboxError):
            outbox.record(device, topic, {"name": "x"}, subject="ADM-000002", actor=L.APPROVER)
        self.assertEqual(len(first.idempotency_key), 64)

    def test_delivery_failure_and_pending(self):
        device = L.register().device
        event = outbox.record(device, models.OutboxTopic.TOPOLOGY_DEVICE_ADMITTED, self.PAYLOAD, subject="ADM-1", actor=L.APPROVER)
        self.assertEqual([e.pk for e in outbox.pending()], [event.pk])
        failed = outbox.fail(event, code="CONSUMER_DOWN")
        self.assertEqual((failed.state, failed.attempts), (models.OutboxState.FAILED, 1))
        self.assertEqual([e.pk for e in outbox.pending(models.OutboxTopic.TOPOLOGY_DEVICE_ADMITTED)], [event.pk])
        delivered = outbox.deliver(event, consumer="phase8-topology", actor="system:phase8")
        self.assertEqual((delivered.state, delivered.attempts), (models.OutboxState.DELIVERED, 2))
        self.assertEqual(outbox.deliver(event, consumer="again", actor="system:phase8").consumer, "phase8-topology")
        with self.assertRaises(outbox.OutboxError):
            outbox.fail(event, code="LATE")
        self.assertEqual(outbox.pending(), [])
        self.assertTrue(device.lifecycle_events.filter(action="OUTBOX_DELIVER").exists())


class TransportTests(Base):
    def test_problems_and_live_target_fail_closed(self):
        self.assertEqual(transport.problems(None), ["NOT_REGISTERED"])
        flow = I.Flow(self)
        found = transport.problems(flow.device, purpose="WRITE")
        self.assertTrue({"LIFECYCLE_STATE", "IDENTITY_UNVERIFIED", "CREDENTIAL_NOT_TRANSITIONED", "WRITE_NOT_AUTHORIZED"} <= set(found))
        self.assertIsNone(transport.live_target(flow.device.name))
        self.assertIsNone(transport.live_target("NOPE"))

    def test_ready_device_reads_but_does_not_write_before_approval(self):
        self.ready()
        self.assertEqual(transport.problems(self.device, purpose="READ"), [])
        self.assertEqual(transport.problems(self.device, purpose="WRITE"), ["WRITE_NOT_AUTHORIZED"])
        self.assertFalse(transport.write_authorized(self.device))
        endpoint = transport.endpoint(self.device)
        self.assertEqual((endpoint["address"], endpoint["host_key"], endpoint["username"]), (self.flow.ztp.reserved_address, L.HOST_KEY, "nmas-svc"))
        self.assertIsNone(transport.live_target(self.device.name, purpose="WRITE"))
