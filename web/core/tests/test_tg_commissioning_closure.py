"""Test-governance closure for V2 Phase 6 commissioning and admission: each public function of ``core.services.commissioning``,
``provisioning.commissioning_gate`` and the Phase 5 / 6 models called directly, with an accepting and a refusing case where it
has both.  The device goes through the same real Phase 3 / 4 / 5 services on fakes as ``test_commissioning`` (its ``Base``)."""

from __future__ import annotations

import hashlib
from unittest import mock

from django.test import TestCase, override_settings

from core import models
from core.services import nsot_live
from core.services.commissioning import admission as A
from core.services.commissioning import dependencies as D
from core.services.commissioning import outbox, service as C, transport
from core.services.execution.executors.base import ExecutorError
from core.services.isolation import service as iso
from core.services.provisioning import commissioning_gate as G
from core.services.ztp import policy as ztp_policy
from core.tests.helpers import isolation as I
from core.tests.helpers import lifecycle as L
from core.tests.test_commissioning import EXPECT, Base

St, ASt = models.CommissioningState, models.AdmissionState
S = models.DeviceLifecycleState


class ServiceClosureTests(Base):
    def test_settings_and_authorization_return_configured_values(self):
        with override_settings(NMAS_COMMISSIONING_APPROVAL_MAX_AGE_SECONDS=60):
            self.assertEqual(C.approval_max_age_seconds(), 60.0)
        self.ready()
        self.assertTrue(C.authorization_intact(self.flow.ztp.authorization))

    def test_digest(self):
        with self.subTest("returns the same digest for the same evidence"):
            self.assertEqual(C.digest({"b": 1, "a": 2}), C.digest({"a": 2, "b": 1}))
            self.assertEqual(len(C.digest({})), 64)
        with self.subTest("refuses to equate changed evidence"):
            self.assertNotEqual(C.digest({"a": 1}), C.digest({"a": "1 "}))

    def test_session_management_and_open_records(self):
        self.ready()
        policy = iso.device_policy(self.device)
        other = L.register("NEW2", serial="SN-NEW2", mac="00:1c:73:00:00:02").device
        with self.subTest("returns the bootstrapped session and its addressing"):
            self.assertEqual(C.session_of(self.device).pk, self.flow.ztp.pk)
            management = C.management_of(self.device, policy)
            self.assertEqual((management["interface"], management["ipv4"].split("/")[0]), (self.flow.attachment.local_interface, self.flow.ztp.reserved_address))
            self.assertEqual(C.open_problems(self.device), [])
        with self.subTest("refuses a device without a session or an open record"):
            self.assertIsNone(C.session_of(other))
            self.assertEqual(C.management_of(other, policy), {})
            self.assertIsNone(C.open_record(self.device))
            self.assertIn("COMMISSIONING_DEVICE_NOT_ISOLATED", [b["code"] for b in C.open_problems(other)])
        with self.subTest("returns the open record once opened"):
            record = C.open_commissioning(self.device, actor=L.OPERATOR).record
            self.assertEqual(C.open_record(self.device).pk, record.pk)

    def test_readiness(self):
        self.opened()
        with self.subTest("refuses readiness without a prechecked candidate"):
            checks, _evidence = C.readiness(C.get_record(self.record.pk))
            self.assertIn("production_candidate", [row["check"] for row in checks if not row["ok"]])
        with self.subTest("passes every check once the candidate is prechecked"):
            I.candidate_ready(self.lab)
            checks, evidence = C.readiness(C.get_record(self.record.pk))
            self.assertEqual([row["check"] for row in checks if not row["ok"]], [])
            self.assertEqual(evidence["candidate"]["prov_id"], self.record.provisioning_run.prov_id)

    def test_mark_configuring_refuses_a_run_whose_record_is_not_approved(self):
        self.opened()
        C.mark_configuring(self.record.provisioning_run)
        self.assertEqual(C.get_record(self.record.pk).state, St.OPEN)

    def test_mark_configuring_accepts_the_approved_run_write_ahead(self):
        self.approved()
        C.mark_configuring(self.record.provisioning_run)
        self.assertEqual(C.get_record(self.record.pk).state, St.CONFIGURING)

    def test_abort_refuses_an_admitted_or_closed_record(self):
        self.approved()
        aborted = C.abort(self.record, actor=L.OPERATOR, reason="wrong role").record
        self.assertEqual(C.abort(aborted, actor=L.OPERATOR, reason="again").codes, ["COMMISSIONING_STATE_INVALID"])

    def test_status_never_carries_key_material(self):
        self.opened()
        found = C.status(self.record)
        self.assertEqual(found["state"], St.OPEN)
        self.assertNotIn("PRIVATE KEY", str(found))

    def uncertain(self, text="hostname NEW1\n"):
        self.approved()
        run = self.record.provisioning_run
        models.ProvisioningRun.objects.filter(pk=run.pk).update(status=models.ProvisioningStatus.FAILED,
                                                                pre_config_digest=hashlib.sha256(text.encode()).hexdigest())
        record = C._save(C.get_record(self.record.pk), state=St.UNCERTAIN,
                         failure={"code": "COMMISSIONING_CONFIG_NOT_APPLIED", "provisioning": "FAILED", "restored": False})
        return record, text

    def test_restoration_problems(self):
        record, text = self.uncertain()
        with self.subTest("accepts a device read equal to the pre-execution digest"):
            found, facts = C.restoration_problems(record, reader=lambda device: text)
            self.assertEqual((found, facts["device_digest"]), ([], facts["pre_config_digest"]))
        with self.subTest("refuses a different, unreadable or unbaselined device"):
            self.assertEqual(C.restoration_problems(record, reader=lambda device: text + "router ospf 1\n")[0][0]["code"],
                             "COMMISSIONING_CONFIG_NOT_APPLIED")
            broken = mock.Mock(side_effect=ExecutorError("CONNECTION_FAILED"))
            found, facts = C.restoration_problems(record, reader=broken)
            self.assertEqual((found[0]["code"], facts["device_digest"]), ("COMMISSIONING_CONFIG_NOT_APPLIED", ""))
            models.ProvisioningRun.objects.filter(pk=record.provisioning_run_id).update(pre_config_digest="")
            self.assertTrue(C.restoration_problems(record, reader=lambda device: text)[0])

    def test_reconcile_proves_restoration_and_returns_the_device_to_isolated(self):
        record, text = self.uncertain()
        result = C.reconcile(record, actor=L.APPROVER, reader=lambda device: text)
        self.assertTrue(result.ok, result.codes)
        self.assertEqual((result.record.state, result.record.failure["restoration_proven_by"]), (St.ABORTED, "COM_RECONCILE"))
        self.assertEqual(self.device_state(), S.ISOLATED)

    def test_reconcile_refuses_an_unproven_restoration_and_keeps_it_uncertain(self):
        record, _text = self.uncertain()
        result = C.reconcile(record, actor=L.APPROVER, reader=lambda device: "hostname OTHER\n")
        self.assertEqual((result.ok, result.codes), (False, ["COMMISSIONING_CONFIG_NOT_APPLIED"]))
        self.assertEqual(C.get_record(record.pk).state, St.UNCERTAIN)
        self.assertEqual(self.device_state(), S.COMMISSIONING)


class AdmissionClosureTests(Base):
    def test_timing_settings_return_configured_values(self):
        with override_settings(NMAS_ADMISSION_SETTLE_SECONDS=3, NMAS_ADMISSION_POLL_SECONDS=1):
            self.assertEqual((A.settle_seconds(), A.poll_seconds()), (3.0, 1.0))

    def test_digest(self):
        with self.subTest("returns a canonical digest"):
            self.assertEqual(A.digest({"b": [1], "a": 2}), A.digest({"a": 2, "b": [1]}))
        with self.subTest("refuses to equate different evidence"):
            self.assertNotEqual(A.digest({"a": [1, 2]}), A.digest({"a": [2, 1]}))

    def test_lookups_refuse_unknown_ids_and_closed_admissions(self):
        self.assertIsNone(A.get_admission("ADM-XYZ"))
        self.assertIsNone(A.get_admission(None))
        self.assertIsNone(A.open_admission(L.register("NEW2", serial="SN-NEW2", mac="00:1c:73:00:00:02").device))

    def test_plan_evidence_and_current_problems(self):
        self.configured()
        policy = iso.device_policy(self.device)
        with self.subTest("accepts a configured record and builds its evidence"):
            self.assertEqual(A.plan_problems(C.get_record(self.record.pk)), [])
            found = A.evidence(C.get_record(self.record.pk), policy, EXPECT)
            self.assertEqual((found["commissioning"], found["release_change"]), (self.record.commissioning_id, ""))
        admission = A.plan(C.get_record(self.record.pk), actor=L.OPERATOR, expectations=EXPECT).admission
        with self.subTest("returns current evidence for the planned admission"):
            self.assertEqual(A.current_problems(admission), [])
            built = A.evidence(admission.commissioning, iso.device_policy(self.device), admission.expectations)
            self.assertEqual(A.digest(built), admission.evidence_digest)
        with self.subTest("refuses changed expectations and a second plan"):
            other = A.evidence(admission.commissioning, iso.device_policy(self.device), {**admission.expectations, "reachable": []})
            self.assertNotEqual(A.digest(other), admission.evidence_digest)
            self.assertIn("ADMISSION_OPEN_EXISTS", [b["code"] for b in A.plan_problems(C.get_record(self.record.pk))])
            models.ProductionAdmission.objects.filter(pk=admission.pk).update(expectations={**admission.expectations, "reachable": []})
            self.assertIn("COMMISSIONING_EVIDENCE_STALE", [b["code"] for b in A.current_problems(A.get_admission(admission.pk))])

    def test_failures_refuse_an_adjacency_that_never_forms(self):
        self.admission_approved()
        executor = self.flow.access.executor_factory({"name": "S1", "platform": "ceos"})
        executor.connect()
        found = A.failures(executor, self.flow.refresh(), self.admission.expectations)
        self.assertIn("ospf_adjacency", [row["check"] for row in found])

    def test_cancel_returns_a_cancelled_admission_and_nothing_sent(self):
        self.configured()
        planned = A.plan(self.record, actor=L.OPERATOR, expectations=EXPECT).admission
        before = self.flow.session.config.text()
        self.assertEqual(A.cancel(planned, actor=L.OPERATOR, reason="window closed").admission.state, ASt.CANCELLED)
        self.assertEqual(self.flow.session.config.text(), before)

    def test_reconcile_refuses_an_admission_that_is_not_releasing(self):
        self.admission_approved()
        self.assertEqual(A.reconcile(self.admission, actor=L.APPROVER, access=self.flow.access).codes, ["ADMISSION_STATE_INVALID"])

    def test_status_names_no_admission_before_approval(self):
        self.configured()
        planned = A.plan(self.record, actor=L.OPERATOR, expectations=EXPECT).admission
        found = A.status(planned)
        self.assertEqual((found["state"], found["approved_by"]), (ASt.PLANNED, ""))


class DependencyClosureTests(TestCase):
    def setUp(self):
        L.adopt("R4", role="router")
        self.legacy = models.ManagedDevice.objects.get(name="R4")
        self.mid = L.register("CORE-A", serial="SN-CORE-A", mac="00:1c:73:00:01:01").device
        self.leaf = L.register("EDGE-B", serial="SN-EDGE-B", mac="00:1c:73:00:01:02").device

    def test_edges_returns_every_active_dependency(self):
        D.add(self.leaf, self.mid, kind=models.DependencyKind.DECLARED, actor=L.OPERATOR)
        self.assertEqual(D.edges(), {self.leaf.pk: {self.mid.pk}})

    def test_graph_helpers_refuse_unmet_or_unknown_upstreams(self):
        row = D.add(self.leaf, self.mid, kind=models.DependencyKind.DECLARED, actor=L.OPERATOR).dependency
        self.assertFalse(D.reaches(D.edges(), self.mid.pk, self.leaf.pk))
        self.assertFalse(D.satisfied(self.mid)[0])
        self.assertEqual([b["code"] for b in D.unmet(self.leaf)], ["COMMISSIONING_DEPENDENCY_UNMET"])
        self.assertEqual(D.derive(self.mid, actor=L.OPERATOR), [])                      # no attachment: nothing implied
        self.assertEqual(D.remove(row, actor=L.OPERATOR, reason="").codes, ["COMMISSIONING_DEPENDENCY_INVALID"])
        view = D.graph_view([self.leaf])
        self.assertEqual([(e["upstream"], e["satisfied"]) for e in view["edges"]], [("CORE-A", False)])


class OutboxClosureTests(Base):
    PAYLOAD = {"device_id": "DEV-000001", "name": "NEW1", "admission": "ADM-000001", "links": [], "dependencies": []}
    TOPIC = models.OutboxTopic.TOPOLOGY_DEVICE_ADMITTED

    def test_keys_and_digests(self):
        with self.subTest("returns one stable key and digest per fact"):
            self.assertEqual(outbox.key_for(self.TOPIC, "ADM-1"), outbox.key_for(self.TOPIC, "ADM-1"))
            self.assertEqual(outbox.digest(self.PAYLOAD), outbox.digest(dict(reversed(list(self.PAYLOAD.items())))))
        with self.subTest("refuses to reuse a key or digest across facts"):
            self.assertNotEqual(outbox.key_for(self.TOPIC, "ADM-1"), outbox.key_for(models.OutboxTopic.NSOT_DEVICE_ADMITTED, "ADM-1"))
            self.assertNotEqual(outbox.digest(self.PAYLOAD), outbox.digest({**self.PAYLOAD, "name": "NEW2"}))

    def test_validate_refuses_unknown_topics_missing_fields_and_secrets(self):
        self.assertEqual(outbox.validate("NOPE", self.PAYLOAD), ["unknown topic NOPE"])
        self.assertIn("missing links", outbox.validate(self.TOPIC, {k: v for k, v in self.PAYLOAD.items() if k != "links"}))
        self.assertIn("secret-shaped content", outbox.validate(self.TOPIC, {**self.PAYLOAD, "links": [{"password": "x"}]}))

    def test_record_pending_deliver_and_fail_succeed_for_a_valid_event(self):
        device = L.register().device
        event = outbox.record(device, self.TOPIC, self.PAYLOAD, subject="ADM-1", actor=L.APPROVER)
        self.assertEqual([e.pk for e in outbox.pending(self.TOPIC)], [event.pk])
        self.assertEqual(outbox.fail(event, code="CONSUMER_DOWN").state, models.OutboxState.FAILED)
        self.assertEqual(outbox.deliver(event, consumer="phase8-topology", actor="system:phase8").state, models.OutboxState.DELIVERED)

    def admitted(self):
        self.admission_approved()
        I.admitted_outputs(self.flow.session)
        result = A.execute(self.admission, actor=L.APPROVER, access=self.flow.access, gateway=self.lab.gateway)
        self.assertTrue(result.ok, result.codes)
        return result.admission

    def test_admission_payloads_and_record_admission_return_valid_contracts(self):
        admission = self.admitted()
        payloads = outbox.admission_payloads(admission)
        self.assertEqual({topic: outbox.validate(topic, payload) for topic, payload in payloads.items()}, {t: [] for t in payloads})
        rows = outbox.record_admission(admission, actor=L.APPROVER)
        self.assertEqual(sorted(r.topic for r in rows), sorted(t for t in models.OutboxTopic.values if t.endswith("_ADMITTED")))

    def test_admission_payloads_never_carry_secrets_and_record_admission_never_duplicates(self):
        admission = self.admitted()
        payloads = outbox.admission_payloads(admission)
        self.assertNotIn("ssh_key_ref", str(payloads))
        self.assertNotIn("password", str(payloads))
        before = models.LifecycleOutboxEvent.objects.count()
        outbox.record_admission(admission, actor=L.APPROVER)
        self.assertEqual(models.LifecycleOutboxEvent.objects.count(), before)


class TransportClosureTests(Base):
    def test_lookups_and_endpoint(self):
        self.ready()
        with self.subTest("returns the transition, the device and its pinned endpoint"):
            self.assertEqual(transport.credential_transition(self.device).state, models.BootstrapCredentialState.COMPLETE)
            self.assertEqual(transport.device_for(self.device.name).pk, self.device.pk)
            self.assertEqual(transport.endpoint(self.device)["host_key"], L.HOST_KEY)
        with self.subTest("refuses a legacy device and a device without a transition"):
            L.adopt("S2")
            self.assertIsNone(transport.device_for("S2"))
            self.assertIsNone(transport.credential_transition(L.register("NEW2", serial="SN-NEW2", mac="00:1c:73:00:00:02").device))

    def test_write_authorized_and_live_target_return_access_once_approved(self):
        self.approved()
        self.assertTrue(transport.write_authorized(self.device))
        with mock.patch("modules.device_credentials.load_ssh_private_key", return_value="pkey"):
            target = transport.live_target(self.device.name, purpose="WRITE")
        self.assertEqual((target["pinned_host_key"], target["management"]["source"]), (L.HOST_KEY, transport.SOURCE))
        self.assertEqual(target["ssh_auth"]["pkey"], "pkey")

    def test_connect_pinned(self):
        import paramiko

        target = {"address": "10.254.30.10", "port": 22, "pinned_host_key": "SHA256:expected"}
        auth = {"username": "nmas-svc", "ssh_auth": {"pkey": None}}
        sock = mock.Mock()
        with self.subTest("returns an opened session over the pinned socket"):
            with mock.patch("socket.create_connection", return_value=sock), \
                    mock.patch("netmiko.arista.arista.AristaSSH._open", return_value=None) as opened:
                conn = transport.connect_pinned(target, auth, 5)
            self.assertEqual((conn.host, conn.username, opened.call_count), ("10.254.30.10", "nmas-svc", 1))
            sock.close.assert_not_called()
        with self.subTest("refuses a host key other than the pinned one and closes the socket on failure"):
            with mock.patch("socket.create_connection", return_value=sock), \
                    mock.patch("netmiko.arista.arista.AristaSSH._open", side_effect=paramiko.SSHException("HOST_KEY_MISMATCH")):
                with self.assertRaises(paramiko.SSHException):
                    transport.connect_pinned(target, auth, 5)
            sock.close.assert_called_once()
            policy = conn._build_ssh_client()._policy
            with self.assertRaises(paramiko.SSHException):
                policy.missing_host_key(None, "10.254.30.10", paramiko.RSAKey.generate(1024))

    def test_read_connection_and_config_reader(self):
        session = I.FakeEosSession("hostname NEW1\n")
        with self.subTest("returns an enabled read session and the sanitized configuration"):
            with mock.patch.object(transport, "live_target", return_value={"auth_candidates": ({},)}), \
                    mock.patch.object(transport, "connect_pinned", return_value=session):
                self.assertIs(transport.read_connection({"name": "NEW1"}), session)
            with mock.patch.object(transport, "read_connection", return_value=session):
                self.assertIn("hostname NEW1", transport.config_reader({"name": "NEW1", "platform": "ceos"}))
        with self.subTest("refuses an unready device and a failed connection"):
            with self.assertRaises(ExecutorError) as raised:
                transport.read_connection({"name": "NOPE"})
            self.assertEqual(raised.exception.code, "NOT_CONFIGURED")
            with mock.patch.object(transport, "live_target", return_value={"auth_candidates": ({},)}), \
                    mock.patch.object(transport, "connect_pinned", side_effect=OSError("refused")):
                with self.assertRaises(ExecutorError):
                    transport.read_connection({"name": "NEW1"})
            with mock.patch.object(transport, "read_connection", side_effect=ExecutorError("NOT_CONFIGURED")):
                with self.assertRaises(ExecutorError):
                    transport.config_reader({"name": "NOPE", "platform": "ceos"})

    def test_prober(self):
        self.ready()
        with self.subTest("returns an answering device without production configuration"):
            with mock.patch.object(transport, "config_reader", return_value="hostname NEW1\n"):
                probe = transport.prober({"device": self.device.device_id})
            self.assertEqual((probe.answers, probe.error), (True, ""))
        with self.subTest("refuses an unknown target, an unready device and an unreadable one"):
            self.assertEqual(transport.prober({"device": "DEV-999999"}).error, "TARGET_INVALID")
            other = L.register("NEW2", serial="SN-NEW2", mac="00:1c:73:00:00:02").device
            self.assertEqual(transport.prober({"device": other.device_id}).error, "LIFECYCLE_STATE")
            with mock.patch.object(transport, "config_reader", side_effect=ExecutorError("CONNECTION_FAILED")):
                self.assertEqual(transport.prober({"device": self.device.device_id}).error, "NO_MANAGEMENT_PLANE")

    def test_nsot_live_target_refuses_an_unregistered_or_unready_native_device(self):
        self.assertIsNone(nsot_live.get_live_target("NEW-UNKNOWN", platform="ceos"))
        self.ready()
        self.assertIsNone(nsot_live.get_live_target(self.device.name, purpose="WRITE", platform="ceos"))

    def test_nsot_live_target_returns_a_native_device_to_a_ceos_caller(self):
        self.approved()
        with mock.patch("modules.device_credentials.load_ssh_private_key", return_value="pkey"):
            target = nsot_live.get_live_target(self.device.name, purpose="WRITE", platform="ceos")
        self.assertEqual((target["platform"], target["pinned_host_key"]), ("ceos", L.HOST_KEY))

    def test_nsot_live_target_never_resolves_a_native_device_for_another_platform_or_an_unnamed_caller(self):
        self.approved()
        with mock.patch("modules.device_credentials.load_ssh_private_key", return_value="pkey"):
            for platform in ("", "iosxe", "srlinux"):
                with self.subTest(platform or "unnamed"):
                    self.assertIsNone(nsot_live.get_live_target(self.device.name, purpose="WRITE", platform=platform))


class GateClosureTests(Base):
    def test_gate_accepts_the_commissioning_run(self):
        self.approved()
        run = self.record.provisioning_run
        self.assertTrue(G.is_commissioning(run))
        self.assertEqual(G.record_of(run).pk, self.record.pk)
        self.assertEqual(G.identity_blockers(run, {"device": self.device.device_id}), [])
        self.assertEqual(G.approval_blockers(run, L.APPROVER), [])
        self.assertEqual(G.execution_blockers(run), [])
        G.mark_configuring(run)
        self.assertEqual(C.get_record(self.record.pk).state, St.CONFIGURING)
        with mock.patch.object(transport, "config_reader", return_value="hostname NEW1\n"):
            self.assertEqual(G.config_reader({"name": self.device.name}), "hostname NEW1\n")

    def test_gate_refuses_other_devices_unapproved_runs_and_unadmitted_sync(self):
        self.opened()
        run = self.record.provisioning_run
        self.assertFalse(G.is_commissioning(None))
        self.assertIsNone(G.record_of(None))
        self.assertEqual(G.identity_blockers(run, {"device": "DEV-999999"})[0]["code"], "BOOTSTRAP_TARGET_INVALID")
        self.assertEqual(G.approval_blockers(run, L.APPROVER)[0]["code"], "COMMISSIONING_NOT_APPROVED")
        self.assertEqual(G.execution_blockers(run)[0]["code"], "COMMISSIONING_NOT_APPROVED")
        self.assertEqual(G.sync_blockers(run)[0]["code"], "COMMISSIONING_NOT_ADMITTED")
        G.mark_configuring(run)
        self.assertEqual(C.get_record(self.record.pk).state, St.OPEN)
        with mock.patch.object(transport, "config_reader", side_effect=ExecutorError("NOT_CONFIGURED")):
            with self.assertRaises(ExecutorError):
                G.config_reader({"name": "NOPE"})

    def test_sync_blockers_returns_nothing_once_admitted(self):
        self.admission_approved()
        I.admitted_outputs(self.flow.session)
        self.assertTrue(A.execute(self.admission, actor=L.APPROVER, access=self.flow.access, gateway=self.lab.gateway).ok)
        self.assertEqual(G.sync_blockers(self.record.provisioning_run), [])


class DhcpGateClosureTests(Base):
    def test_dhcp_policy_never_answers_a_port_whose_isolation_drifted(self):
        from core.services.devices import authorization
        from core.services.ztp import workflow

        flow = I.Flow(self)
        flow.verified()
        auth = L.request_auth(flow.device, flow.attachment).authorization
        auth = authorization.approve(auth, actor=L.APPROVER, confirm_digest=auth.binding_digest).authorization
        workflow.open_session(flow.device, authorization=auth, network=flow.network, actor=L.OPERATOR)
        flow.session.send_config_set(["router ospf 1", f"no passive-interface {I.PORT}"])
        iso.check_drift(flow.refresh(), actor=L.APPROVER, access=flow.access)
        self.assertEqual(ztp_policy.build_policy(flow.network).reservations, ())


class ModelClosureTests(Base):
    def test_model_identifiers_and_flags_return_their_values(self):
        self.configured()
        policy = iso.device_policy(self.device)
        self.assertFalse(policy.is_terminal)
        self.assertEqual(self.record.commissioning_id, f"COM-{self.record.pk:06d}")
        self.assertTrue(self.record.is_open)
        admission = A.plan(self.record, actor=L.OPERATOR, expectations=EXPECT).admission
        self.assertEqual(admission.admission_id, f"ADM-{admission.pk:06d}")
        self.assertTrue(admission.is_open)

    def test_model_saves_accept_service_writes(self):
        self.configured()
        policy = iso.device_policy(self.device)
        policy.failure, policy.version = {"note": "x"}, policy.version + 1
        policy.__dict__["_isolation_write"] = True
        policy.save()
        check = models.IsolationCheck(policy=policy, kind=models.IsolationCheckKind.DRIFT, ok=True, recorded_by=L.APPROVER)
        check.save()
        record = C.get_record(self.record.pk)
        record.version += 1
        record.__dict__["_commissioning_write"] = True
        record.save()
        admission = A.plan(record, actor=L.OPERATOR, expectations=EXPECT).admission
        admission.version += 1
        admission.__dict__["_admission_write"] = True
        admission.save()
        other = L.register("NEW2", serial="SN-NEW2", mac="00:1c:73:00:00:02").device
        dependency = models.CommissioningDependency(device=other, upstream=self.device, kind=models.DependencyKind.DECLARED, created_by=L.OPERATOR)
        dependency.save()
        event = outbox.record(self.device, models.OutboxTopic.TOPOLOGY_DEVICE_ADMITTED, OutboxClosureTests.PAYLOAD, subject="ADM-9", actor=L.APPROVER)
        event.attempts += 1
        event.save()
        self.assertEqual(models.IsolationPolicy.objects.get(pk=policy.pk).failure, {"note": "x"})
        self.assertEqual(models.LifecycleOutboxEvent.objects.get(pk=event.pk).attempts, 1)
        self.assertTrue(models.CommissioningDependency.objects.filter(pk=dependency.pk).exists())

    def test_model_saves_refuse_direct_or_invalid_writes(self):
        self.configured()
        policy = iso.device_policy(self.device)
        policy.failure = {"note": "x"}
        with self.assertRaises(ValueError):
            policy.save()
        with self.assertRaises(ValueError):
            models.IsolationCheck(policy=policy, kind="NOPE", ok=True, recorded_by=L.APPROVER).save()
        record = C.get_record(self.record.pk)
        with self.assertRaises(ValueError):
            record.save()
        admission = A.plan(record, actor=L.OPERATOR, expectations=EXPECT).admission
        with self.assertRaises(ValueError):
            admission.save()
        with self.assertRaises(ValueError):
            models.CommissioningDependency(device=self.device, upstream=self.device, kind="NOPE", created_by="x").save()
        event = outbox.record(self.device, models.OutboxTopic.TOPOLOGY_DEVICE_ADMITTED, OutboxClosureTests.PAYLOAD, subject="ADM-9", actor=L.APPROVER)
        event.payload = {**event.payload, "name": "OTHER"}
        with self.assertRaises(ValueError):
            event.save()

    def test_model_deletes_preserve_history(self):
        self.configured()
        policy = iso.device_policy(self.device)
        admission = A.plan(self.record, actor=L.OPERATOR, expectations=EXPECT).admission
        event = outbox.record(self.device, models.OutboxTopic.TOPOLOGY_DEVICE_ADMITTED, OutboxClosureTests.PAYLOAD, subject="ADM-9", actor=L.APPROVER)
        check = policy.checks.first()
        for row in (policy, check, self.record, admission, event):
            with self.subTest(type(row).__name__ + " preserves its row"):
                with self.assertRaises(ValueError):
                    row.delete()
                self.assertTrue(type(row).objects.filter(pk=row.pk).exists())
