"""Test-governance closure for the V2 Phases 5 / 6 branches added to existing provisioning / ZTP functions: the ZTP_MANAGEMENT
bootstrap transport (``bootstrap.target_blockers`` / ``classify``), the commissioning gates of the provisioning lifecycle
(``define_identity``, ``approve``, ``config_digest``, ``execution_blockers``, ``before_first_mutation``, ``sync_nsot``) and the
trusted-isolation prerequisite of ``ztp.dependencies.evaluate``.  Each function is called directly, accepting and refusing."""

from __future__ import annotations

import hashlib
from types import SimpleNamespace
from unittest import mock

from django.utils import timezone

from core import models
from core.services import provisioning_service as ps
from core.services.commissioning import service as C
from core.services.commissioning import transport
from core.services.isolation import service as iso
from core.services.provisioning import bootstrap, commissioning_gate, lifecycle
from core.services.ztp import dependencies
from core.tests.helpers import isolation as I
from core.tests.helpers import lifecycle as L
from core.tests.test_commissioning import Base

ZTP = models.BootstrapTransport.ZTP_MANAGEMENT
St = models.CommissioningState


def codes(blockers):
    return [b["code"] for b in blockers]


class BootstrapTransportTests(Base):
    def target(self):
        return {"device": self.device.device_id}

    def run_for(self, target):
        return SimpleNamespace(platform=self.device.platform, bootstrap_transport=ZTP, bootstrap_target=target,
                               management={"interface": "Management0"})

    def test_target_blockers_accepts_the_onboarded_ceos_device(self):
        self.ready()
        self.assertEqual(bootstrap.target_blockers(self.device.platform, ZTP, self.target()), [])

    def test_target_blockers_refuses_a_malformed_unknown_or_legacy_device(self):
        self.ready()
        legacy = models.ManagedDevice.objects.exclude(origin=models.DeviceOrigin.REGISTERED_NEW).first()
        targets = [{"device": "nope"}, {"device": "DEV-999999"}, {}, {"container": "clab-x-NEW1", "lab": "x"}]
        if legacy is not None:
            targets.append({"device": legacy.device_id})
        for target in targets:
            with self.subTest(str(target)):
                self.assertEqual(codes(bootstrap.target_blockers(self.device.platform, ZTP, target)), ["BOOTSTRAP_TARGET_INVALID"])
        self.assertEqual(codes(bootstrap.target_blockers(models.Platform.UBUNTU_FRR, ZTP, self.target())), ["BOOTSTRAP_TRANSPORT_UNSUPPORTED"])

    def test_classify_returns_reachable_bootstrap_through_the_commissioning_prober(self):
        self.ready()
        seen = []

        def prober(target):
            seen.append(target)
            return bootstrap.Probe(exists=True, running=True, answers=True)

        with mock.patch.object(transport, "prober", prober):            # the default prober of ZTP_MANAGEMENT
            state, evidence, blockers = bootstrap.classify(self.run_for(self.target()))
        self.assertEqual((state, blockers, evidence["answers"]), (models.BootstrapState.REACHABLE_BOOTSTRAP, [], True))
        self.assertEqual(seen, [{**self.target(), "management_interface": "Management0"}])

    def test_classify_refuses_an_invalid_target_and_never_treats_a_silent_device_as_reachable(self):
        self.ready()
        self.assertEqual(bootstrap.classify(self.run_for({"device": "DEV-999999"}))[0::2],
                         (models.BootstrapState.UNKNOWN, [bootstrap.blocker("BOOTSTRAP_TARGET_INVALID")]))
        silent = bootstrap.classify(self.run_for(self.target()), prober=lambda target: bootstrap.Probe(exists=True, error="X"))
        self.assertEqual((silent[0], silent[2]), (models.BootstrapState.UNREACHABLE, []))
        configured = bootstrap.classify(self.run_for(self.target()),
                                        prober=lambda target: bootstrap.Probe(exists=True, answers=True, configured=True))
        self.assertEqual(configured[0], models.BootstrapState.ALREADY_CONFIGURED)


class LifecycleBranchTests(Base):
    def new_run(self, name=None):
        request = ps.create_request(device_name=name or self.device.name, platform=self.device.platform, role=self.device.role,
                                    requested_by=L.OPERATOR)
        self.assertTrue(request.ok, request.codes)
        return request.run

    def identify(self, run):
        return ps.define_identity(run, actor=L.OPERATOR, bootstrap_transport=ZTP, bootstrap_target={"device": self.device.device_id},
                                  management=C.management_of(self.device, iso.device_policy(self.device)))

    def test_define_identity_accepts_the_device_the_run_is_named_after(self):
        self.ready()
        run = self.new_run()
        result = lifecycle.define_identity(run, actor=L.OPERATOR, bootstrap_transport=ZTP,
                                           bootstrap_target={"device": self.device.device_id, "ignored": "x"},
                                           management=C.management_of(self.device, iso.device_policy(self.device)))
        self.assertTrue(result.ok, result.codes)
        run.refresh_from_db()
        self.assertEqual((run.bootstrap_transport, run.bootstrap_target), (ZTP, {"device": self.device.device_id}))

    def test_define_identity_refuses_another_devices_session(self):
        self.ready()
        run = self.new_run(name="OTHER9")
        result = lifecycle.define_identity(run, actor=L.OPERATOR, bootstrap_transport=ZTP, bootstrap_target={"device": self.device.device_id},
                                           management={"interface": "Management0"})
        self.assertFalse(result.ok)
        self.assertIn("BOOTSTRAP_TARGET_INVALID", result.codes)

    def test_approve_accepts_the_commissioning_approver_of_a_ready_record(self):
        self.assessed()
        run = self.record.provisioning_run
        C._save(self.record, state=St.APPROVED, approved_by=L.APPROVER, approved_at=timezone.now())
        result = lifecycle.approve(run, actor=L.APPROVER, confirm_candidate_hash=run.candidate_hash)
        self.assertTrue(result.ok, result.codes)
        run.refresh_from_db()
        self.assertEqual(run.status, models.ProvisioningStatus.APPROVED)

    def test_approve_refuses_the_requester_and_an_approver_the_commissioning_did_not_name(self):
        self.assessed()
        run = self.record.provisioning_run
        self.assertIn("APPROVAL_SELF", lifecycle.approve(run, actor=run.requested_by, confirm_candidate_hash=run.candidate_hash).codes)
        self.assertIn("COMMISSIONING_NOT_APPROVED", lifecycle.approve(run, actor=L.APPROVER, confirm_candidate_hash=run.candidate_hash).codes)

    def test_config_digest_returns_the_commissioning_read_of_a_ceos_device(self):
        self.approved()
        run = self.record.provisioning_run
        self.assertEqual(lifecycle.registry.devices()[run.device_name]["platform"], "ceos")
        with mock.patch.object(lifecycle, "CONFIG_READER", None), \
                mock.patch.object(commissioning_gate, "config_reader", lambda device: "hostname NEW1\n"):
            self.assertEqual(lifecycle.config_digest(run), hashlib.sha256(b"hostname NEW1\n").hexdigest())

    def test_config_digest_refuses_an_unreadable_or_empty_ceos_read(self):
        self.approved()
        run = self.record.provisioning_run

        def unreadable(device):
            raise OSError("closed")

        for reader in (unreadable, lambda device: ""):
            with mock.patch.object(lifecycle, "CONFIG_READER", None), mock.patch.object(commissioning_gate, "config_reader", reader):
                self.assertEqual(lifecycle.config_digest(run), "")

    def test_execution_blockers_accepts_an_approved_commissioning_run(self):
        self.approved()
        self.assertEqual(lifecycle.execution_blockers(self.record.provisioning_run.change), [])

    def test_execution_blockers_refuses_a_commissioning_record_that_is_not_approved(self):
        self.approved()
        models.CommissioningRecord.objects.filter(pk=self.record.pk).update(state=St.READY)
        self.assertEqual(codes(lifecycle.execution_blockers(self.record.provisioning_run.change)), ["COMMISSIONING_NOT_APPROVED"])

    def test_before_first_mutation_accepts_and_marks_the_record_configuring(self):
        self.approved()
        run = self.record.provisioning_run
        with mock.patch.object(lifecycle, "CONFIG_READER", lambda device: "hostname NEW1\n"):
            self.assertEqual(lifecycle.before_first_mutation(run.change), [])
        run.refresh_from_db()
        self.assertEqual((run.status, run.pre_config_digest), (models.ProvisioningStatus.PROVISIONING, hashlib.sha256(b"hostname NEW1\n").hexdigest()))
        self.assertEqual(C.get_record(self.record.pk).state, St.CONFIGURING)

    def test_before_first_mutation_refuses_an_unapproved_commissioning_and_writes_nothing(self):
        self.approved()
        run = self.record.provisioning_run
        models.CommissioningRecord.objects.filter(pk=self.record.pk).update(state=St.READY)
        with mock.patch.object(lifecycle, "CONFIG_READER", lambda device: "hostname NEW1\n"):
            self.assertEqual(codes(lifecycle.before_first_mutation(run.change)), ["COMMISSIONING_NOT_APPROVED"])
        run.refresh_from_db()
        self.assertEqual((run.status, run.pre_config_digest), (models.ProvisioningStatus.APPROVED, ""))
        self.assertEqual(C.get_record(self.record.pk).state, St.READY)

    def test_sync_nsot_refuses_a_commissioned_device_that_is_not_admitted(self):
        self.configured()
        before = list(self.lab.gateway.calls)                            # the IPAM reservation of earlier stages
        result = lifecycle.sync_nsot(self.record.provisioning_run, actor=L.APPROVER, gateway=self.lab.gateway)
        self.assertFalse(result.ok)
        self.assertEqual(result.codes, ["COMMISSIONING_NOT_ADMITTED"])
        self.assertEqual(self.lab.gateway.calls, before)                 # nothing was written to NetBox


class DependencyIsolationTests(Base):
    def checks(self, flow):
        return {c["check"]: c for c in dependencies.evaluate(flow.device, flow.attachment, flow.network)}

    def test_evaluate_accepts_trusted_isolation_once_enforced_and_verified(self):
        flow = I.Flow(self)
        flow.verified()
        found = self.checks(flow)["trusted_isolation"]
        self.assertEqual((found["ok"], found["code"]), (True, ""))

    def test_evaluate_refuses_the_bootstrap_path_without_enforced_isolation(self):
        flow = I.Flow(self)
        found = self.checks(flow)["trusted_isolation"]
        self.assertFalse(found["ok"])
        self.assertTrue(found["code"])
        flow.approved()                                                  # approved but not applied: still not in force
        self.assertFalse(self.checks(flow)["trusted_isolation"]["ok"])
