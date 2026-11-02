"""V2 Phase 7 -- what retirement takes away, and what a governed restoration gives back.

A DECOMMISSIONED device used to stop being a "live" record and so fell back to the LEGACY branch of the one management resolver:
health, rotation and executors could still reach it over its inventory address with its inventory credential.  Now:

    * ``management.resolve.endpoint`` fails closed (DEVICE_RETIRED) for a name whose newest record is retired;
    * only a governed restoration reaches it, inside ``resolve.retired_device_access``, and only when it had no registered
      management paths (those were retired with it: re-enrollment);
    * its management accounts stop rotating (BLOCKED / DEVICE_DECOMMISSIONED) and are reinstated exactly on restoration.

The sessions are the REAL cEOS executor on an in-memory EOS session whose connection factory asks the resolver first, exactly as
``ceos.netmiko_connection`` does (``nsot_live.get_live_target`` -> ``resolve.endpoint``).
"""

from __future__ import annotations

from datetime import timedelta

from django.test import TestCase
from django.utils import timezone

from core import models
from core.services.credentials import policy
from core.services.decommission import service as svc
from core.services.execution.executors.base import ExecutorError
from core.services.execution.executors.ceos import CeosExecutor
from core.services.management import resolve
from core.tests.helpers import decommission as H
from core.tests.helpers import isolation as I
from core.tests.helpers import lifecycle as L
from core.tests.helpers import management as M

D, R, S = models.DecommissionState, models.RestorationState, models.DeviceLifecycleState
INVENTORY_ADDRESS = "172.20.20.11"


def resolving_factory(fake, connects):
    """CeosExecutor whose connection is refused unless the resolver answers a usable endpoint (like netmiko_connection)."""
    def connect(device):
        found = resolve.endpoint(device["name"], legacy_address=INVENTORY_ADDRESS, purpose=resolve.WRITE)
        connects.append((device["name"], found.source, [b["code"] for b in found.blockers]))
        if not found.usable:
            raise ExecutorError("NOT_CONFIGURED")
        return fake

    return lambda device: CeosExecutor(device, connection_factory=connect, reader=I._facts)  # pylint: disable=protected-access


def credential(name="R1", username="nmas-svc", **overrides):
    fields = dict(device_name=name, platform="arista_ceos", username=username, account_kind=models.AccountKind.SERVICE,
                  auth_method=models.DeviceAuthMethod.PASSWORD, secret_ref=f"runtime://device-credentials/{name.lower()}-{username}",
                  rotation_enabled=True, next_due_at=timezone.now() - timedelta(days=1), last_status=models.CredentialStatus.SUCCESS)
    fields.update(overrides)
    return models.DeviceCredential.objects.create(**fields)


class Base(TestCase):
    def setUp(self):
        self.device = L.adopt("R1", role="router").device
        self.fake = H.session()
        self.connects = []
        observer = H.FakeObserver(H.observation(active=False))
        self.runtime = H.runtime(self.fake, observer, factory=resolving_factory(self.fake, self.connects))
        self.account = credential()
        self.other = credential(name="R2")

    def decommission(self):
        record = svc.request(self.device, actor=L.OPERATOR, reason="retire").record
        self.assertTrue(svc.evaluate(record, actor=L.OPERATOR, runtime=self.runtime).ok)
        record.refresh_from_db()
        self.assertTrue(svc.approve(record, actor=L.APPROVER, confirmation=record.plan_hash).ok)
        record.refresh_from_db()
        result = svc.execute(record, actor=L.APPROVER, confirmation=record.plan_hash, runtime=self.runtime)
        self.assertTrue(result.ok, result.codes)
        record.refresh_from_db()
        return record

    def restore(self, record):
        row = svc.request_restore(record, actor=L.OPERATOR).record
        checked = svc.check_restore(row, actor=L.OPERATOR, runtime=self.runtime)
        row.refresh_from_db()
        if not checked.ok:
            return row, checked
        self.assertTrue(svc.approve_restore(row, actor=L.APPROVER, confirmation=row.plan_hash).ok)
        row.refresh_from_db()
        done = svc.execute_restore(row, actor=L.APPROVER, confirmation=row.plan_hash, runtime=self.runtime)
        row.refresh_from_db()
        return row, done


class RetirementTests(Base):
    def test_decommissioned_device_resolves_blocked_and_its_accounts_stop_rotating(self):
        record = self.decommission()
        found = resolve.endpoint("R1", legacy_address=INVENTORY_ADDRESS)
        self.assertEqual((found.source, found.address, [b["code"] for b in found.blockers]), (resolve.BLOCKED, "", ["DEVICE_RETIRED"]))
        self.assertEqual(resolve.endpoint("R1", legacy_address=INVENTORY_ADDRESS, purpose=resolve.WRITE).source, resolve.BLOCKED)
        self.account.refresh_from_db()
        self.assertEqual((self.account.rotation_enabled, self.account.last_status, self.account.last_result_code),
                         (False, models.CredentialStatus.BLOCKED, svc.CREDENTIAL_RETIRED))
        self.assertEqual([c.device_name for c in policy.due_credentials()], ["R2"])      # another device's account is untouched
        retired = {c["id"]: (c["username"], c["rotation_enabled"]) for c in record.outcome["credentials_retired"]}
        self.assertEqual(retired[self.account.pk], ("nmas-svc", True))
        self.assertNotIn(self.other.pk, retired)
        with self.assertRaises(ExecutorError):                                                  # no consumer reaches it any more
            self.runtime.executor_factory({"name": "R1", "platform": "ceos"}).connect()

    def test_restoration_reaches_the_retired_device_only_in_its_scope_and_reinstates_the_accounts(self):
        record = self.decommission()
        row, done = self.restore(record)
        self.assertTrue(done.ok, done.codes)
        self.assertEqual(row.state, R.RESTORED)
        self.assertTrue(all(source == resolve.LEGACY for _name, source, _codes in self.connects))   # every session the restoration opened
        self.account.refresh_from_db()
        self.assertEqual((self.account.rotation_enabled, self.account.last_status, self.account.last_result_code),
                         (True, models.CredentialStatus.SUCCESS, ""))
        self.assertIn({"id": self.account.pk, "reinstated": True}, row.outcome["credentials_reinstated"])
        self.assertEqual(resolve.endpoint("R1", legacy_address=INVENTORY_ADDRESS).source, resolve.LEGACY)   # the successor is live

    def test_retire_only_device_accounts_are_retired_without_any_session(self):
        fresh = L.register("NEW9", serial="SER-NEW9", mac="02:00:00:00:09:09").device
        fresh.lifecycle_state, fresh._lifecycle_write = S.ISOLATED, True   # test-only: a commissioning device, never admitted
        fresh.save()
        account = credential(name="NEW9")
        requested = svc.request(fresh, actor=L.OPERATOR, reason="never admitted")
        self.assertTrue(requested.ok, requested.codes)
        record = requested.record
        svc.evaluate(record, actor=L.OPERATOR, runtime=None)
        record.refresh_from_db()
        svc.approve(record, actor=L.APPROVER, confirmation=record.record_id)
        record.refresh_from_db()
        self.assertTrue(svc.execute(record, actor=L.APPROVER, confirmation=record.record_id, runtime=None).ok)
        account.refresh_from_db()
        self.assertEqual((account.rotation_enabled, account.last_status), (False, models.CredentialStatus.BLOCKED))
        self.assertEqual(self.connects, [])


class RetirementRefusalTests(Base):
    def test_retired_device_outside_a_restoration_scope_never_falls_back_to_the_inventory_address(self):
        self.decommission()
        with resolve.retired_device_access("R2"):                                               # a scope for another name
            self.assertEqual(resolve.endpoint("R1", legacy_address=INVENTORY_ADDRESS).source, resolve.BLOCKED)
        with resolve.retired_device_access("R1"):
            self.assertEqual(resolve.endpoint("R1", legacy_address=INVENTORY_ADDRESS).address, INVENTORY_ADDRESS)
        self.assertEqual(resolve.endpoint("R1", legacy_address=INVENTORY_ADDRESS).source, resolve.BLOCKED)    # scope ended

    def test_retired_device_access_returns_the_legacy_address_inside_the_restoration_scope(self):
        self.decommission()
        with resolve.retired_device_access("R1"):
            found = resolve.endpoint("R1", legacy_address=INVENTORY_ADDRESS)
            with resolve.retired_device_access("R1"):                                            # nested scopes are allowed
                self.assertEqual(resolve.endpoint("R1", legacy_address=INVENTORY_ADDRESS).source, resolve.LEGACY)
        self.assertEqual((found.source, found.address, found.blockers), (resolve.LEGACY, INVENTORY_ADDRESS, ()))

    def test_retired_device_with_registered_paths_requires_reenrollment_and_is_never_contacted(self):
        env = M.lab()
        r1 = env["devices"]["R1"]
        M.path(r1, env["nmas"], attachment=env["oob"], endpoint="192.168.200.1")
        self.device, self.fake, self.connects = r1, H.session(), []
        self.runtime = H.runtime(self.fake, H.FakeObserver(H.observation(active=False)), factory=lambda d: CeosExecutor(
            d, connection_factory=lambda _d: self.fake, reader=I._facts))   # pylint: disable=protected-access
        record = self.decommission()
        self.runtime = H.runtime(self.fake, H.FakeObserver(H.observation(active=False)), factory=resolving_factory(self.fake, self.connects))
        row, checked = self.restore(record)
        self.assertEqual((row.state, checked.codes), (R.REENROLLMENT_REQUIRED, ["RESTORATION_REENROLLMENT_REQUIRED"]))
        self.assertEqual(self.connects, [])
        with resolve.retired_device_access("R1"):
            self.assertEqual([b["code"] for b in resolve.endpoint("R1").blockers], ["MGMT_NO_USABLE_PATH"])

    def test_reinstatement_never_overrides_an_account_changed_after_retirement(self):
        record = self.decommission()
        models.DeviceCredential.objects.filter(pk=self.account.pk).update(last_status=models.CredentialStatus.FAILED, last_result_code="ROTATED_BY_HAND")
        row, done = self.restore(record)
        self.assertTrue(done.ok, done.codes)
        self.account.refresh_from_db()
        self.assertEqual((self.account.rotation_enabled, self.account.last_status), (False, models.CredentialStatus.FAILED))
        self.assertIn({"id": self.account.pk, "reinstated": False}, row.outcome["credentials_reinstated"])
