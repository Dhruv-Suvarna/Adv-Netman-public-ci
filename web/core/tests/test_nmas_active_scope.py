"""PR #68 follow-up: an NMAS-admitted, NetBox-synchronized device joins the managed scope of ordinary Changes.

NetBox's ``managed`` tag never lists a natively provisioned device (provisioning does not write it), so NMAS proves the device's
membership itself (``registry.active_managed``) and carries that proof through the three integration points:

* Tier-2 network validation records it as ``MANAGED_SCOPE`` evidence ``nmas_active`` (``network_config_validation``);
* the Configuration Validation bundle passes it on as ``scope.nmas_active`` (``configuration_validation.service._scope_facts``),
  which the CI check accepts for EXISTING_DEVICE intents of a PASS scope (``configuration_validation.checks.intent_checks``);
* the execution gate admits it (``execution.eligibility._scope_blockers``).

POSITIVE: a device that went through the real commissioning flow (ZTP, isolation, provisioning, admission, NSOT sync) qualifies at
every point.  NEGATIVE: an inactive (still provisioning, not in service, not admitted), unsynchronized, missing or stale (retired
row, older commissioning run, NetBox identity of another object) device never qualifies, and a NEW_DEVICE intent, a non-PASS scope
and an out-of-scope device stay outside.
"""

from __future__ import annotations

import copy
from contextlib import contextmanager, nullcontext
from types import SimpleNamespace

from django.utils import timezone

from core import models
from core.services import network_config_validation as ncv
from core.services.commissioning import admission as A
from core.services.configuration_validation import checks
from core.services.configuration_validation import service as cv_service
from core.services.execution import eligibility as el
from core.services.execution.scope import resolve_scope
from core.services import provisioning_service as ps
from core.services.provisioning import ipam, registry
from core.services.soak import codes as soak_codes
from core.services.validation import sources
from core.tests import test_commissioning as tc
from core.tests import test_configuration_validation as cvt
from core.tests.helpers import execution as ex
from core.tests.helpers import isolation as I
from core.tests.helpers import lifecycle as L
from core.tests.helpers.validation import Dev, make_sources, netbox_data, new_change, simple_pass_change, validate
from core.tests.test_tg_provisioning_closure import DOC, FakeNetbox

EXISTING, NEW = models.DeviceIntentTargetType.EXISTING_DEVICE, models.DeviceIntentTargetType.NEW_DEVICE
FROZEN_MANAGED = ["R1", "R2", "R3", "R4", "S1", "S2", "S3", "S4"]


@contextmanager
def changed(model, pk, **fields):
    """Temporarily overwrite columns of one row, then put them back.  A ManagedDevice is written through its own
    compare-and-swap (the lifecycle service's writer), every other model through a queryset update."""
    def write(values):
        if model is models.ManagedDevice:
            version = model.objects.filter(pk=pk).values_list("version", flat=True).get()
            assert model.objects.compare_and_swap(pk, version, **values) == 1
        else:
            model.objects.filter(pk=pk).update(**values)

    original = model.objects.filter(pk=pk).values(*fields).get()
    write(fields)
    try:
        yield
    finally:
        write(original)


def _bundle(data, status="available") -> sources.SourceBundle:
    other = [sources.SourceResult(name, "available", {}) for name in ("TOPOLOGY", "INVENTORY", "CAPABILITY")]
    return sources.SourceBundle(sources.SourceResult("NETBOX", status, data, "" if status == "available" else "down"), *other,
                                repository_head="0" * 40)


class AdmittedDevice(tc.Base):
    """A device admitted through the real Phase 3-6 services, with its registry row, run and commissioning record at hand."""

    def setUp(self):
        super().setUp()
        self.admission_approved()
        I.admitted_outputs(self.flow.session)
        result = A.execute(self.admission, actor=L.APPROVER, access=self.flow.access, gateway=self.lab.gateway)
        self.assertTrue(result.ok, result.codes)
        self.name = self.device.name
        self.row = models.ProvisionedDevice.objects.get(name=self.name, state=models.ProvisionedDeviceState.ACTIVE)
        self.run = self.row.run
        self.record = models.CommissioningRecord.objects.get(device=self.device, state=models.CommissioningState.ADMITTED)

    def snapshot(self, target_type=EXISTING):
        return {"devices": [{"device_name": "R1", "target_type": EXISTING}, {"device_name": self.name, "target_type": target_type}]}

    def with_identity(self, **identity):
        result = copy.deepcopy(self.run.result)
        result["netbox_identity"].update(identity)
        return changed(models.ProvisioningRun, self.run.pk, result=result)


class ActiveManagedTests(AdmittedDevice):
    def test_admitted_synchronized_device_is_active_managed(self):
        self.assertEqual((self.run.status, self.row.netbox_device_id, self.run.result["netbox_identity"]["managed_scope"]),
                         (models.ProvisioningStatus.NSOT_SYNCED, self.run.result["netbox_identity"]["device_id"], True))
        self.assertTrue(registry.active_managed(self.name))

    def test_missing_device_names_are_not_active_managed(self):
        for name in ("R1", "NOSUCHDEVICE", ""):
            with self.subTest(name=name):
                self.assertFalse(registry.active_managed(name))

    def test_inactive_device_is_not_active_managed(self):
        cases = {
            "registry row still ADMITTED (provisioning)": (models.ProvisionedDevice, self.row.pk, {"state": models.ProvisionedDeviceState.ADMITTED}),
            "device not in service": (models.ManagedDevice, self.device.pk, {"lifecycle_state": models.DeviceLifecycleState.FAILED}),
            "device not admitted": (models.ManagedDevice, self.device.pk, {"admission_state": models.ProductionAdmissionState.NOT_ADMITTED}),
            "device decommissioned": (models.ManagedDevice, self.device.pk, {"lifecycle_state": models.DeviceLifecycleState.DECOMMISSIONED}),
        }
        for label, (model, pk, fields) in cases.items():
            with self.subTest(case=label), changed(model, pk, **fields):
                self.assertFalse(registry.active_managed(self.name))
        self.assertTrue(registry.active_managed(self.name))                     # every case was put back

    def test_unsynchronized_run_is_not_active_managed(self):
        for status in (models.ProvisioningStatus.POSTCHECKED, models.ProvisioningStatus.FAILED, models.ProvisioningStatus.DECOMMISSIONED):
            with self.subTest(status=status), changed(models.ProvisioningRun, self.run.pk, status=status):
                self.assertFalse(registry.active_managed(self.name))
        without = {k: v for k, v in self.run.result.items() if k != "netbox_identity"}
        with self.subTest(case="no NetBox identity recorded"), changed(models.ProvisioningRun, self.run.pk, result=without):
            self.assertFalse(registry.active_managed(self.name))
        for identity in ({"managed_scope": False}, {"managed_scope": "true"}, {"status": "planned"}):
            with self.subTest(identity=identity), self.with_identity(**identity):
                self.assertFalse(registry.active_managed(self.name))
        with self.subTest(case="disposable"), changed(models.ProvisionedDevice, self.row.pk, disposable=True):
            self.assertFalse(registry.active_managed(self.name))

    def test_stale_identity_or_binding_is_not_active_managed(self):
        other = self.row.netbox_device_id + 1000
        with self.subTest(case="retired registry row"), changed(models.ProvisionedDevice, self.row.pk, state=models.ProvisionedDeviceState.RETIRED):
            self.assertFalse(registry.active_managed(self.name))
        with self.subTest(case="identity of another NetBox object"), self.with_identity(device_id=other):
            self.assertFalse(registry.active_managed(self.name))
        with self.subTest(case="identity of another device name"), self.with_identity(name="R1"):
            self.assertFalse(registry.active_managed(self.name))
        with self.subTest(case="device bound to another NetBox object"), changed(models.ManagedDevice, self.device.pk, netbox_device_id=other):
            self.assertFalse(registry.active_managed(self.name))
        with self.subTest(case="registry row without a NetBox id (None == None must not match)"), \
                changed(models.ProvisionedDevice, self.row.pk, netbox_device_id=None), self.with_identity(device_id=None):
            self.assertFalse(registry.active_managed(self.name))
        with self.subTest(case="commissioning record aborted"), changed(models.CommissioningRecord, self.record.pk, state=models.CommissioningState.ABORTED):
            self.assertFalse(registry.active_managed(self.name))
        with self.subTest(case="commissioning record of no / another run"), changed(models.CommissioningRecord, self.record.pk, provisioning_run_id=None):
            self.assertFalse(registry.active_managed(self.name))

    def test_device_with_matching_netbox_reference_is_active_managed(self):
        with changed(models.ManagedDevice, self.device.pk, netbox_device_id=self.row.netbox_device_id):
            self.assertTrue(registry.active_managed(self.name))


class ManagedScopeEvidenceTests(AdmittedDevice):
    def test_admitted_device_passes_managed_scope_as_nmas_active(self):
        (check,) = ncv._managed_scope_checks(self.snapshot(), _bundle({"managed_devices": FROZEN_MANAGED}))
        self.assertEqual((check["status"], check["message"], check["evidence"]),
                         ("PASS", "All targets are managed or admitted to production by NMAS.", {"outside_scope": [], "nmas_active": [self.name]}))

    def test_netbox_managed_active_device_stays_nmas_active(self):
        # Lab 8 R6/R7: once NSOT sync put the device in NetBox's managed scope, it vanished from ``nmas_active`` and the CI check
        # (which reads the repository inventory, never listing a native device) refused every later Change on it.
        (check,) = ncv._managed_scope_checks(self.snapshot(), _bundle({"managed_devices": [*FROZEN_MANAGED, self.name]}))
        self.assertEqual((check["status"], check["message"], check["evidence"]),
                         ("PASS", "All targets are managed or admitted to production by NMAS.", {"outside_scope": [], "nmas_active": [self.name]}))

    def test_netbox_managed_frozen_targets_record_no_nmas_active(self):
        snapshot = self.snapshot()
        snapshot["devices"] = [{**snapshot["devices"][0], "device_name": "R1"}]
        (check,) = ncv._managed_scope_checks(snapshot, _bundle({"managed_devices": FROZEN_MANAGED}))
        self.assertEqual((check["status"], check["message"], check["evidence"]), ("PASS", "All targets are managed.", {"outside_scope": []}))

    def test_new_device_intent_of_an_active_device_blocks_managed_scope(self):
        (check,) = ncv._managed_scope_checks(self.snapshot(NEW), _bundle({"managed_devices": FROZEN_MANAGED}))
        self.assertEqual((check["status"], check["evidence"]), ("BLOCKED", {"outside_scope": [self.name]}))

    def test_stale_device_blocks_managed_scope(self):
        with changed(models.ProvisionedDevice, self.row.pk, state=models.ProvisionedDeviceState.RETIRED):
            (check,) = ncv._managed_scope_checks(self.snapshot(), _bundle({"managed_devices": FROZEN_MANAGED}))
        self.assertEqual((check["status"], check["evidence"]), ("BLOCKED", {"outside_scope": [self.name]}))

    def test_unavailable_netbox_blocks_even_an_active_device(self):
        (check,) = ncv._managed_scope_checks(self.snapshot(), _bundle(None, status="unavailable"))
        self.assertEqual((check["status"], check["message"]), ("BLOCKED", "Authoritative managed scope is unavailable."))


class _Runs:
    def __init__(self, run):
        self.run = run

    def filter(self, **_):
        return self

    def order_by(self, *_):
        return self

    def first(self):
        return self.run


def _change_with(checks_):
    run = None if checks_ is None else SimpleNamespace(checks=checks_)
    return SimpleNamespace(network_config_validation_runs=_Runs(run))


class ScopeFactsTests(AdmittedDevice):
    def test_scope_facts_carry_recorded_nmas_active(self):
        recorded = ncv._managed_scope_checks(self.snapshot(), _bundle({"managed_devices": FROZEN_MANAGED}))
        self.assertEqual(cv_service._scope_facts(_change_with(recorded), "h"),
                         {"check": "PASS", "outside_scope": [], "provisioning": [], "nmas_active": [self.name]})

    def test_scope_facts_without_a_recorded_run_have_no_nmas_active(self):
        self.assertEqual(cv_service._scope_facts(_change_with(None), "h"),
                         {"check": "NOT_RECORDED", "outside_scope": [], "provisioning": [], "nmas_active": []})
        legacy = [{"check": "MANAGED_SCOPE", "status": "PASS", "evidence": {"outside_scope": []}}]   # recorded before this field existed
        self.assertEqual(cv_service._scope_facts(_change_with(legacy), "h")["nmas_active"], [])


class ExecutionGateTests(AdmittedDevice):
    def gate(self, target_type=EXISTING):
        change = new_change("ordinary change to the admitted device")
        dev = Dev(change, self.name, target_type=target_type)
        dev.address(dev.iface("loopback30", kind="LOOPBACK"), "198.51.100.30/32")
        fixture = SimpleNamespace(change=change, sources=make_sources(netbox=netbox_data(managed_devices=FROZEN_MANAGED)))
        prepared = ex.prepared(fixture, require_permit=False)
        self.assertIsNotNone(prepared.plan)
        scope, problems = resolve_scope(prepared.plan, prepared.change.execution_mode)
        self.assertEqual((problems, scope.devices), ([], [self.name]))
        report = el.EligibilityReport(change=prepared.change, mode=prepared.change.execution_mode)
        el._scope_blockers(report, scope, prepared.plan, sources=prepared.sources)
        return {b["code"] for b in report.blockers}

    def test_admitted_device_is_inside_the_execution_scope(self):
        self.assertNotIn("TARGET_DEVICE_OUTSIDE_MANAGED_SCOPE", self.gate())

    def test_device_not_admitted_blocks_execution_scope(self):
        with changed(models.ManagedDevice, self.device.pk, admission_state=models.ProductionAdmissionState.NOT_ADMITTED):
            self.assertIn("TARGET_DEVICE_OUTSIDE_MANAGED_SCOPE", self.gate())

    def test_unsynchronized_run_blocks_execution_scope(self):
        with changed(models.ProvisioningRun, self.run.pk, status=models.ProvisioningStatus.POSTCHECKED):
            self.assertIn("TARGET_DEVICE_OUTSIDE_MANAGED_SCOPE", self.gate())


@cvt.ENABLED
class BundleScopeCheckTests(cvt.Base):
    """The CI side (``checks.intent_checks``, merged in PR #68 without a test) reads what ``_scope_facts`` produced."""

    NAME = "NEW7"

    def setUp(self):
        super().setUp()
        f = simple_pass_change()
        validate(f.change, f.sources)
        self.good, _payload = self.bundle()

    def bundle_for(self, *, check="PASS", nmas_active=(NAME,), target_type=EXISTING, name=NAME):
        bundle = copy.deepcopy(self.good)
        bundle["devices"][1]["device"] = name
        for device in bundle["intent"]["devices"]:
            if device["device_name"] == "R2":
                device.update(device_name=name, target_type=target_type)
        bundle["scope"] = {"check": check, "outside_scope": [], "provisioning": [], "nmas_active": list(nmas_active)}
        return bundle

    def scope_status(self, bundle):
        category = checks.intent_checks(bundle, repo_root=cvt.ROOT)
        return {c["name"]: c["status"] for c in category.checks}["every target is inside the managed scope"]

    def test_nmas_active_existing_target_is_inside_the_bundle_scope(self):
        self.assertEqual(self.scope_status(self.bundle_for()), checks.PASS)

    def test_bundle_scope_check_fails_when_target_is_not_nmas_active(self):
        cases = {"not listed": {"nmas_active": ()}, "scope not PASS": {"check": "BLOCKED"}, "scope not recorded": {"check": "NOT_RECORDED"},
                 "NEW_DEVICE intent": {"target_type": NEW}, "out-of-scope device": {"name": "R5", "nmas_active": ("R5",)}}
        for label, overrides in cases.items():
            with self.subTest(case=label):
                self.assertEqual(self.scope_status(self.bundle_for(**overrides)), checks.FAIL)


class _NoScopeGateway:
    """A NetBox gateway that activates the objects but cannot confirm the managed scope (e.g. ``iac_managed`` missing)."""

    def __init__(self, inner):
        self.inner = inner

    def __getattr__(self, name):
        return getattr(self.inner, name)

    def activate(self, created, *, managed):
        self.inner.activate(created, managed=managed)
        return {"managed_scope": False}


class StaleSynchronizationTests(AdmittedDevice):
    """Admission whose NSOT synchronization could not prove the NetBox managed scope: the device never joins the scope."""

    def setUp(self):
        tc.Base.setUp(self)
        self.admission_approved()
        I.admitted_outputs(self.flow.session)
        self.lab.gateway = _NoScopeGateway(self.lab.gateway)
        self.result = A.execute(self.admission, actor=L.APPROVER, access=self.flow.access, gateway=self.lab.gateway)
        self.name = self.device.name

    def test_unconfirmed_netbox_scope_leaves_the_device_not_active_managed(self):
        run = models.ProvisioningRun.objects.get(pk=models.CommissioningRecord.objects.get(device=self.device).provisioning_run_id)
        self.assertNotEqual(run.status, models.ProvisioningStatus.NSOT_SYNCED)
        self.assertNotIn("netbox_identity", run.result or {})
        self.assertEqual(registry.managed_scope_refusal(self.name), "NOT_ACTIVE_PROVISIONED")
        (check,) = ncv._managed_scope_checks(self.snapshot(), _bundle({"managed_devices": FROZEN_MANAGED}))
        self.assertEqual((check["status"], check["evidence"]), ("BLOCKED", {"outside_scope": [self.name]}))


class RefusalReasonTests(AdmittedDevice):
    def test_admitted_device_qualifies_for_the_managed_scope(self):
        self.assertEqual(registry.managed_scope_refusal(self.name), "")

    def test_each_broken_link_blocks_with_its_refusal_reason(self):
        other = self.row.netbox_device_id + 1000
        cases = [
            ("NOT_ACTIVE_PROVISIONED", changed(models.ProvisionedDevice, self.row.pk, state=models.ProvisionedDeviceState.RETIRED)),
            ("DISPOSABLE", changed(models.ProvisionedDevice, self.row.pk, disposable=True)),
            ("NETBOX_ID_MISSING", changed(models.ProvisionedDevice, self.row.pk, netbox_device_id=None)),
            ("NOT_SYNCHRONIZED", changed(models.ProvisioningRun, self.run.pk, status=models.ProvisioningStatus.POSTCHECKED)),
            ("NETBOX_IDENTITY_MISMATCH", self.with_identity(device_id=other)),
            ("MANAGED_SCOPE_MISSING", self.with_identity(managed_scope=False)),
            ("DEVICE_NOT_ADMITTED", changed(models.ManagedDevice, self.device.pk, admission_state=models.ProductionAdmissionState.WITHDRAWN)),
            ("IDENTITY_NOT_VERIFIED", changed(models.ManagedDevice, self.device.pk, identity_state=models.IdentityVerificationState.MISMATCH)),
            ("IDENTITY_NOT_VERIFIED", changed(models.ManagedDevice, self.device.pk, verified_host_key="")),
            ("CONFIGURATION_DRIFT", changed(models.ManagedDevice, self.device.pk, compliance_state=models.ComplianceState.DRIFT)),
            ("NETBOX_IDENTITY_MISMATCH", changed(models.ManagedDevice, self.device.pk, netbox_device_id=other)),
            ("COMMISSIONING_NOT_BOUND", changed(models.CommissioningRecord, self.record.pk, state=models.CommissioningState.UNCERTAIN)),
        ]
        for code, context in cases:
            with self.subTest(code=code), context:
                self.assertEqual(registry.managed_scope_refusal(self.name), code)
                self.assertFalse(registry.active_managed(self.name))
        self.assertEqual(registry.managed_scope_refusal(self.name), "")


class ProbationTests(AdmittedDevice):
    """The run's authorized post-commissioning probation: the normal 7-day soak over its Probation bundle."""

    def setUp(self):
        super().setUp()
        result = ps.start_probation(self.run, actor=L.APPROVER)
        self.assertTrue(result.ok, result.codes)
        self.run.refresh_from_db()
        self.soak = self.run.soak_run

    def new_soak(self, bundle_id):
        """A new RUNNING soak over ``bundle_id`` with the original window's pinned facts (a retry is a NEW run)."""
        pinned = {name: getattr(self.soak, name) for name in models.ProbationSoakRun._IMMUTABLE if name != "created_at"}
        return models.ProbationSoakRun.objects.create(**{**pinned, "bundle_id": bundle_id, "state": models.SoakState.RUNNING})

    def soak_ended(self, state, reason="", result=""):
        """End the run's soak through the model's own RUNNING -> finished transition; a finished one is followed by a new run."""
        soak = models.ProbationSoakRun.objects.get(pk=models.ProvisioningRun.objects.get(pk=self.run.pk).soak_run_id)
        if soak.state != models.SoakState.RUNNING:
            soak = self.new_soak(self.run.probation_bundle_id)
            models.ProvisioningRun.objects.filter(pk=self.run.pk).update(soak_run_id=soak.pk)
        soak.state, soak.terminal_reason, soak.result, soak.finished_at = state, reason, result, timezone.now()
        soak.save()
        return nullcontext()

    def test_device_in_running_probation_is_active_managed(self):
        self.assertEqual((self.run.status, self.soak.state, self.soak.bundle_id), (models.ProvisioningStatus.PROBATION, models.SoakState.RUNNING,
                                                                                 self.run.probation_bundle_id))
        self.assertEqual(registry.managed_scope_refusal(self.name), "")
        (check,) = ncv._managed_scope_checks(self.snapshot(), _bundle({"managed_devices": FROZEN_MANAGED}))
        self.assertEqual(check["evidence"], {"outside_scope": [], "nmas_active": [self.name]})

    def test_probation_ending_without_golden_keeps_the_device_managed(self):
        for state, reason, result in ((models.SoakState.COMPLETED, "", models.SoakResult.PASS),
                                      (models.SoakState.COMPLETED, "", models.SoakResult.FAIL),
                                      (models.SoakState.COMPLETED, "", models.SoakResult.INCOMPLETE),
                                      (models.SoakState.INVALIDATED, soak_codes.OVERLAPPING_EXECUTION, ""),
                                      (models.SoakState.CANCELLED, soak_codes.CANCELLED_BY_OPERATOR, "")):
            with self.subTest(state=state, reason=reason, result=result), self.soak_ended(state, reason, result):
                self.assertEqual(registry.managed_scope_refusal(self.name), "")

    def test_probation_with_integrity_failure_or_drift_is_not_active_managed(self):
        for reason in (soak_codes.BUNDLE_INTEGRITY_FAILED, soak_codes.CONFIGURATION_DRIFT):
            with self.subTest(reason=reason), self.soak_ended(models.SoakState.INVALIDATED, reason):
                self.assertEqual(registry.managed_scope_refusal(self.name), "PROBATION_UNTRUSTED")

    def test_probation_not_bound_to_its_soak_is_not_active_managed(self):
        other = self.new_soak(self.run.probation_bundle.parent_id)        # a soak over the root (Deployed) bundle, not this probation
        for label, context in (("no soak", changed(models.ProvisioningRun, self.run.pk, soak_run_id=None)),
                               ("no probation bundle", changed(models.ProvisioningRun, self.run.pk, probation_bundle_id=None)),
                               ("soak of another bundle", changed(models.ProvisioningRun, self.run.pk, soak_run_id=other.pk))):
            with self.subTest(case=label), context:
                self.assertEqual(registry.managed_scope_refusal(self.name), "PROBATION_UNBOUND")

    def test_probation_never_weakens_identity_admission_or_synchronization(self):
        for code, context in (("IDENTITY_NOT_VERIFIED", changed(models.ManagedDevice, self.device.pk,
                                                                 identity_state=models.IdentityVerificationState.MISMATCH)),
                              ("DEVICE_NOT_ADMITTED", changed(models.ManagedDevice, self.device.pk,
                                                              lifecycle_state=models.DeviceLifecycleState.DECOMMISSION_PENDING)),
                              ("COMMISSIONING_NOT_BOUND", changed(models.CommissioningRecord, self.record.pk, state=models.CommissioningState.ABORTED)),
                              ("MANAGED_SCOPE_MISSING", self.with_identity(managed_scope=False)),
                              ("NOT_ACTIVE_PROVISIONED", changed(models.ProvisionedDevice, self.row.pk, state=models.ProvisionedDeviceState.ADMITTED))):
            with self.subTest(code=code), context:
                self.assertEqual(registry.managed_scope_refusal(self.name), code)


def _scoped_netbox(*, tags=("csci5840-iac", "managed", "unmanaged")):
    netbox = FakeNetbox()
    for slug in tags:
        netbox.extras.tags._add(name=slug, slug=slug)
    return netbox, ipam.NetboxGateway(client=netbox)


def _tag_slugs(netbox, device):
    by_id = {tag.id: tag.slug for tag in netbox.extras.tags.store.values()}
    return sorted(by_id[ref["id"] if isinstance(ref, dict) else ref.id] for ref in netbox.dcim.devices.store[device].tags)


class NetboxActivationTests(cvt.Base):
    """``NetboxGateway.activate`` against an in-memory pynetbox-shaped client (no NetBox is contacted)."""

    def reserved(self, gw):
        provenance = {"prov_id": "PROV-000042", "requested_by": "requester"}
        device = gw.create_device(DOC["device"], tags=[ipam.PROVISIONING_TAG], provenance=provenance)
        address = gw.create_address(DOC["addresses"][0], gw.create_interface(device, DOC["interfaces"][0], tags=[ipam.PROVISIONING_TAG]),
                                    tags=[ipam.PROVISIONING_TAG], provenance=provenance)
        return device, [{"kind": "device", "id": device}, {"kind": "ip_address", "id": address}]

    def test_activation_of_a_managed_device_joins_the_netbox_managed_scope(self):
        netbox, gw = _scoped_netbox()
        device, created = self.reserved(gw)
        self.assertEqual(gw.activate(created, managed=True), {"managed_scope": True})
        stored = netbox.dcim.devices.store[device]
        self.assertEqual((stored.status, stored.custom_fields), ("active", {"iac_managed": True}))
        self.assertEqual(_tag_slugs(netbox, device), ["csci5840-iac", "managed", ipam.PROVISIONING_TAG])

    def test_activation_is_idempotent_for_the_managed_scope(self):
        netbox, gw = _scoped_netbox()
        device, created = self.reserved(gw)
        gw.activate(created, managed=True)
        self.assertEqual(gw.activate(created, managed=True), {"managed_scope": True})
        self.assertEqual(_tag_slugs(netbox, device), ["csci5840-iac", "managed", ipam.PROVISIONING_TAG])

    def test_disposable_activation_never_joins_the_managed_scope(self):
        netbox, gw = _scoped_netbox()
        device, created = self.reserved(gw)
        self.assertEqual(gw.activate(created, managed=False), {"managed_scope": False})
        stored = netbox.dcim.devices.store[device]
        self.assertEqual((stored.status, getattr(stored, "custom_fields", None)), ("active", None))
        self.assertEqual(_tag_slugs(netbox, device), [ipam.PROVISIONING_TAG])

    def test_activation_without_the_netbox_scope_tags_is_refused_before_any_write(self):
        for missing in ("csci5840-iac", "managed"):
            with self.subTest(missing=missing):
                netbox, gw = _scoped_netbox(tags=[t for t in ("csci5840-iac", "managed") if t != missing])
                device, created = self.reserved(gw)
                with self.assertRaises(ipam.IpamUnavailable):
                    gw.activate(created, managed=True)
                self.assertEqual(netbox.dcim.devices.store[device].status, "planned")
                self.assertNotIn(missing, [t.slug for t in netbox.extras.tags.store.values()])   # never created to fake the scope

    def test_activation_of_a_device_tagged_unmanaged_is_refused(self):
        netbox, gw = _scoped_netbox()
        device, created = self.reserved(gw)
        unmanaged = next(t for t in netbox.extras.tags.store.values() if t.slug == "unmanaged")
        netbox.dcim.devices.store[device].tags = [*netbox.dcim.devices.store[device].tags, {"id": unmanaged.id}]
        address = created[1]["id"]
        with self.assertRaises(ipam.IpamUnavailable):
            gw.activate(list(reversed(created)), managed=True)            # the address comes first: still nothing is written
        self.assertNotIn("managed", _tag_slugs(netbox, device))
        self.assertEqual((netbox.dcim.devices.store[device].status, netbox.ipam.ip_addresses.store[address].status), ("planned", "reserved"))

    def test_activation_whose_read_back_lacks_the_scope_is_refused(self):
        netbox, gw = _scoped_netbox()
        device, created = self.reserved(gw)
        stored = netbox.dcim.devices.store[device]
        original = stored.update

        def drops_custom_fields(values):          # a NetBox without the ``iac_managed`` field silently ignores it
            original({k: v for k, v in values.items() if k != "custom_fields"})
        stored.update = drops_custom_fields
        with self.assertRaises(ipam.IpamUnavailable):
            gw.activate(created, managed=True)

    def test_ipam_activate_reports_only_the_proven_scope(self):
        class Gw:
            def __init__(self, answer):
                self.answer = answer

            def activate(self, created, *, managed):
                return self.answer
        refs = {"created": [], "device_id": 7}
        self.assertEqual(ipam.activate(Gw({"managed_scope": True}), refs, managed=True)["managed_scope"], True)
        self.assertEqual(ipam.activate(Gw({"managed_scope": False}), refs, managed=False)["managed_scope"], False)
        self.assertEqual(ipam.activate(Gw({"managed_scope": True}), refs, managed=False)["managed_scope"], False)

    def test_ipam_activate_fails_when_the_requested_scope_is_not_confirmed(self):
        class Gw:
            def __init__(self, answer):
                self.answer = answer

            def activate(self, created, *, managed):
                return self.answer
        for answer in ({"managed_scope": False}, {}, None, {"managed_scope": "true"}):
            with self.subTest(answer=answer), self.assertRaises(ipam.IpamUnavailable):
                ipam.activate(Gw(answer), {"created": []}, managed=True)
