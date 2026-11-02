"""PR #69 LIVE acceptance -- the NMAS-active managed scope on GENUINE lifecycle records and a real (disposable) NetBox.

NOT part of any automated suite (the module name does not match ``test*.py``).  It adds stages to the Phases 5 + 6 live harness
(``live_isolation_commissioning_fixture``), which drives a factory-default cEOS through native ZTP, isolation, governed
commissioning and controlled admission.  With ``NMAS_ISO_LIVE_NETBOX_ENV`` set, that harness uses the REAL
``ipam.NetboxGateway`` against the disposable NetBox of ``labs/managed-scope-isolated/netbox.sh`` (reached only over the
fixture's own veth), so the reservation, the NSOT synchronization and the managed-scope activation are real NetBox writes.

    scope-pre    after commissioning, before admission: NEW1 has a real PLANNED-only NetBox record; it must not qualify
    scope        after admission: NEW1 qualifies, NetBox holds the scope (read back through the production reader); every
                 consumer admits it; each broken link of the chain refuses with its reason; NetBox activation is idempotent,
                 refuses a mismatched record without writing, and recovers a partially-lost scope
    probation    the run's real post-commissioning probation (start_probation, 7-day soak): still qualifies; then real
                 out-of-band configuration drift on NEW1 invalidates the soak (CONFIGURATION_DRIFT) and revokes the scope

Every negative case mutates ONE link of the fixture database's genuine records and restores it (the ``changed`` writer of the
PR #69 tests: a ManagedDevice through its own compare-and-swap).  Nothing here can reach production: the database is the
fixture's SQLite file, NetBox is the disposable instance (any other URL is refused), notifications are recorded, not sent.
"""

from __future__ import annotations

import copy
import os
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from django.utils import timezone

from core import models

FIXTURE_NETBOX = "http://10.254.69.2:8080"
NAME = "NEW1"


# --- the disposable NetBox ---------------------------------------------------------------------------------------------------------
def netbox_values() -> dict | None:
    path = os.environ.get("NMAS_ISO_LIVE_NETBOX_ENV")
    if not path:
        return None
    values = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        key, sep, value = line.partition("=")
        if sep:
            values[key.strip()] = value.strip()
    if values.get("NETBOX_URL") != FIXTURE_NETBOX:       # never anything but the fixture's own instance
        raise SystemExit(f"refusing NetBox {values.get('NETBOX_URL')!r}: only {FIXTURE_NETBOX} is allowed")
    return values


def netbox_client():
    from modules import netbox_ipam as nb

    values = netbox_values()
    if values is None:
        return None
    return nb.build_client(nb.load_config(env=values, env_file=Path("/nonexistent")))


def real_gateway():
    """The production ``ipam.NetboxGateway`` bound to the disposable NetBox, or None when the harness runs with the fake."""
    from core.services.provisioning import ipam

    client = netbox_client()
    return None if client is None else ipam.NetboxGateway(client=client)


def device_view(client, netbox_id) -> dict:
    device = client.dcim.devices.get(netbox_id)
    if device is None:
        return {"exists": False}
    return {"exists": True, "id": device.id, "name": device.name, "status": str(getattr(device.status, "value", device.status)),
            "tags": sorted(t.slug for t in device.tags or []), "iac_managed": (device.custom_fields or {}).get("iac_managed")}


def managed_list(client) -> list:
    from modules import netbox_ipam as nb

    return nb.get_managed_devices(client)


# --- genuine-record mutation (one link at a time, always restored) ---------------------------------------------------------------
@contextmanager
def changed(model, pk, **fields):
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


def _records():
    row = models.ProvisionedDevice.objects.select_related("run").filter(name=NAME).exclude(
        state=models.ProvisionedDeviceState.RETIRED).first()
    device = models.ManagedDevice.objects.filter(name=NAME).order_by("-id").first()
    record = models.CommissioningRecord.objects.filter(device=device).order_by("-id").first()
    return row, (row.run if row else None), device, record


# --- the consumers -----------------------------------------------------------------------------------------------------------
FROZEN_MANAGED = ["R1", "R2", "R3", "R4", "S1", "S2", "S3", "S4", "mgmt_swt"]


def _bundle(managed):
    from core.services.validation import sources

    other = [sources.SourceResult(name, "available", {}) for name in ("TOPOLOGY", "INVENTORY", "CAPABILITY")]
    return sources.SourceBundle(sources.SourceResult("NETBOX", "available", {"managed_devices": list(managed)}), *other,
                                repository_head="0" * 40)


def config_validation_check(managed) -> dict:
    """``network_config_validation._managed_scope_checks`` for an EXISTING_DEVICE intent of NEW1 (what PR #68 left inert)."""
    from core.services import network_config_validation as ncv

    snapshot = {"devices": [{"device_name": NAME, "target_type": models.DeviceIntentTargetType.EXISTING_DEVICE}]}
    (check,) = ncv._managed_scope_checks(snapshot, _bundle(managed))
    return {"status": check["status"], "evidence": check.get("evidence")}


def execution_gate(managed) -> list:
    """The execution gate's managed-scope blockers for an ordinary Change to NEW1 (``eligibility._scope_blockers``)."""
    from core.services.execution import eligibility as el
    from core.services.execution.scope import resolve_scope
    from core.tests.helpers import execution as ex
    from core.tests.helpers.validation import Dev, make_sources, netbox_data, new_change

    change = new_change("PR #69 live: an ordinary change to the admitted device")
    dev = Dev(change, NAME, target_type=models.DeviceIntentTargetType.EXISTING_DEVICE)
    dev.address(dev.iface("Loopback69", kind="LOOPBACK"), "10.254.255.69/32")
    prepared = ex.prepared(SimpleNamespace(change=change, sources=make_sources(netbox=netbox_data(managed_devices=list(managed)))),
                           require_permit=False)
    scope, problems = resolve_scope(prepared.plan, prepared.change.execution_mode)
    assert not problems and scope.devices == [NAME], (problems, scope.devices)
    report = el.EligibilityReport(change=prepared.change, mode=prepared.change.execution_mode)
    el._scope_blockers(report, scope, prepared.plan, sources=prepared.sources)
    return sorted({b["code"] for b in report.blockers})


def consumers(managed=FROZEN_MANAGED) -> dict:
    from core.services.provisioning import registry

    return {"refusal": registry.managed_scope_refusal(NAME), "active_managed": registry.active_managed(NAME),
            "config_validation": config_validation_check(managed), "execution_gate": execution_gate(managed)}


# --- stages ------------------------------------------------------------------------------------------------------------------
def stage_scope_pre(h, evidence):
    """Commissioned, not admitted: the real NetBox record is the PLANNED reservation, and NEW1 must not qualify."""
    client = netbox_client()
    row, run, device, record = _records()
    out = {"run_status": run.status, "registry_state": row.state, "device": [device.lifecycle_state, device.admission_state],
           "commissioning": record.state, "netbox_device_id": row.netbox_device_id}
    out["netbox"] = device_view(client, row.netbox_device_id) if client else "FAKE_GATEWAY"
    out["netbox_managed_devices"] = managed_list(client) if client else None
    out["consumers"] = consumers()
    assert out["consumers"]["refusal"] == "NOT_ACTIVE_PROVISIONED", out["consumers"]
    assert "TARGET_DEVICE_OUTSIDE_MANAGED_SCOPE" in out["consumers"]["execution_gate"], out["consumers"]
    if client:
        assert out["netbox"]["status"] == "planned" and "managed" not in out["netbox"]["tags"], out["netbox"]
        assert NAME not in out["netbox_managed_devices"]
    evidence("55-scope-before-admission.json", out)


def _negative_cases(row, run, device, record, other_netbox_id):
    def identity(**values):
        result = copy.deepcopy(run.result)
        result["netbox_identity"].update(values)
        return changed(models.ProvisioningRun, run.pk, result=result)

    def no_identity():
        result = {k: v for k, v in copy.deepcopy(run.result).items() if k != "netbox_identity"}
        return changed(models.ProvisioningRun, run.pk, result=result)

    D, S = models.DeviceLifecycleState, models.ProvisioningStatus
    return [
        ("inactive registry entry (ADMITTED, not ACTIVE)", "NOT_ACTIVE_PROVISIONED",
         changed(models.ProvisionedDevice, row.pk, state=models.ProvisionedDeviceState.ADMITTED)),
        ("stale registration (registry entry RETIRED)", "NOT_ACTIVE_PROVISIONED",
         changed(models.ProvisionedDevice, row.pk, state=models.ProvisionedDeviceState.RETIRED)),
        ("disposable device", "DISPOSABLE", changed(models.ProvisionedDevice, row.pk, disposable=True)),
        ("missing NetBox identity on the registry entry", "NETBOX_ID_MISSING",
         changed(models.ProvisionedDevice, row.pk, netbox_device_id=None)),
        ("unsynchronized run (POSTCHECKED)", "NOT_SYNCHRONIZED", changed(models.ProvisioningRun, run.pk, status=S.POSTCHECKED)),
        ("no recorded NetBox identity", "NOT_SYNCHRONIZED", no_identity()),
        ("planned-only NetBox identity", "NETBOX_IDENTITY_MISMATCH", identity(status="planned")),
        ("wrong NetBox identity (another real NetBox device)", "NETBOX_IDENTITY_MISMATCH", identity(device_id=other_netbox_id)),
        ("NetBox identity of another name", "NETBOX_IDENTITY_MISMATCH", identity(name="R1")),
        ("NetBox scope not confirmed", "MANAGED_SCOPE_MISSING", identity(managed_scope=False)),
        ("conflicting NetBox association on the device", "NETBOX_IDENTITY_MISMATCH",
         changed(models.ManagedDevice, device.pk, netbox_device_id=other_netbox_id)),
        ("missing admission evidence (NOT_ADMITTED)", "DEVICE_NOT_ADMITTED",
         changed(models.ManagedDevice, device.pk, admission_state=models.ProductionAdmissionState.NOT_ADMITTED)),
        ("revoked lifecycle (DECOMMISSION_PENDING)", "DEVICE_NOT_ADMITTED", changed(models.ManagedDevice, device.pk, lifecycle_state=D.DECOMMISSION_PENDING)),
        ("revoked lifecycle (FAILED)", "DEVICE_NOT_ADMITTED", changed(models.ManagedDevice, device.pk, lifecycle_state=D.FAILED)),
        ("revoked lifecycle (DECOMMISSIONED)", "DEVICE_NOT_ADMITTED", changed(models.ManagedDevice, device.pk, lifecycle_state=D.DECOMMISSIONED)),
        ("identity no longer verified (MISMATCH)", "IDENTITY_NOT_VERIFIED",
         changed(models.ManagedDevice, device.pk, identity_state=models.IdentityVerificationState.MISMATCH)),
        ("pinned host key cleared", "IDENTITY_NOT_VERIFIED", changed(models.ManagedDevice, device.pk, verified_host_key="")),
        ("configuration drift recorded", "CONFIGURATION_DRIFT",
         changed(models.ManagedDevice, device.pk, compliance_state=models.ComplianceState.DRIFT)),
        ("aborted commissioning", "COMMISSIONING_NOT_BOUND",
         changed(models.CommissioningRecord, record.pk, state=models.CommissioningState.ABORTED)),
        ("commissioning bound to another run", "COMMISSIONING_NOT_BOUND",
         changed(models.CommissioningRecord, record.pk, provisioning_run=None)),
    ]


def stage_scope(h, evidence):
    from core.services.provisioning import ipam

    client = netbox_client()
    gateway = real_gateway()
    row, run, device, record = _records()
    out = {"run_status": run.status, "registry_state": row.state, "netbox_identity": run.result.get("netbox_identity"),
           "device": [device.lifecycle_state, device.admission_state, device.identity_state, device.compliance_state],
           "commissioning": [record.state, record.provisioning_run_id == run.pk]}
    assert run.status == models.ProvisioningStatus.NSOT_SYNCED, run.status

    # positive: the admitted, synchronized device
    out["netbox"] = device_view(client, row.netbox_device_id) if client else "FAKE_GATEWAY"
    live_managed = managed_list(client) if client else FROZEN_MANAGED
    out["netbox_managed_devices"] = live_managed
    out["positive_frozen_netbox_list"] = consumers(FROZEN_MANAGED)          # the PR #68 scenario: NetBox's list lacks NEW1
    out["positive_live_netbox_list"] = consumers(live_managed)              # what the real NetBox now says
    assert out["positive_frozen_netbox_list"]["refusal"] == "", out["positive_frozen_netbox_list"]
    assert "TARGET_DEVICE_OUTSIDE_MANAGED_SCOPE" not in out["positive_frozen_netbox_list"]["execution_gate"]
    assert out["positive_frozen_netbox_list"]["config_validation"]["evidence"] == {"outside_scope": [], "nmas_active": [NAME]}
    if client:
        assert out["netbox"]["status"] == "active" and {"csci5840-iac", "managed"} <= set(out["netbox"]["tags"]), out["netbox"]
        assert out["netbox"]["iac_managed"] is True and NAME in live_managed

    # negative: one broken link at a time, each restored
    other = (client.dcim.devices.get(name="R1").id if client else row.netbox_device_id + 1)
    cases = []
    for label, expected, context in _negative_cases(row, run, device, record, other):
        with context:
            seen = consumers(FROZEN_MANAGED)
        cases.append({"case": label, "expected": expected, **seen})
        assert seen["refusal"] == expected, (label, seen)
        assert "TARGET_DEVICE_OUTSIDE_MANAGED_SCOPE" in seen["execution_gate"], (label, seen)
        assert seen["config_validation"]["status"] != "PASS" and NAME in seen["config_validation"]["evidence"]["outside_scope"], (label, seen)
    out["negative"] = cases
    out["restored"] = consumers(FROZEN_MANAGED)["refusal"]
    assert out["restored"] == "", out["restored"]

    # NetBox activation contract against the real instance
    if gateway is not None:
        refs = {k: v for k, v in (run.netbox or {}).items() if k != "plan"}
        before = device_view(client, row.netbox_device_id)
        again = ipam.activate(gateway, refs, managed=True)
        after = device_view(client, row.netbox_device_id)
        out["idempotent_reactivation"] = {"managed_scope": again["managed_scope"], "before": before, "after": after}
        assert again["managed_scope"] is True and before == after, out["idempotent_reactivation"]

        unmanaged = client.extras.tags.get(slug="unmanaged")
        nb_device = client.dcim.devices.get(row.netbox_device_id)
        nb_device.update({"tags": [{"id": t.id} for t in nb_device.tags] + [{"id": unmanaged.id}]})
        tagged = device_view(client, row.netbox_device_id)
        refused = None
        try:
            ipam.activate(gateway, refs, managed=True)
        except ipam.IpamUnavailable:
            refused = "IpamUnavailable"
        untouched = device_view(client, row.netbox_device_id)
        nb_device = client.dcim.devices.get(row.netbox_device_id)
        nb_device.update({"tags": [{"id": t.id} for t in nb_device.tags if t.slug != "unmanaged"]})
        out["mismatched_record_refused"] = {"refused": refused, "tagged": tagged, "after_refusal": untouched,
                                            "restored": device_view(client, row.netbox_device_id)}
        assert refused == "IpamUnavailable" and untouched == tagged, out["mismatched_record_refused"]

        missing = {**refs, "created": [*refs["created"], {"kind": "ip_address", "id": 999999, "name": "203.0.113.99/32"}]}
        nb_device = client.dcim.devices.get(row.netbox_device_id)
        managed_tag = client.extras.tags.get(slug="managed")
        nb_device.update({"tags": [{"id": t.id} for t in nb_device.tags if t.id != managed_tag.id], "custom_fields": {"iac_managed": False}})
        lost = device_view(client, row.netbox_device_id)
        lost_list = managed_list(client)
        refused_partial = None
        try:
            ipam.activate(gateway, missing, managed=True)
        except ipam.IpamUnavailable:
            refused_partial = "IpamUnavailable"
        after_partial = device_view(client, row.netbox_device_id)
        recovered = ipam.activate(gateway, refs, managed=True)
        out["partial_failure_recovery"] = {
            "scope_lost": lost, "managed_list_while_lost": lost_list, "activation_with_a_missing_object": refused_partial,
            "unchanged_after_that_refusal": after_partial == lost, "retry": recovered["managed_scope"],
            "after_retry": device_view(client, row.netbox_device_id), "managed_list_after_retry": managed_list(client)}
        assert NAME not in lost_list and refused_partial == "IpamUnavailable" and after_partial == lost
        assert recovered["managed_scope"] is True and NAME in out["partial_failure_recovery"]["managed_list_after_retry"]
        out["final_netbox"] = device_view(client, row.netbox_device_id)
        out["netbox_objects"] = [{"kind": c["kind"], "id": c["id"], "name": c["name"]} for c in refs["created"]]
    evidence("65-managed-scope-admitted.json", out)


def stage_probation(h, evidence):
    """The run's real post-commissioning probation, then real out-of-band drift on NEW1."""
    from core.services import provisioning_service as ps
    from core.services.soak import codes as soak_codes, lifecycle as soak_lifecycle
    from core.tests.helpers import health as hh

    notes = []
    row, run, device, record = _records()
    out = {}
    with mock.patch.object(soak_lifecycle, "publish", notes.extend):
        if run.status == models.ProvisioningStatus.NSOT_SYNCED:
            started = ps.start_probation(run, actor="arthur")
            out["start_probation"] = {"ok": started.ok, "codes": started.codes}
            assert started.ok, started.codes
        run.refresh_from_db()
        soak = run.soak_run
        out["probation"] = {"run_status": run.status, "bundle": run.probation_bundle.bundle_id, "soak": soak.soak_id,
                            "soak_state": soak.state, "soak_bundle_matches": soak.bundle_id == run.probation_bundle_id,
                            "required_end_at": soak.required_end_at.isoformat(), "baseline_devices": sorted((soak.baseline or {}).get("devices", {}))}
        out["during_probation"] = consumers(FROZEN_MANAGED)
        assert out["during_probation"]["refusal"] == "", out["during_probation"]
        # probation never weakens the other links
        for label, expected, context in (
                ("identity MISMATCH in probation", "IDENTITY_NOT_VERIFIED",
                 changed(models.ManagedDevice, device.pk, identity_state=models.IdentityVerificationState.MISMATCH)),
                ("aborted commissioning in probation", "COMMISSIONING_NOT_BOUND",
                 changed(models.CommissioningRecord, record.pk, state=models.CommissioningState.ABORTED)),
                ("unbound probation (no soak)", "PROBATION_UNBOUND", changed(models.ProvisioningRun, run.pk, soak_run_id=None))):
            with context:
                code = consumers(FROZEN_MANAGED)["refusal"]
            out.setdefault("probation_negative", []).append({"case": label, "expected": expected, "refusal": code})
            assert code == expected, (label, code)

        # real drift: an out-of-band change on the device (the console stand-in), then the soak's own collector tick
        h_cli = __import__("core.tests.live_isolation_commissioning_fixture", fromlist=["cli"]).cli
        h_cli("new1", "configure\ninterface Loopback0\ndescription out-of-band edit (PR #69 live drift)\nend")
        now = timezone.now()
        tick = soak_lifecycle.run_tick(now=now, snapshot=hh.snapshot(now=now), soak_id=soak.soak_id)
        soak.refresh_from_db()
        out["drift_tick"] = [{"action": r.action, "state": r.state, "detail": r.detail} for r in tick.runs]
        out["soak_after_drift"] = {"state": soak.state, "terminal_reason": soak.terminal_reason}
        out["after_drift"] = consumers(FROZEN_MANAGED)
        h_cli("new1", "configure\ninterface Loopback0\nno description\nend")
    out["notifications_recorded_not_sent"] = len(notes)
    assert soak.state == models.SoakState.INVALIDATED and soak.terminal_reason == soak_codes.CONFIGURATION_DRIFT, out["soak_after_drift"]
    assert out["after_drift"]["refusal"] == "PROBATION_UNTRUSTED", out["after_drift"]
    assert "TARGET_DEVICE_OUTSIDE_MANAGED_SCOPE" in out["after_drift"]["execution_gate"], out["after_drift"]
    evidence("68-managed-scope-probation.json", out)
