"""Fixtures for the V2 Phase 5A provisioning tests.  Application state and fakes only: no device, no NetBox, no Docker.

* ``FakeGateway``    an in-memory NetBox: devices, addresses, prefixes, DHCP ranges; scripted write failures.
* ``support``        record full empirical evidence so one capability cell is terminally SUPPORTED in the (empty) test database.
* ``Lab``            one provisioning request driven stage by stage against a ``FakeWorld`` network.
"""

from __future__ import annotations

import ipaddress
import itertools
import json
from types import SimpleNamespace
from unittest import mock

from core import models
from core.services import change_plan_service, execution_service as es, provisioning_service as ps
from core.services.capabilities import evidence
from core.services.capabilities.axes import Axis, EvidenceStatus, EvidenceType
from core.services.provisioning import bootstrap, ipam, lifecycle
from core.tests.helpers import execution as ex, health as h
from core.tests.helpers.validation import Dev, make_sources, netbox_data

FRR = models.Platform.UBUNTU_FRR
TARGET = {"container": "clab-nmas-prov-proof-edge1", "lab": "nmas-prov-proof"}
MANAGEMENT = {"interface": "eth0", "ipv4": "172.31.250.11/24", "ipv6": "fd00:ca:250::11/64"}


def support(platform=FRR, *features):
    """Make ``features`` terminally SUPPORTED for ``platform`` (every mandatory axis VERIFIED by LIVE evidence)."""
    for feature in features or ("interface.LOOPBACK",):
        for axis in Axis:
            evidence.record_evidence(platform=platform, feature=feature, axis=axis.value, status=EvidenceStatus.VERIFIED,
                                     source="test-fixture", evidence_type=EvidenceType.LIVE, recorded_by="tester")


class FakeGateway:
    """In-memory NetBox.  ``fail_on = "ip_address"`` makes that create raise; ``fail_delete = {"device"}`` leaves an object behind."""

    def __init__(self, *, devices=(), addresses=None, prefixes=(), dhcp_ranges=(), available=True):
        self.devices = set(devices)
        self.addresses = dict(addresses or {})            # host -> holder device
        self.prefixes = [ipaddress.ip_network(p) for p in prefixes]
        self.dhcp_ranges = [(ipaddress.ip_address(a), ipaddress.ip_address(b)) for a, b in dhcp_ranges]
        self.available, self.fail_on, self.fail_delete = available, "", set()
        self.objects: dict[int, dict] = {}
        self.calls: list[tuple] = []
        self._ids = itertools.count(1000)

    def _check(self):
        if not self.available:
            raise ipam.IpamUnavailable()

    def device_exists(self, name):
        self._check()
        return name in self.devices or any(o["kind"] == "device" and o["name"] == name for o in self.objects.values())

    def address_holders(self, host):
        self._check()
        return [{"address": host, "status": "active", "device": self.addresses[host]}] if host in self.addresses else []

    def containing_prefix(self, host):
        self._check()
        found = [p for p in self.prefixes if ipaddress.ip_address(host) in p]
        return str(max(found, key=lambda p: p.prefixlen)) if found else None

    def dhcp_ranges_containing(self, host):
        self._check()
        ip = ipaddress.ip_address(host)
        return [f"{a}-{b}" for a, b in self.dhcp_ranges if a.version == ip.version and a <= ip <= b]

    def _create(self, kind, name, **extra):
        self._check()
        self.calls.append(("create", kind, name))
        if self.fail_on == kind:
            raise RuntimeError("scripted NetBox failure")
        obj_id = next(self._ids)
        self.objects[obj_id] = {"kind": kind, "name": name, "status": extra.pop("status", "reserved"), **extra}
        return obj_id

    def create_prefix(self, prefix, *, tags, provenance):
        return self._create("prefix", prefix, tags=tags)

    def create_device(self, device, *, tags, provenance):
        return self._create("device", device["name"], status="planned", tags=tags, provenance=provenance)

    def create_interface(self, device_id, interface, *, tags):
        return self._create("interface", interface["name"], device=device_id)

    def create_address(self, address, interface_id, *, tags, provenance):
        return self._create("ip_address", address["address"], interface=interface_id)

    def activate(self, created, *, managed):
        self._check()
        self.calls.append(("activate", managed))
        for item in created:
            self.objects[item["id"]]["status"] = "active"
            self.objects[item["id"]]["managed"] = managed
        return {"managed_scope": bool(managed)}

    def delete(self, kind, obj_id):
        self._check()
        self.calls.append(("delete", kind, obj_id))
        if kind in self.fail_delete:
            raise RuntimeError("scripted NetBox failure")
        self.objects.pop(obj_id, None)

    def kinds(self):
        return sorted(o["kind"] for o in self.objects.values())


def prober(**overrides):
    """A read-only probe result: a running, pristine container in the declared lab by default."""
    values = {"exists": True, "running": True, "lab": TARGET["lab"], "answers": True, "configured": False, "facts": {"interfaces": ["eth0", "lo"]}}
    values.update(overrides)
    return lambda target: bootstrap.Probe(**values)


class ProvDev(Dev):
    """``Dev`` builders over the intent the provisioning run already created (no second intent, no second revision)."""

    def __init__(self, change, name):
        self.change, self.name = change, name
        self.intent = change.device_intents.get(device_name=name)
        self.revision = self.intent.latest_revision()


class Lab:
    """One request walked through the workflow on fakes.  Each ``to_*`` method stops after the named stage."""

    def __init__(self, *, name="EDGE1", platform=FRR, disposable=True, management=None, target=None, supported=("interface.LOOPBACK",),
                 gateway=None, requested_by="requester"):
        if supported:
            support(platform, *supported)
        self.name = name
        self.gateway = gateway or FakeGateway()
        self.world = ex.FakeWorld(devices=(name,))
        # like the live NetBox source: the authoritative managed-device list is present, and the new device is NOT in it
        self.sources = make_sources(netbox=netbox_data(managed_devices=["R1", "R2", "R3", "R4", "S1", "S2", "S3", "S4", "mgmt_swt"]))
        self.management, self.target = dict(management or MANAGEMENT), dict(target or TARGET)
        self.request = ps.create_request(device_name=name, platform=platform, role="router", requested_by=requested_by, disposable=disposable)
        self.run = self.request.run
        self.last = self.request

    # -- injected device access -------------------------------------------------------------------------------------------
    def config_reader(self, device):
        return json.dumps(self.world.state[device["name"]], sort_keys=True)

    def session(self):
        return h.session_factory({self.name: h.linux_outputs()})

    # -- stages -----------------------------------------------------------------------------------------------------------
    def identity(self, **kw):
        self.last = ps.define_identity(self.run, actor="requester", bootstrap_transport=kw.pop("transport", "DOCKER_EXEC"),
                                       bootstrap_target=kw.pop("target", self.target), management=kw.pop("management", self.management))
        return self.last

    def bootstrap(self, **probe):
        self.last = ps.classify_bootstrap(self.run, actor="requester", prober=prober(**probe))
        return self.last

    def capability(self):
        self.last = ps.resolve_capabilities(self.run, actor="requester")
        return self.last

    def ipam(self):
        self.last = ps.plan_ipam(self.run, actor="requester", gateway=self.gateway)
        return self.last

    def candidate(self, **kw):
        self.last = ps.generate_candidate(self.run, actor="requester", **kw)
        return self.last

    def intent(self, *, loopback="loopback10", address="198.51.100.10/32"):
        dev = ProvDev(self.run.change, self.name)
        iface = dev.iface(loopback, kind="LOOPBACK")
        dev.address(iface, address)
        return dev

    def validate(self):
        self.last = ps.record_validation(self.run, actor="requester", sources=self.sources)
        return self.last

    def plan(self):
        self.last = ps.build_plan(self.run, actor="requester", sources=self.sources)
        return self.last

    def precheck(self, **kw):
        options = dict(snapshot=h.snapshot(), session_factory=self.session(), now=h.NOW)
        options.update(kw)
        self.last = ps.run_precheck(self.run, actor="requester", sources=self.sources, **options)
        return self.last

    def approve(self, *, actor="approver", confirm=None):
        self.last = ps.approve(self.run, actor=actor, confirm_candidate_hash=self.run.candidate_hash if confirm is None else confirm)
        return self.last

    def provision(self, *, actor="approver", config_reader=None, **kw):
        """Execute the provisioning Change the way an operator does: through the ONE execution entry point (there is no provisioning one).

        -> namespace(ok, codes, event, execution): the engine's refusal codes plus the provisioning event the engine hook recorded.
        """
        change = self.run.change
        options = dict(sources=self.sources, executor_factory=self.world.factory, evidence_provider=self.world.evidence_provider,
                       notifier=ex.Notifications(), sleep=lambda seconds: None, clock=ex.stepping_clock(), confirm_mode=change.execution_mode)
        if change.execution_mode == models.ExecutionMode.PARTIAL_UAT:      # the operator's own explicit Partial (UAT) inputs
            options.update(through_cfg_id=change_plan_service.get_latest_plan(change).configlets.order_by("-sequence").first().cfg_id,
                           acknowledgements=ex.ALL_ACKS)
        options.update(kw)
        with mock.patch.object(lifecycle, "CONFIG_READER", config_reader or self.config_reader), \
                mock.patch.object(lifecycle, "GATEWAY_FACTORY", lambda: self.gateway):
            result = es.execute_change(change, actor=actor, **options)
        self.run.refresh_from_db()
        event = self.run.events.order_by("-sequence").first()
        codes = [b["code"] for b in result.blockers] + [b["code"] for b in (event.blockers if event and event.stage == "PROVISION" else [])]
        self.last = SimpleNamespace(ok=self.run.status == models.ProvisioningStatus.POSTCHECKED, codes=codes, event=event, execution=result,
                                    blockers=result.blockers)
        return self.last

    def sync(self):
        self.last = ps.sync_nsot(self.run, actor="approver", gateway=self.gateway)
        return self.last

    ORDER = ("identity", "bootstrap", "capability", "ipam", "candidate", "intent", "validate", "plan", "precheck", "approve", "provision", "sync")

    def through(self, step, **kwargs):
        """Run every step up to and including ``step``; assert each earlier one succeeded."""
        for name in self.ORDER[: self.ORDER.index(step) + 1]:
            result = getattr(self, name)(**(kwargs if name == step else {}))
            if name != "intent" and name != step:
                assert result.ok, (name, result.codes, getattr(result.event, "evidence", None))
        return self.last
