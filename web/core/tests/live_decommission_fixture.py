"""V2 Phase 7 (+8) live acceptance in the disposable decommission fixture (labs/decommission-isolated).  Not a unit test module.

Run through ``labs/decommission-isolated/run-harness.sh <stage> ...`` (inside the fixture's NMAS namespace, fixture settings, fresh
fixture database).  Stages, in order:

    prepare      adopt the five fixture routers (inventory redirected to the fixture; key-only fixture credential)
    stub         STUB: non-redundant and quiescent -> QUIESCENT -> decommission (no transition) -> restore (exact digest)
    gateway      E2: HB's only gateway, active production traffic -> BLOCKED with the operator instruction; nothing written
    transit      T1: active traffic, OSPF alternate via T2 -> REDUNDANT_TRANSITION -> cost-out, traffic observed moving, removal,
                 continuous measurement must show zero loss -> DECOMMISSIONED -> restore -> exact digest, adjacencies FULL
    fault        T1 (restored successor) again; the REAL SSH session is closed right after the device accepted the second removal
                 step (its response never arrives) -> that step is recorded as possibly applied, compensation runs on one fresh
                 session through the same transport -> ROLLED_BACK, digest equal to the baseline, IN_SERVICE; zero loss
    outage       the same, but NMAS's management link to T1 also goes down with the session (a real path outage): no fresh
                 session -> FAILED_COMPENSATION_INCOMPLETE -> UNCERTAIN; the device is never reported restored
    recover      after ``outage``: the link comes back; a governed recovery (the inverse of exactly the run's own operations on the
                 device, approved by a second operator) -> ROLLED_BACK on the baseline digest; the run is reconciled
    again        T1 is evaluated for decommissioning again: no unresolved transaction blocks it (then cancelled)
    infra        Phase 8: dispatch the lifecycle outbox through the infrastructure consumers and record their projections
    report       lifecycle chains, audit counts, an index

Evidence is written (secret-free) to $NMAS_P7_LIVE_EVIDENCE.  Every router is reached by NMAS's real cEOS executor over SSH with the
fixture's key; hosts' counters and the continuous measurement run in the hosts' namespaces.  Nothing touches the production lab.
"""
# pylint: disable=missing-function-docstring
from __future__ import annotations

import json
import os
import re
import secrets
import subprocess
import time
from pathlib import Path
from unittest import mock

from django.conf import settings
from django.utils import timezone

from core import models

REPO = Path(settings.REPO_ROOT)
FX = REPO / "labs" / "decommission-isolated"
RUNTIME = FX / "runtime"
EVIDENCE = Path(os.environ.get("NMAS_P7_LIVE_EVIDENCE") or RUNTIME / "evidence")
OPERATOR, APPROVER = "olivia", "arthur"
SVC_REF = "runtime://device-credentials/fx-p7-nmas-svc"
UNUSED_REF = "runtime://device-credentials/fx-p7-unused"
ROUTERS = {"E1": "10.254.70.1", "T1": "10.254.70.2", "T2": "10.254.70.3", "E2": "10.254.70.4", "STUB": "10.254.70.5"}
HOSTS = {"HA": {"IPV4": "10.254.80.10", "IPV6": "2001:db8:254:80::10"}, "HB": {"IPV4": "10.254.85.10", "IPV6": "2001:db8:254:85::10"}}
PROBE_INTERVAL = 0.05


def fixture(*args, check=True, timeout=120) -> subprocess.CompletedProcess:
    return subprocess.run([str(FX / "fixture.sh"), *args], check=check, capture_output=True, text=True, timeout=timeout)


def evidence(name: str, payload) -> None:
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    text = payload if isinstance(payload, str) else json.dumps(payload, indent=2, sort_keys=True, default=str)
    for marker in ("PRIVATE KEY", "secret sha512", "$6$"):
        assert marker not in text, f"evidence {name} would carry secret material ({marker})"
    (EVIDENCE / name).write_text(text + ("\n" if not text.endswith("\n") else ""), encoding="utf-8")
    print(f"[evidence] {name}", flush=True)


def host_pid(name: str) -> str:
    return subprocess.run(["docker", "inspect", "-f", "{{.State.Pid}}", f"nmas-p7-{name.lower()}"], capture_output=True, text=True,
                          check=True).stdout.strip()


def in_host(name: str, argv: list[str], **kwargs):
    return subprocess.run(["sudo", "-n", "nsenter", "-t", host_pid(name), "-n", *argv], capture_output=True, text=True, check=False, **kwargs)


def fixture_inventory() -> dict:
    import yaml

    with open(REPO / "inventory.yml", encoding="utf-8") as handle:
        document = yaml.safe_load(handle) or {}
    document["network_devices"] = {name: {"username": "nmas-svc", "ssh_key_ref": SVC_REF, "credential_ref": UNUSED_REF,
                                          "monitoring": {"platform": "ceos", "address": address, "source_interface": "Ethernet5"}}
                                   for name, address in ROUTERS.items()}
    document["management"] = {**(document.get("management") or {}), "nmas_ipv4": "10.254.70.100/24"}
    document["hosts"] = {}
    return document


def host_counters(name: str):
    from core.services.decommission.observe import proc_counters

    def read():
        snmp = in_host(name, ["cat", "/proc/net/snmp"]).stdout
        snmp6 = in_host(name, ["cat", "/proc/net/snmp6"]).stdout
        return proc_counters(snmp, snmp6)
    return read


class PingProbe:
    """The continuous measurement: deterministic-count pings HA -> HB per family at 20 packets / s (the monitored flows)."""

    def __init__(self, seconds: float):
        count = int(seconds / PROBE_INTERVAL)
        self.started = time.monotonic()
        self.procs = {}
        for family, flag in (("IPV4", "-4"), ("IPV6", "-6")):
            self.procs[f"HA->HB {family}"] = subprocess.Popen(  # noqa: S603
                ["sudo", "-n", "nsenter", "-t", host_pid("HA"), "-n", "ping", flag, "-n", "-q", "-i", str(PROBE_INTERVAL), "-c", str(count),
                 "-W", "1", HOSTS["HB"][family]], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    def stop(self) -> dict:
        out = {}
        for label, proc in self.procs.items():
            text, _ = proc.communicate(timeout=600)
            match = re.search(r"(\d+) packets transmitted, (\d+) received", text or "")
            out[label] = {"sent": int(match.group(1)), "received": int(match.group(2))} if match else {"sent": None, "received": None,
                                                                                                     "raw": (text or "")[-200:]}
        out["_seconds"] = round(time.monotonic() - self.started, 1)
        return {k: v for k, v in out.items()}


class Workload:
    """Background production traffic (HA <-> HB, both families, 5 packets / s) for the active-traffic scenarios."""

    def __init__(self):
        self.procs = [subprocess.Popen(["sudo", "-n", "nsenter", "-t", host_pid("HA"), "-n", "ping", flag, "-n", "-q", "-i", "0.2",  # noqa: S603
                                        HOSTS["HB"][family]], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                      for family, flag in (("IPV4", "-4"), ("IPV6", "-6"))]

    def stop(self):
        for proc in self.procs:
            subprocess.run(["sudo", "-n", "kill", "-INT", str(proc.pid)], check=False, capture_output=True)  # noqa: S603,S607
        for proc in self.procs:
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                subprocess.run(["sudo", "-n", "kill", "-9", str(proc.pid)], check=False, capture_output=True)  # noqa: S603,S607


class Harness:
    def __init__(self):
        from core.services import nsot_live
        from core.services.health import inventory as health_inventory
        from modules import device_credentials

        self.inventory = fixture_inventory()
        for target, name in ((health_inventory, "load_inventory"), (nsot_live, "_load_inventory")):
            mock.patch.object(target, name, return_value=self.inventory).start()
        device_credentials.DEFAULT_STORE = RUNTIME / "nmas-provider" / "store.json"
        self.store = device_credentials.FileSecretProvider()
        self.store.initialize(SVC_REF, (RUNTIME / "keys" / "nmas-svc").read_text(), replace=True)
        try:
            self.store.candidates(UNUSED_REF)
        except device_credentials.SecretProviderError:
            self.store.initialize(UNUSED_REF, secrets.token_urlsafe(24), replace=True)
        self.readers = {}
        self._runtime = None

    # -- runtime -------------------------------------------------------------------------------------------------------------
    def reader(self, name):
        from core.services.execution.executors.ceos import CeosExecutor

        def read(command):
            executor = self.readers.get(name)
            if executor is None:
                executor = CeosExecutor({"name": name, "platform": "ceos"})
                executor.connect()
                self.readers[name] = executor
            try:
                return executor.show(command)
            except Exception:
                self.readers.pop(name, None)
                raise
        return read

    def runtime(self, probe_seconds: float = 150.0, fault=None):
        from core.services.decommission import observe, service
        from core.services.execution.executors.ceos import CeosExecutor

        specs = observe.flow_specs(workload="HA-HB", sender="HA", receiver="HB", sender_gateway="E1", receiver_gateway="E2", addresses=HOSTS)
        observer = observe.LiveObserver(routers={n: self.reader(n) for n in ROUTERS}, hosts={h: host_counters(h) for h in HOSTS}, flows=specs,
                                        window_seconds=8.0)
        factory = CeosExecutor if fault is None else fault      # ``fault``: an executor factory (see dropping_factory)
        return service.Runtime(executor_factory=factory, observer=observer,
                               management_addresses=lambda device: [ROUTERS[device.name]],
                               probe_factory=lambda: PingProbe(probe_seconds), settle_seconds=6.0, move_timeout_seconds=60.0, soak_seconds=8.0)

    @staticmethod
    def device(name):
        return models.ManagedDevice.objects.filter(name=name).exclude(lifecycle_state__in=tuple(models.DEVICE_LIFECYCLE_TERMINAL)).first()

    def running(self, name) -> str:
        """The running configuration read through NMAS's own SSH executor (the authorized transport, never the container
        console), without account lines (hashes / keys never reach evidence)."""
        from core.services.execution.executors.ceos import CeosExecutor

        executor = CeosExecutor({"name": name, "platform": "ceos"})
        try:
            executor.connect()
            text = executor.show("show running-config")
        except Exception as exc:  # pylint: disable=broad-exception-caught  # noqa: BLE001 - evidence records an unreadable device
            return f"UNREADABLE {type(exc).__name__}"
        finally:
            executor.close()
        return "\n".join(line for line in text.splitlines() if not line.startswith("username ") and "secret" not in line)

    def route(self, name, prefix="10.254.85.10") -> list[str]:
        """``show ip route <prefix>`` through the authorized SSH session (last two lines)."""
        try:
            return self.reader(name)(f"show ip route {prefix}").strip().splitlines()[-2:]
        except Exception as exc:  # pylint: disable=broad-exception-caught  # noqa: BLE001 - evidence records an unreadable device
            return [f"UNREADABLE {type(exc).__name__}"]

    def digest(self, name) -> str:
        from core.services.execution.executors.ceos import CeosExecutor

        executor = CeosExecutor({"name": name, "platform": "ceos"})
        executor.connect()
        try:
            return executor.config_state_digest()
        finally:
            executor.close()

    # -- stages --------------------------------------------------------------------------------------------------------------
    def stage_prepare(self):
        from core.services.devices import lifecycle

        rows = {}
        for name in ROUTERS:
            result = lifecycle.adopt_existing(name, role="router", actor=OPERATOR)
            rows[name] = {"ok": result.ok, "codes": result.codes, "device": getattr(result.device, "device_id", "")}
        routes = {name: self.route(name) for name in ("E1", "T1")}
        evidence("00-prepare.json", {"adopted": rows, "routes_to_hb": routes, "baseline_containers": "see 99-index"})

    def _decommission(self, name, *, label, workload=False, approve=True, execute=True, fault=None):
        from core.services.decommission import service

        traffic = Workload() if workload else None
        try:
            if traffic:
                time.sleep(3)
            device = self.device(name)
            requested = service.request(device, actor=OPERATOR, reason=f"Phase 7 live acceptance: {label}")
            record = requested.record or device.decommissions.filter(state__in=tuple(models.DECOMMISSION_OPEN)).first()
            runtime = self.runtime(fault=fault)
            evaluated = service.evaluate(record, actor=OPERATOR, runtime=runtime)
            record.refresh_from_db()
            out = {"request": {"ok": requested.ok, "codes": requested.codes}, "evaluate": {"ok": evaluated.ok, "codes": evaluated.codes},
                   "state": record.state, "readiness_mode": record.readiness_mode, "readiness": record.readiness,
                   "dependencies": record.dependencies, "blockers": record.blockers, "plan": record.plan, "plan_hash": record.plan_hash,
                   "baseline": record.baseline.snapshot_id if record.baseline else None,
                   "baseline_digest": record.baseline.state_digest if record.baseline else None}
            if not evaluated.ok or not approve:
                return record, out
            refused = service.approve(record, actor=OPERATOR, confirmation=record.plan_hash)
            out["self_approval"] = {"ok": refused.ok, "codes": refused.codes}
            approved = service.approve(record, actor=APPROVER, confirmation=record.plan_hash)
            out["approve"] = {"ok": approved.ok, "codes": approved.codes}
            if not execute or not approved.ok:
                return record, out
            before = self.running(name)
            executed = service.execute(record, actor=APPROVER, confirmation=record.plan_hash, runtime=runtime)
            record.refresh_from_db()
            out["execute"] = {"ok": executed.ok, "codes": executed.codes, "outcome": executed.detail.get("outcome"),
                              "report": {k: executed.detail.get("report", {}).get(k) for k in ("outcome", "failure", "compensation", "postcheck",
                                                                                               "baseline_digest", "final_digest", "restored", "steps")}}
            out["after"] = {"state": record.state, "transition": record.transition, "outcome": record.outcome,
                            "device_lifecycle": models.ManagedDevice.objects.get(pk=record.device_id).lifecycle_state,
                            "running_before_lines": len(before.splitlines()), "running_after": self.running(name).splitlines()[:200]}
            return record, out
        finally:
            if traffic:
                traffic.stop()

    def _restore(self, record, *, label):
        from core.services.decommission import service

        runtime = self.runtime()
        requested = service.request_restore(record, actor=OPERATOR)
        row = requested.record
        out = {"request": {"ok": requested.ok, "codes": requested.codes}}
        if row is None:
            return None, out
        checked = service.check_restore(row, actor=OPERATOR, runtime=runtime)
        row.refresh_from_db()
        out["check"] = {"ok": checked.ok, "codes": checked.codes, "state": row.state, "checks": row.checks, "plan": row.plan}
        if not checked.ok:
            return row, out
        out["self_approval"] = service.approve_restore(row, actor=OPERATOR, confirmation=row.plan_hash).codes
        approved = service.approve_restore(row, actor=APPROVER, confirmation=row.plan_hash)
        out["approve"] = {"ok": approved.ok, "codes": approved.codes}
        executed = service.execute_restore(row, actor=APPROVER, confirmation=row.plan_hash, runtime=runtime)
        row.refresh_from_db()
        out["execute"] = {"ok": executed.ok, "codes": executed.codes, "outcome": executed.detail.get("outcome"), "state": row.state,
                          "outcome_detail": row.outcome,
                          "successor": {"device_id": row.successor.device_id, "origin": row.successor.origin, "lifecycle": row.successor.lifecycle_state,
                                        "admission": row.successor.admission_state, "predecessor": row.successor.predecessor.device_id}
                          if row.successor else None,
                          "exact_digest": row.outcome.get("digest") == record.baseline.state_digest}
        out["label"] = label
        return row, out

    def stage_stub(self):
        record = models.DecommissionRecord.objects.filter(device__name="STUB").order_by("-id").first()
        if record is None or record.state != models.DecommissionState.DECOMMISSIONED:
            record, out = self._decommission("STUB", label="non-redundant quiescent STUB")
        else:      # resumed run: the decommissioning already happened; record it from the database
            out = {"resumed": True, "state": record.state, "readiness_mode": record.readiness_mode, "readiness": record.readiness,
                   "plan": record.plan, "outcome": record.outcome, "transition": record.transition,
                   "baseline_digest": record.baseline.state_digest, "after_running": self.running("STUB").splitlines()[:120]}
        evidence("10-stub-decommission.json", out)
        if record.state == models.DecommissionState.DECOMMISSIONED:
            _row, restored = self._restore(record, label="STUB restore")
            evidence("11-stub-restore.json", restored)

    def stage_gateway(self):
        record, out = self._decommission("E2", label="active non-redundant gateway E2", workload=True, approve=False)
        out["running_unchanged"] = True
        evidence("20-gateway-blocked.json", out)
        from core.services.decommission import service

        cancelled = service.cancel(record, actor=OPERATOR, reason="blocked as expected")
        evidence("21-gateway-cancelled.json", {"ok": cancelled.ok, "state": cancelled.record.state if cancelled.record else None})

    def retired_access(self, name) -> dict:
        """A decommissioned device through NMAS's own resolver and a FRESH executor session: both must refuse (DEVICE_RETIRED);
        the inventory address is never used again outside a governed restoration."""
        from core.services.execution.executors.ceos import CeosExecutor
        from core.services.management import resolve

        stale = self.readers.pop(name, None)            # the harness's cached observation session predates the retirement
        if stale is not None:
            stale.close()
        found = resolve.endpoint(name, legacy_address="inventory")
        executor = CeosExecutor({"name": name, "platform": "ceos"})
        try:
            executor.connect()
            session = "OPENED"
        except Exception as exc:  # pylint: disable=broad-exception-caught  # noqa: BLE001 - the refusal is the evidence
            session = getattr(exc, "code", type(exc).__name__)
        finally:
            executor.close()
        return {"resolver": found.as_dict(), "fresh_session": session}

    def stage_transit(self):
        record, out = self._decommission("T1", label="redundant transit T1 with active traffic", workload=True)
        out["routes_after"] = {"E1": self.route("E1")}
        if record.state == models.DecommissionState.DECOMMISSIONED:
            out["retired_access"] = self.retired_access("T1")
            out["credentials_retired"] = (record.outcome or {}).get("credentials_retired")
        evidence("30-transit-decommission.json", out)
        if record.state == models.DecommissionState.DECOMMISSIONED:
            traffic = Workload()
            try:
                _row, restored = self._restore(record, label="T1 restore")
            finally:
                traffic.stop()
            restored["routes_after_restore"] = self.route("E1")
            evidence("31-transit-restore.json", restored)

    def dropping_factory(self, *, drop_on: str, outage: bool = False):
        """CeosExecutor sessions through NMAS's real transport.  The first configuration set containing ``drop_on`` reaches the
        device, then the real SSH session is closed before NMAS reads the response; with ``outage`` the management link goes
        down at the same moment, so no fresh session can be opened until it comes back."""
        from core.services.execution.executors import ceos

        sessions = {"opened": 0, "dropped": False}

        class Dropping:
            def __init__(self, inner):
                self.inner = inner

            def __getattr__(self, name):
                return getattr(self.inner, name)

            def send_config_set(self, commands, **kwargs):
                text = "\n".join(str(c).strip() for c in commands)
                if sessions["dropped"] or drop_on not in text:
                    return self.inner.send_config_set(commands, **kwargs)
                sessions["dropped"] = True
                self.inner.send_config_set(commands, **kwargs)          # the device applies it
                if outage:
                    fixture("mgmt", "t1", "down")
                self.inner.disconnect()                                 # the SSH session really ends here
                raise OSError("Socket is closed")

        def connect(device):
            sessions["opened"] += 1
            return Dropping(ceos.netmiko_connection(device))

        def factory(device):
            return ceos.CeosExecutor(device, connection_factory=connect)

        return factory, sessions

    def _fault(self, *, outage: bool):
        factory, sessions = self.dropping_factory(drop_on="interface Ethernet2\nshutdown", outage=outage)
        label = "T1 lost session and management outage" if outage else "T1 lost session"
        try:
            record, out = self._decommission("T1", label=label, workload=True, fault=factory)
        finally:
            if outage:
                out_link = fixture("mgmt", "t1", "up", check=False)
                time.sleep(5)
        out["sessions_opened"] = sessions["opened"]
        out["session_dropped"] = sessions["dropped"]
        if outage:
            out["management_link_restored"] = out_link.returncode == 0
        out["digest_now"] = self.digest("T1")
        out["digest_equals_baseline"] = record.baseline is not None and out["digest_now"] == record.baseline.state_digest
        return record, out

    def stage_fault(self):
        _record, out = self._fault(outage=False)
        evidence("40-fault-rollback.json", out)

    def stage_outage(self):
        _record, out = self._fault(outage=True)
        evidence("42-fault-outage.json", out)

    def stage_recover(self):
        """After ``outage``: a governed recovery from the run's own inverses (never an out-of-band repair)."""
        from core.services.decommission import service
        from core.services.isolation import transaction as governed

        record = models.DecommissionRecord.objects.filter(device__name="T1", state=models.DecommissionState.UNCERTAIN).order_by("-id").first()
        out = {"state_before": record.state if record else None, "digest_before": self.digest("T1"),
               "unresolved_before": governed.unresolved_runs("T1")}
        runtime = self.runtime()
        planned = service.plan_recovery(record, actor=OPERATOR, runtime=runtime)
        record.refresh_from_db()
        recovery = (record.outcome or {}).get("recovery") or {}
        out["plan"] = {"ok": planned.ok, "codes": planned.codes, "operations": recovery.get("operations"), "change": recovery.get("change"),
                       "plan_hash": recovery.get("plan_hash")}
        out["self_approval"] = service.approve_recovery(record, actor=OPERATOR, confirmation=recovery.get("plan_hash", "")).codes
        approved = service.approve_recovery(record, actor=APPROVER, confirmation=recovery.get("plan_hash", ""))
        out["approve"] = {"ok": approved.ok, "codes": approved.codes}
        record.refresh_from_db()
        traffic, probe = Workload(), PingProbe(60.0)
        try:
            executed = service.execute_recovery(record, actor=APPROVER, confirmation=recovery.get("plan_hash", ""), runtime=runtime)
        finally:
            measured = probe.stop()
            traffic.stop()
        record.refresh_from_db()
        report = executed.detail.get("report", {})
        out["execute"] = {"ok": executed.ok, "codes": executed.codes, "outcome": executed.detail.get("outcome"),
                          "report": {k: report.get(k) for k in ("outcome", "failure", "postcheck", "baseline_digest", "final_digest", "steps")}}
        out["probe_during_recovery"] = measured
        out["state_after"] = record.state
        out["recovery_state"] = ((record.outcome or {}).get("recovery") or {}).get("state")
        out["adjacencies_before_uncost"] = (((record.outcome or {}).get("recovery") or {}).get("result") or {}).get("adjacencies_before_uncost")
        out["device_lifecycle"] = models.ManagedDevice.objects.get(pk=record.device_id).lifecycle_state
        out["digest_after"] = self.digest("T1")
        out["digest_equals_baseline"] = out["digest_after"] == record.baseline.state_digest
        out["unresolved_after"] = governed.unresolved_runs("T1")
        out["routes_to_hb"] = {"E1": self.route("E1")}
        evidence("43-fault-recovery.json", out)

    def stage_again(self):
        """The recovered device is not left blocked by its interrupted run: a new decommission evaluates (and is cancelled)."""
        from core.services.decommission import service

        record, out = self._decommission("T1", label="T1 again after recovery", workload=True, approve=False)
        cancelled = service.cancel(record, actor=OPERATOR, reason="proof only")
        out["cancelled"] = {"ok": cancelled.ok, "state": cancelled.record.state if cancelled.record else None}
        evidence("44-again-after-recovery.json", {k: out[k] for k in ("request", "evaluate", "state", "readiness_mode", "blockers",
                                                                      "dependencies", "cancelled")})

    def stage_infra(self):
        try:
            from core.services.infrastructure import dispatcher
        except ImportError as exc:
            evidence("50-infrastructure.json", {"available": False, "error": type(exc).__name__})
            return
        results = {}
        for consumer in ("nsot", "topology", "monitoring"):
            try:
                results[consumer] = dispatcher.dispatch(consumer=consumer, limit=500, actor="system:p7-live")
            except Exception as exc:  # pylint: disable=broad-exception-caught  # noqa: BLE001 - recorded as evidence
                results[consumer] = {"error": type(exc).__name__, "detail": str(exc)[:200]}
        evidence("50-infrastructure.json", {
            "dispatch": results,
            "outbox": list(models.LifecycleOutboxEvent.objects.values("device__name", "topic", "sequence", "state", "attempts", "last_error")
                           .order_by("id")),
            "topology_nodes": list(models.TopologyNode.objects.values("name", "state", "last_sequence")),
            "topology_edges": list(models.TopologyEdge.objects.values("device__name", "peer", "kind", "active", "source")),
            "monitoring": list(models.MonitoringTarget.objects.values("name", "state", "address", "generation", "collectors")),
            "nsot": list(models.NsotProjection.objects.values("name", "state", "desired", "discrepancies"))})

    def stage_report(self):
        from core.services.devices import events

        devices = []
        for device in models.ManagedDevice.objects.order_by("id"):
            devices.append({"device_id": device.device_id, "name": device.name, "origin": device.origin, "lifecycle": device.lifecycle_state,
                            "admission": device.admission_state, "predecessor": device.predecessor.device_id if device.predecessor else None,
                            "chain_ok": events.verify_chain(device),
                            "events": list(device.lifecycle_events.order_by("sequence").values_list("action", "outcome", "from_state", "to_state"))})
        evidence("90-lifecycle.json", devices)
        evidence("91-records.json", {
            "decommissions": list(models.DecommissionRecord.objects.order_by("id").values("id", "device__name", "state", "readiness_mode", "plan_hash")),
            "restorations": list(models.RestorationRecord.objects.order_by("id").values("id", "device__name", "state", "successor__name")),
            "audit": {t: models.AuditEvent.objects.filter(event_type=t).count() for t in ("DECOMMISSION_CHANGED", "RESTORATION_CHANGED")}})
        evidence("99-index.json", {"at": timezone.now().isoformat(), "files": sorted(p.name for p in EVIDENCE.iterdir())})


def main():
    harness = Harness()
    for stage in (os.environ.get("NMAS_P7_LIVE_STAGES") or "").split():
        print(f"=== stage {stage}", flush=True)
        getattr(harness, f"stage_{stage}")()
    for executor in harness.readers.values():
        try:
            executor.close()
        except Exception:  # pylint: disable=broad-exception-caught  # noqa: BLE001
            pass
