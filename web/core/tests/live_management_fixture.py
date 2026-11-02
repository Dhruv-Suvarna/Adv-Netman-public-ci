"""V2 Phase 4 LIVE harness -- management VRF execution / compensation, layered probes, failover / failback and bootstrap
credential retirement against the disposable cEOS fixture ``labs/mgmt-multihoming-isolated/fixture.sh``.

NOT part of any automated suite: the module name does not match ``test*.py`` and every test is skipped unless
``NMAS_MGMT_LIVE_FIXTURE=1``.  Run it INSIDE the fixture's NMAS network namespace (the only route to the fixture), with
that namespace's sysfs mounted in a private mount namespace (``labs/mgmt-multihoming-isolated/run-harness.sh`` does both):

    labs/mgmt-multihoming-isolated/run-harness.sh <evidence dir> [LiveManagementFixture | LiveBootstrapRetirement]

What is real and what is substituted (the evidence states the same):

* REAL: the cEOS devices and their CLI, the veth links and STP (failures are injected by shutting a FIXTURE switch port or
  freezing the fixture management switch -- never on DUT1), the NMAS namespace's two interfaces (observed through
  ``nmas_side`` from sysfs / iproute2), every probe socket (bound to the attachment's interface and source address), every SSH session
  (pinned host key, key-only), the cEOS executor's assess / apply / compensate code, the selector / resolver and the
  bootstrap-retirement state machine with the provider-held enrollment key.
* SUBSTITUTED: the NMAS database is the Django test database (disposable); ``inventory.yml`` is replaced by a fixture
  inventory listing only MSW1 / SW1 / DUT1; the service-credential provider is a fixture store under ``runtime/``; the
  production executor, health and NSOT connection factories resolve the approved fixture path through ``nsot_live``;
  the attachment trust observations are recorded from the switches' LIVE ``show lldp neighbors``
  read by this harness; the ZTP enrollment session of the bootstrap test is the Phase-3 flow driven with fake DHCP /
  verification inputs (live ZTP is Phase 3's evidence), so the harness installs that session's enrollment public key on
  DUT1 with the fixture-admin account and points the state machine's SSH connect at DUT1's address and real host key.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import subprocess
import socket
import time
import unittest
from types import SimpleNamespace
from pathlib import Path
from unittest import mock

import paramiko
import yaml
from django.conf import settings
from django.test import TestCase, override_settings
from django.utils import timezone

from core import models
from core.services import change_plan_service as cps
from core.services import nsot_live
from core.services.devices import attachments, lifecycle
from core.services.execution.executors import ceos
from core.services.execution.executors.base import ConfigletSpec
from core.services.health import inventory as health_inventory
from core.services.management import bootstrap_credentials as B, nmas_side, paths, probes, resolve, selector, ssh, vrf
from core.tests.helpers import lifecycle as L
from core.tests.helpers.validation import Dev, make_sources, new_change, validate
from core.tests.test_bootstrap_retirement import BcredMixin
from core.services.ztp import workflow

LIVE = os.environ.get("NMAS_MGMT_LIVE_FIXTURE") == "1"
REPO = Path(settings.REPO_ROOT)
FX = REPO / "labs" / "mgmt-multihoming-isolated"
RUNTIME = FX / "runtime"
EVIDENCE = Path(os.environ["NMAS_MGMT_LIVE_EVIDENCE"]) if os.environ.get("NMAS_MGMT_LIVE_EVIDENCE") else None
DUT_SVI, DUT_VRF, MSW_SVI, SW1_SVI = "10.254.40.21", "10.254.42.1", "10.254.40.2", "10.254.40.3"
SVC_REF = "runtime://device-credentials/fx-dut1-nmas-svc-key"
OPS_REF = "runtime://device-credentials/fx-dut1-nmas-ops-key"
T = models.ManagementPathType
H = models.ManagementPathHealth


# --- fixture plumbing ----------------------------------------------------------------------------------------------------------
def fixture(*args) -> str:
    return subprocess.run([str(FX / "fixture.sh"), *args], check=True, capture_output=True, text=True, timeout=120).stdout.strip()


def fingerprint_of(public_line: str) -> str:
    blob = base64.b64decode(public_line.split()[1])
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def host_key(name: str) -> str:
    """Out-of-band: the device console's ``show management ssh hostkey ed25519 public`` (fixture stand-in for a console)."""
    return fingerprint_of(fixture("hostkey", name))


def key(name: str) -> paramiko.Ed25519Key:
    return paramiko.Ed25519Key.from_private_key_file(str(RUNTIME / "keys" / name))


def public(name: str) -> str:
    return (RUNTIME / "keys" / f"{name}.pub").read_text().strip()


def cli(address: str, user: str, keyname: str, device: str) -> ssh.PinnedCli:
    return ssh.connect(address=address, port=22, username=user, pkey=key(keyname), expected_host_key=host_key(device))


def show(address, device, command, user="nmas-svc", keyname="nmas-svc") -> str:
    session = cli(address, user, keyname, device)
    try:
        return session.show(command)
    finally:
        session.close()


def evidence(name: str, payload) -> None:
    if EVIDENCE is None:
        return
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    text = payload if isinstance(payload, str) else json.dumps(payload, indent=2, sort_keys=True, default=str)
    for marker in ("PRIVATE KEY", "secret sha512", "$6$"):
        assert marker not in text, f"evidence {name} would carry secret material ({marker})"
    (EVIDENCE / name).write_text(text + ("\n" if not text.endswith("\n") else ""), encoding="utf-8")


def _tcp_open(address: str, port: int) -> bool:
    import socket

    try:
        socket.create_connection((address, port), timeout=2).close()
        return True
    except OSError:
        return False


def fixture_inventory() -> dict:
    with open(REPO / "inventory.yml", encoding="utf-8") as handle:
        document = yaml.safe_load(handle) or {}
    document["network_devices"] = {
        name: {"username": "nmas-svc", "ssh_key_ref": SVC_REF, "credential_ref": f"runtime://device-credentials/fx-{name.lower()}-unused",
               "monitoring": {"platform": "ceos", "address": address, "source_interface": "Vlan200"}}
        for name, address in (("MSW1", MSW_SVI), ("SW1", SW1_SVI), ("DUT1", DUT_SVI))}
    document["management"] = {**(document.get("management") or {}), "nmas_ipv4": "10.254.40.10/24"}
    document["hosts"] = {}
    return document


def fixture_store():
    from modules.device_credentials import FileSecretProvider

    return FileSecretProvider(RUNTIME / "nmas-provider" / "store.json")


def wait_for(predicate, *, timeout=60, step=2.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(step)
    return False


@unittest.skipUnless(LIVE, "live fixture harness: set NMAS_MGMT_LIVE_FIXTURE=1 and run inside the fixture's NMAS namespace")
@override_settings(NMAS_MGMT_MIN_PROBE_INTERVAL_SECONDS=0, NMAS_MGMT_FAILBACK_HOLD_DOWN_SECONDS=30)
class LiveManagementFixture(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.inventory = fixture_inventory()
        cls.store = fixture_store()
        for ref, name in ((SVC_REF, "nmas-svc"),):
            cls.store.initialize(ref, (RUNTIME / "keys" / name).read_text(), replace=True)

    def setUp(self):
        from modules import device_credentials

        real_loader = device_credentials.load_ssh_private_key
        for target, value in ((health_inventory, "load_inventory"), (nsot_live, "_load_inventory")):
            patcher = mock.patch.object(target, value, return_value=self.inventory)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = mock.patch.object(device_credentials, "load_ssh_private_key",
                                    side_effect=lambda reference, path=None: real_loader(reference, path=RUNTIME / "nmas-provider" / "store.json"))
        patcher.start()
        self.addCleanup(patcher.stop)

    # ======================================================================================================================
    # 1. management VRF: plan -> cEOS executor assess / apply / verify / compensate (digest-verified) -> re-apply
    # ======================================================================================================================
    def _plan_specs(self):
        change = new_change("Phase 4 live: management VRF on DUT1 Ethernet3")
        dev = Dev(change, "R1")                     # the fixture's validation sources model R1; configlets name no device
        port = dev.iface("Ethernet3")
        dev.address(port, f"{DUT_VRF}/30")
        revision = dev.refresh()
        mvrf = vrf.add_vrf(revision, name="MGMT", description="NMAS management VRF")
        vrf.add_binding(dev.refresh(), vrf_id=mvrf["id"], interface_id=port["id"])
        vrf.add_route(dev.refresh(), vrf_id=mvrf["id"], destination="10.254.43.0/24", next_hop="10.254.42.2")
        for service in ("SSH", "EAPI", "GNMI"):
            vrf.add_service(dev.refresh(), vrf_id=mvrf["id"], service=service)
        run = validate(change, make_sources())
        self.assertIn(run.status, (models.ValidationRunStatus.PASS, models.ValidationRunStatus.PASS_WITH_WARNINGS),
                      [f["code"] for f in run.report["findings"]])
        plan, _created = cps.build_change_plan(change, actor="tester")
        rows = [row for row in plan.configlets.order_by("sequence") if (row.desired_state_ref or {}).get("source", {}).get("object_type", "").startswith("mgmt_")]
        return [ConfigletSpec.from_configlet(row) for row in rows]

    def _executor(self):
        executor = ceos.CeosExecutor({"name": "DUT1", "platform": "ceos"})
        executor.connect()
        self.addCleanup(executor.close)
        return executor

    def test_1_management_vrf_apply_verify_compensate_reapply(self):
        dut, registered, _nmas = self._registry({})
        selected = selector.evaluate(dut, actor="live harness")
        self.assertEqual(selected.active_path, registered["oob"].path_id)
        specs = self._plan_specs()
        self.assertEqual([s.object_type for s in specs], ["mgmt_vrf", "mgmt_vrf_binding", "mgmt_vrf_route", "mgmt_vrf_service",
                                                          "mgmt_vrf_service", "mgmt_vrf_service"])
        executor = self._executor()
        before_text, before = executor._config_text(), executor.config_state_digest()
        assessments = [executor.assess(spec) for spec in specs]
        record = {"before_digest": before, "configlets": [], "transport": "production source/interface-bound cEOS connector",
                  "binding": self._binding(executor._conn, registered["oob"])}
        for spec, assessment in zip(specs, assessments):
            self.assertEqual((assessment.action, assessment.restorable), ("APPLY", True), (spec.object_type, assessment.reason))
        for spec, assessment in zip(specs, assessments):
            outcome = executor.apply(spec, assessment)
            record["configlets"].append({"cfg": spec.cfg_id, "object_type": spec.object_type, "lines": list(spec.lines),
                                         "commands_sent": ceos._commands_for(spec, spec.lines),
                                         "inverse": executor._config_inverses.get(spec.cfg_id), "apply_ok": outcome.ok,
                                         "apply_code": outcome.error_code})
            self.assertTrue(outcome.ok, (spec.object_type, outcome.error_code))
        applied_text = executor._config_text()
        record["applied_digest"] = executor.config_state_digest()
        for line in ("vrf instance MGMT", "ip routing vrf MGMT", "ip route vrf MGMT 10.254.43.0/24 10.254.42.2"):
            self.assertIn(line, applied_text)
        # the SSH service now answers INSIDE the VRF, from the NMAS namespace's second attachment.  Live finding: EOS starts the
        # per-VRF sshd a few seconds after the commit, so the first connection attempts are refused.
        started = time.monotonic()
        self.assertTrue(wait_for(lambda: _tcp_open(DUT_VRF, 22), timeout=120, step=1.0), "ssh never started in VRF MGMT")
        record["ssh_in_vrf_start_seconds"] = round(time.monotonic() - started, 1)
        record["ssh_in_vrf_hostname"] = json.loads(show(DUT_VRF, "dut", "show hostname | json"))["hostname"]
        self.assertEqual(record["ssh_in_vrf_hostname"], "DUT1")
        record["show_vrf"] = show(DUT_SVI, "dut", "show vrf MGMT")
        # reverse-order compensation, each one digest-verified by the executor
        for spec, assessment in reversed(list(zip(specs, assessments))):
            result = executor.compensate(spec, assessment)
            record.setdefault("compensation", []).append({"cfg": spec.cfg_id, "object_type": spec.object_type, "status": result.status,
                                                         "code": result.error_code, "detail": result.detail})
            self.assertEqual(result.status, "COMPENSATED", (spec.object_type, result.error_code))
        record["after_compensation_digest"] = executor.config_state_digest()
        self.assertEqual(record["after_compensation_digest"], before)
        evidence("vrf-running-before.txt", before_text)
        evidence("vrf-running-applied.txt", applied_text)
        # Client-side response-loss injection AFTER a real accepted write.
        # The executor must report uncertainty without repeating the write.
        executor2 = self._executor()
        first = specs[0]
        assessment = executor2.assess(first)
        send = executor2._conn.send_config_set
        def accepted_then_lost(*args, **kwargs):
            send(*args, **kwargs)
            raise OSError("isolated response-loss injection")
        with mock.patch.object(executor2._conn, "send_config_set", side_effect=accepted_then_lost) as sent:
            uncertain = executor2.apply(first, assessment)
            self.assertFalse(uncertain.ok)
            self.assertTrue(uncertain.partial_effects)
            self.assertEqual(sent.call_count, 1)
        restored = executor2.compensate(first, assessment)
        self.assertEqual(restored.status, "COMPENSATED", restored.error_code)
        self.assertEqual(executor2.config_state_digest(), before)
        record["uncertain_write"] = {"injection": "response lost after real accepted write", "apply_calls": 1,
                                      "code": uncertain.error_code, "partial_effects": uncertain.partial_effects,
                                      "compensation": restored.status, "restored_digest": before}
        # Re-apply after PROVEN compensation, through fresh assessments.
        for spec in specs:
            assessment = executor2.assess(spec)
            self.assertTrue(executor2.apply(spec, assessment).ok)
        record["reapplied_digest"] = executor2.config_state_digest()
        self.assertEqual(record["reapplied_digest"], record["applied_digest"])
        evidence("vrf-execution.json", record)

    # ======================================================================================================================
    # 2. registry -> layered probes -> selector: activation, failover OOB -> VLAN 200 -> routed VRF, switch failure,
    #    restore, hold-down, failback; resolver answers at every step; live negative probes
    # ======================================================================================================================
    def _lldp(self, address, device) -> dict:
        doc = json.loads(show(address, device, "show lldp neighbors | json"))
        return {row["port"]: (row["neighborDevice"], row["neighborPort"]) for row in doc.get("lldpNeighbors", [])}

    def _registry(self, record):
        devices = {}
        for name in ("MSW1", "SW1", "DUT1"):
            result = lifecycle.adopt_existing(name, role="switch", actor=L.APPROVER)
            self.assertTrue(result.ok, (name, result.blockers))
            devices[name] = result.device
        lldp = {"MSW1": self._lldp(MSW_SVI, "msw"), "SW1": self._lldp(SW1_SVI, "sw1")}
        record["lldp"] = lldp
        made = {}
        for device, upstream, port, local, connectivity in (("SW1", "MSW1", "Ethernet3", "Ethernet1", models.AttachmentConnectivity.TRUNK),
                                                            ("DUT1", "MSW1", "Ethernet2", "Ethernet1", models.AttachmentConnectivity.ACCESS),
                                                            ("DUT1", "SW1", "Ethernet2", "Ethernet2", models.AttachmentConnectivity.ACCESS)):
            self.assertEqual(lldp[upstream].get(port), (device, local), f"LLDP on {upstream}:{port}")   # the live trust basis
            result = attachments.register_attachment(devices[device], upstream_device=upstream, upstream_interface=port, local_interface=local,
                                                     purpose=models.AttachmentPurpose.MANAGEMENT, connectivity=connectivity, vlan=200,
                                                     actor=L.OPERATOR)
            self.assertTrue(result.ok, result.blockers)
            approved = attachments.approve_attachment(devices[device], result.attachment.pk, actor=L.APPROVER)
            self.assertTrue(approved.ok, approved.blockers)
            lifecycle.record_observation(devices[device], kind=models.ObservationKind.ATTACHMENT,
                                         source=models.ObservationSource.TRUSTED_UPSTREAM_INTERFACE, actor="nmas-observer (live LLDP)",
                                         upstream_device=upstream, upstream_interface=port, local_interface=local)
            made[(device, upstream)] = models.DeviceAttachment.objects.get(pk=result.attachment.pk)
        nmas = {}
        for name, interface, upstream, port, source, network, domain in (
                ("fx-oob", "eth1", "MSW1", "Ethernet1", "10.254.40.10", "10.254.40.0/24", "fx-msw1"),
                ("fx-direct", "eth2", "DUT1", "Ethernet3", "10.254.42.2", "10.254.42.0/30", "fx-direct")):
            result = paths.register_nmas_attachment(name=name, host_interface=interface, upstream_device=upstream, upstream_interface=port,
                                                    source_address=source, network=network, failure_domain=domain, actor=L.OPERATOR)
            self.assertTrue(result.ok, result.blockers)
            self.assertTrue(paths.approve_nmas_attachment(result.attachment, actor=L.APPROVER).ok)
            observed = nmas_side.observe_and_record(result.attachment, actor="nmas-observer")     # REAL sysfs / iproute2 read
            self.assertTrue(observed.ok)
            self.assertEqual(observed.attachment.verification_state, models.AttachmentVerification.VERIFIED, observed.attachment.observation)
            nmas[name] = observed.attachment
            record.setdefault("nmas_observations", {})[name] = observed.attachment.observation
        dut = devices["DUT1"]
        fp = fingerprint_of(public("nmas-svc"))
        credential = models.DeviceCredential.objects.create(device_name="DUT1", platform="arista_ceos", username="nmas-svc",
                                                            account_kind=models.AccountKind.SERVICE, auth_method=models.DeviceAuthMethod.PUBLICKEY,
                                                            ssh_key_ref=SVC_REF, ssh_public_key=public("nmas-svc"), ssh_public_key_fingerprint=fp)
        dut_key = host_key("dut")
        record["dut_host_key"] = dut_key
        common = dict(credential_source=models.ManagementCredentialSource.DEVICE_CREDENTIAL, device_credential_id=credential.pk,
                      expected_host_key=dut_key, actor=L.OPERATOR)
        registered = {}
        for label, kwargs in (("oob", dict(path_type=T.DIRECT_OOB, endpoint_address=DUT_SVI, nmas_attachment_id=nmas["fx-oob"].pk,
                                           attachment_id=made[("DUT1", "MSW1")].pk)),
                              ("via-sw1", dict(path_type=T.VLAN_ADJACENT_SWITCH, endpoint_address=DUT_SVI, nmas_attachment_id=nmas["fx-oob"].pk,
                                               attachment_id=made[("DUT1", "SW1")].pk, via_device="SW1", vlan=200)),
                              ("vrf", dict(path_type=T.ROUTED_VRF, endpoint_address=DUT_VRF, nmas_attachment_id=nmas["fx-direct"].pk, vrf="MGMT"))):
            result = paths.register_path(dut, **kwargs, **common)
            self.assertTrue(result.ok, (label, result.blockers))
            self.assertTrue(paths.approve_path(result.path, actor=L.APPROVER).ok)
            registered[label] = result.path
        return dut, registered, nmas

    def _binding(self, conn, selected):
        sock = conn.remote_conn_pre.get_transport().sock
        interface = sock.getsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, 64).rstrip(b"\0").decode()
        local, peer = sock.getsockname(), sock.getpeername()
        self.assertEqual((interface, local[0], peer[0], peer[1]),
                         (selected.nmas_attachment.host_interface, selected.nmas_attachment.source_address,
                          selected.endpoint_address, selected.port))
        return {"interface": interface, "source": local[0], "target": peer[0], "port": peer[1], "path": selected.path_id}

    def _evaluate(self, dut, record, label):
        result = selector.evaluate(dut, actor="nmas-management-selector (live harness)")
        endpoint = resolve.endpoint("DUT1", purpose=resolve.WRITE)
        reach = ""
        binding = None
        if endpoint.source == resolve.PATH:     # a consumer actually uses the resolved endpoint
            try:
                selected = models.ManagementPath.objects.get(pk=int(endpoint.path_id.removeprefix("MPATH-")))
                session = ceos.netmiko_connection({"name": "DUT1"})
                try:
                    binding = self._binding(session, selected)
                    reach = json.loads(session.send_command("show hostname | json"))["hostname"]
                finally:
                    session.disconnect()
            except ceos.ExecutorError as exc:
                reach = f"FAILED:{getattr(exc, 'code', type(exc).__name__)}"
        row = {"step": label, "at": time.strftime("%H:%M:%S"), **result.as_dict(), "endpoint": endpoint.as_dict(),
               "consumer_reached": reach, "consumer_binding": binding}
        record["evaluations"].append(row)
        print(json.dumps({"step": label, "decision": result.decision, "path": result.active_path,
                          "endpoint_source": endpoint.source, "consumer": reach, "binding": binding}), flush=True)
        if result.decision in ("ACTIVATE", "FAILOVER", "FAILBACK"):
            self.assertEqual(reach, "DUT1", row)
            from core.services.health.live import EosSession
            health = EosSession({"name": "DUT1"})
            try:
                self._binding(health._conn, selected)
                self.assertIn("hostname DUT1", health.run("running_config"))
            finally:
                health.close()
            self.assertEqual(nsot_live.fetch_running_config("DUT1")["status"], "available")
        return result, endpoint

    def _until(self, dut, record, label, predicate, attempts=10, pause=2.0):
        for n in range(attempts):
            result, endpoint = self._evaluate(dut, record, f"{label} #{n + 1}")
            if predicate(result, endpoint):
                return result, endpoint
            time.sleep(pause)
        self.fail(f"{label}: condition not reached; last {record['evaluations'][-1]}")

    def test_2_probes_failover_failback_and_switch_failure(self):
        record = {"evaluations": [], "links": []}
        self.addCleanup(lambda: evidence("failover.json", record))      # written even when a step fails
        self.assertIn("vrf instance MGMT", show(DUT_SVI, "dut", "show running-config section vrf"))   # left by test 1
        dut, p, nmas = self._registry(record)
        record["paths"] = {k: {"id": v.path_id, "type": v.path_type, "class": v.preference_class, "endpoint": v.endpoint_address}
                           for k, v in p.items()}

        result, endpoint = self._evaluate(dut, record, "initial")
        self.assertEqual((result.decision, result.active_path), ("ACTIVATE", p["oob"].path_id))
        self.assertTrue(all(v.get("passed") for v in result.probes.values()), result.probes)
        from core.services.management import ssh_transport
        for label, interface, source, address in (
                ("invalid_interface", "fx-missing0", "10.254.42.2", DUT_VRF),
                ("invalid_source", "eth2", "10.254.42.99", DUT_VRF),
                ("invalid_route", "eth2", "10.254.42.2", DUT_SVI)):
            invalid = SimpleNamespace(endpoint_address=address, port=22,
                                      nmas_attachment=SimpleNamespace(host_interface=interface, source_address=source))
            with self.assertRaises(ssh_transport.ManagedConnectionRejected) as rejected:
                ssh_transport.bound_socket(invalid, 1)
            record.setdefault("negative_bound_transport", {})[label] = rejected.exception.args[0]

        def link(action, name):
            fixture(action, name)
            record["links"].append({"at": time.strftime("%H:%M:%S"), "action": action, "link": name})

        # 1 -> 2: the direct out-of-band link fails (MSW1 side of DUT1 Ethernet1); STP unblocks DUT1 Ethernet2
        link("fail", "oob")
        result, endpoint = self._until(dut, record, "oob down", lambda r, e: r.active_path == p["via-sw1"].path_id)
        self.assertEqual(result.decision, "FAILOVER")
        oob_degraded = [e for e in record["evaluations"] if e["step"].startswith("oob down") and e["decision"] == "NONE"]
        self.assertTrue(oob_degraded, "hysteresis: at least one evaluation below the threshold kept the active path")
        self.assertTrue(all(e["endpoint"]["source"] == resolve.BLOCKED and not e["consumer_reached"] for e in oob_degraded))
        record["stp_after_oob_failure"] = show(DUT_VRF, "dut", "show spanning-tree interface Ethernet2")

        # 2 -> 3: the adjacent-switch link fails too; only the routed VRF over NMAS's second attachment remains
        link("fail", "via-sw1")
        result, endpoint = self._until(dut, record, "via-sw1 down", lambda r, e: r.active_path == p["vrf"].path_id)
        self.assertEqual((result.decision, endpoint.address, endpoint.vrf), ("FAILOVER", DUT_VRF, "MGMT"))

        # management-switch failure: every MSW1 port down; management continues over the independent attachment
        link("fail", "msw")
        result, endpoint = self._until(dut, record, "msw down", lambda r, e: r.active_path == p["vrf"].path_id and r.decision == "NONE",
                                       attempts=3)
        record["spof_during_msw_failure"] = nmas_side.spof_report()
        self.assertTrue(record["spof_during_msw_failure"]["management_switch_failure_tolerant"])
        record["nmas_observation_during_msw_failure"] = nmas_side.observe_interface("eth1", "10.254.40.10")

        # restore everything: restore threshold, then hold-down, then failback to class 1
        for name in ("msw", "via-sw1", "oob"):
            link("restore", name)
        result, endpoint = self._until(dut, record, "restored", lambda r, e: r.decision in ("HOLD_DOWN", "FAILBACK"), attempts=15)
        if result.decision == "HOLD_DOWN":
            record["hold_down_observed"] = True
            state = selector.state_for(dut)
            remaining = max(0.0, (state.failback_not_before - timezone.now()).total_seconds())
            time.sleep(remaining + 1)
            result, endpoint = self._until(dut, record, "after hold-down", lambda r, e: r.decision == "FAILBACK", attempts=5)
        self.assertEqual(result.active_path, p["oob"].path_id)
        record["transitions"] = [{"kind": t.kind, "from": t.from_path.path_id if t.from_path_id else "", "to": t.to_path.path_id if t.to_path_id else "",
                                  "reason": t.reason_code, "at": t.created_at.isoformat()}
                                 for t in models.ManagementPathTransition.objects.filter(device=dut).order_by("id")]
        changes = list(models.ManagementPathTransition.objects.filter(device=dut).order_by("id"))
        last_failover = next(t for t in reversed(changes) if t.kind == "FAILOVER")
        failback = next(t for t in changes if t.kind == "FAILBACK")
        record["failback_elapsed_seconds"] = (failback.created_at - last_failover.created_at).total_seconds()
        self.assertGreaterEqual(record["failback_elapsed_seconds"], 30)
        record["probe_rows"] = models.ManagementPathProbe.objects.filter(device=dut).count()

        # live negatives: an impostor host key is refused at layer 5 before any credential is offered; a revoked path is never
        # contacted; the Containerlab network cannot be registered as an NMAS attachment.  An equivalent live path is refused as a
        # duplicate, so the real routed-VRF path (no longer active after failback) is revoked before the impostor is registered.
        kwargs = dict(path_type=T.ROUTED_VRF, endpoint_address=DUT_VRF, nmas_attachment_id=nmas["fx-direct"].pk, vrf="MGMT",
                      credential_source=models.ManagementCredentialSource.DEVICE_CREDENTIAL,
                      device_credential_id=p["vrf"].device_credential_id, expected_host_key="SHA256:" + "Z" * 43,
                      actor=L.OPERATOR, reason="live negative: wrong pinned key")
        duplicate = paths.register_path(dut, **kwargs)
        record["negative_duplicate_path"] = duplicate.codes
        self.assertIn("MGMT_PATH_DUPLICATE", duplicate.codes)
        revoked = paths.revoke_path(p["vrf"], actor=L.APPROVER, reason="live negative setup")
        self.assertTrue(revoked.ok, revoked.blockers)
        impostor = paths.register_path(dut, **kwargs)
        self.assertTrue(impostor.ok, impostor.blockers)
        paths.approve_path(impostor.path, actor=L.APPROVER)
        report, _row, _ = probes.probe(impostor.path, actor="live harness")
        record["negative_wrong_host_key"] = {"failure_code": report.failure_code, "highest_layer": report.highest_layer,
                                             "presented": report.presented_host_key}
        self.assertEqual(report.failure_code, "L5_HOST_KEY_MISMATCH")
        paths.revoke_path(impostor.path, actor=L.APPROVER, reason="live negative done")
        impostor.path.refresh_from_db()
        _report, _row, refusals = probes.probe(impostor.path, actor="live harness")
        record["negative_revoked_path"] = [b["code"] for b in refusals]
        self.assertEqual(record["negative_revoked_path"], ["PROBE_TARGET_FORBIDDEN"])
        clab = paths.register_nmas_attachment(name="fx-clab", host_interface="eth1", upstream_device="MSW1", source_address="172.20.20.50",
                                              network="172.20.20.0/24", actor=L.OPERATOR)
        record["negative_containerlab_attachment"] = clab.codes
        self.assertIn("MGMT_ENDPOINT_FORBIDDEN", clab.codes)
        active = paths.revoke_path(p["oob"], actor=L.APPROVER, reason="live no-fallback proof", acknowledge_active=True)
        self.assertTrue(active.ok, active.codes)
        self.assertEqual(resolve.endpoint("DUT1", purpose=resolve.WRITE).source, resolve.BLOCKED)
        with self.assertRaises(ceos.ExecutorError) as blocked:
            ceos.netmiko_connection({"name": "DUT1"})
        record["negative_no_legacy_fallback"] = blocked.exception.code
        for remaining in models.ManagementPath.objects.filter(device=dut, approval_state=models.ManagementApproval.APPROVED):
            revoked = paths.revoke_path(remaining, actor=L.APPROVER, reason="live revoke all paths")
            self.assertTrue(revoked.ok, revoked.codes)
        self.assertFalse(models.ManagementPath.objects.filter(device=dut).exclude(approval_state=models.ManagementApproval.REVOKED).exists())
        self.assertEqual(resolve.endpoint("DUT1", purpose=resolve.WRITE).source, resolve.BLOCKED)
        with self.assertRaises(ceos.ExecutorError) as all_revoked:
            ceos.netmiko_connection({"name": "DUT1"})
        record["negative_all_paths_revoked_no_legacy_fallback"] = all_revoked.exception.code
        record["result"] = "PASS"


@unittest.skipUnless(LIVE, "live fixture harness: set NMAS_MGMT_LIVE_FIXTURE=1 and run inside the fixture's NMAS namespace")
class LiveBootstrapRetirement(BcredMixin, TestCase):
    """The Phase-3 enrollment session (DB only, fake DHCP / verification inputs) whose provider-held enrollment key the
    harness installs on DUT1 as ``nmas-enroll``; then the REAL state machine replaces it with ``nmas-ops`` and retires it."""

    def setUp(self):
        super().setUp()
        from modules import device_credentials

        real_loader = device_credentials.load_ssh_private_key
        patcher = mock.patch.object(device_credentials, "load_ssh_private_key",
                                    side_effect=lambda reference, path=None: real_loader(reference, path=RUNTIME / "nmas-provider" / "store.json"))
        patcher.start()
        self.addCleanup(patcher.stop)

    def _users(self) -> str:
        return show(DUT_SVI, "dut", B.USERS, user="fixture-admin", keyname="fixture-admin")

    def test_bootstrap_credential_retirement_complete_only_after_device_proof(self):
        record = {"fixture_step": "fixture-admin installs the session's enrollment public key as nmas-enroll (stands in for the "
                                  "Phase-3 delivered artifact; live ZTP is Phase 3's evidence)"}
        admin = cli(DUT_SVI, "fixture-admin", "fixture-admin", "dut")
        try:
            admin.configure(["configure", f"username nmas-enroll privilege 15 role network-admin secret {os.urandom(18).hex()}",
                             f"username nmas-enroll ssh-key {self.session.enrollment_public_key.strip()}", "end"])
        finally:
            admin.close()
        dut_key = host_key("dut")
        pinned = self.session.enrolled_host_key

        def connect(*, address, port, username, pkey, expected_host_key):
            # the synthetic session pins a synthetic key / address: substitute DUT1's REAL address and out-of-band host key
            self.assertEqual(expected_host_key, pinned)
            from core.services.management import ssh_transport
            path = SimpleNamespace(endpoint_address=DUT_SVI, port=22,
                                   nmas_attachment=SimpleNamespace(host_interface="eth1", source_address="10.254.40.10"))
            sock = ssh_transport.bound_socket(path, ssh.CONNECT_TIMEOUT)
            return ssh.connect(address=DUT_SVI, port=22, username=username, pkey=pkey, expected_host_key=dut_key, sock=sock)

        private, public_line, fp = workflow.generate_enrollment_key(("ssh-ed25519",), "nmas-ops@DUT1")
        store = fixture_store()
        store.initialize(OPS_REF, private, replace=True)
        del private
        credential = self.service_credential("nmas-ops", ssh_key_ref=OPS_REF, ssh_public_key=public_line, ssh_public_key_fingerprint=fp)
        planned = B.plan(self.device, replacement_credential_id=credential.pk, actor=L.OPERATOR, reason="live fixture retirement")
        self.assertTrue(planned.ok, planned.codes)
        approved = B.approve(planned.transition, actor=L.APPROVER, digest=planned.transition.binding_digest)
        self.assertTrue(approved.ok, approved.codes)
        transition = approved.transition
        bootstrap_key = B._Keys.bootstrap(transition)          # kept in memory only, for the independent re-proof below
        before = connect(address="", port=22, username="nmas-enroll", pkey=bootstrap_key, expected_host_key=pinned)
        before.close()
        record["transport"] = {"interface": "eth1", "source": "10.254.40.10", "target": DUT_SVI, "host_key_pinned": True}
        record["before"] = {"bootstrap_login": "ACCEPTED", "accounts": sorted({line.split()[1] for line in self._users().splitlines()
                                                                               if line.startswith("username ")})}
        result = B.execute(transition, actor="nmas-automation (live harness)", connect=connect)
        transition.refresh_from_db()
        record["status"] = B.status(transition)
        self.assertTrue(result.ok, (result.codes, transition.steps))
        self.assertEqual(transition.state, models.BootstrapCredentialState.COMPLETE)
        users = self._users()
        record["after"] = {"accounts": sorted({line.split()[1] for line in users.splitlines() if line.startswith("username ")}),
                           "replacement_key_installed": any(line.startswith("username nmas-ops ssh-key") and public_line.split()[1] in line
                                                            for line in users.splitlines())}
        self.assertNotIn("nmas-enroll", record["after"]["accounts"])
        self.assertTrue(record["after"]["replacement_key_installed"])
        with self.assertRaises(ssh.CliError) as caught:      # independent re-proof: the device rejects the bootstrap key
            connect(address="", port=22, username="nmas-enroll", pkey=bootstrap_key, expected_host_key=pinned)
        record["after"]["bootstrap_login"] = caught.exception.code
        self.assertEqual(caught.exception.code, "AUTH_FAILED")
        ops = connect(address="", port=22, username="nmas-ops", pkey=fixture_store_key(OPS_REF), expected_host_key=pinned)
        record["after"]["replacement_login_hostname"] = json.loads(ops.show("show hostname | json"))["hostname"]
        record["after"]["configuration_sessions"] = ops.show("show configuration sessions")
        ops.close()
        self.assertFalse(self.secret_present())
        record["after"]["enrollment_secret_in_provider"] = "ABSENT"
        evidence("bootstrap-retirement.json", record)
        # fixture tidy-up (not NMAS): remove the replacement account so the fixture can be rerun
        admin = cli(DUT_SVI, "fixture-admin", "fixture-admin", "dut")
        try:
            admin.configure(["configure", "no username nmas-ops", "end"])
        finally:
            admin.close()


def fixture_store_key(reference):
    from modules.device_credentials import load_ssh_private_key

    return load_ssh_private_key(reference)
