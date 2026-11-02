"""V2 Phase 9 LIVE harness -- DHCP relay option 82 as a governed change, then native downstream ZTP that trusts only NMAS's read-back.

NOT part of any automated suite (the module name does not match ``test*.py``).  It reuses the isolated Phases 5+6 fixture with
the relay UP1 started WITHOUT option 82, and the Phases 5+6 harness for the shared stages:

    NMAS_ISO_FX_UP1_OPTION82=off labs/isolation-commissioning-isolated/fixture.sh up
    labs/isolation-commissioning-isolated/run-harness.sh migrate
    NMAS_LIVE_MODULE=core.tests.live_option82_ztp_fixture NMAS_ISO_LIVE_EVIDENCE=<dir> \\
        labs/isolation-commissioning-isolated/run-harness.sh prepare isolate o82-gate o82-fault o82-apply o82-forged ztp o82-verify report

    prepare / isolate   the Phases 5+6 stages: UP1 adopted, NEW1 registered + attached on UP1:Ethernet1, bootstrap network,
                        trusted isolation of the port enforced and verified with the hostile probe on it
    o82-gate            NEW1's bootstrap path is BLOCKED without a read-back (RELAY_READBACK_MISSING); a read-only refresh over
                        NMAS's SSH session reads option 82 off -> still BLOCKED (RELAY_UNTRUSTED); nothing written to UP1
    o82-fault           a governed option 82 change whose run is broken after its first statement: compensated, UP1's
                        configuration digest equals the pre-change digest, no read-back recorded
    o82-apply           the option 82 intent from a Device Builder revision of UP1 (relay on Ethernet1 + ``set_dhcp_relay_option82``)
                        -> plan -> precheck -> refused self-approval -> approval -> execute through CeosExecutor over SSH ->
                        read-back postcheck -> the postcheck read-back recorded; the bootstrap path now PASSES
    o82-forged          the hostile probe on the port sends DHCP requests through UP1 with and without its own option 82
                        (circuit "Ethernet9"); captured at the bootstrap service: giaddr + the circuit id that arrived; NMAS's
                        discovery gate accepts the relay-inserted circuit and refuses the forged one (OPTION82_CIRCUIT_FORGED)
    ztp                 the Phases 5+6 native ZTP stage: NEW1 boots factory default behind UP1, its native DHCP request is
                        relayed with option 82, NMAS's ISC policy matches giaddr AND circuit id, discovery correlates, delivery,
                        first contact, host-key enrollment, management verification (captured at the bootstrap service)
    o82-verify          the lease observation(s): CORRELATED through the trusted relay with the relay-inserted circuit id
    report              the evidence index

Every UP1 change is NMAS's (the governed transaction through its cEOS executor); the fixture console is used only to observe.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import time

from django.utils import timezone

from core import models
from core.tests import live_isolation_commissioning_fixture as P56
from core.tests.live_isolation_commissioning_fixture import APPROVER, EXECUTOR, NET_A, OPERATOR, SERVICE, cli, evidence, fixture

PORT, GIADDR, FORGED = "Ethernet1", "10.254.60.1", "Ethernet9"
CAPTURE_FILE = P56.RUNTIME / "o82-ztp-relayed-requests.json"      # runtime/ is git-ignored


def config_digest(node: str) -> str:
    """The fixture console's view of a node's configuration (comment and banner lines dropped): an independent vantage point."""
    from core.services import dhcp_relay_option82 as o82

    return o82.config_digest(P56.scrub(cli(node, "show running-config")))


def option82_hex(circuit: str) -> str:
    """A client-built option 82 (sub-option 1, circuit id) as busybox udhcpc's ``-x 0x52:<hex>`` value."""
    raw = bytes([1, len(circuit)]) + circuit.encode()
    return "0x52:" + raw.hex()


class Capture:
    """tcpdump of DHCP on the bootstrap service's link (this namespace): what the relay actually sent."""

    def __init__(self, seconds: int):
        self.proc = subprocess.Popen(["sudo", "-n", "timeout", str(seconds), "tcpdump", "-nn", "-vv", "-l", "-i", "eth1", "udp", "port", "67"],
                                     stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        time.sleep(2)

    def stop(self) -> str:
        subprocess.run(["sudo", "-n", "pkill", "-INT", "-f", "tcpdump -nn -vv -l -i eth1 udp port 67"], check=False)
        out, _ = self.proc.communicate(timeout=30)
        return out or ""


def relayed_requests(text: str) -> list[dict]:
    """Per relayed DHCP request: client MAC, giaddr and the option 82 circuit id that reached the service."""
    rows = []
    for packet in re.split(r"\n(?=\d\d:\d\d:\d\d\.\d+ )", text or ""):
        if "BOOTP/DHCP, Request" not in packet:
            continue
        gateway = re.search(r"Gateway-IP (\S+)", packet)
        circuit = re.search(r"Circuit-ID SubOption 1, length \d+: (\S+)", packet)
        client = re.search(r"Client-Ethernet-Address (\S+)", packet)
        kind = re.search(r"DHCP-Message \(53\), length 1: (\w+)", packet)
        rows.append({"client_mac": client.group(1) if client else "", "giaddr": gateway.group(1) if gateway else "",
                     "circuit_id": circuit.group(1) if circuit else "", "agent_information": "Agent-Information" in packet,
                     "message_type": kind.group(1) if kind else ""})
    return rows


class Run(P56.Harness):
    def __init__(self):
        super().__init__()
        self.ztp_capture = None

    def gate(self) -> dict:
        from core.services.ztp import dependencies

        new1 = self.device("NEW1")
        checks = {c["check"]: c for c in dependencies.evaluate(new1, self.attachment(new1, "UP1"), self.network(NET_A["name"]))}
        return checks.get("bootstrap_path_option82") or {"check": "bootstrap_path_option82", "ok": None, "code": "NOT_EVALUATED"}

    def intent(self):
        """UP1's option 82 intent from a Device Builder revision (the operator's intent; the relay sits on Ethernet1)."""
        from core.services import change_service, service_policy_intent_service as spis
        from core.services.ztp import relay_option82
        from core.tests.helpers.validation import Dev

        change = change_service.create_change(title="UP1 Device Builder: DHCP relay option 82 on Ethernet1", created_by=OPERATOR,
                                              description="V2 Phase 9 live: the relay side of NEW1's native ZTP")
        dev = Dev(change, "UP1", platform=models.Platform.ARISTA_CEOS)
        relay = dev.relay(dev.iface(PORT), SERVICE)
        spis.set_dhcp_relay_option82(revision=dev.revision, relay_id=relay["id"])
        dev.revision.refresh_from_db()
        return relay_option82.intent_from_revision(dev.revision, relay["id"]), {"revision": str(dev.revision.pk), "relay": relay["id"]}

    def planned(self, record: dict, key: str):
        from core.services.ztp import relay_option82

        intent, source = self.intent()
        planned = relay_option82.plan(device="UP1", intent=intent, actor=OPERATOR, network=self.network(NET_A["name"]), source=source)
        record[key] = {"ok": planned.ok, "codes": planned.codes, "intent": intent.__dict__, "source": source,
                       "plan_hash": planned.detail.get("plan_hash"), "operations": planned.detail.get("operations"),
                       "prior": planned.detail.get("prior"), "change": planned.change.change_id if planned.change else ""}
        assert planned.ok and planned.change is not None, planned.codes
        return planned

    # =========================================================================================================================
    def stage_o82_gate(self):
        from core.services.ztp import relay_option82

        before = config_digest("up")
        record = {"required_for_UP1": relay_option82.required_for("UP1"), "gate_without_readback": self.gate()}
        assert record["gate_without_readback"]["code"] == "RELAY_READBACK_MISSING", record
        refreshed = relay_option82.refresh("UP1", actor=OPERATOR)
        record["refresh"] = {"ok": refreshed.ok, "codes": refreshed.codes}
        assert refreshed.ok, refreshed.codes
        row = models.DhcpRelayReadback.objects.get(pk=refreshed.detail["readback"])
        record["readback"] = {"source": row.source, "enabled": row.readback.get("enabled"), "port": row.readback["interfaces"].get(PORT)}
        record["gate_with_option82_off"] = self.gate()
        assert record["gate_with_option82_off"]["code"] == "RELAY_UNTRUSTED", record
        record["up1_digest_unchanged"] = config_digest("up") == before
        assert record["up1_digest_unchanged"]
        evidence("o82-10-gate.json", record)

    def stage_o82_fault(self):
        from core.services.ztp import relay_option82

        record = {}
        before = config_digest("up")
        planned = self.planned(record, "plan")
        approved = relay_option82.approve(planned.change, actor=APPROVER, confirmation=planned.detail["plan_hash"])
        assert approved.ok, approved.codes

        def observer(event, key):
            if (event, key) == ("after", "global"):
                raise ConnectionResetError("injected: the session dropped after the first statement")

        done = relay_option82.execute(planned.change, actor=EXECUTOR, confirmation=planned.detail["plan_hash"], observer=observer)
        report = done.detail.get("report") or {}
        record["execute"] = {"ok": done.ok, "outcome": done.detail.get("outcome"), "codes": done.codes,
                             "compensation": report.get("compensation"), "failure": report.get("failure")}
        record["up1_digest_restored"] = config_digest("up") == before
        record["readbacks_recorded"] = models.DhcpRelayReadback.objects.filter(change=planned.change).count()
        record["up1_option82_section"] = cli("up", "show running-config | include dhcp relay information")
        assert not done.ok and record["up1_digest_restored"] and record["readbacks_recorded"] == 0, record
        evidence("o82-20-fault-compensated.json", record)

    def stage_o82_apply(self):
        from core.services.ztp import relay_option82

        record = {}
        before = config_digest("up")
        planned = self.planned(record, "plan")
        change = planned.change
        record["precheck"] = relay_option82.precheck(change, actor=OPERATOR).codes
        record["self_approval"] = relay_option82.approve(change, actor=OPERATOR, confirmation=planned.detail["plan_hash"]).codes
        record["wrong_hash"] = relay_option82.approve(change, actor=APPROVER, confirmation="0" * 64).codes
        approved = relay_option82.approve(change, actor=APPROVER, confirmation=planned.detail["plan_hash"])
        assert approved.ok, approved.codes
        done = relay_option82.execute(change, actor=EXECUTOR, confirmation=planned.detail["plan_hash"])
        report = done.detail.get("report") or {}
        record["execute"] = {"ok": done.ok, "outcome": done.detail.get("outcome"), "codes": done.codes, "steps": report.get("steps")}
        assert done.ok, record["execute"]
        row = models.DhcpRelayReadback.objects.get(pk=done.detail["readback"])
        record["readback"] = {"source": row.source, "change": change.change_id, "run": row.run_id, "enabled": row.readback.get("enabled"),
                              "port": row.readback["interfaces"].get(PORT)}
        record["configlets"] = [{"cfg_id": c.cfg_id, "object_type": c.desired_state_ref["source"]["object_type"], "lines": c.rendered_config.splitlines(),
                                 "rollback": c.rollback_config.splitlines()} for c in change.plans.order_by("-id").first().configlets.order_by("sequence")]
        record["up1_option82_section"] = cli("up", "show running-config | include dhcp relay information")
        record["up1_digest_changed"] = config_digest("up") != before
        record["gate_after"] = self.gate()
        assert record["gate_after"]["ok"] is True, record["gate_after"]
        change.refresh_from_db()
        record["change_state"] = change.lifecycle_state
        evidence("o82-30-governed-apply.json", record)

    def stage_o82_forged(self):
        from core.services.ztp import relay_option82

        capture = Capture(60)
        attempts = {}
        for label, extra in (("probe without option 82", []), (f"probe with its own option 82 circuit {FORGED}", ["-x", option82_hex(FORGED)])):
            done = subprocess.run(["docker", "exec", "nmas-iso-p56-probe-a", "udhcpc", "-i", "eth1", "-n", "-q", "-f", "-t", "2", "-T", "2",
                                   "-s", "/bin/true", *extra], capture_output=True, text=True, timeout=60, check=False)
            attempts[label] = {"lease_obtained": done.returncode == 0,
                               "output": [line for line in (done.stdout + done.stderr).splitlines() if "udhcpc" in line][-4:]}
        relayed = relayed_requests(capture.stop())
        rows = []
        for row in relayed:
            rows.append({**row, "nmas_discovery_gate": relay_option82.lease_problem("UP1", row["giaddr"], row["circuit_id"]) or "TRUSTED"})
        record = {"attempts": attempts, "relayed_requests": rows,
                  "meaning": "the gate is NMAS's discovery check (ztp.discovery.fold -> relay_option82.lease_problem) applied to the "
                             "giaddr and circuit id that reached the bootstrap service; no lease is offered to the probe (no session "
                             "reserves its port), so no lease file entry exists to fold"}
        inserted = [r for r in rows if r["circuit_id"] == PORT]
        forged = [r for r in rows if r["circuit_id"] == FORGED]
        assert inserted and all(r["giaddr"] == GIADDR and r["nmas_discovery_gate"] == "TRUSTED" for r in inserted), rows
        assert forged and all(r["giaddr"] == GIADDR and r["nmas_discovery_gate"] == "OPTION82_CIRCUIT_FORGED" for r in forged), rows
        assert not any(a["lease_obtained"] for a in attempts.values()), attempts
        evidence("o82-40-forged-option82.json", record)

    def stage_ztp(self):
        capture = Capture(1500)
        try:
            super().stage_ztp()
        finally:
            text = capture.stop()
        # every request the relay sent during ZTP (the probe link now belongs to NEW1: nothing else is on bootstrap port A); kept in
        # runtime/ so o82-verify can run in a later invocation.  NEW1 is matched by the hardware address of its correlated lease
        # (cEOS sends DHCP from the Ethernet1 MAC, not from its system MAC, which travels only as the client identifier)
        self.ztp_capture = relayed_requests(text)
        CAPTURE_FILE.write_text(json.dumps(self.ztp_capture, indent=1))
        CAPTURE_FILE.with_suffix(".txt").write_text(text)                    # the raw decode, for review (runtime/ only)

    def stage_o82_verify(self):
        from core.services.ztp import relay_option82, workflow

        new1 = self.device("NEW1")
        session = models.ZtpSession.objects.filter(device=new1).order_by("-id").first()
        leases = [{"address": o.address, "relay": o.relay_address, "circuit_id": o.circuit_id, "relay_trusted": o.relay_trusted,
                   "upstream": f"{o.upstream_device}:{o.upstream_interface}", "outcome": o.outcome, "code": o.code}
                  for o in models.DhcpLeaseObservation.objects.filter(network=self.network(NET_A["name"])).order_by("id")]
        record = {"lease_observations": leases,
                  "session": workflow.status(session) if session else None,
                  "readbacks": [{"source": r.source, "change": r.change.change_id if r.change else "", "enabled": r.readback.get("enabled"),
                                 "captured_at": r.captured_at} for r in models.DhcpRelayReadback.objects.filter(device="UP1").order_by("id")],
                  "trusted_readback_now": relay_option82.trusted_readback("UP1") is not None}
        assert any(lease["outcome"] == models.DhcpLeaseOutcome.CORRELATED and lease["circuit_id"] == PORT and lease["relay_trusted"]
                   for lease in leases), leases
        correlated = models.DhcpLeaseObservation.objects.filter(network=self.network(NET_A["name"]), outcome=models.DhcpLeaseOutcome.CORRELATED,
                                                                device=new1).order_by("id").first()
        captured = self.ztp_capture if self.ztp_capture is not None else json.loads(CAPTURE_FILE.read_text())
        mine = [r for r in captured if correlated is not None and r["client_mac"].lower() == correlated.client_mac.lower()]
        # a relayed message has the relay's giaddr; the only message NEW1 may send the server directly (unicast, giaddr 0, no relay
        # and so no option 82) is the DHCPRELEASE cEOS sends after applying its bootstrap.  Anything else unrelayed fails the run.
        relayed = [r for r in mine if r["giaddr"]]
        direct = [r for r in mine if not r["giaddr"]]
        record.update({"new1_dhcp_hardware_address": correlated.client_mac if correlated else "", "new1_relayed_requests": relayed,
                       "new1_direct_to_server": direct, "requests_captured_total": len(captured)})
        assert relayed and all(r["circuit_id"] == PORT and r["giaddr"] == GIADDR and r["agent_information"] for r in relayed), mine
        assert all(r["message_type"] == "Release" and not r["agent_information"] for r in direct), direct
        assert session is not None and session.stage in (models.ZtpSessionStage.MANAGEMENT_VERIFIED, models.ZtpSessionStage.BOOTSTRAPPED), \
            session and session.stage
        evidence("o82-50-native-ztp.json", record)

    def stage_report(self):
        files = sorted(p.name for p in P56.EVIDENCE.iterdir()) if P56.EVIDENCE.exists() else []
        evidence("o82-99-index.json", {"finished": timezone.now().isoformat(), "files": files,
                                       "fixture": "labs/isolation-commissioning-isolated (cEOS 4.36.2F, ISC dhcpd), UP1 started without option 82",
                                       "transport": "CeosExecutor over SSH as nmas-svc (key only, pinned host key) from the bootstrap-service namespace"})


STAGES = ("prepare", "isolate", "o82-gate", "o82-fault", "o82-apply", "o82-forged", "ztp", "o82-verify", "report")


def main():
    stages = os.environ.get("NMAS_ISO_LIVE_STAGES", "").split()
    unknown = [s for s in stages if s not in STAGES]
    if not stages or unknown:
        raise SystemExit(f"stages: {' '.join(STAGES)} (unknown: {unknown})")
    harness = Run()
    try:
        for stage in stages:
            print(f"[stage] {stage}", flush=True)
            getattr(harness, "stage_" + stage.replace("-", "_"))()
    finally:
        if harness.http is not None:
            harness.http.shutdown()
