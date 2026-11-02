"""V2 Phases 5 + 6 LIVE harness -- trusted-upstream isolation, native ZTP behind it, governed commissioning and controlled
production admission of a factory-default cEOS, plus the downstream (R4 -> R6 -> R7 analogue) rehearsal, against the
disposable fixture ``labs/isolation-commissioning-isolated/fixture.sh``.

NOT part of any automated suite (the module name does not match ``test*.py``).  ``run-harness.sh`` runs it inside the
fixture's bootstrap-service namespace with ``settings_fixture`` (a fresh migrated SQLite database, enrollment store and DHCP
provider root under the git-ignored ``runtime/``).  The NMAS state persists in that database between stages:

    prepare      capability evidence, UP1 adopted, NEW1 registered + attached (UP1:Ethernet1, routed), bootstrap network
    isolate      isolation policy for bootstrap port A: require -> plan -> precheck -> approve -> apply -> verify, with the
                 hostile PROBE namespace on the port (traffic matrix + deny counters), BEFORE any untrusted device exists
    ztp          independent authorization, ZTP session, DHCP policy applied in the fixture service, NEW1 booted factory
                 default on the port, delivery + lease folding, first contact, out-of-band host-key enrollment, verification
    onboard      verification with the device present (ARP on the enforced port + device-originated flows), ISOLATE,
                 identity verified, bootstrap credential retired (live BCRED)
    commission   commissioning through the ordinary ProvisioningRun + Change: readiness, refused approvals, approval, the
                 generic execution engine writes NEW1, postcheck; isolation still enforced (no adjacency, no leaked route)
    downstream-early   NEW2 registered: attachment on NEW1 and isolation refused while NEW1 is not admitted; declared
                 dependency unmet
    admit-fail   an admission whose verification cannot pass: released, verification fails, isolation restored
                 (digest-verified) and re-verified
    admit        the admission: released, OSPF FULL, routes and reachability verified, ADMITTED / IN_SERVICE, outbox,
                 production traffic now flows
    downstream   retry after upstream readiness: NEW2 attachment on NEW1 accepted, isolation of NEW1:Ethernet2 with the
                 hostile probe B, NEW2 authorization and ZTP eligibility
    report       the evidence index

What is real and what is substituted (the evidence README states the same):

* REAL: cEOSLab 4.36.2F devices, their CLI and forwarding; the veth links; ISC dhcpd in the service container; the NMAS ZTP
  delivery server (in this process); every SSH session (pinned host key, key-only); the cEOS executor, the isolation
  transaction, the provisioning run and the generic execution engine writing NEW1; OSPF; the traffic flows (sent from the
  fixture namespaces / the device itself, never by NMAS).
* SUBSTITUTED: the NMAS database is the fixture SQLite file; ``inventory.yml`` is a fixture inventory listing only UP1; the
  device-secret provider is a fixture store under ``runtime/``; NetBox is the provisioning tests' in-memory gateway, or -- with
  ``NMAS_ISO_LIVE_NETBOX_ENV`` -- the real ``ipam.NetboxGateway`` against the disposable NetBox of
  ``labs/managed-scope-isolated/netbox.sh`` (PR #69 stages ``scope-pre`` / ``scope`` / ``probation``); the
  validation sources are the fixture NetBox model; the Prometheus snapshot of the precheck is the health tests' synthetic
  one; Slack notification is the engine tests' recorder; the Phase-4 capability evidence for arista_ceos is copied, read-only,
  from the deployed NMAS database (no capability is asserted by this harness).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import sqlite3
import subprocess
import time
from pathlib import Path
from unittest import mock

import yaml
from django.conf import settings
from django.utils import timezone

from core import models

REPO = Path(settings.REPO_ROOT)
FX = REPO / "labs" / "isolation-commissioning-isolated"
RUNTIME = FX / "runtime"
EVIDENCE = Path(os.environ.get("NMAS_ISO_LIVE_EVIDENCE") or RUNTIME / "evidence")
# the capability authority is copied from the deployed database, opened read-only (mode=ro); never written
DEPLOYED_DB = Path(os.environ.get("NMAS_ISO_LIVE_DEPLOYED_DB", "/home/student/Scripts/clab_dualstack_lab-deploy/web/db.sqlite3"))
OPERATOR, APPROVER, EXECUTOR, OTHER = "olivia", "arthur", "erin", "oscar"
SVC_REF = "runtime://device-credentials/fx-iso-nmas-svc"
NEW1_REF = "runtime://device-credentials/fx-iso-new1-svc"
UNUSED_REF = "runtime://device-credentials/fx-iso-unused"
UP1_ADDRESS, SERVICE, HTTP_PORT = "10.254.255.1", "10.254.61.2", 8080   # UP1 managed on its loopback (never on the service link)
PROD_V4, PROD_V6 = "10.254.63.10", "2001:db8:254:63::10"
NEW1_SERIAL, NEW1_MAC = "ISOP56NEW1", "02:5a:76:00:00:11"
NEW2_SERIAL, NEW2_MAC = "ISOP56NEW2", "02:5a:76:00:00:12"
NEW1_LOOPBACK, NEW1_ROUTER_ID, NEW1_DOWNSTREAM = "10.254.255.11/32", "10.254.255.11", "10.254.64.1/24"
NET_A = {"name": "iso-boot-a", "ipv4_prefix": "10.254.60.0/24", "gateway": "10.254.60.1", "pool_start": "10.254.60.10",
         "pool_end": "10.254.60.20", "service_prefix": "10.254.61.0/30", "service_address": SERVICE}
NET_B = {"name": "iso-boot-b", "ipv4_prefix": "10.254.64.0/24", "gateway": "10.254.64.1", "pool_start": "10.254.64.10",
         "pool_end": "10.254.64.20", "service_prefix": "10.254.61.0/30", "service_address": SERVICE}


# --- fixture plumbing ----------------------------------------------------------------------------------------------------------
def fixture(*args, check=True, timeout=120) -> subprocess.CompletedProcess:
    return subprocess.run([str(FX / "fixture.sh"), *args], check=check, capture_output=True, text=True, timeout=timeout)


def cli(node: str, command: str) -> str:
    """The fixture's out-of-band console (``docker exec Cli``): observation and hostile-device emulation only."""
    return fixture("cli", node, command, check=False).stdout


def fingerprint_of(public_line: str) -> str:
    blob = base64.b64decode(public_line.split()[1])
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def evidence(name: str, payload) -> None:
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    text = payload if isinstance(payload, str) else json.dumps(payload, indent=2, sort_keys=True, default=str)
    for marker in ("PRIVATE KEY", "secret sha512", "$6$"):
        assert marker not in text, f"evidence {name} would carry secret material ({marker})"
    (EVIDENCE / name).write_text(text + ("\n" if not text.endswith("\n") else ""), encoding="utf-8")
    print(f"[evidence] {name}")


def scrub(text: str) -> str:
    """Running configurations without account lines (hashes / keys)."""
    return "\n".join(line for line in (text or "").splitlines() if not line.startswith("username ") and "secret" not in line)


def running(node: str) -> str:
    return scrub(cli(node, "show running-config"))


def wait_for(predicate, *, timeout=120, step=3.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(step)
    return None


def fixture_inventory() -> dict:
    with open(REPO / "inventory.yml", encoding="utf-8") as handle:
        document = yaml.safe_load(handle) or {}
    document["network_devices"] = {
        "UP1": {"username": "nmas-svc", "ssh_key_ref": SVC_REF, "credential_ref": UNUSED_REF,
                "monitoring": {"platform": "ceos", "address": UP1_ADDRESS, "source_interface": "Loopback0"}}}
    document["management"] = {**(document.get("management") or {}), "nmas_ipv4": f"{SERVICE}/30"}
    document["hosts"] = {}
    return document


class Harness:
    """Process-wide redirection of every production touch point (see the module docstring), then the stages."""

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
        if not self._has(UNUSED_REF):
            # the legacy inventory resolver needs a password candidate even for a key-only account: a random throwaway value that
            # no fixture device knows (the pinned key is what authenticates)
            self.store.initialize(UNUSED_REF, secrets.token_urlsafe(24), replace=True)
        self._gateway = None
        self.http = None

    def _has(self, ref) -> bool:
        from modules.device_credentials import SecretProviderError

        try:
            return bool(self.store.candidates(ref))
        except SecretProviderError:
            return False

    # -- shared lookups -------------------------------------------------------------------------------------------------------
    @staticmethod
    def device(name):
        return models.ManagedDevice.objects.filter(name=name).exclude(lifecycle_state__in=tuple(models.DEVICE_LIFECYCLE_TERMINAL)).first()

    @staticmethod
    def network(name):
        return models.BootstrapNetwork.objects.get(name=name)

    @staticmethod
    def attachment(device, upstream):
        return device.attachments.filter(upstream_device=upstream).exclude(approval_state=models.AttachmentApproval.REVOKED).order_by("-id").first()

    @staticmethod
    def policy(device):
        from core.services.isolation import service as isolation

        return isolation.device_policy(device) or models.IsolationPolicy.objects.filter(device=device).order_by("-id").first()

    def gateway(self):
        from core.tests.helpers import provisioning as p

        if self._gateway is None:
            from core.tests import live_managed_scope_fixture as scope

            # NMAS_ISO_LIVE_NETBOX_ENV: the real gateway against the disposable NetBox (labs/managed-scope-isolated); else the fake
            self._gateway = scope.real_gateway() or p.FakeGateway(prefixes=["10.254.60.0/24", "10.254.64.0/24", "10.254.255.0/24"])
        return self._gateway

    @staticmethod
    def dhcp_state() -> dict:
        """The precheck's DHCP-service fact, from the FIXTURE dhcpd (substitutes the production nmas / R2 servers)."""
        alive = subprocess.run(["docker", "exec", "nmas-iso-p56-svc", "pgrep", "-x", "dhcpd"], capture_output=True, check=False).returncode == 0
        server = {"ipv4": "active" if alive else "inactive", "ipv6": "inactive", "source": "fixture dhcpd (nmas-iso-p56-svc)"}
        return {"nmas": dict(server), "r2": dict(server)}

    @staticmethod
    def sources():
        from core.tests.helpers.validation import make_sources, netbox_data

        return make_sources(netbox=netbox_data(managed_devices=["R1", "R2", "R3", "R4", "S1", "S2", "S3", "S4", "mgmt_swt"]))

    def serve(self):
        """The NMAS bootstrap delivery server on the service address (this namespace), in a thread."""
        if self.http is None:
            from core.services.ztp import servers

            self.http = servers.make_http_server(SERVICE, HTTP_PORT)
            servers.serve_forever_in_thread(self.http)
        return self.http

    # -- traffic (fixture vantage points; never an NMAS path) -----------------------------------------------------------------
    @staticmethod
    def tcp(where: list[str], address: str, port: int) -> str:
        """OPEN / REFUSED (the path forwarded both ways) / TIMEOUT (dropped)."""
        command = [*where, "timeout", "4", "bash", "-c", f"exec 3<>/dev/tcp/{address}/{port}"]
        done = subprocess.run(command, capture_output=True, text=True, timeout=20, check=False)
        if done.returncode == 0:
            return "OPEN"
        return "REFUSED" if "refused" in (done.stderr or "").lower() else "TIMEOUT"

    @staticmethod
    def ping(where: list[str], address: str) -> bool:
        flag = ["-6"] if ":" in address else []
        done = subprocess.run([*where, "ping", *flag, "-c", "2", "-W", "1", address], capture_output=True, text=True, timeout=20, check=False)
        return done.returncode == 0

    def flows(self, *, source: str) -> list[dict]:
        """``source`` = the probe namespace standing in for a hostile device ("probe-a" / "probe-b") or "new1" (the device)."""
        if source.startswith("probe-"):
            where = [str(FX / "fixture.sh"), "probe", source[-1]]
            device_v4 = "10.254.60.250" if source == "probe-a" else "10.254.64.250"
        else:
            where = ["docker", "exec", f"nmas-iso-p56-{source}"]
            device_v4 = "10.254.60.10"
        prod = [str(FX / "fixture.sh"), "prod"]
        gateway = "10.254.60.1" if source != "probe-b" else "10.254.64.1"
        rows = []

        def add(flow, expect, observed, detail=""):
            rows.append({"flow": flow, "expect": expect, "observed": observed, "detail": detail})

        state = self.tcp(where, SERVICE, HTTP_PORT)
        add(f"{source} -> NMAS bootstrap HTTP {SERVICE}:{HTTP_PORT}", "PERMIT", "PERMIT" if state != "TIMEOUT" else "DENY", state)
        if source != "new1":                 # NEW1 has no route to production in its bootstrap configuration
            add(f"{source} -> production host {PROD_V4} (ICMP)", "DENY", "PERMIT" if self.ping(where, PROD_V4) else "DENY")
            add(f"{source} -> production host {PROD_V6} (ICMPv6)", "DENY", "PERMIT" if self.ping(where, PROD_V6) else "DENY")
            add(f"{source} -> CORE loopback 10.254.255.2 (ICMP)", "DENY", "PERMIT" if self.ping(where, "10.254.255.2") else "DENY")
        else:
            add(f"{source} -> NMAS service {SERVICE} (ICMP, not a bootstrap flow)", "DENY", "PERMIT" if self.ping(where, SERVICE) else "DENY")
            state = self.tcp(where, SERVICE, 22)
            add(f"{source} -> NMAS service {SERVICE}:22 (not a bootstrap flow)", "DENY", "PERMIT" if state != "TIMEOUT" else "DENY", state)
        state = self.tcp(where, gateway, 22)
        add(f"{source} -> upstream's own SSH {gateway}:22", "DENY", "PERMIT" if state != "TIMEOUT" else "DENY", state)
        add(f"production host -> bootstrap side {device_v4} (ICMP)", "DENY", "PERMIT" if self.ping(prod, device_v4) else "DENY")
        if source == "probe-a":
            add("production host -> bootstrap side 2001:db8:254:60::250 (ICMPv6)", "DENY",
                "PERMIT" if self.ping(prod, "2001:db8:254:60::250") else "DENY")
        state = self.tcp([], device_v4, 22)
        add(f"NMAS service -> {device_v4}:22 (NMAS management)", "PERMIT", "PERMIT" if state != "TIMEOUT" else "DENY", state)
        return rows

    def traffic(self, source):
        def run(_policy, _with_device):
            found = self.flows(source=source)
            self.last_flows = found
            return found
        return run

    # =========================================================================================================================
    def stage_prepare(self):
        from core.services.devices import attachments, lifecycle
        from core.services.ztp import policy as ztp_policy

        record = {"capability_rows": self.copy_capability_evidence()}
        if self.device("UP1") is None:
            result = lifecycle.adopt_existing("UP1", role="router", actor=APPROVER)
            assert result.ok, result.codes
        if self.device("NEW1") is None:
            result = lifecycle.register_device(name="NEW1", platform=models.Platform.ARISTA_CEOS, role="router", actor=OPERATOR,
                                               expected_serial=NEW1_SERIAL, expected_base_mac=NEW1_MAC)
            assert result.ok, result.codes
        new1 = self.device("NEW1")
        if self.attachment(new1, "UP1") is None:
            result = attachments.register_attachment(new1, upstream_device="UP1", upstream_interface="Ethernet1", local_interface="Ethernet1",
                                                     purpose=models.AttachmentPurpose.PRODUCTION, connectivity=models.AttachmentConnectivity.ROUTED,
                                                     vlan=None, actor=OPERATOR)
            assert result.ok, result.codes
            result = attachments.approve_attachment(new1, result.attachment.pk, actor=APPROVER)
            assert result.ok, result.codes
        if not models.BootstrapNetwork.objects.filter(name=NET_A["name"]).exists():
            _row, problems = ztp_policy.create_network(actor=APPROVER, **NET_A, trusted_relays=[{"relay_address": "10.254.60.1", "upstream_device": "UP1"}],
                                                      config_root=str(RUNTIME / "dhcp"), lease_file="", provider="ISC_DHCP", http_port=HTTP_PORT, vlan=None)
            assert not problems, problems
        up1, new1 = self.device("UP1"), self.device("NEW1")
        record.update({"UP1": [up1.device_id, up1.lifecycle_state, up1.admission_state], "NEW1": [new1.device_id, new1.lifecycle_state, new1.admission_state],
                       "attachment": str(self.attachment(new1, "UP1")), "upstream_before": running("up")})
        evidence("00-prepare.json", record)

    def copy_capability_evidence(self, *, replace: bool = False) -> int:
        """Read-only copy of the deployed NMAS database's arista_ceos capability evidence / assessments (the gate's inputs), in
        the deployed order and with the deployed ``recorded_at`` (``auto_now_add`` would otherwise restamp every copy)."""
        if models.CapabilityEvidence.objects.exists() and not replace:
            return models.CapabilityEvidence.objects.count()
        if replace:
            models.CapabilityEvidence.objects.all().delete()
            models.CapabilityAssessment.objects.all().delete()
        source = sqlite3.connect(f"file:{DEPLOYED_DB}?mode=ro", uri=True)
        source.row_factory = sqlite3.Row
        copied = 0
        for model, table in ((models.CapabilityEvidence, "core_capabilityevidence"), (models.CapabilityAssessment, "core_capabilityassessment")):
            names = {f.attname for f in model._meta.concrete_fields} - {"id"}
            for row in source.execute(f"SELECT * FROM {table} WHERE platform = 'arista_ceos' ORDER BY id"):  # noqa: S608 - fixed names
                values = {k: row[k] for k in row.keys() if k in names}
                for field in model._meta.concrete_fields:
                    if field.get_internal_type() == "JSONField" and isinstance(values.get(field.attname), str):
                        values[field.attname] = json.loads(values[field.attname])
                stamp = values.pop("recorded_at", None)
                created = model.objects.create(**values)
                if stamp:
                    model.objects.filter(pk=created.pk).update(recorded_at=stamp)
                copied += 1
        source.close()
        return copied

    # =========================================================================================================================
    def stage_isolate(self):
        from core.services.isolation import service as isolation

        new1 = self.device("NEW1")
        record = {}
        policy = self.policy(new1)
        if policy is None:
            result = isolation.require(new1, self.attachment(new1, "UP1"), network=self.network(NET_A["name"]), actor=OPERATOR)
            assert result.ok, result.codes
            policy = result.policy
        self.serve()
        record["before_flows"] = self.flows(source="probe-a")                  # nothing enforced yet: the gap being closed
        planned = isolation.plan(policy, actor=OPERATOR)
        record["plan"] = {"ok": planned.ok, "codes": planned.codes, "detail": planned.detail}
        assert planned.ok, planned.codes
        policy = planned.policy
        record["ops"] = isolation.ops_of(policy)
        checked = isolation.precheck(policy, actor=OPERATOR)
        record["precheck"] = {"ok": checked.ok, "codes": checked.codes}
        assert checked.ok, checked.codes
        policy = models.IsolationPolicy.objects.get(pk=policy.pk)
        record["self_approval"] = isolation.approve(policy, actor=OPERATOR, confirmation=policy.plan_hash).codes
        record["wrong_hash"] = isolation.approve(policy, actor=APPROVER, confirmation="0" * 64).codes
        approved = isolation.approve(policy, actor=APPROVER, confirmation=policy.plan_hash)
        assert approved.ok, approved.codes
        applied = isolation.apply(approved.policy, actor=EXECUTOR, confirmation=policy.plan_hash)
        record["apply"] = {"ok": applied.ok, "codes": applied.codes, "outcome": applied.detail.get("outcome")}
        assert applied.ok, (applied.codes, applied.detail.get("report", {}).get("failure"))
        record["upstream_enforced"] = running("up")
        verified = isolation.verify(applied.policy, actor=APPROVER, traffic=self.traffic("probe-a"))
        record["verify"] = {"ok": verified.ok, "codes": verified.codes, "summary": verified.detail, "flows": self.last_flows}
        assert verified.ok, (verified.codes, self.last_flows)
        record["acl_counters"] = {name: cli("up", f"show {kw} access-lists {name}") for kw, name in (
            ("ip", f"NMAS-ISO-{new1.device_id}-V4"), ("ipv6", f"NMAS-ISO-{new1.device_id}-V6"), ("ip", f"NMAS-ISO-{new1.device_id}-V4-OUT"))}
        record["ospf_neighbors_on_port"] = cli("up", "show ip ospf neighbor")
        record["status"] = isolation.status(verified.policy)
        evidence("10-isolation-before-device.json", record)

    # =========================================================================================================================
    def stage_ztp(self):
        from core.services.devices import authorization
        from core.services.ztp import discovery, policy as ztp_policy, workflow

        new1, network = self.device("NEW1"), self.network(NET_A["name"])
        attachment = self.attachment(new1, "UP1")
        record = {}
        session = models.ZtpSession.objects.filter(device=new1).order_by("-id").first()
        if session is None:
            start = timezone.now() - timezone.timedelta(minutes=1)
            requested = authorization.request_authorization(new1, attachment_id=attachment.pk, scope=["BOOTSTRAP_FETCH", "DHCP_DISCOVERY"],
                                                            valid_from=start, valid_until=start + timezone.timedelta(hours=3), max_uses=1,
                                                            actor=OPERATOR, reason="first boot of NEW1 (live fixture)")
            assert requested.ok, requested.codes
            auth = requested.authorization
            record["auth_self_approval"] = authorization.approve(auth, actor=OPERATOR, confirm_digest=auth.binding_digest).codes
            auth = authorization.approve(auth, actor=APPROVER, confirm_digest=auth.binding_digest).authorization
            from core.services.ztp import relay_option82

            if relay_option82.required_for("UP1") and relay_option82.trusted_readback("UP1") is None:
                # V2 Phase 9: ZTP through a cEOS relay needs NMAS's fresh read-back of its option 82 configuration -- a read-only
                # refresh over NMAS's SSH session (the Phase 9 harness instead applies option 82 through a governed change first)
                refreshed = relay_option82.refresh("UP1", actor=OPERATOR)
                record["relay_readback_refresh"] = {"ok": refreshed.ok, "codes": refreshed.codes}
            opened = workflow.open_session(new1, authorization=auth, network=network, actor=OPERATOR)
            record["open"] = {"ok": opened.ok, "codes": opened.codes}
            assert opened.ok, opened.codes
            session = opened.session
            row, problems = ztp_policy.validate_policy(network, actor=OPERATOR)
            assert not problems, problems
            row, problems = ztp_policy.apply_policy(network, actor=EXECUTOR)
            record["dhcp_apply"] = {"state": row.state, "sha256": row.config_sha256, "sessions": row.sessions, "problems": problems}
            assert not problems, problems
            evidence("20-dhcpd.conf", (RUNTIME / "dhcp" / "dhcpd.conf").read_text())
            print(fixture("attach", "new1", timeout=300).stdout)
        self.serve()

        def delivered():
            discovery.ingest(network)
            fresh = workflow.get_session(session.session_id)
            return fresh if fresh.stage in (models.ZtpSessionStage.DELIVERED, models.ZtpSessionStage.MANAGEMENT_REACHED, models.ZtpSessionStage.MANAGEMENT_VERIFIED, models.ZtpSessionStage.BOOTSTRAPPED) else None

        session = wait_for(delivered, timeout=900, step=10)
        assert session is not None, "NEW1 did not complete native ZTP within 15 minutes"
        record["delivered"] = workflow.status(session)
        Stage = models.ZtpSessionStage
        if session.stage == Stage.DELIVERED:
            # delivery is not application: EOS applies the startup-config after the download.  The harness waits (console
            # observation only) until the enrollment account exists; NMAS's first contact then meets the bootstrapped device.
            applied = wait_for(lambda: "username nmas-enroll" in cli("new1", "show running-config section username"), timeout=300, step=5)
            record["bootstrap_applied_seen_on_console"] = bool(applied)
            contacted = wait_for(lambda: (lambda r: r if r.ok else None)(workflow.contact_management(workflow.get_session(session.session_id), actor=OPERATOR)),
                                 timeout=300, step=10)
            assert contacted is not None, "no management contact"
            session = workflow.get_session(session.session_id)
        if session.stage == Stage.MANAGEMENT_REACHED and not session.enrolled_host_key:
            record["observed_host_key"] = session.observed_host_key
            console = fingerprint_of(fixture("hostkey", "new1").stdout.strip())
            record["console_host_key"] = console
            record["enroll_by_opener"] = workflow.enroll_host_key(session, fingerprint=console, actor=OPERATOR, basis="console").codes
            enrolled = workflow.enroll_host_key(session, fingerprint=console, actor=APPROVER,
                                                basis="fixture console: show management ssh hostkey ed25519 public")
            assert enrolled.ok, enrolled.codes
            session = workflow.get_session(session.session_id)
        if session.stage == Stage.MANAGEMENT_REACHED:
            record["observed_host_key"], record["enrolled_host_key"] = session.observed_host_key, session.enrolled_host_key
            attempts = []

            def verified():
                result = workflow.verify_management(workflow.get_session(session.session_id), actor=EXECUTOR)
                attempts.append({"ok": result.ok, "codes": result.codes, "at": timezone.now().isoformat()})
                return result if result.ok else None

            done = wait_for(verified, timeout=300, step=15)
            record["verify_attempts"] = attempts
            assert done is not None, attempts
        session = workflow.get_session(session.session_id)
        record["session"] = workflow.status(session)
        record["leases"] = (RUNTIME / "dhcp" / "dhcpd.leases").read_text()[-3000:]
        record["new1_running"] = running("new1")
        evidence("20-ztp.json", record)

    # =========================================================================================================================
    def stage_onboard(self):
        from core.services.devices import lifecycle
        from core.services.isolation import service as isolation
        from core.services.management import bootstrap_credentials as B
        from core.services.ztp import workflow

        new1 = self.device("NEW1")
        policy = self.policy(new1)
        record = {}
        self.serve()
        record["new1_kernel_routes"] = subprocess.run(["docker", "exec", "nmas-iso-p56-new1", "ip", "route"], capture_output=True, text=True,
                                                      check=False).stdout
        verified = isolation.verify(policy, actor=APPROVER, traffic=self.traffic("new1"), with_device=True)
        record["verify_with_device"] = {"ok": verified.ok, "codes": verified.codes, "summary": verified.detail, "flows": self.last_flows}
        assert verified.ok, (verified.codes, self.last_flows)
        record["arp"] = cli("up", "show ip arp 10.254.60.10")
        new1.refresh_from_db()
        if new1.lifecycle_state == models.DeviceLifecycleState.BOOTSTRAPPED:
            result = lifecycle.transition(new1, models.DeviceLifecycleState.ISOLATED, actor=APPROVER)
            record["isolate_edge"] = {"ok": result.ok, "codes": result.codes}
            assert result.ok, result.codes
        new1.refresh_from_db()
        if new1.identity_state != models.IdentityVerificationState.VERIFIED:
            session = models.ZtpSession.objects.filter(device=new1).order_by("-id").first()
            result = lifecycle.verify_identity(new1, (session.verification or {}).get("observation"), actor=APPROVER)
            record["identity"] = {"ok": result.ok, "codes": result.codes}
            assert result.ok, result.codes
        new1.refresh_from_db()
        if not models.BootstrapCredentialTransition.objects.filter(device=new1, state=models.BootstrapCredentialState.COMPLETE).exists():
            public = (RUNTIME / "keys" / "nmas-svc.pub").read_text().strip()
            self.store.initialize(NEW1_REF, (RUNTIME / "keys" / "nmas-svc").read_text(), replace=True)
            credential = models.DeviceCredential.objects.filter(device_name="NEW1", username="nmas-svc").first() or models.DeviceCredential.objects.create(
                device_name="NEW1", platform="arista_ceos", username="nmas-svc", account_kind=models.AccountKind.SERVICE,
                auth_method=models.DeviceAuthMethod.PUBLICKEY, ssh_key_ref=NEW1_REF, ssh_public_key=" ".join(public.split()[:2]),
                ssh_public_key_fingerprint=fingerprint_of(public))
            planned = B.plan(new1, replacement_credential_id=credential.pk, actor=OPERATOR, reason="retire the ZTP enrollment credential")
            assert planned.ok, planned.codes
            approved = B.approve(planned.transition, actor=APPROVER, digest=planned.transition.binding_digest)
            assert approved.ok, approved.codes
            result = B.execute(approved.transition, actor="nmas-automation (live harness)")
            transition = models.BootstrapCredentialTransition.objects.get(pk=approved.transition.pk)
            record["bcred"] = {"ok": result.ok, "codes": result.codes, "status": B.status(transition)}
            assert result.ok, (result.codes, transition.steps)
        new1.refresh_from_db()
        record["device"] = {"lifecycle": new1.lifecycle_state, "identity": new1.identity_state, "admission": new1.admission_state}
        record["accounts"] = [line.split()[1] for line in cli("new1", "show running-config section username").splitlines() if line.startswith("username ")]
        record["ztp_status"] = workflow.status(models.ZtpSession.objects.filter(device=new1).order_by("-id").first())
        evidence("30-onboard.json", record)

    # =========================================================================================================================
    def stage_commission(self):
        from core.services import provisioning_service as ps
        from core.services.commissioning import service as commissioning
        from core.services import execution_service as es
        from core.services.isolation import service as isolation
        from core.services.provisioning import lifecycle as plifecycle
        from core.tests.helpers import execution as ex, health as h
        from core.tests.helpers.provisioning import ProvDev

        new1 = self.device("NEW1")
        record = {}
        record_row = models.CommissioningRecord.objects.filter(device=new1).order_by("-id").first()
        if record_row is None or record_row.state in (models.CommissioningState.ABORTED, models.CommissioningState.FAILED):
            opened = commissioning.open_commissioning(new1, actor=OPERATOR)
            record["open"] = {"ok": opened.ok, "codes": opened.codes}
            assert opened.ok, opened.codes
            record_row = opened.record
        run = models.ProvisioningRun.objects.get(pk=record_row.provisioning_run_id)
        record["early_assess"] = commissioning.assess(record_row, actor=OPERATOR).codes            # no candidate yet: refused
        sources = self.sources()
        steps = []

        def step(name, result):
            steps.append({"stage": name, "ok": result.ok, "codes": getattr(result, "codes", [])})
            assert result.ok, (name, result.codes, getattr(getattr(result, "event", None), "evidence", None))
            run.refresh_from_db()

        S = models.ProvisioningStatus
        if run.status == S.IDENTIFIED:
            step("bootstrap", ps.classify_bootstrap(run, actor=OPERATOR))
        if run.status == S.BOOTSTRAP_CLASSIFIED:
            step("capability", ps.resolve_capabilities(run, actor=OPERATOR))
        if run.status == S.CAPABILITY_RESOLVED:
            step("ipam", ps.plan_ipam(run, actor=OPERATOR, gateway=self.gateway()))
        if run.status == S.IPAM_PLANNED:
            step("candidate", ps.generate_candidate(run, actor=OPERATOR))
        if run.status == S.CANDIDATE_READY:
            dev = ProvDev(run.change, run.device_name)
            if not any((dev.refresh().sections or {}).values()):        # the operator's Device Builder intent (once)
                self.new1_intent(dev)
            step("validate", ps.record_validation(run, actor=OPERATOR, sources=sources))
        if run.status == S.VALIDATED:
            step("plan", ps.build_plan(run, actor=OPERATOR, sources=sources))
        if run.status == S.PLANNED:
            now = timezone.now()
            step("precheck", ps.run_precheck(run, actor=OPERATOR, sources=sources, snapshot=h.snapshot(now=now), now=now,
                                             dhcp_state=self.dhcp_state()))
        record["configlets"] = [{"cfg_id": c.cfg_id, "object_type": (c.desired_state_ref or {}).get("source", {}).get("object_type"),
                                 "lines": c.rendered_config.splitlines()} for c in run.plan.configlets.order_by("sequence")]
        record["provisioning_steps"] = steps
        record_row = models.CommissioningRecord.objects.get(pk=record_row.pk)
        if record_row.state == models.CommissioningState.OPEN:
            assessed = commissioning.assess(record_row, actor=OPERATOR)
            record["assess"] = {"ok": assessed.ok, "codes": assessed.codes, "readiness": assessed.record.readiness}
            assert assessed.ok, (assessed.codes, assessed.record.readiness)
            record_row = assessed.record
        if record_row.state == models.CommissioningState.READY:
            record["approve_self"] = commissioning.approve(record_row, actor=OPERATOR, confirmation=record_row.evidence_digest).codes
            record["approve_wrong_digest"] = commissioning.approve(record_row, actor=APPROVER, confirmation="f" * 64).codes
            approved = commissioning.approve(record_row, actor=APPROVER, confirmation=record_row.evidence_digest, comment="live fixture")
            record["approve"] = {"ok": approved.ok, "codes": approved.codes}
            assert approved.ok, approved.codes
        run.refresh_from_db()
        record["upstream_before_configuration"] = running("up")
        if run.status == models.ProvisioningStatus.APPROVED:
            with mock.patch.object(plifecycle, "GATEWAY_FACTORY", self.gateway):
                result = es.execute_change(run.change, actor=APPROVER, sources=sources, notifier=ex.Notifications(),
                                           confirm_mode=run.change.execution_mode)
            run.refresh_from_db()
            record["execution"] = {"outcome": result.outcome, "blockers": result.blockers, "run_status": run.status,
                                   "report_failure": (result.run.report or {}).get("failure") if result.run else None}
            assert run.status == models.ProvisioningStatus.POSTCHECKED, record["execution"]
        record_row = models.CommissioningRecord.objects.get(pk=record_row.pk)
        if record_row.state in (models.CommissioningState.APPROVED, models.CommissioningState.CONFIGURING):
            configured = commissioning.record_configuration(record_row, actor=APPROVER)
            record["configured"] = {"ok": configured.ok, "codes": configured.codes}
            assert configured.ok, configured.codes
            record_row = configured.record
        record["new1_running"] = running("new1")
        record["new1_ospf"] = cli("new1", "show ip ospf neighbor")
        record["up1_ospf"] = cli("up", "show ip ospf neighbor")
        record["up1_route_to_new1_loopback"] = cli("up", f"show ip route {NEW1_ROUTER_ID}")
        policy = self.policy(new1)
        record["isolation_after_configuration"] = {"state": policy.state, "drift": isolation.check_drift(policy, actor=APPROVER).codes}
        record["commissioning"] = commissioning.status(models.CommissioningRecord.objects.get(pk=record_row.pk))
        evidence("40-commission.json", record)

    # =========================================================================================================================
    def stage_downstream_early(self):
        from core.services.commissioning import dependencies
        from core.services.devices import attachments, lifecycle

        record = {}
        if self.device("NEW2") is None:
            result = lifecycle.register_device(name="NEW2", platform=models.Platform.ARISTA_CEOS, role="router", actor=OPERATOR,
                                               expected_serial=NEW2_SERIAL, expected_base_mac=NEW2_MAC)
            assert result.ok, result.codes
        new1, new2 = self.device("NEW1"), self.device("NEW2")
        refused = attachments.register_attachment(new2, upstream_device="NEW1", upstream_interface="Ethernet2", local_interface="Ethernet1",
                                                  purpose=models.AttachmentPurpose.PRODUCTION, connectivity=models.AttachmentConnectivity.ROUTED,
                                                  vlan=None, actor=OPERATOR)
        record["attachment_before_upstream_admitted"] = refused.codes
        assert not refused.ok
        added = dependencies.add(new2, new1, kind=models.DependencyKind.DECLARED, actor=OPERATOR, reason="NEW2 bootstraps behind NEW1:Ethernet2")
        record["declared_dependency"] = {"ok": added.ok, "codes": added.codes}
        record["unmet"] = dependencies.unmet(new2)
        record["cycle_refused"] = dependencies.add(new1, new2, kind=models.DependencyKind.DECLARED, actor=OPERATOR, reason="cycle").codes
        record["graph"] = dependencies.graph_view()
        evidence("45-downstream-before-upstream-admission.json", record)

    # =========================================================================================================================
    def new1_intent(self, dev) -> dict:
        """NEW1's Device Builder intent (the operator's, entered once); returns the interfaces it declared."""
        uplink = dev.iface("Ethernet1")                         # the ZTP-addressed uplink, declared as-is
        dev.address(uplink, "10.254.60.10/24")
        loopback = dev.iface("Loopback0", kind="LOOPBACK")
        dev.address(loopback, NEW1_LOOPBACK)
        downstream = dev.iface("Ethernet2")
        dev.address(downstream, NEW1_DOWNSTREAM)
        dev.relay(downstream, SERVICE)
        ospf = dev.ospf(router_id=NEW1_ROUTER_ID, process_id=1)
        dev.bind("ospf", ospf, dev.current_iface(uplink["id"]), area="0.0.0.0")
        dev.bind("ospf", ospf, dev.current_iface(loopback["id"]), area="0.0.0.0", passive=True)   # a loopback has no neighbour
        dev.bind("ospf", ospf, dev.current_iface(downstream["id"]), area="0.0.0.0", passive=True)
        return {"uplink": uplink, "loopback": loopback, "downstream": downstream}

    def admit_fail_expectations(self) -> dict:
        return {"routing": "OSPF", "ospf_neighbors": [NEW1_ROUTER_ID], "routes_v4": ["10.254.250.0/24"],   # never advertised
                "reachable": [NEW1_ROUTER_ID]}

    def admit_expectations(self) -> dict:
        return {"routing": "OSPF", "ospf_neighbors": [NEW1_ROUTER_ID], "routes_v4": [NEW1_LOOPBACK, "10.254.64.0/24"],
                "reachable": [NEW1_ROUTER_ID]}

    def _admission(self, expectations, *, label):
        from core.services.commissioning import admission

        new1 = self.device("NEW1")
        record_row = models.CommissioningRecord.objects.filter(device=new1).order_by("-id").first()
        planned = admission.plan(record_row, actor=OPERATOR, expectations=expectations)
        out = {"plan": {"ok": planned.ok, "codes": planned.codes}}
        assert planned.ok, planned.codes
        checked = admission.precheck(planned.admission, actor=OPERATOR)
        out["precheck"] = {"ok": checked.ok, "codes": checked.codes}
        assert checked.ok, checked.codes
        row = checked.admission
        out["approve_self"] = admission.approve(row, actor=OPERATOR, confirmation=row.evidence_digest).codes
        approved = admission.approve(row, actor=APPROVER, confirmation=row.evidence_digest)
        out["approve"] = {"ok": approved.ok, "codes": approved.codes}
        assert approved.ok, approved.codes
        out["upstream_before_release"] = running("up")
        executed = admission.execute(approved.admission, actor=EXECUTOR, gateway=self.gateway())
        fresh = models.ProductionAdmission.objects.get(pk=approved.admission.pk)
        out["execute"] = {"ok": executed.ok, "codes": executed.codes, "status": admission.status(fresh)}
        out["upstream_after"] = running("up")
        out["up1_ospf"] = cli("up", "show ip ospf neighbor")
        out["up1_routes"] = cli("up", "show ip route")
        out["label"] = label
        return executed, out

    def stage_admit_fail(self):
        from core.services.isolation import service as isolation

        new1 = self.device("NEW1")
        policy = self.policy(new1)
        before = cli("up", "show running-config")
        executed, record = self._admission(self.admit_fail_expectations(), label="injected failure: a route NEW1 never advertises")
        assert not executed.ok
        after = cli("up", "show running-config")
        record["upstream_restored_byte_identical"] = scrub(before) == scrub(after)
        policy = models.IsolationPolicy.objects.get(pk=policy.pk)
        record["policy_after"] = isolation.status(policy)
        new1.refresh_from_db()
        record["device_after"] = {"lifecycle": new1.lifecycle_state, "admission": new1.admission_state}
        self.serve()
        verified = isolation.verify(policy, actor=APPROVER, traffic=self.traffic("new1"), with_device=True)
        record["reverified"] = {"ok": verified.ok, "codes": verified.codes, "flows": self.last_flows}
        assert verified.ok, verified.codes
        evidence("50-admission-injected-failure.json", record)

    def stage_admit(self):
        from core.services.commissioning import outbox, service as commissioning

        new1 = self.device("NEW1")
        executed, record = self._admission(self.admit_expectations(), label="the admission")
        assert executed.ok, record["execute"]
        new1.refresh_from_db()
        record["device_after"] = {"lifecycle": new1.lifecycle_state, "admission": new1.admission_state}
        record["production_to_new1_loopback"] = self.ping([str(FX / "fixture.sh"), "prod"], NEW1_ROUTER_ID)
        record["production_to_new1_uplink"] = self.ping([str(FX / "fixture.sh"), "prod"], "10.254.60.10")
        record["new1_ospf"] = cli("new1", "show ip ospf neighbor")
        record["core_route_to_new1"] = cli("core", f"show ip route {NEW1_ROUTER_ID}")
        record["outbox"] = [{"topic": e.topic, "state": e.state, "payload": e.payload} for e in outbox.pending()]
        record["commissioning"] = commissioning.status(models.CommissioningRecord.objects.filter(device=new1).order_by("-id").first())
        record["netbox_gateway_calls"] = [list(map(str, call)) for call in getattr(self.gateway(), "calls", [])][-20:]
        evidence("60-admission.json", record)

    # =========================================================================================================================
    def stage_downstream(self):
        from core.services.commissioning import dependencies
        from core.services.devices import attachments, authorization
        from core.services.isolation import service as isolation
        from core.services.ztp import policy as ztp_policy

        new1, new2 = self.device("NEW1"), self.device("NEW2")
        record = {"unmet_after_upstream_admitted": dependencies.unmet(new2), "upstream_satisfied": dependencies.satisfied(new1)}
        attachment = self.attachment(new2, "NEW1")
        if attachment is None:
            result = attachments.register_attachment(new2, upstream_device="NEW1", upstream_interface="Ethernet2", local_interface="Ethernet1",
                                                     purpose=models.AttachmentPurpose.PRODUCTION, connectivity=models.AttachmentConnectivity.ROUTED,
                                                     vlan=None, actor=OPERATOR)
            record["attachment_retry"] = {"ok": result.ok, "codes": result.codes}
            assert result.ok, result.codes
            attachment = attachments.approve_attachment(new2, result.attachment.pk, actor=APPROVER).attachment
        record["derived"] = [str(r.dependency) for r in dependencies.derive(new2, actor=OPERATOR) if r.ok]
        if not models.BootstrapNetwork.objects.filter(name=NET_B["name"]).exists():
            _row, problems = ztp_policy.create_network(actor=APPROVER, **NET_B, trusted_relays=[{"relay_address": "10.254.64.1", "upstream_device": "NEW1"}],
                                                      config_root=str(RUNTIME / "dhcp-b"), lease_file="", provider="ISC_DHCP", http_port=HTTP_PORT, vlan=None)
            record["network_b"] = problems
            assert not problems, problems
        policy = self.policy(new2)
        if policy is None:
            result = isolation.require(new2, attachment, network=self.network(NET_B["name"]), actor=OPERATOR)
            record["require"] = {"ok": result.ok, "codes": result.codes}
            assert result.ok, result.codes
            policy = result.policy
        self.serve()
        record["before_flows"] = self.flows(source="probe-b")
        planned = isolation.plan(policy, actor=OPERATOR)
        record["plan"] = {"ok": planned.ok, "codes": planned.codes, "ops": isolation.ops_of(planned.policy)}
        assert planned.ok, planned.codes
        assert isolation.precheck(planned.policy, actor=OPERATOR).ok
        policy = models.IsolationPolicy.objects.get(pk=policy.pk)
        approved = isolation.approve(policy, actor=APPROVER, confirmation=policy.plan_hash)
        assert approved.ok, approved.codes
        applied = isolation.apply(approved.policy, actor=EXECUTOR, confirmation=policy.plan_hash)
        record["apply"] = {"ok": applied.ok, "codes": applied.codes, "outcome": applied.detail.get("outcome")}
        assert applied.ok, (applied.codes, applied.detail.get("report", {}).get("failure"))
        verified = isolation.verify(applied.policy, actor=APPROVER, traffic=self.traffic("probe-b"))
        record["verify"] = {"ok": verified.ok, "codes": verified.codes, "flows": self.last_flows}
        assert verified.ok, (verified.codes, self.last_flows)
        record["new1_enforced"] = running("new1")
        start = timezone.now() - timezone.timedelta(minutes=1)
        requested = authorization.request_authorization(new2, attachment_id=attachment.pk, scope=["BOOTSTRAP_FETCH", "DHCP_DISCOVERY"],
                                                        valid_from=start, valid_until=start + timezone.timedelta(hours=1), max_uses=1,
                                                        actor=OPERATOR, reason="NEW2 bootstrap behind NEW1 (rehearsal)")
        record["new2_authorization"] = {"ok": requested.ok, "codes": requested.codes}
        record["new2_ztp_gate"] = isolation.ztp_problems(new2, attachment)
        record["graph"] = dependencies.graph_view()
        evidence("70-downstream-rehearsal.json", record)

    # PR #69 managed-scope acceptance (live_managed_scope_fixture)
    def stage_scope_pre(self):
        from core.tests import live_managed_scope_fixture as scope

        scope.stage_scope_pre(self, evidence)

    def stage_scope(self):
        from core.tests import live_managed_scope_fixture as scope

        scope.stage_scope(self, evidence)

    def stage_probation(self):
        from core.tests import live_managed_scope_fixture as scope

        scope.stage_probation(self, evidence)

    def stage_report(self):
        rows = sorted(p.name for p in EVIDENCE.glob("*") if p.is_file())
        events = models.DeviceLifecycleEvent.objects.order_by("id")
        evidence("90-lifecycle-events.json", [{"device": e.device.name, "action": e.action, "outcome": e.outcome, "from": e.from_state,
                                               "to": e.to_state, "actor": e.actor, "blockers": e.blockers} for e in events])
        evidence("99-index.json", {"files": rows, "devices": {d.name: [d.device_id, d.lifecycle_state, d.admission_state, d.identity_state]
                                                          for d in models.ManagedDevice.objects.order_by("id")}})


STAGES = ("prepare", "isolate", "ztp", "onboard", "commission", "downstream-early", "admit-fail", "admit", "downstream", "report",
          "scope-pre", "scope", "probation")


def main():
    stages = os.environ.get("NMAS_ISO_LIVE_STAGES", "").split()
    unknown = [s for s in stages if s not in STAGES]
    if not stages or unknown:
        raise SystemExit(f"stages: {' '.join(STAGES)} (unknown: {unknown})")
    harness = Harness()
    try:
        for stage in stages:
            print(f"[stage] {stage}", flush=True)
            getattr(harness, "stage_" + stage.replace("-", "_"))()
    finally:
        if harness.http is not None:
            harness.http.shutdown()
