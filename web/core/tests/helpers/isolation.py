"""Fixtures for the V2 Phase 5 / 6 trusted-isolation and commissioning tests.  Application state and fakes only.

* ``EosText``        an in-memory EOS running configuration that applies configuration sessions the way EOS does for the
                     statements the isolation renderer emits (block headers, children, ``no`` of either)
* ``FakeEosSession`` a Netmiko-shaped session over an ``EosText`` plus scripted operational ``show`` outputs, driven by the
                     REAL ``CeosExecutor`` (``executor_factory``), so assess / apply / read-back / compensation are the engine's
* ``upstream_config`` the trusted upstream's running configuration with one routed bootstrap port (shape of the live fixture)
"""

from __future__ import annotations

import json

from core.services.execution.executors.ceos import CeosExecutor
from core.services.health.evidence import DeviceEvidence, FactGroup
from core.services.isolation import service as isolation_service

PORT = "Ethernet7"
GATEWAY = "10.254.30.1"
SERVICE = "10.254.31.2"


def upstream_config(*, port=PORT, ospf=True, ipv6=True, helper=SERVICE, switchport=False, extra_port="", extra="", mgmt_acl=""):
    lines = ["hostname S1", "username admin privilege 15 role network-admin secret sha512 $6$x", "!",
             f"interface {port}", "   description bootstrap port"]
    lines += ["   switchport access vlan 30"] if switchport else ["   no switchport", f"   ip address {GATEWAY}/24"]
    if ipv6 and not switchport:
        lines.append("   ipv6 address 2001:db8:30::1/64")
    if helper:
        lines.append(f"   ip helper-address {helper}")
    lines += [f"   {line}" for line in extra_port.splitlines() if line]
    lines += ["!", "interface Ethernet1", "   no switchport", "   ip address 10.0.12.2/30", "!",
              "interface Loopback0", "   ip address 10.255.0.1/32", "!", "ip routing", "ipv6 unicast-routing", "!"]
    if ospf:
        lines += ["router ospf 1", "   router-id 10.255.0.1", "   network 10.0.0.0/8 area 0.0.0.0", "   max-lsa 12000", "!"]
    if mgmt_acl:
        lines += mgmt_acl.splitlines()
    lines += [line for line in extra.splitlines() if line]
    return "\n".join(lines) + "\nend\n"


class EosText:
    """Ordered top-level blocks {header: [children]} and plain top-level lines; renders ``show running-config``."""

    def __init__(self, text):
        self.blocks: list[list] = []
        for raw in text.splitlines():
            line = raw.rstrip()
            if not line.strip() or line.strip() in ("!", "end"):
                continue
            if not line.startswith(" "):
                self.blocks.append([line.strip(), []])
            elif self.blocks:
                self.blocks[-1][1].append(line.strip())

    def find(self, header):
        return next((b for b in self.blocks if b[0] == header), None)

    # interface settings EOS holds one value of (live-verified, cEOS 4.36.2F: DHCP relay option 82 circuit-id / remote-id)
    SINGLE_VALUED = ("ip dhcp relay information option circuit-id", "ip dhcp relay information option remote-id")
    # commands that open a configuration mode; EOS falls back to the global mode for one of these typed inside another mode
    MODES = ("interface ", "router ", "ipv6 router ", "ip access-list ", "ipv6 access-list ", "management ")

    def apply(self, commands):
        """A flattened configuration set (``exit`` closes a mode; a mode command inside another mode re-enters globally)."""
        context = None
        for raw in commands:
            stripped = raw.strip()
            if not stripped or stripped in ("end", "!") or stripped.startswith(("configure", "copy ")):
                continue
            if stripped == "exit":
                context = None
                continue
            if stripped.startswith(self.MODES):
                context = self.find(stripped)
                if context is None:
                    context = [stripped, []]
                    self.blocks.append(context)
                continue
            if stripped.startswith("no ") and stripped[3:].startswith(self.MODES):
                self.blocks = [b for b in self.blocks if b[0] != stripped[3:]]
                context = None
                continue
            if context is None:
                if stripped.startswith("no "):
                    self.blocks = [b for b in self.blocks if b[0] != stripped[3:]]
                elif self.find(stripped) is None:
                    self.blocks.append([stripped, []])
                continue
            stem = next((stem for stem in self.SINGLE_VALUED if stripped.removeprefix("no ").startswith(stem)), None)
            if stem is not None:                               # EOS keeps one value: a new one replaces it, ``no`` (any value) removes it
                context[1] = [c for c in context[1] if not c.startswith(stem)]
                if not stripped.startswith("no "):
                    context[1].append(stripped)
            elif stripped.startswith("default "):               # back to the default: neither the line nor its negation
                context[1] = [c for c in context[1] if c not in (stripped[8:], f"no {stripped[8:]}")]
            elif stripped.startswith("no passive-interface "):  # cEOS 4.36.2F keeps this negation as an explicit line
                context[1] = [c for c in context[1] if c != stripped[3:]]
                if stripped not in context[1]:
                    context[1].append(stripped)
            elif stripped.startswith("no "):
                context[1] = [c for c in context[1] if c != stripped[3:]]
            elif stripped not in context[1]:
                context[1].append(stripped)

    def _rank(self, key):
        order = self.__dict__.setdefault("_order", {})
        return order.setdefault(key, len(order))

    def text(self):
        """Stable order like EOS: a block or child re-created after removal returns to the position it was first seen at."""
        out = []
        for header, children in sorted(self.blocks, key=lambda b: self._rank(b[0])):
            children = sorted(children, key=lambda c: self._rank((header, c)))
            if header.startswith("management ") and not children:
                continue                          # EOS does not display a management mode left at its defaults
            out.append(header)
            out.extend(f"   {child}" for child in children)
            out.append("!")
        return "\n".join(out) + "\nend\n"


NO_OSPF6 = '{\n    "vrfs": {}\n}\n'


def ospf6_neighbors(*rows, process="1") -> str:
    """``show ipv6 ospf neighbor | json`` with (router id, state, interface) rows (the cEOS shape ``decommission.observe`` reads)."""
    entries = [{"routerId": rid, "adjacencyState": state, "interfaceName": iface} for rid, state, iface in rows]
    return json.dumps({"vrfs": {"default": {"instList": {process: {"ospf3NeighborEntries": entries}}}}})


class FakeEosSession:
    """``show running-config`` from the model; other commands from ``outputs`` (a value may be a callable of the session)."""

    def __init__(self, text, *, outputs=None, reject=None, pings=None):
        self.config = EosText(text)
        # cEOS 4.36.2F with no OSPFv3 process (read live from the Phases 5+6 fixture upstream)
        self.outputs = {"show ipv6 ospf neighbor | json": NO_OSPF6, **(outputs or {})}
        self.reject = reject                    # callable(commands) -> bool: refuse that configuration set
        self.pings = dict(pings or {})          # address -> bool
        self.sent, self.commands = [], []

    def send_command(self, command, **_):
        self.commands.append(command)
        if command.startswith("show running-config"):
            return self.config.text()
        if command.startswith("ping "):
            address = command.split()[-3]
            return "2 packets transmitted, 2 received, 0% packet loss" if self.pings.get(address) else "2 packets transmitted, 0 received"
        value = self.outputs.get(command, "")
        return value(self) if callable(value) else value

    def config_mode(self, **_):
        return None

    def check_config_mode(self):
        return False

    def check_enable_mode(self):
        return True

    def send_config_set(self, commands, **_):
        commands = list(commands)
        self.sent.append(commands)
        if self.reject is not None and self.reject(commands):
            raise RuntimeError("% Invalid input")
        self.config.apply(commands)
        return ""

    def disconnect(self):
        return None


def _facts(device):
    return DeviceEvidence(device["name"], "arista_ceos", {name: FactGroup(value, "SYNTHETIC") for name, value in
                                                          (("interfaces", {}), ("addresses", {}), ("routes", []))}, live_attempted=True)


def access(session, *, sources=("192.168.200.100",)):
    """An isolation ``Access`` whose executors are the real CeosExecutor over ``session``."""
    return isolation_service.Access(executor_factory=lambda device: CeosExecutor(device, connection_factory=lambda d: session, reader=_facts),
                                    nmas_sources=tuple(sources), sleep=lambda seconds: None)


def routes(*prefixes, interface=PORT) -> str:
    """``show ip route | json`` with ``prefixes`` learned through ``interface``."""
    return json.dumps({"vrfs": {"default": {"routes": {p: {"vias": [{"interface": interface, "nexthopAddr": "10.254.30.10"}]}
                                                       for p in prefixes}}}})


def ospf_neighbors(*rows) -> str:
    """``show ip ospf neighbor`` with (router id, state, address, interface) rows."""
    head = "Neighbor ID     Instance VRF      Pri State                  Dead Time   Address         Interface"
    return "\n".join([head] + [f"{rid:<15} 1        default  1   {state:<22} 00:00:35    {address:<15} {iface}" for rid, state, address, iface in rows])


ARP_MAC = "a227.1c9a.b67b"                 # the Z.lease() client MAC in EOS notation


def arp(address="10.254.30.10", *, mac=ARP_MAC, interface=PORT) -> str:
    return f"Address         Age (sec)  Hardware Addr   Interface\n{address}      0:00:12  {mac}  {interface}, not learned\n"


class Counter:
    """``show ip access-lists X`` whose deny entry gains ``step`` packets per read (the hostile probe hitting the port)."""

    def __init__(self, step=3):
        self.step, self.value = step, 0

    def __call__(self, _session):
        self.value += self.step
        return f"IP Access List X\n        1000 deny ip any any [match {self.value} packets, 0:00:01 ago]\n"


def traffic_ok(_policy=None, _with_device=False):
    return [{"flow": "probe -> service ssh", "expect": "DENY", "observed": "DENY"},
            {"flow": "device -> service http", "expect": "PERMIT", "observed": "PERMIT"}]


class Flow:
    """One NEW1 behind S1:Ethernet7 (ROUTED) taken through the real Phase 3 / 4 / 5 services on fakes.  Use with
    ``ztp.ZtpTestMixin`` (``real_isolation_gate = True``)."""

    def __init__(self, case, *, text=None, outputs=None):
        from core import models
        from core.tests.helpers import lifecycle as L

        self.case, self.L, self.models = case, L, models
        self.session = FakeEosSession(text or upstream_config(), outputs={
            "show ip ospf neighbor": "", "show ip route | json": routes(), "show ipv6 route | json": routes(), **(outputs or {})})
        self.access = access(self.session)
        L.adopt()
        self.device = L.register().device
        result = L.attach(self.device, port=PORT, vlan=None, connectivity=models.AttachmentConnectivity.ROUTED)
        assert result.ok, result.codes
        self.attachment = result.attachment
        self.network = case.network()
        self.policy = None
        self.ztp = None

    def counters(self, step=3):
        from core.services.isolation import eos

        names = eos.acl_names(self.device.device_id)
        for key, keyword in (("in4", "ip"), ("out4", "ip"), ("in6", "ipv6"), ("out6", "ipv6")):
            self.session.outputs[f"show {keyword} access-lists {names[key]}"] = Counter(step)

    def required(self):
        result = isolation_service.require(self.device, self.attachment, network=self.network, actor=self.L.OPERATOR)
        assert result.ok, result.codes
        self.policy = result.policy
        return result

    def planned(self):
        self.required()
        result = isolation_service.plan(self.policy, actor=self.L.OPERATOR, access=self.access)
        assert result.ok, result.codes
        self.policy = result.policy
        return result

    def approved(self):
        self.planned()
        assert isolation_service.precheck(self.policy, actor=self.L.OPERATOR, access=self.access).ok
        result = isolation_service.approve(self.refresh(), actor=self.L.APPROVER, confirmation=self.policy.plan_hash)
        assert result.ok, result.codes
        self.policy = result.policy
        return result

    def enforced(self):
        self.approved()
        result = isolation_service.apply(self.refresh(), actor=self.L.APPROVER, confirmation=self.policy.plan_hash, access=self.access)
        assert result.ok, (result.codes, result.detail.get("report", {}).get("failure"))
        self.policy = result.policy
        return result

    def verified(self):
        self.enforced()
        self.counters()
        result = isolation_service.verify(self.refresh(), actor=self.L.APPROVER, access=self.access, traffic=traffic_ok)
        assert result.ok, result.codes
        self.policy = result.policy
        return result

    def refresh(self):
        self.policy = self.models.IsolationPolicy.objects.get(pk=self.policy.pk)
        return self.policy

    # -- Phase 3: native ZTP behind the enforced policy -------------------------------------------------------------------
    def bootstrapped(self):
        from core.services.devices import authorization
        from core.services.ztp import discovery, workflow
        from core.tests.helpers import ztp as Z

        L = self.L
        auth = L.request_auth(self.device, self.attachment).authorization
        auth = authorization.approve(auth, actor=L.APPROVER, confirm_digest=auth.binding_digest).authorization
        opened = workflow.open_session(self.device, authorization=auth, network=self.network, actor=L.OPERATOR)
        assert opened.ok, opened.codes
        session = opened.session
        discovery.ingest(session.network, text=Z.lease())
        session.refresh_from_db()
        artifact = session.artifacts.get(state=self.models.BootstrapArtifactState.ACTIVE)
        from core.services.ztp import artifacts

        decision = artifacts.authorize(f"/ztp/v1/{artifact.artifact_id}/{artifact.filename}", session.reserved_address, "HTTP")
        assert decision.ok, decision.code
        artifacts.record(decision, client_address=session.reserved_address, transport="HTTP", outcome="SERVED", bytes_sent=len(decision.content))
        session.refresh_from_db()
        assert workflow.contact_management(session, actor=L.OPERATOR, observe=lambda address: L.HOST_KEY).ok
        session.refresh_from_db()
        assert workflow.enroll_host_key(session, fingerprint=L.HOST_KEY, actor=L.APPROVER, basis="console show management ssh hostkey").ok
        session.refresh_from_db()
        result = workflow.verify_management(session, actor="erin", run=Z.fake_run(Z.eos_outputs(session), L.HOST_KEY))
        assert result.ok, result.codes
        self.ztp = workflow.get_session(session.session_id)
        self.device.refresh_from_db()
        return self.ztp

    def verified_with_device(self):
        self.session.outputs[f"show ip arp {self.ztp.reserved_address}"] = arp(self.ztp.reserved_address)
        self.counters()
        result = isolation_service.verify(self.refresh(), actor=self.L.APPROVER, access=self.access, traffic=traffic_ok, with_device=True)
        assert result.ok, result.codes
        self.policy = result.policy
        return result

    def isolated(self):
        from core.services.devices import lifecycle

        result = lifecycle.transition(self.device, self.models.DeviceLifecycleState.ISOLATED, actor=self.L.APPROVER)
        assert result.ok, result.codes
        self.device.refresh_from_db()
        return result

    def identity_verified(self):
        from core.services.devices import lifecycle

        observation = (self.ztp.verification or {}).get("observation")
        result = lifecycle.verify_identity(self.device, observation, actor=self.L.APPROVER)
        assert result.ok, result.codes
        self.device.refresh_from_db()
        return result

    # -- Phase 4: bootstrap credential retired (BCRED COMPLETE) ------------------------------------------------------------
    def bcred_complete(self):
        from core.services.management import bootstrap_credentials as B
        from core.tests.test_bootstrap_retirement import REPLACEMENT_FP, REPLACEMENT_PUBLIC, FakeEos, FakeKeys

        models, L = self.models, self.L
        blob = self.ztp.enrollment_public_key.split()[1]
        credential = models.DeviceCredential.objects.create(
            device_name=self.device.name, platform="arista_ceos", username="nmas-svc", account_kind=models.AccountKind.SERVICE,
            auth_method=models.DeviceAuthMethod.PUBLICKEY, ssh_key_ref="runtime://device-credentials/nmas-svc-key",
            ssh_public_key=REPLACEMENT_PUBLIC, ssh_public_key_fingerprint=REPLACEMENT_FP)
        planned = B.plan(self.device, replacement_credential_id=credential.pk, actor=L.OPERATOR, reason="retire bootstrap")
        assert planned.ok, planned.codes
        approved = B.approve(planned.transition, actor=L.APPROVER, digest=planned.transition.binding_digest)
        assert approved.ok, approved.codes
        eos = FakeEos(L.HOST_KEY, blob)
        result = B.execute(approved.transition, actor="nmas-automation", connect=eos.connect, keys=FakeKeys(blob))
        assert result.ok, result.codes
        self.device.refresh_from_db()
        return result

    def ready_for_commissioning(self):
        """ISOLATED behind a VERIFIED policy, identity VERIFIED, bootstrap credential retired."""
        self.verified()
        self.bootstrapped()
        self.identity_verified()
        self.verified_with_device()
        self.isolated()
        self.bcred_complete()
        return self


def admitted_outputs(session, *, neighbor="10.255.0.9", prefixes=("10.9.0.0/16",), port=PORT):
    """Operational outputs that follow the configuration: the device's adjacency and routes appear only once the port is no
    longer passive and no longer filtered (what the live upstream does)."""
    def released(s):
        text = s.config.text()
        return f"passive-interface {port}" not in text and "access-group NMAS-ISO-" not in text

    session.outputs["show ip ospf neighbor"] = lambda s: ospf_neighbors((neighbor, "FULL/DR", "10.254.30.10", port)) if released(s) else ""
    session.outputs["show ip route | json"] = lambda s: routes(*prefixes) if released(s) else routes()
    session.pings["10.9.0.1"] = True


def commissioning_lab(run):
    """A ``provisioning.Lab`` over an existing (commissioning) run: same fakes, cEOS health outputs."""
    from core import models
    from core.tests.helpers import execution as ex, health as h
    from core.tests.helpers import provisioning as p
    from core.tests.helpers.validation import make_sources, netbox_data

    p.support(models.Platform.ARISTA_CEOS, "interface.LOOPBACK")
    lab = p.Lab.__new__(p.Lab)
    lab.name, lab.run, lab.request, lab.last = run.device_name, run, None, None
    lab.gateway = p.FakeGateway(prefixes=["10.254.30.0/24"])        # the bootstrap network is an IPAM prefix
    lab.world = ex.FakeWorld(devices=(run.device_name,))
    lab.sources = make_sources(netbox=netbox_data(managed_devices=["R1", "R2", "R3", "R4", "S1", "S2", "S3", "S4", "mgmt_swt"]))
    lab.management, lab.target = dict(run.management), dict(run.bootstrap_target)
    lab.session = lambda: h.session_factory({run.device_name: h.eos_outputs()})
    return lab


def candidate_ready(lab):
    for name in ("bootstrap", "capability", "ipam", "candidate", "intent", "validate", "plan", "precheck"):
        result = getattr(lab, name)()
        if name != "intent":
            assert result.ok, (name, result.codes)
    lab.run.refresh_from_db()
    return lab
