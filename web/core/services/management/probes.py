"""Layered verification of one management path.

    L1 TOPOLOGY       registry provenance (approved + trust-verified attachments, verified NMAS attachment, VLAN chain) and,
                      once a session exists, the device's own report that the path's local interface is connected
    L2 CONFIGURATION  the device's running configuration carries the path (interface mode / VLAN / VRF / address / loop
                      protection / management service in the VRF) -- read over the authenticated session of L5
    L3 REACHABILITY   a TCP connection to the endpoint's management port from a socket BOUND to the NMAS attachment's
                      host interface and source address (so the probe exercises that attachment)
    L4 RETURN PATH    the SSH version exchange and key exchange complete in both directions over that same socket
    L5 AUTHENTICATION the presented host key equals the PINNED fingerprint (checked BEFORE any credential is offered),
                      then the machine credential authenticates
    L6 SERVICE        the management CLI answers and identifies the expected device (hostname / serial)

A path passes only when every layer passes.  ``highest_layer`` is the highest CONSECUTIVE passing layer, so an L2 failure
found after L6 still reports 1.  Only ``guard.authorized_target`` supplies the address: no caller-supplied destination is
ever contacted.  The transport is injectable; the default is paramiko over an attachment-bound socket (never Docker exec, never
the Containerlab management network).  No credential, key or command output is ever stored -- only bounded facts.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import socket
import time
from dataclasses import dataclass, field

from django.conf import settings
from django.utils import timezone

from ... import models
from ..devices import codes
from ..devices.attachments import MANAGEMENT_VLAN
from . import eos_facts, guard, paths, policy

LAYER_NAMES = {1: "TOPOLOGY", 2: "CONFIGURATION", 3: "REACHABILITY", 4: "RETURN_PATH", 5: "AUTHENTICATION", 6: "SERVICE"}
EOS_COMMANDS = ("show hostname | json", "show version | json", "show interfaces status | json", "show running-config")
MAX_OUTPUT = 512 * 1024


class ProbeFailure(Exception):
    def __init__(self, layer: int, code: str, detail: str = ""):
        super().__init__(code)
        self.layer, self.code, self.detail = layer, code, str(detail)[:200]


@dataclass
class ProbeReport:
    path_id: str
    layers: dict = field(default_factory=lambda: {n: {"layer": n, "name": LAYER_NAMES[n], "ok": None, "code": "NOT_RUN", "detail": ""}
                                                  for n in LAYER_NAMES})
    presented_host_key: str = ""
    facts: dict = field(default_factory=dict)
    duration_ms: int = 0

    def set(self, layer: int, ok: bool, code: str = "", detail: str = ""):
        self.layers[layer].update({"ok": ok, "code": code or ("OK" if ok else "FAILED"), "detail": str(detail)[:200]})

    @property
    def passed(self) -> bool:
        return all(entry["ok"] is True for entry in self.layers.values())

    @property
    def highest_layer(self) -> int:
        highest = 0
        for n in sorted(self.layers):
            if self.layers[n]["ok"] is not True:
                break
            highest = n
        return highest

    @property
    def failure_code(self) -> str:
        for n in sorted(self.layers):
            if self.layers[n]["ok"] is False:
                return self.layers[n]["code"]
        return "" if self.passed else "PROBE_INCOMPLETE"

    def as_list(self) -> list:
        return [dict(self.layers[n]) for n in sorted(self.layers)]


def fingerprint(key) -> str:
    return "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")


# --- credentials (resolved at use time; never stored, never logged) --------------------------------------------------------------
class CredentialUnavailable(Exception):
    pass


def auth_material(path) -> tuple[str, list[dict]]:
    """-> (username, [{"pkey": key} | {"password": value}]) for the path's credential SOURCE."""
    from modules.device_credentials import FileSecretProvider, SecretProviderError, ceos_access_profiles, load_ssh_private_key

    S = models.ManagementCredentialSource
    try:
        if path.credential_source == S.ZTP_ENROLLMENT:
            from ..ztp import management as ztp_management
            from ..ztp.workflow import ENROLLMENT_USER

            session = models.ZtpSession.objects.filter(pk=paths._ztp_pk(path.credential_reference), device=path.device).first()
            if session is None:
                raise CredentialUnavailable("no enrollment session")
            return ENROLLMENT_USER, [{"pkey": ztp_management.load_private_key(session.enrollment_key_ref)}]
        if path.credential_source == S.DEVICE_CREDENTIAL:
            credential = path.device_credential
            methods = []
            if credential.ssh_key_ref:
                methods.append({"pkey": load_ssh_private_key(credential.ssh_key_ref)})
            if credential.secret_ref:
                methods += [{"password": item.value} for item in FileSecretProvider().candidates(credential.secret_ref)]
            if not methods:
                raise CredentialUnavailable("no machine credential material")
            return credential.username, methods
        from .. import nsot_live

        inventory = nsot_live._load_inventory()
        profile = ceos_access_profiles(inventory, path.device.name)[0]
        methods = [{"pkey": load_ssh_private_key(profile.ssh_key_ref)}] if profile.ssh_key_ref else []
        methods += [{"password": item.value} for item in FileSecretProvider().candidates(profile.credential_ref)]
        return profile.username, methods
    except (SecretProviderError, KeyError, IndexError, OSError) as exc:
        raise CredentialUnavailable(type(exc).__name__) from None
    except Exception as exc:  # noqa: BLE001 - ZTP ManagementError and malformed inventories all mean "unavailable"
        raise CredentialUnavailable(type(exc).__name__) from None


# --- the default transport ---------------------------------------------------------------------------------------------------------
class ParamikoTransport:
    """L3-L6 over one source-bound socket.  Host-key checking is never disabled; agent / key-file lookup is never used."""

    def run(self, *, source: str, interface: str, address: str, port: int, timeout: int, expected_host_key: str, username: str, methods: list,
            commands, report: ProbeReport) -> dict:
        import paramiko

        family = socket.AF_INET6 if ipaddress.ip_address(address).version == 6 else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        transport = None
        try:
            loopback_test = ipaddress.ip_address(address).is_loopback and getattr(settings, "NMAS_MGMT_ALLOW_LOOPBACK_TARGETS", False)
            try:
                if not hasattr(socket, "SO_BINDTODEVICE"):
                    raise OSError("interface binding unavailable")
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface.encode("ascii") + b"\x00")
                sock.bind((source, 0))
            except (OSError, UnicodeError) as exc:
                raise ProbeFailure(3, "L3_SOURCE_UNAVAILABLE", type(exc).__name__) from None
            try:
                sock.connect((address, int(port)))
            except OSError as exc:
                raise ProbeFailure(3, "L3_UNREACHABLE", type(exc).__name__) from None
            report.set(3, True, detail=f"tcp/{port} from {source if not loopback_test else 'loopback-test'}")
            transport = paramiko.Transport(sock)
            try:
                transport.start_client(timeout=timeout)
            except (paramiko.SSHException, OSError, EOFError) as exc:
                raise ProbeFailure(4, "L4_RETURN_PATH_FAILED", type(exc).__name__) from None
            report.set(4, True, detail="ssh version + key exchange completed both ways")
            presented = fingerprint(transport.get_remote_server_key())
            report.presented_host_key = presented
            if presented != expected_host_key:
                raise ProbeFailure(5, "L5_HOST_KEY_MISMATCH", "presented key is not the pinned key")
            if not self._authenticate(transport, username, methods):
                raise ProbeFailure(5, "L5_AUTH_FAILED")
            report.set(5, True, detail="pinned host key; machine credential accepted")
            outputs = {}
            for command in commands:
                try:
                    channel = transport.open_session(timeout=timeout)
                    channel.settimeout(timeout)
                    channel.exec_command(command)
                    chunks, total = [], 0
                    while total < MAX_OUTPUT:
                        data = channel.recv(65536)
                        if not data:
                            break
                        chunks.append(data)
                        total += len(data)
                    channel.close()
                    outputs[command] = b"".join(chunks).decode("utf-8", "replace")
                except (paramiko.SSHException, OSError, EOFError, socket.timeout) as exc:
                    raise ProbeFailure(6, "L6_SERVICE_UNAVAILABLE", type(exc).__name__) from None
            return outputs
        finally:
            if transport is not None:
                transport.close()
            sock.close()

    @staticmethod
    def _authenticate(transport, username: str, methods: list) -> bool:
        import paramiko

        for method in methods:
            try:
                if "pkey" in method:
                    remaining = transport.auth_publickey(username, method["pkey"])
                    if not remaining:
                        return True
                    # key accepted as the first factor (EOS key + password); a password method may follow
                    for follow in (m for m in methods if "password" in m):
                        if not transport.auth_password(username, follow["password"]):
                            return True
                elif "password" in method:
                    if not transport.auth_password(username, method["password"]):
                        return True
            except paramiko.AuthenticationException:
                continue
            except paramiko.SSHException:
                return False
            if transport.is_authenticated():
                return True
        return transport.is_authenticated()


# --- L2 configuration check (EOS) ------------------------------------------------------------------------------------------------
def _json(text: str) -> dict:
    text = (text or "").strip()
    start = text.find("{")
    try:
        return json.loads(text[start:]) if start >= 0 else {}
    except ValueError:
        return {}


def eos_link_connected(outputs: dict, interface: str) -> bool | None:
    status = (_json(outputs.get("show interfaces status | json", "")).get("interfaceStatuses") or {}).get(interface)
    if status is None:
        return None
    return str(status.get("linkStatus", "")).lower() == "connected"


def eos_config_problems(path, facts: eos_facts.EosFacts) -> list[dict]:
    """L2 for one path against the running configuration facts."""
    problems = []
    endpoint = path.endpoint_address
    holder = facts.interface_holding(endpoint)
    if holder is None:
        return [codes.blocker("L2_CONFIG_MISMATCH", reason="the endpoint address is not configured on the device")]
    if path.path_type == models.ManagementPathType.ROUTED_VRF:
        if path.vrf not in facts.vrfs:
            problems.append(codes.blocker("L2_CONFIG_MISMATCH", reason=f"vrf {path.vrf} not configured"))
        if holder.vrf != path.vrf:
            problems.append(codes.blocker("L2_CONFIG_MISMATCH", reason="the endpoint interface is not in the management VRF"))
        if path.vrf not in facts.ip_routing and ipaddress.ip_address(endpoint).version == 4:
            problems.append(codes.blocker("L2_CONFIG_MISMATCH", reason="ip routing is not enabled in the management VRF"))
        if path.transport == models.ManagementTransport.SSH and not (facts.services.get("ssh") or {}).get(path.vrf):
            problems.append(codes.blocker("L2_CONFIG_MISMATCH", reason="management ssh is not enabled in the VRF"))
        return problems
    if holder.vrf:
        problems.append(codes.blocker("L2_CONFIG_MISMATCH", reason="layer-2 path endpoint sits in a non-default VRF"))
    local = facts.interfaces.get(path.local_interface) if path.local_interface else None
    if path.local_interface and local is None:
        return problems + [codes.blocker("L2_CONFIG_MISMATCH", reason="the path's local interface is not configured")]
    if local is not None:
        if local.shutdown:
            problems.append(codes.blocker("L2_CONFIG_MISMATCH", reason="the local interface is shut down"))
        if local.mode in ("ACCESS", "TRUNK"):
            vlan = path.vlan or MANAGEMENT_VLAN
            carried, tagged = local.carries_vlan(vlan)
            if not carried:
                problems.append(codes.blocker("L2_CONFIG_MISMATCH", reason=f"vlan {vlan} not carried on the local interface"))
            elif tagged != bool(path.tagged):
                problems.append(codes.blocker("L2_CONFIG_MISMATCH", reason="tagging differs from the attachment"))
            if holder.name.lower() != f"vlan{vlan}":
                problems.append(codes.blocker("L2_CONFIG_MISMATCH", reason="the endpoint is not the management VLAN interface"))
            others = [name for name in facts.management_vlan_ports(vlan) if name != path.local_interface]
            if others and facts.spanning_tree_mode == "none":
                problems.append(codes.blocker("MGMT_VLAN_LOOP_RISK", ports=others[:8]))
        elif local.name != holder.name:
            problems.append(codes.blocker("L2_CONFIG_MISMATCH", reason="the endpoint is not on the path's local interface"))
    return problems


def _identity_problems(device, outputs: dict) -> list[dict]:
    hostname = str(_json(outputs.get("show hostname | json", "")).get("hostname") or "")
    serial = str(_json(outputs.get("show version | json", "")).get("serialNumber") or "")
    if not hostname and not serial:
        return [codes.blocker("L6_SERVICE_UNAVAILABLE", reason="no identity output")]
    if device.verified_serial and serial and serial != device.verified_serial:
        return [codes.blocker("L6_IDENTITY_MISMATCH", reason="serial")]
    if device.expected_serial and serial and serial != device.expected_serial:
        return [codes.blocker("L6_IDENTITY_MISMATCH", reason="serial")]
    if hostname and hostname.lower() != device.name.lower():
        return [codes.blocker("L6_IDENTITY_MISMATCH", reason="hostname")]
    return []


# --- the probe -----------------------------------------------------------------------------------------------------------------
def probe(path, *, transport=None, purpose: str = models.ProbePurpose.VERIFY, actor: str = "nmas-management",
          record: bool = True) -> tuple[ProbeReport, models.ManagementPathProbe | None, list[dict]]:
    """Verify ``path`` layer by layer.  -> (report, the recorded probe row, refusals).  A refusal (unauthorized target, rate
    limit) contacts nothing and records nothing."""
    stored, refusals = guard.authorized_target(path)
    if refusals:
        return ProbeReport(path_id=getattr(path, "path_id", "MPATH-NEW")), None, refusals
    limits = policy.effective(stored)
    if purpose == models.ProbePurpose.VERIFY and stored.last_probe_at and limits.min_probe_interval_seconds and \
            (timezone.now() - stored.last_probe_at).total_seconds() < limits.min_probe_interval_seconds:
        return ProbeReport(path_id=stored.path_id), None, [codes.blocker("PROBE_RATE_LIMITED")]
    report = ProbeReport(path_id=stored.path_id)
    started = time.monotonic()
    l1 = paths.topology_problems(stored)
    if l1:
        report.set(1, False, l1[0]["code"], l1[0].get("details", {}).get("reason", "") if isinstance(l1[0].get("details"), dict) else "")
    else:
        report.set(1, True, detail="attachments approved + trust-verified")
        _session_layers(stored, report, transport or ParamikoTransport(), limits)
    report.duration_ms = int((time.monotonic() - started) * 1000)
    row = None
    if record:
        row = models.ManagementPathProbe.objects.create(
            path=stored, device=stored.device, purpose=purpose, passed=report.passed, highest_layer=report.highest_layer,
            failure_code=report.failure_code, layers=report.as_list(), presented_host_key=report.presented_host_key,
            duration_ms=report.duration_ms, actor=actor[:150])
    return report, row, []


def _session_layers(path, report: ProbeReport, transport, limits) -> None:
    if path.device.platform not in paths.VERIFIED_PLATFORMS:
        # The session layers could run, but the path could never pass L2 -- fail closed without contacting the device.
        report.set(2, False, "L2_PLATFORM_NOT_IMPLEMENTED", path.device.platform)
        return
    try:
        username, methods = auth_material(path)
    except CredentialUnavailable as exc:
        report.set(5, False, "L5_AUTH_FAILED", f"credential unavailable ({exc})")
        return
    try:
        outputs = transport.run(source=path.nmas_attachment.source_address, interface=path.nmas_attachment.host_interface,
                                address=path.endpoint_address, port=path.port,
                                timeout=limits.probe_timeout_seconds, expected_host_key=path.expected_host_key, username=username,
                                methods=methods, commands=EOS_COMMANDS, report=report)
    except ProbeFailure as failure:
        report.set(failure.layer, False, failure.code, failure.detail)
        return
    finally:
        methods.clear()          # drop key / password references as soon as the session ends
    identity = _identity_problems(path.device, outputs)
    if identity:
        report.set(6, False, identity[0]["code"], identity[0].get("details", {}).get("reason", ""))
        return
    report.set(6, True, detail="management CLI answered as the expected device")
    if path.local_interface:
        connected = eos_link_connected(outputs, path.local_interface)
        if connected is False:
            report.set(1, False, "L1_LINK_DOWN", path.local_interface)
            report.facts["local_link"] = "down"
        elif connected:
            report.facts["local_link"] = "connected"
    facts = eos_facts.parse(outputs.get("show running-config", ""))
    problems = eos_config_problems(path, facts)
    report.facts.update({"stp_mode": facts.spanning_tree_mode, "hostname": facts.hostname})
    if problems:
        detail = problems[0].get("details", {})
        report.set(2, False, problems[0]["code"], detail.get("reason", "") if isinstance(detail, dict) else "")
    else:
        report.set(2, True, detail="interface / VLAN / VRF / address / service match the path")
