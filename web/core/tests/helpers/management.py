"""Shared fixtures for the V2 Phase 4 management-multihoming tests (NMAS database only; no device, no network).

``lab()`` builds the frozen lab's management shape in the test database: mgmt_swt, S1, S3 and R1 adopted; NMAS attached to
mgmt_swt:Ethernet9 (192.168.200.100/24, observed); R1's direct out-of-band attachment R1:Ethernet3 -> mgmt_swt:Ethernet1
(access VLAN 200, approved and trust-verified).  ``FakeTransport`` stands in for the SSH transport layer by layer.
"""

from __future__ import annotations

import io
import ipaddress
import json
import socket
import threading

import paramiko

from core import models
from core.services.devices import attachments, lifecycle
from core.services.management import paths, probes
from core.tests.helpers import lifecycle as L

OPERATOR, APPROVER = L.OPERATOR, L.APPROVER
HOST_KEY = "SHA256:" + "B" * 43
OTHER_HOST_KEY = "SHA256:" + "C" * 43


def eos_config(*, hostname="R1", ports=None, svi="192.168.200.1/24", stp="none", vrfs=(), extra="") -> str:
    """A minimal EOS running-config.  ``ports``: {name: "access200" | "trunk200" | "trunk101" | "routed:<cidr>" | "vrf:<vrf>:<cidr>"}."""
    ports = {"Ethernet3": "access200"} if ports is None else ports
    lines = [f"hostname {hostname}", f"spanning-tree mode {stp}", "!"]
    for vrf in vrfs:
        lines += [f"vrf instance {vrf}", "!", f"ip routing vrf {vrf}", "!"]
    for name, kind in ports.items():
        lines.append(f"interface {name}")
        if kind == "access200":
            lines.append("   switchport access vlan 200")
        elif kind.startswith("trunk"):
            lines += ["   switchport mode trunk", f"   switchport trunk allowed vlan {kind[5:]}"]
        elif kind.startswith("routed:"):
            lines += ["   no switchport", f"   ip address {kind.split(':', 1)[1]}"]
        elif kind.startswith("vrf:"):
            _tag, vrf, cidr = kind.split(":", 2)
            lines += ["   no switchport", f"   vrf {vrf}", f"   ip address {cidr}"]
        elif kind == "shutdown":
            lines.append("   shutdown")
        lines.append("!")
    if svi:
        lines += ["interface Vlan200", f"   ip address {svi}", "!"]
    for vrf in vrfs:
        lines += ["management ssh", f"   vrf {vrf}", "      no shutdown", "!"]
    return "\n".join(lines) + "\n" + extra + "end\n"


def eos_outputs(*, hostname="R1", serial="SN-R1", links=None, config=None) -> dict:
    links = {"Ethernet3": "connected"} if links is None else links
    return {
        "show hostname | json": json.dumps({"hostname": hostname, "fqdn": hostname}),
        "show version | json": json.dumps({"serialNumber": serial, "modelName": "cEOSLab"}),
        "show interfaces status | json": json.dumps({"interfaceStatuses": {n: {"linkStatus": s} for n, s in links.items()}}),
        "show running-config": config if config is not None else eos_config(hostname=hostname),
    }


class FakeTransport:
    """Behaves like ``probes.ParamikoTransport``: ``behaviour(address, source)`` returns outputs or (layer, code)."""

    def __init__(self, behaviour=None, outputs=None, host_key=HOST_KEY):
        self.behaviour = behaviour
        self.outputs = outputs or eos_outputs()
        self.host_key = host_key
        self.calls = []

    def run(self, *, source, interface, address, port, timeout, expected_host_key, username, methods, commands, report):
        self.calls.append({"source": source, "interface": interface, "address": address, "port": port,
                           "username": username, "commands": list(commands)})
        outcome = self.behaviour(address, source) if self.behaviour else self.outputs
        if isinstance(outcome, tuple):
            layer, code = outcome
            for done in range(3, layer):
                report.set(done, True)
            raise probes.ProbeFailure(layer, code)
        report.set(3, True)
        report.set(4, True)
        report.presented_host_key = self.host_key
        if self.host_key != expected_host_key:
            raise probes.ProbeFailure(5, "L5_HOST_KEY_MISMATCH")
        report.set(5, True)
        return outcome


def fake_credentials(monkeypatch_target=probes):
    """Patch ``probes.auth_material`` to a fixed machine credential (no provider)."""
    from unittest import mock

    return mock.patch.object(monkeypatch_target, "auth_material", return_value=("nmas-automation", [{"password": "x"}]))


def observe_attachment(device, attachment):
    return lifecycle.record_observation(device, kind=models.ObservationKind.ATTACHMENT,
                                        source=models.ObservationSource.TRUSTED_UPSTREAM_INTERFACE, actor="nmas-observer",
                                        upstream_device=attachment.upstream_device, upstream_interface=attachment.upstream_interface,
                                        local_interface=attachment.local_interface)


def management_attachment(device, *, upstream, port, local, connectivity=models.AttachmentConnectivity.ACCESS, verify=True):
    result = attachments.register_attachment(device, upstream_device=upstream, upstream_interface=port, local_interface=local,
                                             purpose=models.AttachmentPurpose.MANAGEMENT, connectivity=connectivity, vlan=200, actor=OPERATOR)
    assert result.ok, result.blockers
    result = attachments.approve_attachment(device, result.attachment.pk, actor=APPROVER)
    assert result.ok, result.blockers
    if verify:
        observe_attachment(device, result.attachment)
    result.attachment.refresh_from_db()
    return result.attachment


def nmas_attachment(*, name="nmas-mgmt", interface="nmas-mgmt", upstream="mgmt_swt", port="Ethernet9", source="192.168.200.100",
                    network="192.168.200.0/24", domain="", verify=True):
    result = paths.register_nmas_attachment(name=name, host_interface=interface, upstream_device=upstream, upstream_interface=port,
                                            source_address=source, network=network, failure_domain=domain, actor=OPERATOR)
    assert result.ok, result.blockers
    result = paths.approve_nmas_attachment(result.attachment, actor=APPROVER)
    assert result.ok, result.blockers
    if verify:
        paths.record_nmas_observation(result.attachment, {"interface": interface, "exists": True, "oper_up": True,
                                                          "addresses": [f"{source}/24"], "holds_source": True}, actor="nmas-observer")
    result.attachment.refresh_from_db()
    return result.attachment


def lab():
    """-> dict(devices, nmas, oob) -- the frozen lab's management shape."""
    devices = {}
    for name, role in (("mgmt_swt", "switch"), ("S1", "switch"), ("S3", "switch"), ("R1", "router")):
        result = lifecycle.adopt_existing(name, role=role, actor=APPROVER)
        assert result.ok, result.blockers
        devices[name] = result.device
    for switch, port, local in (("S1", "Ethernet5", "Ethernet5"), ("S3", "Ethernet7", "Ethernet4")):
        management_attachment(devices[switch], upstream="mgmt_swt", port=port, local=local)
    nmas = nmas_attachment()
    oob = management_attachment(devices["R1"], upstream="mgmt_swt", port="Ethernet1", local="Ethernet3")
    return {"devices": devices, "nmas": nmas, "oob": oob}


def path(device, nmas, *, path_type=models.ManagementPathType.DIRECT_OOB, attachment=None, endpoint="192.168.200.1", vrf="",
         approve=True, host_key=HOST_KEY, **extra):
    if path_type == models.ManagementPathType.ROUTED_VRF and nmas.upstream_device != device.name:
        # Unit-only direct NMAS <-> device link.  This is not an assertion
        # about the production topology; the live fixture has the same shape.
        address = ipaddress.ip_address(endpoint)
        network = ipaddress.ip_network(f"{address}/{30 if address.version == 4 else 127}", strict=False)
        source = next(str(ip) for ip in network.hosts() if ip != address)
        suffix = models.NmasManagementAttachment.objects.count()
        nmas = nmas_attachment(name=f"nmas-vrf-{device.name}-{suffix}", interface=f"nmas-vrf-{suffix}",
                               upstream=device.name, source=source, network=str(network), domain=f"vrf-{suffix}")
    result = paths.register_path(device, path_type=path_type, endpoint_address=endpoint, nmas_attachment_id=nmas.pk,
                                 attachment_id=attachment.pk if attachment else None, vrf=vrf,
                                 credential_source=models.ManagementCredentialSource.INVENTORY, expected_host_key=host_key,
                                 actor=OPERATOR, **extra)
    assert result.ok, result.blockers
    if approve:
        result = paths.approve_path(result.path, actor=APPROVER)
        assert result.ok, result.blockers
    return result.path


class KeyOnlySshServer:
    """A key-only SSH server on 127.0.0.1 for ``username`` + ``authorized_public`` that answers exec requests from ``outputs``.

    An interactive shell (pty + shell) echoes each received line after a ``DUT#`` prompt; a line in ``reject`` is answered
    with the EOS ``% Invalid input`` marker; a line in ``stall`` is echoed but never followed by a prompt.  Every shell line is
    recorded in ``shell_lines``."""

    def __init__(self, *, username: str, authorized_public: str, outputs: dict, reject=(), stall=()):
        from core.services.ztp import workflow

        private, _public, self.fingerprint = workflow.generate_enrollment_key(("ssh-ed25519",), "host@test")
        self.host_key = paramiko.Ed25519Key.from_private_key(io.StringIO(private))
        self.username, self.authorized = username, authorized_public.split()[1]
        self.outputs, self.commands, self.auth_attempts = dict(outputs), [], []
        self.reject, self.stall, self.shell_lines = frozenset(reject), frozenset(stall), []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(4)
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.stop = threading.Event()
        self.transports, self.channels = [], []
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        server = self

        class Iface(paramiko.ServerInterface):
            def get_allowed_auths(self, username):
                return "publickey"

            def check_auth_publickey(self, username, key):
                server.auth_attempts.append(username)
                ok = username == server.username and key.get_base64() == server.authorized
                return paramiko.AUTH_SUCCESSFUL if ok else paramiko.AUTH_FAILED

            def check_channel_request(self, kind, chanid):
                return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

            def check_channel_exec_request(self, channel, command):
                text = server.outputs.get(command.decode(), "% Invalid input\n")
                server.commands.append(command.decode())
                channel.sendall(text.encode())
                channel.send_exit_status(0)
                channel.shutdown_write()
                return True

            def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
                return True

            def check_channel_shell_request(self, channel):
                threading.Thread(target=server._shell, args=(channel,), daemon=True).start()
                return True

        while not self.stop.is_set():
            try:
                conn, _addr = self.sock.accept()
            except (socket.timeout, OSError):
                continue
            transport = paramiko.Transport(conn)
            transport.add_server_key(self.host_key)
            self.transports.append(transport)
            try:
                transport.start_server(server=Iface())
            except (paramiko.SSHException, EOFError, OSError):
                continue
            threading.Thread(target=self._channels, args=(transport,), daemon=True).start()

    def _shell(self, channel):
        buffer = b""
        try:
            channel.sendall(b"DUT#")
            while True:
                data = channel.recv(4096)
                if not data:
                    return
                buffer += data
                while b"\n" in buffer:
                    raw, buffer = buffer.split(b"\n", 1)
                    line = raw.decode().rstrip("\r")
                    self.shell_lines.append(line)
                    answer = "% Invalid input\r\n" if line in self.reject else ""
                    if line == "terminal width 511":
                        answer = "Width set to 511 columns.\r\n"
                    elif line == "terminal length 0":
                        answer = "Pagination disabled.\r\n"
                    # a stalled line is echoed but its prompt never returns (a device still working on it)
                    channel.sendall(f"{line}\r\n{answer}{'' if line in self.stall else 'DUT#'}".encode())
        except (OSError, EOFError, paramiko.SSHException):
            return

    def _channels(self, transport):
        while transport.is_active():
            channel = transport.accept(0.5)
            if channel is not None:
                self.channels.append(channel)

    def close(self):
        self.stop.set()
        for transport in self.transports:
            transport.close()
        self.sock.close()
        self.thread.join(5)
