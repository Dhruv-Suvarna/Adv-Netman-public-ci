"""Bootstrap reality: is the device unreachable, a reachable bootstrap device, or an already configured device?

Three different situations and three different workflows -- provisioning proceeds to execution only for the second:

    UNREACHABLE          nothing answers.  The request stays STAGED: identity, capability, IPAM planning and reservation are possible; nothing is
                         executed and nothing is pretended.  Zero-touch bootstrap (ZTP / DHCP-driven imaging) needs infrastructure this lab does not
                         have, so it is not implemented and not simulated.
    REACHABLE_BOOTSTRAP  the device answers on a PROVEN transport and carries no routed configuration of its own.
    ALREADY_CONFIGURED   the device answers and already holds configuration: that is onboarding (import the running configuration through the
                         existing-device workflow), not provisioning, and is refused here.

Transports are listed per platform and only where the registered executor really uses that transport for a device that has no ``inventory.yml``
entry.  A cEOS / SR Linux / IOS XE executor exists, but each resolves its session from inventory-declared credentials, so a NEW device has no
session: those platforms are honestly unsupported for bootstrap until credential onboarding exists.

The one process boundary is ``docker inspect`` / ``docker exec`` with a fixed argv list, ``shell=False``.  No credential is read or stored.
"""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass, field

from ... import models
from ..health import inventory
from .codes import blocker

State, Transport = models.BootstrapState, models.BootstrapTransport

# platform -> {transport: evidence}.  Deliberately small: only what an executor can really carry for an inventory-less device.
SUPPORTED_TRANSPORTS = {
    models.Platform.UBUNTU_FRR: {
        Transport.DOCKER_EXEC: "LinuxExecutor: every read and write is `docker exec <container> <validated argv>`; no credential, no inventory entry needed.",
    },
    # V2 Phase 6: a natively onboarded cEOS is reached by the ordinary CeosExecutor through nsot_live's commissioning fallback
    # (commissioning.transport): its ZTP-enrolled pinned host key and the key-only service credential of a COMPLETE bootstrap
    # credential retirement.  Only commissioning runs use it, and writes are allowed only while the commissioning is approved.
    models.Platform.ARISTA_CEOS: {
        Transport.ZTP_MANAGEMENT: "CeosExecutor over the commissioning transport: pinned ZTP host key + retired-bootstrap service credential "
                                  "(V2 Phases 3/4/6); live-verified on cEOSLab 4.36.2F in the isolated commissioning fixture.",
    },
}
UNSUPPORTED_REASON = {
    models.Platform.ARISTA_CEOS: ("A device with no inventory entry has no credential for SSH / gNMI; only a natively onboarded device "
                                  "(ZTP_MANAGEMENT, through governed commissioning) is reached, with its retired-bootstrap service credential."),
    models.Platform.NOKIA_SRLINUX: "SrLinuxExecutor needs a gNMI credential and an inventory target; no credential onboarding exists for a new device.",
    models.Platform.CISCO_C8000V_IOSXE: "IosXeExecutor needs an SSH credential and an inventory target; no credential onboarding exists for a new device.",
    models.Platform.CISCO_IOSXR: "No IOS XR executor is registered.",
    models.Platform.SONIC: "No SONiC executor is registered.",
}
_CONTAINER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_LAB = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_TIMEOUT = 15
# FRR statements that mean "this device is already configured" (a pristine FRR prints only its preamble).
_CONFIGURED = re.compile(r"^(router |ip route |ipv6 route | ip address | ipv6 address | ip ospf | ipv6 ospf)", re.MULTILINE)


def configured_interfaces(links: list, management_interface: str) -> list[str]:
    """Interfaces that already carry configuration in the KERNEL (found by the live proof: the Linux executor configures links and
    addresses with iproute2, so an FRR running configuration alone says nothing about them).

    Configured means: a global-scope address on any interface other than loopback ``lo`` and the declared management interface, or any
    ``dummy`` link (NMAS renders loopbacks as dummy links).  Unaddressed data links of a freshly cabled node are not configuration.
    """
    found = []
    for link in links or []:
        name = str(link.get("ifname") or "")
        if name in ("lo", management_interface):
            continue
        global_addresses = [a for a in (link.get("addr_info") or []) if a.get("scope") == "global"]
        if global_addresses or str((link.get("linkinfo") or {}).get("info_kind") or "") == "dummy":
            found.append(name)
    return sorted(found)


def transport_support(platform: str, transport: str) -> tuple[bool, str]:
    evidence = SUPPORTED_TRANSPORTS.get(platform, {}).get(transport)
    if evidence:
        return True, evidence
    return False, UNSUPPORTED_REASON.get(platform, "") or f"{transport or 'No transport'} is not a proven bootstrap transport for {platform}."


def production_lab() -> str:
    return str(inventory.load_inventory().get("lab_name") or "")


def target_blockers(platform: str, transport: str, target: dict) -> list[dict]:
    """Static checks of the bootstrap reference (no device contact)."""
    ok, reason = transport_support(platform, transport)
    if not ok:
        return [blocker("BOOTSTRAP_TRANSPORT_UNSUPPORTED", platform=platform, transport=transport, reason=reason)]
    if transport == Transport.ZTP_MANAGEMENT:
        # the target is a natively onboarded ManagedDevice (DEV-000001), never a container or an address typed by a person
        device_id = str(target.get("device") or "")
        found = models.ManagedDevice.objects.filter(pk=int(device_id[4:])).first() if re.fullmatch(r"DEV-\d{6}", device_id) else None
        if found is None or found.origin != models.DeviceOrigin.REGISTERED_NEW or found.platform != platform:
            return [blocker("BOOTSTRAP_TARGET_INVALID")]
        return []
    container, lab = str(target.get("container") or ""), str(target.get("lab") or "")
    if not _CONTAINER.fullmatch(container) or not _LAB.fullmatch(lab):
        return [blocker("BOOTSTRAP_TARGET_INVALID")]
    production = production_lab()
    if lab == production or container.startswith(f"clab-{production}-"):
        return [blocker("BOOTSTRAP_TARGET_IS_PRODUCTION", lab=lab)]
    return []


@dataclass
class Probe:
    """What a read-only look at the target found.  ``facts`` is bounded and secret-free."""

    exists: bool = False
    running: bool = False
    lab: str = ""
    answers: bool = False              # the configuration read succeeded
    configured: bool = False
    facts: dict = field(default_factory=dict)
    error: str = ""


def _run(argv) -> subprocess.CompletedProcess:
    return subprocess.run(argv, capture_output=True, text=True, timeout=_TIMEOUT, shell=False, check=False)  # noqa: S603 - fixed argv list


def docker_prober(target: dict) -> Probe:
    """The default read-only probe for the DOCKER_EXEC transport."""
    container = str(target.get("container") or "")
    if not _CONTAINER.fullmatch(container):
        return Probe(error="TARGET_INVALID")
    try:
        inspected = _run(["docker", "inspect", container])
        if inspected.returncode:
            return Probe(error="NOT_FOUND")
        document = (json.loads(inspected.stdout) or [{}])[0]
        labels = (document.get("Config") or {}).get("Labels") or {}
        probe = Probe(exists=True, running=bool((document.get("State") or {}).get("Running")), lab=str(labels.get("containerlab") or ""),
                      facts={"image": str((document.get("Config") or {}).get("Image") or "")[:128],
                             "node_kind": str(labels.get("clab-node-kind") or "")[:32]})
        if not probe.running:
            probe.error = "NOT_RUNNING"
            return probe
        config = _run(["docker", "exec", container, "vtysh", "-c", "show running-config"])
        links = _run(["docker", "exec", container, "ip", "-j", "-d", "addr", "show"])
        if config.returncode or links.returncode or "failed to connect" in config.stdout.lower():
            probe.error = "NO_MANAGEMENT_PLANE"
            return probe
        parsed = json.loads(links.stdout or "[]")
        names = sorted(str(link.get("ifname")) for link in parsed)
        already = configured_interfaces(parsed, str(target.get("management_interface") or ""))
        probe.answers = True
        probe.configured = bool(_CONFIGURED.search(config.stdout)) or bool(already)
        probe.facts.update({"interfaces": names[:32], "config_lines": len(config.stdout.splitlines()), "configured_interfaces": already[:16]})
        return probe
    except (OSError, subprocess.SubprocessError, ValueError):
        return Probe(error="PROBE_FAILED")


def classify(run, *, prober=None) -> tuple[str, dict, list[dict]]:
    """-> (bootstrap state, evidence, blockers).  The probe is read-only; a production-lab container is refused whatever was declared."""
    static = target_blockers(run.platform, run.bootstrap_transport, run.bootstrap_target or {})
    if static:
        return State.UNKNOWN, {}, static
    if prober is None and run.bootstrap_transport == Transport.ZTP_MANAGEMENT:
        from ..commissioning import transport as commissioning_transport

        prober = commissioning_transport.prober
    probe = (prober or docker_prober)({**run.bootstrap_target, "management_interface": str((run.management or {}).get("interface") or "")})
    evidence = {"exists": probe.exists, "running": probe.running, "lab": probe.lab, "answers": probe.answers,
                "configured": probe.configured, "facts": probe.facts, "error": probe.error}
    if run.bootstrap_transport == Transport.ZTP_MANAGEMENT:
        pass                                     # no container / lab: the target is an onboarded device (checked statically above)
    elif probe.exists and (probe.lab == production_lab() or probe.lab != str(run.bootstrap_target.get("lab"))):
        code = "BOOTSTRAP_TARGET_IS_PRODUCTION" if probe.lab == production_lab() else "BOOTSTRAP_TARGET_INVALID"
        return State.UNKNOWN, evidence, [blocker(code, lab=probe.lab)]
    if not probe.answers:
        return State.UNREACHABLE, evidence, []
    if probe.configured:
        return State.ALREADY_CONFIGURED, evidence, []
    return State.REACHABLE_BOOTSTRAP, evidence, []
