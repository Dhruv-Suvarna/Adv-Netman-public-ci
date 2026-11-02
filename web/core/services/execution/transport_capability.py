"""Deployment transport capability -- what can actually push a candidate to a
device, as distinct from what can read/monitor it (Phase 20.5 spec section
14: "protocol reachable" / "read operations supported" / "configuration
writes supported" are different facts, and this project must never conflate
them).

This is deliberately its own small module, not part of ``platform_drivers``:
``platform_drivers``/``PLATFORM_CAPABILITIES`` answer "can this project render
CLI for this feature on this platform" (candidate composition); this module
answers "can this project actually deliver a candidate to the device, and
over what transport" (deployment). The two questions have different
registries and different evidence.

Evidence for every row below: ``core/services/execution/executors/registry.py``
(``EXECUTORS``) is the single place a platform selects a real, tested
deployment mechanism:

* ``arista_ceos``  -> ``executors.ceos.CeosExecutor``  (Netmiko SSH configuration-mode session).
* ``ubuntu_frr``   -> ``executors.linux.LinuxExecutor`` (``docker exec <container> <argv>``, a
  lab-local container transport, not a network management protocol).
* ``nokia_srlinux`` -> ``executors.srlinux.SrLinuxExecutor`` (one atomic gNMI CLI-origin Set per
  Configlet, gNMI Get captured-tree inverse; live-verified on an isolated SR Linux 24.10.7 node).
* ``cisco_c8000v_iosxe`` -> ``executors.iosxe.IosXeExecutor`` (Netmiko SSH configuration-mode session,
  captured running-config inverse; live-verified on an isolated Catalyst 8000V, IOS XE 17.06.01a).
* Cisco IOS XR / ``sonic`` -> no entry: deployment is UNAVAILABLE.

NETCONF monitoring remains read-only.  Only AVAILABLE rows are selectable.
"""

from __future__ import annotations

from enum import StrEnum

from .executors.registry import EXECUTORS
from ..health import inventory


class TransportStatus(StrEnum):
    AVAILABLE = "AVAILABLE"
    READ_ONLY = "READ_ONLY"
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"
    IMPLEMENTED_NOT_LIVE_VERIFIED = "IMPLEMENTED_NOT_LIVE_VERIFIED"
    IMPLEMENTED_DISABLED = "IMPLEMENTED_DISABLED"
    PLATFORM_CAPABILITY_UNVERIFIED = "PLATFORM_CAPABILITY_UNVERIFIED"


class Transport(StrEnum):
    SSH_CLI = "SSH_CLI"
    DOCKER_EXEC = "DOCKER_EXEC"
    NETCONF = "NETCONF"
    GNMI_SET = "GNMI_SET"


_TRANSPORT_LABEL = {
    Transport.SSH_CLI: "SSH CLI (Netmiko configuration-mode session)",
    Transport.DOCKER_EXEC: "Docker exec (lab-local container transport)",
    Transport.NETCONF: "NETCONF <edit-config>",
    Transport.GNMI_SET: "gNMI Set",
}

_EXECUTOR_TRANSPORT = {
    "ceos": Transport.SSH_CLI,
    "linux": Transport.DOCKER_EXEC,
    "nokia_srlinux": Transport.GNMI_SET,
    "cisco_c8000v_iosxe": Transport.SSH_CLI,
}

_MODEL_DRIVEN_STATUS = {
    "arista_ceos": {
        Transport.NETCONF: (TransportStatus.READ_ONLY, "Live NETCONF reads exist, but no safe NMAS writer, write credential, or rollback path exists."),
        Transport.GNMI_SET: (TransportStatus.READ_ONLY, "Live gNMI reads exist; Set paths and a write-privileged credential are unverified."),
    },
    "ubuntu_frr": {
        Transport.NETCONF: (TransportStatus.READ_ONLY, "The repository-owned live lab adapter intentionally implements read-only NETCONF."),
        Transport.GNMI_SET: (TransportStatus.READ_ONLY, "The repository-owned live lab adapter intentionally rejects gNMI Set."),
    },
    "nokia_srlinux": {
        Transport.NETCONF: (TransportStatus.NOT_IMPLEMENTED, "Device support is documented, but NMAS has no native-YANG NETCONF translator."),
        Transport.GNMI_SET: (
            TransportStatus.AVAILABLE,
            "Atomic CLI-origin Set with gNMI Get readback and captured-tree compensation, live-verified on an isolated SR Linux 24.10.7 node (interfaces, addresses, static routes).",
        ),
    },
    "cisco_c8000v_iosxe": {
        Transport.NETCONF: (TransportStatus.NOT_IMPLEMENTED, "The C8000V artifact is IOS XE; NMAS has no tested native-YANG translator or live session."),
        Transport.GNMI_SET: (TransportStatus.NOT_IMPLEMENTED, "NMAS has no IOS XE gNMI path mapping or live session."),
    },
    "cisco_iosxr": {
        Transport.NETCONF: (TransportStatus.NOT_IMPLEMENTED, "IOS XR support is documented, but the target release/model inventory is unpinned and NMAS has no tested native-YANG translator."),
        Transport.GNMI_SET: (TransportStatus.NOT_IMPLEMENTED, "IOS XR model-driven writes are documented, but NMAS has no tested per-feature path mapping."),
    },
    "sonic": {
        Transport.NETCONF: (TransportStatus.PLATFORM_CAPABILITY_UNVERIFIED, "NETCONF availability and schema depend on the absent SONiC image."),
        Transport.GNMI_SET: (TransportStatus.PLATFORM_CAPABILITY_UNVERIFIED, "gNMI management-framework availability and paths depend on the absent SONiC image."),
    },
}

# Device/NOS protocol capability is intentionally separate from NMAS
# deployment capability.  A writable server does not make a CLI candidate a
# valid YANG/gNMI payload, and must never make an unimplemented button appear.
# ``UNKNOWN`` means no matching image is deployed in the frozen Lab 1
# baseline, not that the NOS lacks the protocol.
DEVICE_PROTOCOL_CAPABILITIES = {
    "arista_ceos": {
        "NETCONF": {
            "present": True, "read": True, "writable": True, "edit_config": True,
            "running": True, "candidate": True, "commit": True, "confirmed_commit": False,
            "evidence": "Live cEOS 4.36.2F hello discovery on 2026-09-26 (351 capabilities): writable-running and candidate advertised; confirmed-commit, validate, and rollback-on-error absent.",
            "nmas_write_suitable": False,
            "suitability_reason": (
                "NMAS candidates are EOS CLI, not a validated YANG payload; the live server "
                "lacks confirmed-commit/validate/rollback-on-error required for a safe new "
                "writer. Additionally (Phase 20.5 review of modules/netconf.py), the only "
                "NETCONF session this project builds authenticates as the read-only "
                "`nmas-telemetry` identity; no config-write-privileged credential exists in "
                "this project's credential model, and provisioning one is a device-config "
                "change outside a rendering-only phase's scope."
            ),
        },
        "GNMI_SET": {
            "present": True, "read": True, "writable": "UNVERIFIED", "set": "UNVERIFIED",
            "evidence": "The deployed image is read successfully by the existing gNMI monitoring adapter; no safe live Set probe was sent.",
            "nmas_write_suitable": False,
            "suitability_reason": (
                "No validated configuration path/model map exists for the canonical Device "
                "Builder model, and (Phase 20.5 review of modules/gnmi.py) the only gNMI "
                "session this project builds also authenticates as the read-only "
                "`nmas-telemetry` identity -- the same credential-scope gap as NETCONF above."
            ),
        },
    },
    "ubuntu_frr": {
        "NETCONF": {"present": False, "read": False, "writable": False, "edit_config": False,
                    "running": False, "candidate": False, "commit": False, "confirmed_commit": False,
                    "evidence": "The approved Ubuntu 24.04/FRR 8.4.4 containers expose fixed read-only docker-exec probes; no NETCONF server is installed.",
                    "nmas_write_suitable": False, "suitability_reason": "No device NETCONF endpoint."},
        "GNMI_SET": {"present": False, "read": False, "writable": False, "set": False,
                     "evidence": "The approved Ubuntu/FRR containers expose no gNMI target.",
                     "nmas_write_suitable": False, "suitability_reason": "No device gNMI endpoint."},
    },
    "nokia_srlinux": {
        "NETCONF": {"present": True, "read": True, "writable": True, "edit_config": True,
                    "running": True, "candidate": True, "commit": True, "confirmed_commit": True,
                    "evidence": "Nokia SR Linux 24.10 NETCONF documentation advertises candidate, edit-config, validate, rollback-on-error, commit and confirmed-commit; no SR Linux node is deployed in the approved baseline.",
                    "nmas_write_suitable": False, "suitability_reason": "NMAS has neither an SR Linux canonical-to-YANG translator nor a deployed target for safe discovery/post-verification."},
        "GNMI_SET": {"present": True, "read": True, "writable": True, "set": True,
                     "evidence": "Nokia SR Linux 24.10 gNMI documentation describes private candidates and the commit-confirmed extension; no SR Linux node is deployed in the approved baseline.",
                     "nmas_write_suitable": True, "suitability_reason": (
                         "The registered SR Linux executor sends one atomic CLI-origin Set per Configlet and "
                         "proves compensation by gNMI Get readback (isolated 24.10.7 node); commit-confirmed "
                         "is not used because the installed client does not expose it."
                     )},
    },
    "cisco_c8000v_iosxe": {
        "NETCONF": {"present": "ARTIFACT_UNBOOTED", "read": "UNVERIFIED", "writable": "UNVERIFIED", "edit_config": "UNVERIFIED",
                    "running": "UNVERIFIED", "candidate": "UNVERIFIED", "commit": "UNVERIFIED", "confirmed_commit": "UNVERIFIED",
                    "evidence": "Catalyst 8000V IOS XE 17.06.01a qcow2 is present but was not boot-validated through NMAS.",
                    "nmas_write_suitable": False, "suitability_reason": "No NMAS live target, translator, or post-write verifier."},
        "GNMI_SET": {"present": "UNVERIFIED", "read": "UNVERIFIED", "writable": "UNVERIFIED", "set": "UNVERIFIED",
                     "evidence": "The local IOS XE artifact has not been live-discovered for gNMI.",
                     "nmas_write_suitable": False, "suitability_reason": "No NMAS path mapping or live target."},
    },
    "cisco_iosxr": {
        "NETCONF": {"present": True, "read": True, "writable": True, "edit_config": True,
                    "running": True, "candidate": True, "commit": True, "confirmed_commit": True,
                    "evidence": "Cisco 8000 IOS XR programmability documentation lists candidate, confirmed-commit, rollback-on-error and validate; no IOS XR node is deployed in the approved baseline.",
                    "nmas_write_suitable": False, "suitability_reason": "NMAS has no tested IOS XR YANG translator or deployed target."},
        "GNMI_SET": {"present": "DOCUMENTED", "read": "DOCUMENTED", "writable": "DOCUMENTED", "set": "DOCUMENTED",
                     "evidence": "Cisco IOS XR programmability documentation covers model-driven gNMI configuration; exact image capabilities are not live-discovered in this lab.",
                     "nmas_write_suitable": False, "suitability_reason": "No deployed target or tested canonical path/model mapping."},
    },
    "sonic": {
        "NETCONF": {"present": "IMAGE_DEPENDENT", "read": "IMAGE_DEPENDENT", "writable": "IMAGE_DEPENDENT", "edit_config": "IMAGE_DEPENDENT",
                    "running": "IMAGE_DEPENDENT", "candidate": "IMAGE_DEPENDENT", "commit": "IMAGE_DEPENDENT", "confirmed_commit": "IMAGE_DEPENDENT",
                    "evidence": "No SONiC node or image/version is present in the approved baseline; protocol availability is distribution/image dependent.",
                    "nmas_write_suitable": False, "suitability_reason": "No authoritative target schema/image or live capability discovery."},
        "GNMI_SET": {"present": "IMAGE_DEPENDENT", "read": "IMAGE_DEPENDENT", "writable": "IMAGE_DEPENDENT", "set": "IMAGE_DEPENDENT",
                     "evidence": "SONiC management-framework/gNMI support is image dependent; this baseline has no SONiC node to discover models or paths.",
                     "nmas_write_suitable": False, "suitability_reason": "No authoritative target schema/image or live capability discovery."},
    },
}


def device_protocol_capabilities(platform: str) -> dict:
    """Device-side read/write facts; never interpreted as NMAS support."""
    if platform not in DEVICE_PROTOCOL_CAPABILITIES:
        raise ValueError(f"Unknown platform {platform!r}")
    return DEVICE_PROTOCOL_CAPABILITIES[platform]


def deployment_transport_matrix(platform: str) -> list[dict]:
    """One row per known transport for ``platform``: {transport, label, status, evidence}.

    The row with status AVAILABLE (there is at most one) is the transport
    ``executors.registry.executor_for()`` will actually use; this function
    never invents a second, alternative writable transport."""
    health_key = inventory.health_platform(platform)
    executor_transport = _EXECUTOR_TRANSPORT.get(health_key) if health_key in EXECUTORS else None

    rows = []
    for transport in Transport:
        if transport in (Transport.SSH_CLI, Transport.DOCKER_EXEC) or transport == executor_transport:
            if transport == executor_transport:
                status, evidence = TransportStatus.AVAILABLE, "The real, tested deployment path for this platform."
            else:
                status, evidence = TransportStatus.NOT_IMPLEMENTED, "Not this platform's deployment mechanism."
        else:
            status, evidence = _MODEL_DRIVEN_STATUS[platform][transport]
        rows.append({
            "transport": transport.value, "label": _TRANSPORT_LABEL[transport],
            "status": status.value, "evidence": evidence,
        })
    return rows


def selected_transport(platform: str) -> str | None:
    """The one AVAILABLE transport for ``platform``, or None."""
    for row in deployment_transport_matrix(platform):
        if row["status"] == TransportStatus.AVAILABLE.value:
            return row["transport"]
    return None
