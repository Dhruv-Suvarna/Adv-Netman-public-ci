"""Evidence-based Raw Configlet capability matrices.

Two INDEPENDENT dimensions, both using the project's four-state vocabulary (SUPPORTED / NOT_IMPLEMENTED / UNSUPPORTED / UNKNOWN):

* VERIFICATION  can this platform's raw configuration be checked in an isolated sandbox / offline parser?
* EXECUTION     can the Phase-17 engine send a verified Raw Configlet to a real device of this platform?

A platform never becomes raw-deployable merely because structured execution or verification exists.  Nothing here is inferred
from vendor knowledge: each SUPPORTED row cites what was actually observed in this repository / runtime (Phase-18 discovery).
Only syntax is ever verified; no verifier claims semantic correctness.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType

from ..health.codes import Capability


@dataclass(frozen=True)
class VerificationCapability:
    status: str
    adapter_id: str = ""
    requires_privileged: bool = False
    evidence: str = ""
    note: str = ""


@dataclass(frozen=True)
class ExecutionCapability:
    apply: str
    compensation: str
    evidence: str = ""
    note: str = ""


_NOT_COMPENSABLE = "A Raw Configlet lacks proven transactional compensation (no inverse can be derived from opaque text), so Complete mode is refused."

VERIFICATION = MappingProxyType({
    "arista_ceos": VerificationCapability(
        Capability.SUPPORTED, "ceos_config_session", True,
        "Local image ceos:4.36.2F (the image the live cEOS nodes run) started as a DISPOSABLE, network-less container; the EOS CLI "
        "parses the statements inside a `configure session` that is always aborted (Phase-18 discovery: boots in ~36 s, invalid "
        "input reported as '% Invalid input at line N').",
        "Syntax only. cEOS needs --privileged (systemd as PID 1, exactly as containerlab starts it), so this backend is DISABLED by "
        "default and enabled only by an explicit server setting; the reduced isolation is documented, not hidden.",
    ),
    "ubuntu_frr": VerificationCapability(
        Capability.SUPPORTED, "frr_vtysh_dryrun", False,
        "FRR `vtysh --dryrun` (-C) against the same distro package version R3/R4 run (frr 8.4.4-1.1ubuntu6.7), built from the local "
        "ubuntu:24.04 base: unprivileged, network-less, read-only root, all capabilities dropped (Phase-18 discovery).",
        "Syntax only: vtysh parses against its compiled command tree; no daemon runs and no semantic check is made.",
    ),
    "nokia_srlinux": VerificationCapability(Capability.UNSUPPORTED, evidence="Nokia SR Linux is not part of the approved Labs 2/3 baseline; no verifier exists."),
    "cisco_c8000v_iosxe": VerificationCapability(Capability.NOT_IMPLEMENTED, evidence="The IOS XE qcow2 has no NMAS offline verifier."),
    "cisco_iosxr": VerificationCapability(Capability.NOT_IMPLEMENTED, evidence="No IOS XR image or offline verifier is available locally."),
    "sonic": VerificationCapability(Capability.NOT_IMPLEMENTED, evidence="No SONiC image or offline parser is available locally."),
})

EXECUTION = MappingProxyType({
    "arista_ceos": ExecutionCapability(
        Capability.SUPPORTED, Capability.NOT_IMPLEMENTED,
        "Phase-17 cEOS executor (Netmiko configuration mode, master.py::push_eos pattern) sends the verified, pinned statements.",
        "Partial (UAT) only. " + _NOT_COMPENSABLE,
    ),
    "ubuntu_frr": ExecutionCapability(
        Capability.NOT_IMPLEMENTED, Capability.NOT_IMPLEMENTED,
        "master.py applies FRR only as a whole frr.conf + `vtysh -b`; no incremental, supported raw-FRR apply mechanism is proven, and a "
        "Raw Configlet is never interpreted as a Linux shell command.",
    ),
    "nokia_srlinux": ExecutionCapability(Capability.UNSUPPORTED, Capability.UNSUPPORTED, "Not part of the approved live baseline."),
    "cisco_c8000v_iosxe": ExecutionCapability(Capability.NOT_IMPLEMENTED, Capability.NOT_IMPLEMENTED, "No NMAS IOS XE session or apply path."),
    "cisco_iosxr": ExecutionCapability(Capability.NOT_IMPLEMENTED, Capability.NOT_IMPLEMENTED, "No NMAS IOS XR session or apply path."),
    "sonic": ExecutionCapability(Capability.NOT_IMPLEMENTED, Capability.NOT_IMPLEMENTED, "No repository evidence of a session or apply path."),
})

_UNKNOWN_VERIFICATION = VerificationCapability(Capability.UNKNOWN, evidence="Platform not recognised by the raw verifier.")
_UNKNOWN_EXECUTION = ExecutionCapability(Capability.UNKNOWN, Capability.UNKNOWN, "Platform not recognised.")


def verification_capability(platform: str) -> VerificationCapability:
    return VERIFICATION.get(platform, _UNKNOWN_VERIFICATION)


def execution_capability(platform: str) -> ExecutionCapability:
    return EXECUTION.get(platform, _UNKNOWN_EXECUTION)


def can_author(platform: str) -> bool:
    """A Raw Configlet may only be authored for a platform that has an evidence-backed verification path."""
    return verification_capability(platform).status == Capability.SUPPORTED


def compensation_note() -> str:
    return _NOT_COMPENSABLE


def capability_matrix() -> list[dict]:
    """A presentable table of every catalogued platform (used by the UI and the documentation)."""
    rows = []
    for platform in VERIFICATION:
        verify, run = verification_capability(platform), execution_capability(platform)
        rows.append({
            "platform": platform, "verification": verify.status, "adapter": verify.adapter_id, "privileged_sandbox": verify.requires_privileged,
            "execution": run.apply, "compensation": run.compensation, "verification_evidence": verify.evidence, "execution_evidence": run.evidence,
        })
    return rows
