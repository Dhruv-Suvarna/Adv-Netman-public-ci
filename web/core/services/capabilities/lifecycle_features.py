"""Device-lifecycle capabilities in the four-value vocabulary; each names the phase that owns it.

These are NOT matrix cells, so they never enter the 396-cell ledger or its SUPPORTED count.  A status here changes only when
the owning phase lands with its own evidence.  Native ZTP (Phase 3) is per platform: one ``lifecycle.ZTP.<adapter>`` row
derived from the adapter's evidence class -- only SUPPORTED_AND_LIVE_VERIFIED maps to SUPPORTED / PROVEN, an implemented but
not live-proven adapter stays NOT_IMPLEMENTED (feasibility UNKNOWN), and bootstrap delivery is SUPPORTED only while at least
one adapter has live proof of a delivered, applied and verified bootstrap.
"""

from __future__ import annotations

from dataclasses import dataclass

from .axes import CapabilityStatus, Feasibility


@dataclass(frozen=True)
class LifecycleCapability:
    key: str
    label: str
    status: str
    feasibility: str
    owner_phase: int
    basis: str

    def as_dict(self) -> dict:
        return {"key": self.key, "label": self.label, "capability_status": self.status, "feasibility": self.feasibility,
                "owner_phase": self.owner_phase, "basis": self.basis}


_NI, _GAP, _UNKNOWN = CapabilityStatus.NOT_IMPLEMENTED.value, Feasibility.NMAS_GAP.value, Feasibility.UNKNOWN.value

# adapter evidence class -> (capability status, feasibility)
_ZTP_VOCABULARY = {
    "SUPPORTED_AND_LIVE_VERIFIED": (CapabilityStatus.SUPPORTED.value, Feasibility.PROVEN.value),
    "IMPLEMENTED_UNIT_TESTED": (_NI, _UNKNOWN),
    "PARTIALLY_IMPLEMENTED": (_NI, _UNKNOWN),
    "NOT_TESTED_NO_IMAGE": (_NI, Feasibility.UNASSESSED.value),
    "NOT_IMPLEMENTED": (_NI, _GAP),
    "UNSUPPORTED_WITH_VENDOR_EVIDENCE": (CapabilityStatus.UNSUPPORTED.value, Feasibility.PLATFORM_LIMITATION.value),
}


def _ztp_rows() -> tuple:
    from ..ztp.adapters import ADAPTERS          # adapters import nothing from the capability framework

    rows, live = [], []
    for adapter in ADAPTERS.values():
        cap = adapter.capability
        status, feasibility = _ZTP_VOCABULARY[cap.evidence_status]
        if status == CapabilityStatus.SUPPORTED.value:
            live.append(f"{cap.adapter} ({cap.evidence})")
        rows.append(LifecycleCapability(f"lifecycle.ZTP.{cap.adapter}", f"Native ZTP: {cap.vendor} {cap.nos}", status, feasibility, 3,
                                        f"{cap.evidence_status}: {cap.mechanism}. {cap.version_support}."))
    delivery = (LifecycleCapability("lifecycle.BOOTSTRAP_DELIVERY", "Bootstrap configuration delivery", CapabilityStatus.SUPPORTED.value,
                                    Feasibility.PROVEN.value, 3, "Session-bound HTTP delivery live-proven by " + "; ".join(live)
                                    + ". TFTP delivery is unit-tested over real UDP only.")
                if live else
                LifecycleCapability("lifecycle.BOOTSTRAP_DELIVERY", "Bootstrap configuration delivery", _NI, _UNKNOWN, 3,
                                    "Artifact service implemented; no adapter has live proof of an applied bootstrap."))
    return (*rows, delivery)


def _management_rows() -> tuple:
    """V2 Phase 4 rows.  Implemented-and-unit-tested stays NOT_IMPLEMENTED (feasibility UNKNOWN); a row becomes SUPPORTED /
    PROVEN only when ``management.capability_evidence.LIVE`` names a recorded live evidence file for it."""
    from ..management import capability_evidence

    live = capability_evidence.LIVE

    def row(key, label, evidence_key, implemented):
        if live.get(evidence_key):
            return LifecycleCapability(key, label, CapabilityStatus.SUPPORTED.value, Feasibility.PROVEN.value, 4,
                                       f"{implemented} Live evidence: {live[evidence_key]}.")
        return LifecycleCapability(key, label, _NI, _UNKNOWN, 4, f"{implemented} No live evidence is recorded.")

    return (
        row("lifecycle.CREDENTIAL_ONBOARDING", "Credential onboarding (bootstrap credential retirement)", "arista_ceos:live:BCRED",
            "Governed replacement of the ZTP enrollment credential by a key-only SERVICE credential, proven revocation (timed "
            "commit, bootstrap key rejected) and provider retirement: implemented for Arista EOS and unit-tested; every other "
            "platform is refused (BCRED_PLATFORM_NOT_IMPLEMENTED)."),
        row("lifecycle.MGMT_VRF", "Management VRF", "arista_ceos:live:MGMT_VRF",
            "Intent, rendering (EOS / IOS XE / IOS XR / SR Linux / FRR; SONiC mgmt-only; Junos out of scope), validation, "
            "planning, cEOS import and cEOS execution with captured-config compensation are implemented and unit-tested; "
            "cEOS execution stays refused until live evidence is recorded."),
        row("lifecycle.MGMT_FAILOVER", "Management path failover", "arista_ceos:live:MGMT_FAILOVER",
            "Multi-path registry, L1-L6 probes, hysteresis / hold-down selector and the shared resolver are implemented and "
            "unit-tested for cEOS paths; telemetry does not follow failover; NMAS has a single attachment (mgmt_swt), so "
            "management-switch failure tolerance is not claimed."),
    )


def _commissioning_rows() -> tuple:
    """V2 Phases 5 / 6.  Implemented-and-unit-tested stays NOT_IMPLEMENTED (feasibility UNKNOWN); SUPPORTED / PROVEN only when
    ``commissioning.capability_evidence.LIVE`` names a recorded live evidence file."""
    from ..commissioning import capability_evidence

    live = capability_evidence.LIVE

    def row(key, label, phase, evidence_key, implemented):
        if live.get(evidence_key):
            return LifecycleCapability(key, label, CapabilityStatus.SUPPORTED.value, Feasibility.PROVEN.value, phase,
                                       f"{implemented} Live evidence: {live[evidence_key]}.")
        return LifecycleCapability(key, label, _NI, _UNKNOWN, phase, f"{implemented} No live evidence is recorded.")

    return (
        row("lifecycle.ISOLATION", "Trusted-upstream isolation", 5, "arista_ceos:live:ISOLATION",
            "Port ACLs (ingress and egress, IPv4 and IPv6), OSPF passive interface and a management-plane ACL on a trusted cEOS "
            "upstream, governed (plan / precheck / separate approval / digest-verified compensation), verified by read-back, "
            "routing, management-plane, attachment and traffic checks, and gating native ZTP and the ISOLATE edge.  Other "
            "upstream platforms are refused (ISOLATION_PLATFORM_NOT_IMPLEMENTED)."),
        row("lifecycle.COMMISSION", "Commissioning", 6, "arista_ceos:live:COMMISSION",
            "Readiness, evidence-hash-bound separate approval and production configuration through the ordinary provisioning "
            "run (Device Builder candidate, generic execution engine) over the pinned-host-key commissioning transport, with "
            "dependency ordering and cycle refusal.  cEOS devices only."),
        row("lifecycle.ADMISSION", "Production admission", 6, "arista_ceos:live:ADMISSION",
            "Controlled release of the isolation with OSPF / route / reachability verification on the trusted upstream, "
            "digest-verified restoration on failure (UNCERTAIN when unproven) and durable NSOT / topology / monitoring hand-offs."),
    )


CAPABILITIES = (
    *_ztp_rows(),
    *_management_rows(),
    *_commissioning_rows(),
    LifecycleCapability("lifecycle.DECOMMISSION", "Decommissioning", _NI, _GAP, 7,
                        "Lifecycle edges into DECOMMISSION_PENDING / DECOMMISSIONED are defined and refused."),
    LifecycleCapability("lifecycle.EXACT_RESTORATION", "Exact configuration restoration", _NI, _UNKNOWN, 7,
                        "No verified exact restore of a device's full configuration exists outside Maintenance Mode's own scope."),
)


def by_key() -> dict:
    return {capability.key: capability for capability in CAPABILITIES}
