"""The native-ZTP adapter contract.  The lifecycle never branches on a vendor: it asks the platform's adapter.

An adapter describes and drives ONE vendor's documented native bootstrap mechanism -- the DHCP parameters that mechanism reads,
the artifact format it executes, the transports it can fetch with, what it needs for first management trust, how it retries
and how it can be recovered.  It never invents a device-side helper, never embeds a secret and never claims live support it
has no evidence for: ``capability.evidence_status`` is a report-level classification, separate from the four-value
capability vocabulary (``capabilities.lifecycle_features`` maps it).
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

# Report-level evidence classes (Phase 3 handoff vocabulary).  Only SUPPORTED_AND_LIVE_VERIFIED maps to SUPPORTED.
SUPPORTED_AND_LIVE_VERIFIED = "SUPPORTED_AND_LIVE_VERIFIED"
IMPLEMENTED_UNIT_TESTED = "IMPLEMENTED_UNIT_TESTED"
PARTIALLY_IMPLEMENTED = "PARTIALLY_IMPLEMENTED"
NOT_IMPLEMENTED = "NOT_IMPLEMENTED"
UNSUPPORTED_WITH_VENDOR_EVIDENCE = "UNSUPPORTED_WITH_VENDOR_EVIDENCE"
NOT_TESTED_NO_IMAGE = "NOT_TESTED_NO_IMAGE"
EVIDENCE_CLASSES = (SUPPORTED_AND_LIVE_VERIFIED, IMPLEMENTED_UNIT_TESTED, PARTIALLY_IMPLEMENTED, NOT_IMPLEMENTED,
                    UNSUPPORTED_WITH_VENDOR_EVIDENCE, NOT_TESTED_NO_IMAGE)

# Transports, strongest first.  "Integrity" here means transport integrity; NONE of them authenticates a new device.
HTTPS, HTTP, TFTP = "HTTPS", "HTTP", "TFTP"
TRANSPORT_STRENGTH = {HTTPS: 3, HTTP: 2, TFTP: 1}
# What the NMAS artifact service really implements today.  HTTPS needs a trust anchor on a factory-default device and a
# certificate service; it is not offered until both exist (no silent downgrade: see ``select_bootstrap_transport``).
SERVICE_TRANSPORTS = (HTTP, TFTP)


class TransportPolicy:
    """Explicit bootstrap transport security policies (selected per bootstrap network)."""

    ISOLATED_LAB = "ISOLATED_LAB"        # isolated, NMAS-only bootstrap segment: HTTPS > HTTP > TFTP, all allowed
    INTEGRITY_REQUIRED = "INTEGRITY_REQUIRED"   # HTTPS only
    ALLOWED = {ISOLATED_LAB: (HTTPS, HTTP, TFTP), INTEGRITY_REQUIRED: (HTTPS,)}


@dataclass(frozen=True)
class NativeCapability:
    adapter: str
    vendor: str
    nos: str
    platform: str                       # catalogue platform value ('' when the NOS is not in the NMAS platform catalogue)
    mechanism: str
    version_support: str
    min_version: tuple = ()
    transports: tuple = ()              # transports the NATIVE mechanism can fetch with
    discovery: str = ""
    artifact_format: str = ""
    enrollment: str = ""
    enrollment_key_types: tuple = ()    # public-key algorithms the native artifact can install for first management trust
    runtime_conditions: tuple = ()
    evidence_status: str = NOT_IMPLEMENTED
    evidence: str = ""
    limitations: tuple = ()
    implemented: bool = False           # the adapter renders and verifies (not the same as live support)

    def as_dict(self) -> dict:
        return {k: (list(v) if isinstance(v, tuple) else v) for k, v in self.__dict__.items()}


@dataclass(frozen=True)
class DiscoveryParameters:
    """Provider-neutral DHCP parameters the native mechanism reads.  ``options`` uses ISC option names; providers translate."""

    vendor_class_prefix: str = ""       # option 60 prefix the class must match ('' = no vendor match)
    options: tuple = ()                 # ((name, value), ...) e.g. ("bootfile-name", url)
    dhcp_family: int = 4
    notes: str = ""


@dataclass(frozen=True)
class BootstrapContext:
    hostname: str
    session_id: str
    auth_id: str
    interface: str                      # the device's bootstrap interface (local end of the authorized attachment)
    address: str
    prefixlen: int
    gateway: str
    service_address: str
    service_prefix: str
    enrollment_user: str
    enrollment_public_key: str
    locked_password_hash: str = ""      # crypt hash of discarded random bytes (platforms that require a password field)


@dataclass(frozen=True)
class RenderedBootstrap:
    filename: str
    content: str
    content_type: str
    kind: str


@dataclass(frozen=True)
class TransportDecision:
    selected: str
    candidates: tuple
    policy: str
    reason: str
    blockers: tuple = ()

    def as_dict(self) -> dict:
        return {"selected": self.selected, "candidates": list(self.candidates), "policy": self.policy, "reason": self.reason,
                "authenticates_device": False, "integrity_protected": self.selected == HTTPS}


@dataclass
class VerificationReport:
    ok: bool
    checks: list = field(default_factory=list)       # [{"check", "ok", "detail"}]
    claims: dict = field(default_factory=dict)       # serial / base_mac / model / version read over the session
    ztp_disabled: bool | None = None
    production_services: list = field(default_factory=list)

    def add(self, check: str, ok: bool, detail: str = "") -> None:
        self.checks.append({"check": check, "ok": bool(ok), "detail": str(detail)[:200]})
        if not ok:
            self.ok = False

    def as_dict(self) -> dict:
        return {"ok": self.ok, "checks": self.checks, "claims": self.claims, "ztp_disabled": self.ztp_disabled,
                "production_services": self.production_services}


@dataclass(frozen=True)
class RetryBehavior:
    dhcp_retry: str
    dhcp_retry_interval_seconds: int | None
    retries_indefinitely: bool | None   # None = not documented / not observed
    ztp_retry: str
    evidence: str

    def as_dict(self) -> dict:
        return dict(self.__dict__)


@dataclass(frozen=True)
class RecoveryAction:
    key: str
    label: str
    native: bool                        # a documented device-native operation (not a container restart)
    requires: str
    command: str = ""

    def as_dict(self) -> dict:
        return dict(self.__dict__)


@dataclass(frozen=True)
class ZtpDisableCapability:
    automatic_after_success: bool | None
    verifiable_over_management: bool
    how: str
    read_back: str = ""

    def as_dict(self) -> dict:
        return dict(self.__dict__)


_SECRET_LINE = re.compile(
    r"(?i)(-----BEGIN [A-Z ]*PRIVATE KEY-----|\bpassword\s+(0\s+|7\s+)?[^\s$]|\bsecret\s+0\s|\bkey\s+0\s|\bcommunity\s+\S|"
    r"\bapi[_-]?key\b\s*[:=]|\btoken\b\s*[:=]|\bauthorization:\s*bearer|\bpre-shared-key\b|\bradius-server\b.*\bkey\b)")


def secret_findings(content: str) -> list[str]:
    """Secret-shaped lines in a rendered bootstrap (line numbers only).  A public key and a crypt hash of discarded random
    bytes are not secrets; a plaintext password, private key, shared secret or bearer token always is."""
    return [str(number) for number, line in enumerate(content.splitlines(), start=1) if _SECRET_LINE.search(line)]


def version_tuple(text: str) -> tuple:
    match = re.match(r"\s*(\d+)\.(\d+)(?:\.(\d+))?", str(text or ""))
    return tuple(int(x) for x in match.groups() if x is not None) if match else ()


class NativeZtpAdapter:
    """Base: every operation of the contract.  Subclasses override what their NOS really does; the defaults refuse."""

    capability: NativeCapability

    # --- capability ---------------------------------------------------------------------------------------------------------
    def detect_native_ztp_capability(self, version: str = "") -> tuple[NativeCapability, list[str]]:
        """-> (capability, refusal codes).  A version below the documented minimum is refused, an unknown version is not."""
        cap = self.capability
        if not cap.implemented:
            return cap, ["ZTP_ADAPTER_UNAVAILABLE"]
        found = version_tuple(version)
        if version and cap.min_version and found and found < cap.min_version:
            return cap, ["ZTP_VERSION_UNSUPPORTED"]
        return cap, []

    def identify_enrollment_requirements(self) -> dict:
        cap = self.capability
        return {"mechanism": cap.enrollment, "key_types": list(cap.enrollment_key_types),
                "blocked": not cap.enrollment_key_types, "bootstrap_plaintext_material": False,
                "host_key_trust": "out-of-band confirmation of the first host key (console), enrolled by an approver"}

    # --- discovery / transport ------------------------------------------------------------------------------------------------
    def select_bootstrap_transport(self, policy: str = TransportPolicy.ISOLATED_LAB,
                                   service_transports: tuple = SERVICE_TRANSPORTS) -> TransportDecision:
        """Strongest transport that the platform supports, the policy allows and NMAS serves.  Never a silent downgrade: when
        the policy forbids every transport the platform and service share, the decision is blocked, not weakened."""
        allowed = TransportPolicy.ALLOWED.get(policy, ())
        native = tuple(self.capability.transports)
        candidates = tuple(sorted((t for t in native if t in allowed and t in service_transports),
                                  key=lambda t: -TRANSPORT_STRENGTH[t]))
        if not candidates:
            return TransportDecision("", (), policy, "no transport is supported by the platform, allowed by the policy and served by NMAS",
                                     ("ZTP_TRANSPORT_UNAVAILABLE",))
        best_native = max(native, key=lambda t: TRANSPORT_STRENGTH[t])
        reason = f"strongest of {list(candidates)} under {policy}"
        if TRANSPORT_STRENGTH[best_native] > TRANSPORT_STRENGTH[candidates[0]]:
            reason += (f"; the platform also supports {best_native}, which NMAS does not serve yet (no trust anchor exists on a "
                       f"factory-default device) -- recorded, not hidden")
        return TransportDecision(candidates[0], candidates, policy, reason)

    def select_discovery_parameters(self, artifact_url: str, transport: str, service_address: str) -> DiscoveryParameters:
        raise NotImplementedError

    def extract_dhcp_claims(self, lease: dict) -> tuple[dict, bool]:
        """-> (identity claims from client-supplied DHCP fields, whether the request is this NOS's native ZTP request)."""
        return {}, False

    # --- artifact -------------------------------------------------------------------------------------------------------------
    def render_minimal_bootstrap(self, ctx: BootstrapContext) -> RenderedBootstrap:
        raise NotImplementedError

    def prepare_bootstrap_artifact(self, ctx: BootstrapContext) -> tuple[RenderedBootstrap | None, list[str]]:
        """Render, then refuse anything secret-shaped or production-bearing.  -> (artifact | None, refusal codes)."""
        if not self.capability.enrollment_key_types:
            return None, ["ZTP_ENROLLMENT_BLOCKED"]
        key_type = ctx.enrollment_public_key.split(" ", 1)[0]
        if key_type not in self.capability.enrollment_key_types:
            return None, ["ZTP_ENROLLMENT_BLOCKED"]
        rendered = self.render_minimal_bootstrap(ctx)
        if secret_findings(rendered.content):
            return None, ["ARTIFACT_SECRET_DETECTED"]
        if self.production_findings(rendered.content):
            return None, ["BOOTSTRAP_VERIFICATION_FAILED"]
        return rendered, []

    PRODUCTION_PATTERNS = (r"^\s*router\s+(ospf|ospfv3|bgp|rip|isis)\b", r"^\s*ip routing\b", r"^\s*ipv6 unicast-routing\b")

    def production_findings(self, text: str) -> list[str]:
        found = []
        for pattern in self.PRODUCTION_PATTERNS:
            for line in str(text or "").splitlines():
                if re.search(pattern, line, flags=re.I):
                    found.append(line.strip()[:80])
        return found

    # --- verification ---------------------------------------------------------------------------------------------------------
    def verification_commands(self) -> tuple:
        return ()

    def inspect_native_bootstrap_status(self, outputs: dict) -> dict:
        return {"known": False}

    def verify_bootstrap_result(self, outputs: dict, ctx: BootstrapContext) -> VerificationReport:
        report = VerificationReport(ok=False)
        report.add("adapter", False, "no verification is implemented for this platform")
        return report

    # --- retry / recovery / ZTP disable ---------------------------------------------------------------------------------------
    def determine_native_retry_behavior(self) -> RetryBehavior:
        return RetryBehavior("not documented here", None, None, "not documented here", "none")

    def determine_supported_recovery_actions(self) -> list[RecoveryAction]:
        return [RecoveryAction("OPERATOR_CONSOLE", "Operator console intervention", False, "physical / virtual console access")]

    def determine_ztp_disable_capability(self) -> ZtpDisableCapability:
        return ZtpDisableCapability(None, False, "not documented here")

    # --- helpers --------------------------------------------------------------------------------------------------------------
    @staticmethod
    def network_of(address: str, prefixlen: int) -> str:
        return str(ipaddress.ip_interface(f"{address}/{prefixlen}").network)

    def describe(self) -> dict:
        cap = self.capability
        return {**cap.as_dict(), "retry": self.determine_native_retry_behavior().as_dict(),
                "recovery": [a.as_dict() for a in self.determine_supported_recovery_actions()],
                "ztp_disable": self.determine_ztp_disable_capability().as_dict(),
                "enrollment_requirements": self.identify_enrollment_requirements(),
                "transport_decision": self.select_bootstrap_transport().as_dict() if cap.implemented else {}}
