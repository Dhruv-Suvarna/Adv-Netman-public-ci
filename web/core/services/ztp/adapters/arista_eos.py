"""Arista EOS / cEOS native Zero Touch Provisioning.

Native mechanism (EOS ZeroTouch agent): a device that boots without a startup-config enters ZTP, sends DHCPv4 DISCOVERs on
its Ethernet and Management interfaces, and fetches the URL in option 67 (bootfile-name).  A file beginning with ``#!`` is run
as a script; anything else is saved as the startup-config, after which EOS reloads into it and ZTP is disabled.  It retries
from the beginning after each failure until it succeeds or an operator runs ``zerotouch cancel``.

Observed on cEOSLab 4.36.2F in the isolated Phase 3 fixture (``docs/evidence/v2-phase3-ztp/``):
  * DHCPDISCOVER every ~30 s per attempt, parameter request list including 66, 67 and 143 (RFC 8572 SZTP redirect)
  * option 60 ``Arista;<model>;<serial>``, option 61 = the raw 6-byte system MAC, option 77 = ``Arista;<model>;<version>``
  * chaddr is the interface MAC, NOT the system MAC (so host matching on chaddr would be wrong)
  * the startup-config is downloaded over HTTP, saved, EOS reloads its agents and ``show zerotouch`` reports ``disabled``

First management trust: the artifact installs an SSH PUBLIC key for a dedicated enrollment user (the private key never leaves
the NMAS secret provider) and a password field that is a crypt hash of discarded random bytes (EOS requires one; nothing can
log in with it).  The device's host key is NOT trusted on first contact: it is enrolled from an out-of-band read
(``show management ssh hostkey ed25519 public`` on the console) by an approver.  SZTP (signed vouchers, option 143) is not
implemented by NMAS.
"""

from __future__ import annotations

import json
import re

from .base import (HTTP, HTTPS, SUPPORTED_AND_LIVE_VERIFIED, TFTP, BootstrapContext, DiscoveryParameters, NativeCapability,
                   NativeZtpAdapter, RecoveryAction, RenderedBootstrap, RetryBehavior, VerificationReport, ZtpDisableCapability)

ACL_NAME = "NMAS-BOOTSTRAP-MGMT"
EVIDENCE = "docs/evidence/v2-phase3-ztp/ceos-live-ztp.md"


class AristaEosAdapter(NativeZtpAdapter):
    capability = NativeCapability(
        adapter="arista_eos", vendor="Arista", nos="EOS / cEOS", platform="arista_ceos",
        mechanism="EOS Zero Touch Provisioning (ZeroTouch agent, factory default without startup-config)",
        version_support="EOS 4.x ZeroTouch; live-verified on cEOSLab 4.36.2F only", min_version=(4, 0),
        transports=(HTTPS, HTTP, TFTP), discovery="DHCPv4 option 67 (bootfile URL); vendor class 'Arista;<model>;<serial>'",
        artifact_format="startup-config (or a '#!' script, not used: the config form needs no device-side code)",
        enrollment="SSH public key for a dedicated enrollment user; host key enrolled out of band",
        enrollment_key_types=("ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256"),
        runtime_conditions=("no startup-config on flash", "ZTP not disabled in /mnt/flash/zerotouch-config",
                            "a DHCP server reachable directly or through a relay on an Ethernet/Management port",
                            "cEOS: veth checksum offload disabled on software-forwarded paths (fixture concern, not EOS)"),
        evidence_status=SUPPORTED_AND_LIVE_VERIFIED, evidence=EVIDENCE,
        limitations=("SZTP (RFC 8572 option 143 / signed vouchers) is not implemented by NMAS",
                     "HTTPS is supported by EOS but not served by NMAS (no trust anchor on a factory-default device)",
                     "physical EOS boot/loader behaviour (Aboot) is not exercised by cEOS"),
        implemented=True,
    )

    # --- discovery ------------------------------------------------------------------------------------------------------------
    def select_discovery_parameters(self, artifact_url: str, transport: str, service_address: str) -> DiscoveryParameters:
        # EOS reads a full URL from option 67 for every transport it supports; option 66 is not needed with a URL.
        return DiscoveryParameters(vendor_class_prefix="Arista;", options=(("bootfile-name", artifact_url),),
                                   notes="EOS ZTP reads option 67 as a URL; match on the Arista vendor class")

    def extract_dhcp_claims(self, lease: dict) -> tuple[dict, bool]:
        claims = {}
        vendor = str(lease.get("vendor_class") or "")
        native = vendor.startswith("Arista;")
        parts = vendor.split(";")
        if native and len(parts) >= 3 and parts[2].strip():
            claims["serial"] = parts[2].strip()
        client_id = str(lease.get("client_id") or "")
        octets = [p for p in client_id.split(":") if p]
        if len(octets) == 6 and all(re.fullmatch(r"[0-9a-fA-F]{1,2}", p) for p in octets):
            claims["base_mac"] = ":".join(p.zfill(2).lower() for p in octets)
        if client_id:
            claims["client_id"] = client_id[:128]
        if lease.get("hostname"):
            claims["hostname"] = str(lease["hostname"])[:64]
        return claims, native

    # --- artifact -------------------------------------------------------------------------------------------------------------
    def render_minimal_bootstrap(self, ctx: BootstrapContext) -> RenderedBootstrap:
        service_prefix = ctx.service_prefix
        lines = [
            f"! NMAS minimal management bootstrap {ctx.session_id} ({ctx.auth_id}) -- bootstrap scope only.",
            "! No production routing, forwarding, VLANs or services: production configuration is Phase 6 commissioning.",
            f"hostname {ctx.hostname}",
            "!",
            "aaa authorization exec default local",
            "!",
            # EOS requires a password field: a crypt hash of discarded random bytes (no one knows a matching password)
            f"username {ctx.enrollment_user} privilege 15 role network-admin secret sha512 {ctx.locked_password_hash}",
            f"username {ctx.enrollment_user} ssh-key {ctx.enrollment_public_key}",
            "!",
            "no ip routing",
            "!",
            f"ip access-list {ACL_NAME}",
            f"   10 permit tcp host {ctx.service_address} any eq ssh",
            "!",
            f"interface {ctx.interface}",
            f"   description NMAS bootstrap uplink {ctx.session_id}",
            "   no switchport",
            f"   ip address {ctx.address}/{ctx.prefixlen}",
            "!",
            f"ip route {service_prefix} {ctx.gateway}",
            "!",
            "management ssh",
            f"   ip access-group {ACL_NAME} in",
            "!",
            "end",
        ]
        return RenderedBootstrap("startup-config", "\n".join(lines) + "\n", "text/plain", "startup-config")

    # --- verification ---------------------------------------------------------------------------------------------------------
    def verification_commands(self) -> tuple:
        return ("show version | json", "show zerotouch | json", "show hostname | json", "show ip interface brief | json",
                "show ip route | json", "show running-config")

    def inspect_native_bootstrap_status(self, outputs: dict) -> dict:
        data = _json(outputs.get("show zerotouch | json"))
        if not data:
            return {"known": False}
        return {"known": True, "mode": data.get("mode", ""), "disabled": data.get("mode") == "disabled"}

    def verify_bootstrap_result(self, outputs: dict, ctx: BootstrapContext) -> VerificationReport:
        report = VerificationReport(ok=True)
        version = _json(outputs.get("show version | json"))
        report.add("platform", version.get("mfgName") == "Arista", f"{version.get('mfgName', '?')} {version.get('modelName', '?')}")
        report.claims = {k: v for k, v in {
            "serial": str(version.get("serialNumber") or "").strip(), "base_mac": str(version.get("systemMacAddress") or "").lower(),
            "model": str(version.get("modelName") or ""), "version": str(version.get("version") or "")[:64]}.items() if v}
        _cap, codes = self.detect_native_ztp_capability(version.get("version", ""))
        report.add("version_supported", not codes, report.claims.get("version", "unknown"))
        status = self.inspect_native_bootstrap_status(outputs)
        report.ztp_disabled = status.get("disabled") if status.get("known") else None
        report.add("native_ztp_completed", bool(status.get("disabled")), f"zerotouch mode {status.get('mode', 'unknown')}")
        hostname = _json(outputs.get("show hostname | json")).get("hostname", "")
        report.add("hostname", hostname == ctx.hostname, hostname)
        interfaces = (_json(outputs.get("show ip interface brief | json")).get("interfaces") or {})
        addressed = {}
        for name, row in interfaces.items():
            ip = ((row.get("interfaceAddress") or {}).get("ipAddr") or {})
            if ip.get("address") and ip.get("address") != "0.0.0.0":
                addressed[name] = f"{ip['address']}/{ip.get('maskLen')}"
        report.add("bootstrap_address", addressed.get(ctx.interface) == f"{ctx.address}/{ctx.prefixlen}", addressed.get(ctx.interface, "none"))
        report.add("only_bootstrap_interface_addressed", set(addressed) <= {ctx.interface}, ",".join(sorted(addressed)))
        vrf = ((_json(outputs.get("show ip route | json")).get("vrfs") or {}).get("default") or {})
        report.add("routing_disabled", vrf.get("routingDisabled") is True, f"routingDisabled={vrf.get('routingDisabled')}")
        allowed_routes = {self.network_of(ctx.address, ctx.prefixlen), ctx.service_prefix}
        extra = sorted(set((vrf.get("routes") or {})) - allowed_routes)
        report.add("only_bootstrap_routes", not extra, ",".join(extra)[:200])
        running = str(outputs.get("show running-config") or "")
        report.production_services = self.production_findings(running)
        report.add("no_production_services", not report.production_services, ";".join(report.production_services)[:200])
        key_blob = ctx.enrollment_public_key.split()[1] if len(ctx.enrollment_public_key.split()) > 1 else "?"
        report.add("enrollment_key_installed", f"username {ctx.enrollment_user} ssh-key" in running and key_blob in running, ctx.enrollment_user)
        report.add("management_acl_applied", re.search(rf"^management ssh\n(?:\s+.*\n)*?\s+ip access-group {ACL_NAME} in", running, re.M) is not None,
                   ACL_NAME)
        return report

    def production_findings(self, text: str) -> list[str]:
        found = super().production_findings(text)
        # ``no ip routing`` is the bootstrap's own explicit refusal; only a positive ``ip routing`` is production forwarding
        return [line for line in found if not line.lower().startswith("no ")]

    # --- retry / recovery / ZTP disable ---------------------------------------------------------------------------------------
    def determine_native_retry_behavior(self) -> RetryBehavior:
        return RetryBehavior(
            dhcp_retry="DHCPv4 DISCOVER on every Ethernet/Management interface for each ZTP attempt", dhcp_retry_interval_seconds=30,
            retries_indefinitely=True,
            ztp_retry="after a failed DHCP or download step the ZeroTouch agent restarts ZTP from the beginning (attempt N)",
            evidence="observed on cEOSLab 4.36.2F (attempts 1-4, ~30-60 s apart); a link flap is not needed and is not used")

    def determine_supported_recovery_actions(self) -> list[RecoveryAction]:
        return [
            RecoveryAction("WAIT_NATIVE_RETRY", "Let native ZTP retry", True, "none: ZTP retries until success or cancel"),
            RecoveryAction("ZTP_CANCEL", "Cancel ZTP (boots without configuration)", True, "console access during ZTP", "zerotouch cancel"),
            RecoveryAction("RE_ZTP", "Return the device to ZTP", True, "an authenticated privilege-15 management session",
                           "zerotouch enable ; write erase ; reload"),
            RecoveryAction("RELOAD", "Reload into the saved startup-config", True, "an authenticated privilege-15 management session", "reload"),
        ]

    def determine_ztp_disable_capability(self) -> ZtpDisableCapability:
        return ZtpDisableCapability(True, True, "EOS disables ZTP itself once a startup-config is saved",
                                    "show zerotouch | json -> mode == disabled")


def _json(text) -> dict:
    if isinstance(text, dict):
        return text
    raw = str(text or "")
    start = raw.find("{")          # EOS may print a login banner before the JSON document on an exec channel
    try:
        value = json.loads(raw[start:] if start >= 0 else raw)
    except ValueError:
        return {}
    return value if isinstance(value, dict) else {}
