"""Cisco IOS XE native Zero-Touch Provisioning (Python ZTP).

Native mechanism (IOS XE 16.5+ on platforms with guest shell / IOx): a device booting without a startup-config sends DHCPv4
with option 60 ``ciscopnp``; when the reply carries option 67 with the URL of a Python script (HTTP / HTTPS / TFTP), IOS XE
enables IOx, starts guest shell and runs the script, whose ``cli`` module applies configuration.  Without option 67 (or with
option 43 PnP sub-options) the same DHCP exchange leads to Cisco PnP instead -- a different mechanism NMAS does not drive.
Secure ZTP (RFC 8572) exists on some IOS XE platforms and releases only; NMAS does not assume or implement it.

First management trust: the script installs an RSA public key (IOS XE ``ip ssh pubkey-chain`` ``key-hash``) for a dedicated
enrollment user whose ``secret 9`` is an scrypt hash of discarded random bytes, and restricts the vty lines to the NMAS
bootstrap service.  Ed25519 user keys are not assumed (release dependent).

Evidence: unit-tested rendering and parsing only.  The lab's vrnetlab c8000v 17.06.01a image boots with vrnetlab's injected
configuration, so it never presents a factory-default ZTP boot; guest shell / IOx availability on that image was not assessed.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import re
import secrets

from .base import (HTTP, HTTPS, IMPLEMENTED_UNIT_TESTED, TFTP, BootstrapContext, DiscoveryParameters, NativeCapability, NativeZtpAdapter,
                   RecoveryAction, RenderedBootstrap, RetryBehavior, VerificationReport, ZtpDisableCapability)

ACL_NAME = "NMAS-BOOTSTRAP-MGMT"
_STD_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_CISCO_B64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def cisco_type9_locked_hash() -> str:
    """A Cisco type-9 (scrypt N=16384 r=1 p=1) hash of 32 discarded random bytes: a password field nobody can satisfy."""
    salt = "".join(secrets.choice(_CISCO_B64) for _ in range(14))
    digest = hashlib.scrypt(secrets.token_bytes(32), salt=salt.encode(), n=16384, r=1, p=1, dklen=32)
    encoded = base64.b64encode(digest).decode().rstrip("=").translate(str.maketrans(_STD_B64, _CISCO_B64))
    return f"$9${salt}${encoded}"


def rsa_key_hash(public_line: str) -> str:
    """IOS XE ``key-hash ssh-rsa`` value: the MD5 of the decoded public-key blob, upper-case hex."""
    blob = base64.b64decode(public_line.split()[1])
    return hashlib.md5(blob, usedforsecurity=False).hexdigest().upper()


class CiscoIosXeAdapter(NativeZtpAdapter):
    capability = NativeCapability(
        adapter="cisco_iosxe", vendor="Cisco", nos="IOS XE", platform="cisco_c8000v_iosxe",
        mechanism="IOS XE Zero-Touch Provisioning (DHCP option 67 Python script run in guest shell)",
        version_support="IOS XE 16.5+ with guest shell / IOx; not live-verified", min_version=(16, 5),
        transports=(HTTPS, HTTP, TFTP), discovery="DHCPv4 option 67 (Python script URL); option 60 'ciscopnp'",
        artifact_format="Python script using the guest-shell 'cli' module",
        enrollment="RSA public key (pubkey-chain key-hash) for a dedicated enrollment user; host key enrolled out of band",
        enrollment_key_types=("ssh-rsa",),
        runtime_conditions=("no startup-config (factory default or 'write erase' + reload)", "guest shell / IOx available on the platform",
                            "option 67 present and no option 43 PnP redirection"),
        evidence_status=IMPLEMENTED_UNIT_TESTED, evidence="web/core/tests/test_ztp_adapters.py",
        limitations=("lab vrnetlab c8000v image boots pre-configured: factory-default ZTP not exercised",
                     "Secure ZTP (RFC 8572) not implemented", "ZTP state is not exposed as a show command: read-back is the running state"),
        implemented=True,
    )

    def select_discovery_parameters(self, artifact_url: str, transport: str, service_address: str) -> DiscoveryParameters:
        return DiscoveryParameters(vendor_class_prefix="ciscopnp", options=(("bootfile-name", artifact_url),),
                                   notes="option 67 selects Python ZTP; no option 43 is sent so PnP is not triggered")

    def extract_dhcp_claims(self, lease: dict) -> tuple[dict, bool]:
        claims = {}
        native = str(lease.get("vendor_class") or "").startswith("ciscopnp")
        client_id = str(lease.get("client_id") or "")
        # PnP / ZTP client identifier: "cisco-<hhhh.hhhh.hhhh>-<interface>" as ASCII (hex octets in the lease)
        try:
            text = bytes(int(p, 16) for p in client_id.split(":") if p).decode("ascii", "strict")
        except (ValueError, UnicodeDecodeError):
            text = ""
        match = re.match(r"^\x00?cisco-([0-9a-f]{4})\.([0-9a-f]{4})\.([0-9a-f]{4})-", text)
        if match:
            hexdigits = "".join(match.groups())
            claims["base_mac"] = ":".join(hexdigits[i:i + 2] for i in range(0, 12, 2))
        if client_id:
            claims["client_id"] = client_id[:128]
        if lease.get("hostname"):
            claims["hostname"] = str(lease["hostname"])[:64]
        return claims, native

    def render_minimal_bootstrap(self, ctx: BootstrapContext) -> RenderedBootstrap:
        mask = str(ipaddress.ip_interface(f"{ctx.address}/{ctx.prefixlen}").network.netmask)
        service = ipaddress.ip_network(ctx.service_prefix)
        lines = [
            f"hostname {ctx.hostname}",
            "ip domain name nmas.bootstrap",
            "no ip routing",
            f"username {ctx.enrollment_user} privilege 15 secret 9 {ctx.locked_password_hash or cisco_type9_locked_hash()}",
            "ip ssh version 2",
            "ip ssh pubkey-chain",
            f"username {ctx.enrollment_user}",
            f"key-hash ssh-rsa {rsa_key_hash(ctx.enrollment_public_key)}",
            "exit", "exit",
            f"ip access-list standard {ACL_NAME}",
            f"permit host {ctx.service_address}",
            "exit",
            f"interface {ctx.interface}",
            f"description NMAS bootstrap uplink {ctx.session_id}",
            f"ip address {ctx.address} {mask}",
            "no shutdown",
            "exit",
            f"ip route {service.network_address} {service.netmask} {ctx.gateway}",
            "line vty 0 4",
            f"access-class {ACL_NAME} in",
            "login local",
            "transport input ssh",
            "exit",
        ]
        body = ",\n".join(f"    {line!r}" for line in lines)
        script = (
            "#!/usr/bin/env python\n"
            f"# NMAS minimal management bootstrap {ctx.session_id} ({ctx.auth_id}) -- bootstrap scope only.\n"
            "# Runs in IOS XE guest shell (native Python ZTP).  No production routing or services.\n"
            "from cli import configurep, executep\n\n"
            f"configurep([\n{body},\n])\n"
            "executep('crypto key generate rsa modulus 2048 label nmas-bootstrap')\n"
            "executep('copy running-config startup-config')\n"
        )
        return RenderedBootstrap("ztp.py", script, "text/x-python", "python-script")

    def verification_commands(self) -> tuple:
        return ("show version", "show running-config", "show ip interface brief", "show ip route", "show inventory")

    def verify_bootstrap_result(self, outputs: dict, ctx: BootstrapContext) -> VerificationReport:
        report = VerificationReport(ok=True)
        version = str(outputs.get("show version") or "")
        report.add("platform", "Cisco IOS XE Software" in version, "IOS XE" if "IOS XE" in version else "unknown")
        serial = re.search(r"Processor board ID (\S+)", version)
        release = re.search(r"Version (\d+\.\d+\.\d+\w*)", version)
        report.claims = {k: v for k, v in {"serial": serial.group(1) if serial else "", "version": release.group(1) if release else ""}.items() if v}
        running = str(outputs.get("show running-config") or "")
        report.add("hostname", re.search(rf"^hostname {re.escape(ctx.hostname)}$", running, re.M) is not None, ctx.hostname)
        brief = str(outputs.get("show ip interface brief") or "")
        addressed = {m.group(1): m.group(2) for m in re.finditer(r"^(\S+)\s+(\d+\.\d+\.\d+\.\d+)\s", brief, re.M)}
        report.add("bootstrap_address", addressed.get(ctx.interface) == ctx.address, addressed.get(ctx.interface, "none"))
        report.add("only_bootstrap_interface_addressed", set(addressed) <= {ctx.interface}, ",".join(sorted(addressed)))
        report.add("routing_disabled", re.search(r"^no ip routing$", running, re.M) is not None, "no ip routing")
        report.production_services = self.production_findings(running)
        report.add("no_production_services", not report.production_services, ";".join(report.production_services)[:200])
        report.add("enrollment_key_installed", rsa_key_hash(ctx.enrollment_public_key) in running.replace(" ", ""), ctx.enrollment_user)
        report.add("management_acl_applied", f"access-class {ACL_NAME} in" in running, ACL_NAME)
        report.ztp_disabled = None      # IOS XE has no ZTP state command; a saved startup-config prevents ZTP on the next boot
        return report

    def production_findings(self, text: str) -> list[str]:
        return [line for line in super().production_findings(text) if not line.lower().startswith("no ")]

    def determine_native_retry_behavior(self) -> RetryBehavior:
        return RetryBehavior("DHCP DISCOVER from the PnP/ZTP agent while no startup-config exists", None, None,
                             "a failed script download falls back to the PnP discovery cycle; retry timing is release dependent",
                             "Cisco IOS XE Programmability Configuration Guide (ZTP); not observed live")

    def determine_supported_recovery_actions(self) -> list[RecoveryAction]:
        return [RecoveryAction("WRITE_ERASE_RELOAD", "Return to factory default and re-run ZTP", True,
                               "an authenticated privilege-15 session or console", "write erase ; reload"),
                RecoveryAction("CONSOLE_ABORT", "Abort autoinstall at the console", True, "console access", "answer 'yes' to terminate autoinstall")]

    def determine_ztp_disable_capability(self) -> ZtpDisableCapability:
        return ZtpDisableCapability(True, False, "a saved startup-config prevents ZTP on later boots",
                                    "no ZTP state command; verify the saved startup-config instead")
