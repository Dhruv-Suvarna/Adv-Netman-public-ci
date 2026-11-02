"""Native-ZTP adapters for SR Linux, SONiC, Junos, Ubuntu (cloud-init) and IOS XR -- each with its honest evidence level.

None of these is live-verified.  Each renders only what its NOS's documented native mechanism executes; where NMAS cannot
yet produce a correct artifact or the runtime lacks the mechanism, the adapter says so instead of rendering a guess.
"""

from __future__ import annotations

import ipaddress
import json

from .base import (HTTP, HTTPS, NOT_IMPLEMENTED, NOT_TESTED_NO_IMAGE, PARTIALLY_IMPLEMENTED, TFTP,
                   BootstrapContext, DiscoveryParameters, NativeCapability, NativeZtpAdapter, RecoveryAction, RenderedBootstrap,
                   RetryBehavior, ZtpDisableCapability)


class NokiaSrLinuxAdapter(NativeZtpAdapter):
    """SR Linux ZTP: DHCP on the out-of-band ``mgmt0`` port only; option 67 names a provisioning script that SR Linux runs.

    NMAS renders the provisioning script (Python, applying SR Linux CLI ``set`` statements through ``sr_cli``).  The SR Linux
    24.10 container image ships the ZTP client but never launches it: an isolated first-boot probe (no Containerlab, no
    startup configuration, mgmt0 on an isolated link) saw no ZTP process and no DHCP from mgmt0.  Live proof therefore needs
    hardware or a VM form.  Verification over a management session is not implemented yet."""

    capability = NativeCapability(
        adapter="nokia_srlinux", vendor="Nokia", nos="SR Linux", platform="nokia_srlinux",
        mechanism="SR Linux ZTP (DHCP on mgmt0, option 67 provisioning script)", version_support="SR Linux 21.x+ (documented); not live-verified",
        min_version=(21, 0), transports=(HTTPS, HTTP, TFTP), discovery="DHCPv4/v6 on mgmt0; option 67 script URL",
        artifact_format="provisioning script (Python) applying SR Linux CLI statements",
        enrollment="SSH public key on a dedicated local user; host key enrolled out of band", enrollment_key_types=("ssh-ed25519", "ssh-rsa"),
        runtime_conditions=("ZTP enabled on first boot", "mgmt0 attached to an explicit bootstrap relay -- never the Containerlab bridge"),
        evidence_status=PARTIALLY_IMPLEMENTED, evidence="web/core/tests/test_ztp_adapters.py",
        limitations=("the 24.10 container image ships ztpd but never launches it (no app-manager entry; no mgmt0 DHCP on first boot): "
                     "docs/evidence/v2-phase3-ztp/srlinux-container-probe.md",
                     "management verification parser not implemented", "SR Linux role/authorization model for the enrollment user not live-validated"),
        implemented=True,
    )

    def select_discovery_parameters(self, artifact_url, transport, service_address) -> DiscoveryParameters:
        return DiscoveryParameters(options=(("bootfile-name", artifact_url),),
                                   notes="SR Linux vendor class is not relied on: the trusted relay port selects the device")

    def render_minimal_bootstrap(self, ctx: BootstrapContext) -> RenderedBootstrap:
        statements = [
            f"set / system name host-name {ctx.hostname}",
            f"set / system aaa authentication user {ctx.enrollment_user} ssh-key [ \"{ctx.enrollment_public_key}\" ]",
            f"set / interface {ctx.interface} subinterface 0 ipv4 admin-state enable",
            f"set / interface {ctx.interface} subinterface 0 ipv4 address {ctx.address}/{ctx.prefixlen}",
            f"set / network-instance mgmt static-routes route {ctx.service_prefix} next-hop-group nmas-bootstrap",
            f"set / network-instance mgmt next-hop-groups group nmas-bootstrap nexthop 1 ip-address {ctx.gateway}",
        ]
        script = ("#!/usr/bin/env python3\n"
                  f"# NMAS minimal management bootstrap {ctx.session_id} ({ctx.auth_id}) -- SR Linux ZTP provisioning script.\n"
                  "import subprocess\n\n"
                  f"STATEMENTS = {json.dumps(statements, indent=4)}\n\n"
                  "subprocess.run(['sr_cli', '-ec', '--', *STATEMENTS, 'commit save'], check=True)\n")
        return RenderedBootstrap("provision.py", script, "text/x-python", "python-script")

    def determine_native_retry_behavior(self) -> RetryBehavior:
        return RetryBehavior("DHCP on mgmt0 while ZTP is active", None, None, "release dependent (ZTP timeout then reboot/retry)",
                             "Nokia SR Linux ZTP guide; not observed")

    def determine_supported_recovery_actions(self):
        return [RecoveryAction("ZTP_RESTART", "Restart ZTP", True, "an authenticated management session", "tools system ztp restart"),
                RecoveryAction("OPERATOR_CONSOLE", "Operator console intervention", False, "console access")]


class SonicAdapter(NativeZtpAdapter):
    """SONiC ZTP (``sonic-ztp`` package): option 67 names a ZTP JSON, or option 239 names a provisioning script directly.
    A ``configdb-json`` section cannot install an SSH key for first management trust, so the artifact is the native
    provisioning-script form (executed by sonic-ztp itself, not a helper NMAS installs).  No SONiC image exists here."""

    capability = NativeCapability(
        adapter="sonic", vendor="SONiC community", nos="SONiC", platform="sonic", mechanism="sonic-ztp (option 239 provisioning script)",
        version_support="SONiC images built with the sonic-ztp package", transports=(HTTP, HTTPS, TFTP),
        discovery="DHCPv4 option 239 (provisioning script URL) or option 67 (ZTP JSON)", artifact_format="provisioning script (shell)",
        enrollment="SSH public key for a dedicated user", enrollment_key_types=("ssh-ed25519", "ssh-rsa"),
        runtime_conditions=("image built with sonic-ztp", "ZTP admin mode enabled", "no existing config_db"),
        evidence_status=NOT_TESTED_NO_IMAGE, evidence="no SONiC image is available in this environment",
        limitations=("no image: nothing live-verified", "an image without sonic-ztp is NOT ZTP-capable; NMAS installs no helper"),
        implemented=True,
    )

    def select_discovery_parameters(self, artifact_url, transport, service_address) -> DiscoveryParameters:
        return DiscoveryParameters(options=(("nmas-sonic-provisioning-script", artifact_url),),
                                   notes="option 239 (provisioning script URL) is declared by the ISC provider for SONiC")

    def render_minimal_bootstrap(self, ctx: BootstrapContext) -> RenderedBootstrap:
        script = "\n".join([
            "#!/bin/bash", f"# NMAS minimal management bootstrap {ctx.session_id} ({ctx.auth_id}) -- SONiC ZTP provisioning script.",
            "set -eu",
            f"config hostname {ctx.hostname}",
            f"config interface ip add {ctx.interface} {ctx.address}/{ctx.prefixlen}",
            f"config route add prefix {ctx.service_prefix} nexthop {ctx.gateway}",
            f"id -u {ctx.enrollment_user} >/dev/null 2>&1 || useradd -m -s /bin/bash -G sudo {ctx.enrollment_user}",
            f"passwd -l {ctx.enrollment_user}",
            f"install -d -m 700 -o {ctx.enrollment_user} /home/{ctx.enrollment_user}/.ssh",
            f"echo '{ctx.enrollment_public_key}' > /home/{ctx.enrollment_user}/.ssh/authorized_keys",
            f"chown {ctx.enrollment_user} /home/{ctx.enrollment_user}/.ssh/authorized_keys",
            "config save -y", ""])
        return RenderedBootstrap("provision.sh", script, "text/x-shellscript", "provisioning-script")

    def determine_supported_recovery_actions(self):
        return [RecoveryAction("ZTP_RUN", "Re-run ZTP", True, "an authenticated management session", "ztp run -y"),
                RecoveryAction("ZTP_ENABLE", "Enable ZTP admin mode", True, "an authenticated management session", "ztp enable")]

    def determine_ztp_disable_capability(self) -> ZtpDisableCapability:
        return ZtpDisableCapability(True, True, "sonic-ztp marks itself completed and disables admin mode", "ztp status")


def _junos_option43(filename: str, transfer_mode: str) -> str:
    """Junos ZTP option 43 sub-options: 01 = configuration file name, 03 = transfer mode (http / tftp)."""
    def tlv(code: int, value: str) -> str:
        data = value.encode()
        return ":".join([f"{code:02x}", f"{len(data):02x}", *(f"{b:02x}" for b in data)])
    return ":".join([tlv(1, filename), tlv(3, transfer_mode)])


class JuniperJunosAdapter(NativeZtpAdapter):
    """Junos ZTP: a factory-default device reads option 43 sub-options (01 configuration file, 03 transfer mode) and the
    file server (option 150 / 66 / siaddr), fetches and commits the configuration.  Junos refuses a commit without root
    authentication: the artifact sets it to an SSH PUBLIC key (no password).  Junos is not in the NMAS platform catalogue and
    no image exists here, so no device can select this adapter yet."""

    capability = NativeCapability(
        adapter="juniper_junos", vendor="Juniper", nos="Junos OS", platform="", mechanism="Junos ZTP (option 43 sub-options 01/03)",
        version_support="Junos 12.2+ on ZTP-capable platforms (documented)", min_version=(12, 2), transports=(HTTP, TFTP),
        discovery="DHCPv4 option 43 (01 config file, 03 transfer mode) + option 66/150 file server", artifact_format="Junos configuration",
        enrollment="root-authentication and enrollment user with SSH public keys only", enrollment_key_types=("ssh-ed25519", "ssh-rsa"),
        runtime_conditions=("factory-default configuration", "platform in the NMAS catalogue (not yet)"),
        evidence_status=NOT_TESTED_NO_IMAGE, evidence="no Junos image is available in this environment",
        limitations=("not in the NMAS platform catalogue: no device can be registered for it", "no image: nothing live-verified"),
        implemented=True,
    )

    def select_discovery_parameters(self, artifact_url, transport, service_address) -> DiscoveryParameters:
        path = artifact_url.split("://", 1)[-1].split("/", 1)[-1]
        mode = "http" if transport == HTTP else "tftp"
        return DiscoveryParameters(options=(("vendor-encapsulated-options", _junos_option43("/" + path, mode)),
                                            ("tftp-server-name", service_address)),
                                   notes="Junos reads the config file name and transfer mode from option 43, the server from option 66")

    def render_minimal_bootstrap(self, ctx: BootstrapContext) -> RenderedBootstrap:
        key_type = ctx.enrollment_public_key.split()[0]
        keyword = {"ssh-ed25519": "ssh-ed25519", "ssh-rsa": "ssh-rsa"}[key_type]
        text = "\n".join([
            f"/* NMAS minimal management bootstrap {ctx.session_id} ({ctx.auth_id}) -- bootstrap scope only. */",
            "system {", f"    host-name {ctx.hostname};",
            f"    root-authentication {{ {keyword} \"{ctx.enrollment_public_key}\"; }}",
            f"    login {{ user {ctx.enrollment_user} {{ class super-user; authentication {{ {keyword} \"{ctx.enrollment_public_key}\"; }} }} }}",
            "    services { ssh { root-login deny; } }", "}",
            f"interfaces {{ {ctx.interface} {{ unit 0 {{ family inet {{ address {ctx.address}/{ctx.prefixlen}; }} }} }} }}",
            f"routing-options {{ static {{ route {ctx.service_prefix} next-hop {ctx.gateway}; }} }}", ""])
        return RenderedBootstrap("bootstrap.conf", text, "text/plain", "junos-config")


class UbuntuCloudInitAdapter(NativeZtpAdapter):
    """Ubuntu / FRR is a Linux host running a routing suite, not a NOS with DHCP-option-driven ZTP.

    The Ubuntu-native first-boot mechanism is cloud-init.  Its NoCloud ``nocloud-net`` datasource fetches ``user-data`` from a
    seed URL handed over by the hypervisor (SMBIOS serial or kernel command line) -- NOT by DHCP options -- so DHCP only
    addresses the host.  NMAS renders the user-data (hostname, a locked enrollment user with an SSH public key, password
    login off; FRR is left disabled) and serves it like any other artifact.  The lab's R3/R4 are ``ubuntu:24.04`` containers
    with neither cloud-init nor systemd: there they are image-preconfigured and operator-onboarded, which this adapter reports
    and never presents as ZTP."""

    capability = NativeCapability(
        adapter="ubuntu_cloud_init", vendor="Canonical", nos="Ubuntu (FRR as an application)", platform="ubuntu_frr",
        mechanism="cloud-init NoCloud (nocloud-net seed URL from SMBIOS / kernel command line)", version_support="Ubuntu 18.04+ cloud images",
        transports=(HTTPS, HTTP), discovery="none by DHCP option: the seed URL comes from the hypervisor", artifact_format="cloud-config user-data",
        enrollment="cloud-init ssh_authorized_keys on a locked enrollment user", enrollment_key_types=("ssh-ed25519", "ssh-rsa"),
        runtime_conditions=("a VM / bare-metal Ubuntu cloud image with cloud-init", "seed URL provided by the hypervisor"),
        evidence_status=PARTIALLY_IMPLEMENTED, evidence="web/core/tests/test_ztp_adapters.py",
        limitations=("lab R3/R4 are containers without cloud-init or systemd: image preconfiguration + operator onboarding only",
                     "seed-URL hand-over is a hypervisor concern NMAS does not drive", "running FRR configuration management is Phase 6"),
        implemented=True,
    )

    def select_discovery_parameters(self, artifact_url, transport, service_address) -> DiscoveryParameters:
        return DiscoveryParameters(options=(), notes=f"no DHCP option selects cloud-init; seed URL ds=nocloud-net;s={artifact_url.rsplit('/', 1)[0]}/")

    def render_minimal_bootstrap(self, ctx: BootstrapContext) -> RenderedBootstrap:
        network = ipaddress.ip_interface(f"{ctx.address}/{ctx.prefixlen}")
        text = "\n".join([
            "#cloud-config", f"# NMAS minimal management bootstrap {ctx.session_id} ({ctx.auth_id}); FRR stays disabled (Phase 6).",
            f"hostname: {ctx.hostname}", "ssh_pwauth: false", "disable_root: true", "users:",
            f"  - name: {ctx.enrollment_user}", "    lock_passwd: true", "    shell: /bin/bash", "    sudo: \"ALL=(ALL) NOPASSWD:ALL\"",
            "    ssh_authorized_keys:", f"      - {ctx.enrollment_public_key}",
            "write_files:", "  - path: /etc/netplan/60-nmas-bootstrap.yaml", "    permissions: '0600'", "    content: |",
            "      network:", "        version: 2", "        ethernets:", f"          {ctx.interface}:",
            f"            addresses: [{network.with_prefixlen}]",
            f"            routes: [{{to: {ctx.service_prefix}, via: {ctx.gateway}}}]", "runcmd:", "  - [netplan, apply]", ""])
        return RenderedBootstrap("user-data", text, "text/cloud-config", "cloud-init")

    def determine_native_retry_behavior(self) -> RetryBehavior:
        return RetryBehavior("ordinary DHCP client", None, None, "cloud-init runs once per instance id", "cloud-init documentation")

    def determine_supported_recovery_actions(self):
        return [RecoveryAction("CLOUD_INIT_CLEAN", "Re-run cloud-init on next boot", True, "an authenticated management session",
                               "cloud-init clean --reboot")]


class CiscoIosXrAdapter(NativeZtpAdapter):
    """IOS XR has native ZTP, but NMAS has no adapter for it: refused, never guessed."""

    capability = NativeCapability(
        adapter="cisco_iosxr", vendor="Cisco", nos="IOS XR", platform="cisco_iosxr", mechanism="IOS XR ZTP (not implemented by NMAS)",
        version_support="n/a", evidence_status=NOT_IMPLEMENTED, evidence="no adapter", limitations=("no adapter; no image",), implemented=False,
    )


ADAPTER_CLASSES = (NokiaSrLinuxAdapter, SonicAdapter, JuniperJunosAdapter, UbuntuCloudInitAdapter, CiscoIosXrAdapter)
