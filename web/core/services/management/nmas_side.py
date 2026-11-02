"""The NMAS side of management: read-only host observation and the single-point-of-failure (SPOF) report.

NMAS never changes host routing, firewall rules, namespaces or NIC configuration.  ``observe_interface`` only READS
``/sys/class/net`` and ``ip -json address show`` for one named interface.

The SPOF report is computed, never asserted: a device is redundantly managed only when it has at least two USABLE paths
whose dependency sets (NMAS failure domain, NMAS upstream switch, adjacent switch, management-VLAN chain) do not
intersect.  NMAS itself is tolerant of a management-switch failure only with two VERIFIED NMAS attachments in different
failure domains.  In the frozen lab NMAS has one attachment (mgmt_swt), so the report carries ``NMAS_SINGLE_ATTACHMENT``
and nothing is ever called fully redundant.
"""

from __future__ import annotations

import ipaddress
import json
import re
import subprocess
from pathlib import Path

from ... import models
from ..devices import codes
from . import paths, selector

SYS_NET = Path("/sys/class/net")
_IFNAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,31}$")


def _read_addresses(interface: str) -> list[str]:
    done = subprocess.run(["ip", "-json", "address", "show", "dev", interface], capture_output=True, text=True, timeout=5,
                          check=False, shell=False)  # noqa: S603,S607 - fixed argv, read-only
    if done.returncode != 0:
        return []
    try:
        rows = json.loads(done.stdout or "[]")
    except ValueError:
        return []
    return [f"{a.get('local')}/{a.get('prefixlen')}" for row in rows for a in row.get("addr_info", []) if a.get("local")]


def observe_interface(interface: str, source_address: str, *, sys_net: Path = SYS_NET, read_addresses=_read_addresses) -> dict:
    """Read-only facts about one NMAS host interface.  Never writes anything."""
    if not _IFNAME.fullmatch(str(interface or "")):
        return {"interface": str(interface)[:32], "exists": False, "oper_up": False, "addresses": [], "holds_source": False,
                "source": "invalid-name"}
    base = Path(sys_net) / interface
    exists = base.exists()
    operstate = ""
    if exists:
        try:
            operstate = (base / "operstate").read_text(encoding="utf-8").strip().lower()
        except OSError:
            operstate = ""
    addresses = read_addresses(interface) if exists else []
    holds = False
    try:
        target = ipaddress.ip_address(source_address)
        holds = any(ipaddress.ip_interface(cidr).ip == target for cidr in addresses)
    except ValueError:
        holds = False
    return {"interface": interface, "exists": exists, "oper_up": operstate in ("up", "unknown") and exists, "operstate": operstate,
            "addresses": addresses[:16], "holds_source": holds, "source": "sysfs+iproute2 (read-only)"}


def observe_and_record(attachment, *, actor: str, **kwargs) -> paths.Result:
    facts = observe_interface(attachment.host_interface, attachment.source_address, **kwargs)
    return paths.record_nmas_observation(attachment, facts, actor=actor)


def path_dependencies(path) -> set[str]:
    """Everything whose single failure takes ``path`` down (besides the device itself)."""
    nmas = path.nmas_attachment
    deps = {f"nmas-domain:{nmas.failure_domain}", f"nmas-attachment:{nmas.attachment_id}", f"switch:{nmas.upstream_device}"}
    if path.via_device:
        deps.add(f"switch:{path.via_device}")
    if path.path_type == models.ManagementPathType.VLAN_ADJACENT_SWITCH:
        for hop in paths.vlan_chain(path.via_device, nmas.upstream_device) or []:
            deps.add(f"switch:{hop}")
    if path.local_interface:
        deps.add(f"link:{path.device.name}:{path.local_interface}")
    # a direct NMAS attachment to the managed device (live fixture: NMAS eth2 -> DUT1) is no switch between them
    deps.discard(f"switch:{path.device.name}")
    return deps


def spof_report() -> dict:
    attachments = list(models.NmasManagementAttachment.objects.exclude(approval_state=models.ManagementApproval.REVOKED))
    verified = [a for a in attachments if a.approval_state == models.ManagementApproval.APPROVED
                and a.verification_state == models.AttachmentVerification.VERIFIED]
    domains = sorted({a.failure_domain for a in verified})
    blockers = []
    if len(verified) < 2:
        upstream = verified[0].upstream_device if verified else (attachments[0].upstream_device if attachments else "")
        blockers.append(codes.blocker("NMAS_SINGLE_ATTACHMENT", upstream=upstream, verified=len(verified)))
    elif not any(a.failure_domain != b.failure_domain and a.upstream_device != b.upstream_device
                 for index, a in enumerate(verified) for b in verified[index + 1:]):
        blockers.append(codes.blocker("NMAS_SHARED_FAILURE_DOMAIN", domain=domains[0]))
    nmas_tolerant = not blockers
    devices = {}
    for device in models.ManagedDevice.objects.filter(management_paths__approval_state=models.ManagementApproval.APPROVED).distinct():
        approved = paths.approved_paths(device)
        usable = [p for p in approved if selector.usable(p)]
        dependency_sets = [path_dependencies(p) for p in usable]
        shared = sorted(set.intersection(*dependency_sets)) if dependency_sets else []
        independent_pair = any(not first.intersection(second) for index, first in enumerate(dependency_sets)
                               for second in dependency_sets[index + 1:])
        devices[device.name] = {
            "approved_paths": len(approved), "usable_paths": len(usable), "shared_dependencies": shared,
            "path_redundant": independent_pair,
            "fully_redundant": independent_pair and nmas_tolerant,
        }
    return {
        "nmas_attachments": [{"id": a.attachment_id, "interface": a.host_interface, "upstream": a.upstream_device, "domain": a.failure_domain,
                              "approval": a.approval_state, "verification": a.verification_state} for a in attachments],
        "verified_attachments": len(verified), "failure_domains": domains, "management_switch_failure_tolerant": nmas_tolerant,
        "blockers": blockers, "devices": devices,
        "statement": ("NMAS-side management-switch failure tolerance is VERIFIED." if nmas_tolerant else
                      "NMAS management is NOT fully redundant: management-switch failure tolerance is not verified; "
                      "inspect the blockers and upstream attachments."),
    }
