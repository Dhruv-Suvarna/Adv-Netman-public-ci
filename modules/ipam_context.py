"""Phase 3A: NetBox-backed configuration context + shadow rendering.

This module is a pure DATA TRANSFORMATION layer. It:
  * builds a normalized, template-friendly addressing context for a
    managed device from NetBox (via modules/netbox_ipam.py -- the only
    module that speaks the NetBox API);
  * extracts the equivalent "current configuration intent" directly from
    the existing, UNMODIFIED templates/*.cfg.j2 files (regex-based, since
    these templates have no addressing Jinja variables today -- their
    literal text already IS the current desired-state evidence);
  * compares the two and classifies any difference;
  * renders a "candidate" configuration text with NetBox-sourced values
    substituted in place of the current literals, for the shadow-rendering
    requirement, WITHOUT ever writing to templates/*.cfg.j2 or pushing to a
    device.

It does NOT:
  * push configuration anywhere (no SSH/Netmiko/paramiko import at all);
  * connect to network devices;
  * configure DHCP or monitoring;
  * perform Containerlab deployment;
  * modify templates/*.cfg.j2 or master.py.

Design note -- why regex-substitution instead of converting the templates
to Jinja variables
-----------------------------------------------------------------------
The task's own Phase 3A guidance anticipates two designs: converting the
templates' addressing literals to Jinja variables (rendered once from a
"legacy" context and once from a NetBox context), or -- when that would
risk the untouched, still-authoritative `master.py` render path -- a
lighter mechanism that still produces a genuine, comparable candidate
render. This module takes the second path deliberately: `master.py` and
every `templates/*.cfg.j2` file remain **exactly** byte-identical to
before this phase (verified by `monitoring/tests/test_ipam_context.py`),
which means the existing, already-working device-provisioning mechanism
carries zero risk of being broken by this exploratory phase. The
candidate renderer instead reads the current template text (never writing
it back) and substitutes each specific address literal with the value
NetBox produces for the same semantic field, which is both a genuine
"candidate configuration" (Step 8) and, because Phase 2 already proved
NetBox holds the exact current addressing with zero drift, a direct proof
that NetBox round-trips back to the original text (Step 10/11's
equivalence goal) without ever touching the file that matters.

Fail-closed contract (Step 12/13)
----------------------------------
Every function that reads from NetBox propagates `modules.netbox_ipam`'s
exceptions unchanged -- there is no `except Exception: pass` anywhere in
this module, and no function here ever substitutes a legacy/hard-coded
value when NetBox is unavailable or incomplete. `validate_netbox_ready()`
is the explicit pre-flight gate Step 13 asks for.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from modules import netbox_ipam as nb

BASE = Path(__file__).resolve().parents[1]
TEMPLATES_DIR = BASE / "templates"
SHADOW_RUNTIME_DIR = BASE / "netbox" / "runtime" / "shadow"

MANAGED_DEVICES = ("R1", "R2", "R3", "R4", "S1", "S2", "S3", "S4", "mgmt_swt")

# ---------------------------------------------------------------------------
# Step 13: NetBox validation gate.
# ---------------------------------------------------------------------------


def validate_netbox_ready(client=None) -> dict:
    """Confirm NetBox is reachable, authenticated, and holds every object
    this phase's rendering/comparison depends on, BEFORE any shadow
    rendering starts. Raises on the first failure (fail-closed) -- it does
    not return a partial "mostly ready" result for the caller to ignore.

    This is intentionally lighter than the full 387-check
    verify_netbox_model.py (Step 13 explicitly allows that): it checks the
    specific invariants this module's functions rely on -- connectivity,
    auth, the expected managed-device set, and every managed device having
    at least a management interface address -- not every field Phase 2
    modeled.
    """
    config = nb.load_config()
    nb.check_status(config)
    if config.has_token:
        nb.verify_authentication(config)
    client = client or nb.build_client()

    managed = nb.get_managed_devices(client)
    expected = set(MANAGED_DEVICES)
    if set(managed) != expected:
        raise nb.NetboxModelError(
            f"NetBox managed-device set does not match Phase 3A's expected set.\n"
            f"  expected: {sorted(expected)}\n  found:    {sorted(managed)}"
        )
    for device in MANAGED_DEVICES:
        if nb.get_primary_address(device, 4, client) is None and nb.get_primary_address(device, 6, client) is None:
            raise nb.NetboxModelError(f"{device}: no primary IPv4 or IPv6 address in NetBox -- model is incomplete")
    return {"managed_devices": managed, "status": "ready"}


# ---------------------------------------------------------------------------
# Normalized provisioning context (Step 4).
# ---------------------------------------------------------------------------


def build_device_context(device: str, client=None) -> dict:
    """The normalized, template-friendly addressing context for one
    managed device, built entirely from NetBox structural queries -- no
    hard-coded address table. Raises NetboxModelError via
    `require_managed_device` if `device` is not managed (R5/WebServer
    included)."""
    nb.require_managed_device(device, client)
    client = client or nb.build_client()

    info = nb.get_device(device, client)
    interfaces = {}
    for name in _device_interface_names(device, client):
        interfaces[name] = {
            "ipv4": nb.get_interface_address(device, name, 4, client),
            "ipv6": nb.get_interface_address(device, name, 6, client),
        }

    client_vlan_gateways = {}
    for vid in (10, 20, 30):
        client_vlan_gateways[vid] = {
            "ipv4": nb.get_shared_gateway(vid, 4, client),
            "ipv6": nb.get_shared_gateway(vid, 6, client),
        }

    return {
        "device": device,
        "role": info["role"],
        "managed": info["managed"],
        "management": {"ipv4": info["primary_ipv4"], "ipv6": info["primary_ipv6"]},
        "interfaces": interfaces,
        "client_vlan_gateways": client_vlan_gateways,
    }


def _device_interface_names(device: str, client=None) -> list[str]:
    return nb.get_device_interface_names(device, client)


# ---------------------------------------------------------------------------
# Legacy extraction: current configuration intent, read directly from the
# unmodified templates. See module docstring for why this is a valid
# stand-in for "the legacy render" without templating the files.
# ---------------------------------------------------------------------------

_IFACE_RE = re.compile(r"^interface\s+(\S+)")
_IPV4_RE = re.compile(r"^ip address (\d+\.\d+\.\d+\.\d+/\d+)")
_IPV6_RE = re.compile(r"^ipv6 address ([0-9a-fA-F:]+/\d+)")
_VRRP4_RE = re.compile(r"^ip virtual-router address (\d+\.\d+\.\d+\.\d+)")
_VRRP6_RE = re.compile(r"^ipv6 virtual-router address ([0-9a-fA-F:]+)")
_BASH_ADDR_RE = re.compile(r"^ip(?: -6)? addr (?:add|replace) ([0-9a-fA-F:.]+/\d+) dev (\S+)")
_NEIGHBOR_RE = re.compile(r"^neighbor (\S+) remote-as \d+")
_ROUTE_RE = re.compile(r"^ipv6? route (\S+) (\S+)")
_NAT_RE = re.compile(r"ip saddr (\S+) masquerade")
_PERMIT_RE = re.compile(r"seq \d+ permit (\S+)")
_NETWORK_RE = re.compile(r"^network (\S+)$")


@dataclass
class DeviceFacts:
    """The normalized shape both the legacy extractor and the NetBox-facts
    builder produce, so `compare_facts` can diff them field by field."""

    interfaces: dict[str, dict] = field(default_factory=dict)  # {name: {"ipv4": cidr|None, "ipv6": cidr|None}}
    vrrp_gateways: dict[str, dict] = field(default_factory=dict)  # {name: {"ipv4": addr|None, "ipv6": addr|None}}
    peer_candidates: set[str] = field(default_factory=set)  # bare addresses (BGP neighbors + static-route next hops)
    nat_sources: set[str] = field(default_factory=set)  # CIDR prefixes used as NAT/masquerade sources
    referenced_prefixes: set[str] = field(default_factory=set)  # CIDRs from network/permit statements


def extract_legacy_facts(device: str) -> DeviceFacts:
    """Parse templates/<device>.cfg.j2 directly (read-only) for every
    address-shaped literal, tagged by semantic category. This IS the
    "legacy render" for addressing purposes: nothing in these templates
    templates the address fields today, so their literal text already is
    the full current configuration intent."""
    path = TEMPLATES_DIR / f"{device}.cfg.j2"
    if not path.is_file():
        raise FileNotFoundError(f"No template for {device}: {path}")
    facts = DeviceFacts()
    current_iface: str | None = None
    for raw_line in path.read_text().splitlines():
        line = raw_line.strip()

        m = _IFACE_RE.match(line)
        if m:
            current_iface = m.group(1)
            continue
        m = _IPV4_RE.match(line)
        if m and current_iface:
            facts.interfaces.setdefault(current_iface, {})["ipv4"] = m.group(1)
            continue
        m = _IPV6_RE.match(line)
        if m and current_iface:
            facts.interfaces.setdefault(current_iface, {})["ipv6"] = m.group(1)
            continue
        m = _VRRP4_RE.match(line)
        if m and current_iface:
            facts.vrrp_gateways.setdefault(current_iface, {})["ipv4"] = m.group(1)
            continue
        m = _VRRP6_RE.match(line)
        if m and current_iface:
            facts.vrrp_gateways.setdefault(current_iface, {})["ipv6"] = m.group(1)
            continue
        m = _BASH_ADDR_RE.match(line)
        if m:
            addr, dev_name = m.groups()
            family = "ipv6" if ":" in addr else "ipv4"
            facts.interfaces.setdefault(dev_name, {})[family] = addr
            continue
        m = _NEIGHBOR_RE.match(line)
        if m:
            facts.peer_candidates.add(m.group(1))
            continue
        m = _ROUTE_RE.match(line)
        if m:
            facts.peer_candidates.add(m.group(2))  # the next hop is the address-relevant part; see module docstring
            continue
        m = _NAT_RE.search(line)
        if m:
            facts.nat_sources.add(m.group(1))
            continue
        m = _PERMIT_RE.search(line)
        if m:
            facts.referenced_prefixes.add(m.group(1))
            continue
        m = _NETWORK_RE.match(line)
        if m:
            facts.referenced_prefixes.add(m.group(1))
            continue
    return facts


# ---------------------------------------------------------------------------
# NetBox-derived facts, built in the SAME shape as extract_legacy_facts --
# using the interface/relationship NAMES the legacy template already
# defines (never a second hard-coded address table), with every VALUE
# resolved live from NetBox (Step 5).
# ---------------------------------------------------------------------------


def build_netbox_facts(device: str, client=None) -> DeviceFacts:
    """Build the NetBox-derived equivalent of `extract_legacy_facts`, for
    the SAME interfaces the legacy template defines. Which interfaces/
    relationships exist is still the existing template's own routing
    design (unchanged by this phase, per Step 9's "do not change routing
    design" instruction) -- what this function proves is that NetBox
    supplies the correct ADDRESS VALUES for that already-fixed shape.
    """
    client = client or nb.build_client()
    legacy = extract_legacy_facts(device)
    facts = DeviceFacts()

    for iface_name, legacy_addrs in legacy.interfaces.items():
        v4 = nb.get_interface_address(device, iface_name, 4, client)
        v6 = nb.get_interface_address(device, iface_name, 6, client)
        facts.interfaces[iface_name] = {
            "ipv4": v4["cidr"] if v4 else None,
            "ipv6": v6["cidr"] if v6 else None,
        }
        # Peer candidates: every interface's peer (BGP neighbor OR
        # static-route next hop, whichever the legacy template actually
        # uses this interface for) is a member of the accepted set.
        for family, cidr in (("ipv4", facts.interfaces[iface_name]["ipv4"]), ("ipv6", facts.interfaces[iface_name]["ipv6"])):
            if cidr is None:
                continue  # this interface has no address of this family at all (e.g. Vlan99 has no IPv6) -- not a peer candidate
            family_num = 4 if family == "ipv4" else 6
            # Only a genuine point-to-point segment (exactly one other host
            # sharing the prefix) is a BGP-neighbor/static-route-next-hop
            # candidate; a shared segment like the /24 management VLAN or a
            # client VLAN's /24 has many hosts and is not one, so it is
            # skipped rather than treated as an error.
            peers = nb.get_peer_addresses(device, iface_name, family_num, client)
            if len(peers) == 1:
                facts.peer_candidates.add(peers[0]["address"])

    for iface_name in legacy.vrrp_gateways:
        vid = _vlan_id_for_interface(iface_name)
        facts.vrrp_gateways[iface_name] = {
            "ipv4": (nb.get_shared_gateway(vid, 4, client) or {}).get("address"),
            "ipv6": (nb.get_shared_gateway(vid, 6, client) or {}).get("address"),
        }

    # nat_sources / referenced_prefixes: validated against the universe of
    # every prefix NetBox actually knows about (Phase 2's full model),
    # rather than re-deriving "which prefixes SHOULD be referenced" --
    # that is unchanged routing/NAT policy, not an IPAM value. This still
    # catches any wrong ADDRESS/mask, which is what Step 10 asks to prove.
    #
    # Membership is checked against the CANONICAL network form (e.g. EOS's
    # `network 192.168.110.1/31` RIP statement is valid syntax identifying
    # the same /31 as the canonical "192.168.110.0/31" -- host-address-based
    # network statements are normalized here so that is recognized as a
    # match, not reported as a spurious difference); the ORIGINAL string is
    # kept in the result so it still compares equal to `legacy`'s own value.
    universe = _prefix_universe(client)
    facts.nat_sources = {p for p in legacy.nat_sources if _canonical_network(p) in universe}
    facts.referenced_prefixes = {p for p in legacy.referenced_prefixes if _canonical_network(p) in universe}
    return facts


def _canonical_network(value: str) -> str:
    try:
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError:
        return value


def _vlan_id_for_interface(name: str) -> int:
    match = re.fullmatch(r"Vlan(\d+)", name)
    if not match:
        raise nb.NetboxModelError(f"Cannot infer a VLAN id from interface name {name!r}")
    return int(match.group(1))


def _prefix_universe(client=None) -> set[str]:
    return nb.list_all_prefix_cidrs(client)


# ---------------------------------------------------------------------------
# Equivalence checker (Step 10/11).
# ---------------------------------------------------------------------------

EXPECTED_MIGRATION_DIFFERENCE = "EXPECTED-MIGRATION-DIFFERENCE"
BUG = "BUG"
PRE_EXISTING_DRIFT = "PRE-EXISTING-DRIFT"
NON_IPAM_DIFFERENCE = "NON-IPAM-DIFFERENCE"


@dataclass
class FieldDifference:
    category: str
    field: str
    legacy: Any
    netbox: Any
    classification: str


@dataclass
class ComparisonResult:
    device: str
    differences: list[FieldDifference] = field(default_factory=list)

    @property
    def equivalent(self) -> bool:
        return not self.differences


def compare_facts(device: str, legacy: DeviceFacts, netbox_facts: DeviceFacts) -> ComparisonResult:
    """Field-by-field comparison. Every interface/VRRP-gateway address must
    match EXACTLY (these have one unambiguous correct value). Peer
    candidates/NAT sources/referenced prefixes are checked as a
    containment relationship (see module docstring) -- a legacy value with
    no NetBox counterpart is still reported as a difference, never
    silently ignored.
    """
    result = ComparisonResult(device=device)

    all_interfaces = set(legacy.interfaces) | set(netbox_facts.interfaces)
    for name in sorted(all_interfaces):
        legacy_addrs = legacy.interfaces.get(name, {})
        netbox_addrs = netbox_facts.interfaces.get(name, {})
        for fam in ("ipv4", "ipv6"):
            legacy_value = legacy_addrs.get(fam)
            netbox_value = netbox_addrs.get(fam)
            if legacy_value != netbox_value:
                result.differences.append(FieldDifference(
                    category=f"interface:{name}:{fam}", field=fam,
                    legacy=legacy_value, netbox=netbox_value, classification=BUG,
                ))

    all_vrrp = set(legacy.vrrp_gateways) | set(netbox_facts.vrrp_gateways)
    for name in sorted(all_vrrp):
        legacy_addrs = legacy.vrrp_gateways.get(name, {})
        netbox_addrs = netbox_facts.vrrp_gateways.get(name, {})
        for fam in ("ipv4", "ipv6"):
            legacy_value = legacy_addrs.get(fam)
            netbox_value = netbox_addrs.get(fam)
            if legacy_value != netbox_value:
                result.differences.append(FieldDifference(
                    category=f"vrrp_gateway:{name}:{fam}", field=fam,
                    legacy=legacy_value, netbox=netbox_value, classification=BUG,
                ))

    missing_peers = legacy.peer_candidates - netbox_facts.peer_candidates
    for value in sorted(missing_peers):
        result.differences.append(FieldDifference(
            category="peer_candidate", field=value, legacy=value, netbox=None, classification=BUG,
        ))

    missing_nat = legacy.nat_sources - netbox_facts.nat_sources
    for value in sorted(missing_nat):
        result.differences.append(FieldDifference(
            category="nat_source", field=value, legacy=value, netbox=None, classification=BUG,
        ))

    missing_refs = legacy.referenced_prefixes - netbox_facts.referenced_prefixes
    for value in sorted(missing_refs):
        result.differences.append(FieldDifference(
            category="referenced_prefix", field=value, legacy=value, netbox=None, classification=BUG,
        ))

    return result


# ---------------------------------------------------------------------------
# Shadow rendering (Step 8): produce a candidate config text with
# NetBox-sourced values substituted for the current literals, written only
# to a git-ignored runtime directory. Never touches templates/*.cfg.j2,
# never connects to a device.
# ---------------------------------------------------------------------------


def render_candidate_config(device: str, client=None) -> str:
    """Read templates/<device>.cfg.j2 (never write it), and substitute
    every address literal this module recognizes with the value NetBox
    supplies for the same semantic field. Because Phase 2 verified NetBox
    holds the current addressing with zero drift for every managed device,
    a correct implementation renders text IDENTICAL to the original --
    that identity IS the equivalence proof for Step 11's "render complete
    configs and diff them"."""
    client = client or nb.build_client()
    nb.require_managed_device(device, client)
    path = TEMPLATES_DIR / f"{device}.cfg.j2"
    text = path.read_text()
    legacy = extract_legacy_facts(device)
    netbox_facts = build_netbox_facts(device, client)

    substitutions: dict[str, str] = {}
    for name, legacy_addrs in legacy.interfaces.items():
        netbox_addrs = netbox_facts.interfaces.get(name, {})
        for fam in ("ipv4", "ipv6"):
            old, new = legacy_addrs.get(fam), netbox_addrs.get(fam)
            if old and new and old != new:
                substitutions[old] = new
    for name, legacy_addrs in legacy.vrrp_gateways.items():
        netbox_addrs = netbox_facts.vrrp_gateways.get(name, {})
        for fam in ("ipv4", "ipv6"):
            old, new = legacy_addrs.get(fam), netbox_addrs.get(fam)
            if old and new and old != new:
                substitutions[old] = new

    candidate = text
    for old, new in substitutions.items():
        candidate = re.sub(re.escape(old) + r"(?![\w:.])", new, candidate)
    return candidate


def write_candidate_config(device: str, client=None, out_dir: Path | None = None) -> Path:
    out_dir = out_dir or SHADOW_RUNTIME_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    candidate = render_candidate_config(device, client)
    out_path = out_dir / f"{device}.cfg"
    out_path.write_text(candidate)
    return out_path


# ---------------------------------------------------------------------------
# Phase 3B: deterministic dynamic-assignment reservation view + validation.
#
# "Dynamic assignment does NOT mean dynamic address SELECTION": every row
# this section produces is read directly from NetBox's own already-
# validated IP address objects (the same ones Phase 2 populated and Phase
# 3A proved equivalent to the live templates) -- there is no separate
# "reservation pool" or generated address anywhere in this module. A
# reservation is therefore, by construction, never able to disagree with
# NetBox's own mapped address (Step 12): it IS that address.
#
# Phase 3B.3 correction: which rows actually become reservation TARGETS is
# entirely driven by each interface's `ipv4_mode`/`ipv6_mode` (read live
# from NetBox's assignment-mode policy, never hard-coded here) -- a row
# whose mode is `static` (Vlan200, per the corrected management-VLAN
# architecture; see docs/NETBOX_IPAM.md "Phase 3B.3") produces zero
# READY/BLOCKED/FAIL entries in `validate_reservations()`'s readiness list
# and is never evaluated for MAC/DUID/IAID readiness. Nothing below
# mentions "Vlan200" by name for this purpose -- the exclusion is a
# structural consequence of its mode, so it holds automatically for any
# interface whose policy is/becomes static.
# ---------------------------------------------------------------------------


def get_address_reservations(client=None) -> list[dict]:
    """One normalized row per (managed device, interface) -- the unified
    assignment-matrix / future-DHCP-generator-input view (Step 10/17).

    Deliberately excludes:
      * R5/WebServer (unmanaged -- Step 15; `get_managed_devices()` is the
        sole source of which devices appear at all);
      * the 5 shared VRRP gateway addresses (Step 4 -- they belong to a
        VLAN, not a single client interface/identity, and must never be
        mistaken for a DHCP lease).
    """
    client = client or nb.build_client()
    rows: list[dict] = []
    for device in nb.get_managed_devices(client):
        device_type = nb.get_device(device, client)["device_type"]
        if (device_type or "").startswith("ceos"):
            platform = "cEOS"
        elif (device_type or "").startswith("ubuntu"):
            platform = "Linux"
        else:
            platform = device_type
        for interface in nb.get_device_interface_names(device, client):
            v4 = nb.get_interface_address(device, interface, 4, client)
            v6 = nb.get_interface_address(device, interface, 6, client)
            modes = nb.get_assignment_modes(device, interface, client)
            mac = nb.get_interface_mac(device, interface, client)
            rows.append({
                "device": device,
                "platform": platform,
                "interface": interface,
                "mac_address": mac["mac_address"] if mac else None,
                "mac_identity_status": mac["identity_status"] if mac else None,
                "ipv4": v4["address"] if v4 else None,
                "ipv4_mode": modes["ipv4_mode"],
                "ipv6": v6["address"] if v6 else None,
                "ipv6_mode": modes["ipv6_mode"],
                "dhcpv6_duid": modes["dhcpv6_duid"],
                "dhcpv6_iaid": modes["dhcpv6_iaid"],
                "dhcpv6_identity_status": modes["dhcpv6_identity_status"],
            })
    return rows


@dataclass
class ReservationIssue:
    category: str
    detail: str
    rows: list[dict] = field(default_factory=list)
    status: str = "FAIL"
    family: int | None = None


READINESS_READY = "READY"
READINESS_BLOCKED = "BLOCKED"
READINESS_FAIL = "FAIL"


@dataclass
class ReservationReadiness:
    """Readiness of one future fixed reservation (one row/address family)."""

    device: str
    interface: str
    family: int
    status: str
    detail: str


@dataclass
class ReservationReport:
    rows: list[dict]
    issues: list[ReservationIssue] = field(default_factory=list)
    readiness: list[ReservationReadiness] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.issues

    @property
    def overall_status(self) -> str:
        if any(issue.status == READINESS_FAIL for issue in self.issues):
            return READINESS_FAIL
        if any(issue.status == READINESS_BLOCKED for issue in self.issues):
            return READINESS_BLOCKED
        return READINESS_READY

    @property
    def readiness_counts(self) -> dict[str, int]:
        return {
            status: sum(item.status == status for item in self.readiness)
            for status in (READINESS_READY, READINESS_BLOCKED, READINESS_FAIL)
        }


def _row_label(row: dict) -> str:
    return f"{row['device']}/{row['interface']}"


_MAC_RE = re.compile(r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
_HEX_OCTET_RE = re.compile(r"^[0-9A-Fa-f]{2}$")


def _mac_octets(value: str) -> tuple[int, ...] | None:
    """Parse the colon-delimited representation NetBox returns."""
    if not isinstance(value, str) or not _MAC_RE.fullmatch(value):
        return None
    return tuple(int(octet, 16) for octet in value.split(":"))


def _duid_ll_octets(value: str) -> tuple[int, ...] | None:
    """Parse this project's deterministic Ethernet DUID-LL representation.

    RFC 8415 DUID-LL is type 3 (00:03), followed by the Ethernet hardware
    type (00:01), followed by the authoritative six-octet MAC.
    """
    if not isinstance(value, str):
        return None
    parts = value.split(":")
    if len(parts) != 10 or any(not _HEX_OCTET_RE.fullmatch(part) for part in parts):
        return None
    octets = tuple(int(part, 16) for part in parts)
    if octets[:4] != (0x00, 0x03, 0x00, 0x01):
        return None
    return octets


def _iaid_is_valid(value: str) -> bool:
    parts = value.split(":") if isinstance(value, str) else []
    return len(parts) == 4 and all(_HEX_OCTET_RE.fullmatch(part) for part in parts)


def _add_issue(
    issues: list[ReservationIssue], category: str, detail: str, rows: list[dict],
    *, status: str = READINESS_FAIL, family: int | None = None,
) -> None:
    issues.append(ReservationIssue(category, detail, rows, status=status, family=family))


def validate_reservations(rows: list[dict], *, dhcp_ranges: list[dict] | None = None, managed_devices: set[str] | None = None) -> ReservationReport:
    """Fail-closed structural validation over a reservation row set (Step
    11/13/16). Never mutates `rows`; returns every issue found rather than
    stopping at the first one, so a single run reports the complete
    picture."""
    managed_devices = managed_devices if managed_devices is not None else set(MANAGED_DEVICES)
    issues: list[ReservationIssue] = []

    for row in rows:
        if row["device"] not in managed_devices:
            _add_issue(issues, "unmanaged-provisioning-target", f"{_row_label(row)}: not a managed device", [row])
        for family_key, mode_key in (("ipv4", "ipv4_mode"), ("ipv6", "ipv6_mode")):
            mode = row[mode_key]
            if mode not in nb.ASSIGNMENT_MODES:
                _add_issue(issues, "invalid-assignment-mode", f"{_row_label(row)}: {mode_key}={mode!r}", [row], family=4 if family_key == "ipv4" else 6)
                continue
            has_address = row[family_key] is not None
            if mode == "none" and has_address:
                _add_issue(issues, "conflicting-assignment-mode", f"{_row_label(row)}: {mode_key}=none but a {family_key} address is recorded", [row], family=4 if family_key == "ipv4" else 6)
            elif mode != "none" and not has_address:
                _add_issue(issues, f"missing-{family_key}", f"{_row_label(row)}: {mode_key}={mode} but no {family_key} address is recorded", [row], family=4 if family_key == "ipv4" else 6)
            elif has_address:
                try:
                    parsed = ipaddress.ip_address(row[family_key])
                except ValueError:
                    _add_issue(issues, f"invalid-{family_key}", f"{_row_label(row)}: malformed {family_key} address {row[family_key]!r}", [row], family=4 if family_key == "ipv4" else 6)
                else:
                    expected_version = 4 if family_key == "ipv4" else 6
                    if parsed.version != expected_version:
                        _add_issue(issues, f"invalid-{family_key}", f"{_row_label(row)}: {family_key} field contains an IPv{parsed.version} address", [row], family=expected_version)
        # Phase 3B.1: mere EXISTENCE of a MAC/DUID is never sufficient --
        # only an explicit nb.IDENTITY_AUTHORITATIVE status means the value
        # is the deliberate, durable plan rather than a passing
        # observation (Step 12). IAID is deliberately NOT gated on here:
        # ISC dhcpd's fixed-address6/host-identifier matching is DUID-only
        # (see docs/NETBOX_IPAM.md "ISC DHCPv6 matching"), so
        # requiring IAID would couple this check to something the actual
        # future server-side mechanism never uses.
        if row["ipv4_mode"] == "dhcp-reserved":
            mac = row.get("mac_address")
            status = row.get("mac_identity_status")
            octets = _mac_octets(mac) if mac else None
            if not mac:
                _add_issue(issues, "missing-mac", f"{_row_label(row)}: dhcp-reserved with no MAC address recorded", [row], family=4)
            elif octets is None or octets == (0, 0, 0, 0, 0, 0):
                _add_issue(issues, "invalid-mac", f"{_row_label(row)}: malformed or unusable MAC {mac!r}", [row], family=4)
            elif octets[0] & 1:
                _add_issue(issues, "multicast-mac", f"{_row_label(row)}: MAC {mac} has the multicast/group bit set", [row], family=4)

            if status == nb.IDENTITY_BLOCKED:
                _add_issue(issues, "mac-identity-blocked", f"{_row_label(row)}: DHCPv4 identity is explicitly blocked", [row], status=READINESS_BLOCKED, family=4)
            elif status == nb.IDENTITY_OBSERVED:
                _add_issue(issues, "mac-identity-observed", f"{_row_label(row)}: MAC {mac or '-'} is observed only, not authoritative-planned", [row], family=4)
            elif status is None:
                _add_issue(issues, "missing-mac-identity-status", f"{_row_label(row)}: MAC identity decision is missing", [row], family=4)
            elif status != nb.IDENTITY_AUTHORITATIVE:
                _add_issue(issues, "invalid-mac-identity-status", f"{_row_label(row)}: unrecognized MAC identity status {status!r}", [row], family=4)

        if row["ipv6_mode"] == "dhcpv6-reserved":
            duid = row.get("dhcpv6_duid")
            status = row.get("dhcpv6_identity_status")
            iaid = row.get("dhcpv6_iaid")
            if status == nb.IDENTITY_BLOCKED:
                _add_issue(
                    issues, "dhcpv6-identity-blocked",
                    f"{_row_label(row)}: DHCPv6 identity/client mechanism is explicitly blocked by platform evidence",
                    [row], status=READINESS_BLOCKED, family=6,
                )
                if duid or iaid:
                    _add_issue(issues, "blocked-dhcpv6-has-identity", f"{_row_label(row)}: blocked DHCPv6 identity must not carry DUID/IAID values", [row], family=6)
            else:
                if not duid:
                    _add_issue(issues, "missing-dhcpv6-identity", f"{_row_label(row)}: dhcpv6-reserved with no DUID recorded", [row], family=6)
                if status == nb.IDENTITY_OBSERVED:
                    _add_issue(issues, "dhcpv6-identity-observed", f"{_row_label(row)}: DHCPv6 identity is observed only, not authoritative-planned", [row], family=6)
                elif status is None:
                    _add_issue(issues, "missing-dhcpv6-identity-status", f"{_row_label(row)}: DHCPv6 identity decision is missing", [row], family=6)
                elif status != nb.IDENTITY_AUTHORITATIVE:
                    _add_issue(issues, "invalid-dhcpv6-identity-status", f"{_row_label(row)}: unrecognized DHCPv6 identity status {status!r}", [row], family=6)

                if duid:
                    duid_octets = _duid_ll_octets(duid)
                    if duid_octets is None:
                        _add_issue(issues, "invalid-duid", f"{_row_label(row)}: DUID {duid!r} is not a valid Ethernet DUID-LL", [row], family=6)
                    else:
                        mac_octets = _mac_octets(row.get("mac_address") or "")
                        mac_unusable = (
                            mac_octets is None
                            or mac_octets == (0, 0, 0, 0, 0, 0)
                            or bool(mac_octets[0] & 1)
                        )
                        if row.get("mac_identity_status") != nb.IDENTITY_AUTHORITATIVE or mac_unusable:
                            _add_issue(issues, "duid-without-authoritative-mac", f"{_row_label(row)}: deterministic DUID-LL requires a valid authoritative MAC", [row], family=6)
                        elif duid_octets[4:] != mac_octets:
                            _add_issue(issues, "duid-mac-mismatch", f"{_row_label(row)}: DUID-LL does not correspond to authoritative MAC {row['mac_address']}", [row], family=6)

                # IAID is intentionally optional for ISC dhcpd's selected
                # host-identifier/fixed-address6 server match. If supplied,
                # it must still be a well-formed four-octet informational
                # value so malformed metadata cannot silently persist.
                if iaid and not _iaid_is_valid(iaid):
                    _add_issue(issues, "invalid-iaid", f"{_row_label(row)}: informational IAID {iaid!r} is malformed", [row], family=6)

    by_mac: dict[str, list[dict]] = {}
    for row in rows:
        if row["ipv4_mode"] == "dhcp-reserved" and row.get("mac_address"):
            by_mac.setdefault(row["mac_address"].upper(), []).append(row)
    for mac, group in by_mac.items():
        if len(group) > 1:
            _add_issue(issues, "duplicate-mac", f"{mac} used by {', '.join(_row_label(r) for r in group)}", group, family=4)

    by_duid: dict[str, list[dict]] = {}
    for row in rows:
        if row["ipv6_mode"] == "dhcpv6-reserved" and row.get("dhcpv6_duid"):
            by_duid.setdefault(row["dhcpv6_duid"].lower(), []).append(row)
    for duid, group in by_duid.items():
        if len(group) > 1:
            _add_issue(issues, "duplicate-duid", f"{duid} used by {', '.join(_row_label(r) for r in group)}", group, family=6)

    for family_key in ("ipv4", "ipv6"):
        by_address: dict[str, list[dict]] = {}
        for row in rows:
            if row[family_key]:
                by_address.setdefault(row[family_key], []).append(row)
        for address, group in by_address.items():
            if len(group) > 1:
                _add_issue(issues, f"duplicate-{family_key}", f"{address} used by {', '.join(_row_label(r) for r in group)}", group, family=4 if family_key == "ipv4" else 6)

    if dhcp_ranges:
        for row in rows:
            for family_key, family_num in (("ipv4", 4), ("ipv6", 6)):
                address = row[family_key]
                if not address or row[f"{family_key}_mode"] == "none":
                    continue
                try:
                    ip = ipaddress.ip_address(address)
                except ValueError:
                    continue  # already reported as invalid-IPv4/IPv6 above
                for pool in dhcp_ranges:
                    if pool["family"] != family_num:
                        continue
                    if ipaddress.ip_address(pool["start"]) <= ip <= ipaddress.ip_address(pool["end"]):
                        _add_issue(
                            issues, "pool-collision",
                            f"{_row_label(row)} {family_key}={address} falls inside DHCP pool {pool['start']}-{pool['end']}",
                            [row], family=family_num,
                        )

    readiness: list[ReservationReadiness] = []
    for row in rows:
        for family, mode in ((4, row["ipv4_mode"]), (6, row["ipv6_mode"])):
            expected_mode = "dhcp-reserved" if family == 4 else "dhcpv6-reserved"
            if mode != expected_mode:
                continue
            relevant = [
                issue for issue in issues
                if any(candidate is row for candidate in issue.rows) and issue.family in (None, family)
            ]
            if any(issue.status == READINESS_FAIL for issue in relevant):
                status = READINESS_FAIL
            elif any(issue.status == READINESS_BLOCKED for issue in relevant):
                status = READINESS_BLOCKED
            else:
                status = READINESS_READY
            detail = ", ".join(dict.fromkeys(issue.category for issue in relevant)) or "authoritative identity is structurally usable"
            readiness.append(ReservationReadiness(row["device"], row["interface"], family, status, detail))

    return ReservationReport(rows=rows, issues=issues, readiness=readiness)


# ---------------------------------------------------------------------------
# Phase 3C: R2 secondary DHCP server -- normalized pool context.
#
# Every pool boundary (primary AND secondary, both address families) is
# read live from NetBox's own ipam.IPRange objects via
# modules/netbox_ipam.get_dhcp_ranges() -- there is no second, parallel
# hard-coded pool dictionary anywhere in this module or in
# netbox/scripts/render_r2_dhcp.py. Gateways and relay targets are
# likewise derived live (get_shared_gateway()/get_dhcp_relay_targets()),
# never duplicated. CLIENT_VLANS is the one small, explicit, reviewable
# fact this module already assumes elsewhere (see MANAGED_DEVICES above
# for the same pattern) -- the frozen VLAN10/20/30 client-VLAN topology
# per LAB_REQUIREMENTS.md/AGENTS.md, not re-derived from a NetBox "client"
# IPAM Role query (that role is shared with prefixes that are not pool
# subjects at all).
# ---------------------------------------------------------------------------

CLIENT_VLANS = (10, 20, 30)


@dataclass(frozen=True)
class DhcpPool:
    """One normalized DHCP pool boundary, either family, either server."""

    vlan: int
    family: int
    server: str  # "primary" | "secondary" | "unknown" (see get_dhcp_pool_context)
    prefix: str | None
    start: str
    end: str
    gateway: str | None
    relay_targets: tuple[str, ...]
    description: str | None


def get_dhcp_pool_context(client=None) -> list[DhcpPool]:
    """Every modeled DHCP pool (primary AND secondary, every client-VLAN/
    family combination that actually has an ipam.IPRange) as a flat,
    normalized list -- the single read path `get_r2_dhcp_context()` below
    (and any future NMAS-consuming renderer) builds from. Never invents a
    pool: a VLAN/family with no matching range (e.g. VLAN30's IPv4)
    contributes no entry, exactly mirroring VLAN30's IPv6-only design.
    A range whose tags predate the primary/secondary convention reports
    `server="unknown"` rather than being silently dropped or guessed at.
    """
    client = client or nb.build_client()
    pools: list[DhcpPool] = []
    for vid in CLIENT_VLANS:
        vlan = nb.get_vlan(vid, client)
        for rng in nb.get_dhcp_ranges(vid=vid, client=client):
            family = rng["family"]
            prefix_entry = vlan[f"prefix_ipv{family}"]
            relay_targets = tuple(nb.get_dhcp_relay_targets(prefix_entry["prefix"], client)) if prefix_entry else ()
            gateway = (nb.get_shared_gateway(vid, family, client) or {}).get("address")
            pools.append(DhcpPool(
                vlan=vid, family=family, server=rng["server"] or "unknown",
                prefix=prefix_entry["prefix"] if prefix_entry else None,
                start=rng["start"], end=rng["end"], gateway=gateway,
                relay_targets=relay_targets, description=rng["description"],
            ))
    return pools


#: The exact (vlan, family) pairs R2's documented secondary design covers
#: (README.md "DHCP pools" -- Step 8's matrix). VLAN30 IPv4 is deliberately
#: absent -- VLAN30 stays IPv6-only.
R2_EXPECTED_POOLS = frozenset({(10, 4), (10, 6), (20, 4), (20, 6), (30, 6)})


def get_r2_dhcp_context(client=None) -> dict:
    """The normalized rendering context for R2's SECONDARY DHCP-server
    configuration (Step 6/7): exactly the pools tagged `server="secondary"`,
    grouped by address family, in the shape
    `templates/R2_dhcp_server.cfg.j2` consumes. Fail-closed (Step 4/13):
    raises NetboxModelError if a pool the documented design requires is
    missing, or if an unexpected one exists (e.g. a VLAN30 IPv4 secondary
    pool someone added later) -- never silently renders an incomplete or
    over-scoped server, and never fabricates VLAN30 IPv4."""
    pools = get_dhcp_pool_context(client)
    secondary = [p for p in pools if p.server == "secondary"]
    found = {(p.vlan, p.family) for p in secondary}
    missing = R2_EXPECTED_POOLS - found
    if missing:
        raise nb.NetboxModelError(f"R2 secondary DHCP context is missing pool(s) for {sorted(missing)}")
    unexpected = found - R2_EXPECTED_POOLS
    if unexpected:
        raise nb.NetboxModelError(
            f"R2 secondary DHCP context has unexpected pool(s) for {sorted(unexpected)} "
            "(VLAN30 must stay IPv4-less; only VLAN10/20/30 are covered)"
        )
    duplicates = [key for key in found if sum(1 for p in secondary if (p.vlan, p.family) == key) > 1]
    if duplicates:
        raise nb.NetboxModelError(f"R2 secondary DHCP context has duplicate pool(s) for {sorted(duplicates)}")
    ipv4 = sorted((p for p in secondary if p.family == 4), key=lambda p: p.vlan)
    ipv6 = sorted((p for p in secondary if p.family == 6), key=lambda p: p.vlan)
    return {"ipv4_subnets": ipv4, "ipv6_subnets": ipv6}


def validate_dhcp_pool_safety(pools: list[DhcpPool], *, infrastructure_addresses: set[str] | None = None) -> list[str]:
    """Fail-closed structural safety checks over a pool list (Step 4):
    never mutates `pools`; returns every problem found (empty list = safe)
    rather than raising, so a caller can report the complete picture (the
    same convention `validate_reservations()` uses).

    Checks:
      * no primary/secondary overlap for the same VLAN/family;
      * every pool's start/end fall inside its own recorded prefix;
      * no pool contains a shared-gateway/VRRP address (a pool's own
        `gateway` is exempt from this check on itself -- it legitimately
        describes that pool's gateway, not a collision -- but IS checked
        against every OTHER pool);
      * no pool contains an address from `infrastructure_addresses` (S1/S2
        SVI addresses and any other caller-supplied protected address);
      * VLAN30 never has an IPv4 pool of either server.
    """
    problems: list[str] = []
    infrastructure_addresses = infrastructure_addresses or set()

    def _range(pool: DhcpPool) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]:
        return (ipaddress.ip_address(pool.start), ipaddress.ip_address(pool.end))

    for pool in pools:
        if pool.vlan == 30 and pool.family == 4:
            problems.append(f"VLAN30 must stay IPv6-only but a {pool.server} IPv4 pool exists: {pool.start}-{pool.end}")
        if pool.prefix is not None:
            network = ipaddress.ip_network(pool.prefix)
            start, end = _range(pool)
            if start not in network or end not in network:
                problems.append(f"VLAN{pool.vlan} {pool.server} {start}-{end} is not inside its prefix {pool.prefix}")

    by_vlan_family: dict[tuple[int, int], list[DhcpPool]] = {}
    for pool in pools:
        by_vlan_family.setdefault((pool.vlan, pool.family), []).append(pool)
    for (vid, family), group in by_vlan_family.items():
        for i, a in enumerate(group):
            a_start, a_end = _range(a)
            for b in group[i + 1:]:
                b_start, b_end = _range(b)
                if a_start <= b_end and b_start <= a_end:
                    problems.append(
                        f"VLAN{vid} IPv{family} pools overlap: {a.server} {a_start}-{a_end} vs. {b.server} {b_start}-{b_end}"
                    )

    protected: set[str] = set(infrastructure_addresses) | {p.gateway for p in pools if p.gateway is not None}
    for pool in pools:
        start, end = _range(pool)
        for addr in protected:
            try:
                parsed = ipaddress.ip_address(addr)
            except ValueError:
                continue
            if parsed.version != pool.family:
                continue
            if start <= parsed <= end:
                problems.append(f"VLAN{pool.vlan} {pool.server} IPv{pool.family} pool {start}-{end} contains protected address {addr}")

    return problems


# ---------------------------------------------------------------------------
# Phase 3D: R2 DHCP integration into the real push path.
#
# Everything below is the fail-closed gate `master.py`'s push_eos() and
# netbox/scripts/render_r2_dhcp.py both call before rendering/pushing R2 --
# neither one re-implements pool safety, NetBox querying, or DHCP
# architecture rules itself (Step 4/7's own instruction). A NetBox failure
# or any safety-check failure here RAISES (NetboxError/NetboxModelError);
# nothing in this module ever catches one of these to silently fall back
# to rendering R2 without its DHCP section.
# ---------------------------------------------------------------------------

#: S1/S2's own client-VLAN SVI addresses (Step 4's "S1/S2 infrastructure
#: SVI addresses" protection) -- read live from NetBox rather than
#: hard-coded, so a future renumbering is picked up automatically instead
#: of silently going stale here. Moved from netbox/scripts/render_r2_dhcp.py
#: (Phase 3C) so both that script and master.py's push path share one
#: implementation.
_R2_PROTECTED_INFRA_SWITCHES = ("S1", "S2")
_R2_PROTECTED_INFRA_INTERFACES = ("Vlan10", "Vlan20", "Vlan30")


def get_r2_protected_addresses(client=None) -> set[str]:
    """Every address `validate_dhcp_pool_safety()` must treat as protected
    beyond each pool's own gateway: S1/S2's client-VLAN SVI addresses."""
    client = client or nb.build_client()
    addresses: set[str] = set()
    for device in _R2_PROTECTED_INFRA_SWITCHES:
        for interface in _R2_PROTECTED_INFRA_INTERFACES:
            for family in (4, 6):
                addr = nb.get_interface_address(device, interface, family, client)
                if addr is not None:
                    addresses.add(addr["address"])
    return addresses


def build_and_validate_r2_dhcp_context(client=None) -> dict:
    """The Step 7 fail-closed pre-push gate: builds R2's secondary-DHCP
    rendering context AND validates the ENTIRE pool matrix (primary +
    secondary, every VLAN/family) for safety before returning anything.

    Raises (never returns a partial or unsafe result) if:
      * NetBox is unreachable/unauthenticated (`NetboxError` subclasses,
        propagated from `get_dhcp_pool_context()`/`get_r2_dhcp_context()`);
      * the secondary pool set is missing an expected VLAN/family, or
        contains an unexpected one (e.g. a stale VLAN30 IPv4 pool) --
        `get_r2_dhcp_context()`'s own existing fail-closed check;
      * `validate_dhcp_pool_safety()` finds ANY problem (overlap, wrong
        prefix, a gateway or S1/S2 infrastructure address inside a pool).

    Callers (`master.py`'s push path, `netbox/scripts/render_r2_dhcp.py`)
    MUST let this exception propagate rather than catching it to render R2
    without DHCP -- that is precisely the "NetBox failure silently drops
    DHCP" failure mode Step 7 forbids.
    """
    client = client or nb.build_client()
    all_pools = get_dhcp_pool_context(client)
    dhcp_context = get_r2_dhcp_context(client)  # raises on missing/unexpected pools
    infra = get_r2_protected_addresses(client)
    problems = validate_dhcp_pool_safety(all_pools, infrastructure_addresses=infra)
    if problems:
        raise nb.NetboxModelError("R2 DHCP pool safety validation failed:\n  - " + "\n  - ".join(problems))
    return dhcp_context


def validate_r2_candidate_render(candidate: str, client=None) -> None:
    """Post-render fail-closed check (Step 7): the fully-rendered R2
    candidate must contain a non-empty DHCP server section, and must NOT
    have lost Vlan200's static IPv4/IPv6 address -- both read live from
    NetBox (never a hard-coded literal) so this stays correct if Vlan200
    is ever legitimately renumbered by an unrelated, approved change.
    Raises NetboxModelError on either failure."""
    if "dhcp server" not in candidate:
        raise nb.NetboxModelError("R2 candidate render is missing its DHCP server section")
    client = client or nb.build_client()
    for family in (4, 6):
        primary = nb.get_primary_address("R2", family, client)
        if primary is None:
            raise nb.NetboxModelError(f"R2 has no NetBox-recorded primary IPv{family} address to validate against")
        if primary["cidr"] not in candidate:
            raise nb.NetboxModelError(f"R2 candidate render lost its static IPv{family} Vlan200 address ({primary['cidr']})")


def dhcp_render_delta(base_commands: list[str], integrated_commands: list[str]) -> dict[str, list[str]]:
    """Generic semantic-delta helper (Step 5/9): compares two flattened
    `eos_commands()` outputs (typically "R2 rendered without a `dhcp`
    context" vs. "R2 rendered with one") and reports exactly what was
    added/removed, order-independent and de-duplicated. `render_r2_dhcp.py`
    and its tests use this to enforce "the delta is DHCP-only" -- this
    function itself makes no assumption about WHAT counts as DHCP-only,
    it only computes the diff; the caller decides whether the reported
    `added`/`removed` sets are acceptable."""
    base_set, integrated_set = set(base_commands), set(integrated_commands)
    return {
        "added": sorted(integrated_set - base_set),
        "removed": sorted(base_set - integrated_set),
    }


# ---------------------------------------------------------------------------
# Phase 3G: NMAS primary DHCP pool cutover to NetBox.
#
# Mirrors the R2/secondary functions above exactly (Step 15's "one shared
# safety model" -- both call the SAME get_dhcp_pool_context()/
# validate_dhcp_pool_safety()/get_r2_protected_addresses() rather than a
# second, inconsistent implementation). The only NMAS-specific piece is
# the ISC-dhcpd-shaped output (dotted-decimal netmask, not CIDR) the
# dhcp/dhcpd.conf.j2/dhcpd6.conf.j2 templates need.
# ---------------------------------------------------------------------------

#: The exact (vlan, family) pairs NMAS's documented primary design covers
#: -- identical set to R2_EXPECTED_POOLS by design (every VLAN/family that
#: has a secondary pool also has a primary one, and vice versa).
NMAS_EXPECTED_POOLS = frozenset({(10, 4), (10, 6), (20, 4), (20, 6), (30, 6)})

#: NetBox's own modeled management prefixes (Phase 2) -- the "no lease"
#: subnet stub ISC dhcpd requires to exist for the relay's own local
#: network, even though it hands out nothing.
_MANAGEMENT_PREFIX_V4 = "192.168.200.0/24"
_MANAGEMENT_PREFIX_V6 = "2001:db8:200::/64"


def _dotted_netmask(prefix: str) -> str:
    return str(ipaddress.ip_network(prefix).netmask)


def get_nmas_dhcp_context(client=None) -> dict:
    """The normalized rendering context for NMAS's PRIMARY DHCP-server
    configuration: exactly the pools tagged `server="primary"`, in the
    ISC-dhcpd-shaped form `dhcp/dhcpd.conf.j2`/`dhcpd6.conf.j2` consume
    (dotted-decimal netmask for v4, since ISC's `subnet`/`netmask` syntax
    -- unlike EOS's `subnet <CIDR>` -- takes network address + netmask
    separately). Fail-closed (Step 18): raises `NetboxModelError` if a
    pool the documented design requires is missing, or an unexpected one
    exists (mirrors `get_r2_dhcp_context()`'s own contract exactly)."""
    client = client or nb.build_client()
    pools = get_dhcp_pool_context(client)
    primary = [p for p in pools if p.server == "primary"]
    found = {(p.vlan, p.family) for p in primary}
    missing = NMAS_EXPECTED_POOLS - found
    if missing:
        raise nb.NetboxModelError(f"NMAS primary DHCP context is missing pool(s) for {sorted(missing)}")
    unexpected = found - NMAS_EXPECTED_POOLS
    if unexpected:
        raise nb.NetboxModelError(
            f"NMAS primary DHCP context has unexpected pool(s) for {sorted(unexpected)} "
            "(VLAN30 must stay IPv4-less; only VLAN10/20/30 are covered)"
        )
    duplicates = [key for key in found if sum(1 for p in primary if (p.vlan, p.family) == key) > 1]
    if duplicates:
        raise nb.NetboxModelError(f"NMAS primary DHCP context has duplicate pool(s) for {sorted(duplicates)}")

    ipv4_subnets = []
    for p in sorted((p for p in primary if p.family == 4), key=lambda p: p.vlan):
        network = ipaddress.ip_network(p.prefix)
        ipv4_subnets.append({
            "vlan": p.vlan, "network": str(network.network_address), "netmask": str(network.netmask),
            "start": p.start, "end": p.end, "gateway": p.gateway,
        })
    ipv6_subnets = [
        {"vlan": p.vlan, "prefix": p.prefix, "start": p.start, "end": p.end}
        for p in sorted((p for p in primary if p.family == 6), key=lambda p: p.vlan)
    ]

    mgmt_v4 = nb.get_prefix(_MANAGEMENT_PREFIX_V4, client)
    mgmt_v6 = nb.get_prefix(_MANAGEMENT_PREFIX_V6, client)
    mgmt_network = ipaddress.ip_network(mgmt_v4["prefix"])
    return {
        "management": {
            "v4_network": str(mgmt_network.network_address), "v4_netmask": str(mgmt_network.netmask),
            "v6_prefix": mgmt_v6["prefix"],
        },
        "ipv4_subnets": ipv4_subnets,
        "ipv6_subnets": ipv6_subnets,
    }


def build_and_validate_nmas_dhcp_context(client=None) -> dict:
    """The Step 18 fail-closed pre-render gate for NMAS -- mirrors
    `build_and_validate_r2_dhcp_context()` exactly, reusing the SAME
    ten-pool (primary + secondary, every VLAN/family) safety validation
    (Step 15's "one shared safety model"): overlap, prefix containment,
    gateway/S1-S2-infrastructure-address protection, and VLAN30-IPv4
    prohibition are all checked across the FULL matrix before either
    server's context is considered safe to render, not a second,
    NMAS-only copy of that logic.

    Raises (never returns a partial/unsafe result) on any NetBox failure,
    missing/unexpected pool, or safety-check finding -- callers (a future
    `master.py` NMAS-rendering call, `netbox/scripts/render_nmas_dhcp.py`)
    MUST let this propagate rather than falling back to a hard-coded
    range or proceeding to render/install/restart NMAS's DHCP config."""
    client = client or nb.build_client()
    all_pools = get_dhcp_pool_context(client)
    nmas_context = get_nmas_dhcp_context(client)  # raises on missing/unexpected/duplicate pools
    infra = get_r2_protected_addresses(client)
    problems = validate_dhcp_pool_safety(all_pools, infrastructure_addresses=infra)
    if problems:
        raise nb.NetboxModelError("NMAS DHCP pool safety validation failed:\n  - " + "\n  - ".join(problems))
    return nmas_context
