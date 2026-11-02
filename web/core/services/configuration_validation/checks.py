"""What the "Configuration Validation" workflow tests on one dispatched bundle.

Pure: a decoded bundle (and the repository it is checked out in) in, categories of checks out.  No database, no device,
no NetBox, no network.  The bundle is tested against the REPOSITORY's own rules (capability matrix, inventory, parser),
not against what NMAS claimed: where the two disagree, the check fails.

    A  bundle integrity        hashes, schema, provenance
    B  candidate rendering     the candidate parses for its platform, interface blocks are consolidated, no conflicting stanza
    C  platform support        every requested feature is implemented for the target platform; anything else fails closed
    D  intent / dependency     dependency graph, protected VLAN 200, managed scope (R5 and unknown devices), authority boundaries
    E  syntax / semantics      what can be judged without a device: addresses, VLAN ids, markers, secret-shaped content
    F  path-scoped tests       the narrowest existing test modules for this platform / feature / Change type (run by the caller)
"""

from __future__ import annotations

import ipaddress
import re
import uuid
from pathlib import Path

from . import bundle as bundle_module

PASS, FAIL = "PASS", "FAIL"
PASSING_TIER2 = ("PASS", "PASS_WITH_WARNINGS")
PROTECTED_VLAN = 200
# Ordinary infrastructure writes are limited to R1-R4, S1-S4 and mgmt_swt (execution blocker
# TARGET_DEVICE_OUTSIDE_MANAGED_SCOPE): R5 is in the inventory and is not a target of a Configuration Change.
OUT_OF_SCOPE_DEVICES = ("R5",)
UNSUPPORTED_MARKERS = ("not implemented yet", "<process-id-required>", "<interface-required>", "<area-required>")
SINGLE_VALUED = ("description ", "switchport access vlan ", "switchport mode ", "mtu ", "isis metric ", "ip ospf cost ", "encapsulation dot1q ")
_CHANGE_ID = re.compile(r"^CHG-\d{8}-\d{4}$")
_SHA = re.compile(r"^[0-9a-f]{64}$")
_V4 = re.compile(r"^\s*ip address (\S+)")
_V6 = re.compile(r"^\s*ipv6 address (\S+)")
_VLAN = re.compile(r"^\s*(?:vlan|switchport access vlan|interface [Vv]lan) ?(\d+)\s*$")
_MANAGEMENT_SVI = re.compile(rf"^interface vlan ?{PROTECTED_VLAN}$", re.I)

# F: the narrowest existing Django test modules per platform, feature and Change type
TESTS_ALWAYS = ("configuration_validation", "network_config_validation")
TESTS_BY_PLATFORM = {"arista_ceos": ("candidate_renderer", "parser_ceos"), "ubuntu_frr": ("parser_frr", "frr_routing_executor"),
                     "nokia_srlinux": ("srlinux_driver",), "cisco_c8000v_iosxe": ("c8000v_iosxe_driver",), "cisco_iosxr": ("ios8000v_driver",),
                     "sonic": ("sonic_driver",)}
TESTS_BY_FEATURE = (("interface.", ("interface_renderer", "candidate_composition")), ("routing.ISIS", ("isis_ceos",)),
                    ("routing.OSPF", ("phase2_ospf_networks",)), ("routing.", ("routing_renderer", "phase13_routing")))
TESTS_BY_WORKFLOW = {"REMOVE_CONFIGURATION": ("config_workbench",), "CONFIGURATION_CHANGES": ("config_workflows",)}
TESTS_BY_CATEGORY = {"NEW_DEVICE_PROVISIONING": ("provisioning",)}


class Category:
    def __init__(self, key: str, title: str):
        self.key, self.title, self.checks = key, title, []

    def add(self, name: str, ok: bool, detail: str = "") -> bool:
        self.checks.append({"name": name, "status": PASS if ok else FAIL, "detail": str(detail)[:300]})
        return bool(ok)

    @property
    def status(self) -> str:
        return PASS if self.checks and all(check["status"] == PASS for check in self.checks) else FAIL

    def as_dict(self) -> dict:
        return {"category": self.key, "title": self.title, "status": self.status, "checks": self.checks}


def _is_uuid(value) -> bool:
    try:
        uuid.UUID(str(value))
        return True
    except ValueError:
        return False


def _blocks(text: str) -> list[tuple[str, list[str]]]:
    blocks = []
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith(("!", "#")):
            continue
        if not line.startswith(" "):
            blocks.append((line.strip(), []))
        elif blocks:
            blocks[-1][1].append(line.strip())
    return blocks


# ----------------------------------------------------------------------------------------------------------------------- A
def integrity(bundle: dict, payload: dict | None = None) -> Category:
    from ..validation import snapshot as snapshot_module

    found = Category("A", "Bundle integrity")
    missing = [key for key in bundle_module.REQUIRED if key not in bundle]
    if not found.add("schema and required fields", not missing and bundle.get("schema_version") == bundle_module.SCHEMA_VERSION and bundle.get("kind") == bundle_module.KIND,
                     f"missing {', '.join(missing)}" if missing else f"schema {bundle.get('schema_version')}, kind {bundle.get('kind')}"):
        return found
    found.add("snapshot hash matches the intent", snapshot_module.hash_snapshot(bundle["intent"]) == bundle["snapshot_hash"], bundle["snapshot_hash"][:12])
    wrong = [d.get("device", "?") for d in bundle["devices"] if bundle_module.digest(d.get("candidate", "")) != d.get("candidate_sha256")]
    found.add("candidate fragments match their hashes", not wrong, f"altered: {', '.join(wrong)}" if wrong else f"{len(bundle['devices'])} device(s)")
    found.add("candidate hash matches", bundle_module.candidate_hash(bundle["devices"], bundle["removals"]) == bundle["candidate_hash"], bundle["candidate_hash"][:12])
    if payload is not None:
        same = all(payload.get(key) == value for key, value in (("snapshot_hash", bundle["snapshot_hash"]), ("candidate_hash", bundle["candidate_hash"]),
                                                               ("correlation_id", bundle["correlation_id"]), ("change_id", bundle["change"].get("change_id"))))
        found.add("dispatch envelope names this bundle", same)
    validation, change = bundle["validation"], bundle["change"]
    found.add("provenance", _is_uuid(bundle["correlation_id"]) and _is_uuid(validation.get("run_id")) and bool(_CHANGE_ID.match(str(change.get("change_id", ""))))
              and bool(_SHA.match(bundle["snapshot_hash"])) and bool(validation.get("repository_sha")),
              f"{change.get('change_id')} validation {str(validation.get('run_id'))[:8]} repository {str(validation.get('repository_sha'))[:12]}")
    found.add("Tier-2 validation passed for this snapshot", validation.get("status") in PASSING_TIER2 and validation.get("input_hash") == bundle["snapshot_hash"]
              and not validation.get("blocking_findings"), f"{validation.get('status')}, blocking findings: {validation.get('blocking_findings') or 'none'}")
    return found


# ----------------------------------------------------------------------------------------------------------------------- B
def rendering(bundle: dict) -> Category:
    from .. import platform_drivers
    from ..config_workbench.structure import parse

    found = Category("B", "Candidate rendering")
    intent = {d["device_name"]: d for d in bundle["intent"].get("devices") or []}
    if not bundle["devices"]:                   # a removal renders nothing: its content hash is bound by the candidate hash (category A)
        found.add("the Change has a candidate", bool(bundle["removals"]), f"{len(bundle['removals'])} removal(s), no rendered device candidate")
    for device in bundle["devices"]:
        name, text = device["device"], device.get("candidate", "")
        known = device["platform"] in platform_drivers.PLATFORM_DRIVERS
        found.add(f"{name}: a renderer exists for {device['platform']}", known)
        found.add(f"{name}: platform is the intended one", (intent.get(name) or {}).get("platform") == device["platform"])
        try:
            tree = parse(text)
            found.add(f"{name}: candidate parses", bool(text.strip()) and tree.line_count > 0, f"{tree.line_count} lines")
        except Exception as exc:  # noqa: BLE001 - a candidate that cannot be parsed is a failed check, never a crash
            found.add(f"{name}: candidate parses", False, type(exc).__name__)
            continue
        markers = [marker for marker in UNSUPPORTED_MARKERS if marker in text.lower()]
        found.add(f"{name}: no unrendered placeholder", not markers and not device.get("composition_conflicts"),
                  ", ".join(markers) or f"{device.get('composition_conflicts') or 0} composition conflict(s)")
        blocks = _blocks(text)
        headers = [header.lower() for header, _children in blocks if header.lower().startswith("interface ")]
        repeated = sorted({header for header in headers if headers.count(header) > 1})
        found.add(f"{name}: interface blocks are consolidated", not repeated, f"repeated: {', '.join(repeated)}" if repeated else f"{len(headers)} interface block(s)")
        conflicts = []
        for header, children in blocks:
            for stem in SINGLE_VALUED:
                values = {child for child in children if child.startswith(stem)}
                if len(values) > 1:
                    conflicts.append(f"{header}: {stem.strip()}")
            primary = {child for child in children if child.startswith("ip address ") and not child.endswith(" secondary")}
            if len(primary) > 1:
                conflicts.append(f"{header}: ip address")
        found.add(f"{name}: no conflicting stanza", not conflicts, "; ".join(conflicts[:3]))
    return found


# ----------------------------------------------------------------------------------------------------------------------- C
def matrix_status(platform: str, feature: str) -> str:
    """The repository's own capability verdict for one feature on one platform ('' when it knows neither)."""
    from .. import platform_drivers as drivers

    family, _dot, code = feature.partition(".")
    table = {"interface": drivers.PLATFORM_CAPABILITIES, "routing": drivers.ROUTING_CAPABILITIES}.get(family, {}).get(platform, {})
    for key, capability in table.items():
        if str(getattr(key, "value", key)) == code:
            return capability.status.value
    return ""


def platform_support(bundle: dict) -> Category:
    found = Category("C", "Platform support")
    claimed = {(row.get("platform"), row.get("feature")): row.get("status") for row in bundle["matrix"]}
    intent = {d["device_name"]: d for d in bundle["intent"].get("devices") or []}
    for device in bundle["devices"]:
        derived = bundle_module.features_of(intent.get(device["device"]) or {})
        found.add(f"{device['device']}: requested features are the ones in the intent", sorted(device.get("features") or []) == derived, ", ".join(derived) or "none")
        for feature in derived:
            status = matrix_status(device["platform"], feature)
            found.add(f"{device['device']}: {feature} on {device['platform']}", status == "SUPPORTED", status or "not in the capability matrix")
            if claimed.get((device["platform"], feature)) not in (None, status):
                found.add(f"{device['device']}: {feature} matrix fact agrees with the repository", False, f"NMAS said {claimed[(device['platform'], feature)]}")
    if not found.checks:
        found.add("no feature needs a platform capability", True, "removal only")
    return found


# ----------------------------------------------------------------------------------------------------------------------- D
def _protected_vlan_findings(bundle: dict) -> list[str]:
    problems = []
    for device in bundle["intent"].get("devices") or []:
        for interface in (device.get("interfaces") or {}).values():
            name = str(interface.get("name", ""))
            if not _MANAGEMENT_SVI.match(f"interface {name}"):
                continue
            modes = {str(interface.get(key, "")).upper() for key in ("ipv4_assignment_mode", "ipv6_assignment_mode", "ipv4_mode", "ipv6_mode")}
            sources = {str(address.get("source", "")).upper() for address in (interface.get("addresses") or {}).values()}
            if modes & {"DHCP", "DHCPV6", "SLAAC", "AUTO"} or "AUTO" in sources:
                problems.append(f"{device['device_name']}: VLAN {PROTECTED_VLAN} addressing must remain static")
    for device in bundle["devices"]:
        for header, children in _blocks(device.get("candidate", "")):
            lowered = header.lower()
            if lowered in (f"no vlan {PROTECTED_VLAN}", f"no interface vlan{PROTECTED_VLAN}", f"default interface vlan{PROTECTED_VLAN}"):
                problems.append(f"{device['device']}: {header}")
            if _MANAGEMENT_SVI.match(lowered):
                problems += [f"{device['device']}: {header} > {child}" for child in children
                             if child in ("shutdown", "no ip address", "no ipv6 address") or child.startswith(("ip address dhcp", "ipv6 address dhcp", "ipv6 address auto"))]
    return problems


def intent_checks(bundle: dict, *, repo_root: Path) -> Category:
    import yaml

    found = Category("D", "Intent and dependency checks")
    graph = bundle["dependencies"]
    nodes = {node.get("id") for node in graph.get("nodes") or []}
    dangling = [edge for edge in graph.get("edges") or [] if not graph.get("truncated") and (edge.get("from") not in nodes or edge.get("to") not in nodes)]
    found.add("dependency graph is internally consistent", not dangling and not graph.get("cycles"),
              f"{len(dangling)} dangling edge(s), {len(graph.get('cycles') or [])} cycle(s)" if dangling or graph.get("cycles") else f"{len(nodes)} node(s)")
    named = sorted({d["device"] for d in bundle["devices"]} | {r["device"] for r in bundle["removals"]})
    intended = sorted({d["device_name"] for d in bundle["intent"].get("devices") or []} | {r["device"] for r in (bundle["intent"].get("config_removals") or {}).get("items") or []})
    found.add("targets are the devices of the intent", named == intended, ", ".join(named))
    problems = _protected_vlan_findings(bundle)
    found.add(f"protected VLAN {PROTECTED_VLAN} is not changed", not problems, "; ".join(problems[:3]))
    with open(repo_root / "inventory.yml", encoding="utf-8") as handle:
        managed = set((yaml.safe_load(handle) or {}).get("network_devices") or {})
    scope = bundle["scope"]
    new = {d["device_name"] for d in bundle["intent"].get("devices") or [] if d.get("target_type") == "NEW_DEVICE"}
    admitted = set(scope.get("provisioning") or []) & new if bundle["change"].get("category") == "NEW_DEVICE_PROVISIONING" else set()
    existing = {d["device_name"] for d in bundle["intent"].get("devices") or [] if d.get("target_type") == "EXISTING_DEVICE"}
    active = (set(scope.get("nmas_active") or []) & existing) if scope.get("check") == "PASS" else set()
    outside = sorted((set(named) - managed - admitted - active) | (set(named) & set(OUT_OF_SCOPE_DEVICES))
                     | set(scope.get("outside_scope") or []))
    found.add("every target is inside the managed scope", not outside, f"outside: {', '.join(outside)}" if outside else ", ".join(named))
    raw = (bundle["intent"].get("raw_configlets") or {}).get("items") or []
    boundaries = []
    if bundle["change"].get("transition_kind"):
        boundaries.append("a routing transition is executed by its own workflow, not as a Configuration Change")
    if raw and bundle["change"].get("execution_mode") == "COMPLETE":
        boundaries.append("Raw Configlets cannot be part of a Complete execution")
    if any(d.get("target_type") == "NEW_DEVICE" for d in bundle["intent"].get("devices") or []) and bundle["change"].get("category") != "NEW_DEVICE_PROVISIONING":
        boundaries.append("a new device is created by a provisioning Change only")
    found.add("authority boundaries hold", not boundaries, "; ".join(boundaries))
    return found


# ----------------------------------------------------------------------------------------------------------------------- E
def syntax(bundle: dict) -> Category:
    from ..ci import redact

    found = Category("E", "Syntax and semantic checks")
    for device in bundle["devices"]:
        name, problems = device["device"], []
        for line in device.get("candidate", "").splitlines():
            if "\t" in line or any(ord(char) < 32 for char in line):
                problems.append(f"control character: {line.strip()[:40]}")
            if line.lstrip().startswith("%"):
                problems.append(f"device error text in the candidate: {line.strip()[:40]}")
            for pattern, version in ((_V4, 4), (_V6, 6)):
                match = pattern.match(line)
                if match and match.group(1) not in ("dhcp", "auto-config", "virtual", "autoconfig") and "<" not in match.group(1):
                    try:
                        if ipaddress.ip_interface(match.group(1)).version != version:
                            raise ValueError
                    except ValueError:
                        problems.append(f"not an IPv{version} address: {line.strip()[:60]}")
            match = _VLAN.match(line)
            if match and not 1 <= int(match.group(1)) <= 4094:
                problems.append(f"VLAN id out of range: {line.strip()}")
        found.add(f"{name}: statements are well formed", not problems, "; ".join(problems[:3]))
    try:
        bundle_module.assert_safe(bundle)
        found.add("no secret-shaped content in the bundle", True)
    except bundle_module.BundleError as exc:
        found.add("no secret-shaped content in the bundle", False, redact.bound_string(str(exc), 120))
    return found


# ----------------------------------------------------------------------------------------------------------------------- F
def select_tests(bundle: dict, *, repo_root: Path) -> list[str]:
    """Django test labels for this candidate: by platform, feature and Change type.  Only modules that exist."""
    wanted = list(TESTS_ALWAYS)
    for device in [*bundle.get("devices", []), *bundle.get("removals", [])]:
        wanted += TESTS_BY_PLATFORM.get(device.get("platform"), ())
        for feature in device.get("features") or []:
            for prefix, modules in TESTS_BY_FEATURE:
                if feature.startswith(prefix):
                    wanted += modules
    change = bundle.get("change") or {}
    wanted += TESTS_BY_WORKFLOW.get(change.get("workflow"), ())
    wanted += TESTS_BY_CATEGORY.get(change.get("category"), ())
    tests = repo_root / "web" / "core" / "tests"
    return [f"core.tests.test_{name}" for name in dict.fromkeys(wanted) if (tests / f"test_{name}.py").is_file()]


def run_static(bundle: dict, *, repo_root: Path, payload: dict | None = None) -> list[Category]:
    """Categories A to E.  A bundle that fails its integrity check is not examined further."""
    first = integrity(bundle, payload)
    if first.status != PASS:
        return [first]
    return [first, rendering(bundle), platform_support(bundle), intent_checks(bundle, repo_root=repo_root), syntax(bundle)]
