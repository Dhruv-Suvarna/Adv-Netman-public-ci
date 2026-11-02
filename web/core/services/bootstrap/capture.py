"""READ-ONLY capture of what is actually running, and the comparison of a later read with the captured baseline.

Source of truth: the DEVICES, not ``DeviceIntent`` / YAML / Jinja / Git -- the network predates the framework.  Every read goes through the
existing trusted, allowlisted, server-owned sessions of ``health.live`` (Netmiko privileged EXEC ``show`` commands for cEOS; a credential-free
``docker exec <container> <fixed argv>`` for Ubuntu / FRR and for a cEOS device with a Containerlab-assigned address, i.e. R5).  No command, host or path ever comes from a browser; nothing is configured, cleared,
saved or reloaded; a session is opened and closed per device per read.

    cEOS        ``show running-config``
    Ubuntu/FRR  ``vtysh -c "show running-config"`` and ``nft list ruleset``

Raw text lives in memory only: it is sanitized (``bundles.legacy_sanitize``) before ANYTHING is stored, logged or hashed for persistence.

All-or-nothing: every managed inventory device must be read.  An unreachable / unsupported / failing device makes the capture INCOMPLETE and
nothing is created; no device is silently omitted.  (Repository policy currently excludes no managed device; ``EXCLUDED_DEVICES`` is where a
recorded exclusion with its reason would go.)
"""

from __future__ import annotations

import difflib
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime

from ..bundles import canonical, legacy
from ..bundles.legacy_sanitize import SanitizeError, sanitize_config
from ..health import inventory, live, telemetry
from ..health.evidence import DeviceEvidence
from ..health.results import iso, utcnow

MAX_WORKERS = 5
MAX_DIFF_LINES = 5
MAX_DIFF_LINE_CHARS = 160
EXCLUDED_DEVICES: dict = {}   # {device: reason} -- repository policy that takes a device out of managed configuration scope (none today)

# platform key -> ordered (section name, allowlist key, human-readable command)
SECTIONS = {
    "ceos": (("running-config", "running_config", "show running-config"),),
    "linux": (("frr-running-config", "frr_config", "vtysh -c 'show running-config'"), ("nft-ruleset", "nft", "nft list ruleset")),
}
TRANSPORT = {"ceos": "netmiko-ssh (privileged EXEC, show commands only)", "linux": "docker-exec (fixed read-only argv, no shell)"}
TRANSPORT_DOCKER_CLI = "docker-exec Cli -p 15 -c (fixed read-only show commands, no shell; Containerlab-assigned management address)"
CREDENTIAL_REF = {"ceos": "inventory.yml#ceos_credentials", "linux": "none (docker exec)"}


def transport_of(device: dict) -> str:
    """How this device is read: the same rule ``live.default_session_factory`` applies (a cEOS device with no inventory address is read through docker exec)."""
    platform = device.get("platform", "")
    if platform == "ceos" and not device.get("address") and device.get("container"):
        return TRANSPORT_DOCKER_CLI
    return TRANSPORT.get(platform, "NOT_SUPPORTED")


def credential_ref_of(device: dict) -> str:
    return "none (docker exec)" if transport_of(device) == TRANSPORT_DOCKER_CLI else CREDENTIAL_REF.get(device.get("platform", ""), "")


REQUIRED_GROUPS = {"ceos": ("interfaces", "addresses", "routes", "ospf", "bgp"), "linux": ("interfaces", "addresses", "routes", "ospf", "bgp")}


def raw_keys(platform: str) -> tuple:
    return tuple(key for _name, key, _cmd in SECTIONS.get(platform, ()))


@dataclass
class DeviceRead:
    device: dict
    evidence: DeviceEvidence
    raw: dict = field(default_factory=dict)
    errors: dict = field(default_factory=dict)
    read_at: datetime | None = None

    @property
    def name(self) -> str:
        return self.device["name"]


def managed_scope() -> dict:
    """{name: inventory entry} of every managed device that is in configuration scope (from ``inventory.yml`` only)."""
    return {name: entry for name, entry in inventory.managed_devices().items() if name not in EXCLUDED_DEVICES}


def read_all(devices: dict, *, session_factory=None, now: datetime | None = None, max_workers: int = MAX_WORKERS) -> dict:
    """One bounded read-only read of every device (in parallel: independent sessions), -> {name: DeviceRead}, sorted.  Never raises."""
    now = now or utcnow()

    def one(entry):
        evidence, raw, errors = live.read_device_with_raw(entry, raw_keys(entry["platform"]), session_factory=session_factory, now=now)
        return DeviceRead(entry, evidence, raw, errors, now)

    names = sorted(devices)
    if len(names) <= 1 or max_workers <= 1:
        return {name: one(devices[name]) for name in names}
    with ThreadPoolExecutor(max_workers=min(max_workers, len(names))) as pool:
        results = list(pool.map(lambda name: one(devices[name]), names))
    return {read.name: read for read in results}


# --- sanitized sections ---------------------------------------------------------------------------------------------------------
def sanitize_sections(read: DeviceRead) -> tuple[list[dict], list[str]]:
    """-> (sections, problems).  Any missing / empty / unsanitizable section is a PROBLEM: the capture is all-or-nothing."""
    sections, problems = [], []
    for name, key, command in SECTIONS.get(read.device["platform"], ()):
        if key in read.errors or key not in read.raw:
            problems.append(f"{read.name}:{name}:{read.errors.get(key, 'NOT_READ')}")
            continue
        try:
            cleaned = sanitize_config(read.raw[key])
        except SanitizeError as exc:
            problems.append(f"{read.name}:{name}:{exc}")
            continue
        if not cleaned.text.strip() and key != "nft":   # an empty nft ruleset is a real state; an empty running-config is not
            problems.append(f"{read.name}:{name}:EMPTY")
            continue
        sections.append({
            "name": name, "command_key": key, "command": command, "sanitized": cleaned.text, "sha256": canonical.text_hash(cleaned.text),
            "raw_lines": cleaned.raw_lines, "kept_lines": cleaned.kept_lines, "redacted_lines": cleaned.redacted_lines, "redaction_patterns": cleaned.patterns,
        })
    return sections, problems


def _expected_state(evidence: DeviceEvidence, platform: str) -> tuple[dict | None, list[str]]:
    """The baseline-relative facts later samples are held to (from the SAME live read).  A required group that could not be read is a problem."""
    problems, state = [], {}
    for group in REQUIRED_GROUPS.get(platform, ()):
        data = evidence.facts(group)
        if data is None:
            problems.append(f"{evidence.device}:{group}:{(evidence.group(group).error if evidence.group(group) else '') or evidence.live_error or 'UNAVAILABLE'}")
    if problems:
        return None, problems
    routes = {(r["prefix"], r["type"]) for r in evidence.facts("routes")}
    state = {
        "interfaces": {n: {"admin": row.get("admin"), "oper": row.get("oper")} for n, row in sorted(evidence.facts("interfaces").items())},
        "addresses": {n: sorted(v) for n, v in sorted(evidence.facts("addresses").items()) if v},
        "routes": [{"prefix": p, "type": t} for p, t in sorted(routes)],
        "ospf": sorted(({k: n[k] for k in ("family", "neighbor_id", "interface", "state")} for n in evidence.facts("ospf")),
                       key=lambda n: (n["family"], n["interface"], n["neighbor_id"])),
        "bgp": sorted(({k: p[k] for k in ("peer", "remote_as", "state", "family")} for p in evidence.facts("bgp")), key=lambda p: (p["family"], p["peer"])),
    }
    return state, []


def topology_facts(snapshot) -> dict | None:
    if snapshot is None or not snapshot.available:
        return None
    return {"nodes": sorted(snapshot.nodes), "edges": sorted(({"id": str(e["id"]), "status": str(e.get("status") or "UNKNOWN").upper()} for e in snapshot.edges),
                                                                key=lambda e: e["id"])}


def build_payload(reads: dict, *, capture_started_at: datetime, capture_finished_at: datetime, snapshot=None, repository_head: str = "",
                  policy_version: str = "") -> tuple[dict | None, list[str]]:
    """-> (payload, problems).  ``payload`` is None when ANY device could not be captured completely (all-or-nothing)."""
    problems, records = [], []
    redacted_total, patterns = 0, set()
    for name in sorted(reads):
        read = reads[name]
        if read.evidence.live_error:
            problems.append(f"{name}:LIVE:{read.evidence.live_error}")
            continue
        sections, section_problems = sanitize_sections(read)
        expected, state_problems = _expected_state(read.evidence, read.device["platform"])
        problems += section_problems + state_problems
        if section_problems or state_problems:
            continue
        redacted_total += sum(s["redacted_lines"] for s in sections)
        patterns.update(p for s in sections for p in s["redaction_patterns"])
        records.append({
            "device": name, "platform": read.device["platform"],
            "management": {"address": read.device.get("address") or "", "address_v6": read.device.get("address_v6") or "",
                           "transport": transport_of(read.device), "credential_ref": credential_ref_of(read.device)},
            "captured_at": iso(read.read_at), "capture_method": transport_of(read.device) + "; " + "; ".join(c for _n, _k, c in SECTIONS[read.device["platform"]]),
            "read_status": "OK", "sections": sections, "config_digest": legacy.device_config_digest(sections), "expected_state": expected,
        })
    topology = topology_facts(snapshot)
    if topology is None:
        problems.append("TOPOLOGY:UNAVAILABLE")
    if problems:
        return None, problems
    payload = {
        "payload_schema_version": legacy.PAYLOAD_SCHEMA_VERSION, "provenance_type": "LEGACY_BOOTSTRAP",
        "baseline": {
            "description": "The network as it was ACTUALLY RUNNING when captured: configured traditionally, before the automation framework existed.",
            "captured_at": iso(capture_finished_at), "capture_started_at": iso(capture_started_at), "capture_finished_at": iso(capture_finished_at),
            "repository": {"head": repository_head or "UNKNOWN", "role": "provenance only: the baseline is what the devices report, not the repository files"},
            "sanitization": {"stored_text": "SANITIZED_NOT_BYTE_IDENTICAL", "redacted_lines": redacted_total, "redaction_patterns": sorted(patterns),
                             "note": "Secret-bearing values are replaced by <REDACTED>; the baseline represents managed configuration semantics, not literal secret bytes. "
                                     "A change to ONLY a redacted value is not visible to this baseline."},
            "policy_version": policy_version, "excluded_devices": [{"device": d, "reason": r} for d, r in sorted(EXCLUDED_DEVICES.items())],
            "topology": topology, "devices": records,
        },
        "scope": {"devices": [r["device"] for r in records]},
        "verification": {"state": "NOT_APPLICABLE", "scope": "LEGACY_BASELINE", "note": "No Change, plan, UAT or probation soak exists for this configuration; none is fabricated."},
        "items": [],
    }
    return payload, []


# --- comparison of a later read with the captured baseline (configuration drift) ---------------------------------------------------
@dataclass
class ConfigComparison:
    device: str
    status: str                 # MATCH | DRIFT | UNAVAILABLE
    sections_changed: list = field(default_factory=list)
    added: int = 0
    removed: int = 0
    sample_added: list = field(default_factory=list)
    sample_removed: list = field(default_factory=list)
    reason: str = ""

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v not in ("", [], 0) or k in ("device", "status")}


def compare_config(record: dict, read: DeviceRead) -> ConfigComparison:
    """One device: the CURRENT sanitized configuration vs the baseline record.  UNAVAILABLE (never MATCH) when it could not be read completely."""
    if read.evidence.live_error:
        return ConfigComparison(read.name, "UNAVAILABLE", reason=read.evidence.live_error)
    sections, problems = sanitize_sections(read)
    if problems:
        return ConfigComparison(read.name, "UNAVAILABLE", reason=problems[0].split(":", 2)[-1])
    baseline = {s["name"]: s for s in record["sections"]}
    changed, added, removed, sample_added, sample_removed = [], 0, 0, [], []
    if [s["name"] for s in sections] != list(baseline):
        return ConfigComparison(read.name, "DRIFT", sections_changed=["SECTION_SET"])
    for section in sections:
        old = baseline[section["name"]]
        if section["sha256"] == old["sha256"]:
            continue
        changed.append(section["name"])
        for line in difflib.unified_diff(old["sanitized"].splitlines(), section["sanitized"].splitlines(), lineterm="", n=0):
            if line.startswith(("---", "+++", "@@")):
                continue
            if line.startswith("+"):
                added += 1
                if len(sample_added) < MAX_DIFF_LINES:
                    sample_added.append(line[1:][:MAX_DIFF_LINE_CHARS])
            elif line.startswith("-"):
                removed += 1
                if len(sample_removed) < MAX_DIFF_LINES:
                    sample_removed.append(line[1:][:MAX_DIFF_LINE_CHARS])
    if changed:
        return ConfigComparison(read.name, "DRIFT", sections_changed=changed, added=added, removed=removed, sample_added=sample_added, sample_removed=sample_removed)
    return ConfigComparison(read.name, "MATCH")


def compare_all(candidate, reads: dict) -> list[ConfigComparison]:
    """Every included device against the candidate's baseline record (a device with no read is UNAVAILABLE, never assumed to match)."""
    out = []
    for record in ((candidate.payload.get("baseline") or {}).get("devices") or []):
        read = reads.get(record["device"])
        out.append(compare_config(record, read) if read is not None else ConfigComparison(record["device"], "UNAVAILABLE", reason="NOT_READ"))
    return out


def recheck_configuration(candidate, *, session_factory=None, now: datetime | None = None) -> dict:
    """The decision-time re-read of every included device: -> {"result": MATCH|DRIFT|INCOMPLETE, "checked_at_dt", "baseline_digest", "devices": [...]}.
    Read-only, never raises, never mutates; what it sees is compared, never adopted."""
    now = now or utcnow()
    scope = managed_scope()
    wanted = {r["device"] for r in ((candidate.payload.get("baseline") or {}).get("devices") or [])}
    reads = read_all({n: scope[n] for n in sorted(wanted) if n in scope}, session_factory=session_factory, now=now)
    comparisons = compare_all(candidate, reads)
    if any(c.status == "DRIFT" for c in comparisons):
        result = "DRIFT"
    elif comparisons and all(c.status == "MATCH" for c in comparisons) and wanted <= set(scope):
        result = "MATCH"
    else:
        result = "INCOMPLETE"
    return {"result": result, "checked_at_dt": now, "baseline_digest": candidate.payload_digest, "devices": [c.to_dict() for c in comparisons]}
