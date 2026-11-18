"""Per-device troubleshooting qualification matrix (read-only, database + tracked-file reads only).

Answers, for every device NAME discoverable in the tracked sources (``inventory.yml`` network devices + hosts, the tracked Containerlab
topology, the lifecycle registry and the provisioning registry): what kind of thing it is (managed device / excluded edge / host /
external peer / registry-only), which admission gates are met and which are not, which management path would be used (approved
failover order only; the Containerlab management plane is NEVER a production path), which read-only collector commands the
platform/version qualifies for, and what evidence is missing.

Rules (all fail closed):
* Nothing here contacts a device, the gateway, NetBox or a credential store; it grants/approves nothing.
* The OS version comes ONLY from the authoritative observed-version provider; the topology image tag is shown as *declared baseline*
  and is never promoted to an observed version.
* Operational state (reachability, live version) is ``UNKNOWN`` unless an authoritative record says otherwise.
* Evidence classes are kept apart: ``local_test`` / ``fixture`` / ``production`` -- this module only ever reports what a record claims.
"""

from __future__ import annotations

from typing import Any

from . import collectors as col
from . import normalization as nz

MATRIX_VERSION = "ts-qualification/1"

# Approved baseline (AGENTS.md "Frozen Lab 1 Baseline"): cEOS 4.36.2F, Ubuntu 24.04 + FRRouting 8.4.4.  Declared, not observed.
BASELINES = {"ceos": {"nos": "Arista cEOS", "version": "4.36.2F"}, "linux": {"nos": "Ubuntu 24.04 + FRRouting", "version": "8.4.4"},
             "iosxe": {"nos": "Catalyst 8000V IOS XE", "version": "17.06.01a"}}
# The configured production admission takes at most these management path classes, in this order (models.MANAGEMENT_PATH_CLASS).
APPROVED_FAILOVER_ORDER = ("DIRECT_OOB", "VLAN_ADJACENT_SWITCH", "ROUTED_VRF")
PROHIBITED_PRODUCTION_PATHS = ("CONTAINERLAB_MANAGEMENT", "DOCKER_EXEC_LAB_RUNTIME", "AUTO_ADDRESS")

MANAGED, EXCLUDED, HOST, PEER, REGISTRY_ONLY = "MANAGED", "EXCLUDED", "HOST", "EXTERNAL_PEER", "REGISTRY_ONLY"
TOPOLOGY_ROLES = {"arista_ceos": "ceos", "linux": "linux"}


def _safe(fn, *args, default=None):
    try:
        return fn(*args), ""
    except Exception as exc:  # pylint: disable=broad-exception-caught  # noqa: BLE001 - unknown stays unknown; only the class name is kept
        return default, type(exc).__name__


def collector_qualification(platform: str, os_version: str) -> dict:
    """What the existing catalogue allows for this platform/version.  ``parsed`` commands have a normalizer valid for the version;
    ``evidence_only`` commands are retained raw.  An unknown version qualifies nothing (the catalogue's own gate is bypassed when the
    version is empty, so it is refused here instead)."""
    plat = nz.canonical_platform(platform or "")
    base = BASELINES.get(plat)
    parsed = nz.parse_version(os_version)
    if plat not in col.COMMAND_CATALOG:
        return {"platform": plat, "status": "UNSUPPORTED_PLATFORM", "baseline": None, "read_only_commands": [], "limits": ["no collector"]}
    if not parsed:
        return {"platform": plat, "status": "VERSION_UNKNOWN", "baseline": base, "read_only_commands": [],
                "limits": ["no authoritative observed version: no collector command is qualified"]}
    specs = col.commands_for(plat, os_version, include_config=False)
    limits = []
    if parsed != nz.parse_version(base["version"]):
        limits.append(f"observed version differs from the approved baseline {base['version']}: only baseline-qualified parsers are proven")
    if plat == "ceos" and not ((4, 28) <= parsed[:2] < (5, 0)):
        limits.append("eos-json-1.0 parsers are version-gated to EOS 4.28 <= v < 5.0; outside it output is evidence-only")
    if plat == "linux":
        limits.append("Linux/FRR commands are fixed argv tuples (no shell); kernel route tables are a RIB view, not a validated FIB")
    limits.append("running-config snapshot commands are excluded from default qualification (config domain needs explicit approval)")
    return {"platform": plat, "status": "BASELINE" if not any("differs" in x for x in limits) else "NON_BASELINE", "baseline": base,
            "read_only_commands": [{"key": s.key, "command": s.command if isinstance(s.command, str) else " ".join(s.command),
                                    "parsed": bool(s.parser_id), "domains": list(s.domains)} for s in specs],
            "limits": limits}


def _topology(document: dict) -> dict:
    from core.services.devices import resolver
    nodes = (resolver._tracked_topology(document).get("topology") or {}).get("nodes") or {}   # pylint: disable=protected-access
    return {n: {"kind": (v or {}).get("kind", ""), "image": (v or {}).get("image", "")} for n, v in nodes.items()}


def management_paths(device: str) -> dict:
    """Registered management paths in approved failover order (class 1 > 2 > 3; within class 2 by adjacent-switch identity).
    Only APPROVED paths are candidates; the Containerlab management plane is not a path type and can never appear here."""
    from core import models
    from core.services.management import paths
    row = models.ManagedDevice.objects.exclude(lifecycle_state__in=tuple(models.DEVICE_LIFECYCLE_TERMINAL)).filter(name=device).order_by("-pk").first()
    if row is None:
        return {"registered": None, "approved_order": [], "source": "management-registry", "note": "no lifecycle registration"}
    live = paths.live_paths(row)
    return {"registered": len(live), "source": "management-registry",
            "approved_order": [{"path_id": p.path_id, "type": p.path_type, "class": p.preference_class, "via": p.via_device,
                                "health": p.health_state, "active": bool(p.is_active)} for p in live if p.approval_state == "APPROVED"],
            "unapproved": len(live) - len([p for p in live if p.approval_state == "APPROVED"]),
            "note": "" if live else "no registered paths: legacy inventory VLAN200 address is the only declared route"}


def device_matrix(config: dict | None = None) -> dict:
    """The full device-by-device matrix.  ``config`` defaults to ``settings.NMAS_TS_DEPLOYMENT``."""
    from core.services.devices import resolver
    from core.services.health import inventory as health_inventory
    from . import readiness

    document = health_inventory.load_inventory()
    resolution, res_err = _safe(resolver.resolve_all, default=None)
    targets = resolution.targets if resolution else {}
    topo, topo_err = _safe(_topology, document, default={})
    report = readiness.device_readiness(config, sorted(set(document.get("network_devices") or {}) | {n for n, t in targets.items()}))
    rows_by_name = {r["device"]: r for r in report["devices"]}
    version_fn, _ = readiness._resolved(report_cfg(config), "version_provider")   # pylint: disable=protected-access
    out = []
    names = set(document.get("network_devices") or {}) | set(document.get("hosts") or {}) | set(topo) | set(targets)
    for name in sorted(names):
        tgt, rd = targets.get(name), rows_by_name.get(name)
        node = topo.get(name, {})
        in_net = name in (document.get("network_devices") or {})
        platform = (rd or {}).get("platform") or TOPOLOGY_ROLES.get(node.get("kind", ""), "")
        if in_net and tgt is not None and tgt.scope == resolver.Scope.READ_ONLY:
            kind, why = EXCLUDED, "inventory edge/read-only scope (no dedicated machine identity; no management-VLAN address): never admitted, never written"
        elif in_net:
            kind, why = MANAGED, "inventory network_devices with a dedicated credential reference and a declared management address"
        elif tgt is not None:
            kind, why = REGISTRY_ONLY, f"{tgt.authority}; scope {tgt.scope}"
        elif name in (document.get("hosts") or {}) or node:
            kind, why = HOST, "end host / application node: outside NMAS network-device management scope"
        else:
            kind, why = PEER, ""
        observed, obs_err = (None, "")
        if version_fn is not None and kind == MANAGED:
            observed, obs_err = _safe(version_fn, name, dict((tgt.engine_entry or {}) if tgt else {}))
        observed = str(observed or "").strip()
        row: dict[str, Any] = {
            "device": name, "classification": kind, "reason": why, "platform": platform,
            "topology": node or None, "declared_baseline": BASELINES.get(platform, {}).get("version"),
            "observed_version": observed or None,
            "observed_version_error": obs_err, "operational_state": "UNKNOWN",
            "management": {"declared_candidates": [c.as_dict() for c in tgt.management_candidates] if tgt else [],
                           "paths": _safe(management_paths, name, default=None)[0],
                           "production_failover_order": list(APPROVED_FAILOVER_ORDER), "prohibited": list(PROHIBITED_PRODUCTION_PATHS)},
            "credential_refs": sorted((tgt.credential_refs if tgt else {}).keys()),
            "admission": None, "gates": [], "collector": None, "missing_evidence": [],
        }
        if rd is not None and kind == MANAGED:
            row["admission"] = {"state": rd["admission"], "reason": rd["admission_reason"], "admitted": rd["admitted"],
                                "lifecycle": rd["lifecycle_state"], "identity": rd["identity_state"], "production": rd["production_admission"]}
            row["gates"] = [{"code": b["code"], "owner": b["owner"], "action": b["action"], "detail": b["detail"]} for b in rd["blockers"]]
            row["collector"] = collector_qualification(platform, observed)
        elif kind in (MANAGED,):
            row["gates"] = [{"code": "NOT_EVALUATED", "owner": "operator", "action": "readiness did not evaluate this device", "detail": ""}]
        row["missing_evidence"] = _missing(row, kind)
        out.append(row)
    return {"version": MATRIX_VERSION, "topology_error": topo_err, "resolver_error": res_err, "deployment_problems": report["deployment_problems"],
            "counts": {k: sum(1 for r in out if r["classification"] == k) for k in (MANAGED, EXCLUDED, HOST, PEER, REGISTRY_ONLY)},
            "external_peers_note": "no external-peer node is declared in the tracked topology or inventory; none is invented",
            "devices": out}


def report_cfg(config):
    from . import readiness
    return readiness._config(config)[0]   # pylint: disable=protected-access


def _missing(row: dict, kind: str) -> list[str]:
    miss = []
    if kind == MANAGED:
        if not row["observed_version"]:
            miss.append("authoritative observed OS version (core.services.devices.observations.observed_version)")
        if not (row["admission"] or {}).get("admitted"):
            miss.append("production admission (gateway/lifecycle approval) -- not granted by this report")
        miss.append("live reachability / device identity evidence from a gateway-recorded session (operational state is UNKNOWN)")
    elif kind == EXCLUDED:
        miss.append("none requested: exclusion is preserved (no admission path exists)")
    return miss
