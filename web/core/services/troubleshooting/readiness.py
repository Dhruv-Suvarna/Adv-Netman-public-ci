"""Operational readiness of the troubleshooting deployment: why each device is (not) admitted, and which runbooks can run live.

This is a read-only report over the SAME code path a troubleshooting run uses (``deployment.runtime_deps`` ->
``DeploymentAdmission.resolve``).  It never relaxes admission, never adopts or verifies a device, never invents a platform version
and never contacts a device, NetBox, the gateway or a credential store: it calls the configured inventory / lifecycle / version
providers (database and file reads only) and inspects which source bindings resolved.

``DeploymentAdmission`` stops at the FIRST refusal.  An operator fixing devices one gate at a time would otherwise discover the next
blocker only after fixing the previous one, so ``device_readiness`` also evaluates every gate independently and lists ALL blockers,
each with the exact corrective action.  The authoritative verdict (``admission``) is always the unmodified runtime answer.
"""

from __future__ import annotations

from typing import Any

from . import collectors as col
from . import deployment as dep
from . import normalization as nz

REPORT_VERSION = "ts-readiness/1"

# RuntimeDeps attribute -> NMAS_TS_DEPLOYMENT key that binds it
SOURCE_BINDINGS = {
    "cli_transport": "cli_transport_factory", "snmp_session": "snmp_session_factory", "syslog_lines": "syslog_source",
    "gnmi_getter": "gnmi_getter_factory", "dns_runner": "dns_runner_factory", "dns_context": "dns_context_provider",
    "probe_runner": "probe_runner_factory", "probe_context": "probe_context_provider", "stp_context": "stp_context_provider",
    "l2_context": "l2_context_provider", "acl_context": "acl_context_provider", "forwarding_context": "forwarding_context_provider",
    "flow_input": "flow_input", "fib_source": "fib_reader_factory", "qos_source": "qos_reader_factory", "phy_source": "phy_reader_factory",
    "proto_source": "proto_reader_factory", "phy_context": "phy_context_provider",
}

# What each runbook needs before it can produce LIVE evidence.  ``all`` must each be bound; ``any`` needs at least one of each group.
# Derived from the runtime's source use (runtime.DeviceCollector.collect) and docs/troubleshooting/runbooks/*.md.
RUNBOOK_REQUIREMENTS: dict[str, dict[str, Any]] = {
    "RB01": {"title": "Link flapping", "all": ["phy_reader_factory", "phy_context_provider"],
             "any": [["syslog_source", "snmp_session_factory", "gnmi_getter_factory"]],
             "fixture": "approved isolated link-flap fixture (no real topology link may be flapped)"},
    "RB02": {"title": "Reachability (HC01-HC28)", "all": ["cli_transport_factory", "probe_runner_factory", "probe_context_provider", "flow_input",
                                                          "fib_reader_factory", "forwarding_context_provider", "acl_context_provider",
                                                          "baseline_sources_provider"],
             "any": [],
             "fixture": "approved isolated multi-hop fault fixture"},
    "RB03": {"title": "Routing neighborship", "all": ["proto_reader_factory", "cli_transport_factory"], "any": [],
             "fixture": "approved isolated neighbor-mismatch fixture (no production adjacency may be broken)"},
    "RB04": {"title": "STP loops / TC", "all": ["stp_context_provider", "l2_context_provider", "cli_transport_factory"], "any": [],
             "fixture": "approved isolated L2 fixture (no loop injection into the production topology)"},
    "RB05": {"title": "DNS", "all": ["dns_runner_factory", "dns_context_provider"], "any": [],
             "fixture": "approved isolated resolver / zone fixture"},
    "RB06": {"title": "MTU / PMTUD", "all": ["probe_runner_factory", "probe_context_provider", "cli_transport_factory"], "any": [],
             "fixture": "approved isolated MTU-mismatch fixture"},
    "RB07": {"title": "Layer 1", "all": ["phy_reader_factory", "phy_context_provider"], "any": [],
             "fixture": "real optics/FEC hardware (virtual cEOS optics answer UNSUPPORTED_OPERATION)", "hardware": True},
}

# refusal code -> (owner, exact corrective action).  Nothing here is automatic: every action is an operator/review step.
ACTIONS = {
    "MISCONFIGURED": ("operator", "fix NMAS_TS_DEPLOYMENT (see deployment_problems); every device is refused until it loads"),
    "UNKNOWN": ("operator", "device is not in the authoritative inventory (inventory.yml / provisioning registry); troubleshooting cannot target it"),
    "UNSUPPORTED_PLATFORM": ("engineering", "no read-only collector exists for this platform"),
    "LIFECYCLE_PROVIDER_UNBOUND": ("operator", "set NMAS_TS_DEPLOYMENT['lifecycle_provider'] = "
                                               "'core.services.troubleshooting.adapters.nmas_providers.lifecycle' (settings change, reviewed deploy)"),
    "LIFECYCLE_UNKNOWN": ("operator", "the lifecycle provider gave no usable answer; check deployment_problems and the lifecycle registry"),
    "UNREGISTERED": ("operator", "adopt the device on the Devices page (Adopt Existing Device); adoption is a human action, never automatic"),
    "NOT_ADOPTABLE": ("operator", "device cannot be adopted (resolver.adoption_scope refused it); it stays out of troubleshooting scope"),
    "DECOMMISSIONED": ("none", "device is decommissioned/withdrawn; troubleshooting must not probe it"),
    "WITHDRAWN": ("none", "production admission withdrawn; troubleshooting must not probe it"),
    "NOT_ADMITTED": ("operator", "complete production admission through the existing lifecycle workflow"),
    "IDENTITY_UNVERIFIED": ("operator+engineering", "record an AUTHENTICATED_SESSION identity observation with the SSH host key, then "
                                                    "Verify Identity on the device's lifecycle page"),
    "IDENTITY_MISMATCH": ("operator", "investigate the identity mismatch; never override it to admit the device"),
    "IDENTITY_NO_PRODUCER": ("operator", "no AUTHENTICATED_SESSION identity observation exists for this device yet.  For an adopted "
                                         "device: enroll its host-key pin from device-side evidence (host_key_pin_check), have an NMAS "
                                         "Approver grant an ObservationAuthorization (observation_authorize grant), then a different "
                                         "executor runs the read-only pinned capture (device_observe).  Verify Identity is possible only "
                                         "after that observation is recorded"),
    "VERSION_PROVIDER_UNBOUND": ("operator", "set NMAS_TS_DEPLOYMENT['version_provider'] = "
                                             "'core.services.troubleshooting.adapters.nmas_providers.version' (reviewed settings deploy); it reads "
                                             "core.services.devices.observations.observed_version and fails closed"),
    "VERSION_UNKNOWN": ("operator+engineering", "no authoritative observed version for this device: capture it through the read-only "
                                                "authenticated-session observation workflow (observations.observed_version); inventory/image tags are not used"),
    "NO_MANAGEMENT_ADDRESS": ("operator", "inventory declares no usable management address; a transport cannot reach the device"),
}


def _blocker(code: str, detail: str = "") -> dict:
    owner, action = ACTIONS.get(code, ("operator", "see the lifecycle page"))
    return {"code": code, "owner": owner, "action": action, "detail": detail}


def _call(fn, *args):
    try:
        return fn(*args), ""
    except Exception as exc:  # pylint: disable=broad-exception-caught  # noqa: BLE001 - a failing provider is a blocker, not a crash
        return None, type(exc).__name__


def _config(config: dict | None) -> tuple[dict, str]:
    if config is not None:
        return dict(config), ""
    try:
        return dep._settings_config(), ""   # pylint: disable=protected-access  # same reader the runtime factory uses
    except Exception as exc:  # pylint: disable=broad-exception-caught  # noqa: BLE001
        return {}, type(exc).__name__


def _resolved(cfg: dict, key: str):
    try:
        return dep._resolve(cfg.get(key)), ""   # pylint: disable=protected-access
    except Exception as exc:  # pylint: disable=broad-exception-caught  # noqa: BLE001
        return None, type(exc).__name__


def _identity_producer_exists(device: str) -> bool | None:
    """True when the device has at least one OBSERVED, AUTHENTICATED_SESSION identity observation (Verify Identity is then possible)."""
    from core import models
    try:
        return models.DeviceObservation.objects.filter(
            device__name=device, kind=models.ObservationKind.IDENTITY, source=models.ObservationSource.AUTHENTICATED_SESSION,
            trust=models.ObservationTrust.OBSERVED).exclude(result=models.ObservationResult.MISMATCH).exists()
    except Exception:  # pylint: disable=broad-exception-caught  # noqa: BLE001
        return None


def _adoptable(device: str) -> tuple[bool | None, str]:
    from core.services.devices import resolver
    answer, err = _call(resolver.adoption_scope, device)
    if err:
        return None, err
    _target, code = answer
    return not code, code


def _sources(deps) -> dict[str, bool]:
    return {key: getattr(deps, attr, None) is not None for attr, key in SOURCE_BINDINGS.items()}


def device_readiness(config: dict | None = None, devices: list[str] | None = None) -> dict:
    """Per-device readiness.  ``config`` defaults to ``settings.NMAS_TS_DEPLOYMENT``.  Read-only."""
    cfg, cfg_error = _config(config)
    deps = dep.runtime_deps(None if config is None else cfg)     # the exact factory a run uses (re-reads settings when config is None)
    problems = list(getattr(deps, "deployment_problems", []) or [])
    if cfg_error:
        problems.append(f"config: {cfg_error}")
    inventory_fn, inv_err = _resolved(cfg, "inventory")
    lifecycle_fn, life_err = _resolved(cfg, "lifecycle_provider")
    version_fn, ver_err = _resolved(cfg, "version_provider")
    if inventory_fn is None and not inv_err:
        from core.services.health import inventory as health_inventory   # the runtime's own default
        inventory_fn = health_inventory.managed_devices
    known, known_err = _call(inventory_fn) if inventory_fn else ({}, inv_err)
    known = known if isinstance(known, dict) else {}
    names = list(devices) if devices is not None else sorted(known)
    verdicts = deps.admission.resolve(names)
    sources = _sources(deps)
    rows = []
    for name in names:
        verdict = verdicts[name]
        entry = dict(known.get(name) or {})
        platform = nz.canonical_platform(entry.get("platform") or "")
        blockers: list[dict] = []
        if cfg_error or any(p.startswith(("config", "inventory", "version_provider", "lifecycle_provider")) for p in problems):
            blockers.append(_blocker("MISCONFIGURED", "; ".join(problems)))
        if name not in known:
            blockers.append(_blocker("UNKNOWN", known_err))
        elif platform not in dep.KNOWN_PLATFORMS:
            blockers.append(_blocker("UNSUPPORTED_PLATFORM", platform))
        warnings: list[dict] = []
        if name in known and not str(entry.get("address") or entry.get("host") or "").strip():
            warnings.append(_blocker("NO_MANAGEMENT_ADDRESS", "inventory address is empty or 'auto' (refused by the resolver)"))
        life: dict | None = None
        if lifecycle_fn is None:
            blockers.append(_blocker("LIFECYCLE_PROVIDER_UNBOUND", life_err))
        else:
            life, err = _call(lifecycle_fn, name)
            state = str((life or {}).get("state") or "").upper() if isinstance(life, dict) else ""
            if err or not isinstance(life, dict):
                blockers.append(_blocker("LIFECYCLE_UNKNOWN", err))
            elif life.get("withdrawn"):
                blockers.append(_blocker("DECOMMISSIONED" if state == "DECOMMISSIONED" else "WITHDRAWN"))
            elif state == "UNREGISTERED":
                adoptable, why = _adoptable(name)
                blockers.append(_blocker("UNREGISTERED") if adoptable else _blocker("NOT_ADOPTABLE", why))
            elif state.startswith("IDENTITY_"):
                code = "IDENTITY_MISMATCH" if state == "IDENTITY_MISMATCH" else "IDENTITY_UNVERIFIED"
                blockers.append(_blocker(code, str(life.get("detail") or "")))
                if code == "IDENTITY_UNVERIFIED" and _identity_producer_exists(name) is False:
                    blockers.append(_blocker("IDENTITY_NO_PRODUCER"))
            elif state not in col.ADMITTED_STATES:
                blockers.append(_blocker("NOT_ADMITTED" if state == "NOT_ADMITTED" else "LIFECYCLE_UNKNOWN", state))
        version = ""
        if version_fn is None:
            blockers.append(_blocker("VERSION_PROVIDER_UNBOUND", ver_err))
        elif name in known:
            raw, err = _call(version_fn, name, entry)
            version = str(raw or "").strip()
            if err or not nz.parse_version(version):
                blockers.append(_blocker("VERSION_UNKNOWN", err))
        rows.append({
            "device": name, "platform": platform or "", "admission": verdict.state, "admission_reason": verdict.reason,
            "admitted": verdict.state == "VERIFIED", "os_version": verdict.os_version or "",
            "identity_state": (life or {}).get("identity_state", "") if isinstance(life, dict) else "",
            "lifecycle_state": (life or {}).get("lifecycle_state", "") if isinstance(life, dict) else "",
            "production_admission": (life or {}).get("admission_state", "") if isinstance(life, dict) else "",
            "maintenance": bool((life or {}).get("maintenance")) if isinstance(life, dict) else False,
            "telemetry_sources": sorted(k for k, bound in sources.items() if bound),
            "blockers": blockers, "warnings": warnings,
        })
    # consistency: the runtime verdict is VERIFIED exactly when no independent gate found a blocker
    for row in rows:
        row["consistent"] = row["admitted"] == (not row["blockers"])
    return {"version": REPORT_VERSION, "deployment_problems": problems, "sources": sources, "devices": rows}


def runbook_readiness(report: dict) -> list[dict]:
    """Per-runbook readiness from a ``device_readiness`` report.  Live readiness needs every binding, an admitted device and the fixture."""
    bound = {k for k, v in report["sources"].items() if v}
    admitted = [r["device"] for r in report["devices"] if r["admitted"]]
    out = []
    for rb, req in RUNBOOK_REQUIREMENTS.items():
        missing = [k for k in req["all"] if k not in bound]
        missing += ["one of " + "/".join(group) for group in req["any"] if not set(group) & bound]
        if req.get("hardware"):
            status = "EXTERNALLY_BLOCKED_HARDWARE"
        elif missing or not admitted:
            status = "NOT_READY"
        else:
            status = "READY_PENDING_FIXTURE_APPROVAL"
        out.append({"runbook": rb, "title": req["title"], "status": status, "missing_bindings": missing,
                    "admitted_devices": admitted, "fixture": req["fixture"]})
    return out


def render_text(report: dict, runbooks: list[dict]) -> str:
    lines = [f"troubleshooting readiness ({report['version']})", ""]
    if report["deployment_problems"]:
        lines.append("deployment problems: " + "; ".join(report["deployment_problems"]))
    lines.append("bound sources: " + (", ".join(sorted(k for k, v in report["sources"].items() if v)) or "none"))
    lines.append("")
    lines.append(f"{'device':<10} {'platform':<8} {'admission':<22} blockers")
    for row in report["devices"]:
        codes = ", ".join(b["code"] for b in row["blockers"] + row["warnings"]) or "-"
        lines.append(f"{row['device']:<10} {row['platform']:<8} {row['admission']:<22} {codes}")
    lines.append("")
    for rb in runbooks:
        lines.append(f"{rb['runbook']} {rb['status']:<32} missing: {', '.join(rb['missing_bindings']) or '-'}")
    lines.append("")
    seen: dict[str, dict] = {}
    for row in report["devices"]:
        for b in row["blockers"] + row["warnings"]:
            seen.setdefault(b["code"], b)
    for code, b in seen.items():
        lines.append(f"[{code}] ({b['owner']}) {b['action']}")
    return "\n".join(lines)
