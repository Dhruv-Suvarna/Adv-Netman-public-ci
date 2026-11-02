"""Network-device configuration validation (Version 2 Phase 2).

This module validates candidate, removal, running, and post-write device configuration.  It deliberately reuses the
canonical intent snapshot, Phase-13 semantic validators, platform renderers, import parsers, and Phase-15 live
postchecks while persisting its own append-only evidence.  It is not Tier-3 (which validates NMAS source code).
"""

from __future__ import annotations

import hashlib
import ipaddress
import re

from django.db import transaction

from .. import models
from . import candidate_renderer
from .capabilities import evidence as capability_evidence
from .capabilities.axes import Axis, EvidenceStatus
from .capabilities.features import by_key
from .config_import import parser_ceos, parser_frr, parser_iosxe, parser_iosxr, parser_sonic, parser_srlinux
from .validation import engine, snapshot as snapshot_module, sources as sources_module
from .validation.findings import Category, sanitize

ENGINE_VERSION = "2.0.0"
MAX_HISTORY = 25

_UNSUPPORTED_MARKERS = ("not implemented yet", "<process-id-required>", "<interface-required>", "<area-required>")
_CONFLICT_CODES = frozenset({
    "IP_DUPLICATE", "IP_NETBOX_COLLISION", "IP_DHCP_POOL_CONFLICT", "IP_RESERVATION_CONFLICT",
    "LINK_PREFIX_MISMATCH", "ROUTE_FAMILY_MISMATCH", "ROUTE_NEXT_HOP_SELF", "BGP_REMOTE_AS_MISMATCH",
})
_NETBOX_CODES = frozenset({
    "IP_NETBOX_COLLISION", "IP_DHCP_POOL_CONFLICT", "IP_RESERVATION_CONFLICT", "AUTO_IP_UNRESOLVED",
    "AUTO_IP_NO_AVAILABLE_ADDRESS", "VLAN_NOT_IN_NETBOX", "SOURCE_NETBOX_UNAVAILABLE",
})
_VLAN200_CODES = frozenset({"DHCP_VLAN200_FORBIDDEN"})


def _check(name: str, status: str, message: str, *, evidence=None) -> dict:
    # Sanitize each payload exactly once. Re-sanitizing an already-bounded nested document consumes depth and can erase
    # useful evidence as "[TRUNCATED]" even though no additional safety is gained.
    return {"check": sanitize(name), "status": sanitize(status), "message": sanitize(message),
            "evidence": sanitize(evidence or {})}


def _status(checks: list[dict], *, live: bool = False) -> str:
    if any(row["status"] in ("BLOCKED", "FAIL") for row in checks):
        return models.NetworkConfigValidationStatus.FAIL if live else models.NetworkConfigValidationStatus.BLOCKED
    if any(row["status"] == "WARNING" for row in checks):
        return models.NetworkConfigValidationStatus.WARNING
    return models.NetworkConfigValidationStatus.PASS


def _persist(*, operation_type: str, status: str, input_hash: str, actor: str, checks: list[dict], change=None,
             revision=None, snapshot=None, execution_run=None, operational_run=None, device="", platform="",
             source_hash="", syntax=None, semantic=None, live=None, provenance=None):
    warnings = [row for row in checks if row["status"] == "WARNING"]
    errors = [row for row in checks if row["status"] in ("BLOCKED", "FAIL")]
    netbox = [row for row in checks if row["check"].startswith("NETBOX_")]
    with transaction.atomic():
        run = models.NetworkConfigValidationRun.objects.create(
            operation_type=operation_type, status=status, change=change, revision=revision, snapshot=snapshot,
            execution_run=execution_run, operational_run=operational_run, device=device[:64], platform=platform[:32],
            engine_version=ENGINE_VERSION, input_hash=input_hash, source_hash=source_hash, checks=checks,
            warnings=warnings, errors=errors, netbox_observations=netbox, syntax_result=sanitize(syntax or {}),
            semantic_result=sanitize(semantic or {}), live_result=sanitize(live or {}),
            provenance=sanitize(provenance or {}), created_by=actor[:150],
        )
        models.AuditEvent.objects.create(
            event_type=models.AuditEventType.NETWORK_CONFIG_VALIDATED, change=change,
            object_type="NetworkConfigValidationRun", object_id=str(run.run_id), actor=actor[:150],
            summary=f"Network config {operation_type} {status}: {(change.change_id if change else device)}"[:255],
            metadata={"run_id": str(run.run_id), "operation_type": operation_type, "status": status,
                      "warnings": len(warnings), "errors": len(errors), "device": device[:64]},
        )
    return run


def _candidate_syntax(change) -> tuple[list[dict], dict]:
    checks, devices = [], []
    for intent in change.device_intents.order_by("device_name"):
        revision = intent.latest_revision()
        if revision is None:
            checks.append(_check("SYNTAX_PARSE", "BLOCKED", f"{intent.device_name} has no candidate revision."))
            continue
        try:
            rendered = candidate_renderer.render(intent, revision)
            text = rendered["text"]
            markers = [marker for marker in _UNSUPPORTED_MARKERS if marker in text.lower()]
            conflicts = rendered.get("composition_conflicts") or []
            if markers or conflicts:
                checks.append(_check("SYNTAX_PLATFORM", "BLOCKED", f"{intent.device_name} cannot be rendered safely.",
                                     evidence={"markers": markers, "composition_conflicts": len(conflicts)}))
            else:
                checks.append(_check("SYNTAX_PLATFORM", "PASS", f"{intent.device_name} rendered for {intent.platform}."))
            devices.append({"device": intent.device_name, "platform": intent.platform, "revision": revision.revision,
                            "render_digest": hashlib.sha256(text.encode()).hexdigest()})
        except Exception as exc:  # a renderer defect can never authorize a write
            checks.append(_check("SYNTAX_PLATFORM", "BLOCKED", f"{intent.device_name} rendering failed.",
                                 evidence={"error_type": exc.__class__.__name__}))
    return checks, {"devices": devices}


def _semantic_checks(report: dict) -> list[dict]:
    findings = report.get("findings") or []
    checks = []
    groups = (
        ("IP_VALIDITY", lambda f: f.get("code") in {"ADDRESS_INVALID", "ADDRESS_FAMILY_MISMATCH"}),
        ("ADDRESS_CONFLICTS", lambda f: f.get("code") in _CONFLICT_CODES),
        ("NETBOX_IPAM", lambda f: f.get("code") in _NETBOX_CODES),
        ("VLAN200_PROTECTION", lambda f: f.get("code") in _VLAN200_CODES),
        ("PLATFORM_CAPABILITY", lambda f: f.get("category") == Category.PLATFORM),
        ("ROUTING_CONFLICTS", lambda f: f.get("category") == Category.ROUTING),
        ("INTERFACE_DEPENDENCIES", lambda f: f.get("category") in (Category.INTERFACE, Category.DEPENDENCY)),
        ("REMOVAL_SAFETY", lambda f: f.get("category") == Category.REMOVAL),
    )
    for name, predicate in groups:
        rows = [f for f in findings if predicate(f)]
        if any(f.get("blocking") or f.get("incomplete") for f in rows):
            status = "BLOCKED"
        elif any(f.get("severity") == "WARNING" for f in rows):
            status = "WARNING"
        else:
            status = "PASS"
        checks.append(_check(name, status, f"{len(rows)} relevant finding(s).",
                             evidence={"codes": sorted({f.get('code') for f in rows})}))
    return checks


def _managed_scope_checks(snapshot: dict, bundle, change=None) -> list[dict]:
    if not bundle.netbox.available:
        # fail closed: with NetBox unavailable no target can be proven managed (the import path's rule as well)
        return [_check("MANAGED_SCOPE", "BLOCKED", "Authoritative managed scope is unavailable.")]
    managed = (bundle.netbox.data or {}).get("managed_devices")
    if managed is None:  # backward-compatible injected/test bundles; live source always supplies this field in Phase 2
        return [_check("MANAGED_SCOPE", "WARNING", "Authoritative managed-device membership was not included in the source.")]
    requested = sorted(d["device_name"] for d in snapshot.get("devices") or [])
    # V2 Phase 5A: a device admitted by THIS Change's provisioning request is reserved in NetBox (``planned``) and joins the managed
    # scope only after NSOT sync.  It is in scope for its own provisioning Change and for no other.
    from .provisioning import registry as provisioning_registry

    provisioning = sorted(name for name in requested if name not in managed and provisioning_registry.admitted_for(name, change))
    # A natively provisioned device that NMAS admitted and synchronized to NetBox (``registry.active_managed``) is in scope for
    # ordinary Changes that target it as an EXISTING device.  The Configuration Validation bundle carries this list as
    # ``scope.nmas_active``; its CI check accepts it only for EXISTING_DEVICE intents of a PASS scope.
    existing = {d["device_name"] for d in snapshot.get("devices") or [] if d.get("target_type") == "EXISTING_DEVICE"}
    active = sorted(name for name in requested if name not in managed and name not in provisioning and name in existing
                    and provisioning_registry.active_managed(name))
    outside = sorted(set(requested) - set(managed) - set(provisioning) - set(active))
    if outside:
        message = "Targets are outside the authoritative managed scope."
    elif provisioning:
        message = "All targets are managed or admitted by this Change's provisioning request."
    elif active:
        message = "All targets are managed or admitted to production by NMAS."
    else:
        message = "All targets are managed."
    return [_check("MANAGED_SCOPE", "BLOCKED" if outside else "PASS", message,
                   evidence={"outside_scope": outside, **({"provisioning": provisioning} if provisioning else {}),
                             **({"nmas_active": active} if active else {})})]


def _ospf_network_checks(snapshot: dict) -> list[dict]:
    problems, seen = [], {}
    for device in snapshot.get("devices") or []:
        for instance in ((device.get("routing") or {}).get("ospf") or {}).values():
            for network in (instance.get("networks") or {}).values():
                prefix, area = str(network.get("prefix") or ""), str(network.get("area") or "")
                try:
                    parsed = ipaddress.ip_network(prefix, strict=True)
                    if parsed.version != 4:
                        raise ValueError
                except ValueError:
                    problems.append({"device": device["device_name"], "prefix": prefix, "reason": "INVALID_IPV4_PREFIX"})
                    continue
                try:
                    area_value = int(area) if area.isdigit() else int(ipaddress.IPv4Address(area))
                    if not 0 <= area_value <= 0xFFFFFFFF:
                        raise ValueError
                except ValueError:
                    problems.append({"device": device["device_name"], "prefix": prefix, "area": area, "reason": "INVALID_AREA"})
                if instance.get("version") != "OSPFV2":
                    problems.append({"device": device["device_name"], "prefix": prefix, "reason": "OSPFV2_ONLY"})
                key = (device["device_name"], str(parsed))
                if key in seen:
                    problems.append({"device": key[0], "prefix": key[1], "reason": "DUPLICATE_NETWORK_STATEMENT",
                                     "areas": sorted({seen[key], area})})
                seen[key] = area
    return [_check(
        "OSPF_NETWORK_STATEMENTS", "BLOCKED" if problems else "PASS",
        "OSPF network statements contain invalid or conflicting values." if problems else "OSPF network statements are valid.",
        evidence={"problems": problems},
    )]


def validate_candidate(change, *, actor: str = "", sources=None):
    """Validate accepted candidate/removal config and append evidence.  Does not run Tier-2 or plan anything."""
    snapshot = snapshot_module.build_change_snapshot(change)
    bundle = sources or sources_module.build_source_bundle()
    semantic = engine.run_validation(snapshot, bundle)
    checks, syntax = _candidate_syntax(change)
    checks.extend(_managed_scope_checks(snapshot, bundle, change))
    checks.extend(_ospf_network_checks(snapshot))
    checks.extend(_semantic_checks(semantic))

    # Manual addresses outside every modeled NetBox prefix are warnings, while actual allocations already block in
    # the shared semantic engine.  No NetBox write is attempted.
    prefixes = []
    if bundle.netbox.available:
        for row in bundle.netbox.data.get("prefixes") or []:
            try:
                prefixes.append(ipaddress.ip_network(row["prefix"], strict=False))
            except (KeyError, ValueError):
                continue
    unmodeled = []
    for device in snapshot.get("devices") or []:
        for interface in (device.get("interfaces") or {}).values():
            for address in (interface.get("addresses") or {}).values():
                cidr = address.get("cidr")
                if address.get("source") != "AUTO" and cidr:
                    try:
                        ip = ipaddress.ip_interface(cidr).ip
                    except ValueError:
                        continue
                    if not prefixes or not any(ip in prefix for prefix in prefixes):
                        unmodeled.append({"device": device["device_name"], "interface": interface.get("name"), "address": cidr})
    checks.append(_check("NETBOX_PREFIX_RELATIONSHIP", "WARNING" if unmodeled else "PASS",
                         "Valid address is outside expected NetBox pools; allocation was not created." if unmodeled
                         else "Candidate addresses relate to modeled NetBox prefixes.", evidence={"unmodeled": unmodeled}))

    operation = (models.NetworkConfigValidationOperation.REMOVAL_PRECHECK
                 if snapshot.get("config_removals") else models.NetworkConfigValidationOperation.CANDIDATE)
    status = _status(checks)
    revision = change.device_intents.first().latest_revision() if change.device_intents.count() == 1 else None
    platform = change.device_intents.first().platform if change.device_intents.count() == 1 else ""
    device = change.device_intents.first().device_name if change.device_intents.count() == 1 else ""
    if snapshot.get("config_removals") and len(snapshot["config_removals"]["items"]) == 1:
        item = snapshot["config_removals"]["items"][0]
        device, platform = item["device"], item["platform"]
    run = _persist(
        operation_type=operation, status=status, input_hash=snapshot_module.hash_snapshot(snapshot), actor=actor,
        checks=checks, change=change, revision=revision, device=device, platform=platform,
        source_hash=bundle.source_hash(), syntax=syntax,
        semantic={"status": semantic.get("status"), "summary": semantic.get("summary"),
                  "finding_codes": [f.get("code") for f in semantic.get("findings") or []]},
        provenance={**bundle.provenance(), "intent_revision_map": snapshot_module.revision_map(change)},
    )
    _record_candidate_capabilities(snapshot, run, actor)
    return run


def _record_candidate_capabilities(snapshot: dict, run, actor: str) -> None:
    """Feed only features actually present in this candidate into the Phase-1 evidence store."""
    feature_keys: set[tuple[str, str]] = set()
    known = by_key()
    for device in snapshot.get("devices") or []:
        platform = device.get("platform") or ""
        for interface in (device.get("interfaces") or {}).values():
            feature_keys.add((platform, f"interface.{interface.get('kind')}"))
        routing = device.get("routing") or {}
        for route in (routing.get("static_routes") or {}).values():
            feature_keys.add((platform, "routing.STATIC_IPV6" if route.get("family") == "IPV6" else "routing.STATIC_IPV4"))
        for family, instances in routing.items():
            if family == "static_routes" or not isinstance(instances, dict):
                continue
            for instance in instances.values():
                code = instance.get("version") or instance.get("address_family") or family.upper()
                feature_keys.add((platform, f"routing.{code}"))
    evidence_status = (EvidenceStatus.VERIFIED if run.status in (
        models.NetworkConfigValidationStatus.PASS, models.NetworkConfigValidationStatus.WARNING
    ) else EvidenceStatus.FAILED)
    for platform, feature in sorted(feature_keys):
        if platform not in models.Platform.values or feature not in known:
            continue
        capability_evidence.record_evidence(
            platform=platform, feature=feature, axis=Axis.CONFIG_VALIDATION.value,
            status=evidence_status.value, source="network-config-validation",
            detail=f"Candidate validation {run.status}", evidence_ref=str(run.run_id), recorded_by=actor,
        )


def get_latest(change, *, operations=None):
    query = change.network_config_validation_runs.order_by("-created_at", "-id")
    if operations:
        query = query.filter(operation_type__in=operations)
    return query.first()


def get_currency(change, *, sources=None, check_sources: bool = False) -> dict:
    latest = get_latest(change, operations=(models.NetworkConfigValidationOperation.CANDIDATE,
                                            models.NetworkConfigValidationOperation.REMOVAL_PRECHECK))
    current = snapshot_module.hash_snapshot(snapshot_module.build_change_snapshot(change))
    if latest is None:
        return {"state": "NEVER_RUN", "latest": None, "reasons": [], "current_input_hash": current}
    reasons = []
    if latest.input_hash != current:
        reasons.append("ACCEPTED_INTENT_CHANGED")
    if sources is not None or check_sources:
        bundle = sources or sources_module.build_source_bundle()
        if latest.source_hash != bundle.source_hash():
            reasons.append("SOURCE_CHANGED_OR_UNAVAILABLE")
        if latest.engine_version != ENGINE_VERSION:
            reasons.append("ENGINE_VERSION_CHANGED")
    return {"state": "STALE" if reasons else "CURRENT", "latest": latest, "reasons": reasons,
            "current_input_hash": current}


def _running_checks(snapshot, sources) -> tuple[list[dict], dict]:
    text, platform = snapshot.text, snapshot.platform
    checks = []
    try:
        parser = {
            models.Platform.ARISTA_CEOS: parser_ceos.parse,
            models.Platform.UBUNTU_FRR: parser_frr.parse,
            models.Platform.NOKIA_SRLINUX: parser_srlinux.parse,
            models.Platform.CISCO_C8000V_IOSXE: parser_iosxe.parse,
            models.Platform.CISCO_IOSXR: parser_iosxr.parse,
            models.Platform.SONIC: parser_sonic.parse,
        }.get(platform)
        if parser is None:
            raise ValueError("unsupported platform parser")
        parsed = parser(text)
        checks.append(_check("SYNTAX_PARSE", "PASS", f"Configuration parsed with {parsed.parser_version}."))
    except Exception as exc:
        parsed = None
        checks.append(_check("SYNTAX_PARSE", "BLOCKED", "Running configuration could not be parsed.",
                             evidence={"error_type": exc.__class__.__name__}))
    seen, duplicates, invalid = {}, [], []
    addresses = []
    for match in re.finditer(r"(?mi)^\s*(?:ip|ipv6) address\s+(\S+)", text):
        raw = match.group(1)
        try:
            iface = ipaddress.ip_interface(raw)
            addresses.append(str(iface))
            if str(iface.ip) in seen:
                duplicates.append(str(iface.ip))
            seen[str(iface.ip)] = True
        except ValueError:
            invalid.append(raw[:80])
    checks.append(_check("IP_VALIDITY", "BLOCKED" if invalid else "PASS", f"{len(addresses)} address(es) parsed.",
                         evidence={"invalid": invalid}))
    checks.append(_check("ADDRESS_CONFLICTS", "BLOCKED" if duplicates else "PASS",
                         "Duplicate address assignments found." if duplicates else "No internal duplicate addresses found.",
                         evidence={"duplicates": sorted(set(duplicates))}))
    vlan200_dynamic = bool(re.search(r"(?ims)^interface\s+vlan200\b.*?^\s*(?:ip address dhcp|ipv6 address dhcp)", text))
    checks.append(_check("VLAN200_PROTECTION", "BLOCKED" if vlan200_dynamic else "PASS",
                         "VLAN 200 contains dynamic addressing." if vlan200_dynamic else "VLAN 200 remains static."))
    managed = (sources.netbox.data or {}).get("managed_devices") if sources.netbox.available else None
    if managed is not None:
        checks.append(_check("MANAGED_SCOPE", "PASS" if snapshot.device_name in managed else "BLOCKED",
                             "Device is managed." if snapshot.device_name in managed else "Device is outside managed scope."))
    else:
        checks.append(_check("MANAGED_SCOPE", "BLOCKED", "Authoritative managed scope is unavailable."))
    netbox_data = (sources.netbox.data or {}) if sources.netbox.available else {}
    known = set()
    for row in netbox_data.get("ip_addresses") or []:
        if not row.get("ip"):
            continue
        try:
            known.add(str(ipaddress.ip_interface(row["ip"]).ip))
        except ValueError:
            continue
    missing = sorted({str(ipaddress.ip_interface(value).ip) for value in addresses} - known)
    checks.append(_check("NETBOX_RUNNING_RELATIONSHIP", "WARNING" if missing else "PASS",
                         "Running addresses are not all represented in NetBox." if missing else "Running addresses agree with NetBox.",
                         evidence={"not_in_netbox": missing}))
    critical = {"hostname": bool(re.search(r"(?mi)^hostname\s+\S+", text)),
                "management_vlan200": bool(re.search(r"(?mi)^interface\s+vlan200\b", text))}
    checks.append(_check("CRITICAL_FEATURES", "WARNING" if not all(critical.values()) else "PASS",
                         "Expected critical features were assessed.", evidence=critical))
    unsupported = [
        {"label": block.label, "classification": block.classification}
        for block in (getattr(parsed, "unmanaged_blocks", []) if parsed else [])
        if block.classification in ("RECOGNIZED_UNSUPPORTED", "UNKNOWN")
    ]
    checks.append(_check(
        "UNSUPPORTED_MANAGED_CONSTRUCTS", "WARNING" if unsupported else "PASS",
        "The parser found constructs NMAS does not currently manage." if unsupported else "No known unsupported managed constructs found.",
        evidence={"constructs": unsupported[:50], "truncated": len(unsupported) > 50},
    ))
    return checks, {"parser_version": getattr(parsed, "parser_version", ""), "addresses": len(addresses),
                    "unmanaged_blocks": len(getattr(parsed, "unmanaged_blocks", [])) if parsed else 0}


def validate_running(snapshot, *, actor: str = "", sources=None):
    """Assess one already-captured sanitized running config.  Read-only; never remediates."""
    bundle = sources or sources_module.build_source_bundle()
    checks, syntax = _running_checks(snapshot, bundle)
    return _persist(
        operation_type=models.NetworkConfigValidationOperation.RUNNING, status=_status(checks),
        input_hash=snapshot.digest, actor=actor, checks=checks, snapshot=snapshot, device=snapshot.device_name,
        platform=snapshot.platform, source_hash=bundle.source_hash(), syntax=syntax,
        semantic={"auto_remediation": False}, provenance=bundle.provenance(),
    )


def record_live_validation(execution_run, operational_run, *, actor: str = ""):
    """Translate the shared Phase-15 postcheck into distinct post-write configuration evidence."""
    report = operational_run.report or {}
    results = report.get("results") or []
    checks = []
    for row in results:
        status = row.get("status")
        mapped = "PASS" if status in ("PASS", "NOT_APPLICABLE") else ("FAIL" if status == "FAIL" else "BLOCKED")
        checks.append(_check(f"LIVE_{row.get('check_code') or row.get('requirement') or 'CHECK'}", mapped,
                             row.get("message") or "Live device state assessed.",
                             evidence={"device": row.get("device"), "observed": row.get("observed") or {}}))
    if not checks:
        checks.append(_check("LIVE_EVIDENCE", "FAIL", "No live post-write evidence was available."))
    removal = any(r.configlet and r.configlet.origin == models.ConfigletOrigin.REMOVAL
                  for r in execution_run.results.filter(phase=models.ExecutionResultPhase.APPLY))
    operation = (models.NetworkConfigValidationOperation.POST_REMOVAL if removal
                 else models.NetworkConfigValidationOperation.POST_PUSH)
    status = _status(checks, live=True)
    sources = [
        (configlet.desired_state_ref or {}).get("source") or {}
        for configlet in execution_run.plan.configlets.filter(
            cfg_id__in=execution_run.results.filter(
                phase=models.ExecutionResultPhase.APPLY,
                status__in=(models.ExecutionResultStatus.APPLIED, models.ExecutionResultStatus.ALREADY_SATISFIED),
            ).values_list("cfg_id", flat=True)
        )
    ]
    devices = sorted({source.get("device") for source in sources if source.get("device")})
    platforms = sorted({source.get("platform") for source in sources if source.get("platform")})
    run = _persist(
        operation_type=operation, status=status, input_hash=execution_run.plan_hash, actor=actor,
        checks=checks, change=execution_run.change, execution_run=execution_run, operational_run=operational_run,
        device=devices[0] if len(devices) == 1 else "", platform=platforms[0] if len(platforms) == 1 else "",
        source_hash=execution_run.validation_source_hash, live={"operational_status": operational_run.status,
        "operational_run_id": str(operational_run.run_id), "post_write_verified": status in ("PASS", "WARNING")},
        provenance={"execution_run_id": str(execution_run.run_id), "plan_id": str(execution_run.plan.plan_id)},
    )
    _record_live_capabilities(execution_run, run, actor)
    if (execution_run.change.metadata or {}).get("template_sources"):
        from .config_templates import clone as template_clone  # noqa: PLC0415 - templates depend on this module's lifecycle, not vice versa

        template_clone.record_push(execution_run, run, actor=actor)
    return run


def _record_live_capabilities(execution_run, validation_run, actor: str) -> None:
    feature_by_object = {}
    for feature in by_key().values():
        if feature.object_type:
            feature_by_object.setdefault(feature.object_type, feature.key)
    successful = validation_run.status in (models.NetworkConfigValidationStatus.PASS,
                                            models.NetworkConfigValidationStatus.WARNING)
    status = EvidenceStatus.VERIFIED if successful else EvidenceStatus.FAILED
    configlets = execution_run.plan.configlets.filter(cfg_id__in=execution_run.results.filter(
        phase=models.ExecutionResultPhase.APPLY, status__in=(models.ExecutionResultStatus.APPLIED,
                                                            models.ExecutionResultStatus.ALREADY_SATISFIED)
    ).values_list("cfg_id", flat=True))
    for configlet in configlets:
        source = (configlet.desired_state_ref or {}).get("source") or {}
        feature = source.get("capability_feature") or feature_by_object.get(source.get("object_type"))
        platform = source.get("platform")
        if not feature or not platform:
            continue
        for axis in (Axis.LIVE_WRITE, Axis.LIVE_POST_WRITE_VALIDATION, Axis.RUNTIME_VALIDATION):
            capability_evidence.record_evidence(
                platform=platform, feature=feature, axis=axis.value, status=status.value,
                source="network-config-live", detail=f"Execution {execution_run.run_id}: {validation_run.status}",
                evidence_ref=str(validation_run.run_id), recorded_by=actor, evidence_type="LIVE",
            )


def serialize(run) -> dict:
    # Structured JSON fields were sanitized and bounded at persistence time; wrapping the full document in another
    # recursive sanitizer would lose nested evidence depth.
    return {
        "run_id": str(run.run_id), "operation_type": run.operation_type, "status": run.status,
        "change_id": run.change.change_id if run.change_id else "", "device": run.device, "platform": run.platform,
        "engine_version": run.engine_version, "input_hash": run.input_hash, "source_hash": run.source_hash,
        "created_at": run.created_at.isoformat(), "created_by": run.created_by, "checks": run.checks,
        "warnings": run.warnings, "errors": run.errors, "netbox_observations": run.netbox_observations,
        "syntax_result": run.syntax_result, "semantic_result": run.semantic_result, "live_result": run.live_result,
        "provenance": run.provenance,
    }


def list_runs(change, *, limit: int = MAX_HISTORY):
    return list(change.network_config_validation_runs.order_by("-created_at", "-id")[:limit])
