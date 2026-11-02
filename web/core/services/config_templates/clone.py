"""Use Template: clone an immutable template version into a NEW, editable Device Builder working intent.

The template is only ever READ.  The clone is an ordinary Change + DeviceIntent + DeviceIntentRevision built through the
canonical Device Builder services (every value passes the Tier-1 field validators), so from here on it is edited,
validated (field / network-config / Tier-2), planned, prechecked, approved, executed and postchecked exactly like any other
Change.  A template is never pushed; only a Change cloned from it is.

Two modes:

    FULL          the whole resolved template intent becomes the working intent (a new device, or a full rebuild draft).
    INCREMENTAL   an EXISTING running device: its running configuration is imported as context (the Configuration
                  Changes contribution baseline, snapshot-guarded), and only what the template ADDS to the device
                  becomes the Change.  An object the device already has is context and is not re-deployed; a value that
                  differs on an object the device already has is reported, not silently overwritten.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from django.db import transaction
from django.utils import timezone

from ... import models
from .. import (
    candidate_renderer,
    change_service,
    field_commit_service,
    intent_service,
    interface_intent_service,
    routing_intent_service,
    service_policy_intent_service,
)
from ..capabilities import evidence as capability_evidence
from ..config_import import service as import_service
from ..config_workbench import contribution, snapshots
from ..config_workbench import scope as device_scope
from . import features, normalize, schema, working_intent
from .service import TemplateError, _audit

FULL, INCREMENTAL = "FULL", "INCREMENTAL"
MODES = (FULL, INCREMENTAL)
_MUTATION_ERRORS = (interface_intent_service.CollectionMutationError, routing_intent_service.CollectionMutationError,
                    service_policy_intent_service.CollectionMutationError)


@dataclass
class CloneResult:
    change: object
    intent: object
    revision: object
    mode: str
    warnings: list = field(default_factory=list)
    applied: dict = field(default_factory=dict)


def parameter_form(version, *, parameter_set: str = "", device_name: str = "") -> list[dict]:
    """Rows for the clone form: every parameter with its definition and the value the chosen parameter set pre-fills."""
    preset = (version.parameter_sets or {}).get(parameter_set, {})
    rows = []
    for name, spec in (version.parameters or {}).items():
        value = preset.get(name, spec.get("default"))
        if name == "hostname" and device_name and not preset:
            value = device_name
        if isinstance(value, list):
            value = ",".join(str(v) for v in value)
        rows.append({"name": name, "type": spec.get("type"), "description": spec.get("description", ""), "required": bool(spec.get("required")),
                     "value": "" if value is None else value, "is_boolean": spec.get("type") == "boolean", "checked": value is True})
    return rows


def _scope_problem(device_name: str, platform: str) -> tuple[str, str]:
    """-> (refusal, warning) for an EXISTING_DEVICE target, from the authoritative management scope (NetBox + inventory)."""
    scope = device_scope.workbench_scope()
    if scope.unavailable:
        return "", ("The authoritative management scope (NetBox) could not be read; the clone is application state only and "
                    "execution stays fail-closed until the scope is available.")
    row = scope.get(device_name)
    if row is None:
        return f"{device_name} is outside NMAS management scope; a template cannot target it as an existing device.", ""
    if row["platform"] != platform:
        return f"{device_name} is a {row['platform']} device; the working intent platform must match.", ""
    return "", ""


def _invalid_fields(revision) -> list[str]:
    return [f"{state.path}: {state.validation_message or 'invalid value'}"
            for state in revision.field_states.filter(validation_state=models.FieldValidationState.INVALID)]


def _unresolved(parsed) -> list[str]:
    return [block.label[:200] for block in parsed.unmanaged_blocks]


# --- INCREMENTAL: what the template adds to a running device -------------------------------------------------------------
def overlay(template_intent: dict, running_intent: dict) -> dict:
    """Pure.  -> {"new": intent of whole new objects, "operations": contribution operations on existing objects,
    "context": [...already on the device...], "differs": [...same object, different value: NOT changed...]}"""
    new = {"device": template_intent.get("device", {}), "interfaces": [], "static_routes": [], "routing": [], "acls": [], "nat_rules": []}
    operations, context, differs = [], [], []
    running_interfaces = {row["name"]: row for row in running_intent.get("interfaces", [])}
    for row in template_intent.get("interfaces", []):
        existing = running_interfaces.get(row["name"])
        if existing is None:
            new["interfaces"].append(row)
            continue
        context.append(f"interface {row['name']}")
        have = {a.get("cidr") for a in existing.get("addresses", [])}
        for address in row.get("addresses", []):
            if address.get("cidr") not in have:
                operations.append({"op": "interface_address", "interface": row["name"], "cidr": address["cidr"], "role": address.get("role", "PRIMARY")})
        relays = {(r.get("family"), r.get("destination")) for r in existing.get("dhcp_relays", [])}
        for relay in row.get("dhcp_relays", []):
            if (relay.get("family"), relay.get("destination")) not in relays:
                operations.append({"op": "dhcp_relay", "interface": row["name"], "destination": relay["destination"]})
        for key in ("kind", "description", "mtu", "admin_state", "access_vlan", "trunk_allowed_vlans", "native_vlan", "vlan_id"):
            if row.get(key) not in (None, "", []) and row.get(key) != existing.get(key):
                differs.append(f"interface {row['name']} {key}")
        for key in ("fhrp", "acl_attachments"):
            if any(item not in existing.get(key, []) for item in row.get(key, [])):
                differs.append(f"interface {row['name']} {key}")
    route_key = lambda r: (r.get("family"), r.get("destination"), r.get("next_hop_address"), r.get("next_hop_interface"))  # noqa: E731
    have_routes = {route_key(r) for r in running_intent.get("static_routes", [])}
    for route in template_intent.get("static_routes", []):
        (context.append(f"static route {route.get('destination')}") if route_key(route) in have_routes else new["static_routes"].append(route))
    running_routing: dict[str, list] = {}
    for instance in running_intent.get("routing", []):
        running_routing.setdefault(instance["family"], []).append(instance)
    for instance in template_intent.get("routing", []):
        family = instance["family"]
        existing = running_routing.get(family)
        if not existing:
            new["routing"].append(instance)
            continue
        context.append(f"{family} process")
        if len(existing) != 1:
            differs.append(f"{family}: the device has several processes; nothing was attached")
            continue
        current = existing[0]
        if any(current.get("fields", {}).get(k) != v for k, v in instance.get("fields", {}).items()):
            differs.append(f"{family} process fields")
        if family == "bgp":
            peers = {n.get("peer_address") for n in current.get("neighbors", [])}
            for neighbor in instance.get("neighbors", []):
                if neighbor.get("peer_address") not in peers:
                    operations.append({"op": "bgp_neighbor", "peer_address": neighbor["peer_address"], "remote_asn": neighbor["remote_asn"]})
            networks = {n.get("cidr") for n in current.get("networks", [])}
            for network in instance.get("networks", []):
                if network.get("cidr") not in networks:
                    operations.append({"op": "bgp_network", "cidr": network["cidr"]})
        else:
            bound = {b.get("interface_name") for b in current.get("bindings", [])}
            for binding in instance.get("bindings", []):
                if binding.get("interface_name") in bound:
                    continue
                if family == "ospf" and binding.get("interface_name") in running_interfaces and binding.get("area"):
                    operations.append({"op": "ospf_interface", "interface": binding["interface_name"], "area": binding["area"]})
                else:
                    differs.append(f"{family} binding on {binding.get('interface_name')}")
            if any(n not in current.get("networks", []) for n in instance.get("networks", [])):
                differs.append(f"{family} network statements")
    have_acls = {(a.get("family"), a.get("name")) for a in running_intent.get("acls", [])}
    for acl in template_intent.get("acls", []):
        (context.append(f"ACL {acl.get('name')}") if (acl.get("family"), acl.get("name")) in have_acls else new["acls"].append(acl))
    for rule in template_intent.get("nat_rules", []):
        (context.append(f"NAT {rule.get('original_source')}") if rule in running_intent.get("nat_rules", []) else new["nat_rules"].append(rule))
    return {"new": {k: v for k, v in new.items() if v not in ([], {})}, "operations": operations, "context": context, "differs": differs}


def _apply_incremental(*, change, intent, revision, resolved: dict, device_name: str, actor: str, session_factory) -> tuple[dict, list[str]]:
    outcome = snapshots.capture(device_name, actor=actor, session_factory=session_factory)
    if outcome.snapshot is None:
        raise TemplateError(outcome.code or "RETRIEVAL_FAILED", outcome.message or "The running configuration could not be captured.")
    snapshot = outcome.snapshot
    imported = import_service.import_existing_device(change=change, intent=intent, revision=revision, device_name=device_name,
                                                     session_factory=session_factory or snapshots.SESSION_FACTORY)
    if imported.status != "imported":
        raise TemplateError("IMPORT_FAILED", f"The running configuration could not be imported as context: {imported.message}")
    if (imported.provenance or {}).get("config_digest") != snapshot.digest:
        raise TemplateError("SNAPSHOT_STALE", "The running configuration changed while it was being read; try again.")
    revision.refresh_from_db()
    baseline: set = set()
    contribution._collect_ids(revision.sections or {}, baseline)  # noqa: SLF001 - the one baseline definition (contribution workflow)
    change.metadata = {**change.metadata, "workflow": models.ChangeWorkflow.CONFIGURATION_CHANGES,
                       "workflow_snapshot": {"device": device_name, "digest": snapshot.digest, "snapshot_id": str(snapshot.snapshot_id)},
                       "contribution_baseline": {"device": device_name, "object_ids": sorted(baseline)}}
    change.save(update_fields=["metadata", "updated_at"])
    # the running context is normalized exactly like a template source, so only REAL differences are reported
    running, _excluded = normalize.clean(working_intent.intent_from_sections(revision.sections, hostname=device_name), intent.platform)
    delta = overlay(resolved, running)
    existing_ids = {row["name"]: row["id"] for row in interface_intent_service.ordered_interfaces(revision)}
    parsed = schema.to_parsed({**delta["new"], "device": {"hostname": ""}})
    import_service.apply_parsed_config(change=change, intent=intent, revision=revision, parsed=parsed, existing_interface_ids=existing_ids)
    problems: list[str] = []
    for operation in delta["operations"]:
        revision.refresh_from_db()
        contribution._apply(operation, change, intent, revision, problems)  # noqa: SLF001 - the one contribution-apply implementation
    if problems:
        raise TemplateError("CLONE_INVALID", problems[:25])
    warnings = [f"Already on {device_name} (context, not re-deployed): {len(delta['context'])} object(s)."] if delta["context"] else []
    warnings += [f"Differs on {device_name} and was NOT changed (edit it explicitly or use Remove Configuration): {item}" for item in delta["differs"][:40]]
    warnings += [f"Could not be applied: {label}" for label in _unresolved(parsed)]
    applied = {"new_interfaces": len(delta["new"].get("interfaces", [])), "new_static_routes": len(delta["new"].get("static_routes", [])),
               "new_routing_processes": len(delta["new"].get("routing", [])), "operations": len(delta["operations"]),
               "context_objects": len(delta["context"]), "differing_objects": len(delta["differs"]), "snapshot_digest": snapshot.digest}
    return applied, warnings


# --- the clone ---------------------------------------------------------------------------------------------------------
def clone_into_change(*, version, device_name: str, platform: str, parameter_values: dict | None = None, parameter_set: str = "",
                      actor: str = "", change=None, title: str = "", mode: str = FULL,
                      target_type: str = models.DeviceIntentTargetType.EXISTING_DEVICE, session_factory=None) -> CloneResult:
    """-> CloneResult.  All-or-nothing: any refusal leaves no Change / intent behind and never touches the template."""
    template = version.template
    problems = []
    if not version.is_published:
        problems.append("Only a published (immutable) template version can be used.")
    if template.retired_at:
        problems.append("This template is retired.")
    if (version.constraints or {}).get("deployable") is False:
        problems.append("This template describes devices outside NMAS management (lab generation / testing / exchange only); "
                        "it cannot become a managed-device working intent.")
    if mode not in MODES or target_type not in models.DeviceIntentTargetType.values:
        problems.append("Unknown clone mode or target type.")
    if mode == INCREMENTAL and target_type != models.DeviceIntentTargetType.EXISTING_DEVICE:
        problems.append("An incremental clone needs an existing running device.")
    if platform not in (version.platforms or []):
        problems.append(f"Platform {platform!r} is not supported by this template (supported: {', '.join(version.platforms or []) or 'none'}).")
    try:
        models.DEVICE_NAME_VALIDATOR(device_name)
    except Exception:  # noqa: BLE001 - django ValidationError
        problems.append("The target device name is invalid.")
    if parameter_set and parameter_set not in (version.parameter_sets or {}):
        problems.append("Unknown parameter set.")
    if problems:
        raise TemplateError("CLONE_REFUSED", problems)
    warnings: list[str] = []
    if target_type == models.DeviceIntentTargetType.EXISTING_DEVICE:
        refusal, warning = _scope_problem(device_name, platform)
        if refusal or (warning and mode == INCREMENTAL):
            raise TemplateError("DEVICE_OUT_OF_SCOPE", refusal or warning)
        if warning:
            warnings.append(warning)
    supplied = {**(version.parameter_sets or {}).get(parameter_set, {}),
                **{k: v for k, v in (parameter_values or {}).items() if v is not None and not (isinstance(v, str) and v.strip() == "" and
                                                                                             (version.parameters.get(k) or {}).get("type") != "string")}}
    if "hostname" in (version.parameters or {}) and not supplied.get("hostname"):
        supplied["hostname"] = device_name
    resolved, values, problems = schema.resolve(version.intent, version.parameters, supplied)
    if problems:
        raise TemplateError("INVALID_PARAMETERS", problems)
    if change is not None:
        if change.lifecycle_state != models.ChangeLifecycleState.DRAFT or (change.metadata or {}).get("archived_at") \
                or models.ChangeExecutionRun.objects.filter(change=change).exists():
            raise TemplateError("CLONE_REFUSED", "Only an unexecuted, unarchived Draft Change can receive a template clone.")
        if change.device_intents.filter(device_name=device_name).exists():
            raise TemplateError("CLONE_REFUSED", f"Change {change.change_id} already has a working intent for {device_name}.")
        if mode == INCREMENTAL and (change.metadata or {}).get("contribution_baseline"):
            raise TemplateError("CLONE_REFUSED", "This Change already carries an incremental baseline for another device.")
    source = {"template_id": template.template_id, "version": version.version, "digest": version.digest, "family": template.family,
              "device": device_name, "mode": mode, "parameter_set": parameter_set, "cloned_at": timezone.now().isoformat(), "cloned_by": actor[:150]}
    try:
        with transaction.atomic():
            if change is None:
                change = change_service.create_change(
                    title=(title or f"{template.name} v{version.version} -> {device_name}")[:200], created_by=actor[:150],
                    category=models.ChangeCategory.CONFIGURATION_CHANGE, metadata={"template_sources": [source]})
            else:
                change.metadata = {**(change.metadata or {}), "template_sources": [*(change.metadata or {}).get("template_sources", []), source]}
                change.save(update_fields=["metadata", "updated_at"])
            change_service.add_target(change=change, device_name=device_name)
            intent, _created = intent_service.create_or_get_device_intent(change=change, device_name=device_name, platform=platform, target_type=target_type)
            revision = intent_service.create_candidate_revision(
                device_intent=intent, created_by=actor[:150],
                metadata={"template_clone": {**source, "parameters": values, "source_remains_immutable": True}})
            field_commit_service.seed_device_identity_field_states(intent=intent, revision=revision)
            if mode == INCREMENTAL:
                applied, more = _apply_incremental(change=change, intent=intent, revision=revision, resolved=resolved, device_name=device_name,
                                                   actor=actor, session_factory=session_factory)
                warnings += more
            else:
                parsed = schema.to_parsed({**resolved, "device": {"hostname": ""}})   # the hostname is the target device's identity field
                _count, applied, _ids = import_service.apply_parsed_config(change=change, intent=intent, revision=revision, parsed=parsed)
                warnings += [f"Could not be applied: {label}" for label in _unresolved(parsed)]
            revision.refresh_from_db()
            invalid = _invalid_fields(revision)
            if invalid:
                raise TemplateError("CLONE_INVALID", [f"Field validation rejected {item}" for item in invalid[:25]])
            _audit(models.AuditEventType.TEMPLATE_CLONED, f"Template {version.ref} cloned into {change.change_id} for {device_name} ({mode})",
                   actor=actor, version=version, change=change,
                   metadata={"template_id": template.template_id, "version": version.version, "digest": version.digest, "device": device_name,
                             "platform": platform, "mode": mode, "change_id": change.change_id, "parameter_names": sorted(values),
                             "warning_count": len(warnings)})
    except _MUTATION_ERRORS as exc:
        raise TemplateError("CLONE_INVALID", str(exc)) from None
    _record_render_evidence(version, intent, revision, platform, actor)
    return CloneResult(change=change, intent=intent, revision=revision, mode=mode, warnings=warnings, applied=applied)


def _record_render_evidence(version, intent, revision, platform: str, actor: str) -> None:
    """The cloned intent is rendered by the ONE candidate renderer (Jinja2 feature templates); record what was observed."""
    try:
        rendered = candidate_renderer.render(intent, revision)
        ok = bool(rendered)
    except Exception:  # noqa: BLE001 - evidence must record a renderer failure, never raise through the clone
        ok = False
    present = set(features.required_features(working_intent.intent_from_sections(revision.sections, hostname=intent.device_name)))
    for feature in sorted(present & set(version.required_features)):
        capability_evidence.record_evidence(
            platform=platform, feature=feature, axis="RENDERER", status="VERIFIED" if ok else "FAILED", source="template-render",
            detail=f"Template-derived working intent rendered for {intent.device_name}.", evidence_ref=version.ref, recorded_by=actor)


def template_sources(change) -> list[dict]:
    return list((change.metadata or {}).get("template_sources") or [])


def record_push(execution_run, validation_run, *, actor: str = "") -> None:
    """Called after the Phase 2 live post-push validation of a template-derived Change: one audit event linking the
    template version to the verified push.  (Per-feature LIVE_WRITE / post-write capability evidence is already recorded
    by ``network_config_validation._record_live_capabilities`` for every push; it is not duplicated here.)"""
    change = execution_run.change
    for source in template_sources(change):
        models.AuditEvent.objects.create(
            event_type=models.AuditEventType.TEMPLATE_PUSH_RECORDED, change=change, actor=actor[:150],
            object_type="ConfigurationTemplateVersion", object_id=f"{source.get('template_id')}@v{source.get('version')}"[:64],
            summary=f"Template-derived push of {change.change_id} to {source.get('device')}: live validation {validation_run.status}"[:255],
            metadata={"template_id": source.get("template_id"), "version": source.get("version"), "digest": source.get("digest"),
                      "device": source.get("device"), "change_id": change.change_id, "execution_run_id": str(execution_run.run_id),
                      "network_config_validation_run_id": str(validation_run.run_id), "live_status": validation_run.status,
                      "operation": validation_run.operation_type})
