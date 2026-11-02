"""Configuration Changes: small CREATE / ATTACH contributions to an already-running device, as an INCREMENTAL patch.

Two input styles converge on ONE structured operation vocabulary:

    Structured widgets        {"op": "static_route", "destination": ..., "next_hop": ...}
    Direct CLI fragment       recognised lines are normalized onto the same operations; anything else is REJECTED with a
                              reason (``no`` / ``default`` lines belong to Remove Configuration; secrets are refused; unknown
                              syntax is never guessed -- it stays out, and Device Builder's Raw Configlet path remains available)

Building the Change (never on page load, one explicit POST, all-or-nothing):

    1. Change (category CONFIGURATION_CHANGE, workflow CONFIGURATION_CHANGES) + target + EXISTING_DEVICE intent/revision
    2. the device's live running config is IMPORTED through the existing Phase-20.5 importer as CONTEXT; its provenance
       digest must equal the snapshot the operator was looking at, or nothing is kept (STALE)
    3. every imported object id is recorded as the contribution BASELINE (hashed into the validation input)
    4. each operation is applied through the ordinary intent services + Tier-1 field commits (an INVALID value aborts)

The planner then drops every baseline object (``planning.builder._exclude_contribution_context``), so the plan -- and the
preview -- is exactly the contribution: child snippets carry only their own block headers, never a device's full config.
Validation, plan, precheck, explicit approval, execution and postcheck are the existing lifecycle, unchanged.
"""

from __future__ import annotations

import ipaddress
import re

from django.db import transaction

from ... import models
from .. import change_service, field_commit_service, intent_service, interface_intent_service, routing_intent_service
from .. import service_policy_intent_service
from ..config_import import service as import_service
from ..execution import capability as execution_capability
from ..raw_configlets import static_gate
from . import semantics

WORKFLOW = models.ChangeWorkflow.CONFIGURATION_CHANGES

# key -> (label, execution object types, required fields)
OPERATIONS = {
    "static_route": ("Static route", ("static_route",), ("destination", "next_hop")),
    "interface_address": ("Address on an existing interface", ("address",), ("interface", "cidr")),
    "loopback": ("New loopback interface", ("interface", "address"), ("name",)),
    "bgp_neighbor": ("BGP neighbor (existing BGP process)", ("bgp_neighbor", "bgp_neighbor_af"), ("peer_address", "remote_asn")),
    "bgp_network": ("BGP network advertisement (existing BGP process)", ("bgp_network",), ("cidr",)),
    "ospf_interface": ("Attach an existing interface to the existing OSPF process", ("routing_binding",), ("interface", "area")),
    "dhcp_relay": ("DHCP relay on an existing interface", ("dhcp_relay",), ("interface", "destination")),
}


FIELD_LABELS = {
    "destination": "Destination prefix", "next_hop": "Next hop", "interface": "Interface", "cidr": "Address (CIDR)",
    "name": "Interface name", "peer_address": "Peer address", "remote_asn": "Remote AS", "area": "OSPF area",
}


class ContributionError(ValueError):
    """A contribution could not be built; ``problems`` are operator-facing and never contain secret values."""

    def __init__(self, problems):
        self.problems = list(problems)
        super().__init__("; ".join(self.problems))


def operation_catalogue(platform: str) -> list[dict]:
    """Every widget with an HONEST execution classification for the platform (never shown as executable when it is not)."""
    rows = []
    for key, (label, object_types, fields) in OPERATIONS.items():
        caps = [execution_capability.capability_for(platform, t) for t in object_types]
        applies = all(c.apply == "SUPPORTED" for c in caps)
        complete = applies and all(c.compensation == "SUPPORTED" for c in caps)
        rows.append({
            "key": key, "label": label, "fields": fields, "field_labels": [(f, FIELD_LABELS.get(f, f)) for f in fields], "executable": applies,
            "mode": "COMPLETE_OR_PARTIAL" if complete else ("PARTIAL_UAT_ONLY" if applies else "NOT_EXECUTABLE"),
            "note": next((c.note for c in caps if c.apply != "SUPPORTED"), "") or next((c.note for c in caps if c.note), ""),
        })
    return rows


def snapshot_context(text: str, platform: str) -> dict:
    """What already exists (for widget choices and direct-CLI resolution), from the same semantic index as removal."""
    model = semantics.build_model(text, platform)
    interfaces = sorted(o.id.split(":", 1)[1] for o in model.objects.values() if o.id.startswith("interface:"))
    bgp = sorted(o.id.split(":", 1)[1] for o in model.objects.values() if o.kind == "bgp_process")
    ospf = sorted(o.id.split(":", 1)[1] for o in model.objects.values() if o.kind == "ospf_process")
    protected = sorted(o.id.split(":", 1)[1] for o in model.objects.values() if o.id.startswith("interface:") and o.protected)
    return {"interfaces": interfaces, "bgp_processes": bgp, "ospf_processes": ospf, "protected_interfaces": protected}


# --- direct CLI --------------------------------------------------------------------------------------------------------
def parse_direct_cli(fragment: str, platform: str, snapshot_text: str) -> dict:
    """Normalize a small CLI fragment onto structured operations.  Nothing is sent anywhere; unrecognised text is rejected."""
    context = snapshot_context(snapshot_text, platform)
    operations, rejected = [], []
    gate = static_gate.evaluate(fragment or "")
    if not (fragment or "").strip():
        return {"operations": [], "rejected": [{"line": 0, "text": "", "reason": "EMPTY"}]}
    header, header_line = None, 0
    for number, raw in enumerate((fragment or "").replace("\r\n", "\n").split("\n"), start=1):
        line = raw.rstrip()
        text = line.strip()
        if not text or text.startswith("!"):
            continue
        if static_gate.secret_patterns(text):
            rejected.append({"line": number, "text": "(secret-bearing line withheld)", "reason": "SECRET_MATERIAL_REFUSED"})
            continue
        if text.split()[0] in ("no", "default"):
            rejected.append({"line": number, "text": text, "reason": "REMOVAL_BELONGS_IN_REMOVE_CONFIGURATION"})
            continue
        indented = line[:1] in (" ", "\t")
        if not indented:
            header, header_line = None, number
            if (m := re.fullmatch(r"(ip|ipv6) route (\S+) (\S+)(?: (\d+))?", text)):
                operations.append({"op": "static_route", "destination": m.group(2), "next_hop": m.group(3), "distance": m.group(4) or "",
                                   "source_lines": [number]})
            elif (m := re.fullmatch(r"interface (\S+)", text)):
                header = ("interface", m.group(1))
                if m.group(1) not in context["interfaces"]:
                    if re.fullmatch(r"Loopback\d+", m.group(1)):
                        operations.append({"op": "loopback", "name": m.group(1), "cidr": "", "source_lines": [number]})
                    else:
                        rejected.append({"line": number, "text": text, "reason": "INTERFACE_NOT_ON_DEVICE"})
                        header = None
            elif (m := re.fullmatch(r"router bgp (\S+)", text)):
                header = ("bgp", m.group(1))
                if m.group(1) not in context["bgp_processes"]:
                    rejected.append({"line": number, "text": text, "reason": "BGP_PROCESS_NOT_ON_DEVICE"})
                    header = None
            else:
                rejected.append({"line": number, "text": text, "reason": "UNRECOGNISED_STATEMENT"})
            continue
        if header is None:
            rejected.append({"line": number, "text": text, "reason": "NO_RECOGNISED_CONTEXT"})
            continue
        kind, name = header
        if kind == "interface":
            loop = next((op for op in operations if op["op"] == "loopback" and op["name"] == name), None)
            if (m := re.fullmatch(r"(ip|ipv6) address (\S+)( secondary)?", text)):
                if loop is not None and not loop["cidr"]:
                    loop["cidr"] = m.group(2)
                    loop["source_lines"].append(number)
                else:
                    operations.append({"op": "interface_address", "interface": name, "cidr": m.group(2),
                                       "role": "SECONDARY" if m.group(3) else "PRIMARY", "source_lines": [header_line, number]})
            elif (m := re.fullmatch(r"ip helper-address (\S+)", text)):
                operations.append({"op": "dhcp_relay", "interface": name, "destination": m.group(1), "source_lines": [header_line, number]})
            elif (m := re.fullmatch(r"ip ospf area (\S+)", text)):
                operations.append({"op": "ospf_interface", "interface": name, "area": m.group(1), "source_lines": [header_line, number]})
            else:
                rejected.append({"line": number, "text": text, "reason": "UNRECOGNISED_STATEMENT"})
        elif kind == "bgp":
            if (m := re.fullmatch(r"neighbor (\S+) remote-as (\d+)", text)):
                operations.append({"op": "bgp_neighbor", "peer_address": m.group(1), "remote_asn": m.group(2), "source_lines": [header_line, number]})
            elif (m := re.fullmatch(r"network (\S+)", text)):
                operations.append({"op": "bgp_network", "cidr": m.group(1), "source_lines": [header_line, number]})
            else:
                rejected.append({"line": number, "text": text, "reason": "UNRECOGNISED_STATEMENT"})
    if not gate.normalized and not operations and not rejected:
        rejected.append({"line": 0, "text": "", "reason": "STATIC_GATE_REFUSED"})
    return {"operations": operations, "rejected": rejected}


# --- validation of one operation (pure; the authoritative semantic validation is the Phase-13 engine) --------------------
def check_operation(op: dict, platform: str, context: dict) -> list[str]:
    problems = []
    key = op.get("op")
    if key not in OPERATIONS:
        return [f"Unknown operation {key!r}."]
    label, object_types, fields = OPERATIONS[key]
    for field in fields:
        if not str(op.get(field) or "").strip():
            problems.append(f"{label}: {field.replace('_', ' ')} is required.")
    if problems:
        return problems
    if not any(r["key"] == key and r["executable"] for r in operation_catalogue(platform)):
        problems.append(f"{label} is not executable on {platform}; it cannot be saved as a change.")
    if key in ("interface_address", "ospf_interface", "dhcp_relay"):
        if op["interface"] not in context["interfaces"]:
            problems.append(f"Interface {op['interface']} does not exist on the device.")
        elif op["interface"] in context["protected_interfaces"]:
            problems.append(f"Interface {op['interface']} is part of the protected management plane.")
    if key in ("bgp_neighbor", "bgp_network") and not context["bgp_processes"]:
        problems.append("The device has no BGP process to attach to (create it through Device Builder).")
    if key == "ospf_interface" and not context["ospf_processes"]:
        problems.append("The device has no OSPF process to attach to.")
    if key == "loopback" and op["name"] in context["interfaces"]:
        problems.append(f"{op['name']} already exists; use 'Address on an existing interface'.")
    for field in ("destination", "cidr"):
        if op.get(field):
            try:
                ipaddress.ip_interface(op[field]) if "/" in op[field] else ipaddress.ip_address(op[field])
            except ValueError:
                problems.append(f"{op[field]!r} is not a valid address or prefix.")
    return problems


# --- building the Change ---------------------------------------------------------------------------------------------
def _collect_ids(value, found: set) -> None:
    if isinstance(value, dict):
        if isinstance(value.get("id"), str):
            found.add(value["id"])
        for key, child in value.items():
            if key != "_import":
                _collect_ids(child, found)
    elif isinstance(value, list):
        for child in value:
            _collect_ids(child, found)


def _commit(change, intent, revision, path: str, value, problems: list, label: str) -> None:
    state = field_commit_service.commit_field(change=change, intent=intent, revision=revision, path=path, raw_value=value)
    if state.validation_state == models.FieldValidationState.INVALID:
        problems.append(f"{label}: {state.validation_message or 'invalid value'}")


def _interface_id(revision, name: str) -> str | None:
    return next((row["id"] for row in interface_intent_service.ordered_interfaces(revision) if row.get("name") == name), None)


def _single_instance(revision, family: str) -> str | None:
    instances = routing_intent_service.ordered_instances(revision, family)
    return instances[0]["id"] if len(instances) == 1 else None


def _apply(op: dict, change, intent, revision, problems: list) -> None:
    key = op["op"]
    label = OPERATIONS[key][0]
    if key == "static_route":
        family = "IPV6" if ":" in op["destination"] else "IPV4"
        route = routing_intent_service.add_static_route(revision=revision, family=family)
        base = f"routing.static_routes.{route['id']}"
        _commit(change, intent, revision, f"{base}.destination", op["destination"], problems, label)
        _commit(change, intent, revision, f"{base}.next_hop_address", op["next_hop"], problems, label)
        if str(op.get("distance") or "").strip():
            _commit(change, intent, revision, f"{base}.distance", int(op["distance"]), problems, label)
    elif key in ("interface_address", "loopback"):
        if key == "loopback":
            iface = interface_intent_service.add_interface(revision=revision, kind="LOOPBACK", name=op["name"])
            if_id = iface["id"]
        else:
            if_id = _interface_id(revision, op["interface"])
        if if_id is None:
            problems.append(f"{label}: the interface was not imported from the running configuration.")
            return
        if op.get("cidr"):
            family = "IPV6" if ":" in op["cidr"] else "IPV4"
            address = interface_intent_service.add_address(revision=revision, interface_id=if_id, family=family, source="MANUAL")
            base = f"interfaces.{if_id}.addresses.{address['id']}"
            _commit(change, intent, revision, f"{base}.cidr", op["cidr"], problems, label)
            if op.get("role") == "SECONDARY":
                _commit(change, intent, revision, f"{base}.role", "SECONDARY", problems, label)
    elif key in ("bgp_neighbor", "bgp_network"):
        instance = _single_instance(revision, "bgp")
        if instance is None:
            problems.append(f"{label}: exactly one imported BGP process is required.")
            return
        if key == "bgp_neighbor":
            routing_intent_service.add_bgp_neighbor(revision=revision, instance_id=instance, peer_address=op["peer_address"],
                                                    remote_asn=int(op["remote_asn"]))
        else:
            routing_intent_service.add_bgp_network(revision=revision, instance_id=instance, family="IPV6" if ":" in op["cidr"] else "IPV4",
                                                   cidr=op["cidr"])
    elif key == "ospf_interface":
        instance, if_id = _single_instance(revision, "ospf"), _interface_id(revision, op["interface"])
        if instance is None or if_id is None:
            problems.append(f"{label}: the OSPF process or interface was not imported.")
            return
        binding = routing_intent_service.add_interface_binding(revision=revision, family="ospf", instance_id=instance, interface_id=if_id)
        _commit(change, intent, revision, f"routing.ospf.{instance}.interfaces.{binding['id']}.area", op["area"], problems, label)
    elif key == "dhcp_relay":
        if_id = _interface_id(revision, op["interface"])
        if if_id is None:
            problems.append(f"{label}: the interface was not imported.")
            return
        service_policy_intent_service.add_dhcp_relay(revision=revision, family="IPV6" if ":" in op["destination"] else "IPV4",
                                                     interface_id=if_id, destination=op["destination"])


def create_contribution_change(*, snapshot, operations: list[dict], actor: str = "", title: str = "", session_factory=None):
    """-> Change.  Raises ContributionError; on any failure NOTHING is persisted (one transaction)."""
    context = snapshot_context(snapshot.text, snapshot.platform)
    problems = [p for op in operations for p in check_operation(op, snapshot.platform, context)]
    if not operations:
        problems.append("Add at least one change.")
    if problems:
        raise ContributionError(problems)
    try:
        with transaction.atomic():
            change = change_service.create_change(
                title=(title or f"Configuration change on {snapshot.device_name}")[:200], created_by=actor[:150],
                category=models.ChangeCategory.CONFIGURATION_CHANGE,
                metadata={"workflow": WORKFLOW, "workflow_snapshot": {
                    "device": snapshot.device_name, "digest": snapshot.digest, "snapshot_id": str(snapshot.snapshot_id)}},
            )
            change_service.add_target(change=change, device_name=snapshot.device_name)
            intent, _ = intent_service.create_or_get_device_intent(
                change=change, device_name=snapshot.device_name, platform=snapshot.platform,
                target_type=models.DeviceIntentTargetType.EXISTING_DEVICE,
            )
            revision = intent_service.create_candidate_revision(device_intent=intent, created_by=actor[:150])
            field_commit_service.seed_device_identity_field_states(intent=intent, revision=revision)
            from .snapshots import SESSION_FACTORY  # noqa: PLC0415 - read at call time so tests can inject a fake

            imported = import_service.import_existing_device(change=change, intent=intent, revision=revision,
                                                             device_name=snapshot.device_name, session_factory=session_factory or SESSION_FACTORY)
            if imported.status != "imported":
                raise ContributionError([f"The running configuration could not be imported as context: {imported.message}"])
            if (imported.provenance or {}).get("config_digest") != snapshot.digest:
                raise ContributionError(["The running configuration changed since the snapshot you were viewing. Refresh it and try again."])
            revision.refresh_from_db()
            baseline: set = set()
            _collect_ids(revision.sections or {}, baseline)
            change.metadata = {**change.metadata, "contribution_baseline": {"device": snapshot.device_name, "object_ids": sorted(baseline)},
                               "operations": [{k: v for k, v in op.items() if k != "source_lines"} for op in operations]}
            change.save(update_fields=["metadata", "updated_at"])
            apply_problems: list[str] = []
            for op in operations:
                _apply(op, change, intent, revision, apply_problems)
            if apply_problems:
                raise ContributionError(apply_problems)
            return change
    except (interface_intent_service.CollectionMutationError, routing_intent_service.CollectionMutationError,
            service_policy_intent_service.CollectionMutationError) as exc:
        raise ContributionError([str(exc)]) from None
