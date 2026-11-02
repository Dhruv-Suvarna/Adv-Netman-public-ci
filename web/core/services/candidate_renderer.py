"""
The one authoritative Python candidate-rendering contract.

    candidate_renderer.render(intent, revision, field_overrides=None)

This module is reused by the Device Builder preview today, and is intended
for deployment planning, deployment, Golden comparison, and rollback
preparation once those phases exist -- there must never be a second,
unrelated renderer built for any of those later; extend the platform driver
registry (platform_drivers.py) instead.

Phase 9 renders only currently-modeled foundational device-identity fields.
Detailed interface/routing/service/security rendering is Phase 10+ scope;
this renderer says so explicitly (see platform_drivers.NOT_IMPLEMENTED_LINE)
rather than fabricating vendor CLI for sections that do not exist yet.

Renders never touch NetBox, Git, GitHub, or a live device -- every value
comes from the DeviceIntent row and its IntentFieldState rows already in
the database.
"""

from __future__ import annotations

import difflib
from copy import deepcopy

from . import (
    interface_intent_service,
    platform_drivers,
    routing_intent_service,
    service_policy_intent_service,
)

HEADER_LINES = [
    "! Candidate Configuration",
    "! Not deployed. Tier-1 syntax acceptance only; project validation is pending.",
]


def _base_field_values(intent) -> dict:
    return {
        "device.hostname": intent.device_name,
        "device.description": "",
        "device.platform": intent.platform,
        "device.target_type": intent.target_type,
        "device.image_reference": intent.image_reference,
    }


def _field_values_from_states(revision, *, use_draft: bool) -> dict:
    values = {}
    for field_state in revision.field_states.all():
        values[field_state.path] = field_state.draft_value if use_draft else field_state.accepted_value
    return values


_LINE_BREAKS = ("\n", "\r", "\x00")


def _line_text(descriptor: dict) -> str | None:
    if descriptor["kind"] == "static":
        return descriptor["text"]
    value = descriptor.get("value") or ""
    if not value and descriptor.get("omit_if_empty"):
        return None
    if isinstance(value, str) and any(mark in value for mark in _LINE_BREAKS):
        # Defence in depth (Lab 7 finding F1): a field value is substituted into ONE line; a value that would break out of it
        # (stored before the Tier-1 fix, imported, or injected) is withheld as a visible refusal, never rendered.
        from .platform_drivers import UNSUPPORTED_OBJECT_MARKER

        return f"{UNSUPPORTED_OBJECT_MARKER} {descriptor.get('path') or 'field'} contains a line break; value withheld"
    return descriptor["template"].format(value=value)


def _interfaces_from_sections(revision, values: dict) -> list[dict]:
    """Hydrate the structured interface schema with accepted/draft field state.

    ``sections`` is the canonical versioned object schema. IntentFieldState
    remains the Phase-8 editing/audit contract; applying its selected side
    here is what lets accepted and draft renders share one object model.
    """
    interfaces = deepcopy((revision.sections or {}).get("interfaces") or {})
    for path, value in values.items():
        if not isinstance(path, str) or not path.startswith("interfaces."):
            continue
        parts = path.split(".")
        if len(parts) < 3 or parts[1] not in interfaces:
            continue
        interface = interfaces[parts[1]]
        if len(parts) == 3 and parts[2] in interface_intent_service.INTERFACE_FIELDS:
            interface[parts[2]] = value
            if parts[2] == "kind" and value in interface_intent_service.KIND_MODES:
                interface["mode"] = interface_intent_service.KIND_MODES[value]
        elif len(parts) == 4 and parts[2] == "wan" and parts[3] in interface_intent_service.WAN_FIELDS:
            interface.setdefault("wan", {})[parts[3]] = value
        elif len(parts) == 5 and parts[2] == "addresses":
            address = (interface.get("addresses") or {}).get(parts[3])
            if address is not None and parts[4] in interface_intent_service.ADDRESS_FIELDS:
                address[parts[4]] = value
    return sorted(
        interfaces.values(),
        key=lambda row: (int(row.get("sequence") or 0), row.get("id", ""), row.get("name", "")),
    )


def _routing_from_sections(revision, values: dict) -> dict:
    """Hydrate the structured routing schema with accepted/draft field state.

    Mirrors ``_interfaces_from_sections`` exactly, generalized to routing's
    six sub-namespaces (``static_routes``/``rip``/``ospf``/``isis``/``eigrp``/
    ``bgp``), each keyed by stable object ID rather than list position.
    """
    routing = deepcopy((revision.sections or {}).get("routing") or {})
    for family in routing_intent_service.PROTOCOL_FAMILIES:
        if not isinstance(routing.get(family), dict):
            routing[family] = {}

    for path, value in values.items():
        if not isinstance(path, str) or not path.startswith("routing."):
            continue
        parts = path.split(".")
        if len(parts) < 4 or parts[1] not in routing_intent_service.PROTOCOL_FAMILIES:
            continue
        family = parts[1]
        objects = routing[family]
        if parts[2] not in objects:
            continue

        if family == "static_routes":
            if len(parts) == 4 and parts[3] in routing_intent_service.STATIC_ROUTE_FIELDS:
                objects[parts[2]][parts[3]] = value
            continue

        instance = objects[parts[2]]
        if len(parts) == 4 and parts[3] in routing_intent_service.INSTANCE_FIELDS[family]:
            instance[parts[3]] = value
        elif family in routing_intent_service.BINDING_FAMILIES and len(parts) == 6 and parts[3] == "interfaces":
            binding = (instance.get("interfaces") or {}).get(parts[4])
            if binding is not None and parts[5] in routing_intent_service.BINDING_FIELDS[family]:
                binding[parts[5]] = value
        elif family == "ospf" and len(parts) == 6 and parts[3] == "networks":
            network = (instance.get("networks") or {}).get(parts[4])
            if network is not None and parts[5] in routing_intent_service.OSPF_NETWORK_FIELDS:
                network[parts[5]] = value
        elif family == "bgp" and len(parts) == 6 and parts[3] == "neighbors":
            neighbor = (instance.get("neighbors") or {}).get(parts[4])
            if neighbor is not None and parts[5] in routing_intent_service.BGP_NEIGHBOR_FIELDS:
                neighbor[parts[5]] = value
        elif family == "bgp" and len(parts) == 6 and parts[3] == "networks":
            network = (instance.get("networks") or {}).get(parts[4])
            if network is not None and parts[5] in routing_intent_service.BGP_NETWORK_FIELDS:
                network[parts[5]] = value
    return routing


def _phase12_from_sections(revision, values: dict) -> dict:
    """Hydrate the five Phase-12 namespaces from the same accepted/draft
    IntentFieldState selection used by every earlier Device Builder module."""
    phase12 = deepcopy(service_policy_intent_service.structured_sections(revision))
    wrapper = dict(revision.sections or {})
    wrapper.update(phase12)
    for path, value in values.items():
        if not isinstance(path, str) or not path.startswith(("fhrp.", "nat.", "services.", "security.", "policy.")):
            continue
        target, field = service_policy_intent_service._field_target(wrapper, path)
        if target is not None and field is not None:
            target[field] = value
    return {key: wrapper[key] for key in ("fhrp", "nat", "services", "security", "policy")}


def descriptor_text(descriptor: dict) -> str | None:
    """Public form of the descriptor -> line rule (None = omitted line)."""
    return _line_text(descriptor)


def hydrate_state(intent, revision, *, field_overrides: dict | None = None, use_draft: bool = False) -> dict:
    """The one structured, hydrated view of a candidate revision.

    ``use_draft=False`` selects ACCEPTED field state only.  render() is built
    on this function and Phase-13 validation snapshots consume it too, so the
    renderer and the validator can never disagree about what "accepted" means.
    """
    values = _base_field_values(intent)
    values.update(_field_values_from_states(revision, use_draft=use_draft))
    if field_overrides:
        values.update(field_overrides)
    phase12 = _phase12_from_sections(revision, values)
    # V2 Phase 4: management-VRF intent travels with the Phase-12 namespaces ONLY when the revision holds an object, so
    # every existing candidate, snapshot and plan stays byte-identical.
    from .management import vrf as management_vrf

    management = management_vrf.section(revision)
    if management_vrf.present(management):
        phase12["management"] = management
    return {
        "field_values": values,
        "interfaces": _interfaces_from_sections(revision, values),
        "routing": _routing_from_sections(revision, values),
        "phase12": phase12,
        # Import provenance and opaque configuration travel with every
        # candidate/planning payload, but are deliberately never converted to
        # CLI.  This is how unsupported configuration survives managed edits
        # without NMAS pretending that it owns or can safely rewrite it.
        "import_metadata": deepcopy((revision.sections or {}).get("_import") or {}),
    }


def render(intent, revision, *, field_overrides: dict | None = None, use_draft: bool = False) -> dict:
    """
    use_draft=False (default, "authoritative"): renders from ACCEPTED field
    state only. This is what "the Python authoritative candidate" means
    throughout Phase 9 -- returned after every successful commit, used for
    Copy Candidate and Download Candidate.

    use_draft=True: renders using DRAFT field state where present (falling
    back to the same accepted/base values otherwise). Used only for the
    draft side of the accepted-vs-draft diff -- never persisted, never
    returned as if it were the authoritative accepted candidate.

    field_overrides lets a caller substitute specific paths without
    persisting anything (provided for later deployment-planning reuse;
    Phase 9's own UI does not use it).
    """
    state = hydrate_state(intent, revision, field_overrides=field_overrides, use_draft=use_draft)
    values, interfaces = state["field_values"], state["interfaces"]
    routing, phase12 = state["routing"], state["phase12"]

    driver = platform_drivers.get_driver(intent.platform)
    normalized = driver.compose_candidate(
        field_values=values, interfaces=interfaces, routing=routing, phase12=phase12
    )
    descriptors = driver.render_composed(normalized)
    body_lines = [text for descriptor in descriptors if (text := _line_text(descriptor)) is not None]
    lines = [*HEADER_LINES, "", *body_lines]

    return {
        "platform": intent.platform,
        "device_name": intent.device_name,
        "header_lines": list(HEADER_LINES),
        "descriptors": descriptors,
        "lines": lines,
        "text": "\n".join(lines),
        "field_values": values,
        "interfaces": normalized["interfaces"],
        "routing": normalized["routing"],
        "phase12": normalized["phase12"],
        "import_metadata": state["import_metadata"],
        "normalized_candidate": normalized,
        "composition_conflicts": normalized["conflicts"],
    }


def diff_accepted_vs_draft(intent, revision) -> dict:
    """
    Accepted Candidate vs Current (last-committed-attempt) Draft Candidate.
    Both renders come from already-persisted field state -- this never
    triggers a fresh browser round trip or a live-device/NetBox read, and is
    only computed when explicitly requested (e.g. a "Show Diff" click), not
    automatically on every edit.
    """
    accepted = render(intent, revision, use_draft=False)
    draft = render(intent, revision, use_draft=True)
    diff_lines = list(
        difflib.unified_diff(accepted["lines"], draft["lines"], fromfile="accepted", tofile="draft", lineterm="")
    )
    return {
        "accepted": accepted,
        "draft": draft,
        "diff_lines": diff_lines,
        "identical": accepted["lines"] == draft["lines"],
    }
