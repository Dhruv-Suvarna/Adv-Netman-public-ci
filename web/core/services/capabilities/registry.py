"""Aggregation: one CapabilityRecord per (platform, feature) built from every registry plus empirical evidence."""

from __future__ import annotations

from dataclasses import dataclass, field

from ... import models
from .. import platform_drivers
from ..config_import import service as config_import_service
from ..execution import capability as execution_capability
from ..execution.codes import Capability
from ..execution.executors.registry import EXECUTORS
from ..health import inventory
from .axes import (
    AXIS_LABELS, EMPIRICAL_ONLY_AXES, SUMMARY_LABELS, Axis, EvidenceKind, EvidenceStatus, EvidenceType, Summary,
    TerminalStatus,
)
from . import vocabulary
from .axes import CAPABILITY_STATUS_LABELS, CapabilityStatus
from .evidence import latest_evidence
from .features import INTERFACE, ROUTING, Feature, by_key, catalogue, platforms

_FROM_RENDER = {
    platform_drivers.CapabilityStatus.SUPPORTED: EvidenceStatus.IMPLEMENTED,
    platform_drivers.CapabilityStatus.NOT_IMPLEMENTED: EvidenceStatus.NOT_IMPLEMENTED,
    platform_drivers.CapabilityStatus.UNSUPPORTED: EvidenceStatus.UNSUPPORTED,
    platform_drivers.CapabilityStatus.UNKNOWN: EvidenceStatus.UNKNOWN,
}
_FROM_EXECUTION = {
    Capability.SUPPORTED: EvidenceStatus.IMPLEMENTED,
    Capability.NOT_IMPLEMENTED: EvidenceStatus.NOT_IMPLEMENTED,
    Capability.UNSUPPORTED: EvidenceStatus.UNSUPPORTED,
    Capability.UNKNOWN: EvidenceStatus.UNKNOWN,
}
# Platforms with a live, read-only capture/session transport (health.live: cEOS SSH, Linux docker exec).
_LIVE_CAPTURE_PLATFORMS = frozenset({"arista_ceos", "ubuntu_frr"})
# Object types for which Phase-15 has a concrete state evaluator. A transport-capable executor alone is not evidence
# that post-write state can be proved (routing process definitions, including OSPF network statements, remain honest
# UAT-only until a configuration read-back evaluator is added).
_POST_WRITE_VERIFIABLE = frozenset({
    "interface", "address", "static_route", "routing_binding", "bgp_neighbor", "bgp_neighbor_af",
    "fhrp", "dhcp_relay", "acl", "acl_attachment", "nat_rule",
})


@dataclass(frozen=True)
class AxisEvidence:
    axis: Axis
    status: EvidenceStatus
    kind: EvidenceKind
    source: str
    detail: str = ""
    registry_status: EvidenceStatus | None = None  # what the code claims when empirical evidence overrides it
    evidence_type: EvidenceType | None = None
    evidence_ref: str = ""
    repository_head: str = ""
    runtime_version: str = ""
    recorded_at: object | None = None

    @property
    def label(self) -> str:
        return AXIS_LABELS[self.axis]


@dataclass(frozen=True)
class CapabilityRecord:
    platform: str
    feature: Feature
    axes: dict[Axis, AxisEvidence] = field(default_factory=dict)
    assessment: object | None = None

    @property
    def summary(self) -> Summary:
        return derive_summary(self.axes)

    @property
    def summary_label(self) -> str:
        return SUMMARY_LABELS[self.summary]

    @property
    def status(self) -> TerminalStatus:
        if self.assessment is not None and not self.assessment.complete:
            return TerminalStatus.UNSUPPORTED
        return resolve_terminal_status(self.axes)

    @property
    def status_label(self) -> str:
        return self.status.value

    @property
    def _vocabulary(self) -> tuple[str, str]:
        complete = bool(self.assessment is not None and self.assessment.complete)
        reasons = self.assessment.reasons if self.assessment is not None else ()
        return vocabulary.classify(self.status.value, complete=complete, reasons=reasons, platform=self.platform, feature=self.feature.key)

    @property
    def capability_status(self) -> str:
        """The four-value vocabulary (SUPPORTED is exactly ``status`` SUPPORTED; see ``vocabulary.classify``)."""
        return self._vocabulary[0]

    @property
    def capability_status_label(self) -> str:
        return CAPABILITY_STATUS_LABELS[CapabilityStatus(self.capability_status)]

    @property
    def feasibility(self) -> str:
        return self._vocabulary[1]

    @property
    def unsupported_reason(self) -> str:
        if self.assessment is not None and not self.assessment.complete:
            outstanding = [name for name, result in self.assessment.probes.items() if result["outcome"] == "PENDING"]
            return f"Exhaustive assessment requires {len(outstanding)} outstanding probe(s); current evidence cannot establish support."
        if self.status == TerminalStatus.SUPPORTED:
            return "All mandatory implementation and empirical axes are satisfied."
        failed = next((ev for ev in self.axes.values() if ev.status == EvidenceStatus.FAILED), None)
        if failed:
            reason = (failed.detail or failed.source).rstrip(".")
            return f"{failed.label} failed: {reason}."
        for axis in MANDATORY_AXES:
            ev = self.axes[axis]
            if not _axis_satisfied(axis, ev):
                reason = (ev.detail or "required evidence is absent").rstrip(".")
                return f"{ev.label} is {ev.status.value}: {reason}."
        return "Mandatory support evidence is incomplete."


MANDATORY_AXES = tuple(Axis)
_MUST_BE_EMPIRICALLY_VERIFIED = frozenset({
    Axis.AUTOMATED_TESTS, Axis.LIVE_READ, Axis.LIVE_WRITE, Axis.LIVE_POST_WRITE_VALIDATION,
    Axis.COMPENSATION, Axis.RUNTIME_VALIDATION,
})


def _axis_satisfied(axis: Axis, evidence: AxisEvidence) -> bool:
    if axis in _MUST_BE_EMPIRICALLY_VERIFIED:
        return evidence.kind == EvidenceKind.EMPIRICAL and evidence.status == EvidenceStatus.VERIFIED
    return evidence.status in (EvidenceStatus.IMPLEMENTED, EvidenceStatus.VERIFIED)


def resolve_terminal_status(axes: dict[Axis, AxisEvidence]) -> TerminalStatus:
    """Fail closed: only a complete, verified operator workflow is green."""
    return TerminalStatus.SUPPORTED if all(_axis_satisfied(axis, axes[axis]) for axis in MANDATORY_AXES) \
        else TerminalStatus.UNSUPPORTED


def _render_capability(platform: str, feature: Feature):
    if feature.family == INTERFACE:
        return platform_drivers.capability_for(platform, feature.code), platform_drivers.is_interface_kind_selectable(platform, feature.code)
    if feature.family == ROUTING:
        protocol = platform_drivers.RoutingProtocol(feature.code)
        return platform_drivers.capability_for_routing(platform, protocol), platform_drivers.is_routing_protocol_selectable(platform, protocol)
    return (platform_drivers.capability_for_service_policy(platform, feature.code),
            platform_drivers.is_service_policy_feature_selectable(platform, feature.code))


def registry_axes(platform: str, feature: Feature) -> dict[Axis, AxisEvidence]:
    """What the code base implements, axis by axis (no empirical evidence)."""
    reg = EvidenceKind.REGISTRY
    render, selectable = _render_capability(platform, feature)
    render_status = _FROM_RENDER[render.status]
    axes: dict[Axis, AxisEvidence] = {
        Axis.SEMANTIC_MODEL: AxisEvidence(Axis.SEMANTIC_MODEL, EvidenceStatus.IMPLEMENTED, reg, "device_builder.intent_model",
                                          "Platform-neutral canonical intent model field."),
        Axis.RENDERER: AxisEvidence(Axis.RENDERER, render_status, reg, "platform_drivers", render.evidence),
        Axis.DEVICE_BUILDER_UI: AxisEvidence(
            Axis.DEVICE_BUILDER_UI, EvidenceStatus.IMPLEMENTED if selectable else (render_status if render_status != EvidenceStatus.IMPLEMENTED else EvidenceStatus.NOT_IMPLEMENTED),
            reg, "platform_drivers.selectable", "Selectable in the Device Builder." if selectable else "Not offered by the Device Builder for this platform."),
        Axis.CONFIG_VALIDATION: AxisEvidence(
            Axis.CONFIG_VALIDATION,
            EvidenceStatus.IMPLEMENTED if render_status == EvidenceStatus.IMPLEMENTED else render_status,
            reg, "network_config_validation",
            "Version 2 Phase 2 validates syntax, addressing/conflicts, IPAM relationship, managed scope and platform capability."
            if render_status == EvidenceStatus.IMPLEMENTED else "No validated renderer exists for this feature/platform.",
        ),
    }

    live_capture = platform in _LIVE_CAPTURE_PLATFORMS
    has_parser = live_capture or platform in config_import_service.FIXTURE_PARSERS
    parser_features = config_import_service.PARSER_FEATURES.get(platform)
    if parser_features is not None:
        has_parser = has_parser and feature.key in parser_features
    axes[Axis.PARSER_IMPORT] = AxisEvidence(
        Axis.PARSER_IMPORT, EvidenceStatus.IMPLEMENTED if has_parser else EvidenceStatus.NOT_IMPLEMENTED, reg, "config_import",
        ("Platform parser with live capture" if live_capture else "Platform parser, fixture-tested only (no live capture transport)")
        + "; per-feature parse coverage is assessed in Version 2 Phase 4." if has_parser else "No parser for this platform.")
    axes[Axis.LIVE_READ] = AxisEvidence(
        Axis.LIVE_READ, EvidenceStatus.IMPLEMENTED if live_capture else EvidenceStatus.NOT_IMPLEMENTED, reg, "health.live",
        "Read-only live session exists (platform level)." if live_capture else "No live read session for this platform in the approved lab.")

    if feature.object_type:
        cap = execution_capability.capability_for(platform, feature.object_type)
        apply_status = _FROM_EXECUTION[cap.apply]
        comp_status = _FROM_EXECUTION[cap.compensation]
        note = cap.note or cap.evidence
    else:
        apply_status = comp_status = EvidenceStatus.NOT_IMPLEMENTED
        note = "No execution object type carries this feature."
    has_executor = inventory.health_platform(platform) in EXECUTORS
    if apply_status == EvidenceStatus.IMPLEMENTED and render_status != EvidenceStatus.IMPLEMENTED:
        # The executor could carry the object type, but NMAS cannot produce this feature's configuration.
        apply_status, note = EvidenceStatus.NOT_IMPLEMENTED, "The executor supports the object type, but no renderer produces this feature for this platform."
        comp_status = EvidenceStatus.NOT_IMPLEMENTED
    axes[Axis.LIVE_WRITE] = AxisEvidence(Axis.LIVE_WRITE, apply_status, reg, "execution.capability", note)
    axes[Axis.LIVE_POST_WRITE_VALIDATION] = AxisEvidence(
        Axis.LIVE_POST_WRITE_VALIDATION,
        EvidenceStatus.IMPLEMENTED
        if apply_status == EvidenceStatus.IMPLEMENTED and has_executor and feature.object_type in _POST_WRITE_VERIFIABLE
        else EvidenceStatus.NOT_IMPLEMENTED,
        reg, "execution.engine+health.postcheck",
        ("Applied state is verified by a Phase-15 postcheck read group."
         if apply_status == EvidenceStatus.IMPLEMENTED and has_executor and feature.object_type in _POST_WRITE_VERIFIABLE
         else "No concrete post-write evaluator exists for this feature; transport acceptance is not treated as success."))
    axes[Axis.COMPENSATION] = AxisEvidence(Axis.COMPENSATION, comp_status, reg, "execution.capability", note if comp_status != EvidenceStatus.IMPLEMENTED else "Exact inverse verified by read-back.")
    for axis in EMPIRICAL_ONLY_AXES:
        axes[axis] = AxisEvidence(axis, EvidenceStatus.NOT_ASSESSED, EvidenceKind.EMPIRICAL, "", "No empirical evidence recorded yet.")
    return axes


def capability_record(platform: str, feature: Feature | str, *, evidence=None, assessment=None) -> CapabilityRecord:
    if isinstance(feature, str):
        feature = by_key()[feature]
    axes = registry_axes(platform, feature)
    evidence = latest_evidence() if evidence is None else evidence
    for axis in Axis:
        row = evidence.get((platform, feature.key, axis.value))
        if row is None:
            continue
        base = axes[axis]
        axes[axis] = AxisEvidence(axis, EvidenceStatus(row.status), EvidenceKind.EMPIRICAL, row.source,
                                  row.detail or row.evidence_ref, registry_status=base.status if base.kind == EvidenceKind.REGISTRY else None,
                                  evidence_type=EvidenceType(row.evidence_type), evidence_ref=row.evidence_ref,
                                  repository_head=row.repository_head, runtime_version=row.runtime_version,
                                  recorded_at=row.recorded_at)
    return CapabilityRecord(platform, feature, axes, assessment)


def derive_summary(axes: dict[Axis, AxisEvidence]) -> Summary:
    """The derived level.  Live claims need live-axis evidence; renderer support alone never implies live support."""
    write, post = axes[Axis.LIVE_WRITE], axes[Axis.LIVE_POST_WRITE_VALIDATION]
    live_axes = (write, post, axes[Axis.COMPENSATION], axes[Axis.RUNTIME_VALIDATION])
    if any(a.status == EvidenceStatus.FAILED for a in live_axes):
        return Summary.LIVE_FAILED
    if write.status == EvidenceStatus.VERIFIED and post.status == EvidenceStatus.VERIFIED:
        return Summary.LIVE_VERIFIED
    if write.status in (EvidenceStatus.IMPLEMENTED, EvidenceStatus.VERIFIED):
        return Summary.LIVE_IMPLEMENTED
    render = axes[Axis.RENDERER].status
    if render in (EvidenceStatus.IMPLEMENTED, EvidenceStatus.VERIFIED):
        return Summary.RENDER_ONLY
    if render == EvidenceStatus.NOT_IMPLEMENTED:
        return Summary.NOT_IMPLEMENTED
    if render == EvidenceStatus.UNSUPPORTED:
        return Summary.UNSUPPORTED
    return Summary.UNKNOWN


def evidence_matrix(*, family: str | None = None) -> dict:
    """The page model: features x platforms, each cell a CapabilityRecord (one evidence query for the whole matrix)."""
    evidence = latest_evidence()
    from .assessment import latest_assessments
    assessments = latest_assessments()
    plats = platforms()
    rows = []
    for feature in catalogue():
        if family and feature.family != family:
            continue
        rows.append({"feature": feature, "cells": [capability_record(p, feature, evidence=evidence,
                        assessment=assessments.get((p, feature.key))) for p in plats]})
    counts: dict[str, int] = {status.value: 0 for status in TerminalStatus}
    capability_counts: dict[str, int] = {status.value: 0 for status in CapabilityStatus}
    for row in rows:
        for cell in row["cells"]:
            counts[cell.status.value] += 1
            capability_counts[cell.capability_status] += 1
    labels = {value: label for value, label in models.Platform.choices}
    return {"platforms": plats, "rows": rows, "axes": list(Axis), "axis_labels": AXIS_LABELS,
            "platform_labels": labels, "summary_counts": counts, "evidence_rows": len(evidence),
            "capability_counts": capability_counts, "capability_labels": {s.value: CAPABILITY_STATUS_LABELS[s] for s in CapabilityStatus},
            "assessment_counts": {"total": sum(len(row["cells"]) for row in rows),
                                  "assessed": sum(bool(c.assessment and c.assessment.complete) for row in rows for c in row["cells"]),
                                  "unassessed": sum(not c.assessment or not c.assessment.complete for row in rows for c in row["cells"])}}
