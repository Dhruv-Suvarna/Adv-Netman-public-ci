"""Capability axes, evidence statuses and the summary vocabulary."""

from __future__ import annotations

from enum import StrEnum


class Axis(StrEnum):
    SEMANTIC_MODEL = "SEMANTIC_MODEL"                          # canonical intent model represents the feature
    DEVICE_BUILDER_UI = "DEVICE_BUILDER_UI"                    # an operator can select / author it in the Device Builder
    RENDERER = "RENDERER"                                      # NMAS renders platform configuration for it
    CONFIG_VALIDATION = "CONFIG_VALIDATION"                    # network-configuration validation exists (V2 Phase 2+)
    PARSER_IMPORT = "PARSER_IMPORT"                            # existing configuration can be parsed back into intent
    AUTOMATED_TESTS = "AUTOMATED_TESTS"                        # automated test evidence exists (empirical)
    LIVE_READ = "LIVE_READ"                                    # NMAS can read the live device state
    LIVE_WRITE = "LIVE_WRITE"                                  # NMAS can push it to a live device
    LIVE_POST_WRITE_VALIDATION = "LIVE_POST_WRITE_VALIDATION"  # the push is verified by live read-back
    COMPENSATION = "COMPENSATION"                              # an exact, verified undo exists
    RUNTIME_VALIDATION = "RUNTIME_VALIDATION"                  # observed working end-to-end on the running lab (empirical)


AXIS_LABELS = {
    Axis.SEMANTIC_MODEL: "Semantic model", Axis.DEVICE_BUILDER_UI: "Device Builder UI", Axis.RENDERER: "Renderer",
    Axis.CONFIG_VALIDATION: "Config validation", Axis.PARSER_IMPORT: "Parser / import", Axis.AUTOMATED_TESTS: "Automated tests",
    Axis.LIVE_READ: "Live read", Axis.LIVE_WRITE: "Live write / push", Axis.LIVE_POST_WRITE_VALIDATION: "Post-write validation",
    Axis.COMPENSATION: "Compensation / rollback", Axis.RUNTIME_VALIDATION: "Runtime validation",
}

# Axes that only EMPIRICAL evidence can satisfy (no registry claims them).
EMPIRICAL_ONLY_AXES = frozenset({Axis.AUTOMATED_TESTS, Axis.RUNTIME_VALIDATION})


class EvidenceStatus(StrEnum):
    VERIFIED = "VERIFIED"                # empirically observed working
    FAILED = "FAILED"                    # empirically observed NOT working
    IMPLEMENTED = "IMPLEMENTED"          # registry: a code path exists, not (yet) empirically verified here
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"  # the platform could; NMAS does not (yet)
    UNSUPPORTED = "UNSUPPORTED"          # genuine platform limitation
    NOT_ASSESSED = "NOT_ASSESSED"        # no evidence either way yet
    UNKNOWN = "UNKNOWN"                  # the registry itself has no evidence


EMPIRICAL_STATUSES = frozenset({EvidenceStatus.VERIFIED, EvidenceStatus.FAILED, EvidenceStatus.NOT_ASSESSED})


class EvidenceKind(StrEnum):
    REGISTRY = "REGISTRY"
    EMPIRICAL = "EMPIRICAL"


class EvidenceType(StrEnum):
    """How an empirical observation was produced, ordered weakest to strongest."""

    STATIC = "STATIC"
    FIXTURE = "FIXTURE"
    LIVE = "LIVE"


EVIDENCE_TYPE_STRENGTH = {
    EvidenceType.STATIC: 1,
    EvidenceType.FIXTURE: 2,
    EvidenceType.LIVE: 3,
}


class TerminalStatus(StrEnum):
    """The only vocabulary exposed by the final operator capability matrix."""

    SUPPORTED = "SUPPORTED"
    UNSUPPORTED = "UNSUPPORTED"


class Summary(StrEnum):
    """One derived level per (platform, feature), strongest first."""

    LIVE_VERIFIED = "LIVE_VERIFIED"          # push + post-write validation empirically verified
    LIVE_FAILED = "LIVE_FAILED"              # a live axis was observed failing
    LIVE_IMPLEMENTED = "LIVE_IMPLEMENTED"    # an executor path exists; not yet empirically verified
    RENDER_ONLY = "RENDER_ONLY"              # NMAS renders it but cannot push it
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"
    UNSUPPORTED = "UNSUPPORTED"
    UNKNOWN = "UNKNOWN"


SUMMARY_LABELS = {
    Summary.LIVE_VERIFIED: "Live: verified", Summary.LIVE_FAILED: "Live: failing evidence",
    Summary.LIVE_IMPLEMENTED: "Live push implemented (unverified)", Summary.RENDER_ONLY: "Render only (no live push)",
    Summary.NOT_IMPLEMENTED: "Not implemented", Summary.UNSUPPORTED: "Unsupported (platform)", Summary.UNKNOWN: "Unknown",
}


class CapabilityStatus(StrEnum):
    """The operator-facing capability vocabulary (V2 Lifecycle Phase 2).

    Derived from -- never replacing -- the binary ``TerminalStatus`` ledger value: SUPPORTED is exactly TerminalStatus
    SUPPORTED; every ledger UNSUPPORTED cell is split by its classified reasons (see ``vocabulary.classify``)."""

    SUPPORTED = "SUPPORTED"                # NMAS does it, with the mandatory live evidence
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"    # NMAS does not (yet); the platform could, or feasibility is not established
    UNSUPPORTED = "UNSUPPORTED"            # a demonstrated platform / vendor limitation
    OUT_OF_SCOPE = "OUT_OF_SCOPE"          # deliberately excluded by a recorded decision


class Feasibility(StrEnum):
    PROVEN = "PROVEN"                            # supported: proven by live evidence
    PLATFORM_LIMITATION = "PLATFORM_LIMITATION"  # a completed assessment found the platform cannot
    EXCLUDED = "EXCLUDED"                        # a recorded scope decision
    NMAS_GAP = "NMAS_GAP"                        # the platform could; an NMAS layer is missing
    UNKNOWN = "UNKNOWN"                          # assessed, but the evidence cannot tell platform from NMAS (runtime / harness)
    UNASSESSED = "UNASSESSED"                    # no completed assessment


CAPABILITY_STATUS_LABELS = {
    CapabilityStatus.SUPPORTED: "Supported", CapabilityStatus.NOT_IMPLEMENTED: "Not implemented",
    CapabilityStatus.UNSUPPORTED: "Unsupported (platform)", CapabilityStatus.OUT_OF_SCOPE: "Out of scope",
}
