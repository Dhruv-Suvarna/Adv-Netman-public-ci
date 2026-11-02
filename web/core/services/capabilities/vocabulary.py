"""The four-value capability vocabulary, derived from the binary ledger without rewriting it.

    SUPPORTED        ledger ``final_status`` SUPPORTED (unchanged: the same cells, the same live evidence)
    UNSUPPORTED      a COMPLETED assessment recorded a platform reason (PLATFORM_DOES_NOT_SUPPORT, VENDOR_LIMITATION)
    OUT_OF_SCOPE     the cell is listed in ``SCOPE_EXCLUSIONS`` (a recorded decision; empty until someone decides one)
    NOT_IMPLEMENTED  everything else -- with ``feasibility`` saying why: an NMAS gap, an unknown (runtime / harness / policy
                     evidence cannot tell platform from NMAS), or no completed assessment at all

Unknown feasibility therefore never silently becomes SUPPORTED or UNSUPPORTED.  Historical ledger rows are read as they are;
the derived fields are added next to ``final_status``, which keeps its binary meaning for every existing consumer.
"""

from __future__ import annotations

from enum import StrEnum

from .axes import CapabilityStatus, Feasibility

PLATFORM_REASONS = frozenset({"PLATFORM_DOES_NOT_SUPPORT", "VENDOR_LIMITATION"})
# Evidence that cannot attribute the failure to the platform or to NMAS (or a deliberate refusal to automate).
UNKNOWN_FEASIBILITY_REASONS = frozenset({"RUNTIME_IMAGE_UNAVAILABLE", "RUNTIME_BOOT_FAILED", "FUNCTIONAL_TEST_FAILED", "HARNESS_ERROR",
                                         "UNSAFE_TO_AUTOMATE"})
# (platform, feature) -> recorded reason.  A cell is OUT_OF_SCOPE only by an explicit entry here; none is recorded yet.
SCOPE_EXCLUSIONS: dict[tuple[str, str], str] = {}


def classify(final_status: str, *, complete: bool, reasons=(), platform: str = "", feature: str = "",
             exclusions: dict | None = None) -> tuple[str, str]:
    """-> (CapabilityStatus, Feasibility) for one cell's binary ledger status, completeness and classified reasons."""
    exclusions = SCOPE_EXCLUSIONS if exclusions is None else exclusions
    if final_status == "SUPPORTED":
        return CapabilityStatus.SUPPORTED.value, Feasibility.PROVEN.value
    if final_status != "UNSUPPORTED":
        raise ValueError("final_status must be SUPPORTED or UNSUPPORTED.")
    if (platform, feature) in exclusions:
        return CapabilityStatus.OUT_OF_SCOPE.value, Feasibility.EXCLUDED.value
    if not complete:
        return CapabilityStatus.NOT_IMPLEMENTED.value, Feasibility.UNASSESSED.value
    found = set(reasons or ())
    if found & PLATFORM_REASONS:
        return CapabilityStatus.UNSUPPORTED.value, Feasibility.PLATFORM_LIMITATION.value
    if not found or found & UNKNOWN_FEASIBILITY_REASONS:
        return CapabilityStatus.NOT_IMPLEMENTED.value, Feasibility.UNKNOWN.value
    return CapabilityStatus.NOT_IMPLEMENTED.value, Feasibility.NMAS_GAP.value


def classify_cell(cell: dict) -> dict:
    """The derived fields of one ledger cell dictionary (as ``CellAssessment.as_dict`` / the stored ledger write it)."""
    status, feasibility = classify(cell["final_status"], complete=bool(cell.get("assessment_complete")),
                                   reasons=cell.get("unsupported_reasons") or (), platform=str(cell.get("platform", "")),
                                   feature=str(cell.get("feature", "")))
    return {"capability_status": status, "feasibility": feasibility}


def counts(cells) -> dict:
    """{CapabilityStatus: n} over ledger cell dictionaries (every status present, zero when absent)."""
    found = {status.value: 0 for status in CapabilityStatus}
    for cell in cells:
        found[classify_cell(cell)["capability_status"]] += 1
    return found


# --- V2 Phase 9: the ten-stage closure classification --------------------------------------------------------------------
# A refinement of -- never a replacement for -- ``CapabilityStatus``: SUPPORTED, NOT_IMPLEMENTED, UNSUPPORTED (= unsupported by
# the platform) and OUT_OF_SCOPE keep their existing values and meanings; the four new values only split NOT_IMPLEMENTED by
# which of the ten stages exist.  ``CLOSURE_TO_STATUS`` maps every class back to the four-value vocabulary.
class ClosureClass(StrEnum):
    SUPPORTED = "SUPPORTED"                            # all ten stages exist (incl. live verification on that platform)
    LIVE_EVIDENCE_MISSING = "LIVE_EVIDENCE_MISSING"    # every NMAS stage through execution exists; a live stage is unproven
    PARTIAL = "PARTIAL"                                # render + validate exist and at least one later stage, not all
    RENDER_VALIDATE_ONLY = "RENDER_VALIDATE_ONLY"      # intent, renderer and validation exist; nothing executes it
    BLOCKED_BY_ENVIRONMENT = "BLOCKED_BY_ENVIRONMENT"  # live assessment impossible here (image unavailable / boot failed)
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"                # intent, renderer or validation is missing
    UNSUPPORTED = "UNSUPPORTED"                        # a demonstrated platform / vendor limitation (unsupported by platform)
    OUT_OF_SCOPE = "OUT_OF_SCOPE"                      # a recorded scope decision


CLOSURE_TO_STATUS = {
    ClosureClass.SUPPORTED: CapabilityStatus.SUPPORTED.value, ClosureClass.UNSUPPORTED: CapabilityStatus.UNSUPPORTED.value,
    ClosureClass.OUT_OF_SCOPE: CapabilityStatus.OUT_OF_SCOPE.value,
    **{c: CapabilityStatus.NOT_IMPLEMENTED.value for c in (ClosureClass.LIVE_EVIDENCE_MISSING, ClosureClass.PARTIAL,
                                                           ClosureClass.RENDER_VALIDATE_ONLY, ClosureClass.BLOCKED_BY_ENVIRONMENT,
                                                           ClosureClass.NOT_IMPLEMENTED)},
}
