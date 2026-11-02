"""Phase-18 Raw Configlets -- the reusable service API.

Views, a CLI or a later phase call THIS module; no raw logic lives in a view.  Every mutating call is EXPLICIT: opening a page,
typing, saving a revision, validating a Change and building a plan never start a sandbox, and nothing here can send a Raw
Configlet to a device -- that remains the Phase-17 ``execute_change`` (Partial (UAT) only) with the pinned, verified revision.

    create_raw_configlet(change, ...)     new stable RAW-NNN + revision 1 (server-side static gate; a failing text is never stored)
    save_revision(raw, ...)               a NEW immutable revision (an identical save is a no-op)
    set_enabled(raw, enabled)             soft add to / remove from the EFFECTIVE Change input
    request_verification(revision, ...)   the explicit Verify action (isolated sandbox / parser); reuses a CURRENT acceptable result
    verification_currency(revision)       NEVER_RUN / CURRENT / STALE with reasons (never starts anything)
    verify_raw_configlet(revision, ctx)   the pure verifier entry point (no DB), for tests / CLI
    capability_matrix()                   the verification / execution capability matrix
"""

from __future__ import annotations

from .raw_configlets import assertions, capability, codes, static_gate, store, text, verification, verifier

create_raw_configlet = store.create_raw_configlet
save_revision = store.save_revision
set_enabled = store.set_enabled
redisplay_safe = store.redisplay_safe
list_raw = store.list_raw
get_raw = store.get_raw
get_revision = store.get_revision
get_verification_run = store.get_verification_run
status_of = store.status_of
snapshot_entries = store.snapshot_entries
node_id = store.node_id
RawConfigletError = store.RawConfigletError

request_verification = verification.request_verification
verification_currency = verification.currency
pinned_verification_state = verification.pinned_verification_state

verify_raw_configlet = verifier.verify_raw_configlet
VerificationContext = verifier.VerificationContext
verification_identity = verifier.identity

evaluate_static_policy = static_gate.evaluate
capability_matrix = capability.capability_matrix
verification_capability = capability.verification_capability
execution_capability = capability.execution_capability
parse_assertion_lines = assertions.parse_lines
ASSERTION_KINDS = tuple(sorted(assertions.CATALOGUE))
content_hash = text.content_hash
POLICY_VERSION = codes.POLICY_VERSION
VERIFIER_VERSION = codes.VERIFIER_VERSION
CODE_CATALOG = codes.CODE_CATALOG
LIMITS = {
    "max_bytes": codes.MAX_BYTES, "max_lines": codes.MAX_LINES, "max_line_length": codes.MAX_LINE_LENGTH,
    "max_dependencies": codes.MAX_DEPENDENCIES, "max_assertions": codes.MAX_ASSERTIONS,
}

__all__ = [
    "ASSERTION_KINDS", "CODE_CATALOG", "LIMITS", "POLICY_VERSION", "RawConfigletError", "VERIFIER_VERSION", "VerificationContext",
    "capability_matrix", "content_hash", "create_raw_configlet", "evaluate_static_policy", "execution_capability", "get_raw", "get_revision",
    "get_verification_run", "list_raw", "node_id", "parse_assertion_lines", "pinned_verification_state", "request_verification",
    "redisplay_safe", "save_revision", "set_enabled", "snapshot_entries", "status_of", "verification_capability", "verification_currency",
    "verification_identity", "verify_raw_configlet",
]
