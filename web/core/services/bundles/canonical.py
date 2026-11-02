"""Deterministic canonical serialization and the bundle digests.

Canonical JSON: keys sorted, compact separators, ASCII-escaped, ``NaN`` refused, and NO ``default`` hook -- a value that is not plain
JSON (a datetime, a set, an object) raises instead of being silently stringified into something unstable.  The same semantic payload
therefore hashes identically regardless of dict insertion order, query ordering, whitespace or row iteration order.  ``repr()`` is never
hashed.

Every digest is SHA-256 over a DOMAIN-TAGGED envelope ``{"domain", "schema", "value"}`` so a payload digest can never equal a bundle,
item or export digest of the same bytes.

What each digest COVERS is the contract (documented in docs/IMMUTABLE_CONFIGURATION_BUNDLES.md):

    payload_digest   the semantic payload: source provenance, executed scope, ordered items (payloads, hashes, dependencies, raw pins,
                     execution results, expected-state descriptors) and the honest verification quality.  NOT the bundle id, the
                     database primary key, ``created_at`` / ``created_by``, or the builder version.
    bundle_digest    payload_digest + kind + schema version + parent / source-UAT bundle digests (+ for a GOLDEN bundle its ``promotion``
                     provenance: the soak run, evidence digest and operator decision; + for the one-time legacy bootstrap its
                     ``legacy_bootstrap`` provenance block).  The tamper / provenance identity.
    item_digest      one canonical item record.
    export_digest    the whole exported document (creation metadata included), excluding the digest field itself.
"""

from __future__ import annotations

import hashlib
import json

from .codes import BUNDLE_SCHEMA_VERSION, EXPORT_SCHEMA_VERSION


def canonical_json(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def text_hash(text: str) -> str:
    """SHA-256 of a payload's exact UTF-8 text (what an item's ``payload_hash`` is)."""
    return hashlib.sha256(str(text).encode("utf-8")).hexdigest()


def _digest(domain: str, schema: int, value) -> str:
    return hashlib.sha256(canonical_json({"domain": domain, "schema": schema, "value": value}).encode("ascii")).hexdigest()


def payload_digest(payload: dict, *, schema_version: int = BUNDLE_SCHEMA_VERSION) -> str:
    return _digest("clab.bundle.payload", schema_version, payload)


def item_digest(record: dict, *, schema_version: int = BUNDLE_SCHEMA_VERSION) -> str:
    return _digest("clab.bundle.item", schema_version, record)


def bundle_digest(*, kind: str, payload_digest: str, parent_bundle_digest: str = "", source_uat_bundle_digest: str = "",
                  schema_version: int = BUNDLE_SCHEMA_VERSION, promotion: dict | None = None, legacy_bootstrap: dict | None = None) -> str:
    value = {
        "kind": kind, "payload_digest": payload_digest, "parent_bundle_digest": parent_bundle_digest,
        "source_uat_bundle_digest": source_uat_bundle_digest,
    }
    if promotion is not None:   # Phase 20: a GOLDEN bundle's digest also covers its soak / operator-decision provenance.  Absent for UAT / PROBATION,
        value["promotion"] = promotion   # so their digests are byte-identical to Phase 19.
    if legacy_bootstrap is not None:   # one-time legacy bootstrap: the candidate / initial Golden digest also covers the LEGACY_BOOTSTRAP provenance block.
        value["legacy_bootstrap"] = legacy_bootstrap   # Absent for every other bundle, so all existing digests stay byte-identical.
    return _digest("clab.bundle", schema_version, value)


def export_digest(document_without_digest: dict, *, schema_version: int = EXPORT_SCHEMA_VERSION) -> str:
    return _digest("clab.bundle.export", schema_version, document_without_digest)
