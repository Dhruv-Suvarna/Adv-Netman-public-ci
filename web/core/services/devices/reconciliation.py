"""Inventory-to-lifecycle-registry reconciliation report -- STRICTLY READ-ONLY.

Compares the supported authority sources (``inventory.yml`` via the resolver, the provisioning registry, and the
``ManagedDevice`` lifecycle registry) and reports, per device, what is registered, what is missing and which evidence is absent.

It never adopts, registers, approves, verifies, pins a host key, creates an identity or a management path, contacts a device,
NetBox or a credential broker, or grants admission.  Anything it cannot establish is reported as ``UNKNOWN`` / ``MISSING``
(fail closed).  ``admission_granted`` is always ``False`` on every row: this report is evidence, not authority.
"""

from __future__ import annotations

import hashlib
import json

from django.db import DatabaseError

from ... import models
from . import lifecycle, resolver

# Row classifications
REGISTERED = "REGISTERED"                         # configured registry row consistent with its authority source
ADOPTION_PENDING = "ADOPTION_PENDING"             # eligible inventory device with no configured registry row
EXCLUDED = "EXCLUDED"                             # not writable / edge (e.g. R5): never adopted
CONFLICT = "CONFLICT"                             # registry and inventory disagree (name collision, platform mismatch, ...)
REGISTRY_ONLY = "REGISTRY_ONLY"                   # registry row with no current inventory/provisioning authority
UNKNOWN = "UNKNOWN"                               # registry unreadable: nothing may be concluded

# Evidence gap codes (each means "not established", never "assumed present")
GAPS = ("NO_LIFECYCLE_ROW", "IDENTITY_UNVERIFIED", "NO_APPROVED_MANAGEMENT_PATH", "NO_BROKER_REFERENCE", "NO_HOST_KEY_PIN",
        "NO_INDEPENDENT_IDENTITY_APPROVAL", "NETBOX_NOT_CHECKED")


def _history(name: str) -> dict:
    try:
        return lifecycle._linked_history(name)
    except DatabaseError:
        return {"status": "UNKNOWN", "evidence_class": "LOCAL", "reason": "HISTORY_UNAVAILABLE"}


def _evidence(row, target) -> dict:
    """Evidence facts for one configured registry row (counts and references only; no secret is read)."""
    paths = list(row.management_paths.exclude(approval_state=models.ManagementApproval.REVOKED))
    approved = [p for p in paths if p.approval_state == models.ManagementApproval.APPROVED]
    broker = any(p.credential_reference for p in approved)
    pinned = bool(row.verified_host_key) or any(p.expected_host_key for p in approved)
    # Independent approval = a verifier recorded that is not the person who registered the device.  Unknown otherwise.
    independent = bool(row.identity_verified_by) and row.identity_verified_by != row.registered_by
    gaps = []
    if row.identity_state != models.IdentityVerificationState.VERIFIED:
        gaps.append("IDENTITY_UNVERIFIED")
    if not approved:
        gaps.append("NO_APPROVED_MANAGEMENT_PATH")
    if not broker:
        gaps.append("NO_BROKER_REFERENCE")
    if not pinned:
        gaps.append("NO_HOST_KEY_PIN")
    if not independent:
        gaps.append("NO_INDEPENDENT_IDENTITY_APPROVAL")
    # An identifier is a link, never evidence of a current NetBox comparison.
    gaps.extend(["NETBOX_NOT_CHECKED", "CURRENT_IDENTITY_NOT_CHECKED", "APPROVAL_PROVENANCE_NOT_CHECKED"])
    return {"evidence_class": "LOCAL", "current_identity_validated": False,
            "approval_provenance_validated": False, "netbox_compared": False,
            "management_paths": len(paths), "approved_management_paths": len(approved), "host_key_pinned": pinned,
            "broker_reference_recorded": broker, "independent_identity_approval": independent,
            "inventory_credential_reference_keys": sorted(k for k in (target.credential_refs if target else {}) if k.endswith("_ref")),
            "netbox_device_id": row.netbox_device_id, "gaps": gaps}


def _row_dict(name, classification, *, target=None, row=None, conflicts=(), next_step="") -> dict:
    out = {"name": name, "classification": classification, "admission_granted": False,
           "authority": target.authority if target else ("NMAS_REGISTRY" if row else "NONE"),
           "evidence_class": "LOCAL", "current_management_status": "UNKNOWN",
           "provenance": "UNKNOWN",
           "scope": target.scope if target else "", "platform": (target.platform if target else (row.platform if row else "")),
           "conflicts": sorted(set(conflicts)), "next_operator_step": next_step}
    if row is not None:
        out["lifecycle"] = {"device_id": row.device_id, "origin": row.origin, "lifecycle_state": row.lifecycle_state,
                            "identity_state": row.identity_state, "admission_state": row.admission_state, "ztp_state": row.ztp_state,
                            "compliance_state": row.compliance_state, "role": row.role, "version": row.version}
        out["evidence"] = _evidence(row, target)
        out["linked_history"] = _history(name)
    else:
        out["lifecycle"] = None
        out["evidence"] = {"gaps": ["NO_LIFECYCLE_ROW"] if classification == ADOPTION_PENDING else []}
    return out


def _build_report(*, document: dict | None = None) -> dict:
    """Return the reconciliation report (pure read; deterministic for unchanged inputs)."""
    resolution = resolver.resolve_all(document=document)
    discrepancies = [d.as_dict() for d in resolution.discrepancies]
    by_name: dict = {}
    for d in discrepancies:
        by_name.setdefault(d["name"], []).append(d["code"])
    if "LIFECYCLE_REGISTRY_UNAVAILABLE" in by_name.get("*", []):
        rows = [_row_dict(t.name, UNKNOWN, target=t, conflicts=["LIFECYCLE_REGISTRY_UNAVAILABLE"],
                          next_step="restore registry access; no conclusion is possible") for t in resolution.targets.values()
                if t.authority == resolver.Authority.INVENTORY_FILE]
        return _finish(rows, discrepancies, registry_readable=False)

    live = {r.name: r for r in models.ManagedDevice.objects.exclude(lifecycle_state__in=tuple(models.DEVICE_LIFECYCLE_TERMINAL))
            .prefetch_related("management_paths")}
    rows, seen = [], set()
    for name, target in sorted(resolution.targets.items()):
        seen.add(name)
        row = live.get(name)
        codes = list(by_name.get(name, []))
        if target.authority == resolver.Authority.INVENTORY_FILE:
            if not target.writable or not target.platform:
                # excluded scope; a registry row for an excluded host is a conflict, not an adoption
                if row is not None:
                    codes.append("EXCLUDED_HOST_HAS_REGISTRY_ROW")
                    rows.append(_row_dict(name, CONFLICT, target=target, row=row, conflicts=codes,
                                          next_step="operator review; NMAS does not manage this host"))
                else:
                    rows.append(_row_dict(name, EXCLUDED, target=target, conflicts=codes))
            elif row is None:
                rows.append(_row_dict(name, ADOPTION_PENDING, target=target, conflicts=codes,
                                      next_step=f"operator: nmas_devices adopt --name {name} --role <role> --actor <approver> --confirm {name}"))
            elif row.origin != models.DeviceOrigin.LEGACY_ADOPTION:
                rows.append(_row_dict(name, CONFLICT, target=target, row=row, conflicts=codes + ["NAME_COLLISION"],
                                      next_step="operator review; existing registry identity is preserved"))
            elif row.platform != target.platform:
                rows.append(_row_dict(name, CONFLICT, target=target, row=row, conflicts=codes + ["PLATFORM_MISMATCH"],
                                      next_step="operator review; neither side is rewritten"))
            else:
                rows.append(_row_dict(name, CONFLICT if codes else REGISTERED, target=target, row=row, conflicts=codes))
        else:
            cls = REGISTRY_ONLY if target.authority == resolver.Authority.NMAS_REGISTRY else (
                REGISTERED if row is not None and row.origin == models.DeviceOrigin.REGISTERED_NEW else CONFLICT)
            if cls == REGISTRY_ONLY:
                codes.append("CURRENT_AUTHORITY_NOT_ESTABLISHED")
            if row is not None and target.platform and row.platform != target.platform:
                cls = CONFLICT
                codes.append("PLATFORM_MISMATCH")
            if codes and cls == REGISTERED:
                cls = CONFLICT
            rows.append(_row_dict(name, cls, target=target, row=row, conflicts=codes))
    for name, row in sorted(live.items()):
        if name not in seen:
            rows.append(_row_dict(name, REGISTRY_ONLY, row=row,
                                  conflicts=by_name.get(name, []) + ["NOT_IN_CURRENT_AUTHORITY"],
                                  next_step="operator review; the row and its history are preserved"))
    return _finish(rows, discrepancies, registry_readable=True)


def _finish(rows, discrepancies, *, registry_readable: bool) -> dict:
    counts: dict = {}
    for r in rows:
        counts[r["classification"]] = counts.get(r["classification"], 0) + 1
    report = {"evidence_class": "LOCAL", "evidence_scope": "configured database and local inventory only",
              "live_observation": False, "production_registry_validated": False,
              "evidence_classes": {"SUPPLIED": "operator claim, not independently observed",
                  "HISTORICAL": "prior artifact or recorded history, not current observation",
                  "LOCAL": "configured database or source read, environment not attested",
                  "GATEWAY_ATTESTED": "gateway-recorded execution; scope determined by operation",
                  "LIVE": "gateway-recorded observation of the named current target; unit tests never qualify"},
              "read_only": True, "registry_readable": registry_readable, "admission_granted_any": False,
              "summary": counts, "missing_eligible": [r["name"] for r in rows if r["classification"] == ADOPTION_PENDING],
              "excluded": [r["name"] for r in rows if r["classification"] == EXCLUDED],
              "conflicts": [r["name"] for r in rows if r["classification"] in (CONFLICT, UNKNOWN, REGISTRY_ONLY)],
              "devices": rows, "discrepancies": discrepancies,
              "not_checked": ["NetBox (not queried)", "live device identity/host keys", "credential broker contents"]}
    report["has_gaps"] = (not registry_readable or bool(report["missing_eligible"] or report["conflicts"])
                          or any(r["evidence"].get("gaps") for r in rows if r["classification"] != EXCLUDED)
                          or bool(discrepancies))
    report["digest"] = hashlib.sha256(json.dumps(report, sort_keys=True, default=str).encode()).hexdigest()
    return report


def build_report(*, document: dict | None = None) -> dict:
    """Read configured sources; a mid-read database failure invalidates the entire snapshot."""
    try:
        return _build_report(document=document)
    except DatabaseError:
        discrepancies = [{"name": "*", "code": "LIFECYCLE_REGISTRY_UNAVAILABLE",
                          "detail": "configured registry snapshot could not be read"}]
        try:
            targets = resolver.resolve_all(document=document, with_lifecycle=False).targets.values()
            rows = [_row_dict(t.name, UNKNOWN, target=t, conflicts=["LIFECYCLE_REGISTRY_UNAVAILABLE"])
                    for t in targets if t.authority == resolver.Authority.INVENTORY_FILE]
        except DatabaseError:
            rows = []
        return _finish(rows, discrepancies, registry_readable=False)
