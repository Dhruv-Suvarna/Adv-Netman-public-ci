"""Discovery ingestion: the NMAS-controlled DHCP provider's own lease database -> Phase 2 observations.

Source and trust.  Leases are read from the provider NMAS configured and runs (a controlled source), never accepted from an
API post.  Inside a lease:

    client MAC, client identifier, vendor / user class, hostname   CLAIMS (DHCP_CLIENT_CLAIM): can only contradict
    relay address (giaddr) + option 82 circuit id                  OBSERVED (DHCP_RELAY_ATTACHMENT) -- only when the relay is
                                                                   a listed trusted relay of the bootstrap network

A lease without a listed relay or without a circuit id is recorded as UNTRUSTED_RELAY and changes nothing else: the provider's
policy only offers addresses through trusted relays, so such a lease means a policy or relay fault and is surfaced as one.
V2 Phase 9: for a relay whose platform has a verified option 82 implementation, the circuit id must also be the one NMAS's fresh
read-back of the relay says the giaddr port inserts (``relay_option82.lease_problem``): a client can put any circuit id into its
own option 82 and cEOS forwards it unchanged, so a mismatch is OPTION82_CIRCUIT_FORGED (no read-back: RELAY_READBACK_MISSING).

Lease-state blocks.  A provider writes a later block when a binding is released, expires or is freed (ISC: ``binding state
free`` with no relay data).  Such a block is the end of an existing binding, not a new one: it updates that binding's state
and is never classified (a released lease carries no relay evidence, so treating it as a binding would raise a false
UNTRUSTED_RELAY).  Such blocks are counted as ``inactive``; one with no earlier binding is otherwise ignored.

Idempotency.  One ``DhcpLeaseObservation`` per distinct binding (network, address, client MAC, client id, relay, circuit,
vendor class).  Retransmissions, renewals and re-reads of the same lease file only move ``last_seen`` / ``seen_count`` and the
lease times; lifecycle observations and events are written once, when the binding is first seen.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from django.db import IntegrityError, transaction
from django.utils import timezone

from ... import models
from ..devices import authorization as authorization_service
from ..devices import events, lifecycle
from . import adapters, dhcp, policy

ACTOR = "system:ztp-dhcp-ingest"
Outcome = models.DeviceLifecycleEventOutcome
L = models.DhcpLeaseOutcome
MAX_LEASE_FILE = 4 * 1024 * 1024
INACTIVE_STATES = frozenset({"free", "released", "expired", "abandoned", "backup", "reset"})


def idempotency_key(network, row: dict) -> str:
    parts = [str(network.pk), row.get("address", ""), row.get("client_mac", ""), row.get("client_id", ""), row.get("relay_address", ""),
             row.get("circuit_id", ""), row.get("vendor_class", "")]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()


def read_lease_file(network) -> str:
    path = Path(network.lease_file or Path(network.config_root) / "dhcpd.leases")
    dhcp.base.safe_root(str(path.parent))
    if not path.exists() or path.is_symlink():
        return ""
    with open(path, encoding="utf-8", errors="replace") as handle:
        return handle.read(MAX_LEASE_FILE)


def ingest(network, *, text: str | None = None, now=None, runner=None) -> dict:
    """Read and fold every lease of ``network`` -> counts by outcome plus how many bindings were new."""
    provider = dhcp.for_network(network, runner=runner)
    rows = provider.parse_leases(read_lease_file(network) if text is None else text)
    summary = {"leases": len(rows), "new": 0, "repeat": 0, "inactive": 0, "outcomes": {}}
    for row in rows:
        observation, created = fold(network, row, now=now)
        if created is None:
            summary["inactive"] += 1
            continue
        summary["new" if created else "repeat"] += 1
        summary["outcomes"][observation.outcome] = summary["outcomes"].get(observation.outcome, 0) + 1
    return summary


def _trusted_upstream(network, row) -> str:
    relays = policy.relay_map(network)
    return relays.get(row.get("relay_address", ""), "") if row.get("circuit_id") else ""


def _session_for_port(network, upstream: str, interface: str):
    return (models.ZtpSession.objects.select_related("device", "authorization", "authorization__attachment")
            .filter(network=network, stage__in=tuple(models.ZTP_SESSION_OPEN), authorization__attachment__upstream_device=upstream,
                    authorization__attachment__upstream_interface=interface).first())


def _end_of_binding(network, row: dict, now):
    """A released / expired / free block -> the binding it ends (state and times updated), or None when none was seen."""
    existing = (models.DhcpLeaseObservation.objects.filter(network=network, address=row.get("address", ""),
                                                           client_mac=str(row.get("client_mac") or "")[:17])
                .order_by("-last_seen", "-id").first())
    if existing is None:
        return None
    state = str(row.get("binding_state") or "")[:16]
    if existing.binding_state != state:
        existing.binding_state, existing.last_seen = state, now
        existing.lease_ends = row.get("ends") or existing.lease_ends
        existing.save(update_fields=["binding_state", "last_seen", "lease_ends"])
    return existing


def fold(network, row: dict, *, now=None):
    """One lease -> (DhcpLeaseObservation, created).  Repeats update counters only.  A released / expired block -> (the binding
    it ends or None, None)."""
    now = now or timezone.now()
    if str(row.get("binding_state") or "").lower() in INACTIVE_STATES and not row.get("relay_address"):
        return _end_of_binding(network, row, now), None
    key = idempotency_key(network, row)
    existing = models.DhcpLeaseObservation.objects.filter(idempotency_key=key).first()
    if existing is not None:
        existing.last_seen, existing.seen_count = now, existing.seen_count + 1
        existing.binding_state = row.get("binding_state", "")[:16]
        existing.lease_starts, existing.lease_ends = row.get("starts"), row.get("ends")
        existing.save(update_fields=["last_seen", "seen_count", "binding_state", "lease_starts", "lease_ends"])
        return existing, False
    upstream = _trusted_upstream(network, row)
    interface = str(row.get("circuit_id") or "")[:64]
    fields = dict(network=network, idempotency_key=key, provider=network.provider, address=row["address"],
                  client_mac=str(row.get("client_mac") or "")[:17], client_id=str(row.get("client_id") or "")[:128],
                  vendor_class=str(row.get("vendor_class") or "")[:128], user_class=str(row.get("user_class") or "")[:128],
                  hostname=str(row.get("hostname") or "")[:64], relay_address=str(row.get("relay_address") or "")[:39],
                  circuit_id=interface, remote_id=str(row.get("remote_id") or "")[:64], relay_trusted=bool(upstream),
                  upstream_device=upstream, upstream_interface=interface if upstream else "",
                  binding_state=str(row.get("binding_state") or "")[:16], lease_starts=row.get("starts"), lease_ends=row.get("ends"),
                  last_seen=now)
    if not upstream:
        return _create(fields, L.UNTRUSTED_RELAY, "RELAY_UNTRUSTED", audit=True), True
    from . import relay_option82

    forged = relay_option82.lease_problem(upstream, fields["relay_address"], interface, now=now)
    if forged:
        # the circuit id is not the one the relay's own read-back says the giaddr port inserts: a client-supplied (forged) option 82,
        # or a relay NMAS has not read -- recorded, never trusted
        untrusted = {**fields, "relay_trusted": False, "upstream_device": "", "upstream_interface": ""}
        return _create(untrusted, L.UNTRUSTED_RELAY, forged, audit=True), True
    session = _session_for_port(network, upstream, interface)
    if session is None:
        return _create(fields, L.UNAUTHORIZED, "UNAUTHORIZED_DEVICE", audit=True), True
    if row["address"] != session.reserved_address:
        return _create({**fields, "session": session, "device": session.device}, L.REFUSED, "BOOTSTRAP_NETWORK_INVALID", audit=True), True
    return _correlate(session, fields, row, now), True


def _create(fields: dict, outcome: str, code: str, *, audit: bool = False, **extra):
    try:
        with transaction.atomic():
            row = models.DhcpLeaseObservation.objects.create(**fields, outcome=outcome, code=code, **extra)
    except IntegrityError:          # a concurrent ingester folded the same binding first
        return models.DhcpLeaseObservation.objects.get(idempotency_key=fields["idempotency_key"])
    if audit:
        events.audit("ZTP_DISCOVERY", Outcome.REFUSED, actor=ACTOR, object_id=fields["network"].name,
                     summary=f"DHCP binding {fields['address']} {outcome.lower()}",
                     metadata={"lease_observation": row.pk, "code": code, "relay_trusted": fields["relay_trusted"]})
    return row


def _correlate(session, fields: dict, row: dict, now):
    device = session.device
    adapter = adapters.get(session.adapter)
    claims, native = adapter.extract_dhcp_claims(row) if adapter else ({}, False)
    identity_claims = {k: v for k, v in claims.items() if k in lifecycle.CLAIM_KEYS}
    identity_result = lifecycle.record_observation(device, kind=models.ObservationKind.IDENTITY, source=models.ObservationSource.DHCP_CLIENT_CLAIM,
                                                   actor=ACTOR, claims=identity_claims, observed_at=row.get("starts") or now)
    attachment_result = lifecycle.record_observation(device, kind=models.ObservationKind.ATTACHMENT,
                                                     source=models.ObservationSource.DHCP_RELAY_ATTACHMENT, actor=ACTOR,
                                                     upstream_device=fields["upstream_device"], upstream_interface=fields["upstream_interface"],
                                                     observed_at=row.get("starts") or now)
    identity_obs = getattr(identity_result, "observation", None)
    attachment_obs = getattr(attachment_result, "observation", None)
    request = {"scope": "DHCP_DISCOVERY", "serial": claims.get("serial", ""), "base_mac": claims.get("base_mac", ""),
               "upstream_device": fields["upstream_device"], "upstream_interface": fields["upstream_interface"],
               "attachment_source": models.ObservationSource.DHCP_RELAY_ATTACHMENT}
    decision = authorization_service.decide(models.BootstrapAuthorization.objects.get(pk=session.authorization_id), request, now=now)
    if decision.decision == authorization_service.Decision.IDENTITY_MISMATCH or (identity_obs and identity_obs.result == models.ObservationResult.MISMATCH):
        outcome, code = L.IDENTITY_MISMATCH, "IDENTITY_MISMATCH"
    elif decision.authorized:
        outcome, code = L.CORRELATED, ""
    else:
        outcome, code = L.REFUSED, decision.decision
    observation = _create({**fields, "session": session, "device": device}, outcome, code,
                          identity_observation=identity_obs, attachment_observation=attachment_obs)
    with transaction.atomic():
        fresh = models.ZtpSession.objects.select_for_update().get(pk=session.pk)
        if outcome == L.CORRELATED and fresh.stage == models.ZtpSessionStage.AWAITING_DISCOVERY:
            fresh.stage = models.ZtpSessionStage.DISCOVERED
        if outcome == L.CORRELATED:
            fresh.discovery = {"lease_observation": observation.pk, "address": observation.address, "relay": observation.relay_address,
                               "upstream": f"{observation.upstream_device}:{observation.upstream_interface}",
                               "native_ztp_request": native, "claimed_keys": sorted(identity_claims), "observed_at": now.isoformat()}
        fresh.version += 1
        fresh.save(update_fields=["stage", "discovery", "version", "updated_at"])
        device = models.ManagedDevice.objects.get(pk=device.pk)
        events.record(device, "ZTP_DISCOVERY", Outcome.RECORDED if outcome == L.CORRELATED else Outcome.REFUSED, actor=ACTOR,
                      actor_kind=events.AUTOMATION, from_state=device.lifecycle_state, to_state=device.lifecycle_state,
                      bootstrap_authorization=session.authorization, observation=attachment_obs,
                      blockers=list(decision.blockers), authorization={"decision": decision.decision, "production_admission": False},
                      evidence={"session": session.session_id, "lease_observation": observation.pk, "address": observation.address,
                                "relay_trusted": True, "upstream": f"{observation.upstream_device}:{observation.upstream_interface}",
                                "native_ztp_request": native, "claimed_keys": sorted(identity_claims),
                                "meaning": "DHCP discovery only: neither identity verification nor bootstrap success"})
    if outcome == L.IDENTITY_MISMATCH:
        # non-retryable: the session closes FAILED (artifact revoked, policy entry dropped at the next apply) -- a later lease
        # on the same port cannot resume this onboarding; the operator investigates and opens a new session
        from . import workflow

        workflow.record_failure(fresh, "IDENTITY_MISMATCH", retryable=False, actor=ACTOR,
                                detail="the device on the authorized port claims another identity: investigate before retrying")
    if native and outcome == L.CORRELATED:
        lifecycle.record_ztp_state(device, models.ZtpState.ENABLED, actor=ACTOR,
                                   evidence={"basis": "the device's native ZTP DHCP request arrived through a trusted relay",
                                             "lease_observation": observation.pk})
    return observation
