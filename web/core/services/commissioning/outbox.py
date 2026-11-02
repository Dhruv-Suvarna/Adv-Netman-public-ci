"""Durable, idempotent hand-off of an admitted device to the consumers of Phase 8 (NetBox / NSOT, the topology graph, monitoring).

An event is written in the SAME transaction that made its fact true (the admission), so a fact never exists without its hand-off and
a hand-off never exists without its fact.  Delivery is at least once; the consumer applies it at most once by ``idempotency_key``.
Each payload is a versioned contract (``CONTRACTS``) of identifiers, addresses and digests only -- never a credential, key or token.
Phase 6 recorded and validated the admission contracts.  Phase 8 adds lifecycle FACTS (``record_fact``): one event per
consumer topic (NetBox, topology, monitoring) with a per-device monotonic ``sequence``, contract version 2, written in the
caller's transaction; ``core.services.infrastructure.dispatcher`` consumes them.  A failed delivery is retried with
exponential backoff (``next_attempt_at``) -- the first retry is immediate (next batch), then 2, 4, 8 ... minutes (capped).
"""

from __future__ import annotations

import hashlib
import json

from datetime import timedelta

from django.conf import settings
from django.db import transaction
from django.db.models import Max, Q
from django.utils import timezone

from ... import models
from .. import secret_policy
from ..devices import events

Topic, State = models.OutboxTopic, models.OutboxState
Outcome = models.DeviceLifecycleEventOutcome
CONTRACT_VERSION = 1
CONTRACTS = {
    Topic.NSOT_DEVICE_ADMITTED: ("device_id", "name", "platform", "role", "admission", "admitted_at", "management", "provisioning_run",
                                 "config_digest"),
    Topic.TOPOLOGY_DEVICE_ADMITTED: ("device_id", "name", "admission", "links", "dependencies"),
    Topic.MONITORING_TARGET_ADMITTED: ("device_id", "name", "platform", "admission", "address", "management_source", "checks"),
}
# V2 Phase 8 -- lifecycle facts (contract version 2): identifiers and states only, never an address list or a credential
FACT_CONTRACT_VERSION = 2
FACT_FIELDS = ("device_id", "name", "platform", "role", "fact", "lifecycle_state", "admission_state", "sequence", "detail")
FACT_TOPICS = (Topic.NSOT_DEVICE_STATE, Topic.TOPOLOGY_DEVICE_STATE, Topic.MONITORING_TARGET_STATE)
CONTRACTS.update({topic: FACT_FIELDS for topic in FACT_TOPICS})

DISCOVERED, IDENTITY_VERIFIED, BOOTSTRAPPED, ISOLATED = "DISCOVERED", "IDENTITY_VERIFIED", "BOOTSTRAPPED", "ISOLATED"
COMMISSIONING_READY, COMMISSIONING_STARTED, COMMISSIONED, ADMITTED = "COMMISSIONING_READY", "COMMISSIONING_STARTED", "COMMISSIONED", "ADMITTED"
ATTACHMENT_CHANGED, MANAGEMENT_PATH_CHANGED = "ATTACHMENT_CHANGED", "MANAGEMENT_PATH_CHANGED"
MAINTENANCE_ENTERED, MAINTENANCE_EXITED = "MAINTENANCE_ENTERED", "MAINTENANCE_EXITED"
DECOMMISSION_REQUESTED, DECOMMISSIONED, DECOMMISSION_CANCELLED, RESTORED = (
    "DECOMMISSION_REQUESTED", "DECOMMISSIONED", "DECOMMISSION_CANCELLED", "RESTORED")
HEALTH_CHANGED, MONITORING_ELIGIBILITY_CHANGED = "HEALTH_CHANGED", "MONITORING_ELIGIBILITY_CHANGED"
FACTS = frozenset({DISCOVERED, IDENTITY_VERIFIED, BOOTSTRAPPED, ISOLATED, COMMISSIONING_READY, COMMISSIONING_STARTED, COMMISSIONED,
                   ADMITTED, ATTACHMENT_CHANGED, MANAGEMENT_PATH_CHANGED, MAINTENANCE_ENTERED, MAINTENANCE_EXITED,
                   DECOMMISSION_REQUESTED, DECOMMISSIONED, DECOMMISSION_CANCELLED, RESTORED, HEALTH_CHANGED,
                   MONITORING_ELIGIBILITY_CHANGED})
# lifecycle-event action -> fact, for the automatic emission at the ``events.record`` choke point.  DECOMMISSION* / RESTORE*
# are deliberately absent (Phase 7 records those facts explicitly), and OUTBOX_* can never emit (no recursion).
ACTION_FACTS = {
    "DISCOVER": DISCOVERED, "VERIFY_IDENTITY": IDENTITY_VERIFIED, "BOOTSTRAP": BOOTSTRAPPED, "ISOLATE": ISOLATED,
    "COMMISSION_READY": COMMISSIONING_READY, "COMMISSION": COMMISSIONING_STARTED, "COMMISSION_COMPLETE": COMMISSIONED,
    "COMMISSION_ABORT": ISOLATED, "COMMISSION_READY_WITHDRAW": ISOLATED, "FAIL": HEALTH_CHANGED,
    "ATTACHMENT_APPROVE": ATTACHMENT_CHANGED, "ATTACHMENT_REVOKE": ATTACHMENT_CHANGED, "OBSERVE_ATTACHMENT": ATTACHMENT_CHANGED,
    "MGMT_PATH_APPROVE": MANAGEMENT_PATH_CHANGED, "MGMT_PATH_REVOKE": MANAGEMENT_PATH_CHANGED,
    **{f"MGMT_{kind}": MANAGEMENT_PATH_CHANGED for kind in ("ACTIVATE", "FAILOVER", "FAILBACK", "LOST", "RECOVERED", "DEACTIVATE",
                                                            "RESTART_RECOVERY")},
}
EMITTING_OUTCOMES = frozenset({Outcome.ADVANCED, Outcome.RECORDED})
DETAIL_MAX_KEYS, DETAIL_MAX_BYTES = 16, 2048
BACKOFF_BASE_SECONDS, BACKOFF_MAX_SECONDS = 60, 3600


class OutboxError(ValueError):
    pass


def digest(payload: dict) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def key_for(topic: str, subject: str) -> str:
    """The consumer-side idempotency key: one per (topic, admitted fact)."""
    return hashlib.sha256(f"{topic}|{subject}".encode()).hexdigest()


def validate(topic: str, payload: dict) -> list[str]:
    """Contract problems ([] = valid): a known topic, every required field present, nothing secret-shaped."""
    if topic not in CONTRACTS:
        return [f"unknown topic {str(topic)[:40]}"]
    problems = [f"missing {name}" for name in CONTRACTS[topic] if name not in payload]
    extra = sorted(set(payload) - set(CONTRACTS[topic]))
    if extra:
        problems.append(f"unexpected {extra[:5]}")
    if secret_policy.redact(payload) != payload:
        problems.append("secret-shaped content")
    return problems


def record(device, topic: str, payload: dict, *, subject: str, actor: str):
    """Write one event (inside the caller's transaction).  Idempotent: the same subject with the same payload returns the existing
    event; the same subject with a DIFFERENT payload is refused (a fact never silently changes)."""
    problems = validate(topic, payload)
    if problems:
        raise OutboxError("; ".join(problems))
    key, body_digest = key_for(topic, subject), digest(payload)
    existing = models.LifecycleOutboxEvent.objects.filter(idempotency_key=key).first()
    if existing is not None:
        if existing.payload_digest != body_digest:
            raise OutboxError("the subject was already recorded with a different payload")
        return existing
    event = models.LifecycleOutboxEvent.objects.create(device=device, topic=topic, contract_version=CONTRACT_VERSION, idempotency_key=key,
                                                       payload=payload, payload_digest=body_digest)
    events.record(device, "OUTBOX_RECORD", Outcome.RECORDED, actor=actor, actor_kind=events.AUTOMATION if actor.startswith("system:") else events.HUMAN,
                  from_state=device.lifecycle_state, to_state=device.lifecycle_state,
                  evidence={"topic": topic, "event": event.pk, "payload_digest": body_digest})
    return event


def admission_payloads(admission) -> dict:
    """{topic: payload} for one ADMITTED production admission (identifiers, addresses and digests only)."""
    device, record_ = admission.device, admission.commissioning
    run, policy = record_.provisioning_run, admission.isolation_policy
    management = {k: v for k, v in (getattr(run, "management", None) or {}).items() if k in ("interface", "ipv4", "ipv6")}
    admitted_at = (admission.finished_at or timezone.now()).isoformat()
    common = {"device_id": device.device_id, "name": device.name, "admission": admission.admission_id}
    links = [{"local_interface": a.local_interface, "upstream_device": a.upstream_device, "upstream_interface": a.upstream_interface}
             for a in models.DeviceAttachment.objects.filter(device=device, approval_state=models.AttachmentApproval.APPROVED)]
    dependencies = sorted(d.upstream.name for d in models.CommissioningDependency.objects.select_related("upstream").filter(
        device=device, state=models.DependencyState.ACTIVE))
    expected = admission.expectations or {}
    checks = (["reachability"] + (["ospf_adjacency"] if expected.get("ospf_neighbors") else [])
              + (["ospfv3_adjacency"] if expected.get("ospfv3_neighbors") else []) + ["routes"])
    return {
        Topic.NSOT_DEVICE_ADMITTED: {**common, "platform": device.platform, "role": device.role, "admitted_at": admitted_at,
                                     "management": management, "provisioning_run": getattr(run, "prov_id", ""),
                                     "config_digest": getattr(run, "post_config_digest", "")},
        Topic.TOPOLOGY_DEVICE_ADMITTED: {**common, "links": links or [{"local_interface": policy.attachment.local_interface,
                                                                       "upstream_device": policy.upstream_device,
                                                                       "upstream_interface": policy.upstream_interface}],
                                         "dependencies": dependencies},
        Topic.MONITORING_TARGET_ADMITTED: {**common, "platform": device.platform, "address": str(management.get("ipv4", "")).split("/")[0],
                                           "management_source": "COMMISSIONING", "checks": checks},
    }


def record_admission(admission, *, actor: str) -> list:
    """The three hand-offs of one admission (inside the admission's own transaction)."""
    return [record(admission.device, topic, payload, subject=admission.admission_id, actor=actor)
            for topic, payload in admission_payloads(admission).items()]


def pending(topic: str | None = None, *, limit: int = 100, now=None):
    """Undelivered events that are due: PENDING, or FAILED whose backoff (``next_attempt_at``) has elapsed."""
    now = now or timezone.now()
    rows = models.LifecycleOutboxEvent.objects.filter(state__in=(State.PENDING, State.FAILED)).filter(
        Q(next_attempt_at__isnull=True) | Q(next_attempt_at__lte=now))
    if topic:
        rows = rows.filter(topic=topic)
    return list(rows.order_by("created_at", "id")[:max(1, min(int(limit), 500))])


def deliver(event, *, consumer: str, actor: str):
    """The consumer acknowledged ``event`` (applied, or already applied by its key).  Idempotent on a delivered event."""
    with transaction.atomic():
        fresh = models.LifecycleOutboxEvent.objects.select_for_update().get(pk=event.pk)
        if fresh.state == State.DELIVERED:
            return fresh
        fresh.state, fresh.delivered_at, fresh.consumer, fresh.last_error = State.DELIVERED, timezone.now(), str(consumer)[:64], ""
        fresh.attempts += 1
        fresh.save(update_fields=["state", "delivered_at", "consumer", "last_error", "attempts"])
        device = models.ManagedDevice.objects.select_for_update().get(pk=fresh.device_id)
        events.record(device, "OUTBOX_DELIVER", Outcome.RECORDED, actor=actor, actor_kind=events.AUTOMATION if actor.startswith("system:") else events.HUMAN,
                      from_state=device.lifecycle_state, to_state=device.lifecycle_state,
                      evidence={"topic": fresh.topic, "event": fresh.pk, "consumer": fresh.consumer})
    return fresh


def backoff_seconds(attempts: int) -> int:
    """Delay before the next retry after ``attempts`` failed deliveries: 0 after the first (retried in the next batch), then
    exponential from ``NMAS_OUTBOX_BACKOFF_BASE_SECONDS`` (default 60 s) up to ``NMAS_OUTBOX_BACKOFF_MAX_SECONDS`` (1 h)."""
    attempts = max(0, int(attempts))
    if attempts <= 1:
        return 0
    base = int(getattr(settings, "NMAS_OUTBOX_BACKOFF_BASE_SECONDS", BACKOFF_BASE_SECONDS))
    cap = int(getattr(settings, "NMAS_OUTBOX_BACKOFF_MAX_SECONDS", BACKOFF_MAX_SECONDS))
    return int(min(cap, base * (2 ** min(attempts - 2, 20))))


def fail(event, *, code: str, now=None):
    """A delivery attempt failed (retryable).  ``code`` is a fixed token, never the consumer's error text.  The next attempt
    is scheduled with exponential backoff (``backoff_seconds``)."""
    with transaction.atomic():
        fresh = models.LifecycleOutboxEvent.objects.select_for_update().get(pk=event.pk)
        if fresh.state == State.DELIVERED:
            raise OutboxError("a delivered event cannot fail")
        fresh.state, fresh.attempts, fresh.last_error = State.FAILED, fresh.attempts + 1, str(code)[:64]
        fresh.next_attempt_at = (now or timezone.now()) + timedelta(seconds=backoff_seconds(fresh.attempts))
        fresh.save(update_fields=["state", "attempts", "last_error", "next_attempt_at"])
    return fresh


# --- V2 Phase 8: lifecycle facts --------------------------------------------------------------------------------------------
def fact_detail(detail: dict | None) -> dict:
    """The bounded, secret-free ``detail`` of a fact.  Refuses (OutboxError) anything secret-shaped or oversized -- it is never
    silently redacted into the durable record."""
    detail = dict(detail or {})
    if len(detail) > DETAIL_MAX_KEYS:
        raise OutboxError("fact detail has too many keys")
    if secret_policy.redact(detail) != detail:
        raise OutboxError("secret-shaped content")
    if len(json.dumps(detail, sort_keys=True, default=str)) > DETAIL_MAX_BYTES:
        raise OutboxError("fact detail is too large")
    return json.loads(json.dumps(detail, sort_keys=True, default=str))


def next_sequence(device) -> int:
    """The next per-device fact sequence (call under the device row lock, inside a transaction): max(recorded) + 1."""
    current = models.LifecycleOutboxEvent.objects.filter(device=device).aggregate(top=Max("sequence"))["top"] or 0
    return int(current) + 1


def fact_payload(device, fact: str, sequence: int, detail: dict, *, lifecycle_state: str = "") -> dict:
    return {"device_id": device.device_id, "name": device.name, "platform": device.platform, "role": device.role or "", "fact": fact,
            "lifecycle_state": lifecycle_state or device.lifecycle_state, "admission_state": device.admission_state,
            "sequence": int(sequence), "detail": detail}


def record_fact(device, fact: str, *, actor: str, detail: dict | None = None, lifecycle_state: str = "") -> list:
    """Record one lifecycle FACT for every infrastructure consumer (NetBox, topology, monitoring), inside the caller's
    transaction.  -> the three ``LifecycleOutboxEvent`` rows, sharing one per-device monotonic ``sequence``.

    Idempotency key per (topic, device, fact, sequence).  The payload is identifiers and states only (contract version 2);
    ``detail`` is bounded and refused when secret-shaped.  Writes no lifecycle event of its own (the caller's event is the
    evidence), so it can be called from the ``events.record`` choke point without recursion."""
    if fact not in FACTS:
        raise OutboxError(f"unknown fact {str(fact)[:40]}")
    if device is None or device.pk is None:
        raise OutboxError("a fact needs a recorded device")
    clean = fact_detail(detail)
    rows = []
    with transaction.atomic():
        models.ManagedDevice.objects.select_for_update().filter(pk=device.pk).first()      # serialize sequence allocation
        sequence = next_sequence(device)
        for topic in FACT_TOPICS:
            payload = fact_payload(device, fact, sequence, clean, lifecycle_state=lifecycle_state)
            problems = validate(topic, payload)
            if problems:
                raise OutboxError("; ".join(problems))
            key = key_for(topic, f"{device.device_id}|{fact}|{sequence}")
            existing = models.LifecycleOutboxEvent.objects.filter(idempotency_key=key).first()
            if existing is not None:
                rows.append(existing)
                continue
            rows.append(models.LifecycleOutboxEvent.objects.create(
                device=device, topic=topic, sequence=sequence, contract_version=FACT_CONTRACT_VERSION, idempotency_key=key,
                payload=payload, payload_digest=digest(payload)))
    return rows


def fact_for_action(action: str, outcome: str) -> str:
    """The fact a lifecycle-event action emits automatically ('' = none).  Never for refusals, idempotent repeats, outbox
    bookkeeping (no recursion) or DECOMMISSION* / RESTORE* (Phase 7 records those explicitly: no double emission)."""
    action = str(action or "")
    if outcome not in EMITTING_OUTCOMES or action.startswith(("OUTBOX_", "DECOMMISSION", "RESTORE")):
        return ""
    return ACTION_FACTS.get(action, "")


def emit_for_event(device, action: str, outcome: str, *, actor: str, to_state: str = "", evidence: dict | None = None) -> list:
    """The automatic hook called by ``events.record`` for every lifecycle event: records the mapped fact, if any.  Disabled by
    ``settings.NMAS_INFRASTRUCTURE_FACTS = False``."""
    fact = fact_for_action(action, outcome)
    if not fact or not getattr(settings, "NMAS_INFRASTRUCTURE_FACTS", True):
        return []
    keep = ("path", "transition", "from", "to", "reason", "attachment", "approval_state", "was_active")
    detail = {"action": action[:40], **{k: v for k, v in (evidence or {}).items() if k in keep and isinstance(v, (str, int, bool))}}
    detail = {k: (v[:120] if isinstance(v, str) else v) for k, v in secret_policy.redact(detail).items()
              if not (isinstance(v, str) and v == secret_policy.REDACTED)}
    return record_fact(device, fact, actor=actor, detail=detail, lifecycle_state=to_state)
