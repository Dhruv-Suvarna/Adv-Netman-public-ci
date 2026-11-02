"""The durable, idempotent, at-least-once dispatcher of lifecycle outbox events to the Phase 8 consumers.

For each due event (``outbox.pending``: PENDING, or FAILED past its backoff) in creation order:
    1. lock the event row (``select_for_update``, ``skip_locked`` where the database supports it) and re-check it is undelivered
       -- two dispatchers never apply the same event concurrently
    2. hand it to its topic's consumer, which applies it only when ``event.sequence`` is newer than the projection's
       ``last_sequence`` (older / out-of-order facts are acknowledged as SUPERSEDED, never regressing state)
    3. acknowledge with ``outbox.deliver`` in the SAME transaction as the consumer's writes (exactly-once projection effect)
    4. on failure the consumer's writes roll back and ``outbox.fail`` records a FIXED code (never exception text) with backoff

Consumers re-derive their state from the NMAS database, so replays, crashes and restarts converge.
"""

from __future__ import annotations

from django.db import DatabaseError, connection, transaction

from ... import models
from ..commissioning import outbox
from . import facts, monitoring, nsot, topology

Topic, State = models.OutboxTopic, models.OutboxState
ACTOR = "system:nmas-infrastructure"
CONSUMERS = {
    "nsot": (nsot, (Topic.NSOT_DEVICE_ADMITTED, Topic.NSOT_DEVICE_STATE)),
    "topology": (topology, (Topic.TOPOLOGY_DEVICE_ADMITTED, Topic.TOPOLOGY_DEVICE_STATE)),
    "monitoring": (monitoring, (Topic.MONITORING_TARGET_ADMITTED, Topic.MONITORING_TARGET_STATE)),
}
TOPIC_CONSUMER = {topic: name for name, (_module, topics) in CONSUMERS.items() for topic in topics}


def consumer_for(topic: str) -> tuple[str, object]:
    """(consumer name, module) for ``topic``.  Raises KeyError for an unknown topic."""
    name = TOPIC_CONSUMER[topic]
    return name, CONSUMERS[name][0]


def due(consumer: str | None = None, *, limit: int = 50, now=None) -> list:
    """Due events for one consumer (or all), oldest first."""
    if consumer is not None and consumer not in CONSUMERS:
        raise ValueError(f"unknown consumer {str(consumer)[:20]}")
    topics = CONSUMERS[consumer][1] if consumer else tuple(TOPIC_CONSUMER)
    rows = [e for topic in topics for e in outbox.pending(topic, limit=limit, now=now)]
    return sorted(rows, key=lambda e: (e.created_at, e.pk))[:max(1, min(int(limit), 500))]


def _lock(event):
    kwargs = {"skip_locked": True} if connection.features.has_select_for_update_skip_locked else {}
    return models.LifecycleOutboxEvent.objects.select_for_update(**kwargs).filter(
        pk=event.pk, state__in=(State.PENDING, State.FAILED)).first()


def dispatch_one(event, *, actor: str = ACTOR, nsot_client=None) -> dict:
    """Apply and acknowledge one event.  -> {event, topic, consumer, result, code}; result APPLIED | SUPERSEDED | SKIPPED | FAILED."""
    name, module = consumer_for(event.topic)
    row = {"event": event.pk, "topic": event.topic, "consumer": name, "device": event.device_id, "sequence": event.sequence,
           "result": "", "code": ""}
    try:
        with transaction.atomic():
            locked = _lock(event)
            if locked is None:
                row["result"] = "SKIPPED"          # delivered (or claimed) by another dispatcher
                return row
            row["result"] = module.apply(locked, nsot_client=nsot_client)
            outbox.deliver(locked, consumer=getattr(module, "CONSUMER", name), actor=actor)
        return row
    except facts.ConsumerError as exc:
        code = exc.code
    except (DatabaseError, LookupError, OSError, TypeError, ValueError):   # a retryable consumer failure: a fixed code, never its text
        code = f"{name.upper()}_CONSUMER_ERROR"
    outbox.fail(event, code=code)
    hook = getattr(module, "mark_failed", None)
    if hook is not None:
        hook(event, code)
    row.update(result="FAILED", code=code)
    return row


def dispatch(consumer: str | None = None, *, limit: int = 50, actor: str = ACTOR, nsot_client=None, now=None) -> dict:
    """One batch: every due event (up to ``limit``) for ``consumer`` (or all).  -> {processed, results, counts}."""
    results = [dispatch_one(event, actor=actor, nsot_client=nsot_client) for event in due(consumer, limit=limit, now=now)]
    counts = {}
    for item in results:
        counts[item["result"]] = counts.get(item["result"], 0) + 1
    return {"consumer": consumer or "all", "processed": len(results), "counts": counts, "results": results}


def status() -> dict:
    """Queue and projection overview (codes only, no payloads)."""
    queue = {}
    for topic, state in models.LifecycleOutboxEvent.objects.values_list("topic", "state"):
        consumer = TOPIC_CONSUMER.get(topic, "unknown")
        bucket = queue.setdefault(consumer, {s: 0 for s in State.values})
        bucket[state] = bucket.get(state, 0) + 1
    failures = [{"event": e.pk, "topic": e.topic, "device": e.device.device_id, "attempts": e.attempts, "code": e.last_error,
                 "next_attempt_at": e.next_attempt_at.isoformat() if e.next_attempt_at else ""}
                for e in models.LifecycleOutboxEvent.objects.select_related("device").filter(state=State.FAILED).order_by("-pk")[:20]]
    return {"queue": queue, "failures": failures, "topology": topology.summary(), "monitoring": monitoring.summary(),
            "nsot": nsot.summary()}
