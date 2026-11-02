"""V2 Phase 8: event-driven infrastructure projections (NetBox / NSOT, the NetworkX topology, monitoring, Grafana).

Every projection is a consumer of the durable lifecycle outbox (``core.services.commissioning.outbox``) driven by
``dispatcher``; each one re-derives its state from the NMAS database (restart-safe) and applies facts in per-device
``sequence`` order.  See docs/V2_DYNAMIC_INFRASTRUCTURE.md.
"""
