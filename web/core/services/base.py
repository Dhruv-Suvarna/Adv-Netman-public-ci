"""
Shared shape for service-boundary placeholders.

Phase 3 establishes the boundary between Django views/templates and the
project's real automation/monitoring/NSOT logic (modules/, netbox/,
monitoring/) without wiring any of it up yet. Every service function in
core/services/ returns data shaped like ``not_integrated(...)`` below until
its real phase lands -- never fabricated numbers/status that looks live.
"""

from __future__ import annotations


def not_integrated(message: str, **extra) -> dict:
    payload = {"status": "not_integrated", "message": message}
    payload.update(extra)
    return payload
