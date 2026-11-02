"""The provisioning hooks of the execution engine.  Deliberately tiny and lazily bound.

The execution engine is the ONE authoritative execution boundary.  Provisioning adds no second entry point: it contributes policy to that
boundary through these three functions, which the engine calls for every Change and which do nothing for a Change that is not a
provisioning candidate.

    blockers(change)                 part of the read-only eligibility gate (approval, staleness, bootstrap reachability)
    before_first_mutation(change)    inside the device lock, after assessment, before the first write (baseline digest)
    after_execution(run)             after the run was finalised (record success, or reconcile a failure)

The lifecycle module is imported inside each function: it depends on the planning / validation / health services, which must not be import
dependencies of the execution engine.
"""

from __future__ import annotations


def blockers(change) -> list[dict]:
    from . import lifecycle

    return lifecycle.execution_blockers(change)


def before_first_mutation(change) -> list[dict]:
    from . import lifecycle

    return lifecycle.before_first_mutation(change)


def after_execution(run) -> None:
    from . import lifecycle

    lifecycle.after_execution(run)
