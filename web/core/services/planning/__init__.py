"""Phase-14 planning package: validated intent -> granular Configlets -> ordered deployment PLAN.

    priorities.py           the one object-type -> (priority, operation, namespace) catalogue
    snippets.py             driver-based (authoritative renderer) snippet extraction
    configlet_factory.py    graph node -> Configlet spec(s)
    dependency_mapping.py   Phase-13 typed edges -> Configlet dependencies
    ordering.py             deterministic, cycle-safe topological order
    builder.py              eligibility, compute (pure), persist (atomic), currency
    serialization.py        sanitized machine-readable report

Use ``core.services.change_plan_service``; do not import these from views.
"""
