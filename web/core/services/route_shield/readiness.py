"""Which shielded transitions may execute.  Enforced by ``runner.execute`` before anything is read or assessed.

``READY`` means proven loss-free on the disposable sandbox AND authorized for the managed network.  Nothing here is
configurable at run time: changing a state is a reviewed code change that cites its evidence.
"""

from __future__ import annotations

STATIC_IPV6_TO_ISIS = "STATIC_IPV6_TO_ISIS"          # baseline migration (its automatic reverse path included)
ISIS_TO_STATIC_IPV6_REVERT = "ISIS_TO_STATIC_IPV6_REVERT"   # operator-initiated revert of a COMPLETED baseline migration
ISIS_METRIC_STEER = "ISIS_METRIC_STEER"              # planned maintenance drain / restore of R1 or R2, northbound
OSPFV3_EXTERNAL_METRIC_STEER = "OSPFV3_EXTERNAL_METRIC_STEER"   # the same, southbound: the router's own OSPFv3 external metric

READY, NOT_READY, NOT_AUTHORIZED = "READY", "NOT_READY", "PROVEN_NOT_AUTHORIZED"

# Evidence: docs/V2_LOSSLESS_ROUTE_SHIELD.md sections 6 and 8 (runs proof20kc, drain20 and the lifecycle runs).  All are
# proven on the sandbox.  STATIC_IPV6_TO_ISIS: the forwarding mechanism (R3/R4 covers included) is the accepted design and
# NMAS runs it as one transaction (lifecycle.py).  Authorized for production by the operator on 2026-10-12, after the
# 16/16 go/no-go checklist passed on deployed 044754da3841a8f1c8adf0df25839a398b3bb22c (dry run PASS, production precheck
# PASS, 0 write attempts): permanent IS-IS on R1/R2/S1/S2 only, R3/R4 stay OSPFv3 and get the temporary covers only.
# The revert and the metric steer are NOT authorized.
# ISIS_METRIC_STEER moves the northbound direction only: it is not a complete R1/R2 maintenance drain.
READINESS = {
    STATIC_IPV6_TO_ISIS: READY,
    ISIS_TO_STATIC_IPV6_REVERT: NOT_AUTHORIZED,
    ISIS_METRIC_STEER: NOT_AUTHORIZED,
    OSPFV3_EXTERNAL_METRIC_STEER: NOT_READY,
}


def refusal(kind: str) -> str:
    """Why a transition of ``kind`` must not run, or '' when it may.  An unknown kind is never executable."""
    state = READINESS.get(kind, NOT_READY)
    return "" if state == READY else f"TRANSITION_{state}: {kind or 'UNKNOWN'}"
