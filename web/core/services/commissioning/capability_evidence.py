"""Recorded LIVE evidence for the Phase 5 / 6 lifecycle capability rows.  An entry exists only for a behaviour proven on real
devices in the isolated fixture (``labs/isolation-commissioning-isolated``); the value names the evidence file (repository
relative).  A unit test or a renderer never adds an entry here.
"""

_DIR = "docs/evidence/v2-phase5-6-isolation-commissioning/live"
LIVE: dict = {
    # Isolation planned from, enforced on and verified against a real cEOS trusted upstream, with hostile-flow traffic proof before
    # any device existed (and again on NEW1 as the upstream of NEW2, 70-downstream-rehearsal.json).
    "arista_ceos:live:ISOLATION": f"{_DIR}/10-isolation-before-device.json",
    # A natively onboarded cEOS commissioned through its ProvisioningRun and the generic execution engine; postcheck PASS while isolated.
    "arista_ceos:live:COMMISSION": f"{_DIR}/40-commission.json",
    # Isolation released under approval with OSPF / route / reachability verification; injected failure restored in 50-*.json.
    "arista_ceos:live:ADMISSION": f"{_DIR}/60-admission.json",
}
