"""Phase-13 Python-owned Tier-2 project-aware Change validation.

Package layout (one concern per module, no giant validator):

    findings.py          vocabulary, stable finding codes, Finding, sanitizing
    snapshot.py          deterministic accepted-intent snapshot + SHA-256
    sources.py           read-only NetBox / topology / inventory / capability adapters
    context.py           parsed project model shared by every validator
    capabilities.py      capability + renderer-consistency validation
    addressing.py        IP collision, DHCP, reservation, VLAN 200, AUTO derivation
    topology.py          link / interface / VLAN / MTU cross-endpoint checks
    routing.py           static / OSPF / BGP / RIP / router-id checks
    fhrp.py              FHRP / VARP domain checks
    services_policy.py   NAT / DHCP relay / DNS / PBR project checks
    acl.py               conservative ACL first-match traffic-impact analysis
    dependency_graph.py  semantic dependency graph, missing edges, cycles
    engine.py            orchestration, status derivation, determinism

NetBox is passive storage: nothing in this package writes to it, to Git, to a
device, or to Containerlab.  See docs/CHANGE_VALIDATION_AND_DEPENDENCIES.md.
"""
