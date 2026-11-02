"""V2 Phase 5 -- trusted-upstream isolation (see docs/V2_TRUSTED_ISOLATION_COMMISSIONING.md).

``service`` is the one writer of ``IsolationPolicy``; ``intent`` and ``eos`` are pure; ``transaction`` is the governed
single-device configuration transaction shared with production admission (``core.services.commissioning``).
"""
