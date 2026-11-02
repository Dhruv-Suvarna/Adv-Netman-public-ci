"""Capability evidence framework (V2 Phase 1) -- ONE aggregation layer over the existing, legitimately separate
registries, plus durable empirical evidence.

The registries stay where they are because they answer different questions:

* ``platform_drivers``                 can NMAS RENDER this feature for this platform (and is it selectable in the UI)?
* ``execution.capability``            can the executor APPLY / COMPENSATE this object type on this platform?
* ``execution.transport_capability``  which deployment transport is real for this platform?
* ``config_import``                    is there a parser (live-captured or fixture-only) for this platform?

``registry.capability_record`` reads all of them for one (platform, feature) and adds the newest EMPIRICAL evidence
(``CapabilityEvidence`` rows: automated tests, live read/write/post-write/compensation/runtime observations) per axis.
The UI is driven by the derived summary -- never by renderer support alone.  Version 2 Phase 4 completes the matrix by
recording evidence through ``evidence.record_evidence``; no rewrite of this layer is needed for that.

Not to be confused with Tier-3 (NMAS application validation) or network-configuration validation (V2 Phase 2): the
``CONFIG_VALIDATION`` axis only RECORDS whether the latter exists per feature.
"""
