"""V2 Phase 4 -- management multihoming, management VRF, automatic failover and bootstrap credential retirement.

Modules
    policy      bounded selector / probe settings (the environment can tighten, never disable, a safety bound)
    guard       the probe-target guard: only registered, approved management targets are ever contacted
    paths       NMAS-side attachments, the management-path registry, priority ordering and L1 topology checks
    nmas_side   read-only NMAS host observation and the single-point-of-failure report
    probes      layered L1-L6 verification behind an injectable transport
    selector    failover / hysteresis / failback with hold-down / in-flight safety / restart recovery
    resolve     the ONE address resolver every NMAS device consumer uses (via nsot_live)
    vrf         management-VRF intent, per-platform rendering, validation and the capability classification
    eos_facts   EOS running-config facts used by L2 verification and management-VRF import
    ssh         a pinned, key-only SSH CLI transport (never Docker exec)
    bootstrap_credentials  governed replacement and retirement of the ZTP enrollment credential
"""
