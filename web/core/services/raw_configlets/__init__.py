"""Phase-18 Raw Configlets + isolated verifier / sandbox.

A Raw Configlet is an EXPLICIT escape hatch from the structured Device Builder: operator-authored network *configuration
statements* for one device that the structured schema cannot express.  It is not an escape hatch from validation,
verification, dependency ordering, planning, execution eligibility, locking, audit or postcheck.

Layout (each module has ONE job; nothing here executes a Configlet on a device or touches NetBox / Git / Containerlab):

    codes.py         limits, versions, the result / currency vocabulary and the stable finding-code catalogue
    text.py          deterministic normalization, content hash, the command stream shared by verifier AND executor
    static_gate.py   the deterministic static safety gate (size, encoding, secrets, shell / exec-mode / mode-control)
    capability.py    the evidence-based verification and execution capability matrices (four-state vocabulary)
    assertions.py    the bounded catalogue of structured, server-owned postcheck assertions (no arbitrary show commands)
    sandbox.py       trusted server-owned sandbox configuration, the ONLY subprocess boundary, output sanitization
    adapters.py      per-platform verifier adapters (FRR ``vtysh --dryrun``; cEOS aborted config session)
    verifier.py      ``verify_raw_configlet``: static gate -> capability -> sandbox adapter -> structured outcome (no DB)
    store.py         Raw Configlet / immutable revision persistence, effective Change input entries, audit
    verification.py  append-only verification runs: lease, duplicate-run guard, currency, current-result reuse

Architecture rules enforced by contract tests: browser text never reaches a process argv or a shell; every image / backend
choice is server-owned configuration; verification NEVER targets a managed lab device; execution payloads are always
re-read from the pinned immutable revision; only the Phase-17 engine can send a Raw Configlet to a real device.
"""
