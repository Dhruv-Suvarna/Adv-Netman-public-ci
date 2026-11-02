"""``verify_raw_configlet``: the reusable verifier entry point.  Pure Python: no Django view, no ORM writes, no JavaScript.

    static gate  ->  capability  ->  isolated sandbox adapter  ->  structured outcome (result + findings + evidence + provenance)

The outcome distinguishes the static policy result, sandbox availability, the platform parser's verdict, warnings, blocking
findings and provenance.  It never reduces "the process exited zero" to "this is safe": an accepted syntax is reported as syntax
verification with an explicit ``SEMANTICS_NOT_VERIFIED`` note, and a static or sandbox problem is never a PASS.  Verification
never touches a managed lab device -- the only things it can start are the server-owned disposable sandbox images.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from django.utils import timezone

from . import adapters, capability, codes, sandbox, static_gate, text as text_module
from .codes import finding


@dataclass
class VerificationContext:
    actor: str = ""
    runner: object = None      # process runner (defaults to the sandbox boundary; tests inject a fake)
    config: object = None      # sandbox.SandboxConfig (defaults to the server settings)
    adapters: dict | None = None   # adapter registry override (tests inject shared verifier fakes)
    clock: object = time.monotonic
    sleep: object = time.sleep


@dataclass
class VerifierOutcome:
    result: str
    findings: list
    static: dict
    evidence: dict
    provenance: dict
    started_at: object
    finished_at: object


def _registry(context: VerificationContext) -> dict:
    return context.adapters if context.adapters is not None else adapters.REGISTRY


def identity(platform: str, *, context: VerificationContext | None = None) -> dict:
    """The version identity a verification of this platform is pinned to.  Computed WITHOUT starting anything.

    Currency compares a stored verification with this: a change to ANY field makes the earlier result STALE.
    """
    context = context or VerificationContext()
    cap = capability.verification_capability(platform)
    adapter = _registry(context).get(cap.adapter_id)
    try:
        backend = adapter.backend(context.config or sandbox.load_config()) if adapter else ""
    except ValueError:  # a malformed server-owned image setting degrades to STALE / INCOMPLETE; it must never 500 a validation page
        backend = "INVALID_SANDBOX_CONFIGURATION"
    return {
        "verifier_version": codes.VERIFIER_VERSION, "policy_version": codes.POLICY_VERSION,
        "adapter_id": adapter.adapter_id if adapter else "", "adapter_version": adapter.adapter_version if adapter else "",
        "backend": backend,
    }


def verify_raw_configlet(revision, context: VerificationContext | None = None) -> VerifierOutcome:
    """Verify ONE exact revision.  Never raises for an operational problem: every outcome is a structured result."""
    context = context or VerificationContext()
    started = timezone.now()
    findings: list[dict] = []
    gate = static_gate.evaluate(revision.content)
    findings.extend(gate.findings)
    static = {
        "passed": gate.passed, "codes": gate.codes, "policy_version": codes.POLICY_VERSION,
        "stats": text_module.stats(gate.normalized) if gate.normalized is not None else {},
    }
    if gate.normalized is not None and text_module.content_hash(gate.normalized) != revision.content_hash:
        findings.append(finding("RAW_REVISION_INTEGRITY"))
    cap = capability.verification_capability(revision.platform)
    if cap.status != "SUPPORTED":
        findings.append(finding("RAW_PLATFORM_UNSUPPORTED", f"Raw verification is {cap.status} for platform {revision.platform}."))

    evidence: dict = {"sandbox": {"started": False}}
    provenance = {**identity(revision.platform, context=context), "platform": revision.platform, "content_hash": revision.content_hash}
    if not any(f["blocking"] for f in findings):
        adapter = _registry(context).get(cap.adapter_id)
        if adapter is None:
            findings.append(finding("SANDBOX_UNAVAILABLE"))
        else:
            try:
                outcome = adapter.verify(
                    gate.normalized, config=context.config or sandbox.load_config(), runner=context.runner or sandbox.run_process,
                    clock=context.clock, sleep=context.sleep,
                )
                findings.extend(outcome.findings)
                evidence = {"sandbox": {**outcome.sandbox, "started": outcome.started}, **outcome.evidence}
            except Exception:  # noqa: BLE001 - the verifier boundary: a defect is INCOMPLETE, never PASS
                findings.append(finding("VERIFIER_INTERNAL_ERROR"))
    findings = codes.bounded_findings(findings)
    return VerifierOutcome(
        result=codes.derive_result(findings), findings=findings, static=static, evidence=evidence, provenance=provenance,
        started_at=started, finished_at=timezone.now(),
    )
