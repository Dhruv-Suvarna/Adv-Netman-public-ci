"""Executable runbook framework (pure Python: no ORM, no I/O).

* ``Obs`` / ``EvidenceView``   immutable normalized observations as the tests see them.  A test can only *read* evidence through
                               ``Ctx.need()``; a missing/stale/untrusted/unsupported reading raises ``Gap`` which the executor turns into
                               INCONCLUSIVE / UNAVAILABLE -- missing evidence is never evidence of absence (spec 2.1, UT-006).
* ``TestSpec`` / ``Hypothesis`` / ``Runbook``   the typed test DAG.  ``requires`` = hard data dependency (the test is NOT_APPLICABLE when
                               the prerequisite did not produce what it needs); ``after`` = ordering only.
* ``Result`` / ``Finding``     what a test returns.  PASS = the healthy expectation held, FAIL = the fault condition is present.

Observation addressing: ``key`` is the canonical metric (``interface.oper_state``), ``device`` the probed device and ``subject`` the
optional per-object qualifier (interface, neighbour, prefix, name).  Persisted as target=<device>, key="<key>@<subject>".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable, Iterable

from .. import contracts as c

APPLICABILITY = ("EXECUTED", "NOT_APPLICABLE", "UNAVAILABLE", "UNSAFE_TO_EXECUTE", "SKIPPED_AFTER_CONFIRMED_ISOLATION")
# applicability status -> persisted verdict (contracts.VERDICTS has no dedicated values for these; status is kept in `observed`).
STATUS_VERDICT = {"NOT_APPLICABLE": "SKIPPED", "UNSAFE_TO_EXECUTE": "SKIPPED", "SKIPPED_AFTER_CONFIRMED_ISOLATION": "SKIPPED",
                  "UNAVAILABLE": "UNAVAILABLE"}
UNAVAILABLE_REASONS = ("PERMISSION_DENIED", "UNSUPPORTED", "COMMAND_NOT_ALLOWED", "NOT_ADMITTED", "PARSER_UNAVAILABLE", "REFUSED")
KEY_SEP = "@"
CONTEXT, DISCRIMINATING, SAFETY = "CONTEXT", "DISCRIMINATING", "SAFETY"


class Gap(Exception):
    """Evidence needed by a test is not usable.  ``status`` is UNAVAILABLE (capability/permission) or INCONCLUSIVE (absent/stale)."""

    def __init__(self, status: str, reason: str):
        super().__init__(reason)
        self.status, self.reason = status, reason


def split_key(stored_key: str) -> tuple[str, str]:
    key, _, subject = stored_key.partition(KEY_SEP)
    return key, subject


def join_key(key: str, subject: str = "") -> str:
    return f"{key}{KEY_SEP}{subject}" if subject else key


@dataclass(frozen=True)
class Obs:
    key: str
    device: str
    subject: str
    value: Any
    observed_at: datetime
    quality: str = "GOOD"
    max_age_seconds: int = 300
    record_id: str = ""
    evidence_ids: tuple[str, ...] = ()
    is_missing: bool = False
    missing_reason: str = ""
    unit: str = ""
    freshness: str = c.FRESH

    @property
    def ref(self) -> str:
        return f"{self.key}{KEY_SEP + self.subject if self.subject else ''}@{self.device}"


class EvidenceView:
    """Latest-per-(key, device, subject) lookup with freshness evaluated against a fixed ``now``."""

    def __init__(self, observations: Iterable[Obs], now: datetime):
        self.now = now
        self._latest: dict[tuple[str, str, str], Obs] = {}
        for o in observations:
            fr = c.freshness(o.observed_at, o.max_age_seconds, now, quality=o.quality, is_missing=o.is_missing)
            o = Obs(**{**o.__dict__, "freshness": fr})
            k = (o.key, o.device, o.subject)
            prev = self._latest.get(k)
            if prev is None or o.observed_at >= prev.observed_at:
                self._latest[k] = o

    def latest(self, key: str, device: str, subject: str = "") -> Obs | None:
        return self._latest.get((key, device, subject))

    def each(self, key: str, device: str | None = None) -> list[Obs]:
        return sorted((o for (k, d, _s), o in self._latest.items() if k == key and (device is None or d == device)),
                      key=lambda o: (o.device, o.subject))

    def all(self) -> list[Obs]:
        return list(self._latest.values())


@dataclass
class Finding:
    id: str
    title: str
    domain: str
    device: str = ""
    hypothesis: str = ""
    causal: bool = False          # the test itself observed the mechanism (not just a correlate)
    confidence: float = 0.5
    remediation_hint: str = ""
    contradicted_by: list[str] = field(default_factory=list)


@dataclass
class Result:
    verdict: str                      # PASS | FAIL | INCONCLUSIVE | SKIPPED | UNAVAILABLE
    status: str = "EXECUTED"
    reason: str = ""
    summary: str = ""
    observed: dict[str, Any] = field(default_factory=dict)
    interpretation: str = ""
    next_action: str = ""
    evidence_ids: list[str] = field(default_factory=list)
    finding: Finding | None = None
    target: str = ""
    command: str = ""
    counter_evidence: list[str] = field(default_factory=list)


def ok(summary: str, interpretation: str = "", **observed) -> Result:
    return Result("PASS", summary=summary, interpretation=interpretation, observed=observed)


def fault(summary: str, finding: Finding, interpretation: str = "", next_action: str = "", **observed) -> Result:
    return Result("FAIL", summary=summary, interpretation=interpretation, finding=finding, next_action=next_action, observed=observed)


def inconclusive(reason: str, summary: str = "", **observed) -> Result:
    return Result("INCONCLUSIVE", reason=reason, summary=summary or reason, observed=observed)


def not_applicable(reason: str) -> Result:
    return Result("SKIPPED", status="NOT_APPLICABLE", reason=reason, summary=reason)


def unsafe(reason: str) -> Result:
    return Result("SKIPPED", status="UNSAFE_TO_EXECUTE", reason=reason, summary=reason)


@dataclass(frozen=True)
class TestSpec:
    __test__ = False  # not a pytest/unittest collectable
    id: str
    title: str
    layer: str                                   # L1 L2 L3 L4 L7 SVC CTRL
    hypothesis: str                              # hypothesis id this test discriminates
    expected: str                                # healthy expectation, stated before execution
    fn: Callable[["Ctx"], Result]
    applies: Callable[["Ctx"], tuple[bool, str]] | None = None
    requires: tuple[str, ...] = ()               # hard data dependency (test ids)
    after: tuple[str, ...] = ()                  # ordering only
    command: str = ""                            # read-only CLI/API identifier (allowlisted catalogue key / structured source)
    cls: str = DISCRIMINATING
    version: str = "1"
    condition: str = ""                          # hypothesized fault condition (for the matrix)
    sources: tuple[str, ...] = ()                # observation keys / intent sources the test reads (collection plan)


@dataclass(frozen=True)
class Hypothesis:
    id: str
    title: str
    domain: str
    tests: tuple[str, ...]
    rank: int = 5


@dataclass(frozen=True)
class Runbook:
    id: str
    name: str
    version: str
    title: str
    tests: tuple[TestSpec, ...]
    hypotheses: tuple[Hypothesis, ...]
    orders: dict[str, tuple[str, ...]]           # strategy -> preferred order of test ids
    select_strategy: Callable[["Ctx"], tuple[str, str]]
    doc: str                                     # file name under docs/troubleshooting/runbooks/
    test_prefixes: tuple[str, ...] = ()
    purpose: str = ""
    impact_tests: tuple[str, ...] = ()            # tests that measure real service impact; a PASS there contradicts an 'impact-causing' finding
    remediations: dict[str, dict] = field(default_factory=dict)   # finding id -> governed-remediation skeleton (NEVER executed here)

    @property
    def by_id(self) -> dict[str, TestSpec]:
        return {t.id: t for t in self.tests}

    def validate(self) -> list[str]:
        """DAG hygiene: unique ids, known references, acyclic hard/soft edges, every hypothesis test exists, orders complete."""
        problems, ids = [], [t.id for t in self.tests]
        if len(set(ids)) != len(ids):
            problems.append("duplicate test ids")
        known = set(ids)
        for t in self.tests:
            for dep in (*t.requires, *t.after):
                if dep not in known:
                    problems.append(f"{t.id}: unknown dependency {dep}")
            if not t.hypothesis:
                problems.append(f"{t.id}: no hypothesis")
        hyp_ids = {h.id for h in self.hypotheses}
        for t in self.tests:
            if t.hypothesis not in hyp_ids:
                problems.append(f"{t.id}: unknown hypothesis {t.hypothesis}")
        for h in self.hypotheses:
            for tid in h.tests:
                if tid not in known:
                    problems.append(f"hypothesis {h.id}: unknown test {tid}")
        for name, order in self.orders.items():
            if set(order) != known or len(order) != len(known):
                problems.append(f"order {name!r} is not a permutation of the test set")
        try:
            self.order(next(iter(self.orders)))
        except ValueError as exc:
            problems.append(str(exc))
        return problems

    def order(self, strategy: str) -> list[str]:
        """Topological order that follows the strategy's preference but never violates requires/after edges."""
        pref = list(self.orders[strategy])
        by_id = self.by_id
        done: list[str] = []
        remaining = list(pref)
        while remaining:
            for tid in remaining:
                deps = set(by_id[tid].requires) | set(by_id[tid].after)
                if deps <= set(done):
                    done.append(tid)
                    remaining.remove(tid)
                    break
            else:
                raise ValueError(f"cycle among {remaining}")
        return done


class Ctx:
    """Everything a test may read.  ``used`` accumulates the evidence ids a test actually relied on (so PASS/FAIL always cite evidence)."""

    def __init__(self, *, view: EvidenceView, now: datetime, case: dict, flow: dict, intent: dict, baselines: dict, changes: list[dict],
                 path_fwd: list[dict], path_ret: list[dict], exceptions: list[dict] | None = None, results: dict[str, Result] | None = None,
                 intent_evidence_ids: dict[str, str] | None = None, alarms: list[dict] | None = None, correlation: dict | None = None):
        self.view, self.now, self.case, self.flow = view, now, case, flow
        self.intent, self.baselines, self.changes = intent, baselines, changes
        self.path_fwd, self.path_ret = path_fwd, path_ret
        self.exceptions = exceptions or []
        self.results = results if results is not None else {}
        self.intent_evidence_ids = intent_evidence_ids or {}
        self.alarms = alarms or []
        self.correlation = correlation or {}
        self.used: list[str] = []
        self.gaps: list[str] = []

    # ------------------------------------------------------------------------------------------------------------ evidence access
    def _note(self, o: Obs) -> None:
        for e in o.evidence_ids:
            if e not in self.used:
                self.used.append(e)

    def need(self, key: str, device: str, subject: str = "") -> Obs:
        o = self.view.latest(key, device, subject)
        ref = f"{key}{KEY_SEP + subject if subject else ''}@{device}"
        if o is None:
            self.gaps.append(f"{ref}: not collected")
            raise Gap("INCONCLUSIVE", f"{ref} was not collected (missing evidence is not evidence of absence)")
        if o.is_missing:
            status = "UNAVAILABLE" if any((o.missing_reason or "").upper().startswith(p) for p in UNAVAILABLE_REASONS) else "INCONCLUSIVE"
            self.gaps.append(f"{ref}: {o.missing_reason}")
            raise Gap(status, f"{ref} unavailable: {o.missing_reason or 'missing data'}")
        if o.freshness == c.UNTRUSTED or o.quality == "UNTRUSTED":
            self.gaps.append(f"{ref}: untrusted parse")
            raise Gap("INCONCLUSIVE", f"{ref} is UNTRUSTED_PARSE; diagnosis on it is blocked")
        if o.freshness != c.FRESH:
            age = int((self.now - o.observed_at).total_seconds())
            self.gaps.append(f"{ref}: stale")
            raise Gap("INCONCLUSIVE", f"{ref} is {o.freshness} (age {age}s, limit {o.max_age_seconds}s); not used as live state")
        self._note(o)
        return o

    def need_any(self, key: str, devices: Iterable[str]) -> Obs:
        """No usable instance of ``key`` exists: raise the precise Gap (UNAVAILABLE/UNSUPPORTED/stale) of the first recorded one, else 'not collected'."""
        devices = list(devices)
        for d in devices:
            for o in self.view.each(key, d):
                self.need(key, d, o.subject)       # raises Gap for missing/stale/untrusted instances; returns for a usable one
                return o
        self.need(key, devices[0] if devices else "?", "")
        raise Gap("INCONCLUSIVE", f"{key} was not collected")

    def opt(self, key: str, device: str, subject: str = "") -> Obs | None:
        try:
            return self.need(key, device, subject)
        except Gap:
            return None

    def each(self, key: str, device: str | None = None) -> list[Obs]:
        out = []
        for o in self.view.each(key, device):
            if not o.is_missing and o.freshness == c.FRESH and o.quality != "UNTRUSTED":
                self._note(o)
                out.append(o)
        return out

    def use_intent(self, *names: str) -> None:
        for n in names:
            e = self.intent_evidence_ids.get(n)
            if e and e not in self.used:
                self.used.append(e)

    def result(self, test_id: str) -> Result | None:
        return self.results.get(test_id)

    # ------------------------------------------------------------------------------------------------------------- topology helpers
    @property
    def src(self) -> str:
        return self.flow.get("src", "")

    @property
    def dst(self) -> str:
        return self.flow.get("dst", "")

    def devices_on_path(self, *, routers_only: bool = False) -> list[str]:
        roles = {n["name"]: n.get("role", "") for n in self.intent.get("nodes", [])}
        out = []
        for hop in self.path_fwd:
            d = hop["device"]
            if d not in out and (not routers_only or roles.get(d) in ("router", "firewall", "l3switch")):
                out.append(d)
        return out

    def node(self, name: str) -> dict:
        return next((n for n in self.intent.get("nodes", []) if n["name"] == name), {})

    def nodes_by_role(self, *roles: str) -> list[str]:
        return [n["name"] for n in self.intent.get("nodes", []) if n.get("role") in roles]

    def since(self, seconds: int) -> datetime:
        return self.now - timedelta(seconds=seconds)
