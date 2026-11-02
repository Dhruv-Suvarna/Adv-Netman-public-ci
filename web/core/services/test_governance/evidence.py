"""Persisted evidence for the NMAS pages: accept, store (immutably), select, and judge CURRENT / STALE.

Pages never run tests, AST scans, coverage or Pylint: they read an accepted report.  A report is accepted only when it
parses, validates against ``report.schema.json`` and its recomputed canonical hash equals its ``payload_sha256``
(a report edited after generation is refused).  Nothing is ever accepted from a browser: the sources are the tracked
bundled report (``docs/evidence/lab7``), a local evidence run, or the Tier-3 artifact fetched by ``github_evidence``.

Freshness: CURRENT when the report's repository SHA is the deployed SHA, or when its source fingerprint (every deployed
artifact + every test + the governance policy / baseline / ledger) equals the deployed checkout's -- a documentation-only
commit does not make evidence stale; any code or test change does.  Otherwise STALE, and the page says so.
"""

from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from . import inventory as inventory_module, report as report_module, schema
from .constants import BUNDLED_EVIDENCE, REPO_ROOT, REPORT_SCHEMA_VERSION, Freshness

MAX_REPORT_BYTES = 40 * 1024 * 1024
FINGERPRINT_TTL_SECONDS = 300
_lock = threading.Lock()
_report_cache: dict[str, tuple[float, dict]] = {}
_fingerprint_cache: dict[str, tuple[float, str]] = {}


class EvidenceError(ValueError):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code, self.detail = code, detail


def evidence_dir() -> Path:
    try:
        from django.conf import settings

        configured = getattr(settings, "NMAS_TEST_GOVERNANCE_DIR", None)
    except Exception:  # pylint: disable=broad-exception-caught  # noqa: BLE001 - usable without Django configured (CLI / tests)
        configured = None
    return Path(configured or os.environ.get("NMAS_TEST_GOVERNANCE_DIR") or (REPO_ROOT / "web" / "var" / "test-governance"))


def verify_report(raw: bytes) -> dict:
    """Parse + schema + hash.  Raises EvidenceError with a fixed code; never returns an unverified report."""
    if len(raw) > MAX_REPORT_BYTES:
        raise EvidenceError("EVIDENCE_TOO_LARGE")
    try:
        data = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise EvidenceError("EVIDENCE_NOT_JSON") from exc
    if not isinstance(data, dict) or data.get("schema_version") != REPORT_SCHEMA_VERSION:
        raise EvidenceError("EVIDENCE_SCHEMA_VERSION", str(data.get("schema_version") if isinstance(data, dict) else ""))
    problems = schema.validate(data)
    if problems:
        raise EvidenceError("EVIDENCE_SCHEMA_INVALID", "; ".join(problems[:3]))
    if report_module.payload_hash(data) != data.get("payload_sha256"):
        raise EvidenceError("EVIDENCE_HASH_MISMATCH", "the canonical payload does not match payload_sha256")
    return data


def accept(raw: bytes, *, source: str, directory: Path | None = None) -> dict:
    """Store a verified report under its payload hash (write-once) and make it the latest accepted evidence."""
    data = verify_report(raw)
    directory = Path(directory or evidence_dir())
    accepted = directory / "accepted"
    accepted.mkdir(parents=True, exist_ok=True)
    target = accepted / f"{data['payload_sha256']}.json"
    with _lock:
        if not target.exists():
            tmp = target.with_suffix(".tmp")
            tmp.write_bytes(raw)
            os.replace(tmp, target)
        meta = {"payload_sha256": data["payload_sha256"], "repository_sha": data.get("repository_sha", ""), "source": source[:200],
                "accepted_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
        (accepted / f"{data['payload_sha256']}.meta.json").write_text(json.dumps(meta, sort_keys=True), encoding="utf-8")
    return meta


@dataclass(frozen=True)
class Candidate:
    path: Path
    source: str
    accepted_at: str = ""


def candidates(directory: Path | None = None, *, bundled: Path | None = None) -> list[Candidate]:
    out = []
    bundled = BUNDLED_EVIDENCE if bundled is None else bundled
    directory = Path(directory or evidence_dir())
    for meta_path in sorted((directory / "accepted").glob("*.meta.json")):
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        report_path = meta_path.with_name(meta_path.name.replace(".meta.json", ".json"))
        if report_path.is_file():
            out.append(Candidate(report_path, str(meta.get("source") or "accepted"), str(meta.get("accepted_at") or "")))
    if Path(bundled).is_file():
        out.append(Candidate(Path(bundled), "repository (docs/evidence/lab7)"))
    return out


def load_verified(path: Path) -> dict:
    """Parse + verify once per file version (mtime / size), then serve from memory."""
    stat = path.stat()
    key = f"{path}:{stat.st_mtime_ns}:{stat.st_size}"
    with _lock:
        hit = _report_cache.get(str(path))
        if hit and hit[0] == key:
            return hit[1]
    data = verify_report(path.read_bytes())
    with _lock:
        _report_cache[str(path)] = (key, data)
    return data


def deployed_state(repo: Path = REPO_ROOT, *, now: float | None = None) -> dict:
    """The deployed checkout's SHA and evidence-input fingerprint (cached for a few minutes; read-only git)."""
    sha = inventory_module.head_sha(repo)
    now = time.time() if now is None else now
    with _lock:
        hit = _fingerprint_cache.get(f"{repo}:{sha}")
    if hit and now - hit[0] < FINGERPRINT_TTL_SECONDS:
        return {"sha": sha, "fingerprint": hit[1]}
    try:
        fingerprint = report_module.evidence_fingerprint(inventory_module.build_inventory(repo), repo)
    except Exception:  # pylint: disable=broad-exception-caught  # noqa: BLE001 - an unreadable checkout means UNKNOWN freshness, never a crash or a false CURRENT
        fingerprint = ""
    with _lock:
        _fingerprint_cache[f"{repo}:{sha}"] = (now, fingerprint)
    return {"sha": sha, "fingerprint": fingerprint}


def freshness(report: dict, deployed: dict) -> tuple[str, str]:
    if not deployed.get("sha") and not deployed.get("fingerprint"):
        return Freshness.UNKNOWN, "the deployed checkout could not be identified"
    if report.get("repository_sha") and report["repository_sha"] == deployed.get("sha"):
        return Freshness.CURRENT, "the evidence was produced for exactly the deployed commit"
    if deployed.get("fingerprint") and report.get("source_fingerprint") == deployed["fingerprint"]:
        return Freshness.CURRENT, "the deployed source, tests and governance inputs are byte-identical to the tested ones"
    if not deployed.get("fingerprint"):
        return Freshness.UNKNOWN, "the deployed source could not be fingerprinted"
    return Freshness.STALE, "the deployed source differs from the tested source: re-run Tier-3 (or Refresh) before relying on it"


def select(directory: Path | None = None, *, repo: Path = REPO_ROOT, bundled: Path | None = None) -> dict:
    """Choose the evidence to show: exact deployed SHA, else identical fingerprint, else the newest (marked STALE)."""
    deployed = deployed_state(repo)
    loaded, refused = [], []
    for candidate in candidates(directory, bundled=bundled):
        try:
            loaded.append((candidate, load_verified(candidate.path)))
        except (EvidenceError, OSError) as exc:
            refused.append({"source": candidate.source, "code": getattr(exc, "code", type(exc).__name__)})
    if not loaded:
        return {"report": None, "freshness": Freshness.NONE, "reason": "no accepted evidence is available", "deployed": deployed,
                "source": "", "refused": refused}
    ranked = []
    for candidate, data in loaded:
        state, reason = freshness(data, deployed)
        exact = data.get("repository_sha") == deployed.get("sha")
        ranked.append(((state == Freshness.CURRENT, exact, data.get("generated_at", "")), candidate, data, state, reason))
    ranked.sort(key=lambda r: r[0], reverse=True)
    _rank, candidate, data, state, reason = ranked[0]
    return {"report": data, "freshness": state, "reason": reason, "deployed": deployed, "source": candidate.source,
            "accepted_at": candidate.accepted_at, "refused": refused, "available": len(loaded)}
