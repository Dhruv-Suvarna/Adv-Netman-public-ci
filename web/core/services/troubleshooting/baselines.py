"""Stage "Baseline" (spec 3.3, 6.3): three DISTINCT references, approved-change detection and golden-soak context.

1. INTENDED DESIGN      NetBox intent (+ topology) and the active golden configuration -- with the exact bundle revision, digest and the
                        direct operator URL of the golden-config page (never a title; a missing/unverifiable link is reported as such).
2. HISTORICAL NORMAL    learned from prior observations: hour-of-day buckets, robust statistics, an honest confidence, staleness.
3. PRODUCTION CONTRACT  service-flow definition and SLO: what must work and what is intentionally blocked.

Sources are injected (``BaselineSources``): ``DjangoBaselineSources`` reuses the real NMAS services (nsot_service, topology_service,
ConfigurationBundle/ProbationSoakRun/Change models); ``StaticSources`` replays recorded data.  A source that cannot answer returns
``{"status": "unavailable", ...}`` -- the baseline is then UNKNOWN, never a guessed value.

Pure helpers (``learn_history``, ``assess_drift``, ``decide_preserve_or_remediate``, ``classify_changes``) have no ORM/I/O.
Persistence helper ``persist_baselines`` is the only function here that writes (through ``repository`` only).
"""

from __future__ import annotations

import statistics
from datetime import datetime, timedelta
from typing import Any, Callable, Iterable, Protocol

from . import contracts as c
from . import repository as repo

BASELINE_KINDS = ("INTENT", "GOLDEN_CONFIG", "LEARNED_HISTORICAL", "SLO")


class BaselineSources(Protocol):
    def intent(self, devices: list[str], flow: dict) -> dict: ...
    def golden(self, devices: list[str]) -> dict: ...
    def history(self, flow: dict, devices: list[str], now: datetime) -> dict: ...
    def slo(self, flow: dict) -> dict: ...
    def changes(self, devices: list[str], since: datetime, until: datetime) -> dict: ...
    def configs(self, devices: list[str]) -> dict: ...


def unavailable(source: str, reason: str) -> dict:
    return {"status": "unavailable", "source": source, "reason": reason}


class StaticSources:
    """Recorded/simulated sources.  ``fail`` names sources that must answer ``unavailable`` (negative tests)."""

    def __init__(self, data: dict, *, fail: Iterable[str] = ()):
        self.data, self.fail = data, set(fail)

    def _get(self, name: str, **extra) -> dict:
        if name in self.fail or name not in self.data:
            return unavailable(name, "source did not answer" if name in self.fail else "no recorded data for this source")
        return {"status": "available", "source": f"static:{name}", **self.data[name]}

    def intent(self, devices, flow):
        return self._get("intent")

    def golden(self, devices):
        return self._get("golden")

    def history(self, flow, devices, now):
        return self._get("history")

    def slo(self, flow):
        return self._get("slo")

    def changes(self, devices, since, until):
        return self._get("changes")

    def configs(self, devices):
        return self._get("configs")


# ------------------------------------------------------------------------------------------------------- Django-backed sources
class DjangoBaselineSources:
    """Real NMAS integrations (read-only).  Each method degrades to ``unavailable`` rather than raising.

    * intent  -> ``nsot_service`` (NetBox cache) + ``topology_service`` (live topology graph).  The topology payload carries edges between
                 nodes but NOT interface names, so links built from it have empty interfaces -- reported in ``limitations``.
    * golden  -> DEVICE-SCOPED: per device the newest GOLDEN bundle with a ``ConfigurationBundleItem`` for it, plus the relevant parent/active
                 ``ProbationSoakRun`` (see ``select_golden_scope`` and docs/troubleshooting/baseline-scope.md); the page URL is ``core:bundle_detail``
                 and is only marked OK after the bundle row and the route both resolve.
    * changes -> ``Change`` rows touching the devices (approved = lifecycle beyond VALIDATED) and their ``ChangeExecutionRun`` timestamps.
    * configs -> ``adapters.baseline_history.ConfigSnapshotBaseline`` (immutable TsEvidenceRef config snapshots vs exact golden item payloads;
                 needs ``actor``).  history -> ``HistoryBaseline`` over an injected ``history_reader``.  slo -> case flow or overrides.
                 Without those collaborators each is honestly unavailable.
    """

    def __init__(self, *, nsot=None, topology=None, overrides: dict[str, Callable[..., dict]] | None = None, actor: "repo.Actor | None" = None,
                 history_reader: Callable[[dict], Any] | None = None, history_limits: dict | None = None, config_adapter=None):
        self._nsot, self._topology, self._ov = nsot, topology, overrides or {}
        self._actor, self._history_reader, self._history_limits, self._config_adapter = actor, history_reader, history_limits, config_adapter

    # -- helpers
    def _services(self):
        if self._nsot is None or self._topology is None:
            from core.services import nsot_service, topology_service
            return self._nsot or nsot_service, self._topology or topology_service
        return self._nsot, self._topology

    def intent(self, devices, flow):
        if "intent" in self._ov:
            return self._ov["intent"](devices, flow)
        try:
            nsot, topo = self._services()
            summary = topo.get_topology_summary()
            devs = nsot.get_devices()
        except Exception as exc:  # pylint: disable=broad-exception-caught  # noqa: BLE001 - any upstream failure is UNKNOWN, not a guess
            return unavailable("netbox+topology", f"{type(exc).__name__}: {exc}")
        if summary.get("status") != "available":
            return unavailable("topology_service", summary.get("message") or "topology unavailable")
        graph = summary["data"]["graph"]
        links = [{"id": e.get("id", ""), "a": e["source"], "a_if": e.get("source_interface", ""), "b": e["target"], "b_if": e.get("target_interface", ""),
                  "observed_status": e.get("status")} for e in graph["edges"]]
        rows = {d["name"]: d for d in (devs.get("data") or [])} if devs.get("status") in ("available", "ok") else {}
        nodes = [{"name": n["id"], "role": (rows.get(n["id"]) or {}).get("role") or "unknown",
                  "platform": (rows.get(n["id"]) or {}).get("platform") or "unknown", "health": n.get("health")} for n in graph["nodes"]]
        return {"status": "available", "source": "netbox+topology", "fetched_at": summary.get("generated_at") or "", "nodes": nodes, "links": links,
                "netbox_status": devs.get("status", "unavailable"),
                "limitations": ["topology edges carry no interface names; path hops are device-level only"] if not any(l["a_if"] for l in links) else []}

    def golden(self, devices):
        """Device-scoped golden + soak selection (never the globally newest golden or any unrelated running soak).  See ``select_golden_scope``."""
        if "golden" in self._ov:
            return self._ov["golden"](devices)
        try:
            return select_golden_scope(devices, *_load_golden_scope(devices))
        except Exception as exc:  # pylint: disable=broad-exception-caught  # noqa: BLE001
            return unavailable("golden_config", f"{type(exc).__name__}: {exc}")

    def changes(self, devices, since, until):
        if "changes" in self._ov:
            return self._ov["changes"](devices, since, until)
        try:
            from core import models as m
            wanted = set(devices)
            rows = []
            approved_states = {s for s in m.ChangeLifecycleState.values if s not in ("DRAFT", "VALIDATED", "CI_PENDING", "CI_FAILED")}
            for run in m.ChangeExecutionRun.objects.select_related("change").filter(started_at__gte=since, started_at__lte=until):
                touched = sorted(wanted & set(run.devices or []))
                if not touched:
                    continue
                rows.append({"change_id": run.change.change_id, "approved": run.change.lifecycle_state in approved_states, "kind": "execution",
                             "at": c.iso(run.started_at), "devices": touched, "summary": run.change.title, "outcome": run.outcome or run.state,
                             "source": "ChangeExecutionRun", "lifecycle": run.change.lifecycle_state})
            return {"status": "available", "source": "Change+ChangeExecutionRun", "changes": rows,
                    "limitations": ["manual/out-of-band device changes are only visible through configs() drift, not through this list"]}
        except Exception as exc:  # pylint: disable=broad-exception-caught  # noqa: BLE001
            return unavailable("changes", f"{type(exc).__name__}: {exc}")

    def history(self, flow, devices, now):
        if "history" in self._ov:
            return self._ov["history"](flow, devices, now)
        if self._history_reader is None:
            return unavailable("history", "NMAS stores no telemetry history; inject a bounded history_reader (adapters.baseline_history.FluxHistoryReader) or overrides['history']")
        from .adapters.baseline_history import HistoryBaseline
        return HistoryBaseline(self._history_reader, limits=self._history_limits)(flow, devices, now)

    def slo(self, flow):
        if "slo" in self._ov:
            return self._ov["slo"](flow)
        declared = flow.get("slo")
        if declared:
            return {"status": "available", "source": "case.flow_scope", "revision": flow.get("slo_revision", ""), "contract": {**declared}}
        return unavailable("slo", "the case flow definition carries no SLO; no service-contract store exists")

    def configs(self, devices):
        if "configs" in self._ov:
            return self._ov["configs"](devices)
        adapter = self._config_adapter
        if adapter is None and self._actor is not None:
            from .adapters.baseline_history import ConfigSnapshotBaseline
            adapter = ConfigSnapshotBaseline.from_orm(self._actor, self.golden)
        if adapter is None:
            return unavailable("configs", "no actor/config_adapter: tenant-scoped immutable snapshots cannot be read (running config is UNKNOWN)")
        return adapter.configs(devices)


# ------------------------------------------------------------------------------------------------------- device-scoped golden selection
def _load_golden_scope(devices: list[str]) -> tuple[list[dict], list[dict]]:
    """Read-only ORM load -> plain dicts.  Only GOLDEN bundles with a ConfigurationBundleItem for a requested device, and only soaks that are
    (a) the soak of a selected golden's parent PROBATION bundle or (b) RUNNING on a PROBATION bundle that itself touches a requested device."""
    from django.urls import resolve, reverse
    from core import models as m

    wanted = sorted({d for d in devices if isinstance(d, str) and d})
    if not wanted:
        return [], []
    items_by_bundle: dict[int, dict[str, list[dict]]] = {}
    for it in m.ConfigurationBundleItem.objects.filter(bundle__kind=m.BundleKind.GOLDEN, device__in=wanted).order_by("bundle_id", "sequence"):
        items_by_bundle.setdefault(it.bundle_id, {}).setdefault(it.device, []).append(
            {"cfg_id": it.cfg_id, "payload_hash": it.payload_hash, "item_digest": it.item_digest, "operation": it.operation, "sequence": it.sequence})
    goldens = []
    for g in (m.ConfigurationBundle.objects.select_related("change", "parent").filter(pk__in=list(items_by_bundle)).order_by("-created_at", "-id")):
        url = reverse("core:bundle_detail", args=[g.bundle_id])
        try:
            resolve(url)
            link_ok = m.ConfigurationBundle.objects.filter(bundle_id=g.bundle_id).exists()
        except Exception:  # pylint: disable=broad-exception-caught  # noqa: BLE001
            link_ok = False
        goldens.append({"bundle_id": g.bundle_id, "digest": g.bundle_digest, "created_at": g.created_at, "url": url, "link_ok": link_ok,
                        "approved_change_id": g.change.change_id if g.change else "", "provenance": g.provenance,
                        "parent_bundle_id": g.parent.bundle_id if g.parent else "", "parent_pk": g.parent_id, "items": items_by_bundle[g.pk]})
    parent_pks = {g["parent_pk"] for g in goldens if g["parent_pk"]}
    active_pks = set(m.ConfigurationBundleItem.objects.filter(bundle__kind=m.BundleKind.PROBATION, device__in=wanted,
                                                              bundle__soak_runs__state=m.SoakState.RUNNING).values_list("bundle_id", flat=True))
    cover: dict[int, set[str]] = {}
    for bid, dev in m.ConfigurationBundleItem.objects.filter(bundle_id__in=active_pks | parent_pks, device__in=wanted).values_list("bundle_id", "device"):
        cover.setdefault(bid, set()).add(dev)
    soaks = []
    for s in m.ProbationSoakRun.objects.select_related("bundle", "bundle__change").filter(bundle_id__in=active_pks | parent_pks).order_by("-started_at", "-id"):
        ch = s.bundle.change
        soaks.append({"soak_id": s.soak_id, "state": s.state, "result": s.result, "started_at": s.started_at, "required_end_at": s.required_end_at,
                      "url": reverse("core:soak_detail", args=[s.soak_id]), "bundle_id": s.bundle.bundle_id, "bundle_pk": s.bundle_id,
                      "bundle_digest": s.bundle_digest, "active": s.state == m.SoakState.RUNNING, "devices": sorted(cover.get(s.bundle_id, ())),
                      "change_id": ch.change_id if ch else "", "change_lifecycle": ch.lifecycle_state if ch else "",
                      "is_parent_of_golden": s.bundle_id in parent_pks})
    return goldens, soaks


def select_golden_scope(devices: list[str], goldens: list[dict], soaks: list[dict]) -> dict[str, Any]:
    """PURE selection.  ``goldens`` are newest-first GOLDEN bundles carrying ``items`` {device: [item]}; ``soaks`` are candidate soak runs.

    Rules (each outcome is explicit, nothing is guessed):
      * per requested device the effective golden is the NEWEST golden that has an item for THAT device; a newer golden touching only other
        devices is irrelevant to it.  Devices with no item in any golden are UNCOVERED (never silently attributed to another bundle).
      * one distinct effective revision -> the legacy top-level fields (revision/digest/url/...) carry it (``coverage`` FULL, or PARTIAL when
        some devices are uncovered, listing them).  More than one -> MIXED_REVISION: the top-level revision/digest/url are EMPTY (no single
        revision is claimed), ``revisions`` and ``device_scope`` carry each exact revision/hash/URL, and an ambiguity record is emitted.
      * no covered device (or no devices requested) -> unavailable (fail closed; the globally newest golden is never a fallback).
      * soak: RUNNING soaks on probation bundles touching the devices, else the soak of the selected golden's parent; more than one distinct
        active soak, or no single revision to anchor a parent soak, -> ``soak`` is None and an ambiguity record lists every candidate."""
    wanted = list(dict.fromkeys(d for d in devices if isinstance(d, str) and d))
    if not wanted:
        return unavailable("golden_config", "no devices in scope; a device-scoped golden cannot be selected (the global newest golden is never used)")
    scope, uncovered = [], []
    for dev in wanted:
        having = [g for g in goldens if dev in g["items"]]
        if not having:
            uncovered.append(dev)
            scope.append({"device": dev, "status": "UNCOVERED", "reason": "no golden bundle contains a configlet item for this device"})
            continue
        g = having[0]
        prev = having[1] if len(having) > 1 else None
        scope.append({"device": dev, "status": "COVERED", "revision": g["bundle_id"], "digest": g["digest"], "url": g["url"], "link_ok": g["link_ok"],
                      "created_at": c.iso(g["created_at"]), "items": g["items"][dev], "previous_revision": prev["bundle_id"] if prev else "",
                      "previous_url": prev["url"] if prev else "", "superseded_for_device": [x["bundle_id"] for x in having[1:]]})
    covered = [s for s in scope if s["status"] == "COVERED"]
    if not covered:
        return unavailable("golden_config", f"no golden bundle covers any of the devices {wanted}")
    revs = list(dict.fromkeys(s["revision"] for s in covered))
    by_id = {g["bundle_id"]: g for g in goldens}
    ambiguities: list[dict] = []
    mixed, partial = len(revs) > 1, bool(uncovered)
    if mixed:
        ambiguities.append({"kind": "MIXED_REVISION", "revisions": revs,
                            "devices": {r: [s["device"] for s in covered if s["revision"] == r] for r in revs},
                            "note": "devices are covered by different golden revisions; no single golden revision is claimed"})
    if partial:
        ambiguities.append({"kind": "PARTIAL_COVERAGE", "uncovered_devices": uncovered,
                            "note": "these devices have no golden item: their intended configuration is UNKNOWN, not 'conforming'"})
    out: dict[str, Any] = {"status": "available", "source": "ConfigurationBundleItem", "coverage": ("PARTIAL_" if partial else "") + ("MIXED" if mixed else "FULL"),
                           "mixed_revision": mixed, "partial_coverage": partial, "scoped_devices": wanted, "covered_devices": [s["device"] for s in covered],
                           "uncovered_devices": uncovered, "device_scope": scope, "revisions": revs, "ambiguities": ambiguities}
    if mixed:
        out.update({"revision": "", "digest": "", "url": "", "link_ok": False, "created_at": "", "approved_change_id": "", "provenance": "",
                    "previous_revision": "", "previous_url": ""})
        sel = [by_id[r] for r in revs]
    else:
        g = by_id[revs[0]]
        prevs = {s["previous_revision"] for s in covered}
        prev_id = next(iter(prevs)) if len(prevs) == 1 else ""
        out.update({"revision": g["bundle_id"], "digest": g["digest"], "url": g["url"], "link_ok": g["link_ok"], "created_at": c.iso(g["created_at"]),
                    "approved_change_id": g["approved_change_id"], "provenance": g["provenance"], "previous_revision": prev_id,
                    "previous_url": next((s["previous_url"] for s in covered if s["previous_revision"] == prev_id), "") if prev_id else ""})
        sel = [g]
    out["soak"], out["soaks"] = _select_soak(sel, soaks, ambiguities)
    return out


def _soak_view(s: dict, relation: str) -> dict:
    return {"soak_id": s["soak_id"], "state": s["state"], "result": s["result"], "started_at": c.iso(s["started_at"]),
            "required_end_at": c.iso(s["required_end_at"]), "url": s["url"], "bundle_id": s["bundle_id"], "bundle_digest": s.get("bundle_digest", ""),
            "active": bool(s["active"]), "devices": s.get("devices", []), "change_id": s.get("change_id", ""),
            "change_lifecycle": s.get("change_lifecycle", ""), "relation": relation}


def _select_soak(selected: list[dict], soaks: list[dict], ambiguities: list[dict]) -> tuple[dict | None, list[dict]]:
    parent_pks = {g["parent_pk"] for g in selected if g.get("parent_pk")}
    active = [s for s in soaks if s["active"] and s.get("devices")]
    parents = [s for s in soaks if s["bundle_pk"] in parent_pks]
    listing = [_soak_view(s, "ACTIVE_CANDIDATE_FOR_DEVICES") for s in active]
    listing += [_soak_view(s, "PARENT_OF_SELECTED_GOLDEN") for s in parents if not s["active"]]
    if len(active) > 1:
        ambiguities.append({"kind": "MULTIPLE_ACTIVE_SOAKS", "soaks": [s["soak_id"] for s in active],
                            "note": "several running soaks touch the scoped devices; none is selected and none is blamed"})
        return None, listing
    if active:
        return _soak_view(active[0], "ACTIVE_CANDIDATE_FOR_DEVICES"), listing
    if len(selected) != 1:
        if parents:
            ambiguities.append({"kind": "SOAK_WITHOUT_SINGLE_REVISION", "soaks": [s["soak_id"] for s in parents],
                                "note": "mixed golden revisions: no single parent soak is claimed"})
        return None, listing
    if parents:
        return _soak_view(parents[0], "PARENT_OF_SELECTED_GOLDEN"), listing
    return None, listing


# ------------------------------------------------------------------------------------------------------------- historical normal
def learn_history(samples: list[dict], *, now: datetime, key: str | None = None, min_samples: int = 12, max_age_days: int = 30) -> dict[str, Any]:
    """Learn a per-hour-of-day normal from [{t, value}].  Returns overall and bucketed statistics + a confidence.

    Confidence is a calibrated explanatory estimate (sample count and recency), NOT a probability.  Fewer than ``min_samples`` -> UNKNOWN."""
    pts = []
    for s in samples:
        t = c.parse_time(s.get("t"))
        if t is not None and isinstance(s.get("value"), (int, float)) and not isinstance(s.get("value"), bool) and t <= now:
            pts.append((t, float(s["value"])))
    if len(pts) < min_samples:
        return {"state": "UNKNOWN", "reason": f"only {len(pts)} usable samples (< {min_samples}); no learned normal", "samples": len(pts)}
    newest = max(t for t, _ in pts)
    age_days = (now - newest).total_seconds() / 86400
    values = [v for _, v in pts]
    med = statistics.median(values)
    mad = statistics.median(abs(v - med) for v in values) or 1e-9
    buckets: dict[int, list[float]] = {}
    for t, v in pts:
        buckets.setdefault(t.hour, []).append(v)
    hour = {h: {"median": statistics.median(vs), "n": len(vs)} for h, vs in buckets.items()}
    stale = age_days > max_age_days
    conf = round(min(0.9, 0.3 + len(pts) / 200) * (0.3 if stale else 1.0), 2)
    return {"state": "STALE" if stale else "LEARNED", "key": key, "samples": len(pts), "median": med, "mad": mad, "min": min(values), "max": max(values),
            "hour_of_day": hour, "newest": c.iso(newest), "newest_age_days": round(age_days, 2), "confidence": conf,
            "reason": f"newest sample is {age_days:.1f} days old (> {max_age_days}); baseline is stale and must not be treated as current normal" if stale else ""}


def anomaly(value: float, stats: dict, *, at: datetime | None = None, z_threshold: float = 4.0) -> dict[str, Any]:
    """Anomaly vs the learned normal.  An anomaly is a *signal*, not a fault and never permission to remediate (spec 3.4)."""
    if stats.get("state") != "LEARNED":
        return {"anomalous": None, "reason": f"baseline is {stats.get('state', 'UNKNOWN')}; no comparison made"}
    ref = stats["median"]
    if at is not None and stats["hour_of_day"].get(at.hour, {}).get("n", 0) >= 5:
        ref = stats["hour_of_day"][at.hour]["median"]
    z = 0.6745 * (value - ref) / stats["mad"]
    return {"anomalous": abs(z) >= z_threshold, "robust_z": round(z, 2), "reference": ref, "confidence": stats["confidence"],
            "false_positive_risk": "MEDIUM" if stats["samples"] < 50 else "LOW",
            "reason": f"value {value} vs normal {ref} (robust z={z:.1f}); an anomaly is a signal, not a fault verdict"}


# ----------------------------------------------------------------------------------------------------------------- change facts
def classify_changes(changes: list[dict], *, soak: dict | None, onset: datetime) -> list[dict]:
    """Annotate each change with approval and soak membership.  Unapproved = no approved change record (``approved`` not True)."""
    start = c.parse_time((soak or {}).get("started_at"))
    end = c.parse_time((soak or {}).get("required_end_at"))
    out = []
    for ch in changes:
        t = c.parse_time(ch.get("at"))
        in_soak = bool(soak and soak.get("active") and start and t and start <= t <= (end or onset))
        out.append({**ch, "approved": True if ch.get("approved") is True else False, "approval_known": ch.get("approved") is not None,
                    "in_soak": in_soak or bool(ch.get("in_soak"))})
    return out


def soak_window(soak: dict | None, onset: datetime) -> dict[str, Any]:
    if not soak:
        return {"state": "NONE", "onset_in_window": False}
    start, end = c.parse_time(soak.get("started_at")), c.parse_time(soak.get("required_end_at"))
    inside = bool(soak.get("active") and start and end and start <= onset <= end)
    return {"state": "ACTIVE" if soak.get("active") else soak.get("state", "UNKNOWN"), "soak_id": soak.get("soak_id", ""), "url": soak.get("url", ""),
            "started_at": soak.get("started_at"), "required_end_at": soak.get("required_end_at"), "onset_in_window": inside,
            "note": "incident onset falls inside the soak window; correlation is recorded but the golden candidate is not blamed without causal evidence"
            if inside else "incident onset is outside any active soak window"}


# ----------------------------------------------------------------------------------------------------------------------- drift
def assess_drift(configs: dict, *, changes: list[dict], production_impact: str) -> list[dict]:
    """Intended-vs-running differences, each tied to an approved change if one exists.  ``production_impact`` (NONE/DEGRADED/OUTAGE/UNKNOWN) is
    the *measured* service impact and is what decides priority -- conformity alone never does (UT-029/030)."""
    if configs.get("status") != "available":
        return [{"subject": "configuration", "drift_kind": "UNKNOWN", "applicability": "APPLICABLE", "expected": None, "observed": None, "delta": None,
                 "approved_change_id": "", "production_impact": production_impact, "materiality": "UNKNOWN",
                 "conclusion": f"config comparison unavailable ({configs.get('reason', 'no data')}); drift is UNKNOWN, not 'none'"}]
    by_change = {ch.get("change_id"): ch for ch in changes}
    rows = [{"subject": dev, "drift_kind": "UNKNOWN", "applicability": "APPLICABLE", "expected": None, "observed": None, "delta": None, "approved_change_id": "",
             "production_impact": production_impact, "materiality": "UNKNOWN",
             "conclusion": f"{dev}: {u.get('reason', 'UNKNOWN')} - {u.get('detail', '')}; drift is UNKNOWN, not 'none'"}
            for dev, u in sorted((configs.get("unknown_devices") or {}).items())]
    for dev, entry in sorted((configs.get("devices") or {}).items()):
        diffs = entry.get("diffs") or []
        if not diffs:
            rows.append({"subject": dev, "drift_kind": "NONE", "applicability": "APPLICABLE", "expected": entry.get("golden_hash"),
                         "observed": entry.get("running_hash"), "delta": None, "approved_change_id": "", "production_impact": production_impact,
                         "materiality": "NONE", "conclusion": f"{dev} running configuration conforms to golden {entry.get('golden_hash', '')[:12]}"})
        for d in diffs:
            cid = d.get("change_id") or ""
            known = by_change.get(cid)
            approved = bool(known and known.get("approved"))
            kind = "APPROVED" if approved else "UNAPPROVED"
            rows.append({"subject": f"{dev}:{d.get('path', '')}", "drift_kind": kind, "applicability": "APPLICABLE", "expected": d.get("golden"),
                         "observed": d.get("running"), "delta": d.get("summary"), "approved_change_id": cid if approved else "", "blocks": d.get("blocks", []),
                         "production_impact": production_impact,
                         "materiality": "HIGH" if production_impact in ("DEGRADED", "OUTAGE") else "LOW" if approved else "MEDIUM",
                         "conclusion": (f"approved change {cid}: expected drift, not a fault; no rollback because of drift" if approved else
                                        "difference without an approved change record: unauthorized or unrecorded; investigate")
                         + (f"; measured production impact {production_impact} takes priority over conformity" if production_impact in ("DEGRADED", "OUTAGE") else "")})
    return rows


def decide_preserve_or_remediate(drift: dict, *, soak_active: bool, causal_evidence: bool) -> dict[str, Any]:
    """Decision matrix for a drifted config (spec 6.3).  Never returns an automatic rollback."""
    impact, kind = drift["production_impact"], drift["drift_kind"]
    if impact in ("NONE",):
        return {"decision": "PRESERVE", "auto_rollback": False,
                "reason": f"{kind.lower()} drift but no production impact: keep monitoring" + ("; soak window continues" if soak_active else "")}
    if impact == "UNKNOWN":
        return {"decision": "OBSERVE", "auto_rollback": False, "reason": "production impact cannot be measured; no change is proposed on drift alone"}
    if not causal_evidence:
        return {"decision": "INVESTIGATE", "auto_rollback": False,
                "reason": "production is impaired and a change is nearby, but no causal test links them; contain via governed options only after proof"}
    return {"decision": "PROPOSE_GUARDED_FIX", "auto_rollback": False, "tier": 2,
            "reason": "production impairment causally linked to the change: propose a narrow hotfix or reviewed rollback requiring Tier-2 approval, "
                      "dry-run and continuous production-flow guard"}


# ------------------------------------------------------------------------------------------------------------ assemble + persist
def gather(sources: BaselineSources, *, devices: list[str], flow: dict, now: datetime, onset: datetime, lookback_seconds: int = 7 * 86400) -> dict[str, Any]:
    """Pull every source once.  Result keys are always present; unavailable ones carry status=unavailable."""
    intent = sources.intent(devices, flow)
    golden = sources.golden(devices)
    changes = sources.changes(devices, onset - timedelta(seconds=lookback_seconds), now)
    history = sources.history(flow, devices, now)
    if history.get("status") == "available" and "series" in history and "stats" not in history:
        history = {**history, "stats": {ref: learn_history(samples, now=now, key=ref) for ref, samples in history["series"].items()}}
    soak = golden.get("soak") if golden.get("status") == "available" else None
    cls = classify_changes(changes.get("changes", []), soak=soak, onset=onset) if changes.get("status") == "available" else []
    return {"intent": intent, "golden": golden, "history": history, "slo": sources.slo(flow), "changes": changes,
            "configs": sources.configs(devices), "classified_changes": cls, "soak_window": soak_window(soak, onset), "gathered_at": c.iso(now)}


def distinct_provenance(bs: dict) -> dict[str, str]:
    """Each of the three references must keep its own source/revision (UT-026)."""
    return {"intended_design": f"{bs['intent'].get('source', '?')}|{bs['golden'].get('source', '?')}@{bs['golden'].get('revision', '-')}",
            "historical_normal": str(bs["history"].get("source", "?")), "production_contract": str(bs["slo"].get("source", "?"))}


def persist_baselines(actor: repo.Actor, case, bs: dict, *, now: datetime, link_checker: Callable[[str], bool] | None = None) -> tuple[list, dict]:
    """Write BaselineReference records, each citing its own evidence.  Returns the records.  Golden's operator URL is stored exactly as built
    by the source; a source without a URL stores none (link_status MISSING) -- nothing is invented (UT-011/027)."""
    records, ev = [], {}
    def evidence(kind: str, doc: dict, *, device: str = "", url: str = "", quality: str = "GOOD"):
        return repo.store_evidence(actor, case, source_type=kind, device=device, command_or_api=f"baseline:{kind}", adapter="troubleshooting.baselines",
                                   adapter_version="1", collected_at=now, raw=c.canonical_json(doc), operator_url=url, link_checker=link_checker,
                                   quality=quality)
    intent, golden, hist, slo = bs["intent"], bs["golden"], bs["history"], bs["slo"]
    ev["intent"] = evidence("netbox_intent", _brief(intent), quality="GOOD" if intent.get("status") == "available" else "MISSING")
    records.append(repo.record(actor, case, "baseline", basis="DERIVED", evidence_ids=[ev["intent"].evidence_id], now=now, baseline_type="INTENT",
        subject="netbox+topology", revision=str(intent.get("fetched_at", "")), valid_from=c.parse_time(intent.get("fetched_at")), link_status=ev["intent"].link_status,
        data={"status": intent.get("status"), "reason": intent.get("reason", ""), "nodes": len(intent.get("nodes", [])), "links": len(intent.get("links", [])),
              "limitations": intent.get("limitations", [])}, stage_decision="intended design (NetBox/topology): intent is not proof of operational state"))
    url = golden.get("url", "") if golden.get("status") == "available" else ""
    ev["golden"] = evidence("golden_config", _brief(golden), url=url, quality="GOOD" if golden.get("status") == "available" else "MISSING")
    soak = golden.get("soak") or {}
    records.append(repo.record(actor, case, "baseline", basis="DERIVED", evidence_ids=[ev["golden"].evidence_id], now=now, baseline_type="GOLDEN_CONFIG",
        subject="golden configuration", revision=golden.get("revision", ""), revision_hash=(golden.get("digest") or "")[:64],
        valid_from=c.parse_time(golden.get("created_at")), operator_url=url, link_status=ev["golden"].link_status if url else "MISSING",
        approved_change_id=golden.get("approved_change_id", ""), soak_state=("ACTIVE" if soak.get("active") else soak.get("state", "")) if soak else "",
        data={"status": golden.get("status"), "reason": golden.get("reason", ""), "previous_revision": golden.get("previous_revision", ""),
              "previous_url": golden.get("previous_url", ""), "soak": soak, "link_ok": golden.get("link_ok"),
              "coverage": golden.get("coverage", ""), "device_scope": golden.get("device_scope", []), "revisions": golden.get("revisions", []),
              "uncovered_devices": golden.get("uncovered_devices", []), "ambiguities": golden.get("ambiguities", [])},
        stage_decision=("active golden revision with direct page URL" if url else "golden revision/link UNAVAILABLE")
        + (f"; coverage {golden['coverage']}" if golden.get("coverage") and golden.get("coverage") != "FULL" else "")))
    ev["history"] = evidence("historical_baseline", _brief(hist), quality="GOOD" if hist.get("status") == "available" else "MISSING")
    stats = hist.get("stats") or {}
    records.append(repo.record(actor, case, "baseline", basis="DERIVED", evidence_ids=[ev["history"].evidence_id], now=now, baseline_type="LEARNED_HISTORICAL",
        subject="last-known-good / historical normal", revision=str(hist.get("revision", "")), valid_from=c.parse_time(hist.get("lkg_at")), link_status=ev["history"].link_status,
        data={"status": hist.get("status"), "reason": hist.get("reason", ""), "stats": stats, "lkg_at": hist.get("lkg_at")},
        stage_decision="historical normal (confidence and staleness recorded)"))
    ev["slo"] = evidence("service_contract", _brief(slo), quality="GOOD" if slo.get("status") == "available" else "MISSING")
    records.append(repo.record(actor, case, "baseline", basis="DERIVED", evidence_ids=[ev["slo"].evidence_id], now=now, baseline_type="SLO", subject="production service contract",
        revision=str(slo.get("revision", "")), link_status=ev["slo"].link_status, data={"status": slo.get("status"), "reason": slo.get("reason", ""), "contract": slo.get("contract", {})},
        stage_decision="current production contract (what must work / what is intentionally blocked)"))
    return records, ev


def _brief(doc: dict) -> dict:
    """Bounded evidence body (no secrets are ever part of a baseline source; redaction still runs inside store_evidence)."""
    return {k: v for k, v in doc.items() if k not in ("raw", "running_config")}
