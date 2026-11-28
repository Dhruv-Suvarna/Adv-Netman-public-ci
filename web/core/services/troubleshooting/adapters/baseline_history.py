"""Historical and snapshot baseline source adapters (spec 3.3 / 6.3).  Read-only; no network, credentials, schema change or device contact.

Two reusable sources feed ``baselines.DjangoBaselineSources``:

* ``ConfigSnapshotBaseline`` -- running-vs-golden comparison.  *Running* side = the newest IMMUTABLE ``TsEvidenceRef`` (config snapshot, redacted
  content-addressed ``TsEvidenceBlob``, integrity re-verified).  *Golden* side = the exact ``ConfigurationBundleItem`` payloads of the per-device
  golden selection (``baselines.select_golden_scope``), integrity re-verified against ``payload_hash``.  Only the configuration SCOPE the golden
  items define is compared (their lines); everything else in the running config is out of scope, never "conforming" and never "drift".  A device
  with no snapshot, a stale/predating/foreign-platform/corrupt snapshot, redacted-only scope or no golden coverage is UNKNOWN for that device.
* ``HistoryBaseline`` -- last-known-good / historical normal from an injected, bounded ``reader`` (callable) over the existing monitoring
  query layer.  ``FluxHistoryReader`` builds validated Flux against the repository's own gNMI catalog (HTTP call injected, like ``flux_syslog_query``).
  NMAS itself stores no telemetry history, so without a reader the answer is explicit ``unavailable`` -- nothing is invented.

Every function degrades to ``{"status": "unavailable", ...}`` / per-device UNKNOWN instead of raising for source failures.
"""

from __future__ import annotations

import csv
import hashlib
import io
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from .. import contracts as c

ADAPTER_VERSION = "1"
CONFIG_SOURCE_TYPES = frozenset({"config", "config_snapshot"})
DEFAULT_MAX_SNAPSHOT_AGE_S = 86400.0  # == collectors.SOURCE_PROFILES[CONFIG_SNAPSHOT]["freshness_max_age_s"]
DEFAULT_LIMITS = {"max_series": 16, "max_points": 2000, "window_days": 30, "max_sample_age_s": 3600.0, "min_samples": 12}
_REF = re.compile(r"[A-Za-z0-9_.:\-/\[\]=]{1,96}")
_IDENT = re.compile(r"[A-Za-z0-9_.\-]{1,64}")


def _unavailable(source: str, reason: str, **extra) -> dict:
    return {"status": "unavailable", "source": source, "reason": reason, **extra}


# ======================================================================================================== configuration snapshots
def norm_lines(text: str) -> list[str]:
    """Whitespace-normalised, non-empty, non-comment lines (order preserved, duplicates removed)."""
    seen, out = set(), []
    for raw in (text or "").splitlines():
        line = " ".join(raw.split())
        if line and not line.startswith(("!", "#")) and line not in seen:
            seen.add(line)
            out.append(line)
    return out


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def orm_snapshot_reader(actor, devices: list[str], *, now: datetime) -> dict[str, dict]:
    """Newest immutable running-config snapshot per device from ``TsEvidenceRef`` (tenant/device scoped by ``actor``).  Plain dicts out."""
    from core import models as m

    out: dict[str, dict] = {}
    wanted = [d for d in devices if d and actor.can_see_device(d)]
    qs = (m.TsEvidenceRef.objects.select_related("raw_blob", "case").filter(device__in=wanted, case__tenant=actor.tenant)
          .order_by("-collected_at", "-id"))
    for ref in qs:
        if ref.device in out or ref.source_type.lower() not in CONFIG_SOURCE_TYPES or "running" not in ref.command_or_api.lower():
            continue
        blob = ref.raw_blob
        entry = {"evidence_id": ref.evidence_id, "collected_at": ref.collected_at, "platform": (ref.scope or {}).get("platform", ""),
                 "command": ref.command_or_api, "quality": ref.quality, "operator_url": ref.operator_url, "link_status": ref.link_status}
        if blob is None:
            entry.update(text=None, integrity="NO_CONTENT")
        else:
            ok = c.sha256_text(blob.content) == blob.stored_sha256
            entry.update(text=blob.content if ok else None, sha256=blob.stored_sha256, integrity="OK" if ok else "FAILED")
        out[ref.device] = entry
    return out


def orm_payload_loader(device: str, bundle_id: str, cfg_ids: list[str]) -> list[dict]:
    """Exact golden item payloads (read-only ORM) with payload-hash verification."""
    from core import models as m
    from core.services.bundles import canonical

    rows = m.ConfigurationBundleItem.objects.filter(bundle__bundle_id=bundle_id, device=device, cfg_id__in=cfg_ids).order_by("sequence")
    return [{"cfg_id": r.cfg_id, "platform": r.platform, "operation": r.operation, "payload": r.payload, "payload_hash": r.payload_hash,
             "integrity": "OK" if canonical.text_hash(r.payload) == r.payload_hash else "FAILED"} for r in rows]


class ConfigSnapshotBaseline:
    """``configs(devices)`` for ``BaselineSources``.  All collaborators are injectable so tests (and sites) can replace the ORM readers.

    * ``golden_provider(devices) -> golden dict`` (per-device ``device_scope`` with ``bundle_id``/``items``/``created_at``).
    * ``snapshot_reader(devices) -> {device: {text, collected_at, platform, evidence_id, integrity, ...}}``; ``PermissionError`` == denied.
    * ``payload_loader(device, bundle_id, cfg_ids) -> [item]``.
    * ``explain(device, line, golden_entry) -> change_id`` links a missing line to an approved change; default: none (UNAPPROVED).
    """

    def __init__(self, *, golden_provider: Callable[[list[str]], dict], snapshot_reader: Callable[[list[str]], dict],
                 payload_loader: Callable[[str, str, list[str]], list[dict]] = orm_payload_loader,
                 explain: Callable[[str, str, dict], str] | None = None, now: Callable[[], datetime] | None = None,
                 max_snapshot_age_s: float = DEFAULT_MAX_SNAPSHOT_AGE_S, max_lines: int = 5000, max_diffs: int = 50):
        self.golden_provider, self.snapshot_reader, self.payload_loader = golden_provider, snapshot_reader, payload_loader
        self.explain, self.max_age, self.max_lines, self.max_diffs = explain, max_snapshot_age_s, max_lines, max_diffs
        self._now = now or (lambda: datetime.now(tz=timezone.utc))

    @classmethod
    def from_orm(cls, actor, golden_provider, **kw) -> "ConfigSnapshotBaseline":
        clock = kw.get("now") or (lambda: datetime.now(tz=timezone.utc))
        return cls(golden_provider=golden_provider, snapshot_reader=lambda devs: orm_snapshot_reader(actor, devs, now=clock()), now=clock, **{k: v for k, v in kw.items() if k != "now"})

    def configs(self, devices: list[str]) -> dict:
        devices = sorted({d for d in devices if isinstance(d, str) and d})
        if not devices:
            return _unavailable("configs", "no devices in scope")
        try:
            golden = self.golden_provider(devices)
        except Exception as exc:  # pylint: disable=broad-exception-caught  # noqa: BLE001
            return _unavailable("configs", f"golden source failed: {type(exc).__name__}")
        if golden.get("status") != "available":
            return _unavailable("configs", f"no golden scope to compare against ({golden.get('reason', 'unavailable')})")
        scope = {e["device"]: {**e, "bundle_id": e.get("bundle_id") or e.get("revision", ""), "approved_change_id": e.get("approved_change_id") or golden.get("approved_change_id", "")}
                 for e in golden.get("device_scope", []) if e.get("status", "COVERED") == "COVERED" and (e.get("bundle_id") or e.get("revision"))}
        try:
            snaps = self.snapshot_reader(sorted(scope)) if scope else {}
        except PermissionError:
            return _unavailable("configs", "snapshot reader denied", denied=True)
        except Exception as exc:  # pylint: disable=broad-exception-caught  # noqa: BLE001
            return _unavailable("configs", f"snapshot reader failed: {type(exc).__name__}")
        now = self._now()
        results, unknown = {}, {}
        for dev in devices:
            if dev not in scope:
                unknown[dev] = {"reason": "NO_GOLDEN_COVERAGE", "detail": "no golden item for this device; intended configuration is UNKNOWN"}
                continue
            res = self._device(dev, scope[dev], snaps.get(dev), now)
            (unknown if res.get("unknown") else results)[dev] = res.get("unknown") or res
        if not results:
            return _unavailable("configs", "no device could be compared (see unknown_devices)", unknown_devices=unknown)
        return {"status": "available", "source": "tsevidence:config+configuration-bundle", "adapter_version": ADAPTER_VERSION, "devices": results,
                "unknown_devices": unknown, "coverage": "FULL" if not unknown else "PARTIAL", "gathered_at": c.iso(now),
                "scope_note": "only lines defined by the device's golden bundle items are compared; other running configuration is out of scope"}

    def _device(self, dev: str, g: dict, snap: dict | None, now: datetime) -> dict:
        def unk(code, detail, **extra):
            return {"unknown": {"reason": code, "detail": detail, "golden_revision": g.get("bundle_id"), **extra}}

        if not snap:
            return unk("NO_SNAPSHOT", "no immutable running-config snapshot exists for this device")
        if snap.get("integrity") != "OK" or not isinstance(snap.get("text"), str):
            return unk("SNAPSHOT_INTEGRITY", f"snapshot {snap.get('evidence_id', '')} content unavailable/failed integrity ({snap.get('integrity')})",
                       evidence_id=snap.get("evidence_id"))
        taken = c.parse_time(snap.get("collected_at"))
        if taken is None:
            return unk("SNAPSHOT_UNDATED", "snapshot has no collection time", evidence_id=snap.get("evidence_id"))
        age = (now - taken).total_seconds()
        if age > self.max_age:
            return unk("STALE_SNAPSHOT", f"snapshot is {age / 3600:.1f}h old (> {self.max_age / 3600:.0f}h)", evidence_id=snap.get("evidence_id"), snapshot_at=c.iso(taken))
        created = c.parse_time(g.get("created_at"))
        if created and taken < created:
            return unk("SNAPSHOT_PREDATES_GOLDEN", "snapshot was taken before the golden revision existed; it cannot show conformity to it",
                       evidence_id=snap.get("evidence_id"), snapshot_at=c.iso(taken))
        cfg_ids = [i["cfg_id"] for i in g.get("items", [])]
        try:
            items = self.payload_loader(dev, g["bundle_id"], cfg_ids)
        except PermissionError:
            return unk("PAYLOAD_DENIED", "golden payload reader denied")
        except Exception as exc:  # pylint: disable=broad-exception-caught  # noqa: BLE001
            return unk("PAYLOAD_UNAVAILABLE", f"golden payload reader failed: {type(exc).__name__}")
        if {i["cfg_id"] for i in items} != set(cfg_ids) or any(i.get("integrity") != "OK" for i in items):
            return unk("GOLDEN_INTEGRITY", "golden item payloads missing or failed payload_hash verification")
        plats = {i.get("platform") for i in items if i.get("platform")}
        sp = (snap.get("platform") or "").lower()
        if sp and plats and sp not in {p.lower() for p in plats}:
            return unk("SCOPE_MISMATCH", f"snapshot platform {sp!r} != golden item platform {sorted(plats)}", evidence_id=snap.get("evidence_id"))
        run_lines = norm_lines(snap["text"])
        if len(run_lines) > self.max_lines:
            return unk("SNAPSHOT_TOO_LARGE", f"{len(run_lines)} lines exceeds the bounded comparison limit {self.max_lines}")
        running = set(run_lines)
        diffs, compared, opaque = [], 0, 0
        for item in items:
            if item.get("operation") not in ("CREATE_DEFINE", "ACTIVATE_ATTACH"):
                return unk("UNSUPPORTED_OPERATION", f"golden item {item['cfg_id']} operation {item.get('operation')!r} cannot be compared by containment")
            for line in norm_lines(item["payload"]):
                if c.REDACTED in line:
                    opaque += 1
                    continue
                compared += 1
                if line not in running:
                    cid = (self.explain(dev, line, g) if self.explain else "") or ""
                    diffs.append({"path": f"{item['cfg_id']}: {line[:120]}", "golden": line, "running": None, "summary": "golden line absent from running configuration",
                                  "change_id": cid, "cfg_id": item["cfg_id"]})
        if compared == 0:
            return unk("NOTHING_COMPARABLE", f"no comparable (non-redacted) golden lines ({opaque} redacted)")
        golden_hash = _sha("|".join(sorted(f"{i['cfg_id']}:{i['payload_hash']}" for i in items)))
        return {"golden_hash": golden_hash, "running_hash": snap.get("sha256") or _sha(snap["text"]), "diffs": diffs[: self.max_diffs], "diff_total": len(diffs),
                "compared_lines": compared, "unverifiable_lines": opaque, "golden_revision": g.get("bundle_id"), "golden_digest": g.get("digest"),
                "golden_url": g.get("url"), "snapshot_evidence_id": snap.get("evidence_id"), "snapshot_at": c.iso(taken),
                "snapshot_age_s": round(age, 1), "snapshot_url": snap.get("operator_url") or "", "platform_verified": bool(sp and plats),
                "golden_approved_change_id": g.get("approved_change_id", "")}


# ======================================================================================================= telemetry history
def flux_series_query(bucket: str, series: dict, *, start: str, stop: str | None = None, device_tag: str = "device") -> str:
    """Flux for one declared series.  Measurement/field are validated against the repository's gNMI stream catalog; device/ranges are strict-regex."""
    from .monitoring import load_gnmi_stream_catalog

    measurement, field, device = series.get("measurement", ""), series.get("field", ""), series.get("device", "")
    catalog = load_gnmi_stream_catalog()
    fields = {f for s in catalog["streams"] for f in (s["field"] if isinstance(s["field"], list) else [s["field"]]) if s.get("measurement") == measurement}
    if field not in fields:
        raise ValueError("series is not in the gNMI stream catalog")
    if not _IDENT.fullmatch(device) or not _IDENT.fullmatch(device_tag) or not re.fullmatch(r"[A-Za-z0-9_.\-]{1,64}", bucket):
        raise ValueError("invalid device/tag/bucket")
    if not all(re.fullmatch(r"(-\d{1,4}[smhd]|\d{4}-\d\d-\d\dT[\d:.]+Z)", v) for v in (start, stop) if v):
        raise ValueError("invalid range")
    rng = f"start: {start}" + (f", stop: {stop}" if stop else "")
    return (f'from(bucket: "{bucket}") |> range({rng}) |> filter(fn: (r) => r._measurement == "{measurement}" and r.{device_tag} == "{device}" '
            f'and r._field == "{field}") |> keep(columns: ["_time", "_value"]) |> sort(columns: ["_time"])')


def parse_flux_samples(text: str) -> list[dict]:
    """Annotated-CSV Flux response -> ``[{t, value}]`` (non-numeric rows dropped)."""
    out, header = [], None
    for rec in csv.reader(io.StringIO(text)):
        if not rec or rec[0].startswith("#"):
            continue
        if "_value" in rec and "_time" in rec:
            header = rec
            continue
        if header and len(rec) == len(header):
            row = dict(zip(header, rec))
            try:
                out.append({"t": row["_time"], "value": float(row["_value"])})
            except (KeyError, ValueError):
                continue
    return out


class FluxHistoryReader:
    """Reader over the existing InfluxDB query layer; ``query_fn(flux) -> csv text`` is injected (this module opens no connection)."""

    def __init__(self, query_fn: Callable[[str], str], bucket: str, *, device_tag: str = "device"):
        self.query_fn, self.bucket, self.device_tag = query_fn, bucket, device_tag

    def __call__(self, request: dict) -> list[dict]:
        flux = flux_series_query(self.bucket, request, start=request["start"], stop=request.get("stop"), device_tag=self.device_tag)
        return parse_flux_samples(self.query_fn(flux))


def clean_samples(samples: Any, *, kind: str, now: datetime, max_points: int) -> dict:
    """Validate/ordering/dedup, drop future samples and (for counters) convert to per-second rates, discarding the interval across a RESET."""
    pts, dropped = [], {"invalid": 0, "future": 0, "duplicate": 0}
    seen = set()
    for s in samples if isinstance(samples, list) else []:
        t, v = c.parse_time(s.get("t")) if isinstance(s, dict) else None, (s or {}).get("value") if isinstance(s, dict) else None
        if t is None or isinstance(v, bool) or not isinstance(v, (int, float)) or v != v:
            dropped["invalid"] += 1
        elif t > now:
            dropped["future"] += 1
        elif t in seen:
            dropped["duplicate"] += 1
        else:
            seen.add(t)
            pts.append((t, float(v)))
    pts.sort()
    truncated = len(pts) > max_points
    pts = pts[-max_points:]
    resets = 0
    if kind == "counter":
        rates = []
        for (t0, v0), (t1, v1) in zip(pts, pts[1:]):
            if v1 < v0:
                resets += 1  # counter reset / device restart: the interval is unusable, never a negative rate
                continue
            rates.append((t1, (v1 - v0) / max((t1 - t0).total_seconds(), 1e-9)))
        pts = rates
    return {"samples": [{"t": c.iso(t), "value": v} for t, v in pts], "resets": resets, "dropped": dropped, "truncated": truncated}


class HistoryBaseline:
    """``history(flow, devices, now)`` for ``BaselineSources`` over declared series (``flow['history_series']``) and an injected bounded reader.

    Series entry: ``{"ref", "device", "measurement", "field", "kind": "gauge"|"counter"}``.  Devices outside the case scope are refused
    (never queried).  ``reader(request) -> [{t, value}]``; ``PermissionError`` marks that series ``DENIED``.
    """

    def __init__(self, reader: Callable[[dict], Any] | None, *, limits: dict | None = None):
        self.reader, self.limits = reader, {**DEFAULT_LIMITS, **(limits or {})}

    def __call__(self, flow: dict, devices: list[str], now: datetime) -> dict:
        from ..baselines import learn_history

        if self.reader is None:
            return _unavailable("history", "no history reader is configured (NMAS stores no telemetry history; inject a bounded monitoring reader)")
        declared = (flow or {}).get("history_series")
        if not isinstance(declared, list) or not declared:
            return _unavailable("history", "the case flow declares no history_series; nothing to learn from")
        lim, scope = self.limits, set(devices)
        end, start = now, now - timedelta(days=lim["window_days"])
        series, stats, per, refused = {}, {}, {}, []
        for spec in declared[: lim["max_series"]]:
            ref = spec.get("ref") if isinstance(spec, dict) else None
            if not isinstance(ref, str) or not _REF.fullmatch(ref) or spec.get("kind", "gauge") not in ("gauge", "counter"):
                refused.append({"ref": str(ref)[:40], "reason": "INVALID_SERIES"})
                continue
            if spec.get("device") not in scope:
                per[ref] = {"state": "DENIED", "reason": "series device is outside the case scope; not queried"}
                continue
            request = {"ref": ref, "device": spec["device"], "measurement": spec.get("measurement", ""), "field": spec.get("field", ""),
                       "start": c.iso(start), "stop": c.iso(end), "max_points": lim["max_points"]}
            try:
                raw = self.reader(request)
            except PermissionError:
                per[ref] = {"state": "DENIED", "reason": "history reader denied this query"}
                continue
            except Exception as exc:  # pylint: disable=broad-exception-caught  # noqa: BLE001
                per[ref] = {"state": "UNAVAILABLE", "reason": f"history reader failed: {type(exc).__name__}"}
                continue
            cleaned = clean_samples(raw, kind=spec.get("kind", "gauge"), now=now, max_points=lim["max_points"])
            learned = learn_history(cleaned["samples"], now=now, key=ref, min_samples=lim["min_samples"], max_age_days=lim["window_days"])
            newest = c.parse_time(learned.get("newest"))
            age = (now - newest).total_seconds() if newest else None
            fresh = "UNKNOWN" if age is None else "FRESH" if age <= lim["max_sample_age_s"] else "AGED"
            series[ref] = cleaned["samples"]
            stats[ref] = {**learned, "device": spec["device"], "kind": spec.get("kind", "gauge"), "resets": cleaned["resets"], "dropped": cleaned["dropped"],
                          "truncated": cleaned["truncated"], "sample_freshness": fresh, "newest_age_s": None if age is None else round(age, 1)}
            per[ref] = {"state": learned["state"], "reason": learned.get("reason", "")}
        learned_refs = [r for r, s in stats.items() if s["state"] == "LEARNED"]
        if not stats:
            return _unavailable("history", "no series could be read", series_state=per, refused=refused)
        newest = max((c.parse_time(s.get("newest")) for s in stats.values() if s.get("newest")), default=None)
        return {"status": "available", "source": "monitoring-history-reader", "adapter_version": ADAPTER_VERSION, "series": series, "stats": stats,
                "series_state": per, "refused": refused, "lkg_at": c.iso(newest) if newest else None, "revision": c.iso(end),
                "coverage": "FULL" if len(learned_refs) == len(declared) else "PARTIAL" if learned_refs else "NONE",
                "devices_covered": sorted({stats[r]["device"] for r in learned_refs}), "devices_uncovered": sorted(scope - {stats[r]["device"] for r in learned_refs}),
                "window": {"start": c.iso(start), "end": c.iso(end)}}
