"""Running-configuration snapshot ingestion for the config-vs-golden baseline (spec 3.3 / 6.3; docs/troubleshooting/config-snapshot.md).

Read-only, no network code and no credentials: collection goes through the EXISTING ``collectors.CliCollector`` (catalogue entries
``running_config`` for ceos/iosxe and ``frr_config`` for linux, admission + capability gate, budgets, redaction, gateway provenance) over a transport
the deployment injects.  This module only (a) decides whether/what to collect, (b) marks degraded collections so they can never pass as a usable
snapshot, (c) supplies the platform scope persisted on the evidence row and (d) wraps ``baseline_history.orm_snapshot_reader`` with fail-closed guards.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable

from .. import collectors as col
from .. import normalization as nz
from . import baseline_history as bh

ADAPTER_VERSION = "1"
WANT_KEY = "configs"
SNAPSHOT_KEYS = {"ceos": "running_config", "iosxe": "running_config", "linux": "frr_config"}   # canonical platform -> catalogue key


def snapshot_key(platform: str) -> str | None:
    """Catalogue key of the running-config read for ``platform`` (None => no catalogued read: the platform is not guessed)."""
    key = SNAPSHOT_KEYS.get(nz.canonical_platform(platform))
    return key if key and col.COMMAND_CATALOG.get(nz.canonical_platform(platform), {}).get(key) is not None else None


def requested(wanted) -> bool:
    return WANT_KEY in set(wanted)


def evidence_scope(evidence: dict) -> dict:
    """Extra provenance scope for a stored config-snapshot evidence row (``platform`` is what ``orm_snapshot_reader`` and the golden scope check read)."""
    return {"platform": evidence.get("platform") or "", "os_version": evidence.get("os_version") or "", "snapshot_kind": "running-config",
            "config_snapshot_adapter": ADAPTER_VERSION}


def degrade_empty(bundle: dict) -> dict:
    """An empty running-config is a failed read, not an empty configuration: mark its evidence PARTIAL and add an explicit missing record, so that
    it can never be compared against golden lines (which would report every golden line as drift)."""
    for e in bundle.get("evidence", []):
        if e.get("source_type") == col.SourceType.CONFIG_SNAPSHOT and not (e.get("raw_ref") or {}).get("bytes"):
            e["status"], e["status_detail"] = "PARTIAL", "device returned an empty running configuration"
            bundle.setdefault("missing", []).append(nz.missing_record(
                nz.Missing.EMPTY, source_type=col.SourceType.CONFIG_SNAPSHOT, device=e.get("device", ""), command=e["command_or_api"],
                observed_at=col.to_utc(e["collected_at"]), evidence_id=e["evidence_id"],
                detail="empty running-config output; configuration is UNKNOWN (not an empty configuration)"))
    return bundle


def admission(cli: "col.CliCollector", target: "col.Target") -> "col.Admission":
    """CONFIG_SNAPSHOT-specific capability/admission gate (the CLI collector only gates the CLI source type); evaluated before any transport is touched."""
    return col.check_admission(target, col.SourceType.CONFIG_SNAPSHOT, capability_probe=cli.capability_probe, authorized_sources=cli.authorized_sources)


def collect(cli: "col.CliCollector", target: "col.Target", transport, *, transport_name: str = "cli") -> dict | None:
    """One bounded read of the platform's running config via the canonical CLI collector (None => no catalogued command)."""
    key = snapshot_key(target.platform)
    if key is None:
        return None
    return degrade_empty(cli.collect(target, [key], transport, transport_name=transport_name))


# ---------------------------------------------------------------------------------------------------------------- reading (baseline side)
def guarded_reader(actor, *, now: Callable[[], datetime] | None = None) -> Callable[[list[str]], dict]:
    """``snapshot_reader`` for ``ConfigSnapshotBaseline``: newest immutable snapshot per device, with per-device fail-closed states.

    DENIED (actor may not see the device), PARTIAL (non-GOOD quality evidence), EMPTY (no content) => ``text`` is withheld and the integrity
    marker makes the baseline report the device as UNKNOWN; they are never treated as conforming or as drift."""
    clock = now or (lambda: datetime.now(tz=timezone.utc))

    def read(devices: list[str]) -> dict[str, dict]:
        visible = [d for d in devices if actor.can_see_device(d)]
        out = bh.orm_snapshot_reader(actor, visible, now=clock())
        for dev in devices:
            if dev not in visible:
                out[dev] = {"evidence_id": "", "collected_at": None, "platform": "", "text": None, "integrity": "DENIED"}
                continue
            e = out.get(dev)
            if e is None or e.get("integrity") != "OK":
                continue
            if e.get("quality") not in (None, "GOOD"):
                e.update(text=None, integrity="PARTIAL")
            elif not (e.get("text") or "").strip():
                e.update(text=None, integrity="EMPTY")
        return out
    return read


def baseline_sources(actor, *, now: Callable[[], datetime] | None = None, payload_loader=bh.orm_payload_loader, **kw: Any):
    """``DjangoBaselineSources`` whose ``configs`` uses the guarded reader (golden side = the same sources' device-scoped golden selection)."""
    from .. import baselines as bl
    holder: dict[str, Any] = {}
    adapter = bh.ConfigSnapshotBaseline(golden_provider=lambda devs: holder["src"].golden(devs), snapshot_reader=guarded_reader(actor, now=now), payload_loader=payload_loader, now=now)
    holder["src"] = bl.DjangoBaselineSources(actor=actor, config_adapter=adapter, **kw)
    return holder["src"]
