"""Adapters over the EXISTING monitoring sources.  No collector or database is duplicated.

* ``load_gnmi_stream_catalog`` / ``load_snmp_oids`` read ``monitoring/config/gnmi_paths.yml`` and ``snmp_oids.yml`` (the files that
  ``modules/gnmi.py`` / ``modules/snmp.py`` themselves load) instead of copying paths/OIDs; ``verify_oid_consistency`` proves our IF-MIB
  columns equal the repository's.
* ``flux_syslog_query`` / ``parse_flux_csv`` reuse the ``syslog_event`` measurement written by the existing rsyslog -> InfluxDB pipeline
  (see ``modules/syslog.py::influx_contains``); the HTTP call itself is injected (``query_fn``), because this module never opens a
  network connection or reads ``monitoring.env``.
* ``TopologyTelemetryCollector`` turns the existing ``health.telemetry`` snapshot (topology service, InfluxDB-derived) into evidence +
  interface observations without any device contact.
"""

from __future__ import annotations

import csv
import io
import json
import re
from pathlib import Path

from .. import normalization as nz
from ..collectors import (IF_TABLE_COLUMNS, SOURCE_PROFILES, SourceType, Target, _BaseCollector, _refuse, build_evidence)

REPO_ROOT = Path(__file__).resolve().parents[5]
MONITORING_CONFIG = REPO_ROOT / "monitoring" / "config"


def _yaml(path: Path):
    import yaml
    return yaml.safe_load(path.read_text())


def load_gnmi_stream_catalog(path: Path | None = None) -> dict:
    data = _yaml(path or MONITORING_CONFIG / "gnmi_paths.yml")
    return {"sample_interval_ns": data["sample_interval_ns"], "streams": data["streams"], "paths": [s["path"] for s in data["streams"]]}


def gnmi_allowed_prefixes(catalog: dict | None = None) -> tuple:
    """Subscription prefixes derived from the repository's verified stream catalog (wildcards trimmed at the first ``[``)."""
    catalog = catalog or load_gnmi_stream_catalog()
    return tuple(sorted({p.split("[", 1)[0].rstrip("/") for p in catalog["paths"]}))


def load_snmp_oids(path: Path | None = None) -> dict:
    return _yaml(path or MONITORING_CONFIG / "snmp_oids.yml")


def verify_oid_consistency(oids: dict | None = None) -> list[str]:
    """Mismatches between ``IF_TABLE_COLUMNS`` and ``snmp_oids.yml`` for the names both define (empty list == consistent)."""
    oids = oids or load_snmp_oids()
    return [f"{name}: collector {IF_TABLE_COLUMNS[name]} != repository {oids[name]}" for name in IF_TABLE_COLUMNS if name in oids and oids[name] != IF_TABLE_COLUMNS[name]]


def flux_syslog_query(bucket: str, device: str, *, start: str = "-15m", pattern: str | None = None) -> str:
    """Flux for the existing ``syslog_event`` measurement.  ``device`` is validated against a strict name pattern (no query injection)."""
    if not re.fullmatch(r"[A-Za-z0-9_.\-]{1,64}", device):
        raise ValueError("invalid device name")
    if not re.fullmatch(r"-\d{1,4}[smhd]", start):
        raise ValueError("invalid range")
    query = (f'from(bucket: {json.dumps(bucket)}) |> range(start: {start}) '
             f'|> filter(fn: (r) => r._measurement == "syslog_event" and r.device == "{device}" and r._field == "message")')
    if pattern:
        if not re.fullmatch(r"[A-Za-z0-9_\- :.%]{1,80}", pattern):
            raise ValueError("invalid pattern")
        query += f' |> filter(fn: (r) => r._value =~ /{re.escape(pattern)}/)'
    return query


def parse_flux_csv(text: str) -> list[tuple[str, str]]:
    """Annotated-CSV Flux response -> ``[(message, iso time)]`` (the receive/event time Influx stored)."""
    rows, header = [], None
    for record in csv.reader(io.StringIO(text)):
        if not record or record[0].startswith("#"):
            continue
        if record[0] == "" and "_value" in record:
            header = record
            continue
        if header and len(record) == len(header):
            row = dict(zip(header, record))
            if row.get("_value"):
                rows.append((row["_value"], row.get("_time", "")))
    return rows


class TopologyTelemetryCollector(_BaseCollector):
    """Adapter over ``core.services.health.telemetry.TelemetrySnapshot`` (duck-typed: ``available``, ``nodes``, ``edges``, ``generated_at``, ``now``).

    Freshness is the topology service's own per-endpoint ``evidence_fresh``; a non-fresh endpoint produces NO state observation (UNKNOWN)."""

    source_type = SourceType.TOPOLOGY_TELEMETRY
    name = "topology-telemetry"

    def collect(self, target: Target, snapshot) -> dict:
        run, admission = self._run(target, "topology-service")
        run.commands.append("topology_service.get_topology_summary")
        run.requested = 1
        if not admission.ok:
            return _refuse(run, admission, run.commands[-1])
        if not getattr(snapshot, "available", False):
            self._fail(run, nz.Missing.TRANSPORT_ERROR, "topology/telemetry service unavailable", run.commands[-1])
            return run.bundle()
        node = snapshot.nodes.get(target.device)
        if node is None:
            self._fail(run, nz.Missing.EMPTY, "device is not in the monitored topology", run.commands[-1])
            return run.bundle()
        started = run.now()
        endpoints = [(e.get("monitor_interface") or e.get("interface"), e) for edge in snapshot.edges for e in edge.get("endpoint_state", []) if e.get("node") == target.device]
        raw = json.dumps({"node": {k: node.get(k) for k in ("id", "health", "last_telemetry_timestamp")}, "endpoints": [e for _, e in endpoints]}, sort_keys=True, default=str)
        evidence = build_evidence(seq=run.next_seq(), source_type=self.source_type, transport="topology-service", adapter=self.adapter, device=target.device, platform=target.platform,
                                  os_version=target.os_version, command_or_api=run.commands[-1], raw=raw, started_at=started, finished_at=run.now(), status="OK", store=self.raw_store,
                                  coverage={"monitored_endpoints": len(endpoints)})
        run.evidence.append(evidence)
        parser = {"id": "topology.telemetry", "version": "1.0", "template": "topology-endpoint-state", "input_kind": "dict"}
        last_seen = node.get("last_telemetry_timestamp")
        if last_seen:
            run.observations.append(nz.make_observation("telemetry.last_seen", nz.iso(nz.to_utc(last_seen)), device=target.device, evidence=evidence, observed_at=nz.to_utc(last_seen),
                                                         now=run.now(), parser=parser, max_age_s=SOURCE_PROFILES[self.source_type]["freshness_max_age_s"]))
        else:
            self._fail(run, nz.Missing.STALE_SOURCE, "no telemetry timestamp for the node", run.commands[-1])
        for name, endpoint in endpoints:
            if not name:
                continue
            if not endpoint.get("evidence_fresh"):
                self._fail(run, nz.Missing.STALE_SOURCE, f"endpoint {name}: topology service marks evidence not fresh", run.commands[-1])
                continue
            at = nz.to_utc(last_seen) if last_seen else None
            for key, field in (("interface.oper_state", "oper_status"), ("interface.admin_state", "admin_status")):
                if endpoint.get(field) is not None:
                    run.observations.append(nz.make_observation(key, (nz.norm_oper_state if "oper" in key else nz.norm_admin_state)(endpoint[field]), device=target.device, evidence=evidence,
                                                                 observed_at=at, interface=nz.canonical_interface(name, platform=target.platform), now=run.now(), parser=parser,
                                                                 flags=["MONITORED_ENDPOINT_ONLY"]))
        return run.bundle()
