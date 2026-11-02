"""The automation transport: a small, explicit, READ-ONLY data-access layer over the NMAS deployment database.

Why the database and not the website: the console must keep working when ``nmas-web.service`` is down, and scraping HTML is not a
transport.  The NMAS automation records (Changes, execution / validation / check runs, bundles, the probation soak and its samples,
traffic runs, provisioning requests, credential-rotation runs) are rows in the deployment's SQLite file, so they are read there.

Read-only is enforced three ways, not assumed:

* the file is opened with the SQLite URI ``mode=ro`` -- the library refuses every write at the VFS;
* ``PRAGMA query_only = ON`` on the connection;
* this module contains only the fixed ``SELECT`` statements below.  No statement is built from input, there is no ``execute`` taking
  caller SQL, no migration and no Django ORM (so no Django settings / app loading is needed).

Each refresh opens a connection, reads, and closes it: no lock is held between refreshes.  A locked or busy database is a fixed
``DB_BUSY`` error for that cycle (the collector backs off and the view keeps the last good data, marked stale).

Secrets: every query names its columns.  ``core_devicecredential.secret_ref`` / ``ssh_key_ref`` / key material, soak / bundle
payloads, raw traffic output and report bodies are never selected.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path

from ..models import iso, parse_time

FRESH, STALE, NO_SAMPLE = "FRESH", "STALE", "NO_SAMPLE"      # the project's soak collector vocabulary (soak/overview.py)

QUERIES = {
    "changes": "SELECT id, change_id, title, category, execution_mode, lifecycle_state, validation_state, created_by, created_at, updated_at "
               "FROM core_change ORDER BY id DESC LIMIT ?",
    "executions": "SELECT e.run_id, c.change_id, e.mode, e.state, e.outcome, e.actor, e.devices, e.started_at, e.finished_at, "
                  "e.precheck_run_id, e.postcheck_run_id FROM core_changeexecutionrun e LEFT JOIN core_change c ON c.id = e.change_id "
                  "ORDER BY e.id DESC LIMIT ?",
    "validations": "SELECT v.run_id, c.change_id, v.status, v.created_by, v.created_at FROM core_changevalidationrun v "
                   "LEFT JOIN core_change c ON c.id = v.change_id ORDER BY v.id DESC LIMIT ?",
    "config_validations": "SELECT n.run_id, c.change_id, n.operation_type, n.status, n.device, n.platform, n.created_at "
                          "FROM core_networkconfigvalidationrun n LEFT JOIN core_change c ON c.id = n.change_id ORDER BY n.id DESC LIMIT ?",
    "checks": "SELECT o.id, o.run_id, c.change_id, o.mode, o.status, o.device, o.started_at, o.finished_at FROM core_operationalcheckrun o "
              "LEFT JOIN core_change c ON c.id = o.change_id ORDER BY o.id DESC LIMIT ?",
    "bundles": "SELECT b.id, b.bundle_id, b.kind, b.provenance, p.bundle_id AS parent, c.change_id, b.created_by, b.created_at "
               "FROM core_configurationbundle b LEFT JOIN core_configurationbundle p ON p.id = b.parent_id "
               "LEFT JOIN core_change c ON c.id = b.change_id ORDER BY b.id DESC LIMIT ?",
    "traffic": "SELECT run_id, operator, source, destination, address_family, family, protocol, status, failure_reason, started_at, "
               "finished_at FROM core_trafficrun ORDER BY id DESC LIMIT ?",
    "provisioning": "SELECT id, device_name, platform, role, status, bootstrap_state, requested_by, created_at, updated_at, finished_at "
                    "FROM core_provisioningrun ORDER BY id DESC LIMIT ?",
    "rotation_runs": "SELECT r.run_id, d.device_name, d.username, r.trigger_reason, r.phase, r.final_status, r.error_category, r.started_at, "
                     "r.completed_at FROM core_credentialrotationrun r LEFT JOIN core_devicecredential d ON d.id = r.credential_id "
                     "ORDER BY r.id DESC LIMIT ?",
    "rotation_policy": "SELECT device_name, username, account_kind, rotation_enabled, rotation_interval_days, last_rotated_at, next_due_at, "
                       "last_status FROM core_devicecredential WHERE rotation_enabled = 1 ORDER BY device_name, username LIMIT ?",
    "soaks": "SELECT s.id, s.state, s.result, s.terminal_reason, s.policy, s.started_at, s.required_end_at, s.finished_at, s.started_by, "
             "s.baseline, b.bundle_id, pb.bundle_id AS root_bundle, c.change_id FROM core_probationsoakrun s "
             "JOIN core_configurationbundle b ON b.id = s.bundle_id LEFT JOIN core_configurationbundle pb ON pb.id = b.parent_id "
             "LEFT JOIN core_change c ON c.id = b.change_id ORDER BY s.id DESC LIMIT ?",
    "soak_latest_sample": "SELECT bucket, sampled_at, result, integrity_ok, interference, expected_state_result, device_health, "
                          "telemetry_freshness, monitoring_state, config_drift, evidence FROM core_probationsoaksample "
                          "WHERE run_id = ? ORDER BY bucket DESC, id DESC LIMIT 1",
    "soak_sample_counts": "SELECT result, COUNT(*) AS n FROM core_probationsoaksample WHERE run_id = ? GROUP BY result",
    "soak_decision": "SELECT decision, decided_by, decided_at FROM core_goldendecision WHERE run_id = ? ORDER BY id DESC LIMIT 1",
    "golden": "SELECT bundle_id, created_at FROM core_configurationbundle WHERE kind = 'GOLDEN' ORDER BY id DESC LIMIT 1",
}
_TIME_COLUMNS = frozenset({"created_at", "updated_at", "started_at", "finished_at", "completed_at", "required_end_at", "sampled_at",
                           "decided_at", "last_rotated_at", "next_due_at"})
_OPTIONAL = frozenset({"provisioning", "rotation_runs", "rotation_policy", "traffic", "config_validations", "golden"})


class AutomationUnavailable(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def connect(path: Path, *, busy_timeout: float = 2.0) -> sqlite3.Connection:
    """A connection that cannot write: URI ``mode=ro`` plus ``query_only``.  A missing file is an error, never a new database."""
    if not Path(path).is_file():
        raise AutomationUnavailable("DB_NOT_FOUND")
    try:
        connection = sqlite3.connect(f"{Path(path).resolve().as_uri()}?mode=ro", uri=True, timeout=busy_timeout, check_same_thread=False)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only = ON")
        return connection
    except sqlite3.Error as exc:
        raise AutomationUnavailable(_classify(exc)) from exc


def _classify(exc: sqlite3.Error) -> str:
    text = str(exc).lower()
    if "locked" in text or "busy" in text:
        return "DB_BUSY"
    if "no such table" in text or "no such column" in text:
        return "DB_SCHEMA_MISMATCH"
    if "unable to open" in text:
        return "DB_NOT_READABLE"
    if "readonly" in text or "read-only" in text:
        return "DB_READ_ONLY_VIOLATION"
    return "DB_ERROR"


def _rows(connection, name: str, *params) -> list[dict]:
    try:
        cursor = connection.execute(QUERIES[name], params)
    except sqlite3.Error as exc:
        code = _classify(exc)
        if code == "DB_SCHEMA_MISMATCH" and name in _OPTIONAL:     # an older deployment without that feature: an empty section
            return []
        raise AutomationUnavailable(code) from exc
    found = []
    for row in cursor.fetchall():
        entry = dict(row)
        for column in _TIME_COLUMNS & entry.keys():
            entry[column] = iso(parse_time(entry[column]))
        found.append(entry)
    return found


def _json(text, default):
    try:
        value = json.loads(text) if text else default
    except ValueError:
        return default
    return value if isinstance(value, type(default)) else default


def describe_soak(row: dict, latest: dict | None, counts: dict, decision: dict | None, *, now: datetime) -> dict:
    """The probation picture of one soak, using the project's own definitions (``soak/overview.py``):

    collector  FRESH = a sample within two sample intervals; NO_SAMPLE = none yet and the soak only just started; else STALE.
    eligibility  RUNNING -> IN_PROBATION; COMPLETED + PASS -> ELIGIBLE_DECISION_REQUIRED (or DECIDED_<decision>); else NOT_ELIGIBLE.
    """
    policy = _json(row.get("policy"), {})
    baseline = _json(row.get("baseline"), {})
    interval = int(policy.get("sample_interval_seconds") or 900)
    started, due, finished = parse_time(row["started_at"]), parse_time(row["required_end_at"]), parse_time(row.get("finished_at"))
    reference = finished or now
    elapsed = max(0.0, (min(reference, due) - started).total_seconds()) if started and due else None
    remaining = max(0.0, (due - reference).total_seconds()) if due else None
    duration = (due - started).total_seconds() if started and due else None
    devices = sorted((baseline.get("devices") or {}).keys())
    sample, drift = None, []
    if latest:
        evidence = _json(latest.get("evidence"), {})
        sampled = parse_time(latest["sampled_at"])
        age = (now - sampled).total_seconds() if sampled else None
        collector = {"state": FRESH if age is not None and age <= 2 * interval else STALE, "last_sample_at": iso(sampled),
                     "age_seconds": age, "expected_every_seconds": interval}
        sample = {"bucket": latest["bucket"], "sampled_at": iso(sampled), "result": latest["result"],
                  "expected_state": latest["expected_state_result"], "device_health": latest["device_health"],
                  "telemetry_freshness": latest["telemetry_freshness"], "monitoring_state": latest["monitoring_state"],
                  "integrity_ok": bool(latest["integrity_ok"]), "interference": bool(latest["interference"]),
                  "config_drift": bool(latest["config_drift"])}
        for name, state in sorted((evidence.get("config") or {}).items()):
            if isinstance(state, dict):
                drift.append({"device": name, "state": str(state.get("state") or ""), "baseline": str(state.get("baseline") or "")[:12],
                              "current": str(state.get("current") or "")[:12], "changed_sections": list(state.get("changed_sections") or [])})
    else:
        age = (now - started).total_seconds() if started else None
        collector = {"state": NO_SAMPLE if age is not None and age <= 2 * interval else STALE, "last_sample_at": "", "age_seconds": age,
                     "expected_every_seconds": interval}
    if not drift:
        drift = [{"device": name, "state": "NOT_SAMPLED", "baseline": str((baseline["devices"][name] or {}).get("digest") or "")[:12],
                  "current": "", "changed_sections": []} for name in devices]
    if row["state"] == "RUNNING":
        eligibility = {"code": "IN_PROBATION", "text": "In probation. Not eligible for Golden before the full policy period has elapsed."}
    elif row["state"] == "COMPLETED" and row["result"] == "PASS":
        if decision:
            eligibility = {"code": f"DECIDED_{decision['decision']}", "text": f"Operator decision: {decision['decision']}."}
        else:
            eligibility = {"code": "ELIGIBLE_DECISION_REQUIRED",
                           "text": "The full period passed with sufficient healthy evidence. The operator's Golden decision is required."}
    else:
        eligibility = {"code": "NOT_ELIGIBLE", "text": "This soak ended without passing and can never become Golden."}
    drift_states = {entry["state"] for entry in drift}
    return {
        "soak_id": f"SOAK-{int(row['id']):06d}", "state": row["state"], "result": row["result"], "terminal_reason": row["terminal_reason"],
        "bundle_id": row["bundle_id"], "root_bundle": row.get("root_bundle") or "", "change_id": row.get("change_id") or "",
        "devices": devices, "started_by": row["started_by"], "started_at": iso(started), "due_at": iso(due), "finished_at": iso(finished),
        "elapsed_seconds": elapsed, "remaining_seconds": remaining, "duration_seconds": duration,
        "percent_elapsed": round(100.0 * elapsed / duration, 2) if elapsed is not None and duration else None,
        "policy": {"duration_seconds": policy.get("duration_seconds"), "sample_interval_seconds": interval,
                   "min_coverage_percent": policy.get("min_coverage_percent"), "max_gap_seconds": policy.get("max_gap_seconds")},
        "collector": collector, "latest_sample": sample, "sample_counts": counts, "samples": sum(counts.values()),
        "drift": drift, "drift_state": "DRIFT" if "DRIFT" in drift_states or (sample and sample["config_drift"]) else
                                       "MATCH" if drift_states == {"MATCH"} else "/".join(sorted(drift_states)) or "UNKNOWN",
        "health": (sample or {}).get("device_health", ""), "eligibility": eligibility,
    }


def read_snapshot(path: Path, *, now: datetime, limit: int = 25, busy_timeout: float = 2.0) -> dict:
    """Everything the Automation view shows, in one short read-only session.  Raises ``AutomationUnavailable`` with a fixed code."""
    connection = connect(path, busy_timeout=busy_timeout)
    try:
        snapshot = {name: _rows(connection, name, limit) for name in
                    ("changes", "executions", "validations", "config_validations", "checks", "bundles", "traffic", "provisioning",
                     "rotation_runs", "rotation_policy")}
        soaks = []
        for row in _rows(connection, "soaks", limit):
            latest = _rows(connection, "soak_latest_sample", row["id"])
            counts = {entry["result"]: entry["n"] for entry in _rows(connection, "soak_sample_counts", row["id"])}
            decision = _rows(connection, "soak_decision", row["id"])
            soaks.append(describe_soak(row, latest[0] if latest else None, counts, decision[0] if decision else None, now=now))
        golden = _golden(connection)
        snapshot.update({"soaks": soaks, "golden": golden})
        return snapshot
    finally:
        connection.close()


def _golden(connection) -> dict | None:
    try:
        row = connection.execute(QUERIES["golden"]).fetchone()
    except sqlite3.Error:
        return None
    return {"bundle_id": row["bundle_id"], "created_at": iso(parse_time(row["created_at"]))} if row else None
