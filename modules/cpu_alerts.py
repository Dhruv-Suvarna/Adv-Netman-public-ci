"""NMAS collector-generated CPU threshold alerting.

This module consumes REAL HOST-RESOURCES-MIB::hrProcessorLoad values already
obtained by the existing SNMP poll path in `modules/snmp.py:collect()` -- it
never polls a device itself and never fabricates a CPU sample. It implements
the second, explicitly accepted path in `LAB_REQUIREMENTS.md` section 4
"Notifications": "NMAS-side threshold alerting generated from repeated CPU
polls, stored as an event and clearly labelled as collector-generated rather
than a device SNMP trap."

Every stored event:
  - is written to the InfluxDB measurement `collector_alert`, never
    `snmp_trap` (which is reserved for device-originated SNMPv3
    notifications: linkUp/linkDown/coldStart/test);
  - carries `source=collector` and `alert_type=cpu_threshold` tags, and a
    `monitoring_method=snmp_polling` tag, so it can never be mistaken for a
    device-emitted trap by anyone querying InfluxDB or reading Grafana;
  - is produced by simple consecutive-sample + hysteresis state logic (see
    `evaluate_cpu_threshold`) so a single instantaneous poll cannot create an
    alert storm, and so a repeated high reading does not create a duplicate
    event every polling cycle.

State is small, repository-owned, and persisted as one JSON file per device
(and, separately, per verification run) under
`monitoring/runtime/cpu-alert-state/`, mirroring the existing per-device
`*-snmp-state.json` convergence-state pattern in `modules/snmp.py`.
Persistence (rather than pure in-memory state) is required here because SNMP
polling in this project is not a standing background loop -- each
`--snmp-only` run performs one poll per device -- so "repeated polls" means
repeated invocations over time, and the alert/recovery state must survive
between them.
"""
from __future__ import annotations

import json
import math
import numbers
import time
from pathlib import Path

import requests
import yaml

from modules.nmas import MONITORING, NmasError

RUNTIME = MONITORING / "runtime"
STATE_DIR = RUNTIME / "cpu-alert-state"
POLICY_FILE = MONITORING / "config/cpu_threshold_policy.yml"
MEASUREMENT = "collector_alert"

LEVEL_ORDER = {"normal": 0, "warning": 1, "critical": 2}
REQUIRED_POLICY_KEYS = {"warning_pct", "critical_pct", "consecutive_samples", "recovery_pct"}


def _validate_policy(policy: dict) -> dict:
    missing = REQUIRED_POLICY_KEYS - policy.keys()
    if missing:
        raise NmasError("CPU threshold policy missing required keys: " + ", ".join(sorted(missing)))
    if not (0 < policy["recovery_pct"] < policy["warning_pct"] < policy["critical_pct"] <= 100):
        raise NmasError("CPU threshold policy must satisfy 0 < recovery_pct < warning_pct < critical_pct <= 100")
    if not isinstance(policy["consecutive_samples"], int) or policy["consecutive_samples"] < 1:
        raise NmasError("CPU threshold policy consecutive_samples must be a positive integer >= 1")
    return policy


def load_policy() -> dict:
    """The normal, repository-configured, production alerting policy."""
    return _validate_policy(dict(yaml.safe_load(POLICY_FILE.read_text())))


PRODUCTION_POLICY = load_policy()


INVALID = "invalid"


def is_valid_sample(cpu_value) -> bool:
    """A usable CPU sample is a finite real number.  None, bools, strings, NaN and +/-inf are not evidence of anything."""
    return isinstance(cpu_value, numbers.Real) and not isinstance(cpu_value, bool) and math.isfinite(cpu_value)


def classify(cpu_value: float, policy: dict) -> tuple[str, float | None]:
    """normal / warning / critical against ``policy``; ``invalid`` (fail closed, never ``normal``) for a non-finite or
    non-numeric sample.  An incomplete policy raises KeyError."""
    critical, warning = policy["critical_pct"], policy["warning_pct"]
    if not is_valid_sample(cpu_value):
        return INVALID, None
    if cpu_value >= critical:
        return "critical", critical
    if cpu_value >= warning:
        return "warning", warning
    return "normal", None


def _state_path(device: str, *, verification: bool) -> Path:
    suffix = "-verification" if verification else ""
    return STATE_DIR / f"{device}{suffix}.json"


def load_state(device: str, *, verification: bool = False) -> dict:
    path = _state_path(device, verification=verification)
    if not path.is_file():
        return {"state": "normal", "streak_level": "normal", "streak": 0}
    return json.loads(path.read_text())


def save_state(device: str, state: dict, *, verification: bool = False) -> None:
    path = _state_path(device, verification=verification)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state))
    path.chmod(0o600)


def _tag(value) -> str:
    return str(value).replace("\\", "\\\\").replace(" ", "\\ ").replace(",", "\\,").replace("=", "\\=")


def _influx() -> tuple[requests.Session, dict]:
    env = dict(line.split("=", 1) for line in (RUNTIME / "monitoring.env").read_text().splitlines() if "=" in line)
    session = requests.Session()
    session.trust_env = False
    session.headers["Authorization"] = "Token " + env["INFLUXDB_TOKEN"]
    return session, env


def write_event(event: dict) -> None:
    """Persist one collector-generated CPU threshold event to InfluxDB.

    Measurement is always `collector_alert` -- deliberately distinct from
    `snmp_trap` (device-originated notifications) so the two can never be
    confused in storage, in a query, or on a dashboard.
    """
    session, env = _influx()
    tags = ",".join(
        f"{key}={_tag(event[key])}"
        for key in ("device", "platform", "alert_type", "source", "severity", "transition", "monitoring_method")
    )
    tags += f",verification={'true' if event['verification'] else 'false'}"
    fields = (
        f'value=1i,cpu_value={float(event["cpu_value"])},threshold_pct={float(event["threshold_pct"])},'
        f'consecutive_samples={int(event["consecutive_samples"])}i,'
        f'previous_state="{event["previous_state"]}"'
    )
    line = f"{MEASUREMENT},{tags} {fields} {event['timestamp_ns']}"
    response = session.post(
        "http://127.0.0.1:8086/api/v2/write",
        params={"org": env["INFLUXDB_ORG"], "bucket": env["INFLUXDB_BUCKET"], "precision": "ns"},
        data=line,
        timeout=15,
    )
    response.raise_for_status()


def confirm_stored(event: dict, timeout: int = 15) -> bool:
    """Query the same event back from InfluxDB (like modules/snmp.py:collect() does for snmp_poll)."""
    session, env = _influx()
    stamp = event["timestamp_ns"]
    query = (
        f'from(bucket: {json.dumps(env["INFLUXDB_BUCKET"])}) '
        f"|> range(start: time(v: {stamp}), stop: time(v: {stamp + 1})) "
        f'|> filter(fn: (r) => r._measurement == "{MEASUREMENT}" and r.device == "{event["device"]}" '
        f'and r.transition == "{event["transition"]}")'
    )
    response = session.post(
        "http://127.0.0.1:8086/api/v2/query",
        params={"org": env["INFLUXDB_ORG"]},
        headers={"Content-Type": "application/vnd.flux"},
        data=query,
        timeout=timeout,
    )
    response.raise_for_status()
    return event["device"] in response.text and MEASUREMENT in response.text


def evaluate_cpu_threshold(
    device: str,
    platform: str,
    cpu_value: float,
    *,
    policy: dict | None = None,
    verification: bool = False,
    timestamp_ns: int | None = None,
) -> dict | None:
    """Apply consecutive-sample + hysteresis alert-state logic to ONE real,
    already-SNMP-polled CPU value for `device`, and store a `collector_alert`
    event in InfluxDB if (and only if) a state transition warrants one.

    Returns the stored event dict, or None when no event was written (the
    common case: normal CPU, a transient excursion below the required
    consecutive-sample count, or an ongoing alert/normal state that has
    already been reported).

    `policy` defaults to the repository production policy
    (`monitoring/config/cpu_threshold_policy.yml`) and is never mutated by a
    `verification=True` call -- callers pass an explicit, separate policy
    dict for verification, and verification state is tracked in its own,
    separate per-device state file so it can never interfere with the
    production alert state for that device (or any other device).
    """
    active_policy = _validate_policy(dict(policy)) if policy is not None else PRODUCTION_POLICY
    level, threshold = classify(cpu_value, active_policy)
    if level == INVALID:
        # A non-finite / non-numeric sample is no evidence: it neither recovers an alert nor raises one, and it does not
        # touch the stored streak.  Nothing is written.
        return None
    state = load_state(device, verification=verification)

    if level == state.get("streak_level"):
        state["streak"] = state.get("streak", 0) + 1
    else:
        state["streak_level"] = level
        state["streak"] = 1

    current = state.get("state", "normal")
    event = None

    if level == "normal":
        if current != "normal" and cpu_value <= active_policy["recovery_pct"]:
            event = {
                "device": device,
                "platform": platform,
                "alert_type": "cpu_threshold",
                "source": "collector",
                "severity": "info",
                "transition": "recovery",
                "previous_state": current,
                "cpu_value": cpu_value,
                "threshold_pct": active_policy["recovery_pct"],
                "consecutive_samples": state["streak"],
                "monitoring_method": "snmp_polling",
                "verification": verification,
            }
            state["state"] = "normal"
    elif state["streak"] >= active_policy["consecutive_samples"] and LEVEL_ORDER[level] > LEVEL_ORDER.get(current, 0):
        event = {
            "device": device,
            "platform": platform,
            "alert_type": "cpu_threshold",
            "source": "collector",
            "severity": level,
            "transition": "alert",
            "previous_state": current,
            "cpu_value": cpu_value,
            "threshold_pct": threshold,
            "consecutive_samples": state["streak"],
            "monitoring_method": "snmp_polling",
            "verification": verification,
        }
        state["state"] = level

    save_state(device, state, verification=verification)

    if event is not None:
        event["timestamp_ns"] = timestamp_ns if timestamp_ns is not None else time.time_ns()
        write_event(event)
    return event
