"""Component health for the NMAS / monitoring stack: what was actually observed, never what is assumed.

A component is UP only when every check it has passed.  Where a component exposes a safe read-only health endpoint, that endpoint is
checked in addition to the service manager -- "systemd says active" alone is not reported as UP for those.  Where no safe
unauthenticated probe exists (FreeRADIUS needs the shared secret even for Status-Server), the row says which evidence it rests on.
"""

from __future__ import annotations

import os
import stat
from datetime import datetime

from ..models import DEGRADED, DOWN, UNKNOWN, UP, Check, ServiceObservation, utcnow
from . import http, process


# --- primitive checks --------------------------------------------------------------------------------------------------------
def systemd_properties(unit: str, properties: tuple[str, ...], *, runner=process.run, timeout: float = 8.0) -> dict | None:
    argv = ["systemctl", "show", unit]
    for name in properties:
        argv += ["-p", name]
    result = runner(tuple(argv), timeout=timeout)
    if not result.ok:
        return None
    return dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)


def systemd_check(unit: str, *, runner=process.run, timeout: float = 8.0, want: str = "active") -> Check:
    found = systemd_properties(unit, ("LoadState", "ActiveState", "SubState"), runner=runner, timeout=timeout)
    if found is None:
        return Check("systemd", None, "service manager not readable")
    if found.get("LoadState") == "not-found":
        return Check("systemd", False, f"{unit} not installed")
    state = f"{found.get('ActiveState', '?')}/{found.get('SubState', '?')}"
    return Check("systemd", found.get("ActiveState") == want, state)


def container_check(name: str, *, runner=process.run, timeout: float = 8.0) -> Check:
    template = "{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}"
    result = runner(("docker", "inspect", "-f", template, name), timeout=timeout)
    if result.error:
        return Check("container", None, "container runtime not readable")
    if not result.ok:
        return Check("container", False, "container not found")
    status, _, health = result.stdout.strip().partition("|")
    if status != "running":
        return Check("container", False, status or "not running")
    if health and health != "healthy":
        return Check("container", False, f"running/{health}")
    return Check("container", True, f"running/{health}" if health else "running (no healthcheck defined)")


def http_check(url: str, *, getter=http.get, timeout: float = 4.0, verify_tls: bool = True, expect=None, headers=None) -> tuple[Check, float | None]:
    """``expect(result) -> str``: "" when the body proves health, otherwise the fixed reason it does not."""
    result = getter(url, timeout=timeout, verify_tls=verify_tls, headers=headers)
    if result.status is None:
        return Check("http", False, result.error or "UNREACHABLE"), None
    if not result.ok:
        return Check("http", False, f"HTTP {result.status}"), result.elapsed_ms
    problem = expect(result) if expect else ""
    if problem:
        return Check("http", False, problem), result.elapsed_ms
    return Check("http", True, f"HTTP {result.status}"), result.elapsed_ms


def socket_check(path) -> Check:
    try:
        mode = os.stat(path).st_mode
    except OSError:
        return Check("socket", False, "socket path missing")
    return Check("socket", stat.S_ISSOCK(mode), "listening socket present" if stat.S_ISSOCK(mode) else "path is not a socket")


def verdict(checks: list[Check]) -> str:
    """UP = every check passed.  DOWN = the liveness check (the last one: the deepest probe) failed.  DEGRADED = mixed."""
    known = [c for c in checks if c.ok is not None]
    if not known:
        return UNKNOWN
    if all(c.ok for c in known):
        return UP
    return DOWN if not known[-1].ok else DEGRADED


# --- body expectations -----------------------------------------------------------------------------------------------------------
def _expect_text(needle: bytes):
    return lambda result: "" if needle in result.body[:4096].lower() else "unexpected response body"


def _expect_json(key: str, value: str):
    def check(result):
        document = result.json()
        return "" if isinstance(document, dict) and str(document.get(key, "")).lower() == value else f"{key} is not {value}"
    return check


# --- the component table ---------------------------------------------------------------------------------------------------------
def observe_all(config, *, runner=process.run, getter=http.get, netbox_url: str = "", netbox_headers: dict | None = None, now=utcnow) -> list[ServiceObservation]:
    """One observation of every component.  Each is independent: a failure of one never prevents the others being observed."""
    kw = {"runner": runner, "timeout": config.command_timeout}
    web = {"getter": getter, "timeout": config.http_timeout}

    def nmas_web():
        check, ms = http_check(config.nmas_web_health_url, expect=_expect_text(b"ok"), **web)
        return [systemd_check("nmas-web.service", **kw), check], ms

    def netbox():
        # with a token: the authenticated status API; without one: the login page proves the application answers
        url = (netbox_url or config.netbox_url or "http://127.0.0.1:8000").rstrip("/") + ("/api/status/" if netbox_headers else "/login/")
        check, ms = http_check(url, headers=netbox_headers, **web)
        return [container_check(config.netbox_container, **kw), check], ms

    def influxdb():
        check, ms = http_check(config.influxdb_health_url, expect=_expect_json("status", "pass"), **web)
        return [container_check(config.influxdb_container, **kw), check], ms

    def grafana():
        check, ms = http_check(config.grafana_health_url, expect=_expect_json("database", "ok"), **web)
        return [container_check(config.grafana_container, **kw), check], ms

    def freeradius():
        return [container_check(config.freeradius_container, **kw)], None

    def privacyidea():
        check, ms = http_check(config.privacyidea_url, verify_tls=False, **web)
        return [container_check(config.privacyidea_container, **kw), check], ms

    def traffic_runner():
        return [systemd_check("nmas-traffic-runner.socket", **kw), socket_check(config.traffic_runner_socket)], None

    def soak_timer():
        last = systemd_properties("nmas-probation-soak-tick.service", ("Result", "ExecMainStatus", "ExecMainExitTimestamp"), **kw)
        if last is None:
            ran_check = Check("last-run", None, "service manager not readable")
        else:
            ran = bool(last.get("ExecMainExitTimestamp"))
            good = last.get("Result") == "success" and last.get("ExecMainStatus") in ("0", "")
            ran_check = Check("last-run", good if ran else None,
                              f"result {last.get('Result', '?')}, last exit {last.get('ExecMainExitTimestamp') or 'never'}")
        # the timer itself is the liveness check (last): an inactive timer is DOWN, a failed last run with a live timer is DEGRADED
        return [ran_check, systemd_check("nmas-probation-soak-tick.timer", **kw)], None

    def topology():
        check, ms = http_check(config.topology_health_url, expect=_expect_json("status", "ok"), **web)
        return [systemd_check("nmas-topology.service", **kw), check], ms

    def unit(name):
        return lambda: ([systemd_check(name, **kw)], None)

    table = (
        ("nmas-web", "NMAS Web", nmas_web),
        ("netbox", "NetBox", netbox),
        ("influxdb", "InfluxDB", influxdb),
        ("grafana", "Grafana", grafana),
        ("freeradius", "FreeRADIUS (container health only)", freeradius),
        ("privacyidea", "privacyIDEA", privacyidea),
        ("traffic-runner", "Traffic runner (socket)", traffic_runner),
        ("soak-timer", "Probation soak timer", soak_timer),
        ("topology", "Topology / telemetry API", topology),
        ("gnmi-collector", "gNMI telemetry collector", unit("nmas-gnmi-collector.service")),
        ("syslog-ingest", "Syslog ingest", unit("nmas-syslog-ingest.service")),
        ("snmptrapd", "SNMP trap receiver", unit("snmptrapd.service")),
    )
    observations = []
    for component, label, probe in table:
        stamp: datetime = now()
        try:
            checks, latency = probe()
        except Exception:  # noqa: BLE001 - one component's probe failing must not hide the others
            checks, latency = [Check("probe", None, "check could not be performed")], None
        observations.append(ServiceObservation(stamp, component, label, verdict(checks), tuple(checks), latency))
    return observations
