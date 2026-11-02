"""Phase-22 IP connectivity health check.

An explicit, read-only ping FROM one managed device TO an operator-selected destination. The destination is never
free browser text: ``ping_targets`` is the closed, server-owned menu (NMAS or another managed device's inventory
management address); the browser only ever supplies which KEY of that menu it wants (exactly the pattern
``live.py``'s command allowlists already use for everything else). ``live.validate_ping_destination`` is the second,
independent gate before any address reaches a session.

Reuses the Phase-15 ``OperationalCheckRun`` model (mode ``DEVICE_DEEP``, tagged ``check_type=CONNECTIVITY`` in the
report/summary) -- no new model, no migration. Reuses the existing per-platform session classes in ``live.py``
(``EosSession`` / ``LinuxSession`` / ``DockerEosSession``) via their new ``.ping()`` method; no second transport.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime

from . import inventory, live
from .codes import CheckStatus, Freshness, Role
from .device import UnknownDeviceError
from .results import CheckResult, aggregate_health, iso, utcnow

S = CheckStatus
PING_COUNT = 3
CHECK_TYPE = "CONNECTIVITY"


def _host(cidr: str) -> str:
    """The bare address of an inventory ``a.b.c.d/NN`` management CIDR string; '' for anything unparsable/absent."""
    if not cidr:
        return ""
    try:
        return str(ipaddress.ip_interface(str(cidr)).ip)
    except ValueError:
        return ""


def _nmas_target() -> dict:
    management = inventory.load_inventory().get("management") or {}
    return {"name": "nmas", "label": "NMAS (monitoring host)", "address": _host(management.get("nmas_ipv4")),
            "address_v6": _host(management.get("nmas_ipv6"))}


def ping_targets(device_name: str) -> list[dict]:
    """Every valid ping destination FROM ``device_name``: NMAS plus every OTHER managed device with a management
    address. This -- not a text field -- is what the UI renders as a destination <select>; a key not in this list
    can never reach a session (``_resolve`` below refuses it)."""
    targets = [_nmas_target()]
    for name, device in sorted(inventory.managed_devices().items()):
        if name == device_name or not (device.get("address") or device.get("address_v6")):
            continue
        targets.append({"name": name, "label": name, "address": device.get("address", ""), "address_v6": device.get("address_v6", "")})
    return targets


class UnknownDestinationError(LookupError):
    """The destination key is not NMAS or another managed device; nothing is ever probed for it."""


def _resolve(device_name: str, destination_key: str, family: str) -> tuple[str, str]:
    targets = {t["name"]: t for t in ping_targets(device_name)}
    target = targets.get(str(destination_key))
    if target is None:
        raise UnknownDestinationError(destination_key)
    address = target["address_v6"] if str(family) == "6" else target["address"]
    return target["label"], address


def _session_for(device: dict, session_factory=None):
    factory = session_factory or live.default_session_factory(device)
    return factory(device)


def _error_result(device_name: str, destination_key: str, label: str, address: str, code: str, started: datetime) -> CheckResult:
    return CheckResult(
        "CONNECTIVITY_CHECK_UNAVAILABLE", S.UNKNOWN, device_name,
        f"Ping to {label} ({address}) could not be attempted: {live.LIVE_ERRORS.get(code, code)}", "LIVE",
        observed={"destination": destination_key, "reason_code": code}, role=Role.FLEET, observed_at=iso(started),
    )


def _ping_result(device_name: str, destination_key: str, label: str, address: str, family: str, stats: dict, started: datetime) -> CheckResult:
    observed = {"destination": destination_key, "destination_label": label, "address": address, "family": int(family), **stats}
    now_iso = iso(started)
    if stats["transmitted"] == 0 or stats["received"] == 0:
        return CheckResult("CONNECTIVITY_UNREACHABLE", S.FAIL, device_name,
                           f"No reply from {label} ({address}): {stats['loss_percent']:.0f}% packet loss.", "LIVE",
                           observed=observed, expected={"loss_percent": 0}, observed_at=now_iso, freshness=Freshness.FRESH, role=Role.FLEET)
    if stats["loss_percent"] > 0:
        return CheckResult("CONNECTIVITY_DEGRADED", S.WARN, device_name,
                           f"Partial packet loss to {label} ({address}): {stats['loss_percent']:.0f}%.", "LIVE",
                           observed=observed, expected={"loss_percent": 0}, observed_at=now_iso, freshness=Freshness.FRESH, role=Role.FLEET)
    return CheckResult("CONNECTIVITY_REACHABLE", S.PASS, device_name,
                       f"{label} ({address}) replied to all {stats['transmitted']} probe(s).", "LIVE",
                       observed=observed, observed_at=now_iso, freshness=Freshness.FRESH, role=Role.FLEET)


def _perform_ping(device: dict, destination_key: str, label: str, address: str, family: str, session_factory, started: datetime) -> CheckResult:
    if not address:
        return CheckResult("CONNECTIVITY_CHECK_UNAVAILABLE", S.UNKNOWN, device["name"],
                           f"{label} has no configured IPv{family} management address.", "LIVE",
                           observed={"destination": destination_key, "family": int(family)}, role=Role.FLEET, observed_at=iso(started))
    capability = live.get_capability(device["platform"])
    if capability["status"] != "SUPPORTED":
        return CheckResult("CONNECTIVITY_CHECK_UNAVAILABLE", S.UNKNOWN, device["name"],
                           f"Live read-only queries are not implemented for platform {device['platform']}.", "LIVE",
                           observed={"destination": destination_key, "capability": capability["status"]}, role=Role.FLEET, observed_at=iso(started))
    try:
        session = _session_for(device, session_factory)
    except live.LiveError as exc:
        return _error_result(device["name"], destination_key, label, address, exc.code, started)
    except Exception:  # noqa: BLE001 - sanitized: only the reason code ever leaves this module
        return _error_result(device["name"], destination_key, label, address, "CONNECTION_FAILED", started)
    try:
        try:
            output = session.ping(address, count=PING_COUNT)
        except live.LiveError as exc:
            return _error_result(device["name"], destination_key, label, address, exc.code, started)
        except Exception:  # noqa: BLE001
            return _error_result(device["name"], destination_key, label, address, "COMMAND_FAILED", started)
    finally:
        session.close()
    try:
        stats = live.parse_ping_output(output)
    except live.LiveError as exc:
        return _error_result(device["name"], destination_key, label, address, exc.code, started)
    return _ping_result(device["name"], destination_key, label, address, family, stats, started)


def run_connectivity(device_name: str, destination_key: str, family: str = "4", *, actor: str = "",
                     session_factory=None, now: datetime | None = None, persist: bool = True):
    """Explicit, read-only ping FROM one managed device -> (run | None, report dict). Never raises for a device or
    network failure (reported as a CONNECTIVITY_* CheckResult); raises only ``UnknownDeviceError`` /
    ``UnknownDestinationError`` for a request naming something outside the closed inventory."""
    device = inventory.get_managed_device(device_name)
    if device is None:
        raise UnknownDeviceError(device_name)
    label, address = _resolve(device_name, destination_key, family)
    started = now or utcnow()
    result = _perform_ping(device, destination_key, label, address, family, session_factory, started)
    status = aggregate_health([result])
    extra = {"device": device_name, "destination": destination_key, "destination_label": label,
             "family": int(family), "check_type": CHECK_TYPE, "summary": {"check_type": CHECK_TYPE, "destination": destination_key}}
    if not persist:
        from .persistence import build_report

        report, _ = build_report("DEVICE_DEEP", status, [result], extra)
        return None, report
    from .persistence import record_run, serialize_health_run

    run = record_run(mode="DEVICE_DEEP", status=status, results=[result], extra=extra, actor=actor, device=device_name, started_at=started)
    return run, serialize_health_run(run)["report"]


def latest_connectivity_run(device_name: str):
    """The most recent connectivity run for ``device_name``, or None. Filters the shared DEVICE_DEEP history by the
    ``check_type`` tag recorded in ``summary`` -- no new model/column, per the "reuse OperationalCheckRun" mandate."""
    from ... import models

    for run in models.OperationalCheckRun.objects.filter(mode="DEVICE_DEEP", device=device_name).order_by("-created_at")[:20]:
        if (run.summary or {}).get("check_type") == CHECK_TYPE:
            return run
    return None
