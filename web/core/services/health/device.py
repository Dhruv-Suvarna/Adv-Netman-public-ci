"""Per-device Deep Health: explicit, one device at a time, read-only.

Combines the device's Fleet-Quick telemetry with a bounded LIVE read-only query (fixed allowlist, ``live.py``) by the
documented evidence precedence (live wins per fact group; conflicts are reported).  A timeout or refusal never raises:
it becomes UNKNOWN / DEVICE_UNREACHABLE with a sanitized reason code, and the remaining checks still run.
"""

from __future__ import annotations

from datetime import datetime

from . import fleet, inventory, live, telemetry
from .codes import CheckStatus, Freshness, Mode, Role
from .evidence import DeviceEvidence, merge_precedence
from .results import CheckResult, aggregate_health, iso, ordered, utcnow

S = CheckStatus
MAX_FACT_ROWS = 20


class UnknownDeviceError(LookupError):
    """The name is not a managed inventory device; nothing is ever probed for it."""


def reachability_check(device: str, evidence: DeviceEvidence, telemetry_freshness: str, *, role: str) -> CheckResult:
    """Did the explicit live read-only query complete?  (UNKNOWN unless telemetry independently corroborates an outage.)"""
    if not evidence.live_attempted:
        reason = evidence.live_error or "NOT_ATTEMPTED"
        capability = live.get_capability(evidence.platform)
        return CheckResult("DEVICE_REACHABLE", S.NOT_APPLICABLE, device,
                           f"No live read-only query was made ({live.LIVE_ERRORS.get(reason, reason)} Platform capability: {capability['status']}).",
                           "LIVE", observed={"reason_code": reason, "capability": capability["status"]}, role=role)
    now_iso = iso(utcnow())
    if evidence.live_error:
        corroborated = telemetry_freshness == Freshness.EXPIRED
        return CheckResult(
            "DEVICE_UNREACHABLE", S.FAIL if corroborated else S.UNKNOWN, device,
            live.LIVE_ERRORS[evidence.live_error] + (" Telemetry is also expired." if corroborated else ""), "LIVE",
            observed={"reason_code": evidence.live_error, "telemetry_freshness": telemetry_freshness}, observed_at=now_iso,
            freshness=Freshness.FRESH, role=role)
    return CheckResult("DEVICE_REACHABLE", S.PASS, device, "A read-only live query completed.", "LIVE",
                       observed={"reachable": True}, observed_at=now_iso, freshness=Freshness.FRESH, role=role)


def _interface_checks(device, evidence, role) -> list[CheckResult]:
    group, addresses = evidence.group("interfaces"), evidence.facts("addresses") or {}
    if group is None or not group.available or group.source != live.SOURCE:
        return []
    now_iso, results, up = iso(group.observed_at), [], 0
    checked = [name for name in sorted(group.data) if addresses.get(name)]  # "expected up" == it carries an address
    for name in checked:
        row = group.data[name]
        if row["admin"] == "DOWN":
            results.append(CheckResult("INTERFACE_ADMIN_DOWN", S.WARN, device, f"{name} has an address but is administratively down.", live.SOURCE,
                                       observed=row, expected={"admin": "UP"}, observed_at=now_iso, freshness=Freshness.FRESH, role=role, subject=name))
        elif row["oper"] == "DOWN":
            results.append(CheckResult("INTERFACE_OPER_DOWN", S.FAIL, device, f"{name} is administratively up but operationally down.", live.SOURCE,
                                       observed=row, expected={"oper": "UP"}, observed_at=now_iso, freshness=Freshness.FRESH, role=role, subject=name))
        else:
            up += 1
    if checked and up == len(checked):
        results.append(CheckResult("INTERFACE_EXPECTED_UP", S.PASS, device, f"All {up} addressed interfaces are up.", live.SOURCE,
                                   observed={"addressed_interfaces": len(checked), "up": up}, observed_at=now_iso, freshness=Freshness.FRESH, role=role))
    return results


def _routing_checks(device, evidence, role) -> list[CheckResult]:
    results = []
    ospf, bgp = evidence.group("ospf"), evidence.group("bgp")
    if ospf is not None and ospf.available and ospf.data:
        bad = [n for n in ospf.data if n["state"] not in ("FULL", "TWO_WAY")]  # 2-Way is the normal DROTHER-to-DROTHER state
        for n in bad:
            results.append(CheckResult("OSPF_ADJACENCY_DOWN", S.FAIL, device, f"OSPF neighbor {n['neighbor_id']} on {n['interface']} is {n['state']}.",
                                       ospf.source, observed=n, expected={"state": "FULL"}, observed_at=iso(ospf.observed_at), freshness=Freshness.FRESH,
                                       role=role, subject=f"{n['interface']}/{n['neighbor_id']}"))
        if not bad:
            results.append(CheckResult("OSPF_EXPECTED_FULL", S.PASS, device, f"{len(ospf.data)} OSPF adjacencies are FULL / 2-Way.", ospf.source,
                                       observed={"neighbors": len(ospf.data)}, observed_at=iso(ospf.observed_at), freshness=Freshness.FRESH, role=role))
    if bgp is not None and bgp.available and bgp.data:
        bad = [p for p in bgp.data if p["state"] != "ESTABLISHED"]
        for p in bad:
            results.append(CheckResult("BGP_SESSION_DOWN", S.FAIL, device, f"BGP peer {p['peer']} is {p['state'] or 'not established'}.", bgp.source,
                                       observed=p, expected={"state": "ESTABLISHED"}, observed_at=iso(bgp.observed_at), freshness=Freshness.FRESH,
                                       role=role, subject=p["peer"]))
        if not bad:
            results.append(CheckResult("BGP_EXPECTED_ESTABLISHED", S.PASS, device, f"{len(bgp.data)} BGP session(s) Established.", bgp.source,
                                       observed={"peers": len(bgp.data)}, observed_at=iso(bgp.observed_at), freshness=Freshness.FRESH, role=role))
    return results


def dhcp_state_check(state: dict, *, device: str = "FLEET", role: str = Role.FLEET) -> CheckResult:
    """A server is healthy when at least one address family is active -- the verifier's own semantics, reused."""
    def ok(server):
        return bool(server) and "active" in (server.get("ipv4"), server.get("ipv6"))

    nmas, r2 = state.get("nmas"), state.get("r2")
    observed = {"nmas": {k: (nmas or {}).get(k) for k in ("ipv4", "ipv6")}, "r2": {k: (r2 or {}).get(k) for k in ("ipv4", "ipv6")}}
    if state.get("error") or nmas is None or r2 is None:
        return CheckResult("DHCP_SERVICE_UNHEALTHY", S.UNKNOWN, device, "The DHCP servers could not be inspected.", "LIVE", observed=observed, role=role)
    if ok(nmas) and ok(r2):
        return CheckResult("DHCP_SERVICE_UNHEALTHY", S.PASS, device, "Both DHCP servers report an active service.", "LIVE", observed=observed, role=role,
                           observed_at=iso(utcnow()), freshness=Freshness.FRESH)
    return CheckResult("DHCP_SERVICE_UNHEALTHY", S.FAIL, device, "A DHCP server reports no active address family.", "LIVE", observed=observed, role=role,
                       observed_at=iso(utcnow()), freshness=Freshness.FRESH)


def facts_summary(evidence: DeviceEvidence) -> dict:
    """Bounded normalized facts + per-group provenance for the run report (never raw command output)."""
    out = {"groups": {name: {"source": g.source, "observed_at": iso(g.observed_at), "available": g.available, "complete": g.complete, "error": g.error}
                      for name, g in sorted(evidence.groups.items()) if g is not None},
           "live": {"attempted": evidence.live_attempted, "error": evidence.live_error}}
    interfaces, addresses = evidence.facts("interfaces"), evidence.facts("addresses") or {}
    if interfaces is not None:
        out["interfaces"] = [{"name": n, **interfaces[n], "addresses": addresses.get(n, [])} for n in sorted(interfaces)[:MAX_FACT_ROWS]]
    routes = evidence.facts("routes")
    if routes is not None:
        out["routes"] = {"count": len(routes), "sample": [r["prefix"] for r in routes[:MAX_FACT_ROWS]]}
    for name in ("ospf", "bgp"):
        rows = evidence.facts(name)
        if rows is not None:
            out[name] = rows[:MAX_FACT_ROWS]
    tele = evidence.facts("telemetry")
    if tele is not None:
        out["resources"] = {k: tele.get(k) for k in ("cpu_percent", "memory_percent", "critical_syslog", "snmp_traps")}
    return out


def deep_checks(device: str, evidence: DeviceEvidence, snapshot: telemetry.TelemetrySnapshot, now: datetime, *, role: str = Role.FLEET,
                dhcp_state: dict | None = None) -> list[CheckResult]:
    tele_group = evidence.group("telemetry")
    tele_fresh = tele_group.freshness(now, snapshot.thresholds) if tele_group is not None and tele_group.available else Freshness.UNKNOWN
    live_ok = evidence.live_reachable
    results = [reachability_check(device, evidence, tele_fresh, role=role)]
    results += fleet.quick_checks(device, evidence, snapshot, now=now, role=role, live_ok=live_ok)
    results += _interface_checks(device, evidence, role)
    results += _routing_checks(device, evidence, role)
    for conflict in evidence.conflicts[:10]:
        results.append(CheckResult("EVIDENCE_CONFLICT", S.WARN, device,
                                   f"Interface {conflict['key']}: live says {conflict['live']}, older telemetry said {conflict['telemetry']}; live used.",
                                   "LIVE", observed=conflict, role=role, subject=conflict["key"]))
    hosts = inventory.dhcp_hosts()
    if hosts["secondary_device"] == device:
        results.append(dhcp_state_check(dhcp_state if dhcp_state is not None else live.dhcp_service_state(), device=device, role=role))
    return results


def run_device_health(device_name: str, *, actor: str = "", snapshot: telemetry.TelemetrySnapshot | None = None, session_factory=None,
                      dhcp_state: dict | None = None, now: datetime | None = None, persist: bool = True):
    """Explicit Deep Health for ONE managed device -> (run | None, report dict).  Read-only; raises only UnknownDeviceError."""
    device = inventory.get_managed_device(device_name)
    if device is None:
        raise UnknownDeviceError(device_name)
    started = now or utcnow()
    snapshot = snapshot or telemetry.collect(now=started)
    tele = telemetry.device_evidence(snapshot, device["name"], device["platform"])
    live_evidence = live.read_device(device, session_factory=session_factory, now=started)
    merged = merge_precedence(live_evidence, tele)
    results = deep_checks(device["name"], merged, snapshot, started, dhcp_state=dhcp_state)
    status = aggregate_health(results)
    extra = {"device": device["name"], "platform": device["platform"], "capability": live.get_capability(device["platform"]),
             "facts": facts_summary(merged), "thresholds": snapshot.thresholds, "precedence": "LIVE > TELEMETRY (per fact group)"}
    if not persist:
        from .persistence import build_report

        report, _ = build_report(Mode.DEVICE_DEEP, status, results, extra)
        return None, report
    from .persistence import record_run, serialize_health_run

    run = record_run(mode=Mode.DEVICE_DEEP, status=status, results=ordered(results), extra=extra, actor=actor, device=device["name"], started_at=started)
    return run, serialize_health_run(run)["report"]
