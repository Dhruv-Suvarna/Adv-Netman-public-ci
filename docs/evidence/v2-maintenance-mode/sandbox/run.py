#!/usr/bin/env python3
"""Maintenance Mode against the REAL disposable sandbox ``isisbx``: cEOS 4.36.2F (R1, R2, S1, S2 and the edge R5 = ``pe``)
and FRR 8.4.4 cores (R3/R4 = ``c3``/``c4``), in the post-migration state (IS-IS access, OSPFv3 core), with real hosts.

The PRODUCT runs unchanged: ``maintenance_mode.service`` / ``collector`` / ``drain`` / ``executor`` / ``protection`` and
the worker ``tick``, the health reader ``health.live.read_device``, the cEOS executor and the route-shield probes.  Only
the wiring differs from ``service.production_runtime``: the inventory is the sandbox containers (cEOS reached through
``docker exec Cli``), the cabling is the sandbox's, and the scope is the managed scope's shape (R1-R4, S1, S2; R5 not
writable).  Where a scenario needs a mechanism to be READY the harness passes ``shield_states`` to the collector for that
run (a sandbox-only input, exactly what a reviewed READINESS change would do); the reviewed constants are not changed.

Isolated: Django on a scratch SQLite file (``maintenance_sandbox_settings``, NMAS_SANDBOX_DB), no NetBox, no inventory,
no deployed database.  Every container is checked for the label nmas-sandbox=isisbx before anything runs.

usage (from the worktree's web/ directory):
    NMAS_SANDBOX_DB=<scratch>.sqlite3 DJANGO_SETTINGS_MODULE=maintenance_sandbox_settings PYTHONPATH=<this dir> \\
        python <this dir>/run.py <outdir> <scenario> [<scenario> ...]       (scenario "all" runs every one in order)
    ... run.py <outdir> child-enter <record id> <hold after operation key>  (the crash scenario's worker; internal)
"""
import json
import os
import re
import signal
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..", "..", "v2-route-shield", "sandbox")))
import mig                                                      # sandbox plumbing only: guard, CLI reads, workload sessions

import django

django.setup()
from datetime import timedelta                                   # noqa: E402

from django.core.management import call_command                  # noqa: E402
from django.utils import timezone                                # noqa: E402

from core import models                                          # noqa: E402
from core.services.capabilities.isolated_live import DockerEosConfigConnection, _run   # noqa: E402
from core.services.execution.executors.ceos import CeosExecutor  # noqa: E402
from core.services.health import live                            # noqa: E402
from core.services.health.evidence import FactGroup              # noqa: E402
from core.services.maintenance_mode import collector, drain, lifecycle, model, plan, protection, service, store, topology  # noqa: E402
from core.services.maintenance_mode import evidence as chain     # noqa: E402
from core.services.route_shield import core_cover, gates, migration, probes  # noqa: E402
from core.services.route_shield import lifecycle as shield_lifecycle         # noqa: E402
from core.services.route_shield import readiness as shield_readiness         # noqa: E402
from core.services.route_shield.migration import ADD, Operation              # noqa: E402

OUT = sys.argv[1]
os.makedirs(OUT, exist_ok=True)
RUN = mig.Run(OUT)
P = mig.P
SHORT = {"R1": "r1", "R2": "r2", "S1": "s1", "S2": "s2", "R3": "c3", "R4": "c4", "R5": "pe"}
DEVICES = {name: {"name": name, "platform": "linux" if name in ("R3", "R4") else "ceos", "container": f"{P}-{short}", "address": ""}
           for name, short in SHORT.items()}
SCOPE = frozenset({"R1", "R2", "R3", "R4", "S1", "S2"})          # the managed scope's shape: the edge router is not writable
MANAGEMENT = {name: ("Management0", "Vlan200", "eth0") for name in DEVICES}       # never named by an operation (protection)
# The sandbox cabling (up.sh / core_frr.sh), read from the containers: a cEOS data port is EthernetN in the order its
# networks were connected; an FRR core has no management port at all (its docker bridge is disconnected), so its eth0 is
# the link toward R1 -- which is exactly why the topology must be told each device's management ports.
LINKS = (("R1", "eth1", "R3", "eth0"), ("R1", "eth2", "R4", "eth0"), ("R1", "eth3", "S1", "eth1"),
         ("R2", "eth1", "R3", "eth1"), ("R2", "eth2", "R4", "eth1"), ("R2", "eth3", "S2", "eth1"),
         ("S1", "eth2", "S2", "eth2"), ("S1", "eth3", "H1", "eth0"), ("S1", "eth4", "H2", "eth0"),
         ("S2", "eth3", "H3", "eth0"), ("S2", "eth4", "H4", "eth0"),
         ("R3", "eth2", "R5", "eth1"), ("R4", "eth2", "R5", "eth2"), ("R5", "eth3", "WebServer", "eth0"))
PORTS = {name: (() if DEVICES[name]["platform"] == "linux" else ("Management0", "Vlan200")) for name in DEVICES}
HOSTS = {"H1": ("S1", (4, 6)), "H2": ("S1", (4, 6)), "H3": ("S2", (4, 6)), "H4": ("S2", (6,))}
TOPO = topology.Topology(LINKS, {name: topology.Host(name, f"{P}-{name.lower()}", "eth0", families, switch) for name, (switch, families) in HOSTS.items()},
                         topology.Service("WebServer", f"{P}-web", mig.WEB4, mig.WEB6, "R5"), dict(DEVICES), (), PORTS)

PRODUCTION_STATES = None                                          # the reviewed constants of route_shield.readiness
NORTH_READY = {shield_readiness.ISIS_METRIC_STEER: shield_readiness.READY, shield_readiness.OSPFV3_EXTERNAL_METRIC_STEER: shield_readiness.NOT_READY}
BOTH_READY = {shield_readiness.ISIS_METRIC_STEER: shield_readiness.READY, shield_readiness.OSPFV3_EXTERNAL_METRIC_STEER: shield_readiness.READY}


def core_hops():
    found = {}
    for name in ("R3", "R4"):
        text = mig.kern(SHORT[name], "ip", "-6", "route", "show", mig.CLIENTS[0])
        hops = re.findall(r"nexthop via (\S+) dev (\S+)", text)
        if len(hops) != 2:
            sys.exit(f"{name}: {mig.CLIENTS[0]} is not forwarded to both boundary routers: {text!r}")
        found[name] = tuple(hops)
    return found


# The tracked access design on the sandbox cabling.  Maintenance reads the switches and the cores from it; the covers in it
# belong to the migration and are never used by a maintenance (the cores are handed out read-only).
DEFINITION = migration.with_cabling(migration.PRODUCTION, name="sandbox", access_interface="Ethernet3", core_hops=core_hops())


class SandboxConnection(DockerEosConfigConnection):
    """The isolated docker transport, plus the two non-configuration exec commands the workflow sends: an echo request
    (the shield's next-hop gate) and saving the startup configuration."""

    def send_command(self, command, **kwargs):
        if command.startswith("ping ipv6 ") or command == "copy running-config startup-config":
            return _run(["docker", "exec", self._container, "Cli", "-p", "15", "-c", command], timeout=60).stdout
        text = super().send_command(command, **kwargs)
        return "\n".join(line for line in text.splitlines() if not line.startswith("> show ")) + "\n"


def factory(device):
    if device["platform"] == "linux":
        return core_cover.KernelCoverExecutor(device, sandbox_covers=DEFINITION.covers)
    return CeosExecutor(device, connection_factory=SandboxConnection, reader=live.read_device)


FLOWS = []
for _host, (_v4, _v6) in mig.HOSTS.items():
    FLOWS.append(probes.Flow(f"{_host}-web-v6", f"{P}-{_host}", mig.WEB6, 0.01))
    FLOWS.append(probes.Flow(f"web-{_host}-v6", f"{P}-web", _v6, 0.02, mig.WEB6))
    if _v4:
        FLOWS.append(probes.Flow(f"{_host}-web-v4", f"{P}-{_host}", mig.WEB4, 0.1))
        FLOWS.append(probes.Flow(f"web-{_host}-v4", f"{P}-web", _v4, 0.1, mig.WEB4))

HOOK = {"fn": None}
PROBES_SEEN = []


def observer(event, key):
    RUN.ev("NMAS", event, key)
    if HOOK["fn"] is not None:
        HOOK["fn"](event, key)


def host_gate():
    return gates.default_host_gate(max_load_per_cpu=8.0)        # the sandbox host itself runs several per CPU


host_gate.consecutive_samples = 3


def environment():
    source = probes.HostProbes(FLOWS)
    PROBES_SEEN.append(source)
    return shield_lifecycle.Environment(devices=DEVICES, executor_factory=factory, read=live.read_device, probes=source,
                                        host_gate=host_gate, observer=observer)


def runtime(states, *, read=live.read_device, gated=False):
    sources = collector.Sources(TOPO, read, shield_states=states)
    return service.Runtime(sources, environment, lambda env: env.probes.start(), DEFINITION, gated=gated, probe_warmup=25.0,
                           writable=lambda: set(SCOPE), management_interfaces=MANAGEMENT)


# ------------------------------------------------------------------------------------------------------------- evidence
def _h(text):
    return mig.digest(text)


def snapshot():
    """Digests of everything a maintenance could have changed: running AND startup of the cEOS devices, the FRR running
    and boot configuration and the non-dynamic kernel routes of the cores, and the VLAN 200 sentinel on the switches."""
    def config(device, command):                    # ``Cli -c`` echoes the command first ("> show ..."): never part of the configuration
        return "\n".join(l for l in mig.cli(device, command).splitlines() if l.strip() and not l.startswith(("! ", "> ")))

    found = {}
    for name in ("R1", "R2", "S1", "S2", "R5"):
        found[name] = {"running": _h(config(SHORT[name], "show running-config")), "startup": _h(config(SHORT[name], "show startup-config"))}
    for name in ("R3", "R4"):
        frr = "\n".join(l for l in mig.kern(SHORT[name], "vtysh", "-c", "show running-config").splitlines() if l.strip() and not l.startswith(("!", "Building", "Current")))
        static = mig.kern(SHORT[name], "sh", "-c", "ip -6 route show table all | grep -E 'proto (boot|static|kernel)' | grep -v '^fe80' | grep -v '^local' | grep -v '^multicast' || true")
        found[name] = {"frr_running": _h(frr), "frr_conf": _h(mig.kern(SHORT[name], "cat", "/etc/frr/frr.conf")), "kernel_static": _h(static),
                       "kernel_static_lines": [l.strip() for l in static.splitlines() if l.strip()]}
    found["vlan200"] = {s: _h(mig.cli(SHORT[s], "show running-config section Vlan200") + mig.cli(SHORT[s], "show running-config section vlan 200"))
                        for s in ("S1", "S2")}
    return found


def comparable(snap):
    return {k: ({kk: vv for kk, vv in v.items() if kk != "kernel_static_lines"} if isinstance(v, dict) else v) for k, v in snap.items()}


def dump(name, value):
    with open(os.path.join(OUT, f"{name}.json"), "w") as handle:
        json.dump(value, handle, indent=1, default=str)


def evidence_of(row):
    row.refresh_from_db()
    entries = [{"seq": e.sequence, "kind": e.kind, "from": e.state_from, "to": e.state_to, "summary": e.summary, "actor": e.actor} for e in chain.entries(row)]
    return {"record": row.record_id, "state": row.state, "escalated": row.escalated, "plan_hash": row.plan_hash, "plan_status": row.plan_status,
            "findings": row.snapshot.get("findings"), "maintenance_only_state": row.snapshot.get("maintenance_only_state"),
            "chain_ok": chain.verify(row)[0], "entries": entries}


def chain_ok(row):
    return chain.verify(row)


RESULTS = {}


def result(name, ok, **facts):
    RESULTS[name] = {"ok": bool(ok), **facts}
    RUN.ev("RESULT", name, "PASS" if ok else "FAIL", json.dumps(facts, default=str)[:900])
    dump("results", RESULTS)


def now():
    return timezone.now()


def close_open(device):
    """Cancel an unresolved record that never entered (the next scenario starts from a clean slate)."""
    row = service.current(device)
    if row is not None and row.state in (lifecycle.REQUESTED, lifecycle.BLOCKED, lifecycle.READY, lifecycle.PLANNED, lifecycle.APPROVED):
        service.cancel(row.pk, "sandbox-operator", now=now())


def workload(on, *, ipv4=False):
    """The production workload: a long TCP session and an HTTP loop from every host to the service, over IPv6 (and over
    IPv4 too with ``ipv4``).  IPv4 runs on RIP, which has no drain: an active IPv4 workload blocks every R1/R2 entry."""
    for host in mig.HOSTS:
        mig.hx(host, "pkill -TERM -f '[t]cp_long.py'; pkill -TERM -f '[h]ttp_loop.py'; true")
    if on:
        for host, (v4, _v6) in mig.HOSTS.items():
            mig.hx(host, "mkdir -p /tmp/t")
            for family, target in (("6", mig.WEB6), ("4", mig.WEB4)):
                if family == "4" and not (ipv4 and v4):
                    continue
                mig.hx(host, f"python3 /tools/tcp_long.py {target} /tmp/t/tcp{family}.log", detach=True)
                mig.hx(host, f"python3 /tools/http_loop.py {target} /tmp/t/http{family}.log", detach=True)
        time.sleep(5)
    else:
        time.sleep(25)                    # let the last packets of the sessions drain off the counters' window


def planned(device, states, *, read=live.read_device):
    rt = runtime(states, read=read)
    row = service.request(device, "sandbox-operator", "sandbox scenario", timedelta(hours=1), now=now(), runtime=rt)
    row = service.evaluate(row.pk, "sandbox-operator", now=now(), runtime=rt)
    return row, rt


def approved(device, states):
    row, rt = planned(device, states)
    if row.state != lifecycle.PLANNED:
        raise RuntimeError(f"{device} not planned: {row.state} {json.dumps(row.snapshot.get('findings'))[:600]}")
    row = service.approve(row.pk, "sandbox-approver", now=now(), plan_hash=row.plan_hash)
    return row, rt


def probe_totals():
    if not PROBES_SEEN:
        return {}
    flows = PROBES_SEEN[-1].report()
    return {"answered": sum(f["answered"] for f in flows), "lost": sum(f["lost"] for f in flows), "flows": len(flows)}


def enter(row, rt):
    try:
        row = service.enter(row.pk, "sandbox-operator", now=now, runtime=rt)
    except model.MaintenanceError as exc:
        RUN.ev("ENTER", "refused/aborted", exc.code, str(exc)[:300])
        row.refresh_from_db()
    return row


def leave(row, rt):
    try:
        row = service.leave(row.pk, "sandbox-operator", now=now, runtime=rt)
    except model.MaintenanceError as exc:
        RUN.ev("LEAVE", "refused", exc.code, str(exc)[:300])
        row.refresh_from_db()
    return row


def oob(on):
    """An out-of-band change on S2 (sandbox only): a description on the H4 access port, added or removed exactly."""
    mig.conf("s2", ["interface Ethernet4", "description out-of-band-sandbox-change" if on else "no description"])


def write_count():
    return sum(1 for e in models.MaintenanceEvidence.objects.filter(kind__in=(chain.ENTRY, chain.RESTORE)))


# ------------------------------------------------------------------------------------------------------------ scenarios
def s01_observation():
    workload(True)
    before = snapshot()
    observation = collector.observe("R1", runtime(PRODUCTION_STATES).sources)
    summary = observation.summary()
    after = snapshot()
    workload(False)
    flows = {f.label: (f.activity, f.on_device) for f in observation.flows}
    dump("s01_observation", summary)
    reachable = {name: row["reachable"] for name, row in summary["provenance"].items()}
    ok = (comparable(before) == comparable(after) and all(reachable.values()) and observation.role == topology.BOUNDARY_ROUTER and observation.access is not None
          and all(activity != model.UNKNOWN for activity, _o in flows.values()) and flows["h1-v6-north"] == (model.ACTIVE, True)
          and all(summary["paths"][label]["complete"] for label in summary["paths"]) and observation.alternates == {(model.IPV6, model.NORTHBOUND): True, (model.IPV6, model.SOUTHBOUND): True})
    result("01_read_only_observation", ok, role=observation.role, access=observation.access.as_dict() if observation.access else None, flows=flows,
           alternates={f"{k[0]}/{k[1]}": v for k, v in observation.alternates.items()}, reachable=reachable, nothing_changed=comparable(before) == comparable(after),
           paths={label: row["path"] for label, row in summary["paths"].items()})


def s03_block():
    before = snapshot()
    rows = {}
    for label, device, states, ipv4 in (("R1_production_states", "R1", PRODUCTION_STATES, False), ("R1_north_ready_only", "R1", NORTH_READY, False),
                                        ("R1_ipv4_active", "R1", BOTH_READY, True), ("S1_single_homed", "S1", BOTH_READY, False)):
        workload(True, ipv4=ipv4)
        row, _rt = planned(device, states)
        report = store.load(row).report
        rows[label] = {"state": row.state, "plan_hash": row.plan_hash, "cells": {f"{a}/{b}": c["verdict"] for (a, b), c in (report.cells if report else {}).items()},
                       "codes": sorted({(f["code"], f.get("family") or "", f.get("direction") or "") for f in row.snapshot.get("findings") or []})}
        close_open(device)
    workload(False)
    after = snapshot()
    production, north, ipv4, s1 = (rows[k] for k in ("R1_production_states", "R1_north_ready_only", "R1_ipv4_active", "S1_single_homed"))
    ok = (all(r["state"] == lifecycle.BLOCKED and not r["plan_hash"] for r in rows.values())
          and {("DRAIN_MECHANISM_NOT_READY", "IPV6", "NORTHBOUND"), ("DRAIN_MECHANISM_NOT_READY", "IPV6", "SOUTHBOUND")} <= set(production["codes"])
          and north["cells"]["IPV6/NORTHBOUND"] == "DRAINABLE" and north["cells"]["IPV6/SOUTHBOUND"] == "BLOCKED"
          and ("DRAIN_MECHANISM_NOT_READY", "IPV6", "SOUTHBOUND") in north["codes"]
          and ipv4["cells"]["IPV4/NORTHBOUND"] == "BLOCKED" and ipv4["cells"]["IPV6/NORTHBOUND"] == "DRAINABLE"
          and "ACTIVE_TRAFFIC_NO_LOSSLESS_DRAIN" in {c[0] for c in s1["codes"]} and comparable(before) == comparable(after))
    result("03_active_without_safe_redundancy_blocks", ok, rows=rows, nothing_changed=comparable(before) == comparable(after))


def s12_r5():
    before = snapshot()
    try:
        service.request("R5", "sandbox-operator", "edge", timedelta(hours=1), now=now(), runtime=runtime(BOTH_READY))
        refused = ""
    except model.MaintenanceError as exc:
        refused = exc.code
    bad = [Operation("r5-metric", "SOUTHBOUND", "R5", "MAINTENANCE", ADD, ("route-map X permit 10", "   set metric 10"), ("route-map X permit 10", "   no set metric"))]
    found = protection.violations(bad, writable=SCOPE, management_interfaces=MANAGEMENT)
    after = snapshot()
    ok = refused == protection.OUTSIDE_SCOPE and any(f.startswith(protection.OUTSIDE_SCOPE) for f in found) and before["R5"] == after["R5"]
    result("12_r5_never_writable", ok, request_refused=refused, plan_violation=found[:1], r5_unchanged=before["R5"] == after["R5"])


def s11_vlan200():
    before = snapshot()
    real = drain.operations

    def with_vlan200(access, definition, state, cells, *, drain):
        ops = real(access, definition, state, cells, drain=drain)
        return [*ops, Operation("s1-vlan200", "NORTHBOUND", access.switch, "MAINTENANCE", ADD, ("interface Vlan200", "   shutdown"), ("interface Vlan200", "   no shutdown"))]

    drain.operations = with_vlan200
    try:
        workload(True)
        row, _rt = planned("R1", BOTH_READY)
        workload(False)
    finally:
        drain.operations = real
    codes = sorted({f["code"] for f in row.snapshot.get("findings") or []})
    close_open("R1")
    after = snapshot()
    ok = row.state == lifecycle.BLOCKED and protection.PROTECTED_SCOPE in codes and not row.plan_hash and comparable(before) == comparable(after) \
        and before["vlan200"] == after["vlan200"]
    result("11_vlan200_never_modified", ok, state=row.state, codes=codes, vlan200_before=before["vlan200"], vlan200_after=after["vlan200"],
           nothing_changed=comparable(before) == comparable(after))


def s09_stale_observation():
    def aged(device):
        evidence = live.read_device(device)                         # a real read, served as if it came from a 150 s old cache
        for key, group in list(evidence.groups.items()):
            if group.observed_at is not None:
                evidence.groups[key] = FactGroup(data=group.data, source=group.source, observed_at=group.observed_at - timedelta(seconds=150),
                                                 complete=group.complete, error=group.error) if group.available else group
        return evidence

    workload(True)
    before = snapshot()
    row, _rt = planned("R1", BOTH_READY, read=aged)
    after = snapshot()
    workload(False)
    codes = sorted({f["code"] for f in row.snapshot.get("findings") or []})
    close_open("R1")
    ok = row.state == lifecycle.BLOCKED and service.NOT_FRESH in codes and not row.plan_hash and comparable(before) == comparable(after)
    result("09_stale_observation_refuses_plan", ok, state=row.state, codes=codes, nothing_changed=comparable(before) == comparable(after))


def s02_10_ready_then_stale_plan():
    workload(True)
    before = snapshot()
    row, rt = approved("R1", BOTH_READY)
    document = row.snapshot["plan"]
    ops = document["drain"]["operations"]
    ready = {"state": row.state, "plan_hash": row.plan_hash, "devices": sorted({op["device"] for op in ops}), "stages": [op["stage"] for op in ops],
             "cells": {k: v["verdict"] for k, v in document["readiness"]["cells"].items()}}
    oob(True)                                                        # someone changes the path the traffic would move to
    row = enter(row, rt)
    stale_codes = sorted({f["code"] for f in row.snapshot.get("findings") or []})
    oob(False)
    after = snapshot()
    workload(False)
    close_open("R1")
    result("02_ready_with_existing_redundancy", ready["state"] == lifecycle.APPROVED and ready["devices"] == ["R1", "S1"]
           and ready["stages"] == ["NORTHBOUND"] * 3 + ["SOUTHBOUND"], **ready)
    result("10_stale_plan_refuses_entry", row.state == lifecycle.APPROVED and plan.PLAN_STALE in stale_codes and comparable(before) == comparable(after),
           state_after_refusal=row.state, codes=stale_codes, plan_status=row.plan_status, nothing_changed=comparable(before) == comparable(after))


def cycle(name, device, states, *, active, restore=True, hook=None, expect_active=True):
    """One complete maintenance: plan, approve, enter (drain), then the restore.  -> (row after entry, row after restore)."""
    workload(active)
    base = snapshot()
    row, rt = approved(device, states)
    HOOK["fn"] = hook
    try:
        entered = enter(row, rt)
    finally:
        HOOK["fn"] = None
    drained = snapshot()
    entry = entered.snapshot.get("evidence", {}).get("entry") or {}
    facts = {"state_after_entry": entered.state, "entry_outcome": entry.get("outcome"), "failure": entry.get("failure"),
             "applied": entry.get("applied"), "compensation": entry.get("compensation"), "probes_lost_in_run": (entry.get("probes") or {}).get("lost"),
             "probe_totals_entry": probe_totals(), "proofs": entry.get("proofs"), "after_paths": {k: v["path"] for k, v in ((entry.get("after") or {}).get("paths") or {}).items()},
             "persistence": entry.get("persistence"), "drained_digests": drained, "base_digests": base}
    final = entered
    if restore and entered.state == lifecycle.ACTIVE:
        final = leave(entered, rt)
        rest = final.snapshot.get("evidence", {}).get("restore") or {}
        facts.update(state_after_restore=final.state, restore_outcome=rest.get("outcome"), restore_failure=rest.get("failure"),
                     restore_compensation=rest.get("compensation"), probes_lost_in_restore=(rest.get("probes") or {}).get("lost"),
                     probe_totals_restore=probe_totals(), verification=(final.snapshot.get("evidence", {}).get("restore_verification") or {}).get("findings"))
    end = snapshot()
    workload(False) if active else None
    ok_chain, problems = chain_ok(final)
    facts.update(end_digests=end, baseline_restored=comparable(end) == comparable(base), chain_ok=ok_chain, chain_problems=problems[:3])
    dump(f"{name}_evidence", evidence_of(final))
    dump(f"{name}_snapshot", final.snapshot)
    return entered, final, facts, base


def s04_05_06_quiesced_north():
    entered, final, facts, base = cycle("s04", "R1", NORTH_READY, active=False)
    s1_drained = facts["drained_digests"]["S1"]
    ok_entry = (entered.state == lifecycle.ACTIVE and facts["probes_lost_in_run"] == 0 and facts["entry_outcome"] == "SUCCEEDED"
                and [s for s in (entered.snapshot.get("steps") or [])] and s1_drained["running"] == s1_drained["startup"]
                and facts["drained_digests"]["R1"] == base["R1"] and facts["drained_digests"]["R3"] == base["R3"] and facts["drained_digests"]["R4"] == base["R4"])
    result("04_quiesced_traffic_permits_progression", entered.state == lifecycle.ACTIVE and [st["direction"] for st in entered.snapshot.get("steps") or []] == ["NORTHBOUND"],
           steps=entered.snapshot.get("steps"), note="all hosts quiet; northbound READY (sandbox input), southbound NOT_READY: only the northbound cell is drained")
    result("05_drain_syntax_readback_traffic_moved_zero_loss", ok_entry,
           **{k: facts[k] for k in ("entry_outcome", "applied", "probes_lost_in_run", "probe_totals_entry", "proofs", "after_paths", "persistence")},
           s1_startup_equals_running_drained=s1_drained["running"] == s1_drained["startup"], router_and_cores_untouched=ok_entry)
    ok_restore = (final.state == lifecycle.RESTORED and not final.escalated and facts["baseline_restored"] and facts["probes_lost_in_restore"] == 0
                  and not facts["verification"] and facts["chain_ok"])
    result("06_successful_restore_exact_baseline", ok_restore,
           **{k: facts.get(k) for k in ("state_after_restore", "restore_outcome", "probes_lost_in_restore", "probe_totals_restore", "verification", "baseline_restored", "chain_ok")},
           end_running_equals_startup={n: facts["end_digests"][n]["running"] == facts["end_digests"][n]["startup"] for n in ("R1", "R2", "S1", "S2")})


def s05b_both_directions_active():
    """Both directions, with the production workload running: the southbound OSPFv3 external metric without any core
    cover.  Measured, never assumed: zero loss makes the device ACTIVE, any loss aborts the entry and restores it."""
    entered, final, facts, base = cycle("s05b", "R1", BOTH_READY, active=True)
    lossless = entered.state == lifecycle.ACTIVE
    ok = (lossless and final.state == lifecycle.RESTORED and facts["baseline_restored"]) or \
         (not lossless and entered.state == lifecycle.ABORTED_RESTORED and facts["baseline_restored"] and (facts["failure"] or {}).get("code") in (gates.PACKET_LOSS, "GATE_FAILED"))
    result("05b_southbound_metric_without_covers_measured", ok, lossless=lossless,
           **{k: facts.get(k) for k in ("state_after_entry", "entry_outcome", "failure", "applied", "compensation", "probes_lost_in_run", "probe_totals_entry",
                                        "state_after_restore", "probes_lost_in_restore", "baseline_restored", "chain_ok")},
           cores_unchanged=all(facts["drained_digests"][c] == base[c] for c in ("R3", "R4")))


class Injected(Exception):
    """The intentional failure of the entry-failure scenario."""


def s07_entry_failure():
    def fail(event, key):
        if (event, key) == ("after", "S1-uplink-metric-drain"):
            RUN.ev("INJECT", "failure after", key)
            raise Injected(key)

    entered, final, facts, base = cycle("s07", "R1", NORTH_READY, active=False, hook=fail)
    order = [entry["operation"] for entry in facts["compensation"] or []]
    ok = (entered.state == lifecycle.ABORTED_RESTORED and not entered.escalated and facts["baseline_restored"]
          and order == ["S1-uplink-metric-drain", "S1-shield-install-drain"] and all(e["status"] == "COMPENSATED" for e in facts["compensation"]))
    result("07_entry_failure_compensated_newest_first", ok, state=entered.state, failure=facts["failure"], compensation=facts["compensation"],
           probes_lost_in_run=facts["probes_lost_in_run"], baseline_restored=facts["baseline_restored"], chain_ok=facts["chain_ok"])


def s08_restore_failure():
    workload(False)
    base = snapshot()
    row, rt = approved("R1", NORTH_READY)
    row = enter(row, rt)
    if row.state != lifecycle.ACTIVE:
        return result("08_restore_failure_escalates", False, reason=f"entry {row.state}", findings=row.snapshot.get("findings"))
    oob(True)                                                        # the path that carries the traffic changed while active
    failed = leave(row, rt)
    locks_after_failure = list(models.ExecutionDeviceLock.objects.values_list("device", flat=True))
    blocked_other = ""
    try:                                                              # an escalated record blocks what intersects it
        other, _rt = planned("R2", NORTH_READY)
        blocked_other = sorted({f["code"] for f in other.snapshot.get("findings") or []})
        close_open("R2")
    except model.MaintenanceError as exc:
        blocked_other = exc.code
    drained_kept = [line.strip() for line in mig.cli("s1", "show running-config").splitlines() if line.strip() == f"isis metric {mig_drain_metric()}"]
    oob(False)
    retried = leave(failed, rt)                                       # the operator fixed the cause and runs the restore again
    end = snapshot()
    ok_chain, _problems = chain_ok(retried)
    ok = (failed.state == lifecycle.RESTORE_FAILED and failed.escalated and bool(drained_kept) and locks_after_failure == []
          and retried.state == lifecycle.RESTORED and comparable(end) == comparable(base) and ok_chain)
    dump("s08_evidence", evidence_of(retried))
    result("08_restore_failure_escalates", ok, failed_state=failed.state, failed_findings=failed.snapshot.get("findings"), drained_state_kept=drained_kept,
           locks_after_failure=locks_after_failure, entry_on_intersecting_device=blocked_other, retried_state=retried.state,
           baseline_restored=comparable(end) == comparable(base), chain_ok=ok_chain)


def mig_drain_metric():
    from core.services.route_shield import lab
    return lab.DRAIN_METRIC


def s14_deadline():
    workload(False)
    base = snapshot()
    row, rt = approved("R1", NORTH_READY)
    row = enter(row, rt)
    if row.state != lifecycle.ACTIVE:
        return result("14_deadline_restore", False, reason=f"entry {row.state}")
    record = store.load(row)
    record.entered_at = now() - model.MAINTENANCE_CYCLE - timedelta(minutes=1)    # a cycle has passed (a clock jump on this record only)
    store.save(record, row)
    results = service.tick(now=now, runtime_factory=lambda: rt)
    row.refresh_from_db()
    end = snapshot()
    ok_chain, _p = chain_ok(row)
    ok = row.state == lifecycle.RESTORED and row.restore_trigger == lifecycle.DEADLINE and comparable(end) == comparable(base) and ok_chain
    dump("s14_evidence", evidence_of(row))
    result("14_deadline_restore", ok, tick=results, state=row.state, trigger=row.restore_trigger, deadline_at=row.deadline_at,
           baseline_restored=comparable(end) == comparable(base), chain_ok=ok_chain)


def _tick_process():
    env = dict(os.environ)
    return subprocess.Popen([sys.executable, os.path.abspath(__file__), os.path.join(OUT, "tick-child"), "child-tick"], env=env, cwd=os.getcwd(),
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


def s13_worker_idempotent():
    workload(False)
    base = snapshot()
    row, _rt = approved("R1", NORTH_READY)
    service.queue(row.pk, service.ENTER, "sandbox-operator", now=now(), plan_hash=row.plan_hash)
    try:
        service.queue(row.pk, service.ENTER, "sandbox-operator", now=now(), plan_hash=row.plan_hash)
        second_queue = "ACCEPTED"
    except model.MaintenanceError as exc:
        second_queue = exc.code
    workers = [_tick_process(), _tick_process()]                      # two worker passes at the same moment
    outputs = [w.communicate(timeout=1800)[0] for w in workers]
    row.refresh_from_db()
    entries = models.MaintenanceEvidence.objects.filter(record=row, kind=chain.ENTRY).count()
    again = service.tick(now=now, runtime_factory=lambda: runtime(NORTH_READY))
    active_state = row.state
    service.queue(row.pk, service.RESTORE, "sandbox-operator", now=now())
    restored = service.tick(now=now, runtime_factory=lambda: runtime(NORTH_READY))
    idle = service.tick(now=now, runtime_factory=lambda: runtime(NORTH_READY))
    row.refresh_from_db()
    end = snapshot()
    ok = (second_queue == "RECORD_BUSY" and active_state == lifecycle.ACTIVE and entries == 1 and again == [] and row.state == lifecycle.RESTORED
          and idle == [] and comparable(end) == comparable(base))
    dump("s13_worker_outputs", outputs)
    result("13_worker_retry_idempotent", ok, second_queue=second_queue, concurrent_workers=[o.strip().splitlines()[-1:] for o in outputs], entry_runs=entries,
           state_after_workers=active_state, tick_again=again, restore_tick=restored, idle_tick=idle, final=row.state, baseline_restored=comparable(end) == comparable(base))


def s11b_crash_recovery():
    """A worker killed mid-drain.  Hold point 1: after the switch shield was removed (a step boundary: the drain is fully
    in place, unpersisted) -> the recovery restores it.  Hold point 2: right after the uplink metric, with the shield
    still installed (unknown completion of a stage) -> the recovery escalates instead of guessing."""
    out = {}
    for label, hold in (("after_step_boundary", "S1-shield-remove-drain"), ("inside_stage", "S1-uplink-metric-drain")):
        workload(False)
        base = snapshot()
        row, _rt = approved("R1", NORTH_READY)
        child = subprocess.Popen([sys.executable, os.path.abspath(__file__), os.path.join(OUT, f"crash-{label}"), "child-enter", str(row.pk), hold],
                                 env=dict(os.environ), cwd=os.getcwd(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        marker = os.path.join(OUT, f"crash-{label}", "held")
        for _ in range(900):
            if os.path.exists(marker) or child.poll() is not None:
                break
            time.sleep(1)
        child.send_signal(signal.SIGKILL)
        child.wait()
        row.refresh_from_db()
        killed = {"state": row.state, "claim": bool(row.claim_token), "locks": list(models.ExecutionDeviceLock.objects.values_list("device", flat=True)),
                  "s1_running": snapshot()["S1"]["running"]}
        immediate = service.tick(now=now, runtime_factory=lambda: runtime(NORTH_READY))       # the claim is still fresh: nobody steals it
        service.CLAIM_STALE_AFTER = timedelta(seconds=5)                                       # the sandbox does not wait 20 minutes
        time.sleep(6)
        recovered = service.tick(now=now, runtime_factory=lambda: runtime(NORTH_READY))
        service.CLAIM_STALE_AFTER = timedelta(minutes=20)
        row.refresh_from_db()
        facts = {"killed": killed, "tick_while_claim_fresh": immediate, "recovery": recovered, "state": row.state, "escalated": row.escalated,
                 "maintenance_only_state": row.snapshot.get("maintenance_only_state"), "findings": row.snapshot.get("findings")}
        facts["s1_unchanged_by_recovery"] = snapshot()["S1"]["running"] == killed["s1_running"]
        if row.state == lifecycle.RESTORE_FAILED:                    # the operator's manual recovery, from the evidence
            facts["operator_recovery"] = "configure replace startup-config on S1 (startup is the unpersisted pre-state)"
            mig.cli("s1", "configure replace startup-config")
            retried = leave(row, runtime(NORTH_READY))
            facts["after_operator_retry"] = retried.state
            row = retried
        end = snapshot()
        facts["baseline_restored"] = comparable(end) == comparable(base)
        facts["chain_ok"] = chain_ok(row)[0]
        dump(f"s11b_{label}_evidence", evidence_of(row))
        out[label] = facts
    ok = (out["after_step_boundary"]["state"] == lifecycle.ABORTED_RESTORED and out["after_step_boundary"]["baseline_restored"]
          and out["inside_stage"]["state"] == lifecycle.RESTORE_FAILED and out["inside_stage"]["escalated"] and out["inside_stage"]["baseline_restored"]
          and out["inside_stage"]["s1_unchanged_by_recovery"] and service.UNCERTAIN in {f["code"] for f in out["inside_stage"]["findings"] or []}
          and all(f["tick_while_claim_fresh"] == [] and f["killed"]["claim"] for f in out.values()))
    result("11b_worker_crash_recovery", ok, **out)


def child_enter(record_pk, hold):
    marker = os.path.join(OUT, "held")

    def held(event, key):
        if (event, key) == ("after", hold):
            open(marker, "w").write(key)
            RUN.ev("HOLD", "worker holds after", key, "until killed")
            time.sleep(3600)

    HOOK["fn"] = held
    service.enter(int(record_pk), "sandbox-operator", now=now, runtime=runtime(NORTH_READY))


def child_tick():
    found = service.tick(now=now, runtime_factory=lambda: runtime(NORTH_READY))
    print(json.dumps(found, default=str))


SCENARIOS = [("01", s01_observation), ("03", s03_block), ("12", s12_r5), ("11", s11_vlan200), ("09", s09_stale_observation),
             ("02_10", s02_10_ready_then_stale_plan), ("04_05_06", s04_05_06_quiesced_north), ("07", s07_entry_failure), ("08", s08_restore_failure),
             ("14", s14_deadline), ("13", s13_worker_idempotent), ("05b", s05b_both_directions_active), ("11b", s11b_crash_recovery)]


def main():
    mig.guard()
    call_command("migrate", verbosity=0, interactive=False)
    what = sys.argv[2]
    if what == "child-enter":
        return child_enter(sys.argv[3], sys.argv[4])
    if what == "child-tick":
        return child_tick()
    wanted = [key for key, _fn in SCENARIOS] if what == "all" else sys.argv[2:]
    RUN.ev("START maintenance-sandbox", wanted, "load", *mig.load())
    for key, fn in SCENARIOS:
        if key in wanted:
            RUN.ev("SCENARIO", key, "begin", "load", *mig.load())
            try:
                fn()
            except Exception as exc:  # noqa: BLE001 - a crashed scenario is a failed scenario, with its reason
                import traceback
                RUN.ev("SCENARIO", key, "CRASHED", type(exc).__name__, str(exc)[:500])
                result(key, False, crashed=traceback.format_exc()[-1500:])
                HOOK["fn"] = None
    RUN.ev("END", json.dumps({k: v["ok"] for k, v in RESULTS.items()}), "load", *mig.load())
    return 0 if RESULTS and all(v["ok"] for v in RESULTS.values()) else 1


if __name__ == "__main__":
    sys.exit(main() or 0)
