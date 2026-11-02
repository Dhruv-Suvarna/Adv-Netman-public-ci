"""READ-ONLY production transport verification and precheck snapshot of the baseline migration.

``run()`` drives the code the live migration would drive -- ``production.environment()``, the same executors, the same
credential lookup, the same sessions, the same precheck, the same probe source, the same read-back checks -- behind a
guard that refuses and counts every write-capable call.  It needs no Change, records nothing in the database and sends
no configuration, kernel-route or persistence command.  The only things it starts are the dedicated echo probes inside
the client hosts and the service host, which it stops again.

Two verdicts, never merged:

    PRODUCTION_READ_ONLY_DRY_RUN   the production wiring works end to end and no write was attempted
    PRODUCTION_PRECHECK            the precheck the live migration would run finds no blocker right now
"""

from __future__ import annotations

import ipaddress
import json
import time

from django.utils import timezone

from ... import models
from ..execution.executors.base import ExecutorError
from . import checks, core_cover, gates, lab, lifecycle, migration, production, source_of_truth

PASS, FAIL, BLOCKED = "PASS", "FAIL", "BLOCKED"
READ_ONLY = "READ_ONLY_DRY_RUN"
_CORE_READS = (("ip", "-j"), ("vtysh", "-c", "show "), ("cat", core_cover.PERSISTENT_CONFIG), ("hostname",))
_SESSION_READS = ("show ", "ping ipv6 ")


class WriteGuard:
    """Refuses every call that could change a device, and remembers that it was asked."""

    def __init__(self):
        self.attempts: list[str] = []
        self.reads = 0

    def _refuse(self, device: str, what: str):
        def refused(*_args, **_kwargs):
            self.attempts.append(f"{device}: {what}")
            raise ExecutorError(READ_ONLY)
        return refused

    def _core_runner(self, device: str, runner):
        def guarded(container, argv, timeout):
            head = " ".join(str(word) for word in argv)
            if not any(head.startswith(" ".join(allowed)) for allowed in _CORE_READS):
                self.attempts.append(f"{device}: {head[:60]}")
                raise ExecutorError(READ_ONLY)
            self.reads += 1
            return runner(container, argv, timeout)
        return guarded

    def _session(self, device: str, connection):
        send = connection.send_command

        def guarded(command, *args, **kwargs):
            if not str(command).startswith(_SESSION_READS):
                self.attempts.append(f"{device}: {str(command)[:60]}")
                raise ExecutorError(READ_ONLY)
            self.reads += 1
            return send(command, *args, **kwargs)

        connection.send_command = guarded
        for name in ("send_config_set", "config_mode", "send_config_from_file", "save_config", "commit"):
            if hasattr(connection, name):
                setattr(connection, name, self._refuse(device, name))

    def factory(self, executor_factory):
        """The production executor factory, with every executor it returns made read-only."""
        def build(device: dict):
            executor, name = executor_factory(device), device["name"]
            for method in ("apply", "compensate", "save_startup", "_send"):
                if hasattr(executor, method):
                    setattr(executor, method, self._refuse(name, method))
            if hasattr(executor, "_runner"):
                executor._runner = self._core_runner(name, executor._runner)
            else:
                connect = executor.connect

                def guarded_connect(connect=connect, executor=executor, name=name):
                    connect()
                    if getattr(executor, "_conn", None) is not None:      # the real cEOS executor: its session is guarded as well
                        self._session(name, executor._conn)

                executor.connect = guarded_connect
            return executor
        return build


def _json(text: str) -> dict:
    try:
        return json.loads(text or "{}")
    except ValueError:
        return {}


def _access_snapshot(name: str, definition, env, facts: dict) -> dict:
    executor, evidence = env.executors[name], env.read(env.devices[name])
    digests = (facts.get("digests") or {}).get(name) or {}
    expected = []
    if name in definition.switches:
        s = definition.switches[name]
        expected.append((lab.AGGREGATE, s.uplink, s.router_v6))
    else:
        r = definition.routers[name]
        expected += [(prefix, r.access_interface, r.switch_v6) for prefix in lab.CLIENTS]
    statics = []
    for prefix, interface, hop in expected:
        ok, detail = checks.owned(env, device=name, prefix=prefix, source="static", interface=interface, next_hop=hop)
        statics.append({"prefix": prefix, "next_hop": hop, "interface": interface, "installed_by_static": ok, "detail": detail})
    addresses = evidence.facts("addresses") or {}
    management = sorted(a for key, values in addresses.items() if key.lower().startswith("management") for a in values)
    ospf = evidence.facts("ospf") or []
    return {
        "running_config_digest": digests.get("config"), "startup_config_digest": digests.get("startup"),
        "startup_matches_running": bool(digests) and digests.get("config") == digests.get("startup"),
        "expected_static_ipv6_routes": statics,
        "rip": {"neighbors": evidence.facts("rip_neighbors"), "configuration_digest": lifecycle.canonical.text_hash(executor.show("show running-config section router rip"))},
        "ospf": [{k: row.get(k) for k in ("family", "interface", "neighbor_id", "state")} for row in ospf],
        "isis_adjacencies": evidence.facts("isis"),
        "varp": evidence.facts("virtual_addresses"),
        "management": {"reachable": bool(getattr(evidence, "live_reachable", False)), "addresses": management,
                       "expected": env.devices[name].get("address")},
    }


def _core_snapshot(name: str, definition, env, facts: dict) -> dict:
    executor = env.executors[name]
    covers = definition.covers_of(name)
    kernel = [{"dst": row.get("dst"), "protocol": row.get("protocol", "boot"), "next_hops": [list(hop) for hop in core_cover._row_hops(row)]}
              for row in executor.routes_within("2001:db8::/32")]
    return {
        "kernel_ipv6_routes": kernel,
        "approved_covers": [{"prefix": c.prefix, "state": executor.state(c), "next_hops": [list(hop) for hop in c.hops]} for c in covers],
        "approved_covers_absent": all(executor.state(c) == "ABSENT" for c in covers),
        "client_routes": {c.protects: {"next_hops": [list(hop) for row in executor.routes(c.protects) for hop in core_cover._row_hops(row)],
                                       **executor.client_route(c.protects)} for c in covers},
        "ospfv3_full_neighbours": sorted(list(pair) for pair in executor.full_neighbours()),
        "management_interfaces": sorted(executor.management_interfaces()),
        "conflicts": core_cover.precheck(covers, executor, env.read(env.devices[name])),
        "digests": (facts.get("digests") or {}).get(name),
    }


def _global_snapshot(definition, env) -> dict:
    from ..validation import sources

    found: dict = {}
    netbox = sources.collect_netbox()
    transit = ipaddress.ip_network(str(ipaddress.ip_interface(next(iter(definition.transit_v6.values()))).network))
    if netbox.status == "available":
        data = netbox.data
        wanted = {name: str(ipaddress.ip_interface(address).ip) for name, address in definition.transit_v6.items()}
        rows = [row for row in data.get("ip_addresses") or [] if row.get("family") == 6 and ipaddress.ip_address(row["ip"]) in transit]
        found["netbox_vlan99_ipv6"] = {
            "available": True, "prefix": str(transit),
            "prefix_present": any(row.get("prefix") == str(transit) for row in data.get("prefixes") or []),
            "prefix_vlan": next((row.get("vlan") for row in data.get("prefixes") or [] if row.get("prefix") == str(transit)), None),
            "addresses": sorted(f"{row['ip']} {row.get('device')} {row.get('interface')}" for row in rows),
            "expected_addresses_recorded": all(any(row["ip"] == ip and row.get("device") == name for row in rows) for name, ip in wanted.items()),
            # before the migration NetBox holds the prefix and no address in it; the two addresses are recorded after it
            "state": ("POST_MIGRATION" if all(any(row["ip"] == ip and row.get("device") == name for row in rows) for name, ip in wanted.items())
                      else "PRE_MIGRATION" if not rows else "MIXED"),
            "conflicts": sorted(f"{row['ip']} {row.get('device')}" for row in rows if row["ip"] not in wanted.values()),
        }
    else:
        found["netbox_vlan99_ipv6"] = {"available": False}
    topology = sources.collect_topology()
    nodes = (topology.data or {}).get("nodes") if topology.status == "available" else None
    found["topology_membership"] = {"available": nodes is not None,
                                    "members": {name: (nodes or {}).get(name, {}).get("kind") for name in definition.devices}}
    transitions = [c for c in models.Change.objects.exclude(metadata__transition__isnull=True) if lifecycle.is_transition(c)]
    found["transition_changes"] = [{"change": c.change_id, "kind": lifecycle.kind_of(c), "lifecycle": c.lifecycle_state,
                                    "runs": [run.outcome or run.state for run in c.execution_runs.order_by("started_at")]} for c in transitions]
    found["pending_migration"] = [row["change"] for row in found["transition_changes"]
                                  if row["lifecycle"] in (models.ChangeLifecycleState.READY_TO_DEPLOY,)]
    found["unresolved_transitions"] = lifecycle.unresolved_transitions()
    ops = migration.forward_operations(definition)
    temporary = tuple(line for op in ops if op.state == migration.TEMPORARY and op.action == migration.ADD for line in op.lines)
    ok, detail = checks.no_temporary_lines(env, devices=definition.access_devices, lines=temporary)
    found["temporary_state"] = {"access_devices_clean": ok, "detail": detail,
                                "covers_absent": all(env.executors[c.core].state(c) == "ABSENT" for c in definition.covers)}
    found["tracked_intent"] = source_of_truth.tracked_state(definition)
    return found


def _reader_sweep(definition, env) -> dict:
    """Every read-back the live run is gated on, called once.  A reader works when it returns ``(bool, text)``; whether
    it holds today is not the question (IS-IS does not exist yet)."""
    seen, broken, count = set(), [], 0
    every = [*migration.forward_operations(definition), *migration.revert_operations(definition)]
    listed = [check for op in every for group in (op.before, op.after, op.undo_before, op.undo_after) for check in group]
    listed += [*lifecycle._forwarding_checks(definition, migration.KIND), *lifecycle._forwarding_checks(definition, migration.REVERT_KIND)]
    for check in listed:
        if check.label in seen:
            continue
        seen.add(check.label)
        try:
            ok, detail = check.run(env)
            if not isinstance(ok, bool) or not isinstance(detail, str):
                broken.append(f"{check.label}: not a verdict")
        except Exception as exc:  # noqa: BLE001 - a reader that raises is a broken reader
            broken.append(f"{check.label}: {type(exc).__name__}")
        count += 1
    return {"readers": count, "broken": broken}


def run(*, definition: migration.Definition = migration.PRODUCTION, environment=None, warm_up_seconds: float = 30.0, sleep=time.sleep) -> dict:
    """-> the report.  ``report["PRODUCTION_READ_ONLY_DRY_RUN"]`` and ``report["PRODUCTION_PRECHECK"]`` are the verdicts."""
    from .. import nsot_live

    guard, rows = WriteGuard(), []
    started = timezone.now()

    def record(check: str, ok: bool, detail="") -> bool:
        rows.append({"check": check, "status": PASS if ok else FAIL, "detail": detail if isinstance(detail, (dict, list)) else str(detail)[:300]})
        return bool(ok)

    env = environment if environment is not None else production.environment()
    env.executor_factory = guard.factory(env.executor_factory)
    report: dict = {"schema": 1, "engine": lifecycle.ENGINE_VERSION, "definition": definition.name, "started_at": started.isoformat(),
                    "mode": "READ_ONLY", "checks": rows, "snapshot": {}}
    missing = [name for name in definition.devices if name not in env.devices]
    wrong = lifecycle._inventory_findings(definition, env.devices)
    record("inventory: the six managed devices resolve with the expected platform", not missing and not wrong,
           {"devices": {n: {k: env.devices[n].get(k) for k in ("platform", "container", "address")} for n in env.devices}, "findings": wrong})
    resolved = {name: nsot_live.get_live_target(name) is not None for name in definition.access_devices}
    record("credentials resolve for R1, R2, S1, S2 (values never read out)", all(resolved.values()), resolved)
    connected = {}
    for name in definition.devices:
        try:
            env.connect([name])
            connected[name] = "connected"
        except ExecutorError as exc:
            connected[name] = exc.code
    record("transport connects to all six devices", all(v == "connected" for v in connected.values()), connected)
    if missing or any(v != "connected" for v in connected.values()):
        env.close()
        return _finish(report, guard, precheck=None)
    probes_started = False
    try:
        identity = {}
        for name in definition.access_devices:
            host = _json(env.executors[name].show("show hostname | json")).get("hostname")
            version = _json(env.executors[name].show("show version | json"))
            identity[name] = {"hostname": host, "model": version.get("modelName"), "version": version.get("version")}
        for name in definition.cores:
            identity[name] = env.executors[name].identity()
        record("device identity matches the inventory name", all(identity[n]["hostname"] == n for n in definition.devices), identity)
        record("expected platform detected", all("cEOS" in str(identity[n].get("model")) for n in definition.access_devices)
               and all(identity[n].get("platform") == "FRRouting" for n in definition.cores), identity)
        production.start_probes(env)
        probes_started = True
        sleep(warm_up_seconds)
        ops = migration.forward_operations(definition)
        blockers, facts = lifecycle.precheck_blockers(definition, ops, env)
        blockers += lifecycle._record_blockers_for(migration.KIND)
        digests = facts.get("digests") or {}
        record("running and startup configuration of R1, R2, S1, S2 can be read",
               all(digests.get(n, {}).get("config") and digests.get(n, {}).get("startup") for n in definition.access_devices))
        record("R3/R4 kernel routes, FRR and boot configuration can be read",
               all(digests.get(n, {}).get("static_routes") and digests.get(n, {}).get("persistent_config") for n in definition.cores))
        unreadable = [b for b in blockers if b["code"] == gates.EVIDENCE_UNAVAILABLE]
        record("IS-IS, RIP and OSPFv3 preconditions can be evaluated (precheck ran to a verdict)", not unreadable, unreadable)
        healthy, probe_facts = env.probes.healthy()
        record("probe sources start and every flow answers", healthy, {**probe_facts, "flows_detail": env.probes.report()})
        env.baseline = digests
        snapshot = report["snapshot"]
        snapshot["access"] = {name: _access_snapshot(name, definition, env, facts) for name in definition.access_devices}
        snapshot["core"] = {name: _core_snapshot(name, definition, env, facts) for name in definition.cores}
        record("route state can be read on all six devices", all(row["expected_static_ipv6_routes"] for row in snapshot["access"].values())
               and all(row["kernel_ipv6_routes"] for row in snapshot["core"].values()))
        snapshot["global"] = _global_snapshot(definition, env)
        snapshot["host"] = facts.get("host")
        snapshot["probes"] = probe_facts
        record("evidence targets resolve (Change, plan, run, result, check-run and audit records are reachable)", _evidence_targets())
        sweep = _reader_sweep(definition, env)
        post = {core: core_cover.postcheck(definition.covers_of(core), env.executors[core], env.read(env.devices[core]),
                                           adjacencies_before=digests.get(core, {}).get("adjacencies"), present=False) for core in definition.cores}
        record("every postcheck reader functions", not sweep["broken"] and all(isinstance(v, list) for v in post.values()), {**sweep, "core_postcheck": post})
        report["precheck"] = {"status": PASS if not blockers else BLOCKED, "blockers": blockers}
    except Exception as exc:  # noqa: BLE001 - a dry run reports, it never half-finishes silently
        record("dry run completed", False, type(exc).__name__ + (f": {exc.code}" if isinstance(exc, ExecutorError) else ""))
    finally:
        if probes_started:
            env.probes.stop()
            report["probes"] = env.probes.report()
        env.close()
    return _finish(report, guard, precheck=report.get("precheck"))


def _evidence_targets() -> bool:
    for model in (models.Change, models.ChangeValidationRun, models.ChangePlan, models.Configlet, models.OperationalCheckRun,
                  models.ChangeExecutionRun, models.ConfigletExecutionResult, models.AuditEvent, models.ChangeLifecycleEvent):
        model.objects.exists()
    return True


def _finish(report: dict, guard: WriteGuard, *, precheck) -> dict:
    report["checks"].append({"check": "no write method was invoked", "status": PASS if not guard.attempts else FAIL,
                             "detail": {"write_attempts": guard.attempts, "read_commands": guard.reads}})
    report["write_attempts"] = list(guard.attempts)
    report["finished_at"] = timezone.now().isoformat()
    report["PRODUCTION_READ_ONLY_DRY_RUN"] = PASS if all(row["status"] == PASS for row in report["checks"]) else FAIL
    report["PRODUCTION_PRECHECK"] = (precheck or {}).get("status", "NOT_EVALUATED")
    return report
