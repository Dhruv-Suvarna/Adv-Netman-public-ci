#!/usr/bin/env python3
"""The complete NMAS transition lifecycle against the DISPOSABLE isisbx sandbox, with no production authority involved:

    Change -> validation -> Plan -> Precheck -> approval -> execution (R3/R4 covers, IS-IS migration, postchecks,
    cover cleanup) -> final state -> evidence        (mode ``forward``)
    ... and the same up to a chosen operation, then an injected failure -> automatic compensation     (mode ``abort``)
    REVERT COMPLETED BASELINE MIGRATION: a second Change that names a SUCCEEDED migration run          (mode ``revert``)

The persistence stage (startup configuration of the four access devices) is part of every mode.  An abort key of the
form ``PERSISTENCE-<device>`` injects the failure inside that stage.

Isolated: Django runs on a scratch SQLite database (``scratch_settings``), the six "devices" are labelled sandbox containers
handed to the workflow as its inventory, and nothing reads NetBox, ``inventory.yml`` or the production database.

usage: nmas_lifecycle.py <outdir> forward | abort <operation-key> | window <operation-key> | revert <run id of the SUCCEEDED migration | latest>
       (run from the worktree's web/ directory, DJANGO_SETTINGS_MODULE=scratch_settings)
"""
import json, os, re, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mig                                                      # sandbox plumbing only: guard, TCP/HTTP sessions, route monitors

import django
django.setup()
from django.core.management import call_command
from core import models
from core.services import execution_service
from core.services.capabilities.isolated_live import DockerEosConfigConnection, _run
from core.services.execution.executors.ceos import CeosExecutor
from core.services.health import live
from core.services.route_shield import core_cover, gates, lifecycle, migration, probes

out, mode = sys.argv[1], sys.argv[2]
fail_at = sys.argv[3] if len(sys.argv) > 3 else ""
mig.guard()
run = mig.Run(out)
call_command("migrate", verbosity=0, interactive=False)

CONTAINERS = {"R1": "r1", "R2": "r2", "S1": "s1", "S2": "s2", "R3": "c3", "R4": "c4"}
DEVICES = {name: {"name": name, "platform": "linux" if name in ("R3", "R4") else "ceos", "container": f"{mig.P}-{short}", "address": ""}
           for name, short in CONTAINERS.items()}


class SandboxConnection(DockerEosConfigConnection):
    """The isolated docker transport, plus the one non-configuration exec command the workflow sends (an echo request)."""

    def send_command(self, command, **kwargs):
        if command.startswith("ping ipv6 ") or command == "copy running-config startup-config":
            return _run(["docker", "exec", self._container, "Cli", "-p", "15", "-c", command], timeout=60).stdout
        # ``Cli -c`` echoes the command as a first line ("> show ..."), which an SSH session does not: drop it, so that the
        # running and the startup configuration are compared as the production transport would see them
        text = super().send_command(command, **kwargs)
        return "\n".join(line for line in text.splitlines() if not line.startswith("> show ")) + "\n"


def factory(device):
    if device["platform"] == "linux":
        return core_cover.KernelCoverExecutor(device, sandbox_covers=DEFINITION.covers)     # the sandbox cores' own measured next hops
    return CeosExecutor(device, connection_factory=SandboxConnection, reader=live.read_device)


def core_hops():
    """The two next hops each sandbox core's client /64 is installed with: the sandbox equivalent of the production table."""
    found = {}
    for name in ("R3", "R4"):
        text = mig.kern(CONTAINERS[name], "ip", "-6", "route", "show", mig.CLIENTS[0])
        hops = re.findall(r"nexthop via (\S+) dev (\S+)", text)
        if len(hops) != 2:
            sys.exit(f"{name}: {mig.CLIENTS[0]} is not forwarded to both boundary routers: {text!r}")
        found[name] = tuple(hops)
    return found


DEFINITION = migration.with_cabling(migration.PRODUCTION, name="sandbox", access_interface="Ethernet3", core_hops=core_hops())
FLOWS = []
for host, (v4, v6) in mig.HOSTS.items():
    FLOWS.append(probes.Flow(f"{host}-web-v6", f"{mig.P}-{host}", mig.WEB6, 0.01))
    FLOWS.append(probes.Flow(f"web-{host}-v6", f"{mig.P}-web", v6, 0.02, mig.WEB6))
    if v4:
        FLOWS.append(probes.Flow(f"{host}-web-v4", f"{mig.P}-{host}", mig.WEB4, 0.1))
        FLOWS.append(probes.Flow(f"web-{host}-v4", f"{mig.P}-web", v4, 0.1, mig.WEB4))
PROBES = probes.HostProbes(FLOWS)


class Injected(Exception):
    """The intentional failure of the abort proof."""


def observer(event, key):
    run.ev("NMAS", event, key)
    if mode == "abort" and event == "after" and key == fail_at:
        run.ev("INJECT", "failure after", key)
        raise Injected(key)
    if mode == "window" and event == "after" and key == fail_at:
        run.ev("INJECT", "window condition lost after", key)
        WINDOW["lost"] = True


WINDOW = {"lost": False, "samples": 0}


def host_gate():
    """The sandbox host gate.  Mode ``window``: after the chosen operation the gate reports an INJECTED critical CPU
    condition, so that the run is stopped by the workflow's own between-stage guard and not by an exception."""
    ok, facts = gates.default_host_gate(max_load_per_cpu=8.0)      # the sandbox host itself runs ~4 per CPU
    if WINDOW["lost"]:
        WINDOW["samples"] += 1
        run.ev("INJECT", "host gate sample", WINDOW["samples"], "reported as failed")
        return False, {**facts, "failed": ["INJECTED: host CPU at the critical condition with the probes running"]}
    return ok, facts


host_gate.consecutive_samples = 3      # the value of monitoring/config/cpu_threshold_policy.yml


def environment():
    return lifecycle.Environment(devices=DEVICES, executor_factory=factory, read=live.read_device, probes=PROBES,
                                 host_gate=host_gate, observer=observer)


def digests():
    return {dev: mig.digest(mig.running(dev)) for dev in ("r1", "r2", "s1", "s2")}


def startup_digests():
    """The startup configuration of each sandbox access device under the product's own digest formula."""
    found = {}
    for name in ("R1", "R2", "S1", "S2"):
        executor = factory(DEVICES[name])
        executor.connect()
        found[name] = {"startup": executor.startup_state_digest(), "running": executor.config_state_digest()}
        executor.close()
    return found


def boot_digests():
    return {c: mig.digest(mig.kern(c, "cat", "/etc/frr/frr.conf")) for c in ("c3", "c4")}


def cover_routes():
    return {c: mig.kern(c, "ip", "-6", "route", "show", "root", "2001:db8::/32").count("/63") for c in ("c3", "c4")}


def dump(name, value):
    json.dump(value, open(f"{out}/{name}.json", "w"), indent=1, default=str)


run.ev("START nmas-lifecycle", mode, fail_at, "load", *mig.load())
base = digests()
start_startup, start_boot = startup_digests(), boot_digests()
run.ev("CONFIG start", json.dumps(base), "covers", json.dumps(cover_routes()))
run.ev("STARTUP start", json.dumps(start_startup), "core-boot", json.dumps(start_boot))
for dev in ("pe", "c3", "c4", "r1", "r2", "s1", "s2"):           # no monitor of an earlier run may write into this run's evidence
    mig.sh("docker", "exec", f"{mig.P}-{dev}", "pkill", "-f", "ip -ts -6 monitor")
mig.monitors(True)
mig.sessions_start()
PROBES.start()
time.sleep(25)
failed = None
try:
    actor = "sandbox-operator"
    if mode == "revert":
        wanted = fail_at if fail_at and fail_at != "latest" else str(models.ChangeExecutionRun.objects.filter(outcome="SUCCEEDED").order_by("-started_at").first().run_id)
        try:
            lifecycle.create_revert(actor=actor, migration_run_id="00000000-0000-0000-0000-000000000000", definition=DEFINITION)
            raise RuntimeError("a revert of a run that does not exist was accepted")
        except lifecycle.LifecycleError as exc:
            run.ev("GATE", "revert of an unknown run ->", ",".join(b["code"] for b in exc.blockers))
        change = lifecycle.create_revert(actor=actor, migration_run_id=wanted, definition=DEFINITION)
        basis = lifecycle.revert_basis(change)
        run.ev("LIFECYCLE", "revert of", change.metadata["transition"]["reverts"]["change"], "run", wanted)
    else:
        change = lifecycle.create_change(actor=actor, definition=DEFINITION)
    run.ev("LIFECYCLE", "change", change.change_id, json.dumps(change.metadata))
    validation = lifecycle.validate_change(change, actor=actor, definition=DEFINITION, inventory=DEVICES)
    run.ev("LIFECYCLE", "validation", validation.status, "findings=%d" % len(validation.report["findings"]))
    plan = lifecycle.build_plan(change, actor=actor, definition=DEFINITION)
    run.ev("LIFECYCLE", "plan", str(plan.plan_id)[:8], "operations=%d" % plan.configlets.count(), "permanent=%d" % len(plan.summary["permanent"]),
           "temporary=%d" % len(plan.summary["temporary"]))
    generic = execution_service.check_execution_eligibility(change, confirm_mode="COMPLETE")
    run.ev("GATE", "general execution engine ->", ",".join(b["code"] for b in generic.blockers if b["code"].startswith("TRANSITION")) or "NOT BLOCKED")
    assert generic.has("TRANSITION_CHANGE_NOT_GENERIC")
    precheck = lifecycle.run_precheck(change, actor=actor, env=environment(), definition=DEFINITION)
    run.ev("LIFECYCLE", "precheck", precheck.status, json.dumps(precheck.summary))
    if precheck.status != "PASS":
        raise RuntimeError("precheck: " + json.dumps(precheck.report["blockers"])[:500])
    refused = lifecycle._execute(change, actor=actor, confirmation=change.change_id, env=environment(), definition=DEFINITION)
    run.ev("GATE", "execution before approval ->", refused.outcome, ",".join(b["code"] for b in refused.blockers))
    assert refused.outcome == "BLOCKED" and base == digests()
    try:
        lifecycle.approve(change, actor=actor, confirmation=change.change_id, acknowledgements={}, definition=DEFINITION)
        raise RuntimeError("approval without acknowledgements was accepted")
    except lifecycle.LifecycleError as exc:
        run.ev("GATE", "approval without acknowledgements ->", ",".join(b["code"] for b in exc.blockers))
    lifecycle.approve(change, actor=actor, confirmation=change.change_id, acknowledgements={name: True for name, _ in lifecycle.ACKNOWLEDGEMENTS},
                      definition=DEFINITION)
    change.refresh_from_db()
    run.ev("LIFECYCLE", "approved", change.lifecycle_state)
    try:
        service = lifecycle.execute(change, actor=actor, confirmation=change.change_id, env=environment())
        run.ev("GATE", "service entry point execute() ->", service.outcome, ",".join(b["code"] for b in service.blockers))
    except lifecycle.LifecycleError as exc:                      # the sandbox definition is not the production one: refused even earlier
        run.ev("GATE", "service entry point execute() ->", "REFUSED", ",".join(b["code"] for b in exc.blockers))
    assert base == digests()
    run.ev("LIFECYCLE", "execute", "begin", "load", *mig.load())
    result = lifecycle._execute(change, actor=actor, confirmation=change.change_id, env=environment(), definition=DEFINITION)   # ungated: sandbox only
    change.refresh_from_db()
    report = result.run.report
    end = digests()
    run.ev("LIFECYCLE", "execute", result.outcome, "lifecycle=%s" % change.lifecycle_state, "probes_lost=%s" % report["probes"]["lost"],
           "applied=%d" % len(report["state"]["applied"]), "compensated=%d" % len(report["state"]["compensated"]),
           "temporary_remaining=%s" % json.dumps(report["temporary_state"]["remaining"]), "restored=%s" % report["restored"])
    end_startup, end_boot = startup_digests(), boot_digests()
    in_sync = all(row["startup"] == row["running"] for row in end_startup.values())
    run.ev("CONFIG end", json.dumps(end), "baseline-restored=%s" % (end == base), "covers", json.dumps(cover_routes()))
    run.ev("STARTUP end", json.dumps(end_startup), "startup-equals-running=%s" % in_sync, "startup-unchanged=%s" % (end_startup == start_startup),
           "core-boot-unchanged=%s" % (end_boot == start_boot), "persistence=%s" % json.dumps(report.get("persistence", {}).get("status")))
    dump("persistence", {"report": report.get("persistence"), "startup_start": start_startup, "startup_end": end_startup,
                         "core_boot_start": start_boot, "core_boot_end": end_boot})
    dump("run", execution_service.serialize_run(result.run))
    dump("validation", {"status": validation.status, "input_hash": validation.input_hash, "report": validation.report})
    dump("plan", {"plan_hash": plan.plan_hash, "summary": plan.summary, "configlets": [
        {"cfg_id": c.cfg_id, "device": c.target_device, "description": c.description, "operation": c.operation_type, "origin": c.origin,
         "rendered_config": c.rendered_config, "rollback_config": c.rollback_config, "transition": c.metadata.get("transition"),
         "verification": c.verification_spec, "execution_status": c.execution_status} for c in plan.configlets.order_by("sequence")]})
    dump("precheck", {"status": precheck.status, "report": precheck.report})
    dump("audit", [{"type": e.event_type, "summary": e.summary, "actor": e.actor} for e in models.AuditEvent.objects.filter(change=change).order_by("id")])
    dump("lifecycle", [{"from": e.from_state, "to": e.to_state, "reason": e.reason, "metadata": e.metadata} for e in change.lifecycle_events.order_by("id")])
    dump("results", [{"cfg_id": r.cfg_id, "device": r.device, "phase": r.phase, "status": r.status, "error": r.error_code, "detail": r.detail}
                     for r in result.run.results.order_by("phase", "sequence")])
    clean = not report["temporary_state"]["remaining"] and cover_routes() == {"c3": 0, "c4": 0} and report["probes"]["lost"] == 0 \
        and in_sync and end_boot == start_boot
    if mode == "forward":
        ok = clean and result.outcome == "SUCCEEDED" and change.lifecycle_state == "DEPLOYED" and report["persistence"]["status"] == "VERIFIED" \
            and end_startup != start_startup
    elif mode == "revert":
        premigration = {name: row["config"] for name, row in basis["premigration"].items() if name in end_startup}
        ok = clean and result.outcome == "SUCCEEDED" and report["persistence"]["status"] == "VERIFIED" \
            and {name: row["running"] for name, row in end_startup.items()} == premigration \
            and {name: row["startup"] for name, row in end_startup.items()} == premigration
        run.ev("REVERT", "running-and-startup-equal-pre-migration-baseline=%s" % ok)
    else:
        ok = clean and result.outcome == "FAILED_ROLLED_BACK" and report["restored"] is True and end == base and end_startup == start_startup
    if mode == "window":
        run.ev("WINDOW", "failure", json.dumps(report.get("failure")), "host samples", WINDOW["samples"],
               "window notes", json.dumps([[e["status"], e.get("before")] for e in report.get("stages", []) if e.get("stage") == "window"]))
        ok = ok and report["failure"]["code"] == gates.WINDOW_CONDITION_LOST and WINDOW["samples"] == 3
    if not ok:
        raise RuntimeError(f"{mode}: outcome {result.outcome}; failure {json.dumps(report.get('failure'))[:400]}")
except Exception as exc:
    failed = exc
    run.ev("FAILED", type(exc).__name__, str(exc)[:700])
time.sleep(5)
PROBES.stop()
flows = PROBES.report()
dump("probes", flows)
run.ev("PROBES", "answered=%d" % sum(f["answered"] for f in flows), "lost=%d" % sum(f["lost"] for f in flows), "errors=%s" % PROBES.errors[:3])
mig.sessions_stop(out)
mig.monitors(False, out)
run.ev("END", "failed" if failed else "ok", "load", *mig.load())
sys.exit(1 if failed else 0)
