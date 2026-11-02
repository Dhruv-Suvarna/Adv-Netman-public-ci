#!/usr/bin/env python3
"""The NMAS route-shield workflow against the DISPOSABLE isisbx sandbox, end to end, with no production authority involved:

    intent (lab.* transition, sandbox cabling) -> validation (model) -> plan (Configlet specs) -> precheck (gates, live read)
    -> execution (the production CeosExecutor over ``docker exec``) -> read-back -> postcheck (health evaluators)
    -> compensation -> restore

No NetBox, no inventory, no production database: Django runs on scratch settings and every device is a labelled sandbox
container handed to the executor directly.

usage: nmas_pipeline.py <outdir> migrate <cycles> | to-isis | to-static | abort | drain <cycles>
       (run from the worktree's web/ directory, DJANGO_SETTINGS_MODULE=scratch_settings)
"""
import dataclasses, json, os, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mig                                                      # sandbox plumbing only: traffic, events, the additive IS-IS stages

import django
django.setup()
from core.services.capabilities.isolated_live import DockerEosConfigConnection
from core.services.execution.executors.ceos import CeosExecutor
from core.services.health import live
from core.services.route_shield import gates, lab, runner

out, mode = sys.argv[1], sys.argv[2]
count = int(sys.argv[3]) if len(sys.argv) > 3 else 1
mig.guard()
run = mig.Run(out)
DEVICES = {name: {"name": name, "platform": "ceos", "container": f"{mig.P}-{name.lower()}"} for name in ("R1", "R2", "S1", "S2")}
ROUTERS = {name: dataclasses.replace(r, access_interface="Ethernet3", upstream=("c3", "c4")) for name, r in lab.ROUTERS.items()}     # sandbox cabling
EXEC = {}
for name, device in DEVICES.items():
    EXEC[name] = CeosExecutor(device, connection_factory=DockerEosConfigConnection, reader=live.read_device)
    EXEC[name].connect()


class Probes:
    """Production transit probes of the sandbox hosts.  A probe counts as lost once it is 3 s old and still unanswered."""
    AWK = r"""awk -v step=%s 'match($0,/seq=[0-9]+/){s=substr($0,RSTART+4,RLENGTH-4)+0; if(n==0||s<lo)lo=s; if(s>hi)hi=s; seen[s]=1; n++}
              END{hold=int(3/step); for(s=lo;s<=hi-hold;s++) if(!(s in seen)) lost++; print lost+0, n+0}' %s"""
    extra = 0                                                   # the abort demonstration injects one lost probe here

    def _count(self):
        lost = answered = 0
        for h, (v4, v6) in mig.HOSTS.items():
            files = [("/tmp/t/p6.log", mig.I6)] + ([("/tmp/t/p4.log", mig.I4)] if v4 else [])
            for path, step in files:
                a, b = mig.hx(h, self.AWK % (step, path)).split()
                lost, answered = lost + int(a), answered + int(b)
        for h, (v4, v6) in mig.HOSTS.items():
            for path, step in [(f"/tmp/t/p6_{h}.log", mig.I6R)] + ([(f"/tmp/t/p4_{h}.log", mig.I4)] if v4 else []):
                a, b = mig.hx("web", self.AWK % (step, path)).split()
                lost, answered = lost + int(a), answered + int(b)
        return lost, answered

    def healthy(self):
        lost, answered = self._count()
        return lost == 0 and answered > 500, {"lost": lost, "answered": answered}

    def lost(self):
        return self._count()[0] + self.extra


def alive(device, address):
    return "2 received" in mig.kern(device.lower(), "ping", "-6", "-c", "2", "-i", "0.2", "-W", "1", address)


def isis_holds(transition):
    return all(prefix in mig.cli(transition.device.lower(), "show isis database detail") for prefix in transition.protected)


def resolved(device, transition):
    try:
        mig.takeover_ready(run, device.lower(), f"NMAS-{transition.key}", list(transition.protected))
        return True
    except RuntimeError as exc:
        run.ev("NMAS", "takeover-unresolved", str(exc)[:200])
        return False


PROBES = Probes()


def environment():
    return runner.Environment(
        executors=EXEC, read=lambda name: live.read_device(DEVICES[name]), probes=PROBES,
        host_gate=lambda: gates.default_host_gate(max_load_per_cpu=8.0),            # the sandbox host itself runs ~4 per CPU
        next_hop_alive=alive, new_route_available=isis_holds, resolve_takeover=resolved,
        peer_forwards_onward=lambda t: (mig.route(t.via_peer.lower(), mig.AGG) or ("", []))[0:2] == ("isisL2", ["Ethernet1"]),
        upstream_covered=lambda t: all(mig.kern(c, "ip", "-6", "route", "show", p).count("nexthop via") == 2          # read on the cores
                                       for c in t.upstream for p in t.shield_prefixes),
        baseline_digests={name: executor.config_state_digest() for name, executor in EXEC.items()}, poll_seconds=2.0)


def nmas(transition, expect_ok=True):
    """One transition through the workflow.  The plan's baseline digest is taken now: validation -> plan -> precheck -> ..."""
    run.ev("NMAS", "plan", transition.key, transition.shield_kind, "specs=" + ",".join(s.cfg_id.rsplit("-", 2)[-1] for s in
                                                                                     (transition.install_spec(), *transition.step_specs(), transition.remove_spec())))
    result = runner._execute(transition, environment())             # the ungated entry: sandbox only (execute() refuses, see below)
    stages = [(s["stage"], s["status"]) for s in result.stages]
    run.ev("NMAS", "result", transition.key, "ok=%s" % result.ok, "aborted=%s" % (result.aborted or "-"), "restored=%s" % result.restored,
           "lost=%s" % PROBES.lost(), json.dumps(stages))
    json.dump({"transition": transition.key, "ok": result.ok, "aborted": result.aborted, "blockers": result.blockers, "restored": result.restored,
               "stages": result.stages, "compensation": result.compensation}, open(f"{out}/{int(time.time())}-{transition.key}.json", "w"), indent=1, default=str)
    if result.ok != expect_ok:
        raise RuntimeError(f"{transition.key}: ok={result.ok} aborted={result.aborted} {result.blockers[:2]}")
    return result


def prepare(t):
    """The additive stages 1-4 (VLAN99 IPv6, IS-IS, adjacencies, advertisement): nothing is replaced, no shield is involved."""
    mig.SIDES_SAVED = mig.SIDES
    mig.SIDES = ()                                              # forward() then stops after stage 4's availability check
    try:
        mig.forward(run, f"P{t}")
    finally:
        mig.SIDES = mig.SIDES_SAVED
    mig.wait("IS-IS holds every protected prefix",
             lambda: all(isis_holds(x) for side in ("S1", "S2") for x in lab.baseline_migration(side, routers=ROUTERS)) or "not yet", 120, 2)
    time.sleep(3)


def withdraw(t):
    mig.SIDES_SAVED = mig.SIDES
    mig.SIDES = ()
    try:
        mig.rollback(run, f"W{t}")
    finally:
        mig.SIDES = mig.SIDES_SAVED


def digests():
    return {dev: mig.digest(mig.running(dev)) for dev in ("r1", "r2", "s1", "s2")}


run.ev("START nmas-pipeline", mode, count, "load", *mig.load())
refused = runner.execute(lab.switch_to_isis(lab.SWITCHES["S1"]), environment())
run.ev("NMAS", "service-gate", "execute() ->", refused.aborted, "sent-nothing")          # the service entry point refuses everything
assert not refused.ok and refused.aborted.startswith("TRANSITION_"), refused
base = digests()
run.ev("CONFIG start", json.dumps(base))
mig.monitors(True)
mig.sessions_start()
time.sleep(3)
failed = None
try:
    for c in range(1, count + 1):
        mig.pings_start(diag=False)
        time.sleep(6)
        run.ev(f"C{c}", "begin", "load", *mig.load())
        if mode in ("migrate", "to-isis"):
            mig.core_cover_on(run, f"F{c}")
            prepare(c)
            for side in ("S1", "S2"):
                for transition in lab.baseline_migration(side, routers=ROUTERS):
                    nmas(transition)
            mig.core_cover_off(run, f"F{c}")
            run.ev(f"F{c}", "nmas-forward-complete", json.dumps(digests()))
        if mode == "migrate":                                   # fresh probe logs for the rollback half: sequence numbers must not wrap
            time.sleep(5)
            mig.pings_stop(f"{out}/c{2 * c - 1:02d}")
            mig.pings_start(diag=False)
            time.sleep(6)
        if mode in ("migrate", "to-static"):
            mig.core_cover_on(run, f"B{c}")
            for side in ("S2", "S1"):
                for transition in lab.baseline_rollback(side, routers=ROUTERS):
                    nmas(transition)
            withdraw(c)
            mig.core_cover_off(run, f"B{c}")
            run.ev(f"B{c}", "baseline-restored", digests() == base if mode == "migrate" else "n/a", json.dumps(digests()))
            if mode == "migrate" and digests() != base:
                raise RuntimeError("rollback did not restore the baseline configuration")
        elif mode == "abort":
            # compensation and restore on real cEOS: one production probe is reported lost right after the statics are removed
            uncovered = nmas(lab.router_to_isis(ROUTERS["R1"]), expect_ok=False)            # no core cover yet: refused, nothing sent
            run.ev("GATE", "router transition without core covers ->", ",".join(b["code"] for b in uncovered.blockers), "applied=%d" % len(uncovered.applied))
            assert gates.UPSTREAM_COVER_UNCONFIRMED in [b["code"] for b in uncovered.blockers] and not uncovered.applied
            mig.core_cover_on(run, f"A{c}")
            prepare(c)
            nmas(lab.switch_to_isis(lab.SWITCHES["S1"]))
            before = digests()
            real = PROBES.lost

            def tripwire():
                PROBES.extra = 1 if "isisL2" in str(mig.route("r1", mig.CLIENTS[0])) else 0
                return real()
            PROBES.lost = tripwire
            result = nmas(lab.router_to_isis(ROUTERS["R1"]), expect_ok=False)
            PROBES.lost, PROBES.extra = real, 0
            run.ev("ABORT", "aborted=%s" % result.aborted, "restored=%s" % result.restored, "config-restored=%s" % (digests() == before),
                   "owner=%s" % (mig.route("r1", mig.CLIENTS[0]) or ("none",))[0], json.dumps(result.compensation))
            if not result.restored or digests() != before or result.aborted != gates.PACKET_LOSS:
                raise RuntimeError("abort did not restore the last verified state")
            nmas(lab.switch_to_static(lab.SWITCHES["S1"]))
            withdraw(c)
            mig.core_cover_off(run, f"A{c}")
            run.ev(f"B{c}", "baseline-restored", digests() == base)
        elif mode == "drain":
            for name in ("S1", "S2"):
                nmas(lab.steer(lab.SWITCHES[name], drain=True))
                run.ev(f"D{c}-{name}-drain", "verified", name, mig.route(name.lower(), mig.AGG))
                time.sleep(4)
                nmas(lab.steer(lab.SWITCHES[name], drain=False))
                run.ev(f"D{c}-{name}-restore", "verified", name, mig.route(name.lower(), mig.AGG))
                time.sleep(4)
            if digests() != base:
                raise RuntimeError("drain and restore did not return to the starting configuration")
        time.sleep(5)
        run.ev(f"C{c}", "end", "load", *mig.load())
        mig.pings_stop(f"{out}/c{2 * c:02d}")
except Exception as exc:
    failed = exc
    run.ev("FAILED", type(exc).__name__, str(exc)[:600])
    try:
        mig.pings_stop(f"{out}/failed")
    except Exception:
        pass
mig.sessions_stop(out)
mig.monitors(False, out)
run.ev("END", "failed" if failed else "ok", "load", *mig.load())
sys.exit(1 if failed else 0)
