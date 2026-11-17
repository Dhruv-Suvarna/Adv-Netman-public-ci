"""RB01 -- Link flapping.  Differentiates planned administrative down/maintenance from unstable physical behaviour (UT-046)."""

from __future__ import annotations

from datetime import timedelta

from .. import contracts as c
from .. import correlation as corr
from .base import CONTEXT, SAFETY, Ctx, Finding, Hypothesis, Result, Runbook, TestSpec, fault, inconclusive, not_applicable, ok

FLAP_THRESHOLD = 3          # transitions inside the window that make an interface "unstable"
ERR_BURST = 0.5


def _t(ctx):
    t = ctx.case["target"]
    return t["device"], t["interface"]


def _peer(ctx):
    dev, ifn = _t(ctx)
    ln = corr.find_link(ctx.intent.get("links", []), dev, ifn)
    if ln is None:
        return None, None
    return (ln["b"], ln.get("b_if")) if ln["a"] == dev and ln.get("a_if") == ifn else (ln["a"], ln.get("a_if"))


def _events(ctx, dev, ifn):
    o = ctx.need("interface.link_event", dev, ifn)
    ev = sorted(o.value.get("events", []), key=lambda e: e["at"])
    start = ctx.now - timedelta(seconds=o.value.get("window_s", 3600))
    return o, [e for e in ev if (c.parse_time(e["at"]) or ctx.now) >= start]


def lf01(ctx: Ctx) -> Result:
    dev, ifn = _t(ctx)
    o, ev = _events(ctx, dev, ifn)
    downs = [e for e in ev if e["state"] == "down"]
    base = ctx.baselines.get("history", {}).get("stats", {}).get(f"interface.link_transitions_per_h@{dev}@{ifn}", {})
    normal = base.get("median") if base.get("state") == "LEARNED" else None
    ctx.use_intent("history")
    obs = {"transitions": len(ev), "downs": len(downs), "window_s": o.value.get("window_s", 3600), "baseline_per_h": normal,
           "events": [(e["at"], e["state"], e.get("reason", "")) for e in ev][:20]}
    if len(downs) >= FLAP_THRESHOLD and (normal is None or len(downs) > 3 * max(normal, 0.5)):
        return fault(f"{dev}:{ifn} went down {len(downs)}x in {obs['window_s']//60} min (normal {normal if normal is not None else 'unknown'}/h)",
                     Finding("F-flap", f"{dev}:{ifn} is flapping", "L1", dev, "H-phy", False, 0.7, "determine planned vs unplanned (LF02) and physical cause (LF03-LF05) before any action"),
                     "instability is established; cause is not yet", **obs)
    return ok(f"{len(downs)} down transition(s) in the window (< {FLAP_THRESHOLD}); interface stable", "no flapping now", **obs)


def lf02(ctx: Ctx) -> Result:
    dev, ifn = _t(ctx)
    _, ev = _events(ctx, dev, ifn)
    admin = [e for e in ev if e["state"] == "down" and e.get("reason", "").startswith("admin")]
    m = ctx.opt("maintenance.state", dev)
    in_m = bool(m and m.value.get("in_maintenance"))
    planned = [r["change_id"] for r in ctx.correlation.get("changes", []) if dev in (r.get("devices") or []) and r.get("authorized", r.get("approved")) and r["relation"] == "BEFORE_ONSET"]
    ctx.use_intent("changes")
    downs = [e for e in ev if e["state"] == "down"]
    if downs and len(admin) == len(downs) and (in_m or planned):
        return fault(f"all {len(downs)} down events are administrative ({admin[0].get('reason')}), {'device in maintenance' if in_m else 'approved change ' + ','.join(planned)}",
                     Finding("F-planned", "Transitions are a planned administrative/maintenance action", "ops", dev, "H-admin", True, 0.9, "no remediation; verify the planned work ends and the link stays up"),
                     "expected behaviour: do not treat as a physical fault", admin_events=len(admin), maintenance=in_m, changes=planned)
    if admin and len(admin) < len(downs):
        return inconclusive(f"{len(admin)} of {len(downs)} down events are administrative; the rest are not explained by operator action", "mixed causes", admin=len(admin), total=len(downs))
    return ok("down events are not administrative and no maintenance/approved change covers them" if downs else "no down events", "planned work does not explain the transitions", admin=len(admin))


def lf03(ctx: Ctx) -> Result:
    dev, ifn = _t(ctx)
    pdev, pif = _peer(ctx)
    probs = []
    for d, i in ((dev, ifn), (pdev, pif)):
        if not d:
            continue
        t = ctx.opt("interface.transceiver", d, i)
        if t is None:
            continue
        v = t.value
        if v.get("supported") is False:
            probs.append(f"{d}:{i} unsupported transceiver {v.get('part', '')}")
        if v.get("rx_dbm") is not None and v.get("rx_low_alarm") is not None and v["rx_dbm"] < v["rx_low_alarm"] + 1.0:
            probs.append(f"{d}:{i} Rx {v['rx_dbm']} dBm near/below low alarm {v['rx_low_alarm']} dBm")
    sp = [ctx.opt("interface.speed", d, i) for d, i in ((dev, ifn), (pdev, pif)) if d]
    if len(sp) == 2 and all(sp) and sp[0].value != sp[1].value:
        probs.append(f"speed mismatch {sp[0].value} vs {sp[1].value}")
    if not ctx.used:
        ctx.need("interface.transceiver", dev, ifn)
    if probs:
        return fault("; ".join(probs), Finding("F-optics", "Optics/PHY degradation or incompatibility on the flapping link", "L1", dev, "H-phy", True, 0.8,
                     "replace/clean optic or cable (external physical work); no port bounce"), problems=probs)
    return ok("transceivers supported, Rx power margin sufficient, speed agrees on both ends", "optics/PHY not implicated")


def lf04(ctx: Ctx) -> Result:
    dev, ifn = _t(ctx)
    rst = ctx.opt("interface.counter_reset", dev, ifn)
    if rst is not None and rst.value.get("reset"):
        return inconclusive(f"counters on {dev}:{ifn} were reset at {rst.value.get('at')}; error rates before/after cannot be compared", "error trend invalid, not healthy")
    o = ctx.need("interface.rate.in_crc_errors", dev, ifn)
    s = ctx.opt("interface.error_samples", dev, ifn)
    bursts = [x for x in (s.value.get("samples", []) if s else []) if x["rate"] > ERR_BURST]
    _, ev = _events(ctx, dev, ifn)
    downs = [c.parse_time(e["at"]) for e in ev if e["state"] == "down"]
    near = [b for b in bursts if any(abs((c.parse_time(b["at"]) - d).total_seconds()) <= 120 for d in downs)]
    if o.value > ERR_BURST or near:
        return fault(f"CRC/FCS {o.value}/s; {len(near)} error burst(s) within 120 s of a down transition", Finding("F-crc", "Error bursts coincide with the link drops", "L1", dev, "H-phy", False, 0.75,
                     "pair with LF03/LF05 for the physical cause"), "temporal coincidence supports a physical-signal cause", rate=o.value, bursts_near_transitions=len(near))
    return ok(f"CRC/FCS rate {o.value}/s, no bursts near transitions", "errors do not accompany the drops", rate=o.value)


def lf05(ctx: Ctx) -> Result:
    dev, ifn = _t(ctx)
    pdev, pif = _peer(ctx)
    if not pdev:
        return not_applicable("interface has no peer in NetBox intent")
    _, mine = _events(ctx, dev, ifn)
    _, theirs = _events(ctx, pdev, pif)
    m_d, t_d = sum(e["state"] == "down" for e in mine), sum(e["state"] == "down" for e in theirs)
    if m_d >= FLAP_THRESHOLD and t_d >= FLAP_THRESHOLD:
        return fault(f"both ends saw the drops ({dev}:{m_d}, {pdev}:{t_d})", Finding("F-medium", "Both ends lose the link: the physical medium (optic/cable/patch) is implicated", "L1", dev, "H-phy", True, 0.8,
                     "swap optic/cable on one end at a time (operator work); keep the alternate path in mind"), "two-sided corroboration", local=m_d, peer=t_d)
    if m_d >= FLAP_THRESHOLD and t_d == 0:
        return fault(f"only {dev} sees drops ({m_d}); {pdev} sees none", Finding("F-onesided", "One-sided flap: local port/optic or local software fault", "L1", dev, "H-phy", False, 0.5), local=m_d, peer=t_d)
    return ok("neither end shows sustained flapping", "no two-sided evidence", local=m_d, peer=t_d)


def lf06_applies(ctx: Ctx):
    dev, ifn = _t(ctx)
    return (bool(ctx.intent.get("lag", {}).get(f"{dev}:{ifn}")), "interface is not a LAG member in the NetBox intent")


def lf06(ctx: Ctx) -> Result:
    dev, ifn = _t(ctx)
    lag = ctx.intent["lag"][f"{dev}:{ifn}"]
    o = ctx.need("lacp.member", dev, ifn)
    if o.value.get("state") != "bundled" or o.value.get("churn_1h", 0) >= 3:
        return fault(f"LACP member {o.value.get('state')}, churn {o.value.get('churn_1h')}/h in {lag}", Finding("F-lacp", "LACP member churn", "L2", dev, "H-lag", True, 0.7), **o.value)
    return ok(f"LACP member bundled in {lag}, stable", "bundle membership not implicated", **o.value)


def lf07(ctx: Ctx) -> Result:
    dev, ifn = _t(ctx)
    o = ctx.need("interface.errdisable", dev, ifn)
    if o.value.get("reason"):
        return fault(f"errdisable/port-security/link-flap protection active: {o.value['reason']}", Finding("F-errdisable", f"Port protection ({o.value['reason']}) toggles the port", "L2", dev, "H-admin", True, 0.8,
                     "tune/clear only through an approved change"), **o.value)
    return ok("no errdisable, port-security or link-flap-detection event", "port protection not implicated")


def lf08(ctx: Ctx) -> Result:
    dev, _ = _t(ctx)
    o = ctx.need("syslog.system_events", dev)
    hits = [e for e in o.value.get("events", []) if e.get("kind") in ("POWER", "CONTROLLER", "LINECARD", "THERMAL")]
    if hits:
        return fault(f"{len(hits)} power/controller/thermal event(s): {hits[0].get('text', '')}", Finding("F-system", "System-level event coincides with the flap", "system", dev, "H-sys", False, 0.6), events=hits[:5])
    return ok("no power/controller/linecard/thermal events in the window", "platform health not implicated", checked=len(o.value.get("events", [])))


def lf09(ctx: Ctx) -> Result:
    dev, ifn = _t(ctx)
    ctx.use_intent("intent")
    link = corr.find_link(ctx.intent.get("links", []), dev, ifn)
    alts = corr.intended_paths([l for l in ctx.intent["links"] if l is not link], link["a"], link["b"], limit=2) if link else []
    fh = ctx.opt("flow.health", dev, ctx.flow.get("name", "svc")) if ctx.flow else None
    if fh is None and not alts:
        return inconclusive("flow health not collected and no alternate path in intent", "impact unknown")
    return ok(f"alternate intended path {'/'.join(h['device'] for h in alts[0])} exists" if alts else "no alternate intended path: do not drain/bounce",
              "an existing alternate may contain impact; not proven lossless, and no redundancy is invented",
              alternate_exists=bool(alts), lossless_proven=False, flow=fh.value if fh else None)


RB01 = Runbook(
    id="RB01", name="link-flapping", version="1.0.0", title="Link flapping", doc="RB01-link-flapping.md", test_prefixes=("LF",),
    purpose="Establish whether an interface is unstable, why (planned action vs physical/protection/system cause), and what a safe response is.",
    tests=(
        TestSpec("LF01", "Transition history and rate vs baseline", "L1", "H-phy", "fewer than 3 down transitions per window; at baseline", lf01, command="interface.link_event", cls=CONTEXT, condition="interface is flapping", sources=("interface.link_event", "history")),
        TestSpec("LF02", "Administrative shutdown / planned maintenance", "CTRL", "H-admin", "no administrative cause", lf02, command="interface.link_event+maintenance.state", cls=CONTEXT, after=("LF01",), condition="transitions are planned", sources=("interface.link_event", "maintenance.state", "changes")),
        TestSpec("LF03", "Optics DOM, transceiver support, speed/autoneg (both ends)", "L1", "H-phy", "optics healthy and compatible", lf03, command="interface.transceiver", condition="optics/PHY degradation", sources=("interface.transceiver", "interface.speed")),
        TestSpec("LF04", "Error bursts vs transitions (CRC/FCS), counter-reset aware", "L1", "H-phy", "no bursts near drops", lf04, command="interface.rate.in_crc_errors", condition="signal errors precede drops", sources=("interface.rate.in_crc_errors", "interface.counter_reset")),
        TestSpec("LF05", "Peer-side interface health (both ends)", "L1", "H-phy", "peer shows no matching drops", lf05, command="interface.link_event(peer)", condition="two-sided medium fault", sources=("interface.link_event",)),
        TestSpec("LF06", "LACP / port-channel member churn", "L2", "H-lag", "member bundled and stable", lf06, applies=lf06_applies, command="lacp.member", condition="LACP churn", sources=("lacp.member",)),
        TestSpec("LF07", "Port security, errdisable, link-flap detection", "L2", "H-admin", "no protection event", lf07, command="interface.errdisable", condition="port protection toggles the port", sources=("interface.errdisable",)),
        TestSpec("LF08", "Power, controller, system logs", "CTRL", "H-sys", "no platform event", lf08, command="syslog.system_events", condition="platform event", sources=("syslog.system_events",)),
        TestSpec("LF09", "Topology/path change, service impact, existing alternate (read-only)", "CTRL", "H-impact", "alternate evaluated, never assumed lossless", lf09, command="intent+flow.health", cls=SAFETY, condition="impact containment candidates", sources=("intent", "flow.health")),
    ),
    hypotheses=(
        Hypothesis("H-phy", "Physical-layer cause: optics, cable, signal errors, medium", "L1", ("LF01", "LF03", "LF04", "LF05"), 1),
        Hypothesis("H-admin", "Planned administrative action, maintenance or port protection", "ops", ("LF02", "LF07"), 1),
        Hypothesis("H-lag", "LACP/port-channel member churn", "L2", ("LF06",), 3),
        Hypothesis("H-sys", "Power/controller/system event", "system", ("LF08",), 4),
        Hypothesis("H-impact", "Service impact and containment options", "ctrl", ("LF09",), 9),
    ),
    orders={"bottom-up": ("LF01", "LF02", "LF07", "LF03", "LF04", "LF05", "LF06", "LF08", "LF09"),
            "divide-and-conquer": ("LF01", "LF02", "LF05", "LF03", "LF04", "LF07", "LF06", "LF08", "LF09")},
    select_strategy=lambda ctx: (("divide-and-conquer", "both ends of the link are observable: compare local and peer first to split local vs medium causes") if _peer(ctx)[0] and ctx.view.latest("interface.link_event", *_peer(ctx)) else
                                  ("bottom-up", "peer side not observable: climb from the physical layer on the local end")),
    remediations={
        "F-optics": {"tier": 2, "action": "replace or clean transceiver/cable (physical, external work)", "approvals": ["operator acknowledgement of physical intervention", "maintenance window"],
                     "pre_tests": ["LF03", "LF05", "LF09"], "post_tests": ["LF01", "LF04"], "rollback": "restore original optic/cable", "never": ["blind shut/no shut", "counter clear to hide errors"]},
        "F-medium": {"tier": 2, "action": "swap optic/cable one end at a time", "approvals": ["operator acknowledgement", "alternate path proof from LF09"], "pre_tests": ["LF05", "LF09"], "post_tests": ["LF01", "LF05"],
                     "rollback": "reinstall original", "never": ["blind port bounce"]},
        "F-errdisable": {"tier": 2, "action": "correct the policy or port-protection setting", "approvals": ["change approval"], "pre_tests": ["LF07"], "post_tests": ["LF01"], "rollback": "restore previous setting", "never": []},
        "F-planned": {"tier": 1, "action": "none: expected behaviour; keep observing until the planned work ends", "approvals": [], "pre_tests": ["LF02"], "post_tests": ["LF01"], "rollback": "n/a", "never": ["reverting the planned change"]},
    },
)
