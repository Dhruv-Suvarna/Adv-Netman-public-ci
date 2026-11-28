"""RB04 -- STP loops and topology changes.  STP-free (EVPN-VXLAN) domains are excluded and never "fixed" with spanning tree (UT-049)."""

from __future__ import annotations

from .. import correlation as corr
from .base import CONTEXT, Ctx, Finding, Hypothesis, Result, Runbook, TestSpec, fault, inconclusive, not_applicable, ok

TCN_PER_HOUR = 5


def _dom(ctx):
    return ctx.case["target"]["devices"], str(ctx.case["target"].get("vlan", ""))


def _mode(ctx, dev):
    return ctx.intent.get("l2", {}).get("stp", {}).get(dev, "unknown")


def _stp_devs(ctx):
    return [d for d in _dom(ctx)[0] if _mode(ctx, d) not in ("none", "evpn-vxlan", "unknown")]


def st_applies(ctx: Ctx):
    devs = _dom(ctx)[0]
    if all(_mode(ctx, d) in ("none", "evpn-vxlan") for d in devs):
        return False, "domain is STP-free (EVPN-VXLAN/none per NetBox intent); spanning-tree tests and remediation are excluded"
    return True, ""


def st01(ctx: Ctx) -> Result:
    devs, _ = _dom(ctx)
    modes = {d: _mode(ctx, d) for d in devs}
    ctx.use_intent("intent")
    if all(m in ("none", "evpn-vxlan") for m in modes.values()):
        return not_applicable(f"domain {modes} is STP-free (EVPN-VXLAN); loops are prevented by the overlay, not by STP -- run ST10 instead")
    if any(m == "unknown" for m in modes.values()):
        return inconclusive(f"STP mode of {[d for d, m in modes.items() if m == 'unknown']} is not in NetBox intent", "domain type unknown")
    mixed = len(set(modes.values())) > 1
    return ok(f"STP domain: {modes}" + ("; MIXED modes interoperate via compatibility, check ST05" if mixed else ""), "domain eligible for STP tests", modes=modes)


def st02(ctx: Ctx) -> Result:
    _, vlan = _dom(ctx)
    roots, chg = {}, {}
    for d in _stp_devs(ctx):
        o = ctx.need("stp.state", d, vlan)
        roots[d], chg[d] = o.value["root_id"], o.value.get("root_changes_24h", 0)
    want = ctx.intent.get("l2", {}).get("stp_root", {}).get(vlan)
    probs = []
    if len(set(roots.values())) > 1:
        probs.append(f"switches disagree on the root bridge: {roots}")
    if want and set(roots.values()) != {want}:
        probs.append(f"root is {set(roots.values())}, intent says {want}")
    if any(chg.values()):
        probs.append(f"root changed in the last 24 h: {chg}")
    if probs:
        return fault("; ".join(probs), Finding("F-root", "Root bridge changed or inconsistent", "L2", hypothesis="H-root", causal=False, confidence=0.7, remediation_hint="restore root priority via approved change; never during an active loop"), roots=roots, root_changes=chg)
    return ok(f"single stable root {next(iter(roots.values()))} on {len(roots)} switches", "root placement as intended", roots=roots)


def st03(ctx: Ctx) -> Result:
    _, vlan = _dom(ctx)
    tot, per = 0, {}
    for d in _stp_devs(ctx):
        o = ctx.need("stp.state", d, vlan)
        per[d] = {"tcn_1h": o.value.get("tcn_count_1h", 0), "last_tc_port": o.value.get("last_tc_port")}
        tot += per[d]["tcn_1h"]
    base = ctx.baselines.get("history", {}).get("stats", {}).get(f"stp.tcn_per_h@{vlan}", {})
    normal = base.get("median") if base.get("state") == "LEARNED" else None
    ctx.use_intent("history")
    if max(v["tcn_1h"] for v in per.values()) > TCN_PER_HOUR:
        src = max(per, key=lambda d: per[d]["tcn_1h"])
        return fault(f"TCN spike: {per} (normal {normal if normal is not None else 'unknown'}/h); origin port {per[src]['last_tc_port']} on {src}", Finding("F-tcn", "Topology-change storm", "L2", src, "H-root", False, 0.75, "trace the TC origin port (flapping edge port, BPDU source)"), per_switch=per)
    return ok(f"TCN counts {per} within normal", "topology stable", per_switch=per)


def st04(ctx: Ctx) -> Result:
    devs, vlan = _dom(ctx)
    links = [l for l in ctx.intent["links"] if l["a"] in devs and l["b"] in devs]
    g = corr.build_graph(links)
    nodes = [d for d in devs if d in g]
    cyclic = len(links) >= len(nodes)  # a connected graph with >= nodes edges has a cycle
    fwd_ports, blocked = {}, []
    for d in _stp_devs(ctx):
        for p in ctx.need("stp.state", d, vlan).value.get("ports", []):
            fwd_ports[(d, p["name"])] = p["state"]
            if p["state"] in ("blocking", "discarding"):
                blocked.append((d, p["name"]))
    cycle_edges_fwd = [l for l in links if fwd_ports.get((l["a"], l.get("a_if"))) == "forwarding" and fwd_ports.get((l["b"], l.get("b_if"))) == "forwarding"]
    if cyclic and not blocked and len(cycle_edges_fwd) == len(links) and links:
        return fault(f"physical cycle with {len(links)} links across {len(nodes)} switches and NO blocking/discarding port: all links forward", Finding("F-loop", "Layer-2 forwarding loop: STP is not blocking any link in a cyclic topology", "L2", hypothesis="H-loop", causal=True, confidence=0.9,
                     remediation_hint="restore a blocking port: find the BPDU-suppressing setting (ST06); containment needs approval"), "a redundant topology without a blocked port loops by construction", links=len(links), blocked=blocked)
    return ok(f"{len(blocked)} port(s) blocking in a {'cyclic' if cyclic else 'loop-free'} topology: {blocked}", "STP breaks the physical cycle", blocked=blocked)


def st05(ctx: Ctx) -> Result:
    _, _ = _dom(ctx)
    cfgs = {d: ctx.opt("stp.mst_config", d, "") for d in _stp_devs(ctx) if _mode(ctx, d) == "mst"}
    if not cfgs:
        return not_applicable("no MST switch in the domain; PVST/RSTP VLAN-to-instance consistency does not apply")
    digs = {d: (o.value["name"], o.value["revision"], o.value["digest"]) for d, o in cfgs.items() if o}
    if len(set(digs.values())) > 1:
        return fault(f"MST region configuration differs: {digs}", Finding("F-mst", "MST region mismatch splits the topology into regions", "L2", hypothesis="H-root", causal=True, confidence=0.85), digests=digs)
    return ok("MST name/revision/instance digest identical", "single region", digests=digs)


def st06(ctx: Ctx) -> Result:
    _, _ = _dom(ctx)
    bad, n = [], 0
    for d in _stp_devs(ctx):
        for o in ctx.each("stp.port_protection", d):
            n += 1
            v = o.value
            if v.get("bpdu_filter") and v.get("link_type") in ("trunk", "inter-switch"):
                bad.append(f"{d}:{o.subject} bpdu-filter on an inter-switch link (BPDUs neither sent nor processed; loop detection disabled)")
            if v.get("bpdu_rx_on_edge", 0) > 0 and not v.get("bpdu_guard"):
                bad.append(f"{d}:{o.subject} edge port receives BPDUs without BPDU guard")
            if v.get("loop_guard") is False and v.get("link_type") == "inter-switch" and v.get("unidirectional_suspect"):
                bad.append(f"{d}:{o.subject} loop-guard off on a unidirectional-suspect link")
    if not n:
        ctx.need("stp.port_protection", _stp_devs(ctx)[0], "")
    if bad:
        return fault("; ".join(bad), Finding("F-bpdu-filter", "BPDU filtering/guard configuration defeats loop prevention", "L2", hypothesis="H-guard", causal=True, confidence=0.9,
                     remediation_hint="remove the bpdu-filter (or add the missing guard) through an approved change; avoid root/port changes while the loop is live"), problems=bad)
    return ok(f"{n} port-protection settings appropriate (no filter on inter-switch links, guards present)", "BPDU path intact", checked=n)


def st07_applies(ctx: Ctx):
    return (bool(ctx.intent.get("lag")), "no port-channel in the NetBox intent for this domain")


def st07(ctx: Ctx) -> Result:
    bad = []
    for key in ctx.intent["lag"]:
        d, i = key.split(":")
        if d in _dom(ctx)[0]:
            o = ctx.need("lacp.member", d, i)
            if o.value.get("state") != "bundled" or o.value.get("partner_mismatch"):
                bad.append(f"{key} {o.value}")
    if bad:
        return fault("; ".join(bad), Finding("F-lacp-loop", "LACP inconsistency can create one-sided bundles/loops", "L2", hypothesis="H-guard", causal=False, confidence=0.6), problems=bad)
    return ok("all port-channel members bundled with matching partners", "LAG consistent")


def st08(ctx: Ctx) -> Result:
    devs, _ = _dom(ctx)
    links = [l for l in ctx.intent["links"] if l["a"] in devs and l["b"] in devs]
    obs = []
    for l in links:
        o = ctx.opt("lldp.neighbor", l["a"], l.get("a_if"))
        if o is not None:
            obs.append({"a": l["a"], "a_if": l["a_if"], "b": o.value["remote_device"], "b_if": o.value["remote_if"]})
    cmp = corr.compare_topology(links, obs) if obs else {}
    ctx.use_intent("intent")
    if cmp and (cmp["unexpected_in_observed"] or cmp["miscabled"]):
        return fault(f"unexpected L2 adjacency: {cmp['unexpected_in_observed']}", Finding("F-cabling-loop", "Unrecorded cabling creates an extra L2 path", "topology", hypothesis="H-loop", causal=True, confidence=0.85, remediation_hint="verify cabling; fix NetBox or remove the cable (physical work)"), **cmp)
    if not obs:
        return inconclusive("no LLDP evidence to compare the physical graph with NetBox", "cabling loops cannot be excluded")
    return ok(f"{len(obs)} observed adjacencies equal intent: no unrecorded cable", "cabling graph as designed", compared=len(obs))


def st09(ctx: Ctx) -> Result:
    devs, vlan = _dom(ctx)
    flap, storm, n = [], [], 0
    for d in devs:
        m = ctx.opt("mac.table", d, vlan)
        if m is not None:
            n += 1
            if m.value.get("moves_per_min", 0) > 10 or m.value.get("flapping_macs"):
                flap.append(f"{d}: {m.value.get('moves_per_min')} moves/min {m.value.get('flapping_macs')}")
        sc = ctx.opt("storm_control.state", d, "")
        if sc is not None and sc.value.get("broadcast_pps", 0) > sc.value.get("threshold_pps", 10 ** 9):
            storm.append(f"{d}: broadcast {sc.value['broadcast_pps']} pps > storm-control {sc.value['threshold_pps']}")
    if not n:
        ctx.need("mac.table", devs[0], vlan)
    if flap or storm:
        return fault("; ".join(flap + storm), Finding("F-storm", "MAC flapping/broadcast storm: loop symptom", "L2", hypothesis="H-loop", causal=False, confidence=0.8), "storm/MAC flaps are the symptom of a loop, not its cause", mac=flap, storm=storm)
    return ok(f"MAC tables stable and broadcast below storm-control on {n} switch(es)", "no storm indicators")


def st10_applies(ctx: Ctx):
    devs = _dom(ctx)[0]
    return (any(_mode(ctx, d) == "evpn-vxlan" for d in devs), "no EVPN-VXLAN device in the domain")


def st10(ctx: Ctx) -> Result:
    bad = []
    n = 0
    for d in [x for x in _dom(ctx)[0] if _mode(ctx, x) == "evpn-vxlan"]:
        o = ctx.need("evpn.state", d, "")
        n += 1
        if o.value.get("duplicate_mac_detected") or o.value.get("mac_mobility_events_1h", 0) > 20:
            bad.append(f"{d}: duplicate MAC {o.value.get('duplicate_mac_detected')}, mobility {o.value.get('mac_mobility_events_1h')}/h")
    if bad:
        return fault("; ".join(bad), Finding("F-evpn-dup", "EVPN MAC mobility/duplicate-MAC (overlay loop indicator)", "overlay", hypothesis="H-overlay", causal=False, confidence=0.7, remediation_hint="never enable STP in the overlay; fix the L2 attachment / duplicate MAC source"), problems=bad)
    return ok(f"EVPN MAC mobility normal on {n} VTEP(s); loop prevention is overlay-based", "STP-free domain healthy; no spanning-tree action permitted", checked=n)


RB04 = Runbook(
    id="RB04", name="stp-loops-topology-changes", version="1.0.0", title="STP loops and topology changes", doc="RB04-stp-loops.md", test_prefixes=("ST",),
    purpose="Detect and isolate spanning-tree instability or L2 loops, and exclude STP-free EVPN/VXLAN domains from STP actions.",
    tests=(
        TestSpec("ST01", "STP domain eligibility (excludes STP-free EVPN domains)", "L2", "H-domain", "domain runs spanning tree", st01, cls=CONTEXT, command="intent.l2.stp", condition="domain is not an STP domain", sources=("intent",)),
        TestSpec("ST02", "Root and designated bridge consistency", "L2", "H-root", "single stable root as intended", st02, applies=st_applies, requires=("ST01",), command="stp.state", condition="root moved/inconsistent", sources=("stp.state",)),
        TestSpec("ST03", "TCN rate and origin", "L2", "H-root", "TCN within normal", st03, applies=st_applies, requires=("ST01",), command="stp.state", condition="TCN storm", sources=("stp.state", "history")),
        TestSpec("ST04", "Port roles/states vs cabling graph (blocked port in every cycle)", "L2", "H-loop", "a port blocks in each physical cycle", st04, applies=st_applies, requires=("ST01",), command="stp.state+intent", condition="cycle without blocking port", sources=("stp.state", "intent")),
        TestSpec("ST05", "VLAN/MST instance consistency", "L2", "H-root", "identical MST region config", st05, applies=st_applies, requires=("ST01",), command="stp.mst_config", condition="MST region mismatch", sources=("stp.mst_config",)),
        TestSpec("ST06", "BPDU reception, guard, filter, loop guard", "L2", "H-guard", "BPDU path intact, guards present", st06, applies=st_applies, requires=("ST01",), command="stp.port_protection", condition="BPDU filter/guard misconfiguration", sources=("stp.port_protection",)),
        TestSpec("ST07", "Port-channel / LACP consistency", "L2", "H-guard", "LAG members bundled", st07, applies=lambda c_: (st07_applies(c_)[0] and st_applies(c_)[0], st07_applies(c_)[1] if not st07_applies(c_)[0] else st_applies(c_)[1]), requires=("ST01",), command="lacp.member", condition="LAG inconsistency", sources=("lacp.member",)),
        TestSpec("ST08", "Cabling graph vs NetBox (unrecorded loops)", "L2", "H-loop", "observed adjacency equals intent", st08, applies=st_applies, requires=("ST01",), command="lldp.neighbor+intent", condition="unrecorded cable", sources=("lldp.neighbor", "intent")),
        TestSpec("ST09", "MAC-table churn and storm control", "L2", "H-loop", "no MAC flaps/storm", st09, applies=st_applies, requires=("ST01",), command="mac.table+storm_control.state", condition="loop symptoms", sources=("mac.table", "storm_control.state")),
        TestSpec("ST10", "VTEP / L2 overlay boundary (EVPN-VXLAN)", "L2", "H-overlay", "overlay loop prevention healthy", st10, applies=st10_applies, command="evpn.state", condition="overlay MAC mobility", sources=("evpn.state",)),
    ),
    hypotheses=(
        Hypothesis("H-domain", "The domain is (not) a spanning-tree domain", "L2", ("ST01",), 1),
        Hypothesis("H-root", "Root bridge / TCN / MST instability", "L2", ("ST02", "ST03", "ST05"), 2),
        Hypothesis("H-loop", "A forwarding loop exists (no blocked port, extra cable, storm)", "L2", ("ST04", "ST08", "ST09"), 1),
        Hypothesis("H-guard", "BPDU filter/guard/loop-guard/LACP configuration defeats loop prevention", "L2", ("ST06", "ST07"), 1),
        Hypothesis("H-overlay", "EVPN-VXLAN overlay MAC mobility / duplicate MAC", "overlay", ("ST10",), 3),
    ),
    orders={"top-down": ("ST01", "ST09", "ST03", "ST04", "ST02", "ST05", "ST06", "ST07", "ST08", "ST10"),
            "bottom-up": ("ST01", "ST08", "ST06", "ST07", "ST04", "ST02", "ST05", "ST03", "ST09", "ST10")},
    select_strategy=lambda ctx: (("top-down", "storm/MAC-flap symptoms reported: start with the symptom indicators, then localise the mechanism") if any(a.get("kind") in ("BROADCAST_STORM", "MAC_FLAP", "TCN") for a in ctx.alarms) else
                                  ("bottom-up", "no storm alarm: verify cabling and port protection first, then STP state")),
    remediations={
        "F-bpdu-filter": {"tier": 2, "action": "remove bpdu-filter from inter-switch port (or add BPDU guard on edge) -- NOT root/priority changes while the loop is live", "approvals": ["operator approval", "verified blast radius"],
                          "pre_tests": ["ST04", "ST06"], "post_tests": ["ST04", "ST03", "ST09"], "rollback": "re-apply previous port settings", "never": ["bridge-priority change during the loop", "mass shutdown of ports"]},
        "F-loop": {"tier": 2, "action": "bounded containment: shut ONE redundant port only with approval and verified alternate path", "approvals": ["operator approval", "traffic guard"], "pre_tests": ["ST04", "ST09"], "post_tests": ["ST04", "ST09"], "rollback": "no shut of the same port", "never": ["automated root election changes"]},
        "F-cabling-loop": {"tier": 2, "action": "external: remove or record the unrecorded cable", "approvals": ["operator acknowledgement"], "pre_tests": ["ST08"], "post_tests": ["ST04", "ST08"], "rollback": "reconnect", "never": []},
        "F-evpn-dup": {"tier": 2, "action": "locate the duplicate MAC / L2 attachment; no STP in the overlay", "approvals": ["operator approval"], "pre_tests": ["ST10"], "post_tests": ["ST10"], "rollback": "n/a", "never": ["enabling spanning tree in an EVPN-VXLAN domain"]},
    },
)
