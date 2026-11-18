"""RB06 -- MTU mismatches and PMTUD black holes.  Size-dependent loss is established before blaming MTU; blocked ICMP test traffic is not service impact."""

from __future__ import annotations

from .hc import pmtu_assess
from .base import CONTEXT, Ctx, Finding, Hypothesis, Result, Runbook, TestSpec, fault, inconclusive, not_applicable, ok

OVERHEAD = {"gre": 24, "ipsec": 56, "vxlan": 50, "mpls": 8, "ipip": 20, "wireguard": 60, "none": 0}


def _links(ctx):
    seen, out = set(), []
    for h in ctx.path_fwd:
        for ifn in (h.get("in_if"), h.get("out_if")):
            if ifn and (h["device"], ifn) not in seen:
                seen.add((h["device"], ifn))
                out.append((h["device"], ifn))
    return out


def mt01(ctx: Ctx) -> Result:
    o = ctx.need("probe.sizes", ctx.src, ctx.flow.get("protocol", "tcp"))
    sizes = sorted(o.value["sizes"], key=lambda s: s["bytes"])
    good = [s for s in sizes if s["ok"] == s["sent"]]
    bad = [s for s in sizes if s["ok"] < s["sent"]]
    if not bad:
        return ok(f"all payload sizes up to {sizes[-1]['bytes']} B succeed over {ctx.flow.get('protocol', 'tcp').upper()}", "no size-dependent loss: MTU is not implicated by this symptom", sizes=sizes)
    if not good:
        return inconclusive("every payload size fails, including the smallest: this is not a size-dependent (MTU) pattern", "size dependence not shown", sizes=sizes)
    thr = max(s["bytes"] for s in good)
    if min(s["bytes"] for s in bad) > thr:
        return fault(f"sizes <= {thr} B succeed, sizes >= {min(s['bytes'] for s in bad)} B fail on {ctx.flow.get('protocol', 'tcp').upper()}", Finding("F-size-dependent", "Loss depends on packet size", "L3", ctx.src, "H-size", False, 0.7), "size-dependent loss is the PMTUD/MTU signature", threshold=thr, sizes=sizes)
    return inconclusive("loss is not monotonic in packet size; not a clean MTU signature", "irregular loss", sizes=sizes)


def mt02(ctx: Ctx) -> Result:
    per, eff = {}, None
    for dev, ifn in _links(ctx):
        m = ctx.opt("interface.mtu", dev, ifn)
        if m is None:
            continue
        tun = ctx.opt("tunnel.encap", dev, ifn)
        ov = OVERHEAD.get(tun.value.get("type", "none"), 0) if tun else 0
        per[f"{dev}:{ifn}"] = {"mtu": m.value, "overhead": ov, "effective": m.value - ov}
    if not per:
        ctx.need("interface.mtu", *_links(ctx)[0])
    eff = min(v["effective"] for v in per.values())
    exp = ctx.intent.get("expected_mtu", 1500)
    ctx.use_intent("intent")
    below = {k: v for k, v in per.items() if v["effective"] < exp}
    if below:
        return fault(f"effective path MTU {eff} (< intended {exp}): " + "; ".join(f"{k} MTU {v['mtu']} - encap {v['overhead']}" for k, v in below.items()), Finding("F-path-mtu", "A hop/tunnel limits the effective MTU below intent", "L3", next(iter(below)).split(":")[0], "H-mtu", True, 0.85,
                     "align interface MTU (or tunnel MTU/overhead) with intent via approved change; do not raise MTU speculatively"), effective_path_mtu=eff, hops=per)
    return ok(f"every hop carries >= {exp} (effective path MTU {eff})", "configured MTUs consistent with intent", effective_path_mtu=eff, hops=per)


def mt03(ctx: Ctx) -> Result:
    o = ctx.need("path.pmtu", ctx.src, ctx.dst)
    v = o.value
    need = ctx.flow.get("payload_bytes", 1472)
    if not v.get("df", True):
        return inconclusive("probes were sent without DF; PMTUD behaviour not exercised", "probe invalid")
    a = pmtu_assess(v, need)
    if a["typed"]:
        if a["state"] == "UNKNOWN":
            return inconclusive(a["reason"], "payload-size coverage incomplete", assessment=a, **v)
        if a["state"] in ("LOSS_UNCONFIRMED", "BLACKHOLE", "LIMIT"):
            mx = v.get("max_ok_size")
            return fault(f"largest DF probe payload that passes: {mx if mx is not None else 'none'} B (< {need} B service payload; packet {v.get('max_ok_packet')} B); {a['reason']}",
                         Finding("F-pmtu-limit", f"Path MTU supports only {mx} payload bytes", "L3", ctx.src, "H-mtu", False, 0.8 if a["state"] != "LOSS_UNCONFIRMED" else 0.6),
                         "DF probes show where the limit is, not which hop; ICMP/UDP only, TCP behaviour not verified", assessment=a, **v)
        return ok(f"DF probes up to {v['max_ok_size']} B payload succeed (>= {need} B)", "path MTU adequate for ICMP/UDP DF probes (TCP behaviour not verified)", assessment=a, **v)
    if v["max_ok"] < need:
        return fault(f"largest DF probe that passes: {v['max_ok']} B (< {need} B service payload); {len(v.get('probes', []))} bounded probes at {v.get('rate_pps', '?')} pps", Finding("F-pmtu-limit", f"Path MTU supports only {v['max_ok']} bytes", "L3", ctx.src, "H-mtu", False, 0.8), "DF probes show where the limit is, not which hop", **v)
    return ok(f"DF probes up to {v['max_ok']} B succeed (>= {need} B)", "path MTU adequate", **v)


def mt04(ctx: Ctx) -> Result:
    gen = [(d, ctx.opt("icmp.ptb", d, "generated")) for d in ctx.devices_on_path()]
    gen = [(d, o.value) for d, o in gen if o is not None]
    rcv = ctx.need("icmp.ptb", ctx.src, "received")
    sent = sum(v.get("count", 0) for d, v in gen)
    if sent > 0 and rcv.value.get("count", 0) == 0:
        who = [d for d, v in gen if v.get("count", 0) > 0]
        return fault(f"{who} generated {sent} ICMP packet-too-big/frag-needed, the source received {rcv.value.get('count', 0)}: the messages are lost on the way back", Finding("F-ptb-lost", "ICMP too-big messages are generated but never delivered", "L3", ctx.src, "H-ptb", True, 0.85, "locate the filter with MT08"), "PMTUD cannot work if PTB is filtered: classic black hole", generated=dict(gen), received=rcv.value)
    if sent == 0:
        return ok("no device generated PTB (no oversize DF packets reached an MTU limit)", "no PTB loss observed (and none needed)", received=rcv.value)
    return ok(f"{sent} PTB generated, {rcv.value['count']} delivered to the source", "PTB delivery works", received=rcv.value)


def mt05(ctx: Ctx) -> Result:
    o = ctx.need("tcp.mss", ctx.src, ctx.flow.get("name", "svc"))
    pm = ctx.opt("path.pmtu", ctx.src, ctx.dst)
    mx = pm.value.get("max_ok") if pm else None
    limit = (mx + pm.value.get("header_overhead", 28) - 40) if mx is not None else None     # untested/zero-pass probe values never yield an MSS verdict
    if limit is not None and o.value.get("negotiated_mss", 1460) > limit and not o.value.get("clamp"):
        return fault(f"negotiated MSS {o.value['negotiated_mss']} > path-supported {limit} and no MSS clamp configured", Finding("F-mss", "MSS not clamped to the path MTU", "L4", ctx.src, "H-mss", False, 0.7, "targeted MSS clamp at the tunnel/edge (authorised, evidence-appropriate)"), **o.value)
    return ok(f"negotiated MSS {o.value.get('negotiated_mss')} fits the path (limit {limit})" + ("; clamp " + str(o.value.get("clamp")) if o.value.get("clamp") else ""), "MSS compatible", **o.value)


def mt06(ctx: Ctx) -> Result:
    odd, n = [], 0
    for d, i in _links(ctx):
        for sub in ctx.intent.get("subinterfaces", {}).get(f"{d}:{i}", []):
            m = ctx.opt("interface.mtu", d, sub)
            p = ctx.opt("interface.mtu", d, i)
            if m is not None and p is not None:
                n += 1
                if m.value > p.value:
                    odd.append(f"{d}:{sub} MTU {m.value} > parent {i} {p.value}")
    lag = ctx.intent.get("lag", {})
    for key in lag:
        d, i = key.split(":")
        m, l = ctx.opt("interface.mtu", d, i), ctx.opt("interface.mtu", d, lag[key])
        if m is not None and l is not None:
            n += 1
            if m.value != l.value:
                odd.append(f"{d}:{i} member MTU {m.value} != {lag[key]} {l.value}")
    if not n:
        return not_applicable("no subinterface or LAG relationship on the path in the NetBox intent")
    if odd:
        return fault("; ".join(odd), Finding("F-sub-mtu", "Parent/child MTU inconsistency", "L3", hypothesis="H-mtu", causal=True, confidence=0.8), problems=odd)
    return ok(f"{n} parent/child MTU relationships consistent", "LAG/subinterface MTUs consistent")


def mt07(ctx: Ctx) -> Result:
    bad, n = [], 0
    for d, i in _links(ctx):
        for k in ("interface.rate.in_giants", "interface.rate.out_mtu_drops"):
            o = ctx.opt(k, d, i)
            if o is not None:
                n += 1
                if o.value > 0.5:
                    bad.append(f"{d}:{i} {k.rsplit('.', 1)[1]} {o.value}/s")
    if not n:
        ctx.need("interface.rate.in_giants", *_links(ctx)[0])
    if bad:
        return fault("; ".join(bad), Finding("F-mtu-drops", "Frames dropped for size", "L2", hypothesis="H-mtu", causal=True, confidence=0.75), problems=bad)
    return ok(f"no giant/MTU-exceeded drops on {n} counters", "no size-based interface drops")


def mt08(ctx: Ctx) -> Result:
    hits = []
    for d in ctx.devices_on_path():
        for o in ctx.each("acl.counters", d):
            for r in o.value["rules"]:
                if r["action"] == "deny" and str(r.get("proto", "")).startswith("icmp") and r.get("icmp_type") in ("packet-too-big", "fragmentation-needed", "unreachable", "3", "2"):
                    delta = r["hits"] - r.get("prev_hits", r["hits"])
                    if delta > 0:
                        hits.append({"device": d, "acl": o.value["acl"], "where": o.subject, "seq": r["seq"], "icmp_type": r["icmp_type"], "hit_delta": delta})
    if hits:
        h = hits[0]
        return fault(f"{h['device']} {h['acl']} {h['where']} seq {h['seq']} drops ICMP {h['icmp_type']} (+{h['hit_delta']} hits)", Finding("F-ptb-filter", f"{h['device']} filters ICMP packet-too-big, breaking PMTUD", "policy", h["device"], "H-ptb", True, 0.92,
                     "permit ICMPv4 type 3 code 4 / ICMPv6 type 2 (narrowly) through the Tier-2 change process; do not open ICMP broadly"), "the deny counter is incrementing for exactly the messages PMTUD needs", **h)
    if not any(ctx.view.each("acl.counters", d) for d in ctx.devices_on_path()):
        ctx.need("acl.counters", *(ctx.devices_on_path()[:1] * 2))
    return ok("no ACL/firewall rule drops PTB/fragmentation-needed on the path", "ICMP policy does not break PMTUD")


RB06 = Runbook(
    id="RB06", name="mtu-pmtud", version="1.0.0", title="MTU mismatches and PMTUD black holes", doc="RB06-mtu-pmtud.md", test_prefixes=("MT",),
    purpose="Show whether loss is size-dependent, find the limiting hop, and whether ICMP packet-too-big reaches the sender; avoid false MTU inference from blocked diagnostics.",
    tests=(
        TestSpec("MT01", "Size-dependent loss on the real service protocol", "L3", "H-size", "no size-dependent loss", mt01, cls=CONTEXT, command="probe.sizes", condition="loss depends on packet size", sources=("probe.sizes",)),
        TestSpec("MT02", "Per-hop physical/logical/tunnel MTU and encapsulation overhead", "L3", "H-mtu", "effective MTU >= intent", mt02, requires=("MT01",), command="interface.mtu+tunnel.encap", condition="a hop limits the MTU", sources=("interface.mtu", "tunnel.encap", "intent")),
        TestSpec("MT03", "Bounded DF/PMTUD probes", "L3", "H-mtu", "probes up to the service payload pass", mt03, requires=("MT01",), command="path.pmtu", condition="path MTU below payload", sources=("path.pmtu",)),
        TestSpec("MT04", "ICMP packet-too-big / frag-needed delivery", "L3", "H-ptb", "PTB generated is delivered", mt04, requires=("MT01",), command="icmp.ptb", condition="PTB lost", sources=("icmp.ptb",)),
        TestSpec("MT05", "MSS negotiation and clamping", "L4", "H-mss", "MSS fits the path", mt05, requires=("MT01",), command="tcp.mss", condition="MSS too large", sources=("tcp.mss", "path.pmtu")),
        TestSpec("MT06", "LAG / subinterface / VRF MTU consistency", "L3", "H-mtu", "parent and member MTUs consistent", mt06, requires=("MT01",), command="interface.mtu", condition="parent/child MTU mismatch", sources=("interface.mtu", "intent")),
        TestSpec("MT07", "Interface giant / MTU-exceeded drops", "L2", "H-mtu", "no size-based drops", mt07, requires=("MT01",), command="interface.rate.in_giants", condition="frames dropped for size", sources=("interface.rate.in_giants",)),
        TestSpec("MT08", "Firewall/ACL filtering of PTB and fragments; asymmetry", "L4", "H-ptb", "PTB permitted end to end", mt08, requires=("MT01",), command="acl.counters", condition="PTB filtered", sources=("acl.counters",)),
    ),
    hypotheses=(
        Hypothesis("H-size", "Loss is size dependent", "L3", ("MT01",), 1),
        Hypothesis("H-mtu", "A hop, tunnel or LAG limits the effective MTU", "L3", ("MT02", "MT03", "MT06", "MT07"), 2),
        Hypothesis("H-ptb", "ICMP packet-too-big is filtered (PMTUD black hole)", "policy", ("MT04", "MT08"), 1),
        Hypothesis("H-mss", "MSS is not clamped to the path", "L4", ("MT05",), 3),
    ),
    orders={"follow-the-path": ("MT01", "MT03", "MT02", "MT06", "MT07", "MT04", "MT08", "MT05"),
            "top-down": ("MT01", "MT05", "MT03", "MT04", "MT08", "MT02", "MT06", "MT07")},
    select_strategy=lambda ctx: ("follow-the-path", "the symptom is size dependent over a known path: measure, find the limiting hop, then check PTB delivery and filters"),
    remediations={
        "F-ptb-filter": {"tier": 2, "action": "narrowly permit ICMPv4 type 3 code 4 / ICMPv6 type 2 on the filtering device", "approvals": ["operator approval", "dry-run", "continuous production-flow guard"], "pre_tests": ["MT04", "MT08"],
                         "post_tests": ["MT01", "MT03", "MT04"], "rollback": "remove the added ACL line", "never": ["permit icmp any any", "lowering interface MTU to hide the filter"]},
        "F-path-mtu": {"tier": 2, "action": "align the limiting interface/tunnel MTU with intent (or clamp MSS) via approved change", "approvals": ["operator approval"], "pre_tests": ["MT02", "MT03"], "post_tests": ["MT01", "MT03"],
                       "rollback": "restore previous MTU", "never": ["global MTU increase", "disabling PMTUD"]},
        "F-mss": {"tier": 2, "action": "MSS clamp at the tunnel/edge where authorised", "approvals": ["operator approval"], "pre_tests": ["MT05"], "post_tests": ["MT01", "MT05"], "rollback": "remove clamp", "never": ["broad protocol change on speculation"]},
    },
)
