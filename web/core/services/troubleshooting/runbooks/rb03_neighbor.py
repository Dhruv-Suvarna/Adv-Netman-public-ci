"""RB03 -- Routing-protocol neighborship formation failures (OSPFv2/v3, BGP IPv4/IPv6/EVPN, RIP/RIPng, IS-IS, EIGRP *only when capability evidence allows*)."""

from __future__ import annotations

from .base import CONTEXT, Ctx, Finding, Hypothesis, Result, Runbook, TestSpec, fault, inconclusive, ok

SUPPORTED = {"ospf", "ospfv3", "bgp", "rip", "ripng", "isis", "eigrp"}
ESTABLISHED = ("Full", "Established", "Up")


def _t(ctx):
    t = ctx.case["target"]
    return t["device"], t["neighbor_device"], t["protocol"].lower(), t.get("af", "ipv4"), t.get("vrf", "default"), t.get("interface", "")


def _cfg(ctx, dev, proto):
    return ctx.need("protocol.config", dev, proto)


def nb01(ctx: Ctx) -> Result:
    dev, _, proto, af, vrf, _ = _t(ctx)
    if proto not in SUPPORTED:
        return Result("UNAVAILABLE", status="UNAVAILABLE", reason=f"protocol {proto!r} is not in the supported set {sorted(SUPPORTED)}", summary="unsupported protocol; no tests invented")
    cap = ctx.need("capability.protocol", dev, proto)
    if not cap.value.get("supported"):
        return Result("UNAVAILABLE", status="UNAVAILABLE", reason=f"platform capability evidence says {proto} is not supported on {dev}: {cap.value.get('note', '')}", summary="platform capability absent",
                      evidence_ids=list(ctx.used))
    return ok(f"{proto.upper()} ({af}, VRF {vrf}) supported on {dev} ({cap.value.get('platform', '')})", "protocol tests are valid for this platform", **cap.value)


def nb02(ctx: Ctx) -> Result:
    dev, nbr, _, af, vrf, ifn = _t(ctx)
    a, b = ctx.need("interface.oper_state", dev, ifn), ctx.opt("interface.oper_state", nbr, ctx.case["target"].get("neighbor_interface", ""))
    va, vb = ctx.need("interface.vrf", dev, ifn), ctx.opt("interface.vrf", nbr, ctx.case["target"].get("neighbor_interface", ""))
    pa, pb = ctx.need("interface.address", dev, ifn), ctx.opt("interface.address", nbr, ctx.case["target"].get("neighbor_interface", ""))
    probs = []
    if a.value != "up" or (b is not None and b.value != "up"):
        probs.append(f"interface not up ({a.value}/{b.value if b else '?'})")
    if vb is not None and va.value != vb.value:
        probs.append(f"interface VRF differs: {dev}={va.value} {nbr}={vb.value}")
    if va.value != vrf:
        probs.append(f"{dev} interface is in VRF {va.value}, adjacency intended in {vrf}")
    if pb is not None and pa.value.get(af) and pb.value.get(af):
        import ipaddress
        try:
            if ipaddress.ip_interface(pa.value[af]).network != ipaddress.ip_interface(pb.value[af]).network:
                probs.append(f"{af} addresses not in one subnet ({pa.value[af]} vs {pb.value[af]})")
        except ValueError:
            probs.append("unparseable interface address")
    if probs:
        return fault("; ".join(probs), Finding("F-iface-l3", "Interface/VRF/address-family reachability prevents the adjacency", "L3", dev, "H-l3", True, 0.85, "correct interface VRF/address through an approved change"), problems=probs)
    return ok(f"{dev}:{ifn} and peer up, same VRF {va.value}, same {af} subnet", "adjacency transport layer fine")


def nb03_applies(ctx: Ctx):
    return (_t(ctx)[2] in ("bgp",), "OSPF/RIP/IS-IS/EIGRP form adjacencies by multicast/link-local, not a unicast TCP session; reachability is covered by NB02")


def nb03(ctx: Ctx) -> Result:
    dev, nbr, *_ = _t(ctx)
    o = ctx.need("reach.transport", dev, ctx.case["target"].get("neighbor_address", nbr))
    if not o.value.get("tcp179_ok"):
        return fault(f"TCP/179 to {nbr} fails: {o.value.get('error')}", Finding("F-transport", "Transport to the BGP peer is blocked", "L4", dev, "H-l3", True, 0.8), **o.value)
    return ok(f"TCP/179 to {nbr} succeeds ({o.value.get('rtt_ms')} ms)", "transport reachability fine", **o.value)


def nb04(ctx: Ctx) -> Result:
    dev, nbr, proto, af, _, _ = _t(ctx)
    a, b = _cfg(ctx, dev, proto), _cfg(ctx, nbr, proto)
    A, B = a.value, b.value
    probs = []
    if proto in ("ospf", "ospfv3"):
        for k, label in (("area", "area"), ("network_type", "network type")):
            if A.get(k) != B.get(k):
                probs.append(f"OSPF {label} mismatch: {dev}={A.get(k)} {nbr}={B.get(k)}")
        if A.get("stub") != B.get("stub"):
            probs.append(f"OSPF area stub flag mismatch {A.get('stub')} vs {B.get('stub')}")
    if proto == "bgp":
        if A.get("neighbor_remote_as") != B.get("local_as"):
            probs.append(f"BGP AS mismatch: {dev} expects remote-as {A.get('neighbor_remote_as')}, {nbr} runs AS {B.get('local_as')}")
        if B.get("neighbor_remote_as") != A.get("local_as"):
            probs.append(f"BGP AS mismatch: {nbr} expects remote-as {B.get('neighbor_remote_as')}, {dev} runs AS {A.get('local_as')}")
        if A.get("neighbor_vrf", A.get("vrf")) != B.get("neighbor_vrf", B.get("vrf")):
            probs.append(f"BGP VRF mismatch: neighbor configured in VRF {A.get('neighbor_vrf', A.get('vrf'))} on {dev} but VRF {B.get('neighbor_vrf', B.get('vrf'))} on {nbr}")
        if af not in A.get("neighbor_afs", [af]) or af not in B.get("neighbor_afs", [af]):
            probs.append(f"address family {af} not activated on both sides ({dev}={A.get('neighbor_afs')} {nbr}={B.get('neighbor_afs')})")
    if proto == "isis" and A.get("level") != B.get("level"):
        probs.append(f"IS-IS level mismatch {A.get('level')} vs {B.get('level')}")
    if proto in ("rip", "ripng") and A.get("version") != B.get("version"):
        probs.append(f"RIP version mismatch {A.get('version')} vs {B.get('version')}")
    if proto == "eigrp" and A.get("asn") != B.get("asn"):
        probs.append(f"EIGRP ASN mismatch {A.get('asn')} vs {B.get('asn')}")
    if probs:
        return fault("; ".join(probs), Finding("F-proto-config", "Protocol-specific parameters differ between the two ends", "L3-control", dev, "H-params", True, 0.9,
                     "minimal config correction on the end that deviates from NetBox/golden intent; negative-test before applying"), "direct configuration evidence from both ends", problems=probs)
    return ok(f"{proto.upper()} identity parameters agree on both ends (instance/area/AS/level/AF/VRF)", "no identity mismatch", **{"checked": sorted(A)})


def nb05(ctx: Ctx) -> Result:
    dev, nbr, proto, *_ = _t(ctx)
    A, B = _cfg(ctx, dev, proto).value.get("timers"), _cfg(ctx, nbr, proto).value.get("timers")
    if not A or not B:
        return inconclusive("timers not present in one or both configurations", "timer comparison impossible")
    diff = {k: (A.get(k), B.get(k)) for k in set(A) | set(B) if A.get(k) != B.get(k)}
    needs_equal = {"ospf": ("hello", "dead"), "ospfv3": ("hello", "dead"), "isis": ("hello", "hold"), "eigrp": ("hello", "hold"), "rip": (), "ripng": (), "bgp": ()}[proto]
    bad = {k: v for k, v in diff.items() if k in needs_equal}
    if bad:
        return fault(f"timer mismatch {bad} (these must agree for {proto.upper()})", Finding("F-timers", "Hello/dead (or hold) timers differ", "L3-control", dev, "H-params", True, 0.9,
                     "align timers to the golden value"), diff=diff)
    note = f" (BGP keepalive/hold are negotiated, differences {diff} are legal)" if diff and proto == "bgp" else ""
    return ok(f"timers compatible{note}", "no timer-based rejection", diff=diff)


def nb06(ctx: Ctx) -> Result:
    dev, nbr, proto, *_ = _t(ctx)
    A, B = _cfg(ctx, dev, proto).value.get("auth"), _cfg(ctx, nbr, proto).value.get("auth")
    if A is None or B is None:
        return inconclusive("auth configuration not collected on one side", "cannot compare")
    # only fingerprints (hash of key id+algorithm+secret) are ever compared or shown -- never the key
    if A.get("configured") != B.get("configured") or (A.get("configured") and (A.get("fingerprint") != B.get("fingerprint") or A.get("key_id") != B.get("key_id"))):
        return fault("auth settings differ (configured / key-id / key fingerprint); key material is never displayed", Finding("F-auth", "Auth/key mismatch", "L3-control", dev, "H-auth", True, 0.85,
                     "re-provision the key through the secret manager; secrets never in tickets"), configured=(A.get("configured"), B.get("configured")), key_ids=(A.get("key_id"), B.get("key_id")))
    return ok("auth state and key fingerprint agree" if A.get("configured") else "auth not configured on either end", "no auth rejection", configured=A.get("configured"))


def nb07_applies(ctx: Ctx):
    return (_t(ctx)[2] in ("ospf", "ospfv3", "isis"), "interface MTU mismatch only blocks OSPF/IS-IS database exchange; BGP/RIP/EIGRP do not exchange it that way")


def nb07(ctx: Ctx) -> Result:
    dev, nbr, _, _, _, ifn = _t(ctx)
    a, b = ctx.need("interface.mtu", dev, ifn), ctx.need("interface.mtu", nbr, ctx.case["target"].get("neighbor_interface", ""))
    if a.value != b.value:
        return fault(f"interface MTU {dev}={a.value} {nbr}={b.value}: OSPF sticks in ExStart/Exchange", Finding("F-mtu-ospf", "MTU mismatch blocks adjacency", "L3-control", dev, "H-params", True, 0.85), mtu=(a.value, b.value))
    return ok(f"MTU equal ({a.value})", "no MTU-based DBD rejection")


def nb08(ctx: Ctx) -> Result:
    dev, nbr, proto, _, _, ifn = _t(ctx)
    probs = []
    pi = ctx.opt("protocol.interface", dev, ifn)
    if pi is not None and pi.value.get("passive"):
        probs.append(f"{dev}:{ifn} is passive for {proto.upper()}")
    for d in (dev, nbr):
        for o in ctx.each("acl.counters", d):
            for r in o.value["rules"]:
                if r["action"] == "deny" and r.get("proto") in (proto, "ospf" if proto == "ospf" else proto, "89" if proto.startswith("ospf") else "tcp") and r["hits"] - r.get("prev_hits", r["hits"]) > 0 and (
                        (proto == "bgp" and r.get("port") == 179) or proto != "bgp"):
                    probs.append(f"{d} {o.value['acl']} {o.subject} denies control-plane {proto.upper()} (seq {r['seq']}, hits +{r['hits'] - r.get('prev_hits', r['hits'])})")
    g = ctx.opt("bgp.ttl", dev, nbr) if proto == "bgp" else None
    if g is not None and g.value.get("mismatch"):
        probs.append(f"TTL/GTSM mismatch (ebgp-multihop/ttl-security): {g.value}")
    bfd = ctx.opt("bfd.session", dev, nbr)
    if bfd is not None and bfd.value.get("state") == "down" and bfd.value.get("registered_with") == proto:
        probs.append("BFD session registered with the protocol is down")
    if not ctx.used:
        ctx.need("protocol.interface", dev, ifn)
    if probs:
        return fault("; ".join(probs), Finding("F-ctrl-plane", "Passive interface, control-plane filter, TTL or BFD blocks the adjacency", "L3-control", dev, "H-ctrl", True, 0.85), problems=probs)
    return ok("not passive; no control-plane ACL deny, TTL/GTSM or BFD problem", "control-plane path clean")


def nb09(ctx: Ctx) -> Result:
    dev, nbr, _, *_ = _t(ctx)
    o = ctx.need("routing.neighbor.detail", dev, nbr)
    v = o.value
    if v.get("state") in ESTABLISHED:
        return ok(f"neighbor {nbr} is {v['state']}", "no rejection", **v)
    return fault(f"neighbor {nbr} {v.get('state')}: last error \"{v.get('last_error', 'none recorded')}\" (since {v.get('since_s')}s)", Finding("F-reject", "Device-reported rejection reason", "L3-control", dev, "H-reason", False, 0.7),
                 "the device's own reason is evidence, to be matched with the configuration tests", **v)


def nb10_applies(ctx: Ctx):
    o = ctx.view.latest("routing.neighbor.detail", _t(ctx)[0], _t(ctx)[1])
    return (bool(o and not o.is_missing and o.value.get("state") in ESTABLISHED), "neighbor is not established: no routes can be exchanged yet; verify after the fix")


def nb10(ctx: Ctx) -> Result:
    dev, _, proto, _, _, _ = _t(ctx)
    pfx = ctx.case["target"].get("expected_prefix")
    rib, fib = ctx.need("route.rib", dev, pfx), ctx.need("route.fib", dev, pfx)
    if not rib.value.get("present") or not fib.value.get("installed") or rib.value.get("protocol") != proto.rstrip("v3"):
        return fault(f"{pfx}: RIB present={rib.value.get('present')} via {rib.value.get('protocol')}, FIB installed={fib.value.get('installed')}", Finding("F-install", "Adjacency up but routes not installed", "L3", dev, "H-install", True, 0.8), rib=rib.value, fib=fib.value)
    return ok(f"{pfx} learned via {rib.value.get('protocol')} and installed in FIB", "protocol routes forward", rib=rib.value, fib=fib.value)


RB03 = Runbook(
    id="RB03", name="routing-neighborship", version="1.0.0", title="Routing-protocol neighborship formation failures", doc="RB03-routing-neighborship.md", test_prefixes=("NB",),
    purpose="Find why two routers do not form (or lose) a routing adjacency and verify routes install and forward once corrected.",
    tests=(
        TestSpec("NB01", "Protocol/AF capability on the platform", "CTRL", "H-cap", "protocol supported by capability evidence", nb01, cls=CONTEXT, command="capability.protocol", condition="unsupported protocol/platform", sources=("capability.protocol",)),
        TestSpec("NB02", "Interface state, VRF and address-family reachability", "L3", "H-l3", "same VRF/subnet, interfaces up", nb02, requires=("NB01",), command="interface.* both ends", condition="interface/VRF/subnet fault", sources=("interface.oper_state", "interface.vrf", "interface.address")),
        TestSpec("NB03", "Transport reachability (BGP TCP/179)", "L4", "H-l3", "TCP/179 reachable", nb03, applies=nb03_applies, requires=("NB01",), command="reach.transport", condition="peer transport blocked", sources=("reach.transport",)),
        TestSpec("NB04", "Instance, area/AS/level, network type, AF/VRF parameters", "L3-control", "H-params", "identity parameters agree", nb04, requires=("NB01",), command="protocol.config both ends", condition="parameter mismatch", sources=("protocol.config",)),
        TestSpec("NB05", "Hello/dead (hold) timers", "L3-control", "H-params", "timers compatible", nb05, requires=("NB01",), command="protocol.config.timers", condition="timer mismatch", sources=("protocol.config",)),
        TestSpec("NB06", "Authentication / key fingerprint (never the secret)", "L3-control", "H-auth", "auth state and fingerprint agree", nb06, requires=("NB01",), command="protocol.config.auth", condition="auth mismatch", sources=("protocol.config",)),
        TestSpec("NB07", "Interface MTU agreement", "L3", "H-params", "equal MTU", nb07, applies=nb07_applies, requires=("NB01",), command="interface.mtu", condition="MTU mismatch", sources=("interface.mtu",)),
        TestSpec("NB08", "Passive interface, control-plane ACL, TTL/GTSM, BFD", "L3-control", "H-ctrl", "control plane unobstructed", nb08, requires=("NB01",), command="protocol.interface+acl.counters+bfd.session", condition="control-plane obstruction", sources=("protocol.interface", "acl.counters", "bgp.ttl", "bfd.session")),
        TestSpec("NB09", "Device-reported rejection reason", "L3-control", "H-reason", "neighbor established / no error", nb09, requires=("NB01",), command="routing.neighbor.detail", cls=CONTEXT, condition="peer rejects", sources=("routing.neighbor.detail",)),
        TestSpec("NB10", "RIB/FIB installation and forwarding after adjacency", "L3", "H-install", "protocol routes installed in RIB and FIB", nb10, applies=nb10_applies, requires=("NB01",), after=("NB09",), command="route.rib+route.fib", condition="routes not installed", sources=("route.rib", "route.fib")),
    ),
    hypotheses=(
        Hypothesis("H-cap", "Protocol or address family is not supported on the platform", "ctrl", ("NB01",), 1),
        Hypothesis("H-l3", "Interface, VRF, subnet or transport prevents the session", "L3", ("NB02", "NB03"), 2),
        Hypothesis("H-params", "Protocol parameters (area/AS/level/type/AF/VRF/timers/MTU) differ", "L3-control", ("NB04", "NB05", "NB07"), 1),
        Hypothesis("H-auth", "Auth/key mismatch", "L3-control", ("NB06",), 2),
        Hypothesis("H-ctrl", "Passive interface, control-plane filter, TTL/GTSM or BFD", "L3-control", ("NB08",), 3),
        Hypothesis("H-reason", "The device reports a specific rejection reason", "L3-control", ("NB09",), 2),
        Hypothesis("H-install", "Adjacency up but routes not installed/forwarded", "L3", ("NB10",), 4),
    ),
    orders={"follow-the-path": ("NB01", "NB09", "NB02", "NB03", "NB08", "NB04", "NB05", "NB06", "NB07", "NB10"),
            "bottom-up": ("NB01", "NB02", "NB03", "NB07", "NB08", "NB04", "NB05", "NB06", "NB09", "NB10")},
    select_strategy=lambda ctx: (("follow-the-path", "start from the device's own rejection reason, then walk interface -> transport -> control plane -> parameters") if ctx.view.latest("routing.neighbor.detail", ctx.case["target"]["device"], ctx.case["target"]["neighbor_device"]) else
                                  ("bottom-up", "no device-reported reason collected: climb the stack from the interface")),
    remediations={
        "F-proto-config": {"tier": 2, "action": "minimal parameter correction on the deviating end (config-diff against NetBox/golden)", "approvals": ["operator approval", "dry-run pass"], "pre_tests": ["NB04", "NB05", "NB09"],
                           "post_tests": ["NB09", "NB10"], "rollback": "restore previous parameter; verify adjacency + routes", "never": ["clear ip bgp *", "clear ip ospf process", "indiscriminate neighbor reset"]},
        "F-timers": {"tier": 2, "action": "align hello/dead (hold) timers with the golden value", "approvals": ["operator approval"], "pre_tests": ["NB05"], "post_tests": ["NB09", "NB10"], "rollback": "restore timers", "never": ["neighbor reset"]},
        "F-auth": {"tier": 2, "action": "re-provision key via the secret manager on the deviating end", "approvals": ["operator approval", "security owner"], "pre_tests": ["NB06"], "post_tests": ["NB09"], "rollback": "restore previous key id", "never": ["logging key material"]},
        "F-iface-l3": {"tier": 2, "action": "correct interface VRF/address", "approvals": ["operator approval"], "pre_tests": ["NB02"], "post_tests": ["NB02", "NB09"], "rollback": "restore previous binding", "never": []},
    },
)
