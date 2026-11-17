"""Host/network reachability catalogue HC01-HC28 (spec 3.5) -- the executable half of RB02.

PASS = the healthy expectation held; FAIL = the fault condition is present (with a ``Finding``).  HC12/HC28 are context/safety checks whose
PASS means "evaluated, nothing blocking" (HC28 additionally states that losslessness is NEVER inferred from topology).
Every test is read-only: it only reads normalized observations and intent; collecting them is the collectors' (allowlisted) job.
"""

from __future__ import annotations

import ipaddress

from ..adapters import qos as qos_ad
from .. import correlation as corr
from .. import contracts as c
from .. import normalization as nz
from .base import CONTEXT, SAFETY, Ctx, Finding, Hypothesis, Result, TestSpec, fault, inconclusive, ok

ERR_RATE_ABS = 0.5          # frames/s of CRC/input errors that is never normal on a healthy link
DISCARD_RATE_ABS = 5.0
UTIL_HIGH_PCT = 85.0
MAC_MOVES_PER_MIN = 10
TCN_PER_HOUR = 5
DOM_MARGIN_DB = 1.0


# ------------------------------------------------------------------------------------------------------------------- helpers
def _link_ends(ctx: Ctx) -> list[tuple[str, str]]:
    ends, seen = [], set()
    for h in ctx.path_fwd:
        for ifn in (h.get("in_if"), h.get("out_if")):
            if ifn and (h["device"], ifn) not in seen:
                seen.add((h["device"], ifn))
                ends.append((h["device"], ifn))
    return ends


def _l3(ctx: Ctx) -> list[str]:
    roles = {n["name"]: n.get("role") for n in ctx.intent.get("nodes", [])}
    return [h["device"] for h in ctx.path_fwd if roles.get(h["device"]) in ("router", "firewall", "l3switch")]


def _switches(ctx: Ctx) -> list[str]:
    roles = {n["name"]: n.get("role") for n in ctx.intent.get("nodes", [])}
    return [h["device"] for h in ctx.path_fwd if roles.get(h["device"]) in ("switch", "l3switch")]


def _prefix(ctx: Ctx, which: str) -> str:
    return ctx.flow.get("dst_prefix" if which == "dst" else "src_prefix", "")


def _next_dev(ctx: Ctx, dev: str, path: list[dict] | None = None) -> str | None:
    hops = [h["device"] for h in (path or ctx.path_fwd)]
    return hops[hops.index(dev) + 1] if dev in hops and hops.index(dev) + 1 < len(hops) else None


def _pct(sent: int, okn: int) -> float | None:
    return round(100.0 * (sent - okn) / sent, 2) if sent else None


def _rule_matches(rule: dict, flow: dict) -> bool:
    proto = flow.get("protocol", "tcp")
    if rule.get("proto") not in (None, "ip", "any", proto):
        return False
    if rule.get("port") not in (None, flow.get("port")) and proto in ("tcp", "udp"):
        return False
    for fld, ip in (("src", flow.get("src_ip")), ("dst", flow.get("dst_ip"))):
        net = rule.get(fld)
        if net in (None, "any", ""):
            continue
        try:
            if ipaddress.ip_address(ip) not in ipaddress.ip_network(net, strict=False):
                return False
        except ValueError:
            return False
    return True


def _first_match(rules: list[dict], flow: dict) -> dict | None:
    return next((r for r in sorted(rules, key=lambda r: r["seq"]) if _rule_matches(r, flow)), None)


# ---------------------------------------------------------------------------------------------------------------------- tests
def hc01(ctx: Ctx) -> Result:
    ctx.use_intent("slo", "history")
    f, slo = ctx.flow, ctx.baselines.get("slo", {})
    missing = [k for k in ("protocol", "port", "src", "dst") if not f.get(k)]
    if missing or slo.get("status") != "available":
        return inconclusive(f"production contract incomplete ({', '.join(missing) or 'SLO source ' + str(slo.get('reason', 'unavailable'))})",
                            "service definition cannot be established")
    lkg = c.parse_time(ctx.case.get("last_known_good_at")) or c.parse_time((ctx.baselines.get("history") or {}).get("lkg_at"))
    worked = ctx.case.get("worked_before")
    if lkg is None and worked is None:
        return inconclusive("no last-known-good record: cannot tell a new service from a regression",
                            f"{f['protocol'].upper()}/{f['port']} {f['src']}->{f['dst']} contract known; history unknown")
    reg = bool(worked) or lkg is not None
    return ok(f"{f['protocol'].upper()}/{f['port']} {f['src']}->{f['dst']} SLO {slo.get('contract', {})}; "
              f"{'regression: worked until ' + c.iso(lkg) if reg else 'new service (never worked)'}",
              "last-known-good found: this is a regression, search the change window" if reg else "new service: provisioning faults are more likely than regressions",
              worked_before=reg, last_known_good=c.iso(lkg), contract=slo.get("contract", {}))


def hc02(ctx: Ctx) -> Result:
    ctx.use_intent("changes", "configs", "golden")
    rows = ctx.correlation.get("changes", [])
    if ctx.baselines.get("changes", {}).get("status") != "available":
        return inconclusive("change history unavailable: " + str(ctx.baselines.get("changes", {}).get("reason", "")), "cannot answer 'has anything changed?'")
    before = [r for r in rows if r["relation"] == "BEFORE_ONSET"]
    soak = ctx.baselines.get("soak_window", {})
    unapproved = [r for r in before if not r.get("authorized", r.get("approved"))]   # unauthorized: neither human-approved nor policy-authorized
    drift_unapproved = [d for d in ctx.correlation.get("drift", []) if d["drift_kind"] == "UNAPPROVED"]
    obs = {"changes_before_onset": [r["change_id"] for r in before], "unapproved": [r["change_id"] for r in unapproved],
           "unapproved_drift": [d["subject"] for d in drift_unapproved], "soak": soak.get("state"), "onset_in_soak": soak.get("onset_in_window")}
    if unapproved or drift_unapproved:
        return fault("change evidence: " + (f"unapproved/unrecorded change(s) {obs['unapproved'] or obs['unapproved_drift']} precede onset"),
                     Finding("F-unapproved-change", "Unapproved or unrecorded configuration change precedes the onset", "change", hypothesis="H-change",
                             confidence=0.4, remediation_hint="identify author/purpose; proximity is not proof -- confirm with a causal test"),
                     "temporal proximity of an unauthorized change is a lead, not a verdict", "run the path tests to locate the affected mechanism", **obs)
    if before:
        return ok(f"approved change(s) {obs['changes_before_onset']} precede onset; correlation recorded, no blame without a causal test",
                  "approved drift is expected; it does not by itself imply a fault or a rollback", **obs)
    return ok("no configuration change in the lookback window", "no change-based explanation", **obs)


def hc03(ctx: Ctx) -> Result:
    h = ctx.intent.get("hosts", {}).get(ctx.src, {})
    ifn = h.get("interface", "eth0")
    adm, op = ctx.need("interface.admin_state", ctx.src, ifn), ctx.need("interface.oper_state", ctx.src, ifn)
    carrier = ctx.opt("interface.carrier", ctx.src, ifn)
    bad = adm.value != "up" or op.value != "up" or (carrier is not None and carrier.value is False)
    obs = {"admin": adm.value, "oper": op.value, "carrier": carrier.value if carrier else "not collected"}
    if bad:
        return fault(f"{ctx.src}:{ifn} admin={adm.value} oper={op.value}", Finding("F-src-nic", f"{ctx.src} NIC {ifn} not up", "L1", ctx.src,
                     "H-l1", True, 0.9, "check host NIC/cable; physical work needs operator acknowledgement"), **obs)
    return ok(f"{ctx.src}:{ifn} admin up / oper up" + (" / carrier" if carrier else ""), "source NIC healthy", **obs)


def hc04(ctx: Ctx) -> Result:
    problems, checked = [], []
    for lk in ctx.intent.get("links", []):
        ends = [(lk["a"], lk.get("a_if")), (lk["b"], lk.get("b_if"))]
        if not all(e in set(_link_ends(ctx)) for e in ends):
            continue
        sp = [ctx.opt("interface.speed", d, i) for d, i in ends]
        dp = [ctx.opt("interface.duplex", d, i) for d, i in ends]
        if all(sp):
            checked.append(f"{ends[0][0]}:{ends[0][1]}<->{ends[1][0]}:{ends[1][1]} speed")
            if sp[0].value != sp[1].value:
                problems.append(f"speed mismatch {sp[0].value} vs {sp[1].value} on {ends[0][0]}-{ends[1][0]}")
        if all(dp) and dp[0].value != dp[1].value:
            problems.append(f"duplex mismatch {dp[0].value}/{dp[1].value} on {ends[0][0]}-{ends[1][0]}")
        for d, i in ends:
            t = ctx.opt("interface.transceiver", d, i)
            if t is None:
                continue
            v = t.value
            checked.append(f"{d}:{i} DOM")
            if v.get("supported") is False:
                problems.append(f"{d}:{i} unsupported transceiver")
            rx, lo = v.get("rx_dbm"), v.get("rx_low_alarm")
            if rx is not None and lo is not None and rx < lo + DOM_MARGIN_DB:
                problems.append(f"{d}:{i} Rx {rx} dBm within {DOM_MARGIN_DB} dB of low alarm {lo}")
    if not checked:
        ctx.need("interface.speed", *_link_ends(ctx)[0])  # raises Gap with the precise missing source
    if problems:
        return fault("; ".join(problems), Finding("F-phy", "Physical-layer mismatch or optics degradation on the path", "L1", hypothesis="H-l1", causal=True,
                     confidence=0.8, remediation_hint="correct speed/duplex or replace optic/cable (physical work: external acknowledgement)"), **{"problems": problems})
    return ok(f"{len(checked)} PHY/DOM readings consistent across path links", "no speed/duplex/autoneg mismatch, optics within thresholds", checked=checked)


def _rates(ctx: Ctx, key: str, dev: str, ifn: str):
    o = ctx.opt(key, dev, ifn)
    return None if o is None else o


def hc05(ctx: Ctx) -> Result:
    bad, seen, resets = [], 0, []
    stats = ctx.baselines.get("history", {}).get("stats", {})
    for dev, ifn in _link_ends(ctx):
        rst = ctx.opt("interface.counter_reset", dev, ifn)
        if rst is not None and rst.value.get("reset"):
            resets.append(f"{dev}:{ifn}")
            continue  # a reset invalidates the delta -> never read as fault OR health
        for key, absolute in (("interface.rate.in_crc_errors", ERR_RATE_ABS), ("interface.rate.in_errors", ERR_RATE_ABS),
                              ("interface.rate.out_discards", DISCARD_RATE_ABS), ("interface.rate.in_discards", DISCARD_RATE_ABS)):
            o = ctx.opt(key, dev, ifn)
            if o is None:
                continue
            seen += 1
            base = stats.get(f"{key}@{dev}@{ifn}", {})
            normal = base.get("median", 0.0) if base.get("state") == "LEARNED" else None
            if o.value > absolute and (normal is None or o.value > 3 * max(normal, 0.05)):
                bad.append(f"{dev}:{ifn} {key.rsplit('.', 1)[1]}={o.value}/s (normal {normal if normal is not None else 'unknown'})")
    if bad:
        return fault("; ".join(bad), Finding("F-errors", "Error/discard rate above normal on a path interface", "L1", hypothesis="H-l1", causal=False,
                     confidence=0.6, remediation_hint="correlate with HC04 optics and peer side before any action"), "counters alone do not prove cause", errors=bad)
    if not seen:
        return inconclusive("no error/discard counters usable" + (f" ({', '.join(resets)} counter reset)" if resets else ""), "error trend unknown")
    return ok(f"{seen} error/discard rates at or below normal" + (f"; counter reset on {', '.join(resets)} excluded" if resets else ""),
              "no error trend explains the symptom", checked=seen, resets=resets)


def hc06(ctx: Ctx) -> Result:
    hi = ctx.intent.get("hosts", {}).get(ctx.src, {})
    ifn = hi.get("interface", "eth0")
    o = ctx.need("host.address", ctx.src, ifn)
    ips = [a.split("/")[0] for a in o.value.get("addresses", [])]
    want_prefix = hi.get("prefix")
    ok_addr = ctx.flow.get("src_ip") in ips
    in_prefix = bool(want_prefix) and any(ipaddress.ip_address(i) in ipaddress.ip_network(want_prefix) for i in ips)
    vrf_ok = o.value.get("vrf", "default") == hi.get("vrf", "default")
    ctx.use_intent("intent")
    if not (ok_addr and in_prefix and vrf_ok):
        return fault(f"{ctx.src}:{ifn} addresses {ips} vs intended {ctx.flow.get('src_ip')} in {want_prefix} vrf {hi.get('vrf', 'default')}",
                     Finding("F-addr", "Host addressing/VRF differs from intent", "L3", ctx.src, "H-addr", True, 0.85, "correct host addressing"), addresses=ips)
    return ok(f"{ctx.src}:{ifn} {ips} inside {want_prefix}, VRF {o.value.get('vrf', 'default')}", "addressing matches NetBox intent", addresses=ips)


def hc07_applies(ctx: Ctx):
    mode = ctx.intent.get("hosts", {}).get(ctx.src, {}).get("addressing", "static")
    return (mode in ("dhcp", "slaac", "dhcpv6"), f"host {ctx.src} uses {mode} addressing per NetBox intent; no lease/RA to verify")


def hc07(ctx: Ctx) -> Result:
    o = ctx.need("dhcp.lease", ctx.src, ctx.intent["hosts"][ctx.src].get("interface", "eth0"))
    good = o.value.get("state") == "BOUND" and o.value.get("gateway") == ctx.intent["hosts"][ctx.src].get("gateway")
    if not good:
        return fault(f"lease state {o.value.get('state')}, gateway {o.value.get('gateway')}", Finding("F-dhcp", "Provisioning (DHCP/RA) fault", "L3", ctx.src, "H-addr", True, 0.8))
    return ok(f"lease BOUND, gateway {o.value['gateway']}, {o.value.get('lease_remaining_s')}s remaining", "provisioning healthy")


def hc08_applies(ctx: Ctx):
    return (bool(_switches(ctx)), "no L2 switch on the intended path")


def hc08(ctx: Ctx) -> Result:
    bad, n = [], 0
    vlan = ctx.intent.get("hosts", {}).get(ctx.src, {}).get("vlan")
    for h in ctx.path_fwd:
        if h["device"] not in _switches(ctx):
            continue
        for ifn in (h.get("in_if"), h.get("out_if")):
            o = ctx.opt("l2.port", h["device"], ifn)
            if o is None:
                continue
            n += 1
            v = o.value
            if v.get("mode") == "access" and v.get("access_vlan") != vlan:
                bad.append(f"{h['device']}:{ifn} access VLAN {v.get('access_vlan')} != {vlan}")
            if v.get("mode") == "trunk" and vlan not in v.get("allowed_vlans", []):
                bad.append(f"{h['device']}:{ifn} trunk does not allow VLAN {vlan}")
    if not n:
        ctx.need("l2.port", _switches(ctx)[0], ctx.path_fwd[1].get("in_if", ""))
    if bad:
        return fault("; ".join(bad), Finding("F-vlan", "VLAN membership/port-mode mismatch", "L2", hypothesis="H-l2", causal=True, confidence=0.85), problems=bad)
    return ok(f"{n} switch ports carry VLAN {vlan} correctly", "L2 membership consistent")


def hc09(ctx: Ctx) -> Result:
    bad, n = [], 0
    for sw in _switches(ctx):
        o = ctx.opt("mac.table", sw, str(ctx.intent.get("hosts", {}).get(ctx.src, {}).get("vlan", "")))
        if o is None:
            continue
        n += 1
        if o.value.get("moves_per_min", 0) > MAC_MOVES_PER_MIN or o.value.get("flapping_macs"):
            bad.append(f"{sw}: {o.value.get('moves_per_min')} MAC moves/min, flapping {o.value.get('flapping_macs')}")
    if not n:
        ctx.need("mac.table", _switches(ctx)[0], str(ctx.intent["hosts"][ctx.src].get("vlan", "")))
    if bad:
        return fault("; ".join(bad), Finding("F-macflap", "MAC flapping/moves indicate an L2 loop or duplicate MAC", "L2", hypothesis="H-l2", causal=False, confidence=0.7), problems=bad)
    return ok(f"MAC tables stable on {n} switch(es), no moves/flooding", "no L2 loop indicator")


def hc10(ctx: Ctx) -> Result:
    gw = ctx.intent.get("hosts", {}).get(ctx.src, {}).get("gateway")
    o = ctx.need("arp.entry", ctx.src, gw)
    if o.value.get("state") not in ("REACHABLE", "STALE", "DELAY", "PROBE") or o.value.get("dup_macs"):
        return fault(f"gateway {gw} ARP/ND state {o.value.get('state')}, duplicates {o.value.get('dup_macs')}",
                     Finding("F-arp", "Next-hop resolution failure or duplicate address", "L2", ctx.src, "H-addr", True, 0.8), **o.value)
    return ok(f"gateway {gw} resolved to {o.value.get('mac')} ({o.value.get('state')}), no duplicate", "first-hop resolution healthy", mac=o.value.get("mac"))


def hc11_applies(ctx: Ctx):
    return (bool(ctx.intent.get("fhrp")), "no first-hop redundancy protocol in the NetBox intent for this gateway")


def hc11(ctx: Ctx) -> Result:
    states = []
    for dev, spec in ctx.intent["fhrp"].items():
        o = ctx.need("fhrp.state", dev, str(spec["group"]))
        states.append((dev, o.value.get("state"), o.value.get("vip")))
    masters = [d for d, s, _ in states if s == "master"]
    if len(masters) != 1:
        return fault(f"{len(masters)} FHRP masters: {states}", Finding("F-fhrp", "First-hop redundancy has no single forwarder", "L3", hypothesis="H-addr", causal=True, confidence=0.85), states=states)
    mac = ctx.opt("arp.entry", ctx.src, ctx.intent["hosts"][ctx.src].get("gateway"))
    return ok(f"single FHRP master {masters[0]}", "gateway virtual protocol healthy", states=states, resolved_mac=mac.value.get("mac") if mac else None)


def hc12(ctx: Ctx) -> Result:
    inm = []
    for dev in ctx.devices_on_path():
        o = ctx.opt("maintenance.state", dev)
        if o is not None and o.value.get("in_maintenance"):
            inm.append(dev)
    n = sum(1 for d in ctx.devices_on_path() if ctx.opt("maintenance.state", d) is not None)
    if not n:
        ctx.need("maintenance.state", ctx.devices_on_path()[0])
    if inm:
        return fault(f"{inm} in maintenance/isolation", Finding("F-maintenance", "Intentional maintenance/drain explains the disruption", "ops", inm[0], "H-svc", True, 0.9,
                     "do not remediate; wait for or end maintenance through the change workflow"), "disruption is intentional", in_maintenance=inm)
    return ok(f"{n} path device(s) not in maintenance/decommission/isolation", "no intentional disruption", checked=n)


def hc13(ctx: Ctx) -> Result:
    observed, n = [], 0
    for dev, ifn in _link_ends(ctx):
        o = ctx.opt("lldp.neighbor", dev, ifn)
        if o is not None:
            n += 1
            observed.append({"a": dev, "a_if": ifn, "b": o.value["remote_device"], "b_if": o.value["remote_if"]})
    if not n:
        if not _link_ends(ctx):
            return inconclusive("PATH_UNAVAILABLE: no resolved path link ends to check LLDP adjacency on",
                                "topology cannot be judged without a resolved path (not evidence of health)")
        ctx.need("lldp.neighbor", *_link_ends(ctx)[0])
    ctx.use_intent("intent")
    ends = set(_link_ends(ctx))
    intent_links = [lk for lk in ctx.intent["links"] if (lk["a"], lk.get("a_if")) in ends or (lk["b"], lk.get("b_if")) in ends]
    cmp = corr.compare_topology(intent_links, observed)
    # only intent links we observed an endpoint of can be judged missing
    seen_ports = {(o["a"], o["a_if"]) for o in observed} | {(o["b"], o["b_if"]) for o in observed}
    missing = [m for m in cmp["missing_in_observed"] if (m["a"], m.get("a_if")) in seen_ports or (m["b"], m.get("b_if")) in seen_ports]
    if missing or cmp["unexpected_in_observed"]:
        return fault(f"{len(missing)} intended link(s) not observed, {len(cmp['unexpected_in_observed'])} unexpected", Finding("F-cabling", "Observed adjacency differs from NetBox intent",
                     "topology", hypothesis="H-topology", causal=True, confidence=0.8, remediation_hint="verify cabling/inventory against NetBox (intent is not proof either way)"),
                     missing=missing, unexpected=cmp["unexpected_in_observed"], miscabled=cmp["miscabled"])
    return ok(f"{n} LLDP adjacencies match NetBox intent", "topology conforms", links_checked=n)


def hc14_applies(ctx: Ctx):
    return (bool(ctx.intent.get("routing")), "no routing adjacency is intended on this path")


def hc14(ctx: Ctx) -> Result:
    bad, n = [], 0
    for dev, nbrs in ctx.intent["routing"].items():
        for nb in nbrs:
            o = ctx.opt("routing.neighbor", dev, nb["neighbor"])
            if o is None:
                continue
            n += 1
            if o.value.get("state") not in ("Full", "Established"):
                bad.append(f"{dev}->{nb['neighbor']} {o.value.get('state')}")
    if not n:
        d, nbs = next(iter(ctx.intent["routing"].items()))
        ctx.need("routing.neighbor", d, nbs[0]["neighbor"])
    if bad:
        return fault("; ".join(bad), Finding("F-adjacency", "Routing adjacency not established", "L3", hypothesis="H-routing", causal=False, confidence=0.7,
                     remediation_hint="run RB03 for protocol-specific mismatch tests"), problems=bad)
    return ok(f"{n} routing adjacencies Full/Established", "control-plane adjacencies healthy", checked=n)


def _route_dirs(ctx: Ctx, direction: str):
    path = ctx.path_fwd if direction == "fwd" else ctx.path_ret
    prefix = _prefix(ctx, "dst" if direction == "fwd" else "src")
    return path, prefix


def hc15(ctx: Ctx) -> Result:
    bad, n = [], 0
    path, prefix = _route_dirs(ctx, "fwd")
    for dev in _l3(ctx):
        o = ctx.need("route.rib", dev, prefix)
        n += 1
        nxt = _next_dev(ctx, dev, path)
        if not o.value.get("present"):
            bad.append(f"{dev}: no RIB route to {prefix}")
        elif nxt and o.value.get("next_hop_device") not in (None, nxt):
            bad.append(f"{dev}: RIB next hop {o.value.get('next_hop_device')} != intended {nxt}")
    if bad:
        return fault("; ".join(bad), Finding("F-rib", "RIB missing or diverges from the intended path", "L3", hypothesis="H-routing", causal=True, confidence=0.85), problems=bad)
    return ok(f"RIB route to {prefix} present on {n} L3 hop(s) with intended next hops", "route selection matches intent", checked=n, prefix=prefix)


def hc16_applies(ctx: Ctx):
    r = ctx.result("HC15")
    return (r is not None and r.verdict == "PASS", "HC15 found no usable RIB route (or did not run); there is nothing to install in the FIB")


def hc16(ctx: Ctx) -> Result:
    bad, n, prefix = [], 0, _prefix(ctx, "dst")
    for dev in _l3(ctx):
        rib, fib = ctx.need("route.rib", dev, prefix), ctx.need("route.fib", dev, prefix)
        n += 1
        g = corr.rib_fib_gap(rib.value, fib.value)
        if g["verdict"] != "CONSISTENT":
            bad.append(f"{dev}: {g['verdict']} ({g['reason']})")
    if bad:
        return fault("; ".join(bad), Finding("F-fib", "Forwarding table does not match the RIB", "L3", hypothesis="H-routing", causal=True, confidence=0.85,
                     remediation_hint="forwarding installation discrepancy: platform-specific; escalate with TCAM/hardware-programming evidence"), problems=bad)
    return ok(f"RIB and FIB agree on {n} L3 hop(s) (installed, next hop resolved)", "forwarding state matches control plane", checked=n)


def hc17(ctx: Ctx) -> Result:
    o = ctx.need("path.trace", ctx.src, ctx.dst)
    roles = {n["name"]: n.get("role") for n in ctx.intent.get("nodes", [])}
    d = corr.diff_path(corr.l3_view(ctx.path_fwd, roles, ctx.src), o.value.get("hop_devices", []))
    method = o.value.get("method", "icmp")
    if o.value.get("reached") and d["conforms"]:
        return ok(f"{method} trace reaches {ctx.dst} via {d['observed']} (matches intended path)", "forward path as intended", method=method, **d)
    if not o.value.get("reached") and method == "icmp":
        dm = ctx.result("HC23")
        if dm is not None and dm.observed.get("classification") in ("NO_PRODUCTION_IMPACT", "PRODUCTION_IMPACT") and dm.observed.get("icmp_blocked"):
            return inconclusive(f"ICMP trace stopped after {o.value.get('last_hop')} but ICMP is filtered on this path; trace cannot locate a data-plane break",
                                "a blocked diagnostic protocol is not path evidence", method=method, **d)
    if d["conforms"] is False and o.value.get("reached"):
        return fault(f"observed path {d['observed']} diverges from intended {d['intended']}", Finding("F-path", "Traffic follows an unintended path", "L3", hypothesis="H-routing", confidence=0.6), **d)
    return fault(f"trace stops after {o.value.get('last_hop')} (never reached {ctx.dst})", Finding("F-trace-break", f"Forward path breaks after {o.value.get('last_hop')}", "L3",
                 o.value.get("last_hop", ""), "H-routing", False, 0.5, "locate the hop with HC15/16/18"), "trace shows where replies stop, not why", **d)


def hc18_applies(ctx: Ctx):
    devs = [d for d in ctx.devices_on_path() if ctx.view.each("acl.counters", d)]
    return (bool(devs) or bool(ctx.intent.get("acl_devices")), "no ACL/firewall policy is applied on the path per intent or collection")


def _acl_first_match(rules: list[dict], flow: dict) -> tuple[dict | None, str | None]:
    """Ordered first-match.  -> (rule, None) | (None, None) no rule matches | (None, reason) when an UNSUPPORTED rule precedes any supported match: such a
    rule might match first, so the order cannot be resolved and the caller must stay inconclusive."""
    for r in sorted(rules, key=lambda r: r["seq"]):
        if r.get("unsupported"):
            return None, f"seq {r['seq']} uses unsupported syntax ({r['unsupported']}) before any proven match"
        if _rule_matches(r, flow):
            return r, None
    return None, None


def _acl_attachment(ctx: Ctx, dev: str, subject: str, v: dict) -> tuple[str, str]:
    """-> (status, detail).  status: TRAVERSED | NOT_TRAVERSED | WRONG_DIRECTION | AMBIGUOUS.  The attachment is the collected/declared
    interface + direction (subject ``<interface>-<direction>``, never rule content); the flow must enter (``in``) or leave (``out``) the device through it."""
    ifn, _, sdir = subject.rpartition("-")
    direction = v.get("direction")
    if not ifn or sdir not in ("in", "out") or direction not in ("in", "out"):
        return "AMBIGUOUS", "ACL attachment (interface/direction) unknown"
    if sdir != direction or (v.get("interface") and nz.canonical_interface(v["interface"]) != nz.canonical_interface(ifn)):
        return "AMBIGUOUS", "ACL attachment contradicts itself (subject vs direction/interface)"
    if v.get("complete") is False:
        return "AMBIGUOUS", "ACL/attachment collection partial or uncertain: " + "; ".join(map(str, v.get("uncertain", [])))[:120]
    af = ctx.flow.get("af")
    if v.get("af") and af and v["af"] != af:
        return "NOT_TRAVERSED", f"ACL address family {v['af']} differs from flow {af}"
    fvrf, avrf = ctx.flow.get("vrf"), v.get("vrf")
    if fvrf and fvrf != "default" and avrf != fvrf:
        return "AMBIGUOUS", f"ACL VRF {avrf or 'unknown'} not proven equal to flow VRF {fvrf}"
    if avrf and fvrf and avrf != fvrf:
        return "NOT_TRAVERSED", f"ACL VRF {avrf} differs from flow VRF {fvrf}"
    hops = [h for h in ctx.path_fwd if h.get("device") == dev]
    if not hops or any(not (h.get("in_if") or h.get("out_if")) for h in hops):
        return "AMBIGUOUS", f"flow path interfaces on {dev} unknown"
    want, other = ("in_if", "out_if") if direction == "in" else ("out_if", "in_if")
    canon = nz.canonical_interface
    if any(canon(h.get(want, "")) == canon(ifn) for h in hops):
        return "TRAVERSED", f"flow {'enters' if direction == 'in' else 'leaves'} {dev} via {ifn}"
    if any(canon(h.get(other, "")) == canon(ifn) for h in hops):
        return "WRONG_DIRECTION", f"{ifn} {direction} filters the opposite direction of the flow on {dev}"
    return "NOT_TRAVERSED", f"flow does not use {dev} {ifn}"


def hc18(ctx: Ctx) -> Result:
    """Causal denial requires ALL of: attachment known and traversed in the filtering direction; supported ordered first match = deny; counter history
    proving an increment between two complete samples of an unchanged rule.  Anything else is INCONCLUSIVE (never PASS/FAULT)."""
    confirmed, unproven, benign, notes, n = [], [], [], [], 0
    for dev in ctx.devices_on_path():
        for o in ctx.each("acl.counters", dev):
            v, sub = o.value, o.subject
            status, detail = _acl_attachment(ctx, dev, sub, v)
            if status in ("NOT_TRAVERSED", "WRONG_DIRECTION"):
                notes.append(f"{dev}:{sub} {status}: {detail}")
                continue
            if status == "AMBIGUOUS":
                n += 1
                unproven.append(f"{dev}:{sub} {detail}")
                continue
            n += 1
            m, why = _acl_first_match(v["rules"], ctx.flow)
            if why:
                unproven.append(f"{dev}:{sub} {why}")
            elif m is None:
                unproven.append(f"{dev}:{sub} no explicit rule matches; implicit/default action and its counter evidence are unknown")
            elif m is not None and m["action"] == "deny":
                hist = m.get("history", "ok")
                prev = m.get("prev_hits", m.get("hits"))
                if hist != "ok" or not isinstance(m.get("hits"), int) or not isinstance(prev, int) or m["hits"] < prev:
                    unproven.append(f"{dev}:{sub} seq {m['seq']} denies the tuple but counter history is {hist if hist != 'ok' else 'unusable'}")
                elif m["hits"] - prev > 0:
                    confirmed.append((dev, sub, m, m["hits"] - prev, v))
                else:
                    unproven.append(f"{dev}:{sub} seq {m['seq']} denies the tuple but its counter is not incrementing")
            # diagnostic-protocol policy: ICMP may be denied on purpose; recorded for HC23
            icmp, _icmp_why = _acl_first_match(v["rules"], {**ctx.flow, "protocol": "icmp", "port": None})
            if icmp is not None and icmp["action"] == "deny":
                benign.append(f"{dev}:{sub} seq {icmp['seq']} denies icmp")
    if confirmed:
        dev, sub, rule, delta, v = confirmed[0]
        return fault(f"{dev} {v['acl']} {sub}: first match seq {rule['seq']} DENY {rule.get('proto')}/{rule.get('port')} {rule.get('src')}->{rule.get('dst')}, hits +{delta} in {v.get('sample_interval_s', '?')}s",
                     Finding("F-acl-deny", f"ACL {v['acl']} on {dev} {sub} denies the production flow (seq {rule['seq']})", "policy", dev, "H-policy", True, 0.93,
                             f"narrowly scoped correction of {v['acl']} seq {rule['seq']} via Tier-2 approval; compare with golden and approved changes first"),
                     "the first matching rule of an ACL attached in the filtering direction denies the production tuple and its hit counter incremented between two complete samples -- direct causal evidence",
                     "verify with HC02 that seq is absent from golden; propose hotfix (not executed)",
                     device=dev, acl=v["acl"], interface_direction=sub, rule=rule, hit_delta=delta, direction_matches_flow=True, icmp_denies=benign, not_traversed=notes)
    if unproven:
        return inconclusive("ACL policy cannot be proven either way: " + "; ".join(unproven)[:300], "attachment, rule order or counter history is not conclusive",
                            unproven=unproven, not_traversed=notes, icmp_denies=benign)
    if not n:
        if notes:
            return inconclusive("ACLs were collected but none is proven to filter this flow (" + "; ".join(notes)[:200] + ")", "no ACL attachment on the path covers the flow direction",
                                not_traversed=notes, icmp_denies=benign)
        ctx.need_any("acl.counters", ctx.devices_on_path(routers_only=True) or ctx.devices_on_path())
    return ok(f"{n} ACL instance(s) on the path evaluated in the flow direction: no deny matches the production tuple", "policy does not block the production flow",
              checked=n, icmp_denies=benign, not_traversed=notes)


def hc19_applies(ctx: Ctx):
    return (bool(ctx.intent.get("qos_devices")) or any(ctx.view.each("qos.state", d) for d in ctx.devices_on_path()), "no QoS policy on the path per intent or collection")


def _qos_flow_class(classes: list[dict], flow: dict):
    """-> (class | None, reason).  Ordered first match; ``None`` + reason when the production tuple cannot be PROVEN to land in any class
    (unsupported/incomplete class before a proven match, undecidable criteria, or no class matches and so the treatment is unknown)."""
    for cl in sorted(classes, key=lambda x: x.get("order", 0)):
        verdict, why = qos_ad.classify(cl, flow)
        if verdict is None:
            return None, why
        if verdict:
            return cl, why
    return None, "no class provably matches the production tuple; the default treatment is not collected"


def hc19(ctx: Ctx) -> Result:
    """Fault only when ALL hold: attachment direction/interface proven on the flow path; the class is proven from the production tuple (never a ``matches_flow`` flag);
    counters are two ordered same-epoch samples with a usable window and a positive drop delta; and that delta is time-aligned with production loss (flow.health).
    No-drop PASS needs the same attachment/classification/counter proof.  Everything else is INCONCLUSIVE."""
    confirmed, unproven, notes, clear, n = [], [], [], [], 0
    for dev in ctx.devices_on_path():
        for o in ctx.each("qos.state", dev):
            v, sub = o.value, o.subject
            if "classes" not in v or not isinstance(v.get("classes"), list):
                n += 1
                unproven.append(f"{dev}:{sub} unrecognised QoS record")
                continue
            status, detail = _acl_attachment(ctx, dev, sub, v)      # same attachment/direction/VRF/AF proof as ACLs
            if status in ("NOT_TRAVERSED", "WRONG_DIRECTION"):
                notes.append(f"{dev}:{sub} {status}: {detail}")
                continue
            n += 1
            if status == "AMBIGUOUS":
                unproven.append(f"{dev}:{sub} {detail}")
                continue
            cl, why = _qos_flow_class(v["classes"], ctx.flow)
            if cl is None:
                unproven.append(f"{dev}:{sub} {why}")
                continue
            cnt = cl.get("counters") or {}
            if cnt.get("status") != "OK" or not isinstance(cnt.get("delta_dropped"), int):
                unproven.append(f"{dev}:{sub} class {cl.get('name')} drop counters {cnt.get('status', 'MISSING')}: {cnt.get('reason', 'no usable delta')}")
            elif cnt["delta_dropped"] > 0:
                confirmed.append((dev, sub, cl, v))
            else:
                clear.append(f"{dev}:{sub}/{cl.get('name')}")
    for dev in ctx.intent.get("qos_devices", []):       # a device intended to apply QoS on the path with no usable record at all is an evidence gap, not a clean bill
        if dev in ctx.devices_on_path() and not ctx.each("qos.state", dev):
            unproven.append(f"{dev}: intent declares QoS but no usable QoS state was collected")
    if confirmed:
        dev, sub, cl, v = confirmed[0]
        cnt = cl["counters"]
        loss = ctx.opt("flow.health", ctx.src, ctx.flow.get("name", "svc"))
        samples = loss.value.get("samples", []) if loss else []
        if not loss or not samples:
            return inconclusive(f"{dev}:{sub} class {cl['name']} (proven for the production tuple) dropped +{cnt['delta_dropped']} pkts in {cnt['span_s']:.0f}s, but no time-aligned production-loss measurement is available",
                                "drops are real but causality for the production flow cannot be established", classes=cl, unproven=unproven)
        cf = corr.counter_flow_correlation([{"at": s["at"], "hits": s["dropped"], "direction": "out"} for s in cnt["samples"]],
                                           [{"at": s["at"], "loss_pct": s["loss_pct"]} for s in samples], direction="out")
        if cf.get("correlated") is not True:
            return inconclusive(f"{dev}:{sub} class {cl['name']} dropped +{cnt['delta_dropped']} pkts but not time-aligned with production loss: {cf['reason']}",
                                "drops seen; timing does not confirm they impair the production flow", classes=cl, correlation=cf, unproven=unproven)
        return fault(f"{dev}:{sub} class {cl['name']} (proven for the production tuple, {v.get('direction')} attachment) dropped +{cnt['delta_dropped']} pkts in {cnt['span_s']:.0f}s, policer {cl.get('policer_bps')} bps; {cf['reason']}",
                     Finding("F-qos-drop", f"QoS class {cl['name']} on {dev}:{sub} drops production traffic", "qos", dev, "H-qos", True, 0.85,
                             "adjust policer/queue via Tier-2 change after capacity review; configuration may be golden-conformant"),
                     "drops are in the flow's proven class and attachment direction, time-aligned with production loss",
                     classes=cl, correlation=cf, direction_matches_flow=True)
    if unproven:
        return inconclusive("QoS impact cannot be proven either way: " + "; ".join(unproven)[:300], "attachment, classification or counter evidence is not conclusive",
                            unproven=unproven, not_traversed=notes)
    if not n:
        if notes:
            return inconclusive("QoS policies were collected but none is proven to apply to this flow direction (" + "; ".join(notes)[:200] + ")", "no QoS attachment on the path covers the flow direction",
                                not_traversed=notes)
        ctx.need_any("qos.state", ctx.devices_on_path(routers_only=True) or ctx.devices_on_path())
        return inconclusive("no QoS state was evaluated", "QoS state not collected")
    return ok(f"{len(clear)} QoS attachment(s) with a proven flow class and measured counters: no drop delta in the flow's class", "QoS not impairing the flow", checked=clear, not_traversed=notes)


def hc20(ctx: Ctx) -> Result:
    hot, n = [], 0
    for dev, ifn in _link_ends(ctx):
        o = ctx.opt("interface.utilization", dev, ifn)
        if o is None:
            continue
        n += 1
        if max(o.value.get("in_pct", 0), o.value.get("out_pct", 0)) > UTIL_HIGH_PCT or o.value.get("microburst"):
            hot.append(f"{dev}:{ifn} in {o.value.get('in_pct')}% out {o.value.get('out_pct')}% microburst={o.value.get('microburst')}")
    if not n:
        if not _link_ends(ctx):
            return inconclusive("PATH_UNAVAILABLE: no resolved path link ends to check utilization on",
                                "congestion cannot be judged without a resolved path (not evidence of health)")
        ctx.need("interface.utilization", *_link_ends(ctx)[0])
    if hot:
        return fault("; ".join(hot), Finding("F-congestion", "Link congestion/microbursts on the path", "L1/L2", hypothesis="H-cong", causal=False, confidence=0.6), links=hot)
    return ok(f"{n} path interfaces below {UTIL_HIGH_PCT}% with no microburst indicator", "no congestion explanation (5-minute averages can hide microbursts; none flagged)")


def _intended_admin_states(device: str) -> dict[str, str] | None:
    """Intended per-interface admin state from the tracked inventory template (authoritative configuration intent).
    Only literal ``interface`` blocks are judged; a block containing template logic is left unknown.  None: no template."""
    import re
    from pathlib import Path

    import yaml
    from django.conf import settings

    root = Path(settings.REPO_ROOT)
    try:
        inv = yaml.safe_load((root / "inventory.yml").read_text(encoding="utf-8")) or {}
        name = ((inv.get("network_devices") or {}).get(device) or {}).get("template")
        text = (root / "templates" / str(name)).read_text(encoding="utf-8") if name else None
    except (OSError, yaml.YAMLError):
        return None
    if not text:
        return None
    out: dict[str, str] = {}
    for m in re.finditer(r"^interface (\S+)\n(.*?)(?=^!|^interface |\Z)", text, re.M | re.S):
        body = m.group(2)
        if "{%" in body or "{{" in body:
            continue
        out[m.group(1)] = "down" if re.search(r"^\s+shutdown\s*$", body, re.M) else "up"
    return out


def hc29_applies(ctx: Ctx) -> tuple[bool, str]:
    """Applies only when a managed device has collected admin state AND a tracked template states its intent."""
    for o in ctx.view.each("interface.admin_state"):
        if not o.is_missing and o.subject and o.subject in (_intended_admin_states(o.device) or {}):
            return True, "managed-device admin state collected and covered by tracked configuration intent"
    return False, "no collected managed-device admin state covered by tracked configuration intent"


def hc29(ctx: Ctx) -> Result:
    """Managed-device interface admin state vs intended configuration (end hosts are out of scope)."""
    observed = ctx.view.each("interface.admin_state")
    if not observed:
        return inconclusive("no managed-device interface admin state was collected", "admin-state intent cannot be judged without observations")
    ctx.use_intent("intent")
    mismatched, checked, unknown_devices = [], 0, set()
    intents: dict[str, dict | None] = {}
    for o in observed:
        if o.is_missing or not o.subject:
            continue
        if o.device not in intents:
            intents[o.device] = _intended_admin_states(o.device)
        intended = (intents[o.device] or {}).get(o.subject)
        if intended is None:
            unknown_devices.add(o.device)
            continue
        checked += 1
        if str(o.value).lower() != intended:
            mismatched.append({"device": o.device, "interface": o.subject, "observed": str(o.value).lower(), "intended": intended,
                               "observation_id": o.record_id, "evidence_ids": list(o.evidence_ids)})
    if mismatched:
        first = mismatched[0]
        return fault("; ".join(f"{m['device']}:{m['interface']} admin {m['observed']} but intended {m['intended']}" for m in mismatched),
                     Finding("F-admin-state", f"{first['device']} {first['interface']} administrative state differs from intended configuration", "L1",
                             first["device"], "H-admin", True, 0.95,
                             f"governed Change Engine: restore intended admin state on {first['device']} {first['interface']} "
                             f"({'no shutdown' if first['intended'] == 'up' else 'shutdown'}); traffic impact only as independently measured"),
                     "observed admin state contradicts the tracked inventory configuration intent", mismatches=mismatched, checked=checked)
    if not checked:
        return inconclusive("no intended admin state available for the observed interfaces", "tracked templates do not cover these interfaces",
                            devices=sorted(unknown_devices))
    return ok(f"{checked} managed-device interface admin states match intended configuration", "no admin-state deviation from intent", checked=checked)


def pmtu_assess(pm: dict, need: int) -> dict:
    """Interpret one ``path.pmtu`` value against the service payload ``need``.  ``state``: OK | LIMIT (loss/PTB above max_ok, PMTUD signalling seen) | BLACKHOLE (DF loss at
    >= need, no PTB, and the vantage COULD see PTB) | LOSS_UNCONFIRMED (same loss but PTB visibility unknown/not observable) | UNKNOWN (sizes untested, partial, invalid).
    Typed values (``schema == nmas.pmtu/1``, produced by the probe source) are judged strictly; legacy/hand-written values keep the original max_ok/ptb_received rule."""
    if pm.get("schema") != "nmas.pmtu/1":
        low = pm.get("max_ok", 0) < need
        return {"state": "BLACKHOLE" if low and not pm.get("ptb_received", False) else "OK", "typed": False, "max_ok": pm.get("max_ok"), "reason": "legacy untyped value"}
    base = {"typed": True, "max_ok": pm.get("max_ok_size"), "visibility": pm.get("ptb_visibility", "unknown")}
    if pm.get("df") is not True:
        return {**base, "state": "UNKNOWN", "reason": "probes were not sent with DF"}
    rows = {r["data_bytes"]: r for r in pm.get("sizes", [])}
    big = [r for p, r in rows.items() if p >= need and r["status"] != "unknown"]
    if any(r["status"] == "pass" for r in big) and pm.get("monotonic", False):
        return {**base, "state": "OK", "reason": f"a DF probe of payload >= {need} B was answered (ICMP/UDP only; TCP behaviour not verified)"}
    if not big:
        return {**base, "state": "UNKNOWN", "reason": f"no probe at payload >= {need} B was completed (largest tested {pm.get('largest_tested_size')}): coverage is UNKNOWN, not a pass"}
    if not pm.get("monotonic", False) or any(r["status"] == "partial" for r in big):
        return {**base, "state": "UNKNOWN", "reason": "loss at the required size is intermittent or non-monotonic: not size-dependent evidence"}
    if pm.get("ptb_received"):
        return {**base, "state": "LIMIT", "reason": f"DF probes >= {need} B were answered by ICMP too-big (next-hop MTU {pm.get('ptb_mtu')}): PMTUD signalling reaches the source"}
    if base["visibility"] == "observable":
        return {**base, "state": "BLACKHOLE", "reason": f"DF probes >= {need} B time out, no ICMP too-big arrived although the vantage can observe it"}
    return {**base, "state": "LOSS_UNCONFIRMED", "reason": f"DF probes >= {need} B time out but the vantage's PTB visibility is {base['visibility']}: a PMTUD black hole is NOT confirmed"}


def hc21(ctx: Ctx) -> Result:
    exp = ctx.intent.get("expected_mtu", 1500)
    mtus, odd = {}, []
    for dev, ifn in _link_ends(ctx):
        o = ctx.opt("interface.mtu", dev, ifn)
        if o is not None:
            mtus[f"{dev}:{ifn}"] = o.value
            if o.value < exp:
                odd.append(f"{dev}:{ifn} MTU {o.value} < intended {exp}")
    p = ctx.need("path.pmtu", ctx.src, ctx.dst)
    pm = p.value
    need = ctx.flow.get("app_bytes", exp - 28)
    a = pmtu_assess(pm, need)
    note = {"assessment": a}
    if a["state"] == "UNKNOWN":
        return inconclusive(a["reason"], "path MTU not established", mtus=mtus, pmtu=pm, **note)
    if a["state"] == "LOSS_UNCONFIRMED":
        if odd:
            return fault(f"{'; '.join(odd)}; {a['reason']}", Finding("F-mtu", "Interface MTU below intent with DF loss (PMTUD black hole not confirmed)", "L3", hypothesis="H-mtu", causal=False, confidence=0.6), mtus=mtus, pmtu=pm, **note)
        return inconclusive(a["reason"], "size-dependent loss observed; cause not established", mtus=mtus, pmtu=pm, **note)
    blackhole = a["state"] == "BLACKHOLE"
    if odd and blackhole:
        return fault(f"{'; '.join(odd)}; DF probes above {pm.get('max_ok')} fail and no ICMP too-big arrives", Finding("F-mtu", "MTU mismatch with PMTUD black hole", "L3", hypothesis="H-mtu", causal=True, confidence=0.85), mtus=mtus, pmtu=pm, **note)
    if blackhole:
        return fault(f"DF probes above {pm.get('max_ok')} fail without ICMP too-big", Finding("F-pmtud", "PMTUD black hole", "L3", hypothesis="H-mtu", causal=False, confidence=0.6), mtus=mtus, pmtu=pm, **note)
    if a["state"] == "LIMIT":
        return fault(f"{a['reason']}; largest passing payload {pm.get('max_ok_size')}", Finding("F-pmtu-limit", "Path MTU below the service payload (PMTUD signalling works)", "L3", hypothesis="H-mtu", causal=False, confidence=0.6), mtus=mtus, pmtu=pm, **note)
    return ok(f"path MTU supports {pm.get('max_ok')} (>= {need} needed); interface MTUs {sorted(set(mtus.values()))}", "no size-dependent loss", mtus=mtus, pmtu=pm, **note)


def hc22(ctx: Ctx) -> Result:
    o = ctx.need("service.probe", ctx.src, "tcp" if ctx.flow.get("protocol") == "tcp" else ctx.flow.get("protocol", "tcp"))
    v = o.value
    loss = _pct(v["sent"], v["ok"])
    limit = ctx.baselines.get("slo", {}).get("contract", {}).get("max_loss_pct", 1.0)
    if loss is None:
        return inconclusive("no probe samples", "service state unknown")
    if loss > limit:
        return fault(f"{v['ok']}/{v['sent']} {ctx.flow.get('protocol', 'tcp').upper()}/{ctx.flow.get('port')} handshakes succeeded ({loss}% loss > {limit}%)",
                     Finding("F-svc-impact", "Production service handshake failing", "L4/L7", ctx.src, "H-impact", False, 0.95), "the production service is truly impaired: this is not an ICMP-only artefact",
                     loss_pct=loss, **v)
    return ok(f"{v['ok']}/{v['sent']} {ctx.flow.get('protocol', 'tcp').upper()}/{ctx.flow.get('port')} handshakes succeed (p50 {v.get('rtt_ms_p50')} ms)", "production service healthy", loss_pct=loss, **v)


def hc23(ctx: Ctx) -> Result:
    probes = {}
    for p in ("icmp", "udp"):
        o = ctx.opt("service.probe", ctx.src, p)
        if o is not None:
            probes[p] = {"sent": o.value["sent"], "ok": o.value["ok"]}
    tcp = ctx.opt("service.probe", ctx.src, ctx.flow.get("protocol", "tcp"))
    if tcp is not None:
        probes[ctx.flow.get("protocol", "tcp")] = {"sent": tcp.value["sent"], "ok": tcp.value["ok"]}
    if not [p for p in probes if p != ctx.flow.get("protocol", "tcp")]:
        ctx.need("service.probe", ctx.src, "icmp")
    intent_blocked = list(ctx.intent.get("intentionally_blocked", []))
    # approved-change evidence of an ICMP deny (HC18/HC02) and operator exceptions
    suppressed = [e for e in ctx.correlation.get("exceptions", []) if e.get("suppressed")]
    approved_blocks = [p for dr in ctx.correlation.get("drift", []) if dr["drift_kind"] == "APPROVED" for p in dr.get("blocks", [])]
    blocked = intent_blocked + approved_blocks + [p for e in suppressed for p in e.get("protocols", [])]
    d = corr.protocol_distinction(probes, ctx.flow, intentionally_blocked=blocked)
    obs = {"classification": d["classification"], "per_protocol": d["per_protocol"], "icmp_blocked": bool(probes.get("icmp") and probes["icmp"]["ok"] == 0),
           "exceptions_applied": [e.get("policy") for e in suppressed], "approved_change_blocks": approved_blocks,
           "intent_blocked": intent_blocked, "expected_basis": ("intent" if intent_blocked else "approved change" if approved_blocks else "operator exception" if suppressed else "none")}
    if d["classification"] == "PRODUCTION_IMPACT":
        return Result("INCONCLUSIVE", reason="production protocol is failing (HC22); diagnostic-protocol results are context only", summary=d["reason"], observed=obs,
                      interpretation="diagnostic protocols neither confirm nor mask the production failure")
    if d["classification"] == "NO_PRODUCTION_IMPACT" and d.get("expected_protocol_distinction"):
        return ok(f"{d['reason']} -- expected protocol distinction, not an outage", "no remediation; keep observing the suppressed test", **obs)
    if d["classification"] == "NO_PRODUCTION_IMPACT_UNEXPLAINED_DIAGNOSTIC_FAILURE":
        return fault(d["reason"], Finding("F-diag-unexplained", "Diagnostic protocol fails without recorded intent", "policy", hypothesis="H-policy", confidence=0.4,
                     remediation_hint="no remediation: production healthy. Ask the owner to record the intent (operator-confirmed exception)"), "not production impact", **obs)
    return ok(d["reason"], "diagnostic protocols behave", **obs)


def hc24(ctx: Ctx) -> Result:
    bad, n = [], 0
    fw = [d for d in _l3(ctx) if ctx.node(d).get("role") == "firewall"]
    srcp = _prefix(ctx, "src")
    ret_devs = [h["device"] for h in ctx.path_ret] or list(reversed([h["device"] for h in ctx.path_fwd]))
    for dev in [d for d in ret_devs if d in _l3(ctx)]:
        o = ctx.need("route.rib", dev, srcp)
        n += 1
        nxt = _next_dev(ctx, dev, ctx.path_ret or [{"device": d} for d in ret_devs])
        if not o.value.get("present"):
            bad.append(f"{dev}: no return route to {srcp}")
        elif nxt and o.value.get("next_hop_device") not in (None, nxt):
            bad.append(f"{dev}: return next hop {o.value.get('next_hop_device')} != intended {nxt} (asymmetry)")
    for f in fw:
        s = ctx.need("firewall.session", f, ctx.flow.get("name", "svc"))
        if s.value.get("asymmetry_drops", 0) > 0 or not s.value.get("state_found", True):
            bad.append(f"{f}: stateful drops {s.value.get('asymmetry_drops')} / session found={s.value.get('state_found')}")
    if bad:
        return fault("; ".join(bad), Finding("F-return", "Return path or stateful session fault", "L3/L4", hypothesis="H-routing", causal=True, confidence=0.8), problems=bad)
    return ok(f"return route to {srcp} present on {n} L3 hop(s); {len(fw)} firewall session table(s) consistent", "forward and return paths symmetric, no stateful drops", checked=n)


def hc25_applies(ctx: Ctx):
    return (bool(ctx.flow.get("dst_name")), "the service is addressed by IP; no DNS name is part of the contract")


def hc25(ctx: Ctx) -> Result:
    name = ctx.flow["dst_name"]
    want = ctx.intent.get("services", {}).get("dns_names", {}).get(name) or ctx.flow.get("dst_ip")
    res = ctx.need("dns.query", ctx.src, name)
    ans = res.value.get("answers", [])
    if res.value.get("rcode") != "NOERROR" or want not in ans:
        return fault(f"{name}: rcode {res.value.get('rcode')} answers {ans} (intended {want})", Finding("F-dns", "Name resolves wrongly or not at all", "dns", ctx.src, "H-dns", True, 0.8, "run RB05"), **res.value)
    return ok(f"{name} -> {ans} (intended {want}), TTL {res.value.get('ttl')}", "endpoint selection correct", **res.value)


def hc26_applies(ctx: Ctx):
    stp = {d: ctx.intent.get("l2", {}).get("stp", {}).get(d) for d in _switches(ctx)}
    if not stp:
        return False, "no L2 switch on the path"
    if all(v in (None, "none", "evpn-vxlan") for v in stp.values()):
        return False, "path switches run no spanning tree (STP-free / EVPN-VXLAN domain)"
    return True, ""


def hc26(ctx: Ctx) -> Result:
    bad, n = [], 0
    vlan = str(ctx.intent["hosts"][ctx.src].get("vlan", ""))
    for sw in _switches(ctx):
        if ctx.intent.get("l2", {}).get("stp", {}).get(sw) in (None, "none", "evpn-vxlan"):
            continue
        o = ctx.need("stp.state", sw, vlan)
        n += 1
        v = o.value
        if v.get("tcn_count_1h", 0) > TCN_PER_HOUR or v.get("root_changes_24h", 0) > 0 or any(p.get("state") == "blocking" and p.get("role") == "root" for p in v.get("ports", [])):
            bad.append(f"{sw}: TCN/h {v.get('tcn_count_1h')} root changes {v.get('root_changes_24h')}")
    if bad:
        return fault("; ".join(bad), Finding("F-stp", "Spanning-tree instability", "L2", hypothesis="H-l2", causal=False, confidence=0.7, remediation_hint="run RB04"), problems=bad)
    return ok(f"STP stable on {n} switch(es): stable root, TCN below {TCN_PER_HOUR}/h", "no L2 instability", checked=n)


def hc27(ctx: Ctx) -> Result:
    o = ctx.need("flow.health", ctx.src, ctx.flow.get("name", "svc"))
    v = o.value
    contract = ctx.baselines.get("slo", {}).get("contract", {})
    limit = contract.get("max_loss_pct", 1.0)
    cov = v.get("coverage_pct", 0)
    if cov < 50:
        return inconclusive(f"flow monitoring coverage only {cov}%: loss cannot be measured reliably", "production loss unknown", **v)
    if v["loss_pct"] > limit:
        return fault(f"production flow loss {v['loss_pct']}% (SLO {limit}%, baseline {v.get('baseline_loss_pct')}%), coverage {cov}%",
                     Finding("F-flow-loss", "Measured production-flow loss above SLO", "svc", ctx.src, "H-impact", False, 0.9,
                             "prioritize containment; this loss may predate any remediation, do not attribute causality without proof"),
                     "service impact is measured, independent of config conformity", **v)
    return ok(f"production flow loss {v['loss_pct']}% within SLO {limit}% (coverage {cov}%)", "flow healthy", **v)


def hc28(ctx: Ctx) -> Result:
    paths = corr.intended_paths(ctx.intent["links"], ctx.src, ctx.dst, limit=4)
    main = {h["device"] for h in ctx.path_fwd}
    alts = [p for p in paths if {h["device"] for h in p} != main]
    prefix = _prefix(ctx, "dst")
    rib_alts = []
    for dev in _l3(ctx):
        o = ctx.opt("route.rib", dev, prefix)
        if o is not None and o.value.get("alternates"):
            rib_alts.append({"device": dev, "alternates": o.value["alternates"]})
    ctx.use_intent("intent")
    if not rib_alts and ctx.view.each("route.rib") == []:
        return inconclusive("no RIB observation: alternate-path eligibility unknown", "cannot assess failover")
    eligible = bool(alts) and bool(rib_alts)
    return ok(("existing alternate path via " + "/".join(h["device"] for h in alts[0]) + " with backup RIB entries") if eligible else
              "no pre-existing alternate path with backup routes was found", ("eligible as a mitigation CANDIDATE only; capacity and zero-loss are NOT proven" if eligible else
              "a drain/reroute must be refused: redundancy is not invented"), eligible=eligible, lossless_proven=False, alternates=[[h["device"] for h in p] for p in alts], rib_alternates=rib_alts)


# --------------------------------------------------------------------------------------------------------------------- catalogue
def _t(i, title, layer, hyp, expected, fn, **kw):
    return TestSpec(f"HC{i:02d}", title, layer, hyp, expected, fn, **kw)


HC_TESTS: tuple[TestSpec, ...] = (
    _t(1, "Service definition, protocol/port and last-known-good", "SVC", "H-svc", "production contract defined; worked-before determinable", hc01, cls=CONTEXT, condition="service is new or has regressed", sources=("slo", "history")),
    _t(2, "Recent approved/unauthorized changes and golden soak", "CTRL", "H-change", "no unapproved change precedes onset", hc02, cls=CONTEXT, after=("HC01",), condition="a change preceded the onset", sources=("changes", "configs", "golden")),
    _t(3, "Source host NIC admin/oper and carrier", "L1", "H-l1", "NIC up with carrier", hc03, condition="source NIC down", sources=("interface.admin_state", "interface.oper_state")),
    _t(4, "Optics/cable/PHY/speed/duplex/autoneg", "L1", "H-l1", "speed/duplex agree, DOM within thresholds", hc04, condition="PHY mismatch or optics degradation", sources=("interface.speed", "interface.duplex", "interface.transceiver")),
    _t(5, "CRC/FCS/input/output/error/discard rate", "L1", "H-l1", "error rates at baseline; resets excluded", hc05, condition="framing/error burst", sources=("interface.rate.in_crc_errors", "interface.counter_reset")),
    _t(6, "Source IP/IPv6 address, prefix, VRF binding", "L3", "H-addr", "address in intended prefix and VRF", hc06, condition="wrong host addressing", sources=("host.address", "intent")),
    _t(7, "DHCP lease / RA-SLAAC / DHCPv6", "L3", "H-addr", "lease BOUND with intended gateway", hc07, applies=hc07_applies, condition="provisioning failure", sources=("dhcp.lease",)),
    _t(8, "VLAN tagging, port mode, allowed VLANs", "L2", "H-l2", "access/trunk carry the host VLAN", hc08, applies=hc08_applies, condition="access/trunk mismatch", sources=("l2.port",)),
    _t(9, "MAC learning / aging / movement / flooding", "L2", "H-l2", "stable MAC table", hc09, applies=hc08_applies, condition="MAC flaps/flooding", sources=("mac.table",)),
    _t(10, "ARP/ND resolution and duplicate-address check", "L2", "H-addr", "gateway resolved, no duplicates", hc10, condition="resolution failure", sources=("arp.entry",)),
    _t(11, "Gateway virtual protocol / first hop state", "L3", "H-addr", "exactly one FHRP master", hc11, applies=hc11_applies, condition="FHRP split/none", sources=("fhrp.state",)),
    _t(12, "Maintenance / decommission / isolation state", "CTRL", "H-svc", "no intentional disruption on path", hc12, cls=CONTEXT, condition="device in maintenance", sources=("maintenance.state",)),
    _t(13, "Interface, VRF and neighbor topology vs NetBox", "CTRL", "H-topology", "LLDP adjacency equals intent", hc13, condition="wrong attachment/cabling", sources=("lldp.neighbor", "intent")),
    _t(14, "Routing protocol neighbor state and last transitions", "L3", "H-routing", "adjacencies Full/Established", hc14, applies=hc14_applies, condition="adjacency down", sources=("routing.neighbor",)),
    _t(15, "Source and intermediate RIB for service prefix", "L3", "H-routing", "route present with intended next hop on every L3 hop", hc15, condition="route missing/diverted", sources=("route.rib",)),
    _t(16, "Source and intermediate FIB / adjacency / ECMP", "L3", "H-routing", "FIB agrees with RIB", hc16, applies=hc16_applies, requires=("HC15",), condition="forwarding installation discrepancy", sources=("route.fib",)),
    _t(17, "Bounded traceroute / path trace vs intended path", "L3", "H-routing", "trace reaches destination along intended path", hc17, after=("HC23",), condition="path discontinuity", sources=("path.trace",)),
    _t(18, "ACL / firewall / zone policies and counters", "L4", "H-policy", "no deny matches the production tuple", hc18, applies=hc18_applies, condition="directional filter blocks the flow", sources=("acl.counters",)),
    _t(19, "QoS classification, policing, shaping and queue drops", "L4", "H-qos", "no drops in the flow's class", hc19, applies=hc19_applies, condition="policer/queue impairs the flow", sources=("qos.state", "flow.health")),
    _t(20, "Congestion, utilization, microbursts", "L1", "H-cong", "utilization < 85%, no microburst", hc20, condition="queue overload", sources=("interface.utilization",)),
    _t(21, "MTU, DF/PMTUD and effective path MTU", "L3", "H-mtu", "path MTU carries the service payload", hc21, condition="size-dependent loss", sources=("interface.mtu", "path.pmtu")),
    _t(22, "TCP application handshake / L7 health", "L7", "H-impact", "authorised probes succeed within SLO", hc22, cls=CONTEXT, condition="production service impaired", sources=("service.probe",)),
    _t(23, "UDP/ICMP behaviour separately", "L4", "H-policy", "diagnostic protocols as intended", hc23, cls=CONTEXT, condition="diagnostic traffic blocked", sources=("service.probe",)),
    _t(24, "Stateful firewall, NAT, return path, asymmetry", "L4", "H-routing", "symmetric return path, sessions found", hc24, condition="return-path/stateful drop", sources=("route.rib", "firewall.session")),
    _t(25, "DNS resolution, cache and endpoint selection", "L7", "H-dns", "name resolves to the intended endpoint", hc25, applies=hc25_applies, condition="wrong/stale endpoint", sources=("dns.query",)),
    _t(26, "L2 STP/root/TCN/loop state", "L2", "H-l2", "stable root, TCN below threshold", hc26, applies=hc26_applies, condition="unstable forwarding/loop", sources=("stp.state",)),
    _t(27, "Production flow loss/latency/SLO", "SVC", "H-impact", "measured loss within SLO", hc27, cls=CONTEXT, condition="measurable production loss", sources=("flow.health",)),
    _t(28, "Redundant alternate path / failover eligibility (read-only)", "CTRL", "H-alt", "existing alternate path evaluated; never assumed lossless", hc28, cls=SAFETY, condition="mitigation candidates", sources=("route.rib", "intent")),
    _t(29, "Managed-device interface admin state vs intended configuration", "L1", "H-admin", "observed admin state matches intended configuration", hc29, applies=hc29_applies,
       condition="interface administratively disabled contrary to intent", sources=("interface.admin_state", "intent")),
)

HC_HYPOTHESES: tuple[Hypothesis, ...] = (
    Hypothesis("H-svc", "Service contract unknown or an intentional maintenance explains the symptom", "ops", ("HC01", "HC12"), 1),
    Hypothesis("H-impact", "The production service is genuinely impaired (not merely a diagnostic-protocol artefact)", "svc", ("HC22", "HC27"), 1),
    Hypothesis("H-change", "A recent change (approved or not) caused the symptom", "change", ("HC02",), 2),
    Hypothesis("H-admin", "Managed-device interface administratively disabled contrary to intended configuration", "L1", ("HC29",), 2),
    Hypothesis("H-l1", "Layer-1 fault at the source or on a path link (NIC, optics, cable, errors)", "L1", ("HC03", "HC04", "HC05"), 3),
    Hypothesis("H-addr", "Host addressing, provisioning, first-hop resolution or FHRP fault", "L3", ("HC06", "HC07", "HC10", "HC11"), 3),
    Hypothesis("H-l2", "Layer-2 fault: VLAN, MAC instability, STP loop", "L2", ("HC08", "HC09", "HC26"), 3),
    Hypothesis("H-topology", "Physical/logical attachment differs from NetBox intent", "topology", ("HC13",), 4),
    Hypothesis("H-routing", "Routing control or forwarding plane fault (neighbors, RIB, FIB, forward/return path)", "L3", ("HC14", "HC15", "HC16", "HC17", "HC24"), 3),
    Hypothesis("H-policy", "Directional ACL/firewall policy blocks the production flow", "policy", ("HC18", "HC23"), 2),
    Hypothesis("H-qos", "QoS policing/queueing drops the production class", "qos", ("HC19",), 4),
    Hypothesis("H-cong", "Congestion or microbursts on a path link", "L1/L2", ("HC20",), 5),
    Hypothesis("H-mtu", "MTU mismatch / PMTUD black hole", "L3", ("HC21",), 5),
    Hypothesis("H-dns", "Name resolution returns a wrong or no endpoint", "dns", ("HC25",), 5),
    Hypothesis("H-alt", "A pre-existing alternate path could contain the impact (mitigation, not cause)", "ctrl", ("HC28",), 9),
)

HC_ORDERS = {
    "follow-the-path": ("HC01", "HC02", "HC12", "HC27", "HC22", "HC23", "HC03", "HC04", "HC05", "HC06", "HC07", "HC08", "HC09", "HC10", "HC11", "HC13",
                        "HC14", "HC15", "HC16", "HC17", "HC24", "HC18", "HC19", "HC20", "HC21", "HC25", "HC26", "HC29", "HC28"),
    "top-down": ("HC01", "HC02", "HC12", "HC27", "HC22", "HC23", "HC25", "HC18", "HC19", "HC21", "HC24", "HC15", "HC16", "HC17", "HC14", "HC13", "HC11",
                 "HC10", "HC09", "HC08", "HC26", "HC06", "HC07", "HC20", "HC05", "HC04", "HC03", "HC29", "HC28"),
    "bottom-up": ("HC01", "HC02", "HC12", "HC27", "HC03", "HC04", "HC05", "HC20", "HC13", "HC06", "HC07", "HC08", "HC09", "HC26", "HC10", "HC11", "HC14",
                  "HC15", "HC16", "HC17", "HC24", "HC18", "HC19", "HC21", "HC25", "HC22", "HC23", "HC29", "HC28"),
    "divide-and-conquer": ("HC01", "HC02", "HC12", "HC27", "HC22", "HC23", "HC17", "HC15", "HC16", "HC24", "HC18", "HC19", "HC14", "HC13", "HC03", "HC04",
                           "HC05", "HC06", "HC07", "HC08", "HC09", "HC10", "HC11", "HC20", "HC21", "HC25", "HC26", "HC29", "HC28"),
}


def select_strategy(ctx: Ctx) -> tuple[str, str]:
    l1 = [a for a in ctx.alarms if a.get("kind") in corr.PHYSICAL_KINDS]
    n = len(ctx.path_fwd)
    if l1:
        return "bottom-up", f"{len(l1)} physical-layer alarm(s) on or near the path ({l1[0].get('device')}:{l1[0].get('interface')}): verify L1 first, then climb the stack"
    if n >= 8:
        return "divide-and-conquer", f"intended path has {n} devices: bisect with a path trace first, then test the failing half"
    if n >= 3:
        return "follow-the-path", (f"the intended {n}-device path is known from NetBox/topology and there is no physical alarm: walk it source to destination, "
                                   "service-level tests first, lower layers before policy at each hop")
    return "top-down", "short or unknown path: start from the application contract and descend"
