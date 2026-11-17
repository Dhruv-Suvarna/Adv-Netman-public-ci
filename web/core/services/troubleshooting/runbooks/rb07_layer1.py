"""RB07 -- Layer 1 physical and framing degradation.  Distinguishes optics, FEC and cabling faults and refuses to read a counter reset as health or fault."""

from __future__ import annotations

from .. import correlation as corr
from .base import CONTEXT, SAFETY, Ctx, Finding, Hypothesis, Result, Runbook, TestSpec, fault, inconclusive, ok

CRC_ABS = 0.5


def _t(ctx):
    t = ctx.case["target"]
    return t["device"], t["interface"]


def _peer(ctx):
    dev, ifn = _t(ctx)
    ln = corr.find_link(ctx.intent.get("links", []), dev, ifn)
    if ln is None:
        return None, None
    return (ln["b"], ln.get("b_if")) if ln["a"] == dev and ln.get("a_if") == ifn else (ln["a"], ln.get("a_if"))


def ph01(ctx: Ctx) -> Result:
    dev, ifn = _t(ctx)
    rst = ctx.opt("interface.counter_reset", dev, ifn)
    if rst is not None and rst.value.get("reset"):
        return inconclusive(f"counters on {dev}:{ifn} were reset at {rst.value.get('at')}: zeroed error counters are NOT evidence of a healthy link", "error signature cannot be assessed after a reset")
    stats = ctx.baselines.get("history", {}).get("stats", {})
    hot = {}
    for k in ("in_crc_errors", "in_fcs_errors", "in_align_errors", "in_runts", "in_giants", "in_los", "in_lof"):
        o = ctx.opt(f"interface.rate.{k}", dev, ifn)
        if o is None:
            continue
        b = stats.get(f"interface.rate.{k}@{dev}@{ifn}", {})
        normal = b.get("median") if b.get("state") == "LEARNED" else None
        if o.value > CRC_ABS and (normal is None or o.value > 3 * max(normal, 0.05)):
            hot[k] = {"rate": o.value, "normal": normal}
    ev = ctx.opt("interface.l1_events", dev, ifn)
    los = [e for e in (ev.value.get("events", []) if ev else []) if e.get("kind") in ("LOS", "LOF")]
    if not ctx.used:
        ctx.need("interface.rate.in_crc_errors", dev, ifn)
    ctx.use_intent("history")
    if hot or los:
        return fault(f"{dev}:{ifn} error signature {hot} LOS/LOF events {len(los)}", Finding("F-l1-signature", "Framing/signal errors above baseline", "L1", dev, "H-signature", False, 0.7, "determine the physical cause with PH03-PH06"), "framing errors are established; cause is not", signature=hot, los_lof=len(los))
    return ok("framing counters at baseline, no LOS/LOF", "no L1 error signature", checked=True)


def ph02(ctx: Ctx) -> Result:
    dev, ifn = _t(ctx)
    r = ctx.need("interface.counter_reset", dev, ifn)
    if r.value.get("reset"):
        return inconclusive(f"counters on {dev}:{ifn} were reset/cleared at {r.value.get('at')} (by {r.value.get('by', 'unknown')}): pre-reset history is gone, current deltas cover only {r.value.get('seconds_since', '?')} s", "a counter reset is not evidence of recovery nor of fault; trend inconclusive")
    return ok("monotonic counters, no reset/wrap in the window", "counter trend valid", **r.value)


def ph03(ctx: Ctx) -> Result:
    dev, ifn = _t(ctx)
    pdev, pif = _peer(ctx)
    a, b = ctx.need("interface.transceiver", dev, ifn), ctx.opt("interface.transceiver", pdev, pif) if pdev else None
    probs = []
    for o, n in ((a, dev), (b, pdev)):
        if o is not None and o.value.get("supported") is False:
            probs.append(f"{n} transceiver {o.value.get('part')} not supported/coded for this platform")
    if b is not None and a.value.get("type") != b.value.get("type"):
        probs.append(f"transceiver type mismatch {a.value.get('type')} vs {b.value.get('type')}")
    if b is not None and a.value.get("wavelength_nm") != b.value.get("wavelength_nm"):
        probs.append(f"wavelength mismatch {a.value.get('wavelength_nm')} vs {b.value.get('wavelength_nm')} nm")
    if probs:
        return fault("; ".join(probs), Finding("F-transceiver", "Incompatible or unsupported transceivers", "L1", dev, "H-optics", True, 0.9, "replace with a compatible pair (external physical work)"), problems=probs)
    return ok(f"both ends: {a.value.get('type')} {a.value.get('wavelength_nm')} nm, supported and matched", "transceiver identity compatible", a=a.value.get("part"), b=b.value.get("part") if b else None)


def ph04(ctx: Ctx) -> Result:
    dev, ifn = _t(ctx)
    pdev, pif = _peer(ctx)
    probs, n = [], 0
    for d, i in ((dev, ifn), (pdev, pif)):
        if not d:
            continue
        t = ctx.opt("interface.transceiver", d, i)
        if t is None:
            continue
        n += 1
        v = t.value
        for k, lo, hi, label in (("rx_dbm", "rx_low_warn", "rx_high_warn", "Rx power"), ("tx_dbm", "tx_low_warn", "tx_high_warn", "Tx power"), ("temp_c", None, "temp_high_warn", "temperature")):
            val = v.get(k)
            if val is None:
                continue
            if lo and v.get(lo) is not None and val < v[lo]:
                probs.append(f"{d}:{i} {label} {val} below warning {v[lo]}")
            if hi and v.get(hi) is not None and val > v[hi]:
                probs.append(f"{d}:{i} {label} {val} above warning {v[hi]}")
    if not n:
        ctx.need("interface.transceiver", dev, ifn)
    if probs:
        return fault("; ".join(probs), Finding("F-dom", "Optical DOM outside thresholds", "L1", dev, "H-optics", True, 0.85, "clean connectors, then replace optic/fibre (external work); no port bounce"), "DOM readings are direct measurements of the optical budget", problems=probs)
    return ok(f"DOM within warning thresholds on {n} end(s)", "optical budget fine", ends=n)


def ph05_applies(ctx: Ctx):
    return (bool(ctx.intent.get("cables", {}).get("%s:%s" % _t(ctx))), "NetBox has no cable type/length record for this interface")


def ph05(ctx: Ctx) -> Result:
    dev, ifn = _t(ctx)
    cab = ctx.intent["cables"][f"{dev}:{ifn}"]
    t = ctx.need("interface.transceiver", dev, ifn)
    ctx.use_intent("intent")
    reach = t.value.get("reach_m")
    if reach is not None and cab["length_m"] > reach:
        return fault(f"cable {cab['type']} {cab['length_m']} m exceeds transceiver reach {reach} m", Finding("F-reach", "Cable longer than the optic supports", "L1", dev, "H-cable", True, 0.85), cable=cab, reach=reach)
    if cab["type"] in ("cat5", "cat5e") and t.value.get("speed_mbps", 0) >= 10000:
        return fault(f"{cab['type']} cannot reliably carry {t.value['speed_mbps']} Mb/s", Finding("F-cable-class", "Cable category too low for the speed", "L1", dev, "H-cable", True, 0.8), cable=cab)
    return ok(f"{cab['type']} {cab['length_m']} m within reach {reach} m", "media within design limits", cable=cab, reach=reach)


def ph06(ctx: Ctx) -> Result:
    dev, ifn = _t(ctx)
    pdev, pif = _peer(ctx)
    a, b = ctx.need("interface.fec", dev, ifn), ctx.need("interface.fec", pdev, pif)
    sp = (ctx.opt("interface.speed", dev, ifn), ctx.opt("interface.speed", pdev, pif))
    dx = (ctx.opt("interface.duplex", dev, ifn), ctx.opt("interface.duplex", pdev, pif))
    probs = []
    if a.value.get("mode") != b.value.get("mode"):
        probs.append(f"FEC mode mismatch {dev}={a.value.get('mode')} {pdev}={b.value.get('mode')}")
    if all(sp) and sp[0].value != sp[1].value:
        probs.append(f"speed mismatch {sp[0].value}/{sp[1].value}")
    if all(dx) and dx[0].value != dx[1].value:
        probs.append(f"duplex mismatch {dx[0].value}/{dx[1].value}")
    unc = max(a.value.get("uncorrected", 0), b.value.get("uncorrected", 0))
    if probs:
        return fault("; ".join(probs) + f"; uncorrected codewords {unc}", Finding("F-fec", "FEC/speed/duplex mismatch causes framing errors with an otherwise healthy optic", "L1", dev, "H-neg", True, 0.9,
                     "align FEC (or speed) to the golden value through an approved change; physical parts need not be replaced"), "link can stay up with a FEC mismatch while corrupting frames", problems=probs, uncorrected=unc)
    if unc > 0:
        return fault(f"FEC modes agree but {unc} uncorrected codewords: the signal is marginal", Finding("F-fec-uncorrected", "Uncorrectable FEC errors on a matching configuration", "L1", dev, "H-optics", False, 0.6), uncorrected=unc)
    return ok(f"FEC {a.value.get('mode')} on both ends, no uncorrected codewords", "negotiation consistent", fec=a.value.get("mode"))


def ph07(ctx: Ctx) -> Result:
    dev, ifn = _t(ctx)
    ed = ctx.opt("interface.errdisable", dev, ifn)
    al = ctx.opt("component.alarm", dev, "")
    bad = []
    if ed is not None and ed.value.get("reason"):
        bad.append(f"errdisable {ed.value['reason']}")
    if al is not None and al.value.get("alarms"):
        bad.append(f"component alarms {al.value['alarms']}")
    if ed is None and al is None:
        ctx.need("component.alarm", dev, "")
    if bad:
        return fault("; ".join(bad), Finding("F-platform-alarm", "Platform/driver/power/thermal alarm on the device", "L1", dev, "H-platform", False, 0.6), problems=bad)
    return ok("no errdisable, driver, power or thermal alarm", "platform healthy")


def ph08(ctx: Ctx) -> Result:
    dev, ifn = _t(ctx)
    ctx.use_intent("intent")
    lag = ctx.intent.get("lag", {}).get(f"{dev}:{ifn}")
    members = []
    if lag:
        for key, name in ctx.intent["lag"].items():
            if name == lag:
                d, i = key.split(":")
                o = ctx.opt("lacp.member", d, i)
                members.append({"member": key, "state": o.value.get("state") if o else "unknown"})
    link = corr.find_link(ctx.intent["links"], dev, ifn)
    alt = corr.intended_paths([l for l in ctx.intent["links"] if l is not link], link["a"], link["b"], limit=2) if link else []
    downstream = sorted(set(corr._reach(corr.build_graph(ctx.intent["links"]), ctx.case["target"].get("vantage", link["a"])) - corr._reach(corr.build_graph(ctx.intent["links"]), ctx.case["target"].get("vantage", link["a"]), corr._lk(link)))) if link else []
    return ok(f"blast radius: downstream devices if this link goes away {downstream or 'none (redundant)'}; LAG members {members or 'n/a'}; alternate path {'exists' if alt else 'none'}",
              "informational: determines whether physical work needs a maintenance window; losslessness is not claimed", downstream=downstream, lag_members=members, alternate_exists=bool(alt), lossless_proven=False)


def ph09(ctx: Ctx) -> Result:
    dev, ifn = _t(ctx)
    pdev, pif = _peer(ctx)
    for d_, i_ in ((dev, ifn), (pdev, pif)):
        r_ = ctx.opt("interface.counter_reset", d_, i_)
        if r_ is not None and r_.value.get("reset"):
            return inconclusive(f"counters on {d_}:{i_} were reset; per-direction error rates are not comparable", "direction cannot be localised after a counter reset")
    a_rx = ctx.opt("interface.rate.in_crc_errors", dev, ifn)
    b_rx = ctx.opt("interface.rate.in_crc_errors", pdev, pif)
    if a_rx is None or b_rx is None:
        return inconclusive("one end's receive-error counter was not collected", "direction of the fault cannot be localised")
    ctx.opt("interface.transceiver", dev, ifn)   # local optic: cited as evidence (opt() records what the test consulted)
    tb = ctx.opt("interface.transceiver", pdev, pif)   # the peer transmitter is what the Rx-low verdict names
    a_bad, b_bad = a_rx.value > CRC_ABS, b_rx.value > CRC_ABS
    if a_bad and not b_bad:
        sus = f"{pdev} transmitter / fibre direction {pdev}->{dev}" + (f" (peer Tx {tb.value.get('tx_dbm')} dBm)" if tb and tb.value.get("tx_dbm") is not None else "")
        return fault(f"errors only on {dev} Rx ({a_rx.value}/s); {pdev} Rx clean -> suspect {sus}", Finding("F-direction", "One-directional fault localised to the peer's transmit path", "L1", pdev, "H-optics", True, 0.8,
                     "replace/clean the peer's optic or the fibre strand it drives"), "only one direction is corrupted: a two-sided cause (e.g. duplex) is unlikely", rx_errors={dev: a_rx.value, pdev: b_rx.value})
    if b_bad and not a_bad:
        return fault(f"errors only on {pdev} Rx ({b_rx.value}/s); {dev} Rx clean", Finding("F-direction", f"One-directional fault: {dev} transmit path", "L1", dev, "H-optics", True, 0.8), rx_errors={dev: a_rx.value, pdev: b_rx.value})
    if a_bad and b_bad:
        return fault("errors on both receivers -> shared medium/negotiation (FEC/speed/duplex, cable) rather than one transmitter", Finding("F-bidir", "Two-directional errors", "L1", dev, "H-neg", False, 0.6), rx_errors={dev: a_rx.value, pdev: b_rx.value})
    return ok("neither receiver shows errors", "no physical errors to localise", rx_errors={dev: a_rx.value, pdev: b_rx.value})


RB07 = Runbook(
    id="RB07", name="layer1-physical-framing", version="1.0.0", title="Layer 1 physical and framing degradation", doc="RB07-layer1.md", test_prefixes=("PH",),
    purpose="Separate optics, cable, FEC/negotiation and platform causes of framing errors; never act on counters that were reset.",
    tests=(
        TestSpec("PH01", "CRC/FCS/align/runt/giant/LOS/LOF vs baseline", "L1", "H-signature", "framing counters at baseline", ph01, cls=CONTEXT, command="interface.rate.*", condition="framing error signature", sources=("interface.rate.in_crc_errors", "interface.l1_events", "history")),
        TestSpec("PH02", "Counter reset / wrap detection", "L1", "H-counters", "counters monotonic, no reset", ph02, cls=CONTEXT, command="interface.counter_reset", condition="counter reset invalidates the trend", sources=("interface.counter_reset",)),
        TestSpec("PH03", "Both ends' transceiver identity and compatibility", "L1", "H-optics", "supported, matched transceivers", ph03, command="interface.transceiver", condition="incompatible optics", sources=("interface.transceiver",)),
        TestSpec("PH04", "DOM thresholds (Rx/Tx power, temperature)", "L1", "H-optics", "DOM within thresholds", ph04, command="interface.transceiver", condition="optical budget exceeded", sources=("interface.transceiver",)),
        TestSpec("PH05", "Cable type/length vs optic reach", "L1", "H-cable", "media within limits", ph05, applies=ph05_applies, command="intent.cables+transceiver", condition="media beyond design", sources=("intent", "interface.transceiver")),
        TestSpec("PH06", "Speed / FEC / duplex negotiation (both ends)", "L1", "H-neg", "FEC, speed, duplex agree", ph06, command="interface.fec+speed+duplex", condition="negotiation mismatch", sources=("interface.fec", "interface.speed", "interface.duplex")),
        TestSpec("PH07", "Errdisable, driver, power and thermal alarms", "L1", "H-platform", "no platform alarm", ph07, command="interface.errdisable+component.alarm", condition="platform alarm", sources=("interface.errdisable", "component.alarm")),
        TestSpec("PH08", "Port-channel member health and blast radius", "CTRL", "H-blast", "blast radius evaluated (read-only)", ph08, cls=SAFETY, command="intent+lacp.member", condition="intervention impact", sources=("intent", "lacp.member")),
        TestSpec("PH09", "Direction localisation: peer receive errors and Tx power", "L1", "H-optics", "no one-directional fault", ph09, after=("PH04",), command="interface.rate.in_crc_errors(both)", condition="one-directional fault", sources=("interface.rate.in_crc_errors", "interface.transceiver")),
    ),
    hypotheses=(
        Hypothesis("H-signature", "A framing/signal error signature exists", "L1", ("PH01",), 1),
        Hypothesis("H-counters", "Counters were reset or wrapped, so the trend cannot be trusted", "L1", ("PH02",), 1),
        Hypothesis("H-optics", "Optics fault or incompatibility (transceiver, DOM, direction)", "L1", ("PH03", "PH04", "PH09"), 2),
        Hypothesis("H-cable", "Cable/media beyond design", "L1", ("PH05",), 3),
        Hypothesis("H-neg", "FEC/speed/duplex negotiation mismatch", "L1", ("PH06",), 2),
        Hypothesis("H-platform", "Platform, driver, power or thermal alarm", "system", ("PH07",), 4),
        Hypothesis("H-blast", "Blast radius of an intervention", "ctrl", ("PH08",), 9),
    ),
    orders={"bottom-up": ("PH02", "PH01", "PH03", "PH04", "PH05", "PH06", "PH07", "PH09", "PH08"),
            "divide-and-conquer": ("PH02", "PH01", "PH09", "PH06", "PH03", "PH04", "PH05", "PH07", "PH08")},
    select_strategy=lambda ctx: (("divide-and-conquer", "both ends are observable: split the fault by direction before examining parts") if _peer(ctx)[0] else ("bottom-up", "peer unknown: verify the local physical layer first")),
    remediations={
        "F-transceiver": {"tier": 2, "action": "replace with a compatible transceiver pair", "approvals": ["operator acknowledgement of physical intervention", "maintenance window or proof of alternate path"], "pre_tests": ["PH03", "PH08"], "post_tests": ["PH01", "PH04", "PH06"],
                          "rollback": "reinstall original", "never": ["blind port bounce", "clear counters to hide errors"]},
        "F-dom": {"tier": 2, "action": "clean connectors, then replace optic/fibre", "approvals": ["operator acknowledgement", "maintenance window"], "pre_tests": ["PH04", "PH09", "PH08"], "post_tests": ["PH01", "PH04"], "rollback": "reinstall original", "never": ["blind port bounce"]},
        "F-direction": {"tier": 2, "action": "replace the transmitter/fibre strand of the faulty direction", "approvals": ["operator acknowledgement"], "pre_tests": ["PH09", "PH08"], "post_tests": ["PH01", "PH09"], "rollback": "reinstall original", "never": ["blind port bounce"]},
        "F-fec": {"tier": 2, "action": "align FEC (or speed) with the golden/intent value", "approvals": ["operator approval", "traffic-safety proof: the port flaps on renegotiation"], "pre_tests": ["PH06", "PH08"], "post_tests": ["PH01", "PH06"],
                  "rollback": "restore previous FEC setting", "never": ["port bounce as a fix"]},
        "F-reach": {"tier": 2, "action": "move to a longer-reach optic or shorter run", "approvals": ["operator acknowledgement"], "pre_tests": ["PH05"], "post_tests": ["PH01", "PH04"], "rollback": "reinstall original", "never": []},
    },
)
