"""Scenario builders for the deterministic-engine tests (SIMULATED / replay data -- never live evidence).

``rb02_lab()`` is a rich healthy lab for host connectivity:  h1 -- sw1 -- r1 -- r2 -- h2   with an alternate r1 -- r3 -- r2.
Every fault is an *override* of one or two observations of that healthy baseline, so a fault/recovery pair differs in exactly the injected fault.
"""

from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone

T0 = datetime(2026, 11, 9, 12, 0, tzinfo=timezone.utc)
PROVENANCE = "SIMULATED"          # carried in every raw header by ReplayProvider
DEVICES = ["h1", "sw1", "r1", "r2", "h2", "r3"]


def iso(t):
    return t.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _links():
    L = lambda i, a, ai, b, bi: {"id": i, "a": a, "a_if": ai, "b": b, "b_if": bi}
    return [L("c1", "h1", "eth0", "sw1", "Eth1"), L("c2", "sw1", "Eth2", "r1", "Eth1"), L("c3", "r1", "Eth2", "r2", "Eth1"),
            L("c4", "r2", "Eth2", "h2", "eth0"), L("c5", "r1", "Eth3", "r3", "Eth1"), L("c6", "r3", "Eth2", "r2", "Eth3")]


def intent():
    return {"nodes": [{"name": "h1", "role": "host"}, {"name": "sw1", "role": "switch"}, {"name": "r1", "role": "router"}, {"name": "r2", "role": "router"},
                      {"name": "h2", "role": "host"}, {"name": "r3", "role": "router"}],
            "links": _links(), "expected_mtu": 1500,
            "hosts": {"h1": {"interface": "eth0", "prefix": "10.1.1.0/24", "vrf": "default", "addressing": "dhcp", "gateway": "10.1.1.1", "vlan": 10}},
            "fhrp": {"r1": {"group": 1}, "r3": {"group": 1}}, "routing": {"r1": [{"neighbor": "r2"}]},
            "services": {"dns_names": {"app.lab": "10.2.2.20"}}, "l2": {"stp": {"sw1": "rstp"}}, "acl_devices": ["r1"], "qos_devices": ["r1"],
            "intentionally_blocked": []}


FLOW = {"name": "web", "src": "h1", "dst": "h2", "protocol": "tcp", "port": 443, "src_ip": "10.1.1.10", "dst_ip": "10.2.2.20", "src_prefix": "10.1.1.0/24",
        "dst_prefix": "10.2.2.0/24", "vrf": "default", "af": "ipv4", "dst_name": "app.lab", "app_bytes": 1472}

ENDS = [("h1", "eth0"), ("sw1", "Eth1"), ("sw1", "Eth2"), ("r1", "Eth1"), ("r1", "Eth2"), ("r2", "Eth1"), ("r2", "Eth2"), ("h2", "eth0")]
PEER = {}
for _l in _links():
    PEER[(_l["a"], _l["a_if"])] = (_l["b"], _l["b_if"])
    PEER[(_l["b"], _l["b_if"])] = (_l["a"], _l["a_if"])


def history_series(now=T0, n=48):
    """Hourly samples for the last two days: CRC ~0, link transitions ~0 (a learned normal)."""
    out = {}
    for dev, ifn in ENDS:
        for key in ("interface.rate.in_crc_errors", "interface.rate.in_errors", "interface.rate.out_discards", "interface.rate.in_discards"):
            out[f"{key}@{dev}@{ifn}"] = [{"t": iso(now - timedelta(hours=i + 1)), "value": 0.0 if i % 7 else 0.01} for i in range(n)]
    return out


def static_data(now=T0, *, changes=None, diffs=None, soak=None, slo=None, golden_url="/bundles/12/"):
    configs = {"devices": {d: {"golden_hash": "g" * 40, "running_hash": "g" * 40, "diffs": []} for d in ("r1", "r2", "r3", "sw1")}}
    for d, df in (diffs or {}).items():
        configs["devices"][d]["diffs"] = df
        configs["devices"][d]["running_hash"] = "r" * 40
    return {"intent": intent(),
            "golden": {"revision": "golden-r7", "digest": "d" * 64, "url": golden_url, "created_at": iso(now - timedelta(days=9)), "approved_change_id": "CHG-100",
                       "previous_revision": "golden-r6", "previous_url": "/bundles/11/", "link_ok": True, "soak": soak},
            "history": {"lkg_at": iso(now - timedelta(hours=3)), "series": history_series(now), "revision": "hist-1"},
            "slo": {"contract": {"max_loss_pct": 1.0, "latency_ms_p95": 50, "intentionally_blocked": []}, "revision": "slo-3"},
            "changes": {"changes": changes or []}, "configs": configs}


def healthy_obs():
    """{(device, key, subject): value} -- every host-connectivity input in a healthy state."""
    o = {}
    d = lambda dev, key, sub, val: o.__setitem__((dev, key, sub), val)
    d("h1", "interface.admin_state", "eth0", "up"); d("h1", "interface.oper_state", "eth0", "up"); d("h1", "interface.carrier", "eth0", True)
    for dev, ifn in ENDS:
        d(dev, "interface.speed", ifn, 10000); d(dev, "interface.duplex", ifn, "full")
        d(dev, "interface.transceiver", ifn, {"supported": True, "part": "SFP-10G-SR", "rx_dbm": -2.1, "rx_low_alarm": -9.9})
        for k in ("in_crc_errors", "in_errors", "out_discards", "in_discards"):
            d(dev, f"interface.rate.{k}", ifn, 0.0)
        d(dev, "interface.counter_reset", ifn, {"reset": False})
        d(dev, "interface.utilization", ifn, {"in_pct": 22.0, "out_pct": 18.0, "microburst": False})
        d(dev, "interface.mtu", ifn, 1500)
        rd, ri = PEER[(dev, ifn)]
        d(dev, "lldp.neighbor", ifn, {"remote_device": rd, "remote_if": ri})
    d("h1", "host.address", "eth0", {"addresses": ["10.1.1.10/24"], "vrf": "default"})
    d("h1", "dhcp.lease", "eth0", {"state": "BOUND", "gateway": "10.1.1.1", "lease_remaining_s": 40000})
    d("sw1", "l2.port", "Eth1", {"mode": "access", "access_vlan": 10})
    d("sw1", "l2.port", "Eth2", {"mode": "trunk", "allowed_vlans": [10, 20]})
    d("sw1", "mac.table", "10", {"moves_per_min": 0, "flapping_macs": []})
    d("h1", "arp.entry", "10.1.1.1", {"state": "REACHABLE", "mac": "aa:bb:cc:00:00:01", "dup_macs": []})
    d("r1", "fhrp.state", "1", {"state": "master", "vip": "10.1.1.1"}); d("r3", "fhrp.state", "1", {"state": "backup", "vip": "10.1.1.1"})
    for dev in ("h1", "sw1", "r1", "r2", "h2"):
        d(dev, "maintenance.state", "", {"in_maintenance": False})
    d("r1", "routing.neighbor", "r2", {"state": "Full", "protocol": "ospf"})
    for dev, nh_f, nh_r in (("r1", "r2", "sw1"), ("r2", "h2", "r1")):
        d(dev, "route.rib", "10.2.2.0/24", {"present": True, "next_hop": f"nh-{nh_f}", "next_hop_device": nh_f, "alternates": ["r3"] if dev == "r1" else []})
        d(dev, "route.fib", "10.2.2.0/24", {"installed": True, "next_hop": f"nh-{nh_f}", "resolved": True})
        d(dev, "route.rib", "10.1.1.0/24", {"present": True, "next_hop": f"nh-{nh_r}", "next_hop_device": nh_r})
    d("h1", "path.trace", "h2", {"reached": True, "method": "tcp", "hop_devices": ["r1", "r2", "h2"], "last_hop": "h2"})
    d("r1", "acl.counters", "Eth1-in", {"acl": "EDGE-IN", "direction": "in", "sample_interval_s": 30, "rules": [
        {"seq": 10, "action": "permit", "proto": "tcp", "port": 443, "src": "10.1.1.0/24", "dst": "10.2.2.0/24", "hits": 5000, "prev_hits": 4900},
        {"seq": 100, "action": "permit", "proto": "ip", "hits": 40, "prev_hits": 39}]})
    # Normalized ``qos.attachment`` value (nmas.troubleshooting.qos-source/1 -> normalize_qos_state, SIMULATED): actual attachment direction, ordered match criteria
    # that provably cover the production tuple (tcp/443 10.1.1.0/24 -> 10.2.2.0/24), complete collection and two same-epoch counter samples with a zero drop delta.
    _qc = {"status": "OK", "reason": "", "samples": [{"at": "2026-11-09T11:59:00Z", "dropped": 100}, {"at": "2026-11-09T12:00:00Z", "dropped": 100}], "span_s": 60.0, "delta_dropped": 0}
    d("r1", "qos.state", "Eth2-out", {
        "interface": "Ethernet2", "direction": "out", "policy": "EDGE", "vrf": "default", "af": None, "complete": True, "uncertain": [],
        "classes": [
            {"name": "AF31", "order": 10, "match": {"protocol": "tcp", "ports": [443], "src": ["10.1.1.0/24"], "dst": ["10.2.2.0/24"]}, "match_complete": True,
             "unsupported": None, "action": None, "policer_bps": 1_000_000_000, "counters": copy.deepcopy(_qc), "notes": []},
            {"name": "class-default", "order": 99, "match": {"any": True}, "match_complete": True, "unsupported": None, "action": None, "policer_bps": None,
             "counters": copy.deepcopy(_qc), "notes": []}],
        "source": {"id": "sim-qos-agent", "kind": "qos-agent", "read_only": True, "api": "simulated qos read"}, "platform": "ceos", "os_version": "4.36.2F",
        "provenance": {"label": "SIMULATED", "collected_at": "2026-11-09T12:00:00Z"}})
    d("h1", "path.pmtu", "h2", {"max_ok": 1472, "ptb_received": False})
    d("h1", "service.probe", "tcp", {"sent": 20, "ok": 20, "rtt_ms_p50": 2.1})
    d("h1", "service.probe", "icmp", {"sent": 20, "ok": 20})
    d("h1", "dns.query", "app.lab", {"rcode": "NOERROR", "answers": ["10.2.2.20"], "ttl": 300})
    d("sw1", "stp.state", "10", {"tcn_count_1h": 0, "root_changes_24h": 0, "ports": [{"name": "Eth1", "role": "designated", "state": "forwarding"}]})
    d("h1", "flow.health", "web", {"loss_pct": 0.1, "coverage_pct": 92, "baseline_loss_pct": 0.1, "samples": []})
    return o


def apply(obs, overrides):
    """Return a deep copy with ``{(dev,key,sub): value | None}`` applied; ``None`` removes the observation (never collected)."""
    out = copy.deepcopy(obs)
    for k, v in overrides.items():
        if v is None:
            out.pop(k, None)
        else:
            out[k] = v
    return out


def to_fixture(obs, *, fixture_id, ages=None, missing=None, quality=None):
    """Group observations into per-device replay collections (ReplayProvider format)."""
    by_dev = {}
    for (dev, key, sub), val in obs.items():
        o = {"key": key, "subject": sub, "value": val}
        if ages and (dev, key, sub) in ages:
            o["age_s"] = ages[(dev, key, sub)]
        if quality and (dev, key, sub) in quality:
            o["quality"] = quality[(dev, key, sub)]
        by_dev.setdefault(dev, []).append(o)
    for (dev, key, sub), why in (missing or {}).items():
        by_dev.setdefault(dev, []).append({"key": key, "subject": sub, "missing": why})
    return {"fixture_id": fixture_id, "provenance": PROVENANCE,
            "collections": [{"device": dev, "command": f"replay:{dev}", "source_type": "cli", "adapter": "replay", "observations": obs_list, "raw": f"{dev} replay"}
                            for dev, obs_list in sorted(by_dev.items())]}


# ------------------------------------------------------------------------------------------------------------ other runbooks
def _merge_static(**over):
    d = static_data()
    d.update(over)
    return d


def rb01_obs(*, events=None, peer_events=None, reason="link-down", maint=False, crc=0.0, rx=-2.1):
    base = healthy_obs()
    o = {}
    ev = lambda n, why: {"window_s": 3600, "events": [{"at": iso(T0 - timedelta(minutes=50 - 8 * i)), "state": s, "reason": why} for i in range(n) for s in ("down", "up")]}
    o[("r1", "interface.link_event", "Eth2")] = ev(events or 0, reason)
    o[("r2", "interface.link_event", "Eth1")] = ev(peer_events or 0, reason)
    o[("r1", "maintenance.state", "")] = {"in_maintenance": maint}
    o[("r1", "interface.transceiver", "Eth2")] = {"supported": True, "rx_dbm": rx, "rx_low_alarm": -9.9}
    o[("r1", "interface.rate.in_crc_errors", "Eth2")] = crc
    o[("r1", "interface.error_samples", "Eth2")] = {"samples": ([{"at": iso(T0 - timedelta(minutes=50 - 8 * i, seconds=20)), "rate": crc} for i in range(events or 0)] if crc else [])}
    o[("r1", "interface.errdisable", "Eth2")] = {"reason": None}
    o[("r1", "syslog.system_events", "")] = {"events": []}
    o[("r1", "interface.counter_reset", "Eth2")] = {"reset": False}
    for k, v in o.items():
        base[k] = v
    return base


RB03_TARGET = {"device": "r1", "neighbor_device": "r2", "protocol": "ospf", "af": "ipv4", "vrf": "default", "interface": "Eth2", "neighbor_interface": "Eth1",
               "neighbor_address": "10.0.12.2", "expected_prefix": "10.2.2.0/24"}


def rb03_obs(*, proto="ospf", state="Full", a=None, b=None, last_error="", vrf_b="default"):
    cfg = {"area": "0.0.0.0", "network_type": "point-to-point", "stub": False, "timers": {"hello": 10, "dead": 40}, "auth": {"configured": True, "key_id": 1, "fingerprint": "fp-abc"}}
    if proto == "bgp":
        cfg = {"local_as": 65001, "neighbor_remote_as": 65002, "neighbor_vrf": "default", "neighbor_afs": ["ipv4"], "timers": {"keepalive": 60, "hold": 180}, "auth": {"configured": False}}
    ca, cb = {**cfg, **(a or {})}, {**cfg, **(b or {})}
    if proto == "bgp":
        cb.update({"local_as": 65002, "neighbor_remote_as": 65001, **(b or {})})
    o = {}
    for dev, ifn, cf, ip in (("r1", "Eth2", ca, "10.0.12.1/30"), ("r2", "Eth1", cb, "10.0.12.2/30")):
        o[(dev, "capability.protocol", proto)] = {"supported": True, "platform": "ceos"}
        o[(dev, "interface.oper_state", ifn)] = "up"
        o[(dev, "interface.vrf", ifn)] = vrf_b if dev == "r2" else "default"
        o[(dev, "interface.address", ifn)] = {"ipv4": ip}
        o[(dev, "interface.mtu", ifn)] = 1500
        o[(dev, "protocol.config", proto)] = cf
        o[(dev, "protocol.interface", ifn)] = {"passive": False}
    o[("r1", "reach.transport", "10.0.12.2")] = {"tcp179_ok": True, "rtt_ms": 1.2}
    o[("r1", "routing.neighbor.detail", "r2")] = {"state": state, "last_error": last_error, "since_s": 600}
    o[("r1", "route.rib", "10.2.2.0/24")] = {"present": state in ("Full", "Established"), "protocol": proto, "next_hop": "10.0.12.2"}
    o[("r1", "route.fib", "10.2.2.0/24")] = {"installed": state in ("Full", "Established"), "next_hop": "10.0.12.2"}
    return o


def stp_intent(modes):
    sw = lambda n: {"name": n, "role": "switch"}
    L = lambda i, a, ai, b, bi: {"id": i, "a": a, "a_if": ai, "b": b, "b_if": bi}
    return {"nodes": [sw("sw1"), sw("sw2"), sw("sw3")], "links": [L("s1", "sw1", "Eth1", "sw2", "Eth1"), L("s2", "sw2", "Eth2", "sw3", "Eth1"), L("s3", "sw3", "Eth2", "sw1", "Eth2")],
            "l2": {"stp": modes, "stp_root": {"10": "32778.aaaa"}}}


def rb04_obs(*, loop=False, tcn=0, root_change=0, filt=False):
    o = {}
    for sw, ports in (("sw1", ["Eth1", "Eth2"]), ("sw2", ["Eth1", "Eth2"]), ("sw3", ["Eth1", "Eth2"])):
        pl = [{"name": p, "role": "designated", "state": "forwarding"} for p in ports]
        if not loop and sw == "sw3":
            pl[1] = {"name": "Eth2", "role": "alternate", "state": "blocking"}
        o[(sw, "stp.state", "10")] = {"root_id": "32778.aaaa", "tcn_count_1h": tcn if sw == "sw2" else 0, "last_tc_port": "Eth1", "root_changes_24h": root_change, "ports": pl}
        for p in ports:
            o[(sw, "stp.port_protection", p)] = {"bpdu_filter": bool(filt and sw == "sw3" and p == "Eth2"), "link_type": "inter-switch", "loop_guard": True, "bpdu_guard": True}
        o[(sw, "mac.table", "10")] = {"moves_per_min": 900 if loop else 0, "flapping_macs": ["aa:aa:aa:00:00:01"] if loop else []}
        o[(sw, "storm_control.state", "")] = {"broadcast_pps": 90000 if loop else 12, "threshold_pps": 5000}
    for l in stp_intent({})["links"]:
        o[(l["a"], "lldp.neighbor", l["a_if"])] = {"remote_device": l["b"], "remote_if": l["b_if"]}
        o[(l["b"], "lldp.neighbor", l["b_if"])] = {"remote_device": l["a"], "remote_if": l["a_if"]}
    return o


RB05_TARGET = {"client": "c1", "name": "app.lab", "zone": "lab", "resolvers": ["10.0.0.53", "10.0.0.54"], "authoritative": ["ns1", "ns2"]}
RB05_DEVICES = ["c1", "ns1", "ns2"]


def rb05_intent():
    return {"nodes": [{"name": n, "role": "host"} for n in RB05_DEVICES], "links": [], "services": {"dns_names": {"app.lab": "10.2.2.20"}, "resolvers": ["10.0.0.53", "10.0.0.54"]}}


def rb05_obs(*, stale_ns2=False, cache_stale=False, refused=False):
    o = {("c1", "dns.resolver_config", "resolv"): {"nameservers": ["10.0.0.53", "10.0.0.54"], "search": ["lab"]},
         ("c1", "dns.delegation", "lab"): {"lame": []}, ("c1", "dns.records", "app.lab"): {"a": ["10.2.2.20"], "ptr": "app.lab", "cname": None},
         ("c1", "time.sync", ""): {"offset_ms": 3}}
    for r in RB05_TARGET["resolvers"]:
        o[("c1", "dns.transport", r)] = {"udp_ok": True, "tcp_ok": True, "acl_refused": refused and r == "10.0.0.54"}
        ans = {"rcode": "NOERROR", "answers": ["10.2.2.20"], "ttl": 120}
        if refused and r == "10.0.0.54":
            ans = {"rcode": "REFUSED", "answers": [], "ttl": 0}
        if cache_stale and r == "10.0.0.54":
            ans = {"rcode": "NOERROR", "answers": ["10.2.2.99"], "ttl": 240}
        o[("c1", "dns.query", f"app.lab/{r}")] = ans
    for ns in RB05_TARGET["authoritative"]:
        old = stale_ns2 and ns == "ns2"
        o[("c1", "dns.query", f"app.lab/{ns}")] = {"rcode": "NOERROR", "answers": ["10.2.2.99" if old else "10.2.2.20"], "aa": True, "ttl": 300}
        o[("c1", "dns.soa", f"lab/{ns}")] = {"serial": 2026110800 if old else 2026110901}
        o[(ns, "dns.xfr", "lab")] = {"last_result": "REFUSED (TSIG key mismatch)" if old else "ok"}
    return o
