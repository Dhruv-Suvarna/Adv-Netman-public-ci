#!/usr/bin/env python3
"""Shielded static-IPv6 -> IS-IS migration, its rollback, and shielded maintenance drains on the DISPOSABLE isisbx sandbox.

usage: mig.py baseline <outdir> <seconds>
       mig.py migrate  <outdir> <cycles>           # each cycle: one complete forward migration + one complete rollback
       mig.py drain    <outdir> <cycles> [plain]   # each cycle: R1 drain, R1 restore, R2 drain, R2 restore
Refuses any container that does not carry the label nmas-sandbox=isisbx.
"""
import difflib, hashlib, json, os, subprocess, sys, time

P = "isisbx"
WEB4, WEB6 = "172.30.50.10", "2001:db8:3050::10"
AGG = "2001:db8::/32"
SHIELD_AGG = ("2001:db8::/33", "2001:db8:8000::/33")                       # exactly the pair proven on 2026-10-10
CLIENTS = ("2001:db8:10::/64", "2001:db8:20::/64", "2001:db8:30::/64")
# Router shield.  "less" (default): ONE less-specific /63 under each client /64 -- it forwards only while the /64 is being
# replaced, and installing or removing it never touches a route that is carrying traffic.  "more": the /65 pair, kept for
# comparison only: deleting an in-use /65 drops packets on cEOS-lab (measured 2026-10-11).
RSHIELD = os.environ.get("RSHIELD", "less")
SHIELD_CLIENT = {p: ((p.replace("::/64", "::/63"),) if RSHIELD == "less" else (p.replace("::/64", "::/65"), p.replace("::/64", ":0:8000::/65"))) for p in CLIENTS}
ROUTERS = {  # name: access interface (sandbox cabling), switch address on it, anchors, NET
    "r1": dict(acc="Ethernet3", peer="2001:db8:110:1::2", net="49.0110.1921.6825.5001.00",
               anchors=("2001:db8:100:103::2", "2001:db8:100:104::2", WEB6)),
    "r2": dict(acc="Ethernet3", peer="2001:db8:110:2::2", net="49.0110.1921.6825.5002.00",
               anchors=("2001:db8:100:101::2", "2001:db8:100:102::2", WEB6)),
}
SWITCHES = {  # name: router address on the uplink, VLAN99 address, the other switch's VLAN99 address, NET
    "s1": dict(up="2001:db8:110:1::1", v99="2001:db8:110:3::1/64", far="2001:db8:110:3::2", net="49.0110.1921.6825.5011.00", svi6=".2"),
    "s2": dict(up="2001:db8:110:2::1", v99="2001:db8:110:3::2/64", far="2001:db8:110:3::1", net="49.0110.1921.6825.5012.00", svi6=".3"),
}
SIDES = (("s1", "r1"), ("s2", "r2"))
SVIS = ("Vlan10", "Vlan20", "Vlan30")
HOSTS = {"h1": ("192.168.10.102", "2001:db8:10::102"), "h2": ("192.168.20.101", "2001:db8:20::101"),
         "h3": ("192.168.10.103", "2001:db8:10::103"), "h4": (None, "2001:db8:30::104")}
I6, I6R, I4, IDIAG = (os.environ.get(k, v) for k, v in (("I6", "0.01"), ("I6R", "0.02"), ("I4", "0.1"), ("IDIAG", "0.1")))
ALL = ("pe", "c3", "c4", "r1", "r2", "s1", "s2", "h1", "h2", "h3", "h4", "web")


def sh(*args, inp=None, timeout=120):
    return subprocess.run(args, input=inp, capture_output=True, text=True, timeout=timeout)


def guard():
    for n in ALL:
        if sh("docker", "inspect", "-f", '{{index .Config.Labels "nmas-sandbox"}}', f"{P}-{n}").stdout.strip() != P:
            sys.exit(f"{P}-{n} is not a disposable sandbox container")


def cli(dev, command):
    return sh("docker", "exec", f"{P}-{dev}", "Cli", "-p", "15", "-c", command).stdout


def conf(dev, lines):
    out = sh("docker", "exec", "-i", f"{P}-{dev}", "Cli", "-p", "15", inp="configure\n" + "\n".join(lines) + "\nend\n").stdout
    bad = [line for line in out.splitlines() if line.startswith("%")]
    if bad:
        raise RuntimeError(f"{dev}: {bad} for {lines}")


def kern(dev, *args):
    return sh("docker", "exec", f"{P}-{dev}", *args).stdout


def hx(host, command, detach=False):
    return sh("docker", "exec", "-u", "0", *(["-d"] if detach else []), f"{P}-{host}", "sh", "-c", command).stdout


class Run:
    def __init__(self, out):
        self.out = out
        os.makedirs(out, exist_ok=True)
        self.events = open(os.path.join(out, "events.log"), "a", buffering=1)

    def ev(self, *words):
        line = f"{time.time():.3f} " + " ".join(str(w) for w in words)
        self.events.write(line + "\n")
        print(line, flush=True)


# ---------------------------------------------------------------- reads
def find(obj, key):
    if isinstance(obj, dict):
        if key in obj:
            return obj[key]
        for value in obj.values():
            hit = find(value, key)
            if hit is not None:
                return hit
    return None


def route(dev, prefix):
    """(routeType, sorted interfaces, sorted next hops) of the exact prefix, or None."""
    try:
        data = json.loads(cli(dev, f"show ipv6 route {prefix} | json"))
    except ValueError:
        return None
    entry = find(data.get("routes", data), prefix)
    if not entry:
        return None
    vias = entry.get("vias", [])
    return (entry.get("routeType"), sorted({v.get("interface", "") for v in vias}), sorted({v.get("nexthopAddr", "") for v in vias}),
            bool(entry.get("hardwareProgrammed")) and bool(entry.get("kernelProgrammed")))


def lookup(dev, address):
    """Longest match for an address: (prefix, routeType, interfaces)."""
    data = json.loads(cli(dev, f"show ipv6 route {address} | json"))
    routes = data.get("routes") or find(data, "routes") or {}
    for prefix, entry in routes.items():
        return prefix, entry.get("routeType"), sorted({v.get("interface", "") for v in entry.get("vias", [])})
    return None


def isis_neighbors(dev):
    data = json.loads(cli(dev, "show isis neighbors | json") or "{}")
    found = []

    def walk(obj):
        if isinstance(obj, dict):
            if "interfaceName" in obj and "state" in obj:
                found.append((obj["interfaceName"], obj["state"]))
            for value in obj.values():
                walk(value)
        elif isinstance(obj, list):
            for value in obj:
                walk(value)
    walk(data)
    return sorted(found)


def running(dev):
    return "\n".join(line for line in cli(dev, "show running-config").splitlines() if not line.startswith("! ") and line.strip())


def digest(text):
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def wait(what, check, timeout=90, poll=1.0):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = check()
        if last is True:
            return
        time.sleep(poll)
    raise RuntimeError(f"TIMEOUT waiting for {what}: last={last}")


# ---------------------------------------------------------------- shield
def shield_lines(dev, no=""):
    if dev in SWITCHES:
        return [f"{no}ipv6 route {p} {SWITCHES[dev]['up']}" for p in SHIELD_AGG]
    return [f"{no}ipv6 route {half} {ROUTERS[dev]['peer']}" for p in CLIENTS for half in SHIELD_CLIENT[p]]


def shield_prefixes(dev):
    return list(SHIELD_AGG) if dev in SWITCHES else [half for p in CLIENTS for half in SHIELD_CLIENT[p]]


def shield_nexthop(dev):
    return SWITCHES[dev]["up"] if dev in SWITCHES else ROUTERS[dev]["peer"]


def shield_on(run, dev, tag, nexthop=None, prefixes=None):
    nh = nexthop or shield_nexthop(dev)
    prefixes = prefixes or shield_prefixes(dev)
    # the alternate next hop must answer before anything is pointed at it (also resolves it in the kernel table)
    if "2 received" not in kern(dev, "ping", "-6", "-c", "2", "-i", "0.2", "-W", "1", nh):
        raise RuntimeError(f"{dev}: shield next hop {nh} does not answer")
    run.ev(tag, "shield-install", dev, nh)
    conf(dev, [f"ipv6 route {p} {nh}" for p in prefixes])

    def ok():
        for p in prefixes:
            r = route(dev, p)
            if not r or r[0] != "static" or nh not in r[2] or any("Management" in i for i in r[1]) or not r[3]:
                return f"{p}: {r}"
            if nh not in kern(dev, "ip", "-6", "route", "show", p):
                return f"{p}: not in the kernel table"
        return True
    wait(f"{dev} shield installed", ok, 20, 0.5)
    run.ev(tag, "shield-verified", dev)


KDEV = {"Ethernet1": "eth1", "Ethernet3": "eth3", "Vlan99": "vlan99"}
PRERESOLVE = os.environ.get("PRERESOLVE", "1") == "1"
DEMOTE = os.environ.get("DEMOTE", "1") == "1"


def takeover_ready(run, dev, tag, covered):
    """The route that takes over when the shield goes must be programmed AND its next hop must already be a resolved
    neighbour: the first packet to an unresolved next hop is dropped while the neighbour is being discovered."""
    for prefix in covered:
        r = route(dev, prefix)
        if not r or not r[3] or any("Management" in i for i in r[1]):
            raise RuntimeError(f"{dev}: take-over route {prefix} is not programmed: {r}")
        for hop, interface in zip(r[2], r[1]):
            k = KDEV[interface]
            target = f"{hop}%{k}" if hop.startswith("fe80") else hop
            before = kern(dev, "ip", "-6", "neigh", "show", hop, "dev", k).strip()
            if PRERESOLVE:
                if "2 received" not in kern(dev, "ping", "-6", "-c", "2", "-i", "0.2", "-W", "1", target):
                    raise RuntimeError(f"{dev}: take-over next hop {target} does not answer")
                after = kern(dev, "ip", "-6", "neigh", "show", hop, "dev", k).strip()
                if not any(state in after for state in ("REACHABLE", "DELAY", "STALE", "PERMANENT")):
                    raise RuntimeError(f"{dev}: take-over next hop {target} is not a resolved neighbour: {after!r}")
            else:
                after = before
            run.ev(tag, "takeover-nexthop", dev, prefix, r[0], target, "before=" + (before.split()[-1] if before else "NONE"),
                   "after=" + (after.split()[-1] if after else "NONE"))


def shield_off(run, dev, tag, nexthop=None, prefixes=None):
    nh = nexthop or shield_nexthop(dev)
    prefixes = prefixes or shield_prefixes(dev)
    takeover_ready(run, dev, tag, [AGG] if dev in SWITCHES else list(CLIENTS))
    run.ev(tag, "shield-remove", dev)
    conf(dev, [f"no ipv6 route {p} {nh}" for p in prefixes])
    wait(f"{dev} shield gone", lambda: all(route(dev, p) is None and not kern(dev, "ip", "-6", "route", "show", p).strip() for p in prefixes) or "still present", 20, 0.5)
    run.ev(tag, "shield-removed", dev)


def no_shield_anywhere():
    for dev in (*SWITCHES, *ROUTERS):
        text = running(dev)
        if "/33 " in text or "/65 " in text or "/63 " in text or any(l.startswith("ipv6 route ") and l.endswith(" 250") for l in text.splitlines()):
            return f"{dev} still holds a shield route"
    return True


# ---------------------------------------------------------------- forward migration (stages of the brief)
def forward(run, c):
    t = f"F{c}"
    run.ev(t, "stage1 vlan99-ipv6+isis start")
    for s, d in SWITCHES.items():
        conf(s, ["interface Vlan99", f"   ipv6 address {d['v99']}"])
    for dev, d in (*ROUTERS.items(), *SWITCHES.items()):
        conf(dev, ["router isis NMAS", f"   net {d['net']}", "   is-type level-2", "   address-family ipv6 unicast"])
    for r, d in ROUTERS.items():
        conf(r, [f"interface {d['acc']}", "   isis enable NMAS", "   isis metric 10"])
    for s in SWITCHES:
        conf(s, ["interface Ethernet1", "   isis enable NMAS", "   isis metric 10", "interface Vlan99", "   isis enable NMAS", "   isis metric 10"])
    run.ev(t, "stage2 adjacencies wait")
    want = {"r1": [("Ethernet3", "up")], "r2": [("Ethernet3", "up")], "s1": [("Ethernet1", "up"), ("Vlan99", "up")], "s2": [("Ethernet1", "up"), ("Vlan99", "up")]}
    wait("IS-IS adjacencies", lambda: all(isis_neighbors(dev) == nb for dev, nb in want.items()) or {dev: isis_neighbors(dev) for dev in want}, 120, 2)
    run.ev(t, "stage3 advertise start")
    for s in SWITCHES:
        conf(s, [line for svi in SVIS for line in (f"interface {svi}", "   isis enable NMAS", "   isis passive")])
    for r, d in ROUTERS.items():
        conf(r, ["ipv6 prefix-list ACCESS6-NORTHBOUND-AGG", f"   seq 10 permit {AGG}",
                 "route-map ISIS6-TO-OSPF3 permit 10", "   match ipv6 address prefix-list CLIENT-V6", "   set tag 6200",
                 "route-map STATIC6-TO-ISIS6 permit 10", "   match ipv6 address prefix-list ACCESS6-NORTHBOUND-AGG",
                 *(f"ipv6 route {AGG} {a}" for a in d["anchors"])])
        wait(f"{r} aggregate anchored", lambda r=r: (route(r, AGG) or ("",))[0] == "static" or route(r, AGG), 30)
        conf(r, ["router isis NMAS", "   address-family ipv6 unicast", "      redistribute static route-map STATIC6-TO-ISIS6"])
        conf(r, ["ipv6 router ospf 10", "   distance ospf external 130", "   redistribute isis level-2 route-map ISIS6-TO-OSPF3"])
    run.ev(t, "stage4 isis-available wait (static still owns)")

    def available():
        for s, r in SIDES:
            if AGG not in cli(s, "show isis database detail"):
                return f"{s}: aggregate not in the IS-IS database"
            lsdb = cli(r, "show isis database detail")
            if any(p not in lsdb for p in CLIENTS):
                return f"{r}: client prefixes not in the IS-IS database"
            if (route(s, AGG) or ("",))[0] != "static" or any((route(r, p) or ("",))[0] != "static" for p in CLIENTS):
                return f"{s}/{r}: static no longer owns the old routes"
        return True
    wait("IS-IS routes available", available, 90, 2)
    time.sleep(3)
    for s, r in SIDES:                                    # one side at a time: the other router keeps every prefix advertised
        tag = f"{t}-{r}"
        run.ev(tag, "stage5 shield")
        shield_on(run, s, tag)
        shield_on(run, r, tag)
        run.ev(tag, "stage6 shield-forwarding verify")
        hit = lookup(s, WEB6)
        if not hit or hit[0] != SHIELD_AGG[0] or any("Management" in i for i in hit[2]):
            raise RuntimeError(f"{s}: lookup of the service does not use the shield: {hit}")
        for cover in shield_prefixes(r):                  # a less-specific cover is a fall-back: it must be programmed toward the switch
            got = route(r, cover)
            if not got or got[0:2] != ("static", ["Ethernet3"]) or not got[3]:
                raise RuntimeError(f"{r}: shield {cover} is not programmed toward the switch: {got}")
        for h in ("2001:db8:10::102", "2001:db8:20::101", "2001:db8:30::104"):
            hit = lookup(r, h)
            if not hit or hit[2] != ["Ethernet3"] or (RSHIELD == "more" and not hit[0].endswith("/65")):
                raise RuntimeError(f"{r}: lookup of {h} is not toward the switch: {hit}")
        time.sleep(3)
        run.ev(tag, "stage7 static-removal start")
        conf(s, [f"no ipv6 route {AGG} {SWITCHES[s]['up']}"])
        run.ev(tag, "stage7 switch-static-removed")
        peer = ROUTERS[r]["peer"]
        if DEMOTE:
            # Deleting the only static of a prefix withdraws the router's OSPFv3 external LSA for 5 s (measured): the core then
            # replaces its client routes twice.  With a floating copy (distance 250) present the static source never goes
            # away: deleting the distance-1 route is then a best-path change to IS-IS (115) and the core sees nothing.
            conf(r, [f"ipv6 route {p} {peer} 250" for p in CLIENTS])
            run.ev(tag, "stage7 router-floating-statics-added")
            time.sleep(2)
            conf(r, [f"no ipv6 route {p} {peer} 1" for p in CLIENTS])
            run.ev(tag, "stage7 router-statics-removed")
            wait(f"{r} clients by IS-IS", lambda r=r: all((route(r, p) or ("", []))[0:2] == ("isisL2", ["Ethernet3"]) for p in CLIENTS) or [route(r, p) for p in CLIENTS], 60)
            time.sleep(2)
            conf(r, [f"no ipv6 route {p} {peer} 250" for p in CLIENTS])
            run.ev(tag, "stage7 router-floating-statics-removed")
        else:
            conf(r, [f"no ipv6 route {p} {peer}" for p in CLIENTS])
            run.ev(tag, "stage7 router-statics-removed")
        conf(r, ["ipv6 router ospf 10", "   no redistribute static route-map STATIC6-TO-OSPF", "no route-map STATIC6-TO-OSPF permit 10"])
        run.ev(tag, "stage9 isis-ownership wait")
        wait(f"{s} aggregate by IS-IS", lambda s=s: (route(s, AGG) or ("", []))[0:2] == ("isisL2", ["Ethernet1"]) or route(s, AGG), 60)
        wait(f"{r} clients by IS-IS", lambda r=r: all((route(r, p) or ("", []))[0:2] == ("isisL2", ["Ethernet3"]) for p in CLIENTS) or [route(r, p) for p in CLIENTS], 60)
        time.sleep(5)
        run.ev(tag, "stage10 shield-removal")
        shield_off(run, r, tag)
        shield_off(run, s, tag)
        run.ev(tag, "stage11 final-forwarding verify")
        hit = lookup(s, WEB6)
        if not hit or hit[0] != AGG or hit[1] != "isisL2" or hit[2] != ["Ethernet1"]:
            raise RuntimeError(f"{s}: final lookup of the service is {hit}")
        for h, p in (("2001:db8:10::102", CLIENTS[0]), ("2001:db8:20::101", CLIENTS[1]), ("2001:db8:30::104", CLIENTS[2])):
            hit = lookup(r, h)
            if not hit or hit[0] != p or hit[1] != "isisL2" or hit[2] != ["Ethernet3"]:
                raise RuntimeError(f"{r}: final lookup of {h} is {hit}")
        time.sleep(3)
    ok = no_shield_anywhere()
    if ok is not True:
        raise RuntimeError(ok)
    run.ev(t, "stage12 final-config", " ".join(f"{dev}={digest(running(dev))}" for dev in (*ROUTERS, *SWITCHES)))


# ---------------------------------------------------------------- complete rollback, the same stages in reverse
def rollback(run, c):
    t = f"B{c}"
    for s, r in reversed(SIDES):
        tag = f"{t}-{r}"
        run.ev(tag, "rb1 shield")
        shield_on(run, s, tag)
        shield_on(run, r, tag)
        time.sleep(3)
        run.ev(tag, "rb2 static-restore start")
        conf(r, ["route-map STATIC6-TO-OSPF permit 10", "   match ipv6 address prefix-list CLIENT-V6",
                 "ipv6 router ospf 10", "   redistribute static route-map STATIC6-TO-OSPF"])
        conf(r, [f"ipv6 route {p} {ROUTERS[r]['peer']}" for p in CLIENTS])
        run.ev(tag, "rb2 router-statics-restored")
        conf(s, [f"ipv6 route {AGG} {SWITCHES[s]['up']}"])
        run.ev(tag, "rb2 switch-static-restored")
        wait(f"{s} aggregate static", lambda s=s: (route(s, AGG) or ("", []))[0:2] == ("static", ["Ethernet1"]) or route(s, AGG), 60)
        wait(f"{r} clients static", lambda r=r: all((route(r, p) or ("", []))[0:2] == ("static", ["Ethernet3"]) for p in CLIENTS) or [route(r, p) for p in CLIENTS], 60)
        time.sleep(5)
        run.ev(tag, "rb3 shield-removal")
        shield_off(run, r, tag)
        shield_off(run, s, tag)
        time.sleep(3)
    run.ev(t, "rb4 withdraw-advertisements start")
    for r, d in ROUTERS.items():
        conf(r, ["ipv6 router ospf 10", "   no redistribute isis level-2 route-map ISIS6-TO-OSPF3", "   no distance ospf external 130"])
        conf(r, ["router isis NMAS", "   address-family ipv6 unicast", "      no redistribute static route-map STATIC6-TO-ISIS6"])
        conf(r, [*(f"no ipv6 route {AGG} {a}" for a in d["anchors"]), "no route-map STATIC6-TO-ISIS6 permit 10",
                 "no route-map ISIS6-TO-OSPF3 permit 10", "no ipv6 prefix-list ACCESS6-NORTHBOUND-AGG"])
    for s in SWITCHES:
        conf(s, [line for svi in SVIS for line in (f"interface {svi}", "   no isis passive", "   no isis enable")])
    run.ev(t, "rb5 isis-removal start")
    for r, d in ROUTERS.items():
        conf(r, [f"interface {d['acc']}", "   no isis metric", "   no isis enable"])
    for s in SWITCHES:
        conf(s, ["interface Ethernet1", "   no isis metric", "   no isis enable", "interface Vlan99", "   no isis metric", "   no isis enable"])
    for dev in (*ROUTERS, *SWITCHES):
        conf(dev, ["no router isis NMAS"])
    for s, d in SWITCHES.items():
        conf(s, ["interface Vlan99", f"   no ipv6 address {d['v99']}"])
    ok = no_shield_anywhere()
    if ok is not True:
        raise RuntimeError(ok)
    run.ev(t, "rb6 baseline-config", " ".join(f"{dev}={digest(running(dev))}" for dev in (*ROUTERS, *SWITCHES)))


# ---------------------------------------------------------------- maintenance drain by metric, shielded
def steer(run, tag, s, metric, nexthop, expect_if, plain):
    if not plain:
        shield_on(run, s, tag, nexthop, SHIELD_AGG)
        time.sleep(3)
    run.ev(tag, "metric", s, metric)
    conf(s, ["interface Ethernet1", f"   isis metric {metric}"])
    wait(f"{s} aggregate via {expect_if}", lambda: (route(s, AGG) or ("", []))[0:2] == ("isisL2", [expect_if]) or route(s, AGG), 60, 0.5)
    run.ev(tag, "path", s, expect_if)
    time.sleep(5)
    if not plain:
        shield_off(run, s, tag, nexthop, SHIELD_AGG)
    hit = lookup(s, WEB6)
    if not hit or hit[0] != AGG or hit[2] != [expect_if]:
        raise RuntimeError(f"{s}: lookup after {tag} is {hit}")
    run.ev(tag, "verified", s, expect_if, kern(s, "ip", "-6", "route", "show", AGG).split("dev")[-1].split()[0])


def drain_cycle(run, c, plain):
    for s, r in SIDES:
        d = SWITCHES[s]
        steer(run, f"D{c}-{r}-drain", s, 1000, d["far"], "Vlan99", plain)
        time.sleep(4)
        steer(run, f"D{c}-{r}-restore", s, 10, d["up"], "Ethernet1", plain)
        time.sleep(4)


# ---------------------------------------------------------------- traffic
def pings_start(diag=True):
    for h, (v4, v6) in HOSTS.items():
        hx(h, "mkdir -p /tmp/t && rm -f /tmp/t/p*.log")
        hx(h, f"ping -6 -D -O -i {I6} {WEB6} > /tmp/t/p6.log 2>&1", detach=True)
        if v4:
            hx(h, f"ping -4 -D -O -i {I4} {WEB4} > /tmp/t/p4.log 2>&1", detach=True)
    hx("web", "mkdir -p /tmp/t && rm -f /tmp/t/p*.log")
    for h, (v4, v6) in HOSTS.items():
        hx("web", f"ping -6 -D -O -i {I6R} -I {WEB6} {v6} > /tmp/t/p6_{h}.log 2>&1", detach=True)
        if v4:
            hx("web", f"ping -4 -D -O -i {I4} -I {WEB4} {v4} > /tmp/t/p4_{h}.log 2>&1", detach=True)
    if diag:   # device-originated: kernel routing table, not the forwarding plane.  Diagnostic, reported separately.
        for s, d in SWITCHES.items():
            src = f"2001:db8:10::{2 if s == 's1' else 3}"
            sh("docker", "exec", "-d", f"{P}-{s}", "bash", "-c", f"ping -6 -D -O -i {IDIAG} -I {src} {WEB6} > /tmp/diag.log 2>&1")
        for r, d in ROUTERS.items():
            dst = f"2001:db8:10::{2 if r == 'r1' else 3}"
            sh("docker", "exec", "-d", f"{P}-{r}", "bash", "-c", f"ping -6 -D -O -i {IDIAG} {dst} > /tmp/diag.log 2>&1")


def pings_stop(out):
    os.makedirs(out, exist_ok=True)
    for h in (*HOSTS, "web"):
        hx(h, "pkill -INT ping; sleep 0.3")
    for dev in (*SWITCHES, *ROUTERS):
        sh("docker", "exec", f"{P}-{dev}", "pkill", "-INT", "ping")
    time.sleep(0.5)
    for h, (v4, v6) in HOSTS.items():
        for fam in ("6", "4") if v4 else ("6",):
            open(f"{out}/{h}_fwd{fam}.log", "w").write(hx(h, f"cat /tmp/t/p{fam}.log"))
            open(f"{out}/{h}_rev{fam}.log", "w").write(hx("web", f"cat /tmp/t/p{fam}_{h}.log"))
    for dev in (*SWITCHES, *ROUTERS):
        open(f"{out}/diag_{dev}.log", "w").write(kern(dev, "cat", "/tmp/diag.log"))


def sessions_start():
    for h, (v4, v6) in HOSTS.items():
        hx(h, "mkdir -p /tmp/t && rm -f /tmp/t/tcp*.log /tmp/t/http*.log; pkill -f '[t]cp_long.py'; pkill -f '[h]ttp_loop.py'; true")
        for fam, dst in (("6", WEB6), ("4", WEB4)):
            if fam == "4" and not v4:
                continue
            hx(h, f"python3 /tools/tcp_long.py {dst} /tmp/t/tcp{fam}.log", detach=True)
            hx(h, f"python3 /tools/http_loop.py {dst} /tmp/t/http{fam}.log", detach=True)


def sessions_stop(out):
    for h in HOSTS:
        hx(h, "pkill -TERM -f '[t]cp_long.py'; pkill -TERM -f '[h]ttp_loop.py'; sleep 4")
    for h, (v4, v6) in HOSTS.items():
        for fam in ("6", "4") if v4 else ("6",):
            for kind in ("tcp", "http"):
                open(f"{out}/{h}_{kind}{fam}.log", "w").write(hx(h, f"cat /tmp/t/{kind}{fam}.log"))


def monitors(start, out=None):
    for dev in ("pe", "c3", "c4", "r1", "r2", "s1", "s2"):
        if start:
            sh("docker", "exec", "-d", f"{P}-{dev}", "bash", "-c", "ip -ts -6 monitor route > /tmp/mon.log 2>&1")
        else:
            sh("docker", "exec", f"{P}-{dev}", "pkill", "-f", "ip -ts -6 monitor")
            open(f"{out}/mon_{dev}.log", "w").write(kern(dev, "cat", "/tmp/mon.log"))


def load():
    return open("/proc/loadavg").read().split()[0:3]


def reset():
    """Put the four access devices back on their saved baseline (startup-config).  Sandbox only."""
    guard()
    for dev in (*ROUTERS, *SWITCHES):
        print(dev, [l for l in cli(dev, "configure replace startup-config").splitlines() if l.strip()][-1:], digest(running(dev)))


def main():
    if sys.argv[1] == "reset":
        return reset()
    mode, out, n = sys.argv[1], sys.argv[2], int(sys.argv[3])
    plain = "plain" in sys.argv[4:]
    guard()
    run = Run(out)
    run.ev("START", mode, n, "load", *load())
    base = {dev: running(dev) for dev in (*ROUTERS, *SWITCHES)}
    for dev, text in base.items():
        open(f"{out}/{dev}.start.cfg", "w").write(text + "\n")
    run.ev("CONFIG start", " ".join(f"{dev}={digest(text)}" for dev, text in base.items()))
    monitors(True)
    sessions_start()
    time.sleep(3)
    failed = None
    try:
        if mode == "baseline":
            pings_start()
            time.sleep(n)
            pings_stop(f"{out}/c01")
        for c in range(1, n + 1) if mode != "baseline" else ():
            cdir = f"{out}/c{c:02d}"
            pings_start()
            time.sleep(4)
            run.ev(f"C{c}", "begin", "load", *load())
            if mode == "migrate":
                forward(run, c)
                final = {dev: running(dev) for dev in base}
                if c == 1:
                    for dev, text in final.items():
                        open(f"{out}/{dev}.final.cfg", "w").write(text + "\n")
                        open(f"{out}/{dev}.final.diff", "w").write("\n".join(difflib.unified_diff(base[dev].splitlines(), text.splitlines(), "baseline", "final", lineterm="", n=1)) + "\n")
                    first_final = final
                run.ev(f"F{c}", "final-equals-first-final", all(final[dev] == first_final[dev] for dev in base))
                time.sleep(6)
                run.ev(f"C{c}", "between forward and rollback")
                rollback(run, c)
                back = {dev: running(dev) for dev in base}
                same = {dev: back[dev] == base[dev] for dev in base}
                run.ev(f"B{c}", "baseline-restored", all(same.values()), same if not all(same.values()) else "")
                if not all(same.values()):
                    for dev in base:
                        open(f"{cdir}.{dev}.rollback.diff", "w").write("\n".join(difflib.unified_diff(base[dev].splitlines(), back[dev].splitlines(), lineterm="")))
                    raise RuntimeError("rollback did not restore the baseline configuration")
            else:
                drain_cycle(run, c, plain)
            time.sleep(5)
            run.ev(f"C{c}", "end", "load", *load())
            pings_stop(cdir)
    except Exception as exc:                                # keep the evidence; the sandbox is left as it is for inspection
        failed = exc
        run.ev("FAILED", type(exc).__name__, str(exc)[:600])
        try:
            pings_stop(f"{out}/failed")
        except Exception:
            pass
    sessions_stop(out)
    monitors(False, out)
    run.ev("END", "failed" if failed else "ok", "load", *load())
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
