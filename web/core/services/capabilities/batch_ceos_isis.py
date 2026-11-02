"""cEOS IS-IS capability proof on the pre-existing disposable Ethernet2/peer eth2 pair."""

from __future__ import annotations

import json
import time
from copy import deepcopy

from django.utils import timezone

from ..config_import import parser_ceos
from ..execution.executors.base import APPLY, ConfigletSpec
from ..execution.executors.ceos import CeosExecutor, REJECTIONS
from ..health import live
from . import assessment
from .batch_frr_routing import _postcheck, _requirements
from .features import by_key
from .fixture_ceos_ssh import FixtureCeosSsh
from .isolated_live import LAB, NETWORK, _run
from .offline_verify import _descriptors
from .probe_cases import iface, sample

PEER = f"clab-{LAB}-peer"
NET = "49.0001.0000.0000.0044.00"
PEER_NET = "49.0001.0000.0000.0045.00"
PORT = "Ethernet2"
PEER_PORT = "eth2"
REMOTE_PREFIX = "198.51.100.0/24"
LOCAL_PREFIX = "203.0.113.0/24"


def _peer(*args):
    return _run(["docker", "exec", PEER, *args], timeout=45)


def _must_peer(*args):
    result = _peer(*args)
    if result.returncode:
        raise RuntimeError(f"Disposable FRR peer command failed: {args[0]}.")
    return result.stdout


def _vty(*commands):
    args = ["vtysh", "-c", "configure terminal"]
    for command in commands:
        args.extend(("-c", command))
    output = _must_peer(*args)
    if "% Unknown command" in output or "% Command incomplete" in output:
        raise RuntimeError("Disposable FRR IS-IS configuration was rejected.")


def _daemon_running(name):
    """The disposable container's PID 1 leaves zombies; they are not live routing daemons."""
    output = _must_peer("ps", "-eo", "stat=,comm=")
    return any(len(parts := line.split()) == 2 and parts[1] == name and not parts[0].startswith("Z")
               for line in output.splitlines())


def _eos(conn, lines):
    output = conn.send_config_set(lines, read_timeout=90, cmd_verify=True)
    if any(marker in output for marker in REJECTIONS):
        raise RuntimeError("Disposable cEOS rejected a fixture prerequisite or cleanup command.")


def _block(lines, header):
    start = lines.index(header)
    result = [header]
    for line in lines[start + 1:]:
        if line.strip() == "!":
            continue
        if not line.startswith(" "):
            break
        result.append(line)
    return result


def _specs():
    """Select only IS-IS lines from the real cEOS candidate renderer."""
    case = sample("arista_ceos", by_key()["routing.ISIS"])
    sections = deepcopy(case.sections)
    instance = next(iter(sections["routing"]["isis"].values()))
    instance.update(net=NET, level="LEVEL_2", address_family_ipv4=True, address_family_ipv6=False)
    primary = next(iter(sections["interfaces"].values()))
    primary["name"] = PORT
    lo = iface("arista_ceos", kind="LOOPBACK", iid="if_0000000000000002")
    lo["name"] = "Loopback444"
    sections["interfaces"][lo["id"]] = lo
    instance["interfaces"] = {
        "bind_0000000000000003": {"id": "bind_0000000000000003", "sequence": 1,
                                  "interface_id": primary["id"], "passive": False, "metric": 10},
        "bind_0000000000000004": {"id": "bind_0000000000000004", "sequence": 2,
                                  "interface_id": lo["id"], "passive": True, "metric": None},
    }
    rendered = _descriptors("arista_ceos", sections)
    process = _block(rendered, "router isis NMAS")
    bindings = []
    for name in (PORT, "Loopback444"):
        block = _block(rendered, f"interface {name}")
        bindings.append([block[0], *(line for line in block[1:] if line.strip().startswith("isis "))])
    if not all(len(lines) > 1 for lines in (process, *bindings)) or "   net " + NET not in process:
        raise RuntimeError("The NMAS IS-IS candidate lacks a process or interface binding.")
    data = [
        ("routing_isis", process, {"protocol": "isis"}),
        ("routing_binding", bindings[0], {"protocol": "isis", "interface": PORT, "passive": False, "metric": 10}),
        ("routing_binding", bindings[1], {"protocol": "isis", "interface": "Loopback444", "passive": True}),
    ]
    specs = [ConfigletSpec(f"P9-EOS-ISIS-{n}", 1, "ceos", "arista_ceos", kind, "CREATE_DEFINE", tuple(lines), facts)
             for n, (kind, lines, facts) in enumerate(data, 1)]
    return specs, case


def _imported(text, *, exact=True):
    parsed = parser_ceos.parse(text)
    rows = [r for r in parsed.routing_instances if r.family == "isis"]
    if len(rows) != 1:
        return False
    row = rows[0]
    bindings = {b.get("interface_name"): b for b in row.bindings}
    return row.fields == {"net": NET, "level": "LEVEL_2", "address_family_ipv4": True,
                          "address_family_ipv6": False} and not row.preserved_lines and \
        (not exact or (set(bindings) == {PORT, "Loopback444"} and bindings[PORT].get("metric") == 10
                       and not bindings[PORT].get("passive") and bindings["Loopback444"].get("passive")))


def _scenario():
    fixture = FixtureCeosSsh()
    device = fixture.device
    def reader(device_row):
        return live.read_device(device_row, session_factory=fixture.session)

    executor = CeosExecutor(device, connection_factory=lambda _device: fixture.conn, reader=reader)
    executor.connect()
    result = {"applied": False, "read_ok": False, "post_ok": False, "imported": False, "verified": False,
              "compensated": False, "config_restored": False, "restored": False, "control": False,
              "after": False, "actions": [], "statuses": [], "failure": ""}
    inspected = _run(["docker", "inspect", PEER], timeout=10)
    (peer_row,) = json.loads(inspected.stdout or "[null]")
    if not peer_row or peer_row["Config"]["Labels"].get("containerlab") != LAB or \
            NETWORK not in peer_row["NetworkSettings"]["Networks"] or not peer_row["State"]["Running"]:
        fixture.close()
        raise RuntimeError("The FRR peer is outside the running disposable lab.")
    baseline = executor._config_state_digest()
    peer_before = _must_peer("ip", "-j", "addr", "show", "dev", PEER_PORT)
    lo_before = _must_peer("ip", "-j", "addr", "show", "dev", "lo")
    mtu = json.loads(peer_before)[0]["mtu"]
    if "no ip routing" not in executor._config_text() or \
            executor._conn.send_command(f"show running-config interfaces {PORT}").strip() != f"interface {PORT}" or \
            "router isis NMAS" in executor._config_text() or "interface Loopback444" in executor._config_text() or \
            any(a["family"] == "inet" for i in json.loads(peer_before) for a in i["addr_info"]) or \
            any(a.get("local") == "198.51.100.1" for i in json.loads(lo_before) for a in i["addr_info"]):
        fixture.close()
        raise RuntimeError("cEOS IS-IS / FRR peer are not at the expected disposable baseline.")
    prep = {"eos": False, "mtu": False, "link": False, "loop": False, "zebra": False, "isisd": False, "peer": False}
    applied = []
    try:
        observed = reader(device)
        result["control"] = observed.live_reachable and not observed.facts("isis") and not any(
            r.get("prefix") == REMOTE_PREFIX for r in observed.facts("routes") or [])
        if not result["control"]:
            raise RuntimeError("IS-IS negative control failed before apply.")
        prep["eos"] = True
        _eos(fixture.conn, ["ip routing", "interface Ethernet2", "no switchport", "ip address 198.18.0.1/30", "no shutdown",
                            "exit", "interface Loopback444", "ip address 203.0.113.1/24"])
        if mtu != 1500:
            _must_peer("ip", "link", "set", "dev", PEER_PORT, "mtu", "1500"); prep["mtu"] = True
        _must_peer("ip", "addr", "add", "198.18.0.2/30", "dev", PEER_PORT); prep["link"] = True
        _must_peer("ip", "addr", "add", "198.51.100.1/24", "dev", "lo"); prep["loop"] = True
        if not _daemon_running("zebra"):
            _must_peer("/usr/lib/frr/zebra", "-d", "-u", "frr", "-g", "frr", "-A", "127.0.0.1")
            prep["zebra"] = True
        if not _daemon_running("isisd"):
            _must_peer("/usr/lib/frr/isisd", "-d", "-u", "frr", "-g", "frr", "-A", "127.0.0.1")
            prep["isisd"] = True
        prep["peer"] = True
        _vty("router isis NMAS44", f"net {PEER_NET}", "is-type level-2-only", "metric-style wide", "exit",
             "interface eth2", "ip router isis NMAS44", "exit", "interface lo", "ip router isis NMAS44")
        before_apply = executor._config_state_digest()
        specs, _ = _specs()
        preflights = [executor.assess(spec) for spec in specs]
        result["actions"] = [f"{spec.object_type}:{p.action}/{p.restorable}/{p.reason or '-'}" for spec, p in zip(specs, preflights)]
        if any(p.action != APPLY or not p.restorable for p in preflights):
            raise RuntimeError("The NMAS IS-IS executor refused a safe, reversible Configlet.")
        for spec, preflight in zip(specs, preflights):
            applied.append((spec, preflight))
            outcome = executor.apply(spec, preflight)
            if not outcome.ok:
                raise RuntimeError(f"NMAS IS-IS apply failed: {outcome.error_code}.")
        result["applied"] = True
        requirements = _requirements([
            ("isis-process", "ROUTING_PROCESS_INTENDED", {"protocol": "isis"}),
            ("isis-port", "ROUTING_INTERFACE_ENABLED", {"protocol": "isis", "interface": PORT, "metric": 10}),
            ("isis-route", "ISIS_ROUTE_INTENDED", {"prefix": REMOTE_PREFIX, "interfaces": [PORT]}),
        ], device="ceos")
        for _attempt in range(30):
            observed, post_ok, failures = _postcheck(device, requirements, session_factory=fixture.session)
            peer_route = _peer("vtysh", "-c", "show ip route isis")
            result["read_ok"] = observed.live_reachable and observed.group("isis").complete and observed.group("routes").complete
            result["post_ok"] = post_ok
            result["imported"] = _imported(executor._config_text())
            result["verified"] = post_ok and peer_route.returncode == 0 and LOCAL_PREFIX in peer_route.stdout
            if result["verified"] and result["imported"]:
                break
            time.sleep(2)
        if not result["verified"] or not result["imported"]:
            raise RuntimeError(f"IS-IS adjacency/route/import not proved: post={failures}, peer route={LOCAL_PREFIX in peer_route.stdout}, import={result['imported']}.")
    except Exception as exc:  # pylint: disable=broad-exception-caught  # a fixture failure is recorded, then cleaned
        result["failure"] = f"{type(exc).__name__}: {str(exc)[:300]}"
    finally:
        cleanup_errors = []

        def cleanup(label, action):
            try:
                action()
            except Exception as exc:  # pylint: disable=broad-exception-caught  # preserve every cleanup failure
                cleanup_errors.append(f"{label}: {type(exc).__name__}")

        try:
            for spec, preflight in reversed(applied):
                cleanup(spec.object_type, lambda spec=spec, preflight=preflight:
                        result["statuses"].append(executor.compensate(spec, preflight).status))
            result["compensated"] = bool(applied) and all(s == "COMPENSATED" for s in result["statuses"])
            if applied:
                cleanup("pre-apply readback", lambda: result.__setitem__("config_restored", executor._config_state_digest() == before_apply))
            if applied and not result["config_restored"] and prep["eos"]:
                cleanup("cEOS IS-IS emergency inverse", lambda: _eos(fixture.conn, ["interface Ethernet2", "no isis metric",
                        "no isis enable NMAS", "exit", "interface Loopback444", "no isis passive", "no isis enable NMAS",
                        "exit", "no router isis NMAS"]))
            if prep["peer"]:
                cleanup("peer IS-IS inverse", lambda: _vty("interface eth2", "no ip router isis NMAS44", "exit",
                        "interface lo", "no ip router isis NMAS44", "exit", "no router isis NMAS44"))
            if prep["loop"]: cleanup("peer loopback", lambda: _must_peer("ip", "addr", "del", "198.51.100.1/24", "dev", "lo"))
            if prep["link"]: cleanup("peer link", lambda: _must_peer("ip", "addr", "del", "198.18.0.2/30", "dev", PEER_PORT))
            if prep["mtu"]: cleanup("peer mtu", lambda: _must_peer("ip", "link", "set", "dev", PEER_PORT, "mtu", str(mtu)))
            if prep["isisd"]: _peer("pkill", "-x", "isisd")
            if prep["zebra"]: _peer("pkill", "-x", "zebra")
            if prep["eos"]:
                cleanup("cEOS prerequisite inverse", lambda: _eos(fixture.conn,
                        ["no router isis NMAS", "no interface Loopback444", "default interface Ethernet2", "no ip routing"]))
            final = reader(device)
            result["after"] = final.live_reachable and not final.facts("isis") and not any(
                r.get("prefix") == REMOTE_PREFIX for r in final.facts("routes") or [])
            result["restored"] = not cleanup_errors and result["after"] and executor._config_state_digest() == baseline and \
                _must_peer("ip", "-j", "addr", "show", "dev", PEER_PORT) == peer_before and \
                _must_peer("ip", "-j", "addr", "show", "dev", "lo") == lo_before
            if cleanup_errors:
                result["failure"] += "; cleanup=" + ", ".join(cleanup_errors)
        finally:
            fixture.close()
    if not result["restored"]:
        raise RuntimeError(f"Disposable cEOS IS-IS fixture did not restore exactly: {result['failure']}")
    return result


def probe_ceos_isis(cell):
    result = _scenario()
    reference = f"live:{LAB}/ceos-isis-ssh/{timezone.now().isoformat()}"
    detail = ("cEOS 4.36.2F / FRR 8.4.4 Ethernet2↔eth2; pinned, source-bound SSH via the verified disposable management "
              f"bridge; NMAS renderer + CeosExecutor: preflight={result['actions']}; compensation={result['statuses']}; "
              f"negative control={result['control']}; adjacency+routes={result['verified']}; import={result['imported']}; "
              f"postcheck={result['post_ok']}; exact pre-apply state={result['config_restored']}; full baseline={result['restored']}; "
              f"absence after compensation={result['after']}; failure={result['failure'] or 'none'}")
    for stage, ok, reason in (
        ("live_write", result["applied"], "FUNCTIONAL_TEST_FAILED"),
        ("live_read", result["read_ok"], "LIVE_READ_ABSENT"),
        ("live_post_write_validation", result["post_ok"], "POSTCHECK_ABSENT"),
        ("parser_import", result["imported"], "PARSER_ABSENT"),
        ("runtime_validation", result["verified"] and result["control"], "FUNCTIONAL_TEST_FAILED"),
        ("compensation", all(result[k] for k in ("compensated", "config_restored", "after", "restored")), "COMPENSATION_ABSENT"),
    ):
        cell.probes[stage] = assessment.probe("PASS" if ok else "FAIL", detail, reason="" if ok else reason,
                                             test_type="LIVE", reference=reference)
    cell.runtime_version = "ceos:4.36.2F / FRRouting 8.4.4"
