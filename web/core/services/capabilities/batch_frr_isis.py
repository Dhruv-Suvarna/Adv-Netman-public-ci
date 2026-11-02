"""Reversible FRR IS-IS proof on the disposable FRR/FRR pair.

Only the DUT process and link binding are NMAS claims. The peer process and
connected-route advertisement are native lab prerequisites. Every claimed
write runs through LinuxExecutor with a captured-state inverse.
"""

from __future__ import annotations

import time
from copy import deepcopy

from django.utils import timezone

from ..config_import import parser_frr
from ..execution.executors.base import ConfigletSpec
from ..execution.executors.linux import LinuxExecutor
from ..health import live
from . import assessment
from .batch_frr_routing import FrrPair, _call, _postcheck, _requirements, _transaction
from .features import by_key
from .offline_verify import _descriptors
from .probe_cases import sample

KEY = "routing.ISIS"
NET = "49.0001.0000.0000.0044.00"
PEER_NET = "49.0001.0000.0000.0045.00"
PORT = "eth3"
PREFIX = "198.51.100.0/24"


def _block(rendered: list[str], header: str) -> list[str]:
    start = rendered.index(header)
    lines = [header]
    for line in rendered[start + 1:]:
        if not line.startswith(" "):
            break
        lines.append(line)
    return lines


def plan() -> tuple[list[ConfigletSpec], list, dict]:
    case = sample("ubuntu_frr", by_key()[KEY])
    sections = deepcopy(case.sections)
    instance = next(iter(sections["routing"]["isis"].values()))
    instance.update(net=NET, level="LEVEL_2", address_family_ipv4=True, address_family_ipv6=False)
    next(iter(sections["interfaces"].values()))["name"] = PORT
    binding = next(iter(instance["interfaces"].values()))
    binding["metric"] = 20
    rendered = _descriptors("ubuntu_frr", sections)
    process = _block(rendered, "router isis NMAS44")
    link = _block(rendered, f"interface {PORT}")
    if not any(line.strip() == f"net {NET}" for line in process) or not any(
        line.strip() == "ip router isis NMAS44" for line in link):
        raise RuntimeError("FRR IS-IS candidate lacks the NMAS process or link binding.")
    specs = [ConfigletSpec("P9-FRR-ISIS-1", 1, "frr", "ubuntu_frr", "routing_isis", "CREATE_DEFINE", tuple(process),
                           {"protocol": "isis"}),
             ConfigletSpec("P9-FRR-ISIS-2", 1, "frr", "ubuntu_frr", "routing_binding", "CREATE_DEFINE", tuple(link),
                           {"protocol": "isis", "interface": PORT, "passive": False, "metric": 20})]
    requirements = _requirements([
        ("process", "ROUTING_PROCESS_INTENDED", {"protocol": "isis"}),
        ("binding", "ROUTING_INTERFACE_ENABLED", {"protocol": "isis", "interface": PORT, "passive": False, "metric": 20}),
        ("route", "ISIS_ROUTE_INTENDED", {"prefix": PREFIX}),
    ])
    return specs, requirements, sections


def imported(text: str) -> bool:
    rows = [r for r in parser_frr.parse(text).routing_instances if r.family == "isis"]
    if len(rows) != 1:
        return False
    row = rows[0]
    return row.fields == {"net": NET, "level": "LEVEL_2", "address_family_ipv4": True,
                          "address_family_ipv6": False} and any(
        b.get("interface_name") == PORT and b.get("metric") == 20 and b.get("passive") is False
        for b in row.bindings)


def _quiet(pair: FrrPair) -> bool:
    neighbor = live.parse_frr_isis(pair.show(pair.fc, "show isis neighbor json"))
    route = _call(pair.fc, "ip", "route", "show", PREFIX).stdout
    return not neighbor and not route.strip()


def _wait(pair: FrrPair, *, up: bool, seconds: int = 45) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        neighbor = live.parse_frr_isis(pair.show(pair.fc, "show isis neighbor json"))
        route = _call(pair.fc, "ip", "route", "show", PREFIX).stdout
        if up and any(n["interface"] == PORT and n["state"] == "UP" for n in neighbor) and "proto isis" in route:
            return True
        if not up and not neighbor and not route.strip():
            return True
        time.sleep(1.5)
    return False


def _peer(pair: FrrPair) -> None:
    pair.vty(pair.pc, "router isis NMAS44", f"net {PEER_NET}", "is-type level-2-only", "metric-style wide",
             "redistribute ipv4 connected level-2", "exit", "interface eth1", "ip router isis NMAS44",
             "isis network point-to-point", "isis circuit-type level-2-only")


def _scenario(seed: bool) -> dict:
    specs, requirements, _sections = plan()
    pair = FrrPair(("isisd",))
    result = {"actions": [], "statuses": [], "failure": "", "imported": False, "control": False, "after": False,
              "preserved": True, "read_ok": False, "post_ok": False, "runtime_ok": False}
    executor = LinuxExecutor(pair.dut)
    try:
        if seed:
            pair.vty(pair.fc, "router isis NMAS44", f"net {NET}", "is-type level-2-only",
                     "redistribute ipv4 connected level-2")
        _peer(pair)
        before = pair.config(pair.fc)
        result["control"] = _quiet(pair)
        executor.connect()

        def verify():
            observed, post_ok, failed = _postcheck(pair.dut, requirements)
            text = executor._routing_config()  # the same captured live vtysh reader used by the executor
            result["imported"] = imported(text)
            result["read_ok"] = bool(observed.live_reachable)
            result["post_ok"] = post_ok
            result["runtime_ok"] = _wait(pair, up=True, seconds=2)
            peer_up = any(n["state"] == "UP" for n in live.parse_frr_isis(pair.show(pair.pc, "show isis neighbor json")))
            return post_ok and result["imported"] and result["runtime_ok"] and peer_up, (
                f"operator postcheck={post_ok} {failed}; parser import={result['imported']}; IS-IS neighbor and route="
                f"{result['runtime_ok']}; peer adjacency={peer_up}")

        result.update(_transaction(executor, specs, verify, attempts=30))
        result["config_restored"] = pair.config(pair.fc) == before
        result["preserved"] = not seed or "redistribute ipv4 connected level-2" in executor._routing_config()
        result["after"] = _wait(pair, up=False, seconds=30)
    except Exception as exc:  # pylint: disable=broad-exception-caught  # a live fixture failure is a failed probe
        result["failure"] = f"{type(exc).__name__}: {str(exc)[:400]}"
    finally:
        executor.close()
        result["restored"] = pair.close()
    return result


def probe_frr_isis(cell):
    scenarios = {"pristine": _scenario(False), "configured": _scenario(True)}
    reference = f"live:nmas-cap-validation/frr-isis/{timezone.now().isoformat()}"
    text = " || ".join(f"{name}: {row}" for name, row in scenarios.items())
    def every(*keys) -> bool:
        return all(row.get(key) for row in scenarios.values() for key in keys)
    for stage, okay, reason in (
        ("live_write", every("applied"), "FUNCTIONAL_TEST_FAILED"),
        ("live_read", every("read_ok"), "LIVE_READ_ABSENT"),
        ("live_post_write_validation", every("post_ok"), "POSTCHECK_ABSENT"),
        ("runtime_validation", every("verified", "runtime_ok", "control"), "FUNCTIONAL_TEST_FAILED"),
        ("compensation", every("compensated", "config_restored", "after", "restored", "preserved"), "COMPENSATION_ABSENT"),
    ):
        cell.probes[stage] = assessment.probe("PASS" if okay else "FAIL", text[:1900], reason="" if okay else reason,
                                              test_type="LIVE", reference=reference)
    cell.runtime_version = "FRRouting 8.4.4 / FRRouting 8.4.4 isolated pair"
    return scenarios
