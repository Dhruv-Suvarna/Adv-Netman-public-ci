"""Reversible Ubuntu/FRR policy-based-routing probes (V2 Phase 9) on the isolated FRR pair.

    FRR peer eth1  ---  DUT eth3   (198.18.0.0/30, 2001:db8:44::/64)
                        DUT nmaspbr0 (dummy: the policy next hop 198.18.7.2 / 2001:db8:77::2 is reached through it)

Configlets are the planner's own: the harness builds a planning context from the cell's sample intent and calls the
registered ``planning.configlet_factory.HANDLERS`` for the policy and its attachment; the postcheck requirements are the
engine's own descriptors of those Configlets.  Everything NMAS claims goes through the registered ``LinuxExecutor`` in
engine order: preflight all, apply, verify, compensate in reverse.

Lab prerequisites, written natively and removed again (the pair's addresses, routes, rules and daemons are compared with
their captured baselines): ``FrrPair`` (link addresses, the peer's originating prefix, zebra + pbrd), the egress dummy,
a blackhole for the probe destination on the DUT (so unsteered traffic is dropped, never leaked to the management
network), the peer's route to that destination through the DUT, and IPv6 forwarding for packets received on eth3 only
(``force_forwarding``; the DUT's global IPv6 forwarding stays off).

Behaviour: the peer sends echo requests to the probe destination from the policy's source prefix and from its link
address; the DUT's egress dummy counts what is steered to the policy next hop (a dummy device counts every transmitted
packet and discards it).  While attached, exactly the matching traffic is steered; before and after, nothing is.
"""

from __future__ import annotations

import json
import time
from copy import deepcopy
from types import SimpleNamespace

from django.utils import timezone

from .. import frr_pbr, platform_drivers
from ..config_import import parser_frr
from ..execution.executors.base import ConfigletSpec, ExecutorError
from ..execution.executors.linux import LinuxExecutor, frr_config_digest, read_frr_config
from ..health import live
from ..health.requirements import from_descriptor
from ..planning import configlet_factory
from . import assessment
from .batch_frr_acl import _executor_spec
from .batch_frr_routing import FrrPair, ORIGIN, PEER_NET, _call, _postcheck, _transaction
from .features import by_key
from .isolated_live import LAB, _run
from .probe_cases import sample

PLATFORM = "ubuntu_frr"
CELLS = tuple(f"service_policy.{code}" for code in ("PBR_IPV4", "PBR_IPV6", "PBR_ATTACH_IPV4", "PBR_ATTACH_IPV6"))
PORT, SEED_PORT, EGRESS = "eth3", "eth2", "nmaspbr0"
EGRESS_ADDR = {"IPV4": "198.18.7.1/30", "IPV6": "2001:db8:77::1/64"}
NEXT_HOP = {"IPV4": "198.18.7.2", "IPV6": "2001:db8:77::2"}
DESTINATION = {"IPV4": "192.0.2.0/24", "IPV6": "2001:db8:192::/64"}
TARGET = {"IPV4": "192.0.2.77", "IPV6": "2001:db8:192::77"}
DUT_HOP = {"IPV4": "198.18.0.1", "IPV6": "2001:db8:44::1"}
SOURCE = {family: address.split("/")[0] for family, address in ORIGIN["peer"].items()}   # inside the policy's source prefix
OTHER = {"IPV4": "198.18.0.2", "IPV6": "2001:db8:44::2"}                                 # the peer's link address: no match
SEED = ("pbr-map LEGACY seq 10", "match src-ip 203.0.113.0/24", f"set nexthop {NEXT_HOP['IPV4']}")
PINGS = 6
RUNTIME = "FRRouting 8.4.4 (zebra + pbrd) / Ubuntu 24.04 isolated container pair"
_SCENARIO_ERRORS = (RuntimeError, ExecutorError, OSError, ValueError, KeyError)


def family(key: str) -> str:
    return "IPV6" if key.endswith("IPV6") else "IPV4"


# --- intent / plan ---------------------------------------------------------------------------------------------------
def intent(key: str) -> dict:
    """The cell's sample intent, adjusted only where the behaviour test needs specific values: one sequence steering the
    peer's originating prefix towards the probe destination to the egress next hop, attached IN on the DUT's lab port."""
    sections = deepcopy(sample(PLATFORM, by_key()[key]).sections)
    fam = family(key)
    interface = next(iter(sections["interfaces"].values()))
    interface["name"] = PORT
    policy = next(iter(sections["policy"]["pbr"]["policies"].values()))
    first = next(iter(policy["sequences"].values()))
    policy["sequences"] = {first["id"]: {**first, "sequence": 10, "source_prefix": PEER_NET[fam],
                                         "destination_prefix": DESTINATION[fam], "protocol": "IP",
                                         "next_hop": NEXT_HOP[fam], "output_interface_id": ""}}
    sections["policy"]["pbr"]["attachments"] = {"attach_0000000000000003": {
        "id": "attach_0000000000000003", "sequence": 1, "policy_id": policy["id"], "interface_id": interface["id"],
        "direction": "IN"}}
    return sections


def planner_context(sections: dict):
    """A ``configlet_factory.DeviceContext`` over sample intent (the hydrated shape the planner itself uses)."""
    ctx = object.__new__(configlet_factory.DeviceContext)
    ctx.intent = SimpleNamespace(target_type="", device_name="frr", platform=PLATFORM)
    ctx.name, ctx.platform, ctx.hostname = "frr", PLATFORM, "frr"
    ctx.driver = platform_drivers.get_driver(PLATFORM)
    ctx.field_values = {"device.hostname": "frr", "device.description": ""}
    ctx.interfaces = deepcopy(list(sections["interfaces"].values()))
    ctx.routing = deepcopy(sections.get("routing") or {})
    ctx.phase12 = {name: deepcopy(sections.get(name) or {}) for name in ("fhrp", "nat", "services", "security", "policy")}
    ctx.auto = {}
    return ctx


def plan(key: str):
    """-> (executor Configlet specs, postcheck requirements, intent sections)."""
    sections = intent(key)
    ctx = planner_context(sections)
    pbr = sections["policy"]["pbr"]
    nodes = [("pbr_policy", object_id) for object_id in pbr["policies"]]
    nodes += [("pbr_attachment", object_id) for object_id in pbr["attachments"]]
    planned = [spec for kind, object_id in nodes for spec in configlet_factory.HANDLERS[kind](
        ctx, {"id": f"frr/{kind}/{object_id}", "type": kind, "object_id": object_id, "label": f"frr {kind} {object_id}"})]
    specs = [_executor_spec(n, spec) for n, spec in enumerate(planned, 1)]
    requirements = [from_descriptor(spec.cfg_id, descriptor) for spec, plan_spec in zip(specs, planned)
                    for descriptor in configlet_factory.verification_requirements(plan_spec)]
    return specs, requirements, sections


def conflicting() -> ConfigletSpec:
    """The cell's policy attached on the seed's interface, which already carries the pre-existing policy."""
    return ConfigletSpec("P9-FRR-pbr_attachment-conflict", 9, "frr", PLATFORM, "pbr_attachment", "ACTIVATE_ATTACH",
                         tuple(frr_pbr.attachment_lines(SEED_PORT, "CAP_PBR")),
                         {"policy_name": "CAP_PBR", "interface": SEED_PORT, "direction": "IN"})


def preserved(running: str, pbr: dict) -> bool:
    """The pre-existing policy is configured exactly as seeded, still installed, and still applied on its interface."""
    blocks = [block for block in parser_frr._blocks(running) if block[0].startswith("pbr-map LEGACY ")]   # pylint: disable=protected-access
    legacy = (pbr.get("policies") or {}).get("LEGACY") or {}
    return [[line.strip() for line in block] for block in blocks] == [list(SEED)] and bool(legacy.get("valid")) \
        and all(row.get("installed") for row in legacy.get("sequences", [])) \
        and {"interface": SEED_PORT, "policy": "LEGACY", "valid": True} in (pbr.get("attachments") or [])


def imported(sections: dict, running: str) -> bool:
    """The live running configuration, imported by the operator parser, carries the policy (every sequence) and the
    attachment on the lab port."""
    policy = next(iter(sections["policy"]["pbr"]["policies"].values()))
    addr = json.dumps([{"ifname": name, "flags": ["UP"], "mtu": 1500, "addr_info": []} for name in (PORT, SEED_PORT)])
    parsed = parser_frr.parse(running, addr_json=addr)
    row = next((p for p in parsed.pbr_policies if p.name == policy["name"]), None)
    wanted = [(int(s["sequence"]), s["source_prefix"], s["destination_prefix"], s["next_hop"])
              for s in sorted(policy["sequences"].values(), key=lambda s: s["sequence"])]
    got = [(s["sequence"], s["source_prefix"], s["destination_prefix"], s["next_hop"]) for s in row.sequences] if row else []
    port = next((i for i in parsed.interfaces if i.name == PORT), None)
    return bool(row) and row.family == policy["family"] and got == wanted and bool(port) \
        and {"name": policy["name"], "direction": "IN"} in port.pbr_attachments


# --- lab -------------------------------------------------------------------------------------------------------------
class PbrLab:
    """``FrrPair`` with pbrd, plus the egress dummy, the destination's blackhole / peer route and eth3 IPv6 forwarding."""

    def __init__(self, fam: str):
        self.family = fam
        self.pair = FrrPair(("pbrd",))
        self.dut, self.fc, self.pc = self.pair.dut, self.pair.fc, self.pair.pc
        self.prepared = True
        try:
            (row,) = json.loads(_run(["docker", "inspect", self.pc], timeout=10).stdout or "[null]")
            self.peer_pid = str(row["State"]["Pid"])
            self.rules = self.policy_rules()
            self.forwarding = _call(self.fc, "cat", f"/proc/sys/net/ipv6/conf/{PORT}/force_forwarding").stdout.strip()
            must = FrrPair.must
            must(self.fc, "ip", "link", "add", EGRESS, "type", "dummy")
            must(self.fc, "ip", "link", "set", "dev", EGRESS, "up")
            must(self.fc, "ip", "addr", "add", EGRESS_ADDR["IPV4"], "dev", EGRESS)
            must(self.fc, "ip", "-6", "addr", "add", EGRESS_ADDR["IPV6"], "dev", EGRESS, "nodad")
            for flag, fam_ in (("-4", "IPV4"), ("-6", "IPV6")):
                must(self.fc, "ip", flag, "route", "add", "blackhole", DESTINATION[fam_])
                must(self.pc, "ip", flag, "route", "add", DESTINATION[fam_], "via", DUT_HOP[fam_])
            must(self.fc, "sysctl", "-qw", f"net.ipv6.conf.{PORT}.force_forwarding=1")
        except Exception:
            self.close()
            raise

    def policy_rules(self) -> str:
        return "\n".join(_call(self.fc, "ip", flag, "rule", "show").stdout for flag in ("-4", "-6"))

    def pbr_routes(self) -> str:
        """Routes zebra installed for PBR in any table (none may outlive the lab)."""
        return "".join(_call(self.fc, "ip", flag, "route", "show", "table", "all", "proto", "pbr").stdout
                       for flag in ("-4", "-6"))

    def steered(self) -> int:
        return int(_call(self.fc, "cat", f"/sys/class/net/{EGRESS}/statistics/tx_packets").stdout.strip() or -1)

    def ping(self, source: str) -> None:
        """Echo requests from ``source`` on the peer towards the probe destination (no reply is expected)."""
        _run(["sudo", "-n", "nsenter", "-t", self.peer_pid, "-n", "ping", "-c", str(PINGS), "-i", "0.2", "-W", "1", "-I", source,
              TARGET[self.family]], timeout=30)

    def observe(self) -> dict:
        """Packets steered to the policy next hop while the peer sends from the policy's source and from another one."""
        seen = {}
        for label, source in (("matching source", SOURCE[self.family]), ("other source", OTHER[self.family])):
            before = self.steered()
            self.ping(source)
            seen[label] = self.steered() - before
        return seen

    @staticmethod
    def expected(steering: bool) -> dict:
        return {"matching source": PINGS if steering else 0, "other source": 0}

    def settled(self, steering: bool, limit: float = 30.0) -> tuple[bool, dict, int]:
        """``observe`` until it matches ``expected`` (the first MLD reports of a new dummy are transmitted too)."""
        started = time.monotonic()
        while True:
            seen = self.observe()
            if seen == self.expected(steering) or time.monotonic() - started > limit:
                return seen == self.expected(steering), seen, int(time.monotonic() - started)
            time.sleep(2)

    def close(self) -> bool:
        if not getattr(self, "prepared", False):
            return True
        self.prepared = False
        if hasattr(self, "forwarding"):
            _call(self.fc, "sysctl", "-qw", f"net.ipv6.conf.{PORT}.force_forwarding={self.forwarding or 0}")
        for flag, fam_ in (("-4", "IPV4"), ("-6", "IPV6")):
            _call(self.pc, "ip", flag, "route", "del", DESTINATION[fam_], "via", DUT_HOP[fam_])
            _call(self.fc, "ip", flag, "route", "del", "blackhole", DESTINATION[fam_])
        _call(self.fc, "ip", "link", "delete", EGRESS)
        forwarding = _call(self.fc, "cat", f"/proc/sys/net/ipv6/conf/{PORT}/force_forwarding").stdout.strip()
        restored = self.pair.close()          # stops the daemons, removes the pair's addresses, compares the kernel baseline
        checks = {"pair baseline": restored, "policy rules": not hasattr(self, "rules") or self.policy_rules() == self.rules,
                  "PBR routes": not self.pbr_routes().strip(),
                  "eth3 force_forwarding": not hasattr(self, "forwarding") or forwarding == (self.forwarding or "0")}
        if not all(checks.values()):
            raise RuntimeError(f"Disposable PBR lab did not return to its captured baseline: {checks}")
        return True


def _pbr_state(container: str) -> dict:
    keys = ("pbr_map", "pbr_nexthops", "pbr_interface")
    outputs = [_call(container, *live.LINUX_COMMANDS[key]).stdout for key in keys]
    return live.parse_frr_pbr(*outputs)


# --- scenario / probe ------------------------------------------------------------------------------------------------
def _scenario(key: str, *, seeded: bool) -> dict:
    specs, requirements, sections = plan(key)
    result = {"actions": [], "statuses": [], "detail": "", "failure": "", "imported": False, "control": False,
              "after": False, "preserved": True, "negative": ""}
    lab = PbrLab(family(key))
    executor = LinuxExecutor(lab.dut)
    try:
        executor.connect()
        if seeded:
            lab.pair.vty(lab.fc, *SEED, "exit", f"interface {SEED_PORT}", "pbr-policy LEGACY")
        before = frr_config_digest(read_frr_config(lab.fc, 30))
        result["control"], seen, took = lab.settled(steering=False)
        control = f"control before apply (nothing steered expected) ok={result['control']} after {took} s: {seen}"
        if not result["control"]:
            raise RuntimeError(f"Control flows are not as expected: {seen!r}.")
        if seeded:
            found = executor.assess(conflicting())
            result["negative"] = f"{found.action}/{found.restorable}/{found.reason or '-'}"
        state = {}

        def verify():
            observed, post_ok, failed = _postcheck(lab.dut, requirements)
            running = read_frr_config(lab.fc, 30)
            result["imported"] = imported(sections, running)
            kept = preserved(running, _pbr_state(lab.fc)) if seeded else True
            steered, flows, _took = lab.settled(steering=True, limit=6)
            rules = [line.strip() for line in lab.policy_rules().splitlines() if "iif " + PORT in line]
            state.update(read_ok=bool(observed.live_reachable), post_ok=post_ok, preserved=kept)
            return post_ok and result["imported"] and steered and kept, (
                f"operator postcheck pass={post_ok} {failed}; pbr facts={observed.facts('pbr')}; kernel rules={rules}; "
                f"live import recovered the policy, every sequence and the attachment={result['imported']}; packets "
                f"steered to {NEXT_HOP[lab.family]} while attached (expected {lab.expected(True)}): {flows}; "
                f"pre-existing policy preserved={kept}")

        result.update(_transaction(executor, specs, verify, attempts=3))
        result.update(state)
        running = read_frr_config(lab.fc, 30)
        result["config_restored"] = frr_config_digest(running) == before
        if seeded:
            result["preserved"] = result.get("preserved", True) and preserved(running, _pbr_state(lab.fc))
        result["after"], seen, took = lab.settled(steering=False)
        result["detail"] = f"{control}; " + result["detail"] + f"; after compensation (nothing steered expected) after {took} s: {seen}"
    except _SCENARIO_ERRORS as exc:     # recorded as the scenario's failure; anything else aborts the run (fail closed)
        result["failure"] = f"{type(exc).__name__}: {str(exc)[:400]}"
    finally:
        executor.close()
        if seeded:                      # the native seed, removed natively (and anything a failed run left behind)
            _call(lab.fc, "vtysh", "-c", "configure terminal", "-c", f"interface {SEED_PORT}", "-c", "no pbr-policy LEGACY",
                  "-c", "exit", "-c", "no pbr-map LEGACY")
        result["restored"] = lab.close()
    return result


def scenarios_for(key: str) -> dict:
    return {"pristine node": _scenario(key, seeded=False),
            "existing policy attached elsewhere": _scenario(key, seeded=True)}


def probe_frr_pbr(cell, key: str):
    specs, _, _ = plan(key)
    scenarios = scenarios_for(key)
    reference = f"live:{LAB}/frr-{key.split('.')[1].lower()}/{timezone.now().isoformat()}"
    rendered = "; ".join(f"[{spec.object_type}] " + " / ".join(line.strip() for line in spec.lines) for spec in specs)
    text = " || ".join(
        f"{label}: preflight={r['actions']}; conflicting-attachment preflight={r['negative'] or 'n/a'}; {r['detail']}; "
        f"compensation={r['statuses']} codes={r.get('compensation_codes')}; FRR running-config identical to pre-apply "
        f"capture={r.get('config_restored')}; pre-existing policy preserved={r.get('preserved')}; lab baseline restored="
        f"{r.get('restored')}; {r['failure'] or 'no failure'}" for label, r in scenarios.items())
    detail = (f"isolated FRR {key} against an FRR peer through the registered LinuxExecutor (pbrd via vtysh, "
              f"captured-configuration inverse) || {text} || Configlets from the planner's own handlers: {rendered}")
    negative_ok = scenarios["existing policy attached elsewhere"]["negative"] == "APPLY/False/COMPENSATION_NOT_PROVABLE"

    def every(*keys) -> bool:
        return all(r.get(k) for r in scenarios.values() for k in keys)

    for stage, ok, reason in (
        ("live_write", every("applied"), "FUNCTIONAL_TEST_FAILED"),
        ("live_read", every("read_ok"), "LIVE_READ_ABSENT"),
        ("live_post_write_validation", every("post_ok"), "POSTCHECK_ABSENT"),
        ("parser_import", every("imported"), "PARSER_ABSENT"),
        ("runtime_validation", every("verified", "control") and negative_ok, "FUNCTIONAL_TEST_FAILED"),
        ("compensation", every("compensated", "config_restored", "after", "restored", "preserved"), "COMPENSATION_ABSENT"),
    ):
        cell.probes[stage] = assessment.probe("PASS" if ok else "FAIL", detail[:3900], reason="" if ok else reason,
                                              test_type="LIVE", reference=reference)
    cell.runtime_version = RUNTIME
    return scenarios
