"""Ubuntu/FRR executor: bounded iproute2 link/address and incremental vtysh routing changes.

Evidence: the tracked R3/R4 scripts configure interfaces with iproute2, and Phase 15 established ``docker exec`` of a fixed
argv list as the credential-free Linux transport. Phase 4's isolated FRR 8.4.4 lab verified incremental ``vtysh`` static
IPv4/IPv6 route add, normalized route readback, kernel forwarding choice and exact ``no`` compensation, and incremental
OSPF, RIP/RIPng and BGP process changes whose inverse is derived from the captured running configuration
(``frr_routing``).  NAT44 masquerade lives in one dedicated nftables table: created atomically and deleted as a whole, or,
when that exact NMAS-shaped table already exists, extended by the new rule and restored to the captured rule list.  A
table of that name holding anything else is never merged into.  Static NAT44 (V2 Phase 9) is a second dedicated table of
the same discipline: a prerouting ``dnat`` and a postrouting ``snat`` chain whose rules pair up as 1:1 host mappings, both
directions of a mapping always written and removed in one atomic nft transaction.  ACLs (V2 Phase 9) are a third such
table, ``inet DEVICE_BUILDER_ACL`` (``nft_acl``): an ACL Configlet creates or replaces one list chain, an attachment
Configlet adds one family-guarded jump to the IN / OUT hook chain; each is one atomic nft transaction whose inverse
(delete what it created, or restore the captured rule list) must bring the whole ruleset back to its captured digest.

SECURITY: a Configlet line is NEVER handed to a shell.  Each line must match one of a small set of STRICT patterns (the
exact shapes the Jinja feature templates emit) and is converted into an argv list of validated tokens; anything else
refuses the Configlet.  ``subprocess.run`` is only ever called with a list starting with ``docker`` and ``shell=False``.
"""

from __future__ import annotations

import ipaddress
import hashlib
import json
import re
import subprocess

from ... import nft_acl
from ...health import live
from ..codes import device_timeout_seconds
from . import frr_routing, state
from .base import APPLY, REFUSE, ApplyOutcome, Assessment, CompensationOutcome, ConfigletSpec, DeviceExecutor, ExecutorError
from .ceos import config_inverse

FRR_ROUTING_TYPES = frozenset({"routing_ospf", "routing_binding", "routing_rip", "routing_isis", "routing_bgp",
                               "bgp_neighbor", "bgp_neighbor_af", "bgp_network"})


def frr_routing_blocks(lines) -> list[list[str]] | None:
    """Strict vtysh command blocks (OSPF, RIP/RIPng, BGP); each block retains its CLI context."""
    blocks = frr_routing.parse(lines)
    return [frr_routing.commands(block) for block in blocks] if blocks else None


def frr_routing_inverse(lines, running_text: str, *, pending_ok: bool = False) -> list[str] | None:
    """Captured-state inverse: interface leaves before processes, never delete an active Linux interface.

    ``pending_ok`` (preflight only): a BGP neighbor leaf may reference a neighbor that an earlier Configlet of the same
    plan creates; the exact inverse is re-derived against the real configuration immediately before apply.
    """
    blocks = frr_routing.parse(lines)
    if not blocks:
        return None
    running = frr_routing.tree(running_text)
    interfaces, processes = [], []
    for block in blocks:  # pylint: disable=not-an-iterable  # frr_routing.parse returns a list; empty list returns above
        header = block.header
        if block.kind == "interface":
            if any(child.startswith("no ") for child in block.leaves):
                return None
            generic = config_inverse([header, *(f"   {child}" for child in block.leaves)], running_text)
            if generic is None:
                return None
            if generic == [f"no {header}"]:
                interfaces.extend([header, *(f"   no {child}" for child in reversed(block.leaves))])
            else:
                interfaces.extend(generic)
        else:
            generic = frr_routing.process_inverse(block, running, pending_ok=pending_ok)
            if generic is None:
                return None
            processes = [*generic, *processes]            # later blocks are undone first
    inverse = [*interfaces, *processes]
    return inverse if not inverse or frr_routing_blocks(inverse) else None


def docker_exec(container: str, argv: list[str], timeout: float) -> subprocess.CompletedProcess:
    """The ONLY process spawn in the engine: ``docker exec <container> <argv>`` as a list, ``shell=False``.

    Every read and every write of this executor goes through here, so the argv shape, the timeout and the output capture
    are decided in one place.  ``OSError`` / ``subprocess.TimeoutExpired`` propagate: a reader and a writer fail closed
    with different codes.
    """
    return subprocess.run(  # noqa: S603 - argv is a validated list, shell=False
        ["docker", "exec", container, *argv], capture_output=True, text=True, timeout=timeout, shell=False, check=False,
    )


def read_frr_daemons(container: str, timeout: float) -> set[str]:
    """Names of the FRR daemons vtysh can reach; empty when none answers (configuration would be silently dropped)."""
    try:
        result = docker_exec(container, ["vtysh", "-c", "show daemons"], timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ExecutorError("PREVIOUS_STATE_UNAVAILABLE") from exc
    if result.returncode or "failed to connect" in result.stdout.lower():
        return set()
    return set(result.stdout.split())


NAT_TYPES = frozenset({"nat_rule"})
_NAT_TABLE = re.compile(r"^table ip ([A-Za-z0-9_]{1,32}) \{$")
_NAT_RULE = re.compile(r'^oifname "([A-Za-z0-9_.-]{1,15})" ip saddr (\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?) masquerade'
                       r'( comment "nmas-nat44-stateful")?$')   # the only comment NMAS renders (intent mode STATEFUL)
_NAT_CHAIN = ("chain postrouting {", "type nat hook postrouting priority srcnat; policy accept;")


_IPV4_HOST = r"(\d{1,3}(?:\.\d{1,3}){3})"
_STATIC_DNAT = re.compile(r'^iifname "([A-Za-z0-9_.-]{1,15})" ip daddr ' + _IPV4_HOST + " dnat to " + _IPV4_HOST + "$")
_STATIC_SNAT = re.compile(r'^oifname "([A-Za-z0-9_.-]{1,15})" ip saddr ' + _IPV4_HOST + " snat to " + _IPV4_HOST + "$")
_STATIC_PRE = ("chain prerouting {", "type nat hook prerouting priority dstnat; policy accept;")


def parse_static_nat_table(lines) -> dict | None:
    """The static NAT44 shape -> {"table", "kind": "static", "rules": [(oif, inside, global)]}, else None.

    A dedicated NMAS-owned ``table ip`` with exactly a prerouting chain of ``dnat`` rules followed by a postrouting chain
    of ``snat`` rules, where rule k of each chain is the two directions of one 1:1 host mapping (``nft list ruleset``
    prints the chains in creation order).  Hosts only; an address used by two mappings is refused as ambiguous.
    """
    body = [line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#")]
    if len(body) < 10 or tuple(body[1:3]) != _STATIC_PRE or body[-2:] != ["}", "}"]:
        return None
    table = _NAT_TABLE.fullmatch(body[0])
    try:
        split = body.index("}", 3)
    except ValueError:
        return None
    if not table or tuple(body[split + 1:split + 3]) != _NAT_CHAIN:
        return None
    dnat = [_STATIC_DNAT.fullmatch(line) for line in body[3:split]]
    snat = [_STATIC_SNAT.fullmatch(line) for line in body[split + 3:-2]]
    if not dnat or len(dnat) != len(snat) or not all(dnat) or not all(snat):
        return None
    rules = []
    for d, s in zip(dnat, snat):
        if (d.group(1), d.group(3), d.group(2)) != s.groups():
            return None
        try:
            ipaddress.IPv4Address(s.group(2)), ipaddress.IPv4Address(s.group(3))
        except ValueError:
            return None
        rules.append(s.groups())
    if len({r[1] for r in rules}) != len(rules) or len({r[2] for r in rules}) != len(rules) or {r[1] for r in rules} & {r[2] for r in rules}:
        return None
    return {"table": table.group(1), "kind": "static", "rules": rules}


def static_nat_statement(nat: dict) -> str:
    """The whole static table in one atomic nft transaction (validated tokens only)."""
    pre = "".join(f'  iifname "{oif}" ip daddr {glob} dnat to {inside}\n' for oif, inside, glob in nat["rules"])
    post = "".join(f'  oifname "{oif}" ip saddr {inside} snat to {glob}\n' for oif, inside, glob in nat["rules"])
    return (f"table ip {nat['table']} {{\n chain prerouting {{\n  type nat hook prerouting priority dstnat; policy accept;\n"
            f"{pre} }}\n chain postrouting {{\n  type nat hook postrouting priority srcnat; policy accept;\n{post} }}\n}}")


def static_nat_rule_commands(table: str, rules) -> str:
    """``add rule`` commands for both directions of each mapping, for one atomic nft transaction."""
    return "".join(f'add rule ip {table} prerouting iifname "{oif}" ip daddr {glob} dnat to {inside}\n'
                   f'add rule ip {table} postrouting oifname "{oif}" ip saddr {inside} snat to {glob}\n'
                   for oif, inside, glob in rules)


def static_nat_conflict(rules, existing) -> bool:
    """A new mapping that reuses an inside or global address already mapped differently: the result is ambiguous."""
    used = {r[1] for r in existing} | {r[2] for r in existing}
    return any(rule not in existing and (rule[1] in used or rule[2] in used) for rule in rules)


def parse_nat_table(lines) -> dict | None:
    """The NMAS nftables NAT shapes: masquerade (PAT/STATEFUL) -> {"table", "rules": [(oif, source, comment)]}, or the
    static shape of ``parse_static_nat_table``; anything else -> None.

    PAT: a dedicated NMAS-owned ``table ip`` with a single source-NAT postrouting chain of masquerade rules; nothing else.
    """
    body = [line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#")]
    if len(body) >= 3 and tuple(body[1:3]) == _STATIC_PRE:
        return parse_static_nat_table(lines)
    if len(body) < 6 or tuple(body[1:3]) != _NAT_CHAIN or body[-2:] != ["}", "}"]:
        return None
    table = _NAT_TABLE.fullmatch(body[0])
    rules = [_NAT_RULE.fullmatch(line) for line in body[3:-2]]
    if not table or not all(rules):
        return None
    try:
        for rule in rules:
            ipaddress.ip_network(rule.group(2), strict=True)
    except ValueError:
        return None
    # nft lists a host prefix without its /32; one canonical form keeps rendered and listed rules comparable
    return {"table": table.group(1), "rules": [(r.group(1), str(ipaddress.ip_network(r.group(2))), r.group(3) or "") for r in rules]}


def nat_statement(nat: dict) -> str:
    """One nft command: the whole table is created in a single atomic kernel transaction (built from validated tokens only)."""
    rules = "".join(f'  oifname "{oif}" ip saddr {source} masquerade{comment}\n' for oif, source, comment in nat["rules"])
    return (f"table ip {nat['table']} {{\n chain postrouting {{\n  type nat hook postrouting priority srcnat; policy accept;\n"
            f"{rules} }}\n}}")


def nat_rule_tokens(rule) -> list[str]:
    oif, source, comment = rule
    return ["oifname", f'"{oif}"', "ip", "saddr", source, "masquerade", *(comment.split() if comment else [])]


def nat_rule_conflict(rules, existing) -> bool:
    return any(rule not in existing and rule[:2] == other[:2] for rule in rules for other in existing)


def _nat_conflict(nat: dict, existing) -> bool:
    return (static_nat_conflict if nat.get("kind") == "static" else nat_rule_conflict)(nat["rules"], existing)


def nat_table_rules(ruleset: str, table: str, kind: str = ""):
    """Rules of ``table ip <table>`` in a listed ruleset: None when absent, False when it is not the exact NMAS shape
    of ``kind`` ("" = masquerade, "static")."""
    lines = ruleset.splitlines()
    start = next((i for i, line in enumerate(lines) if line.strip() == f"table ip {table} {{" and not line.startswith((" ", "\t"))), None)
    if start is None:
        return None
    end = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("}")), None)
    owned = parse_nat_table(lines[start:end + 1]) if end is not None else None
    return owned["rules"] if owned and owned.get("kind", "") == kind else False


ACL_TYPES = frozenset({"acl", "acl_attachment"})


def acl_request(spec: ConfigletSpec) -> dict | None:
    """What one ACL Configlet asks for: {"chain", "rules"} (a list definition) or {"direction", "jump"} (an attachment).

    The definition must carry exactly one list chain and nothing else; the attachment exactly one hook chain holding
    exactly one jump.  Anything else -- or any line outside the ``nft_acl`` grammar -- is refused."""
    model = nft_acl.parse_table(spec.lines, snippet=True)
    if model is None:
        return None
    jumps = [(direction, jump) for direction, rows in model["hooks"].items() for jump in rows]
    if spec.object_type == "acl":
        if len(model["acls"]) != 1 or model["hook_chains"]:
            return None
        chain, acl = next(iter(model["acls"].items()))
        return {"chain": chain, "rules": acl["rules"]}
    if spec.object_type != "acl_attachment" or model["acls"] or len(jumps) != 1 or len(model["hook_chains"]) != 1:
        return None
    direction, jump = jumps[0]
    return {"direction": direction, "jump": jump}


def read_nft_ruleset(container: str, timeout: float) -> str:
    try:
        result = docker_exec(container, ["nft", "list", "ruleset"], timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ExecutorError("PREVIOUS_STATE_UNAVAILABLE") from exc
    if result.returncode:                                  # no nft on the device, or no permission: nothing is provable
        raise ExecutorError("PREVIOUS_STATE_UNAVAILABLE")
    return result.stdout


def nft_digest(text: str) -> str:
    """Digest of the whole ruleset (unrelated tables included) with volatile packet/byte counter values removed."""
    stable = re.sub(r"counter packets \d+ bytes \d+", "counter", text)
    return hashlib.sha256("\n".join(line.strip() for line in stable.splitlines() if line.strip()).encode()).hexdigest()


def read_links(container: str, timeout: float) -> list[dict]:
    """Every link of the namespace with its addresses (``ip -j addr show``); the captured state of an existing interface."""
    try:
        result = docker_exec(container, ["ip", "-j", "addr", "show"], timeout)
        rows = json.loads(result.stdout) if result.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
        raise ExecutorError("PREVIOUS_STATE_UNAVAILABLE") from exc
    if not isinstance(rows, list):
        raise ExecutorError("PREVIOUS_STATE_UNAVAILABLE")
    return rows


def link_state(rows, name: str) -> dict | None:
    """Semantic state of one link: what a change to an EXISTING interface must leave exactly as it was."""
    row = next((r for r in rows if r.get("ifname") == name), None)
    if row is None:
        return None
    return {"mtu": row.get("mtu"), "up": "UP" in (row.get("flags") or []), "master": row.get("master") or "",
            "addresses": sorted(f"{a.get('local')}/{a.get('prefixlen')}" for a in row.get("addr_info") or [] if a.get("local"))}


def read_frr_config(container: str, timeout: float) -> str:
    try:
        result = docker_exec(container, ["vtysh", "-c", "show running-config"], timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ExecutorError("PREVIOUS_STATE_UNAVAILABLE") from exc
    if result.returncode or "failed to connect" in result.stdout.lower():
        raise ExecutorError("PREVIOUS_STATE_UNAVAILABLE")
    return result.stdout


def frr_config_digest(text: str) -> str:
    lines = [line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith("!")
             and line.strip().lower() not in {"building configuration...", "current configuration:", "end"}]
    # FRR keeps an empty vtysh context for an active kernel interface after its last routing leaf is removed.
    # The interface cannot be deleted while active.  Its empty context has no configuration semantics.
    lines = [line for index, line in enumerate(lines) if not (
        line.startswith("interface ") and index + 1 < len(lines) and lines[index + 1] == "exit"
    ) and not (line == "exit" and index > 0 and lines[index - 1].startswith("interface "))]
    return hashlib.sha256("\n".join(lines).encode()).hexdigest()

_NAME = r"[A-Za-z0-9_.-]{1,32}"
_CIDR = r"[0-9A-Fa-f:.]{2,45}/\d{1,3}"
_PATTERNS = (
    ("set_mtu", re.compile(rf"^ip link set dev ({_NAME}) mtu (\d{{3,5}})$")),
    ("set_state", re.compile(rf"^ip link set dev ({_NAME}) (up|down)$")),
    ("add_vlan", re.compile(rf"^ip link show dev ({_NAME}) >/dev/null 2>&1 \|\| ip link add link ({_NAME}) name ({_NAME}) type vlan id (\d{{1,4}})$")),
    ("add_bridge", re.compile(rf"^ip link show dev ({_NAME}) >/dev/null 2>&1 \|\| ip link add ({_NAME}) type bridge$")),
    ("add_dummy", re.compile(rf"^ip link show dev ({_NAME}) >/dev/null 2>&1 \|\| ip link add ({_NAME}) type dummy$")),
    ("addr", re.compile(rf"^ip (-6 )?addr replace ({_CIDR}) dev ({_NAME})$")),
    ("route", re.compile(r"^(ip|ipv6) route ([0-9A-Fa-f:./]+) ([0-9A-Fa-f:.]+)(?: (\d{1,3}))?$")),
)


def parse_lines(lines) -> list[dict] | None:
    """Configlet lines -> validated operations, or None when ANY line is outside the strict grammar."""
    operations = []
    for line in lines:
        text = line.strip()
        for kind, pattern in _PATTERNS:
            found = pattern.match(text)
            if found:
                args = found.groups()
                if kind == "route":
                    try:
                        family = 4 if args[0] == "ip" else 6
                        if ipaddress.ip_network(args[1], strict=True).version != family \
                                or ipaddress.ip_address(args[2]).version != family \
                                or (args[3] is not None and not 1 <= int(args[3]) <= 255):
                            return None
                    except ValueError:
                        return None
                # the template's guard must test the very interface it then creates (never a different name)
                if (kind == "add_vlan" and args[0] != args[2]) or (kind in ("add_bridge", "add_dummy") and args[0] != args[1]):
                    return None
                operations.append({"kind": kind, "args": args})
                break
        else:
            return None
    return operations


def _argv(operation: dict) -> list[list[str]]:
    kind, a = operation["kind"], operation["args"]
    if kind == "set_mtu":
        return [["ip", "link", "set", "dev", a[0], "mtu", a[1]]]
    if kind == "set_state":
        return [["ip", "link", "set", "dev", a[0], a[1]]]
    if kind == "addr":
        return [["ip", *(["-6"] if a[0] else []), "addr", "replace", a[1], "dev", a[2]]]
    raise ValueError(kind)  # guarded adds are handled by the caller (check-then-add)


def inverse_operations(spec: ConfigletSpec) -> list[list[str]] | None:
    """Exact inverse argv lists for additive address/interface/static route changes."""
    if spec.object_type == "static_route":
        ops = parse_lines(spec.lines)
        if not ops or len(ops) != 1 or ops[0]["kind"] != "route":
            return None
        return [["vtysh", "-c", "configure terminal", "-c", "no " + spec.lines[0].strip()]]
    if spec.object_type == "address":
        ops = parse_lines(spec.lines)
        if not ops or any(op["kind"] != "addr" for op in ops):
            return None
        return [["ip", *(["-6"] if op["args"][0] else []), "addr", "del", op["args"][1], "dev", op["args"][2]] for op in reversed(ops)]
    if spec.object_type == "interface" and spec.expected.get("interface"):
        return [["ip", "link", "delete", spec.expected["interface"]]] if re.fullmatch(_NAME, spec.expected["interface"]) else None
    return None


def docker_run(container: str, argv: list[str], timeout: float) -> int:
    """Run one write argv through :func:`docker_exec` and return its exit status (an FRR CLI error marker counts as failure)."""
    try:
        done = docker_exec(container, argv, timeout)
    except FileNotFoundError as exc:
        raise ExecutorError("DOCKER_UNAVAILABLE") from exc
    except subprocess.TimeoutExpired as exc:
        raise ExecutorError("TIMEOUT") from exc
    except OSError as exc:
        raise ExecutorError("DOCKER_UNAVAILABLE") from exc
    if argv and argv[0] == "vtysh" and any(marker in done.stdout for marker in
                                             ("% Unknown command", "% Command incomplete", "% Invalid input", "% Error")):
        return 1
    return done.returncode


class LinuxExecutor(DeviceExecutor):
    platform = "ubuntu_frr"

    def __init__(self, device: dict, *, runner=None, reader=None, config_reader=None, daemon_reader=None, nft_reader=None,
                 link_reader=None):
        self._device = device
        self._run = runner or docker_run
        self._reader = reader or live.read_device
        self._timeout = device_timeout_seconds()
        self._config_reader = config_reader or read_frr_config
        self._daemon_reader = daemon_reader or read_frr_daemons
        self._nft_reader = nft_reader or read_nft_ruleset
        self._link_reader = link_reader or read_links
        self._routing_inverses: dict[str, list[str]] = {}
        self._routing_applied: dict[str, str] = {}   # cfg_id -> digest captured immediately before that apply
        self._nat_applied: dict[str, dict] = {}      # cfg_id -> ruleset digest and NMAS table rules right before that apply
        self._acl_applied: dict[str, dict] = {}      # cfg_id -> ruleset digest right before that apply and how to undo it

    def _routing_config(self) -> str:
        return self._config_reader(self._device["container"], self._timeout)

    def _assess_routing(self, spec: ConfigletSpec) -> Assessment:
        blocks = frr_routing.parse(spec.lines)
        if blocks is None:
            return Assessment(REFUSE, False, {}, "PLATFORM_EXECUTION_UNSUPPORTED")
        # vtysh silently drops configuration for a daemon it cannot reach; NMAS does not manage daemon lifecycle
        missing = frr_routing.required_daemons(blocks) - self._daemon_reader(self._device["container"], self._timeout)
        text = self._routing_config()
        state_before = {"kind": "frr_config_block", "config_digest": frr_config_digest(text)}
        if missing:
            return Assessment(REFUSE, False, {**state_before, "missing_daemons": sorted(missing)}, "ROUTING_DAEMON_UNAVAILABLE")
        conflict = frr_routing.conflict(blocks, frr_routing.tree(text))
        if conflict:
            return Assessment(REFUSE, False, state_before, conflict)
        inverse = frr_routing_inverse(spec.lines, text, pending_ok=True)
        if inverse is None:
            return Assessment(APPLY, False, state_before, state.COMPENSATION_NOT_PROVABLE)
        if not inverse:
            return Assessment("SKIP_SATISFIED", True, state_before)
        self._routing_inverses[spec.cfg_id] = inverse
        return Assessment(APPLY, True, state_before)

    def _apply_routing(self, spec: ConfigletSpec, assessment: Assessment) -> ApplyOutcome:
        """Re-derive the exact inverse against the configuration as it is NOW (earlier Configlets of the plan applied)."""
        if assessment.restorable:
            try:
                text = self._routing_config()
            except ExecutorError as exc:
                return ApplyOutcome(False, exc.code)
            inverse = frr_routing_inverse(spec.lines, text)
            if inverse is None:
                return ApplyOutcome(False, "COMMAND_REJECTED")   # nothing sent: the proven inverse no longer holds
            self._routing_inverses[spec.cfg_id] = inverse
            self._routing_applied[spec.cfg_id] = frr_config_digest(text)
        return self._send_routing(spec.lines)

    def _send_routing(self, lines) -> ApplyOutcome:
        blocks = frr_routing_blocks(lines)
        if not blocks:
            return ApplyOutcome(False, "UNSUPPORTED")
        sent = 0
        for block in blocks:  # pylint: disable=not-an-iterable  # frr_routing.parse returns a list
            argv = ["vtysh", "-c", "configure terminal", *(part for command in block for part in ("-c", command))]
            try:
                code = self._exec(argv)
            except ExecutorError as exc:
                return ApplyOutcome(False, exc.code, partial_effects=sent > 0, lines_sent=sent)
            sent += len(block)
            if code:
                return ApplyOutcome(False, "COMMAND_REJECTED", partial_effects=sent > len(block), lines_sent=sent)
        return ApplyOutcome(True, lines_sent=sent)

    def _compensate_routing(self, spec: ConfigletSpec, assessment: Assessment) -> CompensationOutcome:
        wanted = self._routing_applied.get(spec.cfg_id) or assessment.previous_state.get("config_digest")
        inverse = self._routing_inverses.get(spec.cfg_id)
        try:
            if wanted and frr_config_digest(self._routing_config()) == wanted:
                return CompensationOutcome("COMPENSATED", detail={"action": "NONE_NEEDED"})
            if not wanted or not inverse:
                return CompensationOutcome("COMPENSATION_FAILED", "UNSUPPORTED")
            sent = self._send_routing(inverse)
            if not sent.ok:
                return CompensationOutcome("COMPENSATION_FAILED", sent.error_code)
            if frr_config_digest(self._routing_config()) != wanted:
                return CompensationOutcome("COMPENSATION_FAILED", "STATE_NOT_RESTORED")
        except ExecutorError as exc:
            return CompensationOutcome("COMPENSATION_UNVERIFIED", exc.code)
        return CompensationOutcome("COMPENSATED", detail={"action": "INVERSE_APPLIED", "commands": len(inverse)})

    # -- an interface that already exists: change only the requested fields, restore exactly what was captured -------
    def _links(self) -> list[dict]:
        return self._link_reader(self._device["container"], self._timeout)

    @staticmethod
    def _existing_link_request(spec: ConfigletSpec) -> dict | None:
        """{"interface", "mtu"?, "up"?} when the Configlet only sets MTU / admin state of ONE interface, else None."""
        operations = parse_lines(spec.lines)
        if spec.object_type != "interface" or not operations or any(op["kind"] not in ("set_mtu", "set_state") for op in operations):
            return None
        names = {op["args"][0] for op in operations}
        if names != {spec.expected.get("interface")}:
            return None
        request = {"interface": names.pop()}
        for op in operations:
            if op["kind"] == "set_mtu":
                request["mtu"] = int(op["args"][1])
            else:
                request["up"] = op["args"][1] == "up"
        return request

    def _assess_existing_link(self, request: dict) -> Assessment | None:
        rows = self._links()
        name = request["interface"]
        before = link_state(rows, name)
        if before is None:
            return None                                    # absent: the ordinary create path decides
        previous = {"kind": "link", "interface": name, **before}
        changes = {key: request[key] for key in ("mtu", "up") if key in request and request[key] != before[key]}
        if not changes:
            return Assessment("SKIP_SATISFIED", True, previous)
        previous["changes"] = changes
        reason = ""
        if "up" in changes:
            reason = "an admin-state change of an existing interface drops its routes and IPv6 addresses"
        elif changes["mtu"] < 1280 and any(":" in address for address in before["addresses"]):
            reason = "an MTU below 1280 removes the interface's IPv6 addresses"
        elif any(row.get("link") == name and (row.get("mtu") or 0) > changes["mtu"] for row in rows):
            reason = "lowering the MTU clamps a child interface, which raising it again does not undo"
        elif before["master"]:
            reason = "the interface is enslaved to another device"
        if reason:
            return Assessment(APPLY, False, {**previous, "unsafe": reason}, state.COMPENSATION_NOT_PROVABLE)
        return Assessment(APPLY, True, previous)

    def _compensate_existing_link(self, assessment: Assessment) -> CompensationOutcome:
        previous = assessment.previous_state
        name = previous["interface"]
        wanted = {key: previous[key] for key in ("mtu", "up", "master", "addresses")}
        try:
            if link_state(self._links(), name) == wanted:
                return CompensationOutcome("COMPENSATED", detail={"action": "NONE_NEEDED"})
            if set(previous.get("changes") or {}) != {"mtu"} or not re.fullmatch(_NAME, name):
                return CompensationOutcome("COMPENSATION_FAILED", "UNSUPPORTED")
            if self._exec(["ip", "link", "set", "dev", name, "mtu", str(int(previous["mtu"]))]) != 0:
                return CompensationOutcome("COMPENSATION_FAILED", "COMMAND_REJECTED")
            if link_state(self._links(), name) != wanted:
                return CompensationOutcome("COMPENSATION_FAILED", "STATE_NOT_RESTORED")
        except ExecutorError as exc:
            return CompensationOutcome("COMPENSATION_UNVERIFIED", exc.code)
        return CompensationOutcome("COMPENSATED", detail={"action": "INVERSE_APPLIED", "commands": 1})

    # -- nftables NAT: one dedicated table, created and deleted as a whole -------------------------------------------
    def _nft(self) -> str:
        return self._nft_reader(self._device["container"], self._timeout)

    def _assess_nat(self, spec: ConfigletSpec) -> Assessment:
        nat = parse_nat_table(spec.lines)
        if nat is None:
            return Assessment(REFUSE, False, {}, "PLATFORM_EXECUTION_UNSUPPORTED")
        ruleset = self._nft()
        state_before = {"kind": "nft_table", "table": nat["table"], "ruleset_digest": nft_digest(ruleset)}
        kind = nat.get("kind", "")
        existing = nat_table_rules(ruleset, nat["table"], kind)
        if kind:
            state_before["nat_kind"] = kind
        if existing is None:
            return Assessment(APPLY, True, state_before)   # the inverse is the deletion of the table this Configlet creates
        if existing is False:
            # a table of that name NMAS did not write in this shape: adding to it has no proven inverse
            return Assessment(APPLY, False, state_before, state.COMPENSATION_NOT_PROVABLE)
        if all(rule in existing for rule in nat["rules"]):
            return Assessment("SKIP_SATISFIED", True, state_before)
        if _nat_conflict(nat, existing):
            # the same match already translates under the other intent mode; an appended rule would never be reached
            return Assessment(APPLY, False, state_before, state.COMPENSATION_NOT_PROVABLE)
        return Assessment(APPLY, True, {**state_before, "existing_rules": len(existing)})

    def _apply_nat(self, spec: ConfigletSpec, assessment: Assessment) -> ApplyOutcome:
        """Create the table, or append to the exact NMAS table found NOW (an earlier Configlet may have created it)."""
        nat = parse_nat_table(spec.lines)
        if nat is None or not assessment.restorable:
            return ApplyOutcome(False, "UNSUPPORTED")
        try:
            ruleset = self._nft()
            static = nat.get("kind") == "static"
            existing = nat_table_rules(ruleset, nat["table"], nat.get("kind", ""))
            if existing is False or (existing and _nat_conflict(nat, existing)):
                return ApplyOutcome(False, "COMMAND_REJECTED")     # foreign or conflicting content since preflight: never merge
            if existing is None:
                argvs = [["nft", static_nat_statement(nat) if static else nat_statement(nat)]]
            elif static:
                # both directions of every new mapping in one atomic transaction: a half-applied 1:1 mapping never exists
                argvs = [["nft", static_nat_rule_commands(nat["table"], [r for r in nat["rules"] if r not in existing])]]
            else:
                argvs = [["nft", "add", "rule", "ip", nat["table"], "postrouting", *nat_rule_tokens(rule)]
                         for rule in nat["rules"] if rule not in existing]
            self._nat_applied[spec.cfg_id] = {"digest": nft_digest(ruleset), "rules": existing, "kind": nat.get("kind", "")}
            for sent, argv in enumerate(argvs, 1):
                if self._exec(argv) != 0:
                    return ApplyOutcome(False, "COMMAND_REJECTED", partial_effects=sent > 1, lines_sent=sent)
        except ExecutorError as exc:
            return ApplyOutcome(False, exc.code)
        return ApplyOutcome(True, lines_sent=len(argvs))

    def _compensate_nat(self, spec: ConfigletSpec, assessment: Assessment) -> CompensationOutcome:
        applied = self._nat_applied.get(spec.cfg_id) or {}
        wanted, table = applied.get("digest") or assessment.previous_state.get("ruleset_digest"), assessment.previous_state.get("table")
        try:
            if wanted and nft_digest(self._nft()) == wanted:
                return CompensationOutcome("COMPENSATED", detail={"action": "NONE_NEEDED"})
            if not wanted or not table or not re.fullmatch(r"[A-Za-z0-9_]{1,32}", table):
                return CompensationOutcome("COMPENSATION_FAILED", "UNSUPPORTED")
            captured = applied.get("rules")
            if captured and applied.get("kind") == "static":
                # both chains back to exactly the captured mappings, in one atomic transaction
                argv = ["nft", f"flush chain ip {table} prerouting\nflush chain ip {table} postrouting\n"
                        + static_nat_rule_commands(table, captured)]
            elif captured:
                # the table existed: put its chain back to exactly the captured rule list, in one atomic transaction
                argv = ["nft", f"flush chain ip {table} postrouting\n" + "".join(
                    f"add rule ip {table} postrouting {' '.join(nat_rule_tokens(rule))}\n" for rule in captured)]
            else:
                argv = ["nft", "delete", "table", "ip", table]
            if self._exec(argv) != 0:
                return CompensationOutcome("COMPENSATION_FAILED", "COMMAND_REJECTED")
            if nft_digest(self._nft()) != wanted:
                return CompensationOutcome("COMPENSATION_FAILED", "STATE_NOT_RESTORED")
        except ExecutorError as exc:
            return CompensationOutcome("COMPENSATION_UNVERIFIED", exc.code)
        return CompensationOutcome("COMPENSATED", detail={"action": "INVERSE_APPLIED", "commands": 1})

    # -- nftables ACLs: one dedicated table; a list chain per ACL, jumps per attachment ---------------------------------
    def _assess_acl(self, spec: ConfigletSpec) -> Assessment:
        request = acl_request(spec)
        if request is None:
            return Assessment(REFUSE, False, {}, "PLATFORM_EXECUTION_UNSUPPORTED")
        ruleset = self._nft()
        existing = nft_acl.table_from_ruleset(ruleset)
        state_before = {"kind": "nft_acl", "table": nft_acl.TABLE, "ruleset_digest": nft_digest(ruleset)}
        if existing is False:
            # a table of that name NMAS did not write in this shape: writing into it has no proven inverse
            return Assessment(APPLY, False, state_before, state.COMPENSATION_NOT_PROVABLE)
        if "chain" in request:
            current = (existing or {}).get("acls", {}).get(request["chain"])
            if current and current["rules"] == request["rules"]:
                return Assessment("SKIP_SATISFIED", True, state_before)
            return Assessment(APPLY, True, {**state_before, "replaces": bool(current)})
        present = (existing or {}).get("hooks", {}).get(request["direction"], [])
        if request["jump"] in present:
            return Assessment("SKIP_SATISFIED", True, state_before)
        if any(other[:2] == request["jump"][:2] for other in present):
            # another list of this family already filters the interface in this direction: its final deny would make
            # the new one unreachable, and replacing it is not what an attachment asks for
            return Assessment(APPLY, False, state_before, state.COMPENSATION_NOT_PROVABLE)
        return Assessment(APPLY, True, state_before)

    def _apply_acl(self, spec: ConfigletSpec, assessment: Assessment) -> ApplyOutcome:
        """One atomic nft transaction against the table found NOW (an earlier Configlet may have created it)."""
        request = acl_request(spec)
        if request is None or not assessment.restorable:
            return ApplyOutcome(False, "UNSUPPORTED")
        try:
            ruleset = self._nft()
            existing = nft_acl.table_from_ruleset(ruleset)
            if existing is False:
                return ApplyOutcome(False, "COMMAND_REJECTED")        # foreign content since preflight: never merge
            undo = {"digest": nft_digest(ruleset)}
            table = "" if existing else f"create table inet {nft_acl.TABLE}\n"
            if "chain" in request:
                chain, current = request["chain"], (existing or {}).get("acls", {}).get(request["chain"])
                if current and current["rules"] == request["rules"]:
                    command = ""
                elif current:
                    command = nft_acl.replace_chain_commands(chain, request["rules"])
                    undo.update(chain=chain, rules=current["rules"])
                else:
                    command = table + nft_acl.create_chain_commands(chain, request["rules"])
                    undo.update(chain=chain, created="table" if table else "chain")
            else:
                direction, jump = request["direction"], request["jump"]
                hook, present = nft_acl.HOOKS[direction][0], (existing or {}).get("hooks", {}).get(direction, [])
                if any(other[:2] == jump[:2] and other != jump for other in present):
                    return ApplyOutcome(False, "COMMAND_REJECTED")
                if jump in present:
                    command = ""
                elif hook in (existing or {}).get("hook_chains", []):
                    command = nft_acl.jump_commands(direction, [jump])
                    undo.update(direction=direction, jumps=present)
                else:
                    # nft refuses a jump to a list chain that does not exist, so nothing is written for an undefined ACL
                    command = table + nft_acl.create_hook_commands(direction) + nft_acl.jump_commands(direction, [jump])
                    undo.update(chain=hook, created="table" if table else "chain")
            self._acl_applied[spec.cfg_id] = undo
            if command and self._exec(["nft", command]) != 0:
                return ApplyOutcome(False, "COMMAND_REJECTED")
        except ExecutorError as exc:
            return ApplyOutcome(False, exc.code)
        return ApplyOutcome(True, lines_sent=1 if command else 0)

    def _acl_inverse(self, undo: dict, current) -> str | None:
        """The nft transaction that undoes one applied ACL Configlet, or None when it cannot be undone exactly."""
        if not current:
            return None                                        # the table vanished or is no longer the NMAS shape
        if undo.get("created") == "table":
            # delete the table only when it again holds nothing but what this Configlet created
            owned = set(current["acls"]) | set(current["hook_chains"])
            return f"delete table inet {nft_acl.TABLE}\n" if owned == {undo["chain"]} else None
        if undo.get("created") == "chain":
            return f"delete chain inet {nft_acl.TABLE} {undo['chain']}\n"   # nft refuses while a jump still uses it
        if "rules" in undo:
            return nft_acl.replace_chain_commands(undo["chain"], undo["rules"])
        if "jumps" in undo:
            hook = nft_acl.HOOKS[undo["direction"]][0]
            return f"flush chain inet {nft_acl.TABLE} {hook}\n" + nft_acl.jump_commands(undo["direction"], undo["jumps"])
        return None

    def _compensate_acl(self, spec: ConfigletSpec, assessment: Assessment) -> CompensationOutcome:
        undo = self._acl_applied.get(spec.cfg_id) or {}
        wanted = undo.get("digest") or assessment.previous_state.get("ruleset_digest")
        try:
            ruleset = self._nft()
            if wanted and nft_digest(ruleset) == wanted:
                return CompensationOutcome("COMPENSATED", detail={"action": "NONE_NEEDED"})
            if not wanted or not undo:
                return CompensationOutcome("COMPENSATION_FAILED", "UNSUPPORTED")
            command = self._acl_inverse(undo, nft_acl.table_from_ruleset(ruleset))
            if command is None:
                return CompensationOutcome("COMPENSATION_FAILED", "STATE_NOT_RESTORED")
            if self._exec(["nft", command]) != 0:
                return CompensationOutcome("COMPENSATION_FAILED", "COMMAND_REJECTED")
            if nft_digest(self._nft()) != wanted:
                return CompensationOutcome("COMPENSATION_FAILED", "STATE_NOT_RESTORED")
        except ExecutorError as exc:
            return CompensationOutcome("COMPENSATION_UNVERIFIED", exc.code)
        return CompensationOutcome("COMPENSATED", detail={"action": "INVERSE_APPLIED", "commands": 1})

    def connect(self) -> None:
        if not self._device.get("container"):
            raise ExecutorError("NOT_CONFIGURED")
        self._read()  # a probe: the container must exist and answer a read-only query before any mutation

    def _read(self):
        evidence = self._reader(self._device)
        if not getattr(evidence, "live_reachable", False):
            raise ExecutorError("PREVIOUS_STATE_UNAVAILABLE")
        return evidence

    def assess(self, spec: ConfigletSpec) -> Assessment:
        if spec.origin == "RAW":  # a Raw Configlet is never interpreted as an iproute2 / Linux command
            return Assessment(REFUSE, False, {}, "PLATFORM_EXECUTION_UNSUPPORTED")
        if spec.object_type in FRR_ROUTING_TYPES:
            self._read()
            return self._assess_routing(spec)
        if spec.object_type in NAT_TYPES:
            self._read()
            return self._assess_nat(spec)
        if spec.object_type in ACL_TYPES:
            self._read()
            return self._assess_acl(spec)
        if not spec.lines or parse_lines(spec.lines) is None:   # an empty Configlet is refused, as by every other executor
            return Assessment(REFUSE, False, {}, "PLATFORM_EXECUTION_UNSUPPORTED")
        evidence = self._read()
        request = self._existing_link_request(spec)
        if request:
            found = self._assess_existing_link(request)
            if found is not None:
                return found
        # An exact inverse is safe only when the route's prefix is unused.
        # Refuse to compete with an existing static or dynamic route.
        if spec.object_type == "static_route":
            prefix = live.norm_prefix(spec.expected.get("prefix"))
            if any(route.get("prefix") == prefix for route in evidence.facts("routes") or []):
                found = state.assess(spec, evidence, additive_overwrites_primary=False)
                if found.action != "SKIP_SATISFIED":
                    return Assessment(REFUSE, False, {}, "PLATFORM_EXECUTION_UNSUPPORTED")
                return found
        found = state.assess(spec, evidence, additive_overwrites_primary=False)
        if found.action == APPLY and found.restorable and inverse_operations(spec) is None:
            found.restorable, found.reason = False, state.COMPENSATION_NOT_PROVABLE
        return found

    def _exec(self, argv: list[str]) -> int:
        return self._run(self._device["container"], argv, self._timeout)

    def apply(self, spec: ConfigletSpec, assessment: Assessment) -> ApplyOutcome:
        if spec.object_type in FRR_ROUTING_TYPES:
            return self._apply_routing(spec, assessment)
        if spec.object_type in NAT_TYPES:
            return self._apply_nat(spec, assessment)
        if spec.object_type in ACL_TYPES:
            return self._apply_acl(spec, assessment)
        operations = parse_lines(spec.lines)
        if operations is None:
            return ApplyOutcome(False, "UNSUPPORTED")
        if assessment.previous_state.get("kind") == "link":   # existing interface: send only the fields that differ
            changes = assessment.previous_state.get("changes") or {}
            operations = [op for op in operations if (op["kind"] == "set_mtu" and "mtu" in changes) or
                          (op["kind"] == "set_state" and "up" in changes)]
        sent = 0
        try:
            for operation in operations:
                if operation["kind"] == "route":
                    argvs = [["vtysh", "-c", "configure terminal", "-c",
                              f"{operation['args'][0]} route {operation['args'][1]} {operation['args'][2]}" +
                              (f" {operation['args'][3]}" if operation['args'][3] else "")]]
                elif operation["kind"] in ("add_vlan", "add_bridge", "add_dummy"):
                    name = operation["args"][0]  # parse_lines guarantees the guard names the interface being created
                    if self._exec(["ip", "link", "show", "dev", name]) == 0:  # the template's own guard: create only if absent
                        continue
                    add = (["ip", "link", "add", "link", operation["args"][1], "name", name, "type", "vlan", "id", operation["args"][3]]
                           if operation["kind"] == "add_vlan" else
                           ["ip", "link", "add", name, "type", "bridge" if operation["kind"] == "add_bridge" else "dummy"])
                    argvs = [add]
                else:
                    argvs = _argv(operation)
                for argv in argvs:
                    code = self._exec(argv)
                    sent += 1
                    if code != 0:
                        return ApplyOutcome(False, "COMMAND_REJECTED", partial_effects=sent > 1, lines_sent=sent)
        except ExecutorError as exc:
            return ApplyOutcome(False, exc.code, partial_effects=sent > 0, lines_sent=sent)
        return ApplyOutcome(True, lines_sent=sent)

    def compensate(self, spec: ConfigletSpec, assessment: Assessment) -> CompensationOutcome:
        if spec.object_type in FRR_ROUTING_TYPES:
            return self._compensate_routing(spec, assessment)
        if spec.object_type in NAT_TYPES:
            return self._compensate_nat(spec, assessment)
        if spec.object_type in ACL_TYPES:
            return self._compensate_acl(spec, assessment)
        if assessment.previous_state.get("kind") == "link":
            return self._compensate_existing_link(assessment)
        try:
            if state.restored(spec, self._read(), assessment.previous_state):
                return CompensationOutcome("COMPENSATED", detail={"action": "NONE_NEEDED"})
        except ExecutorError as exc:
            return CompensationOutcome("COMPENSATION_UNVERIFIED", exc.code)
        inverse = inverse_operations(spec)
        if inverse is None:
            return CompensationOutcome("COMPENSATION_FAILED", "UNSUPPORTED")
        try:
            for argv in inverse:
                if self._exec(argv) != 0:
                    return CompensationOutcome("COMPENSATION_FAILED", "COMMAND_REJECTED")
            verdict = state.restored(spec, self._read(), assessment.previous_state)
        except ExecutorError as exc:
            return CompensationOutcome("COMPENSATION_UNVERIFIED", exc.code)
        if verdict is None:
            return CompensationOutcome("COMPENSATION_UNVERIFIED", "VERIFICATION_UNAVAILABLE")
        if not verdict:
            return CompensationOutcome("COMPENSATION_FAILED", "STATE_NOT_RESTORED")
        return CompensationOutcome("COMPENSATED", detail={"action": "INVERSE_APPLIED", "commands": len(inverse)})
