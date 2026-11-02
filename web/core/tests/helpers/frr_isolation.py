"""An in-memory Ubuntu/FRR trusted upstream for the FRR isolation tests.

``FakeFrrUpstream`` answers exactly the argv lists ``FrrIsolationExecutor`` sends (it is the executor's ``runner``) and keeps
an nftables state: tables are created atomically from a full ``table inet ...`` statement and deleted as a whole, and the
listings / JSON / hook dump are derived from that state the way nft 1.0.9 prints them (counters included).  Unknown argv
fails with status 1, so an executor that sends anything else is caught by the tests.
"""

from __future__ import annotations

import json

from core.services.execution.executors.frr_isolation import CAPABILITY_CANARY, FrrIsolationExecutor, PROCESS_LIST
from core.services.isolation import frr
from core.services.isolation import service as isolation_service

PORT = "eth4"
GATEWAY = "10.254.30.1"
SERVICE = "10.254.31.2"
NMAS_SOURCE = "192.168.200.100"
FRR_TEXT = """frr version 8.4.4
frr defaults traditional
hostname R4
interface Vlan102
 ip ospf area 0.0.0.0
exit
interface eth4
 ip ospf area 0.0.0.10
exit
router ospf
 ospf router-id 10.255.0.4
exit
"""


def link(name, *addresses, kind="", master="", parent="", up=True):
    info = {"linkinfo": {"info_kind": kind}} if kind else {}
    rows = [{"family": "inet6" if ":" in a else "inet", "local": a.split("/")[0], "prefixlen": int(a.split("/")[1])} for a in addresses]
    return {"ifname": name, "flags": ["UP"] if up else [], "addr_info": rows, **info, **({"master": master} if master else {}),
            **({"link": parent} if parent else {})}


class FakeFrrUpstream:
    def __init__(self, *, frr_text=FRR_TEXT, links=None, routes4=None, routes6=None, relay=True, extra_tables=None):
        self.frr_text = frr_text
        self.links = links if links is not None else [
            link("lo", "127.0.0.1/8"), link("Vlan102", "10.254.91.1/30", kind="bridge"),
            link(PORT, f"{GATEWAY}/24", "2001:db8:30::1/64", "fe80::1/64"), link("eth2", "10.254.31.1/30")]
        self.routes4 = routes4 if routes4 is not None else [{"dst": "10.254.30.0/24", "dev": PORT, "protocol": "kernel"},
                                                            {"dst": "default", "dev": "Vlan102", "protocol": "ospf"}]
        self.routes6 = routes6 if routes6 is not None else [{"dst": "2001:db8:30::/64", "dev": PORT, "protocol": "kernel"}]
        self.processes = ["/usr/lib/frr/zebra -d", f"dhcrelay -4 -d -id {PORT} -iu eth2 {SERVICE}"] if relay else ["/usr/lib/frr/zebra -d"]
        self.tables: dict[str, str] = dict(extra_tables or {})     # name -> listing body lines (without counters)
        self.counters: dict[tuple, int] = {}                        # (table, chain) -> packets on the drop rule
        self.ospf_json, self.ospf6_json, self.neigh = json.dumps({"neighbors": {}}), json.dumps({"neighbors": []}), []
        self.route_get = {NMAS_SOURCE: "Vlan102"}
        self.calls: list[list[str]] = []
        self.fail = None                                            # fail(argv) -> True: that call returns status 1
        self.lost = None                                            # lost(argv) -> True: the call raises (session lost)
        self.can = {"check": True, "hooks": True}

    # ------------------------------------------------------------------------------------------------------------ helpers
    def listing(self, name: str, *, counters=True) -> str:
        body = self.tables[name]
        out = []
        chain = ""
        for line in body.splitlines():
            stripped = line.strip()
            if stripped.startswith("chain "):
                chain = stripped.split()[1]
            if counters and stripped.endswith("counter drop"):
                stripped = stripped.replace("counter drop", f"counter packets {self.counters.get((name, chain), 0)} bytes 0 drop")
            out.append(stripped)
        return "\n".join(out) + "\n"

    def ruleset(self) -> str:
        return "".join(self.listing(name) for name in sorted(self.tables))

    def hooks(self) -> str:
        lines = []
        for family in ("ip", "ip6"):
            lines.append(f"family {family} {{")
            for name in sorted(self.tables):
                for chain in ("input", "forward", "output"):
                    if f"chain {chain} {{" in self.tables[name] and f"hook {chain} " in self.tables[name]:
                        lines.append(f"\t0000000000 chain inet {name} {chain} [nf_tables]")
            lines.append("}")
        return "\n".join(lines) + "\n"

    def table_json(self, name: str) -> str:
        items = [{"table": {"family": "inet", "name": name}}]
        for chain in ("forward", "input", "output"):
            if f"chain {chain} {{" in self.tables[name]:
                items.append({"chain": {"family": "inet", "table": name, "name": chain, "type": "filter", "hook": chain, "prio": 0,
                                        "policy": "accept"}})
                if f'"{PORT}" counter drop' in self.tables[name] or "counter drop" in self.tables[name]:
                    items.append({"rule": {"chain": chain, "expr": [{"counter": {"packets": self.counters.get((name, chain), 0)}}, {"drop": None}]}})
        return json.dumps({"nftables": items})

    def hit(self, name: str, chain: str = "forward", packets: int = 3) -> None:
        """The hostile device's packets meet a drop rule."""
        self.counters[(name, chain)] = self.counters.get((name, chain), 0) + packets

    # ------------------------------------------------------------------------------------------------------------ runner
    def __call__(self, argv, _timeout):
        argv = list(argv)
        self.calls.append(argv)
        if self.lost and self.lost(argv):
            from core.services.execution.executors.base import ExecutorError

            raise ExecutorError("TRANSPORT_ERROR")
        if self.fail and self.fail(argv):
            return 1, ""
        return self._answer(argv)

    def _answer(self, argv):  # pylint: disable=too-many-return-statements,too-many-branches
        if argv == ["nft", "--version"]:
            return 0, "nftables v1.0.9 (Old Doc Yak #3)\n"
        if argv == ["nft", "list", "ruleset"]:
            return 0, self.ruleset()
        if argv == ["nft", "-j", "list", "ruleset"]:
            return 0, json.dumps({"nftables": [{"metainfo": {"version": "1.0.9"}}] + [{"table": {"family": "inet", "name": n}} for n in sorted(self.tables)]})
        if argv == ["nft", "-c", CAPABILITY_CANARY]:
            return (0 if self.can["check"] else 1), ""
        if argv == ["nft", "list", "hooks"]:
            return (0, self.hooks()) if self.can["hooks"] else (1, "")
        if argv[:4] == ["nft", "list", "table", "inet"] and len(argv) == 5:
            return (0, self.listing(argv[4])) if argv[4] in self.tables else (1, "")
        if argv[:5] == ["nft", "-j", "list", "table", "inet"] and len(argv) == 6:
            return (0, self.table_json(argv[5])) if argv[5] in self.tables else (1, "")
        if argv[:4] == ["nft", "delete", "table", "inet"] and len(argv) == 5:
            return (0, "") if self.tables.pop(argv[4], None) is not None else (1, "")
        if len(argv) == 2 and argv[0] == "nft" and argv[1].startswith("table inet "):
            params = frr.parse_table(argv[1].splitlines())
            name = argv[1].split()[2]
            if name in self.tables:                                  # nft would MERGE; the executor must never send this
                self.tables[name] += "\n" + "\n".join(argv[1].splitlines()[1:-1])
                return 0, ""
            self.tables[name] = "\n".join(argv[1].splitlines()) if params else argv[1]
            return 0, ""
        if argv == ["vtysh", "-c", "show running-config"]:
            return 0, self.frr_text
        if argv == ["vtysh", "-c", "show ip ospf neighbor json"]:
            return 0, self.ospf_json
        if argv == ["vtysh", "-c", "show ipv6 ospf6 neighbor json"]:
            return 0, self.ospf6_json
        if argv == ["ip", "-d", "-j", "addr", "show"]:
            return 0, json.dumps(self.links)
        if argv == ["ip", "-j", "-4", "route", "show"]:
            return 0, json.dumps(self.routes4)
        if argv == ["ip", "-j", "-6", "route", "show"]:
            return 0, json.dumps(self.routes6)
        if argv[:4] == ["ip", "-j", "route", "get"] and len(argv) == 5:
            return 0, json.dumps([{"dst": argv[4], "dev": self.route_get.get(argv[4], "Vlan102")}])
        if argv == ["ip", "-j", "neigh", "show"]:
            return 0, json.dumps(self.neigh)
        if argv == ["sh", "-c", PROCESS_LIST]:
            return 0, "\n".join(self.processes) + "\n"
        return 1, ""


def access(upstream: FakeFrrUpstream, *, sources=(NMAS_SOURCE,)):
    """An isolation ``Access`` whose executors are the real FrrIsolationExecutor over ``upstream``."""
    return isolation_service.Access(executor_factory=lambda device: FrrIsolationExecutor(device, runner=upstream),
                                    nmas_sources=tuple(sources), sleep=lambda seconds: None)
