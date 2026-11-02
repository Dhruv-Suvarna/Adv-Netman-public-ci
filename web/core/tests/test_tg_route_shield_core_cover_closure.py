"""Lab 7 closure -- ``route_shield.core_cover``: the approved kernel cover route, the ``KernelCoverExecutor`` reads and the fail-closed
precheck / postcheck, each called directly.

Hermetic: the executor's only transport, ``runner(container, argv, timeout)``, is ``FakeKernel`` -- an in-memory answer per read-only argv
(``ip -j -6 route|neigh``, ``vtysh -c show ...``, ``cat /etc/frr/frr.conf``, ``hostname``).  No ``docker exec`` is spawned and nothing is
installed: every test here is a READ or a pure check.  POSITIVE: the exact cover facts, digests, neighbour sets and an empty precheck on a
healthy core.  NEGATIVE: malformed / foreign covers are refused, unreadable reads raise ``ExecutorError``, an unresolved neighbour, a
management-only lookup, a leftover cover and changed adjacencies are reported, missing evidence blocks.
"""
from __future__ import annotations

import json
import subprocess
from types import SimpleNamespace

from django.test import SimpleTestCase

from core.services.execution.executors.base import ExecutorError
from core.services.route_shield import core_cover as cc, gates

COVER = cc.APPROVED_COVERS[0]           # R3: 2001:db8:10::/63 toward R1 (Vlan101) and R2 (Vlan103)
CLIENT = COVER.protects
HOP_ROWS = [{"gateway": address, "dev": interface} for address, interface in COVER.next_hops]


class FakeKernel:
    """Answers the executor's read-only argv from in-memory tables.  ``fail`` names argv prefixes that exit non-zero."""

    def __init__(self, **overrides):
        self.tables = {
            "default": [{"dst": "default", "gateway": "fe80::1", "dev": "eth0"}],
            "show": {CLIENT: [{"dst": CLIENT, "protocol": "ospf6", "nexthops": HOP_ROWS}]},
            "root": {COVER.prefix: [{"dst": CLIENT}]},
            "get": [{"gateway": COVER.next_hops[0][0], "dev": COVER.next_hops[0][1]}],
            "neigh": [{"lladdr": "aa:c1:ab:00:00:01", "state": ["REACHABLE"]}],
            "ospf6": {"1.1.1.1": {"neighborState": "Full", "linkLocalAddress": COVER.next_hops[0][0], "interface": COVER.next_hops[0][1]},
                      "2.2.2.2": {"neighborState": "Full", "linkLocalAddress": COVER.next_hops[1][0], "interface": COVER.next_hops[1][1]},
                      "3.3.3.3": {"neighborState": "Init", "linkLocalAddress": "fe80::9", "interface": "eth9"}},
            "client": {CLIENT: [{"installed": True, "internalNextHopActiveNum": 2, "uptime": "1d02h03m"}]},
            "running": "Building configuration...\n!\nfrr version 8.4.4\nrouter ospf6\n ospf6 router-id 3.3.3.3\n",
            "persistent": "frr version 8.4.4\nrouter ospf6\n",
            "hostname": "R3\n", "version": "FRRouting 8.4.4 (R3) on Linux\n", "all": [],
        }
        self.tables.update(overrides)
        self.fail, self.calls = set(), []

    def __call__(self, container, argv, timeout):
        self.calls.append((container, list(argv)))
        key = " ".join(argv)
        if any(key.startswith(prefix) for prefix in self.fail):
            return subprocess.CompletedProcess(argv, 1, "", "error")
        return subprocess.CompletedProcess(argv, 0, self.answer(argv), "")

    def answer(self, argv):
        t = self.tables
        if argv[:4] == ["ip", "-j", "-6", "route"]:
            verb, rest = argv[4], argv[5:]
            if rest == ["default"]:
                return json.dumps(t["default"])
            if verb == "get":
                return json.dumps(t["get"])
            if rest[:1] == ["root"]:
                return json.dumps(t["root"].get(rest[1], []))
            if rest[:2] == ["table", "all"]:
                return json.dumps(t["all"])
            return json.dumps(t["show"].get(rest[0], []))
        if argv[:4] == ["ip", "-j", "-6", "neigh"]:
            return json.dumps(t["neigh"])
        if argv[:2] == ["vtysh", "-c"]:
            command = argv[2]
            if command.startswith("show ipv6 ospf6 neighbor"):
                return json.dumps(t["ospf6"])
            if command == "show running-config":
                return t["running"]
            if command == "show version":
                return t["version"]
            if command.startswith("show ipv6 route"):
                return json.dumps(t["client"])
        if argv == ["cat", cc.PERSISTENT_CONFIG]:
            return t["persistent"]
        if argv == ["hostname"]:
            return t["hostname"]
        raise AssertionError(f"unexpected argv {argv}")


def executor(kernel=None, **kwargs):
    kernel = kernel or FakeKernel()
    return cc.KernelCoverExecutor({"name": "R3", "container": "clab-sandbox-R3"}, runner=kernel, **kwargs), kernel


def evidence(*, oper="UP", ospf=None, reachable=True):
    facts = {"interfaces": {interface: {"oper": oper} for _a, interface in COVER.next_hops},
             "ospf": ospf if ospf is not None else [{"family": "ipv6", "interface": "Vlan101", "neighbor_id": "1.1.1.1", "state": "Full"}]}
    return SimpleNamespace(facts=facts.get, live_reachable=reachable)


class CoverRouteTests(SimpleTestCase):
    def test_from_expected_hops_and_removal_lines_round_trip_an_approved_cover(self):
        route = cc.CoverRoute.from_expected(COVER.to_expected())
        self.assertEqual(route, COVER)
        self.assertEqual(route.hops, tuple(sorted(COVER.next_hops)))
        self.assertEqual(route.removal_lines(), (f"ip -6 route del {COVER.prefix}",))
        spec = cc.remove_spec(route, "SHIELD-R3-1", 7)
        self.assertEqual((spec.operation, spec.lines, spec.device, spec.object_type), ("REMOVE_DELETE", route.removal_lines(), "R3", cc.OBJECT_TYPE))

    def test_from_expected_refuses_malformed_or_foreign_covers(self):
        good = COVER.to_expected()
        for label, expected in (("refused missing key", {"core": "R3"}), ("refused unapproved core", dict(good, core="R1")),
                                ("refused wrong length", dict(good, prefix="2001:db8:10::/62")),
                                ("refused management hop", dict(good, next_hops=[[COVER.next_hops[0][0], "Management0"], list(COVER.next_hops[1])]))):
            with self.subTest(label), self.assertRaises(cc.CoverError):
                cc.CoverRoute.from_expected(expected)

    def test_is_approved_refuses_an_unlisted_cover(self):
        other = cc.CoverRoute("R3", "2001:db8:40::/63", "2001:db8:40::/64", COVER.next_hops)
        self.assertFalse(cc.is_approved(other))


class ExecutorReadTests(SimpleTestCase):
    def test_reads_return_the_kernel_and_frr_facts(self):
        ex, kernel = executor()
        self.assertEqual(ex.routes(CLIENT)[0]["dst"], CLIENT)
        self.assertEqual(ex.routes_within(COVER.prefix), [{"dst": CLIENT}])
        self.assertEqual(ex.management_interfaces(), {"eth0"})
        self.assertEqual(ex.full_neighbours(), set(COVER.next_hops))
        self.assertEqual(ex.neighbour_state(*COVER.next_hops[0]), "RESOLVED")
        self.assertEqual(ex.identity(), {"hostname": "R3", "platform": "FRRouting", "version": "8.4.4"})
        self.assertRegex(ex.frr_config_digest(), r"^[0-9a-f]{64}$")
        self.assertEqual(ex.persistent_config_digest(), cc.canonical.text_hash(kernel.tables["persistent"]))
        self.assertEqual(ex.client_route(CLIENT), {"installed": True, "active_next_hops": 2, "quiet_seconds": 93780})
        self.assertTrue(all(container == "clab-sandbox-R3" for container, _argv in kernel.calls))

    def test_reads_of_a_failing_kernel_raise_executor_error(self):
        kernel = FakeKernel()
        kernel.fail = {"ip -j -6 route show", "vtysh"}
        ex, _ = executor(kernel)
        for label, call in (("refused routes", lambda: ex.routes(CLIENT)), ("refused routes within", lambda: ex.routes_within(COVER.prefix))):
            with self.subTest(label), self.assertRaisesRegex(ExecutorError, "PREVIOUS_STATE_UNAVAILABLE"):
                call()
        with self.subTest("invalid json client route"):
            self.assertEqual(ex.client_route(CLIENT), {"installed": False, "active_next_hops": 0, "quiet_seconds": -1})

    def test_neighbour_state_of_a_failed_or_unused_neighbour(self):
        for label, rows, expected in (("refused unresolved", [{"state": ["FAILED"]}], "UNRESOLVED"), ("none unused", [], "UNUSED")):
            with self.subTest(label):
                ex, _ = executor(FakeKernel(neigh=rows))
                self.assertEqual(ex.neighbour_state(*COVER.next_hops[0]), expected)

    def test_forwards_and_allowed_refuse_management_lookups_and_unlisted_covers(self):
        ex, _ = executor(FakeKernel(get=[{"gateway": "fe80::1", "dev": "eth0"}]))
        with self.subTest("refused management lookup"):
            self.assertFalse(ex.forwards(COVER))
        with self.subTest("refused unlisted cover"):
            self.assertFalse(ex.allowed(cc.CoverRoute("R3", "2001:db8:40::/63", "2001:db8:40::/64", COVER.next_hops)))
        sandbox, _ = executor(sandbox_covers=[COVER])
        with self.subTest("refused cover outside the sandbox list"):
            self.assertFalse(sandbox.allowed(cc.APPROVED_COVERS[1]))


class PrecheckPostcheckTests(SimpleTestCase):
    def test_precheck_passes_a_healthy_core(self):
        ex, _ = executor()
        self.assertEqual(cc.precheck([COVER], ex, evidence()), [])

    def test_postcheck_reports_an_unconfirmed_or_leftover_cover_and_changed_adjacencies(self):
        ex, _ = executor()
        with self.subTest("refused unconfirmed cover"):
            self.assertEqual([b["code"] for b in cc.postcheck([COVER], ex, evidence(), present=True)], ["SHIELD_NOT_CONFIRMED"])
        installed, _ = executor(FakeKernel(show={COVER.prefix: [{"dst": COVER.prefix, "protocol": "boot", "nexthops": HOP_ROWS}]}))
        with self.subTest("refused leftover cover"):
            self.assertEqual([b["code"] for b in cc.postcheck([COVER], installed, evidence(), present=False)], ["TEMPORARY_STATE_REMAINS"])
        with self.subTest("refused changed adjacencies"):
            before = cc.adjacencies(evidence())
            changed = evidence(ospf=[{"family": "ipv6", "interface": "Vlan101", "neighbor_id": "1.1.1.1", "state": "Init"}])
            self.assertEqual([b["code"] for b in cc.postcheck([COVER], installed, changed, adjacencies_before=before, present=True)],
                             [gates.NEXT_HOP_UNHEALTHY])

    def test_adjacencies_without_ospf_evidence_is_none(self):
        self.assertEqual((cc.adjacencies(None), cc.adjacencies(SimpleNamespace(facts=lambda name: None))), (None, None))
