"""Lab 7 closure -- ``route_shield.checks``: every observation the migration is gated on, called directly with a pass and a fail.

Pure and hermetic: the environment is a namespace whose ``executors`` answer canned ``show`` / neighbour / cover-state reads (the shapes the
real ``CeosExecutor`` / ``KernelCoverExecutor`` return).  Nothing is configured and no session is opened.  POSITIVE: each check returns
``(True, detail)`` on the healthy reading.  NEGATIVE: an absent / wrong-source / management / unprogrammed route, a missing adjacency or LSP,
a silent neighbour, a leftover temporary statement, a cover in the wrong state, a busy core, a changed core adjacency and every unreadable
device return ``(False, reason)`` -- an unreadable device is never a pass.
"""
from __future__ import annotations

import json
from types import SimpleNamespace

from django.test import SimpleTestCase

from core.services.execution.executors.base import ExecutorError
from core.services.route_shield import checks

PREFIX = "2001:db8:10::/64"


def route_json(prefix=PREFIX, *, kind="static", interface="Ethernet1", hop="fe80::1", programmed=True):
    vias = [{"interface": interface, **({"nexthopAddr": hop} if hop else {})}]
    return json.dumps({"vrfs": {"default": {"routes": {prefix: {"routeType": kind, "vias": vias, "hardwareProgrammed": programmed,
                                                                "kernelProgrammed": programmed}}}}})


def isis_json(*interfaces, state="up"):
    adjacencies = [{"interfaceName": i, "state": state, "level": "level-2", "hostname": "R2"} for i in interfaces]
    return json.dumps({"vrfs": {"default": {"isisInstances": {"core": {"neighbors": {"0000.0000.0002": {"adjacencies": adjacencies}}}}}}})


class FakeExecutor:
    def __init__(self, outputs=None, *, error=None, answers=True, state="EXACT", forwards=True, client=None):
        self.outputs, self.error, self._answers, self._state, self._forwards = outputs or {}, error, answers, state, forwards
        self.client = client or {"installed": True, "active_next_hops": 2, "quiet_seconds": 120}

    def show(self, command):
        if self.error:
            raise ExecutorError(self.error)
        for prefix, text in self.outputs.items():
            if command.startswith(prefix):
                return text
        return ""

    def neighbour_answers(self, address, interface=""):
        return self._answers(address, interface) if callable(self._answers) else self._answers

    def state(self, cover):
        if self.error:
            raise ExecutorError(self.error)
        return self._state

    def forwards(self, cover):
        return self._forwards

    def client_route(self, prefix):
        if self.error:
            raise ExecutorError(self.error)
        return self.client


def env(**executors):
    return SimpleNamespace(executors=executors, clock=lambda: 1000.0, last_change_at=None, baseline={}, devices={})


ROUTE_ENV = env(R1=FakeExecutor({"show ipv6 route": route_json()}))
COVER = SimpleNamespace(core="R5", prefix="2001:db8:99::/64")


class RouteReadTests(SimpleTestCase):
    def test_route_returns_the_selected_route(self):
        self.assertEqual(checks.route(ROUTE_ENV, "R1", PREFIX), {"prefix": PREFIX, "type": "static", "interfaces": ["Ethernet1"], "next_hops": ["fe80::1"],
                                                                "vias": [("fe80::1", "Ethernet1")], "programmed": True})

    def test_route_of_an_unreadable_device_or_another_prefix_is_none(self):
        for label, environment, target in (("none for unreadable", env(R1=FakeExecutor(error="CONNECTION_FAILED")), PREFIX),
                                           ("none for invalid json", env(R1=FakeExecutor({"show ipv6 route": "{not json"})), PREFIX),
                                           ("none for other prefix", ROUTE_ENV, "2001:db8:20::/64")):
            with self.subTest(label):
                self.assertIsNone(checks.route(environment, "R1", target))

    def test_owned_and_lookup_accept_the_intended_static_route(self):
        self.assertEqual(checks.owned(ROUTE_ENV, device="R1", prefix=PREFIX, source="static", interface="Ethernet1", next_hop="fe80::1"),
                         (True, f"{PREFIX}: static via Ethernet1 programmed=True"))
        self.assertEqual(checks.lookup(ROUTE_ENV, device="R1", address="2001:db8:10::5", prefix=PREFIX, source="static", interface="Ethernet1")[0], True)

    def test_owned_and_lookup_refuse_wrong_source_management_or_absent_routes(self):
        management = env(R1=FakeExecutor({"show ipv6 route": route_json(interface="Management0")}))
        for label, call in (("refused wrong source", lambda: checks.owned(ROUTE_ENV, device="R1", prefix=PREFIX, source="isis", interface="")),
                            ("refused management", lambda: checks.owned(management, device="R1", prefix=PREFIX, source="static", interface="")),
                            ("refused absent owned", lambda: checks.owned(env(R1=FakeExecutor()), device="R1", prefix=PREFIX, source="static", interface="")),
                            ("refused wrong interface lookup", lambda: checks.lookup(ROUTE_ENV, device="R1", address="2001:db8:10::5", prefix=PREFIX,
                                                                                      source="", interface="Ethernet2")),
                            ("refused absent lookup", lambda: checks.lookup(env(R1=FakeExecutor()), device="R1", address="2001:db8:10::5", prefix=PREFIX,
                                                                            source="", interface="Ethernet1"))):
            with self.subTest(label):
                self.assertFalse(call()[0])

    def test_absent_accepts_a_withdrawn_route(self):
        self.assertEqual(checks.absent(env(R1=FakeExecutor()), device="R1", prefix=PREFIX), (True, f"{PREFIX}: absent"))

    def test_absent_refuses_a_route_that_is_still_installed(self):
        self.assertEqual(checks.absent(ROUTE_ENV, device="R1", prefix=PREFIX), (False, f"{PREFIX}: static"))


class AdjacencyAndNeighbourTests(SimpleTestCase):
    def test_adjacencies_up_and_database_holds_accept_the_expected_state(self):
        e = env(R1=FakeExecutor({"show isis neighbors": isis_json("Ethernet1", "Ethernet2"), "show isis database": f"LSP R2 {PREFIX} more"}))
        self.assertEqual(checks.adjacencies_up(e, device="R1", interfaces=["Ethernet2", "Ethernet1"]), (True, "up on Ethernet1, Ethernet2"))
        self.assertEqual(checks.database_holds(e, device="R1", prefixes=[PREFIX]), (True, "all present"))

    def test_adjacencies_up_and_database_holds_refuse_missing_or_unreadable_state(self):
        down = env(R1=FakeExecutor({"show isis neighbors": isis_json("Ethernet1", state="init"), "show isis database": "LSP R2"}))
        broken = env(R1=FakeExecutor(error="TIMEOUT"))
        for label, call, detail in (("refused adjacency down", lambda: checks.adjacencies_up(down, device="R1", interfaces=["Ethernet1"]), "up on nothing"),
                                    ("refused unreadable neighbours", lambda: checks.adjacencies_up(broken, device="R1", interfaces=[]), "IS-IS neighbours unreadable"),
                                    ("refused missing lsp", lambda: checks.database_holds(down, device="R1", prefixes=[PREFIX]), f"missing {PREFIX}"),
                                    ("refused unreadable database", lambda: checks.database_holds(broken, device="R1", prefixes=[]), "IS-IS database unreadable")):
            with self.subTest(label):
                self.assertEqual(call(), (False, detail))

    def test_answers_and_takeover_ready_accept_answering_next_hops(self):
        e = env(R1=FakeExecutor({"show ipv6 route": route_json()}))
        self.assertEqual(checks.answers(e, device="R1", address="fe80::1", interface="Ethernet1"), (True, "fe80::1 answered"))
        self.assertEqual(checks.takeover_ready(e, device="R1", prefixes=[PREFIX]), (True, "every take-over next hop answers"))

    def test_answers_and_takeover_ready_refuse_silent_unprogrammed_or_hopless_routes(self):
        silent = env(R1=FakeExecutor({"show ipv6 route": route_json()}, answers=False))
        unprogrammed = env(R1=FakeExecutor({"show ipv6 route": route_json(programmed=False)}))
        hopless = env(R1=FakeExecutor({"show ipv6 route": route_json(hop="")}))
        for label, call, detail in (("refused silent", lambda: checks.answers(silent, device="R1", address="fe80::1"), "fe80::1 did not answer"),
                                    ("refused silent next hop", lambda: checks.takeover_ready(silent, device="R1", prefixes=[PREFIX]),
                                     f"{PREFIX}: next hop fe80::1 on Ethernet1 does not answer"),
                                    ("refused unprogrammed", lambda: checks.takeover_ready(unprogrammed, device="R1", prefixes=[PREFIX]),
                                     f"{PREFIX}: take-over route is not programmed"),
                                    ("refused without next hop", lambda: checks.takeover_ready(hopless, device="R1", prefixes=[PREFIX]),
                                     f"{PREFIX}: take-over route has no next hop")):
            with self.subTest(label):
                self.assertEqual(call(), (False, detail))


class ConfigurationAndCoverTests(SimpleTestCase):
    LINES = ["ipv6 route 2001:db8:10::/63 Ethernet1 fe80::1"]

    def test_no_temporary_lines_accepts_clean_devices(self):
        e = env(R1=FakeExecutor({"show running-config": "hostname R1\nipv6 route 2001:db8:10::/64 Ethernet1 fe80::1\n"}))
        self.assertEqual(checks.no_temporary_lines(e, devices=["R1"], lines=self.LINES), (True, "none configured"))

    def test_no_temporary_lines_refuses_leftover_or_unreadable_configuration(self):
        left = env(R1=FakeExecutor({"show running-config": "hostname R1\n" + self.LINES[0] + "\n"}))
        for label, e, detail in (("refused leftover", left, "R1 still holds ipv6 route 2001:db8:10::/63 Ethernet1 fe80::1"),
                                 ("refused unreadable", env(R1=FakeExecutor(error="TIMEOUT")), "R1: running configuration unreadable")):
            with self.subTest(label):
                self.assertEqual(checks.no_temporary_lines(e, devices=["R1"], lines=self.LINES), (False, detail))

    def test_cover_installed_and_cover_absent_accept_the_expected_states(self):
        self.assertEqual(checks.cover_installed(env(R5=FakeExecutor()), cover=COVER), (True, f"{COVER.prefix}: EXACT"))
        self.assertEqual(checks.cover_absent(env(R5=FakeExecutor(state="ABSENT")), cover=COVER), (True, f"{COVER.prefix}: ABSENT"))

    def test_cover_installed_and_cover_absent_refuse_wrong_states_or_unreadable_cores(self):
        for label, call, expected in (("refused not forwarding", lambda: checks.cover_installed(env(R5=FakeExecutor(forwards=False)), cover=COVER),
                                       (False, f"{COVER.prefix}: EXACT")),
                                      ("refused unreadable install", lambda: checks.cover_installed(env(R5=FakeExecutor(error="TIMEOUT")), cover=COVER),
                                       (False, "TIMEOUT")),
                                      ("refused still present", lambda: checks.cover_absent(env(R5=FakeExecutor(state="EXACT")), cover=COVER),
                                       (False, f"{COVER.prefix}: EXACT")),
                                      ("refused unreadable absent", lambda: checks.cover_absent(env(R5=FakeExecutor(error="TIMEOUT")), cover=COVER),
                                       (False, "TIMEOUT"))):
            with self.subTest(label):
                self.assertEqual(call(), expected)

    def test_cores_quiet_accepts_settled_cores(self):
        self.assertEqual(checks.cores_quiet(env(R5=FakeExecutor()), cores=["R5"], prefixes=[PREFIX], seconds=60), (True, "quiet for 60 s"))

    def test_cores_quiet_refuses_recent_changes_single_paths_or_unreadable_cores(self):
        recent = env(R5=FakeExecutor())
        recent.last_change_at = 990.0
        single = env(R5=FakeExecutor(client={"installed": True, "active_next_hops": 1, "quiet_seconds": 500}))
        for label, e, detail in (("refused recent change", recent, "quiet for 10 s"),
                                 ("refused single path", single, f"R5: {PREFIX} is not installed toward both boundary routers"),
                                 ("refused unreadable", env(R5=FakeExecutor(error="TIMEOUT")), "TIMEOUT")):
            with self.subTest(label):
                self.assertEqual(checks.cores_quiet(e, cores=["R5"], prefixes=[PREFIX], seconds=60), (False, detail))

    def adjacency_env(self, before):
        e = env()
        e.baseline = {"R5": {"adjacencies": before}}
        e.devices = {"R5": {"name": "R5"}}
        e.read = lambda device: "evidence"
        return e

    def test_core_adjacencies_unchanged_accepts_the_precheck_state(self):
        from core.services.route_shield import core_cover
        e = self.adjacency_env([["10.0.0.1", "FULL"]])
        with self.subTest("same adjacencies"), mock_adjacencies(core_cover, [("10.0.0.1", "FULL")]):
            self.assertEqual(checks.core_adjacencies_unchanged(e, core="R5"), (True, "unchanged"))

    def test_core_adjacencies_unchanged_refuses_a_changed_or_unrecorded_state(self):
        from core.services.route_shield import core_cover
        for label, before, now in (("refused changed", [["10.0.0.1", "FULL"]], [("10.0.0.1", "INIT")]), ("refused unrecorded", None, [])):
            with self.subTest(label), mock_adjacencies(core_cover, now):
                self.assertEqual(checks.core_adjacencies_unchanged(self.adjacency_env(before), core="R5"),
                                 (False, "the adjacency state differs from the precheck"))


def mock_adjacencies(core_cover, rows):
    from unittest import mock
    return mock.patch.object(core_cover, "adjacencies", return_value=rows)
