"""Connectivity: the required matrix (H1-H3 dual-stack, H4 IPv6 only), every sample recorded, failure / recovery, RTT parsing."""

from __future__ import annotations

from datetime import timedelta

from challenge_console import filters
from challenge_console import models as m
from challenge_console.adapters import endpoints, inventory
from challenge_console.adapters.process import CommandResult
from challenge_console.collectors import ConnectivityCollector
from challenge_console.supervisor import Supervisor

from .helpers import INVENTORY, ConsoleTestCase, FakeRunner, ping_ok, ping_timeout, wait_until

REQUIRED = {"H1/IPV4", "H1/IPV6", "H2/IPV4", "H2/IPV6", "H3/IPV4", "H3/IPV6", "H4/IPV6"}


class PlanTests(ConsoleTestCase):
    def test_required_matrix_is_exactly_the_seven_rows(self):
        plan = inventory.probe_plan(inventory.endpoints(INVENTORY))
        self.assertEqual({spec.key for spec in plan}, REQUIRED)
        self.assertEqual(len(plan), 7)

    def test_h4_ipv4_is_not_a_required_test(self):
        plan = inventory.probe_plan(inventory.endpoints(INVENTORY))
        self.assertNotIn("H4/IPV4", {spec.key for spec in plan})
        self.assertFalse([spec for spec in plan if spec.family == m.V4 and "H4" in (spec.source, spec.destination)])

    def test_every_row_targets_another_endpoint_that_has_the_family(self):
        endpoints_ = {e.name: e for e in inventory.endpoints(INVENTORY)}
        for spec in inventory.probe_plan(list(endpoints_.values())):
            self.assertNotEqual(spec.source, spec.destination)
            self.assertIn(spec.family, endpoints_[spec.destination].families)


class ParsingTests(ConsoleTestCase):
    def test_rtt_parsing(self):
        self.assertEqual(endpoints.parse_ping(ping_ok(3.14).stdout, 0), (True, 3.14, ""))
        self.assertEqual(endpoints.parse_ping("64 bytes from x: icmp_seq=1 ttl=64 time<1 ms\n1 packets transmitted, 1 received, 0% packet loss", 0),
                         (True, 1.0, ""))
        self.assertEqual(endpoints.parse_ping("1 packets transmitted, 1 packets received, 0% packet loss", 0), (True, None, ""))

    def test_timeout_and_unreachable_and_garbage(self):
        self.assertEqual(endpoints.parse_ping(ping_timeout().stdout, 1), (False, None, "TIMEOUT"))
        self.assertEqual(endpoints.parse_ping("From 10.0.0.1 icmp_seq=1 Destination Host Unreachable\n1 packets transmitted, 0 received", 1),
                         (False, None, "UNREACHABLE"))
        self.assertEqual(endpoints.parse_ping("", 2), (False, None, "PROBE_ERROR"))

    def test_addresses_are_discovered_not_hard_coded(self):
        from .helpers import addr_json
        self.assertEqual(endpoints.parse_addresses(addr_json("192.168.10.102", "2001:db8:10::2001")),
                         {m.V4: "192.168.10.102", m.V6: "2001:db8:10::2001"})
        self.assertEqual(endpoints.parse_addresses(addr_json(None, "2001:db8:30::18e5")), {m.V6: "2001:db8:30::18e5"})   # H4: no IPv4, by design
        with self.assertRaises(endpoints.DiscoveryError):
            endpoints.parse_addresses("not json")


class CollectorTests(ConsoleTestCase):
    def collector(self, runner=None):
        self.runner = runner or FakeRunner()
        collector = ConnectivityCollector(self.config, self.store, self.bus, runner=self.runner)
        collector.setup()
        self.addCleanup(collector.teardown)
        return collector

    def rows(self):
        return {row.spec.key: row for row in self.store.probe_rows()}

    def test_all_required_pairs_are_probed_and_pass(self):
        collector = self.collector()
        collector.collect()
        rows = self.rows()
        self.assertEqual(set(rows), REQUIRED)
        self.assertTrue(all(row.state == m.UP and row.samples == 1 and row.last_rtt_ms == 3.1 for row in rows.values()))
        self.assertEqual((rows["H1/IPV4"].source_address, rows["H1/IPV4"].target_address), ("192.168.10.102", "192.168.20.101"))
        self.assertEqual((rows["H4/IPV6"].source_address, rows["H4/IPV6"].target_address), ("2001:db8:30::18e5", "2001:db8:10::2001"))
        pings = [call for call in self.runner.calls if "ping" in call]
        self.assertEqual(len(pings), 7)
        self.assertFalse([call for call in pings if call[2].endswith("-H4") and "-4" in call])       # H4 never sends an IPv4 probe
        self.assertFalse([call for call in pings if call[-1].startswith("172.20.20.")])              # never the Containerlab mgmt address
        for call in pings:                                                                           # bounded: one packet, one second
            self.assertEqual(call[3:9], ("ping", "-n", "-c", "1", "-W", "1"))

    def test_every_sample_is_timestamped_and_recorded_not_only_transitions(self):
        collector = self.collector()
        for _ in range(4):
            collector.collect()
        samples = self.kinds("connectivity.sample")
        self.assertEqual(len(samples), 28)                                                           # 7 rows x 4 cycles: nothing skipped
        self.assertTrue(all(event.ts.tzinfo is not None and event.outcome == m.PASS for event in samples))
        self.assertFalse(self.kinds("connectivity.failure"))                                         # steady state: no transition events
        history = self.store.probe_history("H2/IPV6")
        self.assertEqual(len(history), 4)
        self.assertEqual(sorted(s.ts for s in history), [s.ts for s in history])

    def test_timeout_recovery_and_consecutive_failures(self):
        collector = self.collector()
        target = ("clab-lab-H1", "192.168.20.101")
        collector.collect()
        self.runner.ping_results[target] = ping_timeout()
        for _ in range(3):
            collector.collect()
        row = self.rows()["H1/IPV4"]
        self.assertEqual((row.state, row.consecutive_failures, row.failures, row.samples, row.last_reason), (m.DOWN, 3, 3, 4, "TIMEOUT"))
        self.assertIsNotNone(row.last_failure)
        self.assertEqual(row.last_change, self.store.probe_history("H1/IPV4")[1].ts)                 # when it went down
        self.assertEqual(self.rows()["H1/IPV6"].state, m.UP)                                         # the other family is unaffected
        failures = self.kinds("connectivity.failure")
        self.assertEqual([(e.target, e.data["reason"]) for e in failures], [("H1/IPV4", "TIMEOUT")])  # one transition event ...
        self.assertEqual(len([e for e in self.kinds("connectivity.sample") if e.target == "H1/IPV4" and e.outcome == m.FAIL]), 3)  # ... three samples
        self.runner.ping_results[target] = ping_ok(2.8)
        collector.collect()
        row = self.rows()["H1/IPV4"]
        self.assertEqual((row.state, row.consecutive_failures, row.failures, row.last_rtt_ms), (m.UP, 0, 3, 2.8))
        self.assertEqual([e.target for e in self.kinds("connectivity.recovery")], ["H1/IPV4"])
        self.assertEqual(row.last_success, row.last_ts)
        self.assertEqual(filters.sparkline(self.store.probe_history("H1/IPV4")), ".XXX.")
        self.assertEqual(filters.loss_percent(self.store.probe_history("H1/IPV4")), 60.0)

    def test_a_probe_that_cannot_run_is_still_a_recorded_failure(self):
        collector = self.collector()
        self.runner.ping_results[("clab-lab-H2", "192.168.10.103")] = CommandResult(None, error="TIMEOUT")
        self.runner.ping_results[("clab-lab-H3", "192.168.10.102")] = lambda: (_ for _ in ()).throw(RuntimeError("boom"))
        self.runner.ping_results[("clab-lab-H3", "2001:db8:30::18e5")] = CommandResult(1, stderr_class="CONTAINER_NOT_RUNNING")
        self.runner.ping_results[("clab-lab-H3", "2001:db8:30::18e5")] = CommandResult(126, stderr_class="CONTAINER_NOT_RUNNING")
        collector.collect()
        rows = self.rows()
        self.assertEqual((rows["H2/IPV4"].state, rows["H2/IPV4"].last_reason), (m.DOWN, "TIMEOUT"))
        self.assertEqual((rows["H3/IPV4"].state, rows["H3/IPV4"].last_reason), (m.DOWN, "PROBE_ERROR"))
        self.assertEqual((rows["H3/IPV6"].state, rows["H3/IPV6"].last_reason), (m.DOWN, "SOURCE_CONTAINER_NOT_RUNNING"))
        self.assertEqual(len(self.kinds("connectivity.sample")), 7)                                  # no row silently disappeared
        self.assertNotIn("boom", str([e.data for e in self.events]))

    def test_an_endpoint_that_cannot_be_inspected_fails_its_rows_and_is_logged(self):
        runner = FakeRunner()
        del runner.addresses["H2"]
        collector = self.collector(runner)
        collector.collect()
        rows = self.rows()
        self.assertEqual(rows["H2/IPV4"].last_reason, "SOURCE_NO_SUCH_CONTAINER")
        self.assertEqual(rows["H1/IPV4"].last_reason, "NO_TARGET_ADDRESS")                           # H1 -> H2: target unknown
        self.assertEqual(rows["H3/IPV4"].state, m.UP)
        self.assertEqual([(e.target, e.data["code"]) for e in self.kinds("connectivity.discovery_error")], [("H2", "NO_SUCH_CONTAINER")])
        runner.addresses["H2"] = ("192.168.20.150", "2001:db8:20::2001")                             # a new DHCP lease is picked up
        collector.collect()
        self.assertEqual((self.rows()["H1/IPV4"].state, self.rows()["H1/IPV4"].target_address), (m.UP, "192.168.20.150"))

    def test_one_hour_retention_through_the_collector_path(self):
        collector = self.collector()
        start = m.utcnow()
        for index in range(1500):                                                                    # 7500 s at 5 s: beyond the 2 h default
            collector.record(m.ProbeSample(start + timedelta(seconds=5 * index), "H1/IPV4", "H1", m.V4, "H2", "a", "b", True, 1.0))
        self.assertGreaterEqual(self.store.history_span_seconds("H1/IPV4"), 3600)
        self.assertEqual(len(self.store.probe_history("H1/IPV4")), 1441)                             # the 2 h default window, inclusive

    def test_runs_continuously_under_the_supervisor(self):
        collector = ConnectivityCollector(self.config, self.store, self.bus, runner=FakeRunner())
        supervisor = Supervisor(self.config, self.store, self.bus, [collector])
        self.addCleanup(supervisor.stop)
        supervisor.start()
        self.assertTrue(wait_until(lambda: len(self.store.probe_history("H4/IPV6")) >= 5))
        self.assertEqual(supervisor.stop(), [])
