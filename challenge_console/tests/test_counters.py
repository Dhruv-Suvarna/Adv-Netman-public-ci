"""Interface counters: both platform parsers, rates, reset / rollover, zero traffic, errors, appear / disappear, filters, unavailability."""

from __future__ import annotations

import json
from datetime import timedelta

from challenge_console import filters
from challenge_console import models as m
from challenge_console.adapters import counters, inventory
from challenge_console.adapters.process import CommandResult
from challenge_console.collectors import InterfaceCounterCollector
from challenge_console.state import StateStore

from .helpers import INVENTORY, ConsoleTestCase, FakeRunner


def ceos(**interfaces) -> str:
    body = {}
    for name, (status, protocol, counts) in interfaces.items():
        row = {"name": name, "interfaceStatus": status, "lineProtocolStatus": protocol, "bandwidth": 1000000000, "description": f"desc {name}"}
        if counts is not None:
            rx_b, tx_b, rx_p, tx_p, rx_e, tx_e, rx_d, tx_d = counts
            row["interfaceCounters"] = {"inOctets": rx_b, "outOctets": tx_b, "inTotalPkts": rx_p, "outTotalPkts": tx_p, "totalInErrors": rx_e,
                                        "totalOutErrors": tx_e, "inDiscards": rx_d, "outDiscards": tx_d}
        body[name] = row
    return json.dumps({"interfaces": body})


def linux(**links) -> str:
    return json.dumps([{"ifname": name, "flags": flags, "operstate": oper,
                        "stats64": {"rx": {"bytes": c[0], "packets": c[2], "errors": c[4], "dropped": c[6]},
                                    "tx": {"bytes": c[1], "packets": c[3], "errors": c[5], "dropped": c[7]}}}
                       for name, (flags, oper, c) in links.items()])


class ParserTests(ConsoleTestCase):
    def test_ceos_parsing(self):
        rows = {r.name: r for r in counters.parse_ceos(ceos(
            Ethernet1=("connected", "up", (1000, 2000, 10, 20, 1, 2, 3, 4)), Ethernet2=("disabled", "down", (0, 0, 0, 0, 0, 0, 0, 0)),
            Ethernet3=("notconnect", "down", (5, 5, 1, 1, 0, 0, 0, 0)), Loopback0=("connected", "up", None)), "R1")}
        eth1 = rows["Ethernet1"]
        self.assertEqual((eth1.device, eth1.admin, eth1.oper, eth1.speed_bps, eth1.description), ("R1", m.UP, m.UP, 1000000000, "desc Ethernet1"))
        self.assertEqual(eth1.counters(), (1000, 2000, 10, 20, 1, 2, 3, 4))
        self.assertEqual((rows["Ethernet2"].admin, rows["Ethernet2"].oper), (m.DOWN, m.DOWN))        # administratively down
        self.assertEqual((rows["Ethernet3"].admin, rows["Ethernet3"].oper), (m.UP, m.DOWN))          # enabled, no link
        self.assertEqual(rows["Loopback0"].counters(), (None,) * 8)                                  # no counters exposed: not zeros
        with self.assertRaises(counters.CounterReadError):
            counters.parse_ceos("% Invalid input", "R1")

    def test_ceos_packet_total_falls_back_to_the_cast_counters(self):
        text = json.dumps({"interfaces": {"Ethernet1": {"interfaceStatus": "connected", "lineProtocolStatus": "up", "interfaceCounters": {
            "inOctets": 1, "outOctets": 1, "inUcastPkts": 5, "inMulticastPkts": 6, "inBroadcastPkts": 7, "outUcastPkts": 1}}}})
        row = counters.parse_ceos(text, "R1")[0]
        self.assertEqual((row.rx_packets, row.tx_packets, row.rx_errors), (18, 1, None))

    def test_linux_parsing(self):
        rows = {r.name: r for r in counters.parse_linux(linux(
            eth1=(["BROADCAST", "UP", "LOWER_UP"], "UP", (466074421, 124444722, 4488089, 1371377, 0, 0, 197, 0)),
            eth2=(["BROADCAST"], "DOWN", (0, 0, 0, 0, 0, 0, 0, 0)), lo=(["LOOPBACK", "UP", "LOWER_UP"], "UNKNOWN", (9, 9, 1, 1, 0, 0, 0, 0)),
            eth9=(["NO-CARRIER", "UP"], "LOWERLAYERDOWN", (0, 0, 0, 0, 0, 0, 0, 0))), "R3")}
        eth1 = rows["eth1"]
        self.assertEqual((eth1.admin, eth1.oper, eth1.speed_bps), (m.UP, m.UP, None))                # no speed is invented for veth
        self.assertEqual(eth1.counters(), (466074421, 124444722, 4488089, 1371377, 0, 0, 197, 0))
        self.assertEqual((rows["eth2"].admin, rows["eth2"].oper), (m.DOWN, m.DOWN))
        self.assertEqual(rows["lo"].oper, m.UP)
        self.assertEqual((rows["eth9"].admin, rows["eth9"].oper), (m.UP, m.DOWN))
        with self.assertRaises(counters.CounterReadError):
            counters.parse_linux("{}", "R3")

    def test_each_platform_uses_its_own_native_read_only_command(self):
        runner = FakeRunner()
        runner.outputs[("clab-lab-R1", "Cli", "-p", "15", "-c", "show interfaces | json")] = CommandResult(0, stdout=ceos())
        runner.outputs[("clab-lab-R3", "ip", "-j", "-s", "link", "show")] = CommandResult(0, stdout=linux())
        counters.read("R1", "clab-lab-R1", "ceos", runner=runner)
        counters.read("R3", "clab-lab-R3", "linux", runner=runner)
        self.assertEqual([call[3] for call in runner.calls], ["Cli", "ip"])
        with self.assertRaises(counters.CounterReadError) as caught:
            counters.read("X", "clab-lab-X", "sonic", runner=runner)
        self.assertEqual(caught.exception.code, "PLATFORM_NOT_SUPPORTED")


class RateTests(ConsoleTestCase):
    def setUp(self):
        super().setUp()
        self.t0 = m.utcnow()

    def apply(self, seconds, **values):
        sample = m.InterfaceCounters("R1", "Ethernet1", m.UP, m.UP, **values)
        return self.store.apply_counters("R1", self.t0 + timedelta(seconds=seconds), [sample])

    def row(self):
        return self.store.interface_rows()[0]

    def test_no_rate_is_reported_before_two_samples_exist(self):
        self.apply(0, rx_bytes=1000, tx_bytes=1000, rx_packets=10, tx_packets=10)
        row = self.row()
        self.assertEqual((row.rx_bps, row.tx_bps, row.rx_pps, row.tx_pps), (None, None, None, None))
        self.assertEqual(filters.fmt_rate(row.rx_bps), "-")

    def test_rate_is_delta_counter_over_delta_time(self):
        self.apply(0, rx_bytes=1000, tx_bytes=5000, rx_packets=10, tx_packets=100)
        self.apply(10, rx_bytes=13500, tx_bytes=5000, rx_packets=110, tx_packets=100)
        row = self.row()
        self.assertEqual((row.rx_bps, row.tx_bps, row.rx_pps, row.tx_pps), (10000.0, 0.0, 10.0, 0.0))   # 12500 B * 8 / 10 s
        self.assertEqual(filters.fmt_rate(row.rx_bps), "10.00 kbit/s")

    def test_zero_traffic_is_a_real_zero_rate(self):
        self.apply(0, rx_bytes=77, tx_bytes=88, rx_packets=1, tx_packets=2)
        self.apply(10, rx_bytes=77, tx_bytes=88, rx_packets=1, tx_packets=2)
        row = self.row()
        self.assertEqual((row.rx_bps, row.tx_bps, row.counter_reset), (0.0, 0.0, False))
        self.assertFalse(filters.carrying_traffic(row))

    def test_counter_reset_or_rollover_yields_no_rate_and_is_flagged(self):
        self.apply(0, rx_bytes=2**64 - 10, tx_bytes=500, rx_packets=10, tx_packets=10)
        changes = self.apply(10, rx_bytes=40, tx_bytes=900, rx_packets=11, tx_packets=20)             # rx wrapped / device restarted
        row = self.row()
        self.assertTrue(row.counter_reset)
        self.assertEqual((row.rx_bps, row.tx_bps, row.rx_pps, row.tx_pps), (None, None, None, None))  # never a negative or made-up rate
        self.assertEqual(changes, [{"interface": "Ethernet1", "note": "counter reset"}])
        self.apply(20, rx_bytes=1290, tx_bytes=900, rx_packets=21, tx_packets=20)                     # the next interval is valid again
        self.assertEqual((self.row().rx_bps, self.row().counter_reset), (1000.0, False))

    def test_missing_counters_never_become_rates(self):
        self.apply(0)
        self.apply(10)
        self.assertEqual((self.row().rx_bps, self.row().rx_pps, self.row().error_delta), (None, None, 0))

    def test_errors_and_drops(self):
        self.apply(0, rx_bytes=1, tx_bytes=1, rx_errors=0, tx_errors=0, rx_drops=5, tx_drops=0)
        changes = self.apply(10, rx_bytes=2, tx_bytes=2, rx_errors=3, tx_errors=0, rx_drops=7, tx_drops=1)
        row = self.row()
        self.assertEqual(row.error_delta, 6)
        self.assertTrue(filters.has_errors(row))
        self.assertEqual(changes[0]["note"], "errors/drops +6")
        self.assertEqual(row.last_change, self.t0 + timedelta(seconds=10))

    def test_state_change_appear_and_disappear(self):
        base = dict(rx_bytes=1, tx_bytes=1)
        store, t0 = self.store, self.t0
        store.apply_counters("R1", t0, [m.InterfaceCounters("R1", "Ethernet1", m.UP, m.UP, **base)])
        self.assertIsNone(store.interface_rows()[0].last_change)                                      # the first read is a baseline, not a change
        changes = store.apply_counters("R1", t0 + timedelta(seconds=10), [m.InterfaceCounters("R1", "Ethernet1", m.UP, m.DOWN, **base),
                                                                         m.InterfaceCounters("R1", "Loopback105", m.UP, m.UP)])
        self.assertEqual(changes, [{"interface": "Ethernet1", "note": "state UP/UP -> UP/DOWN"}, {"interface": "Loopback105", "note": "appeared"}])
        changes = store.apply_counters("R1", t0 + timedelta(seconds=20), [m.InterfaceCounters("R1", "Ethernet1", m.UP, m.DOWN, **base)])
        self.assertEqual(changes, [{"interface": "Loopback105", "note": "disappeared"}])
        gone = next(r for r in store.interface_rows() if r.sample.name == "Loopback105")
        self.assertEqual((gone.present, gone.change_note), (False, "disappeared"))
        changes = store.apply_counters("R1", t0 + timedelta(seconds=30), [m.InterfaceCounters("R1", "Ethernet1", m.UP, m.DOWN, **base),
                                                                         m.InterfaceCounters("R1", "Loopback105", m.UP, m.UP)])
        self.assertEqual(changes, [{"interface": "Loopback105", "note": "appeared"}])

    def test_filtering_answers_the_operational_questions(self):
        t0, store = self.t0, StateStore()
        first = [m.InterfaceCounters("R1", "Ethernet1", m.UP, m.UP, rx_bytes=0, tx_bytes=0, description="uplink to S3"),
                 m.InterfaceCounters("R1", "Ethernet2", m.UP, m.DOWN, rx_bytes=0, tx_bytes=0),
                 m.InterfaceCounters("R1", "Ethernet10", m.DOWN, m.DOWN, rx_bytes=0, tx_bytes=0),
                 m.InterfaceCounters("R3", "eth1", m.UP, m.UP, rx_bytes=0, tx_bytes=0, rx_errors=0)]
        store.apply_counters("R1", t0, first[:3])
        store.apply_counters("R3", t0, first[3:])
        store.apply_counters("R1", t0 + timedelta(seconds=10), [m.InterfaceCounters("R1", "Ethernet1", m.UP, m.UP, rx_bytes=9000, tx_bytes=0, description="uplink to S3"),
                                                                 first[1], first[2]])
        store.apply_counters("R3", t0 + timedelta(seconds=10), [m.InterfaceCounters("R3", "eth1", m.UP, m.UP, rx_bytes=0, tx_bytes=0, rx_errors=4)])
        rows, now = store.interface_rows(), t0 + timedelta(seconds=11)
        names = lambda **kw: [f"{r.sample.device}:{r.sample.name}" for r in filters.filter_interfaces(rows, now=now, **kw)]  # noqa: E731
        self.assertEqual(names(), ["R1:Ethernet1", "R1:Ethernet2", "R1:Ethernet10", "R3:eth1"])       # natural order: 2 before 10
        self.assertEqual(names(device="R3"), ["R3:eth1"])
        self.assertEqual(names(text="ethernet1"), ["R1:Ethernet1", "R1:Ethernet10"])
        self.assertEqual(names(text="uplink"), ["R1:Ethernet1"])                                      # description search
        self.assertEqual(names(state="Down"), ["R1:Ethernet2", "R1:Ethernet10"])                      # which interfaces are down?
        self.assertEqual(names(state="Admin down"), ["R1:Ethernet10"])
        self.assertEqual(names(state="Errors / drops"), ["R3:eth1"])                                  # which have errors?
        self.assertEqual(names(state="Carrying traffic"), ["R1:Ethernet1"])                           # which carries traffic?
        self.assertEqual(names(state="Changed recently"), ["R3:eth1"])                                # what changed recently?
        self.assertEqual(names(state="Changed recently", device="R1"), [])
        self.assertEqual(filters.filter_interfaces(rows, state="Changed recently", now=now + timedelta(minutes=6)), [])


class CollectorTests(ConsoleTestCase):
    def setUp(self):
        super().setUp()
        self.runner = FakeRunner()
        self.tick = 0
        self.runner.outputs[("clab-lab-R1", "Cli", "-p", "15", "-c", "show interfaces | json")] = lambda: CommandResult(0, stdout=ceos(
            Ethernet1=("connected", "up", (1000 * self.tick, 0, self.tick, 0, 0, 0, 0, 0)), Vlan200=("connected", "up", None)))
        self.runner.outputs[("clab-lab-R3", "ip", "-j", "-s", "link", "show")] = lambda: CommandResult(0, stdout=linux(
            eth1=(["UP", "LOWER_UP"], "UP", (5 * self.tick, 0, 0, 0, 0, 0, 0, 0))))
        self.collector = InterfaceCounterCollector(self.config, self.store, self.bus, runner=self.runner,
                                                   devices=inventory.managed_devices(INVENTORY))
        self.collector.setup()
        self.addCleanup(self.collector.teardown)

    def cycle(self):
        self.tick += 1
        self.collector.collect()

    def test_only_managed_devices_are_read_and_interfaces_are_discovered(self):
        self.assertEqual([(d.name, d.platform) for d in inventory.managed_devices(INVENTORY)], [("R1", "ceos"), ("R3", "linux")])   # not R5
        self.cycle()
        self.cycle()
        self.assertEqual(sorted((r.sample.device, r.sample.name) for r in self.store.interface_rows()),
                         [("R1", "Ethernet1"), ("R1", "Vlan200"), ("R3", "eth1")])
        self.assertFalse([call for call in self.runner.calls if "R5" in call[2]])
        samples = self.kinds("counters.sample")
        self.assertEqual(len(samples), 4)
        self.assertTrue(all(e.ts.tzinfo for e in samples))
        self.assertEqual(samples[0].data["interfaces"][0][:5], ["Ethernet1", "UP", "UP", 1000000000, 1000])     # raw counters are logged
        eth1 = next(r for r in self.store.interface_rows() if r.sample.name == "Ethernet1")
        self.assertGreater(eth1.rx_bps, 0)

    def test_an_unavailable_device_is_an_event_every_cycle_and_others_continue(self):
        self.cycle()
        self.runner.down_containers.add("clab-lab-R3")
        self.cycle()
        self.cycle()
        errors = self.kinds("counters.error")
        self.assertEqual([(e.target, e.data["code"]) for e in errors], [("R3", "CONTAINER_NOT_RUNNING")] * 2)   # no missed failure
        devices = self.store.counter_devices()
        self.assertEqual((devices["R3"]["ok"], devices["R3"]["reason"], devices["R1"]["ok"]), (False, "CONTAINER_NOT_RUNNING", True))
        self.assertEqual(len([e for e in self.kinds("counters.sample") if e.target == "R1"]), 3)                # R1 was read every cycle
        stale = next(r for r in self.store.interface_rows() if r.sample.device == "R3")
        self.assertEqual((stale.sample.rx_bytes, stale.rx_bps), (5, None))                                      # last counters kept, no rate carried
        self.runner.down_containers.clear()
        self.cycle()
        self.assertEqual([e.target for e in self.kinds("counters.recovered")], ["R3"])
        self.assertTrue(self.store.counter_devices()["R3"]["ok"])

    def test_unparsable_output_and_timeouts_are_classified(self):
        self.runner.outputs[("clab-lab-R1", "Cli", "-p", "15", "-c", "show interfaces | json")] = CommandResult(0, stdout="% Error")
        self.runner.outputs[("clab-lab-R3", "ip", "-j", "-s", "link", "show")] = CommandResult(None, error="TIMEOUT")
        self.cycle()
        self.assertEqual({e.target: e.data["code"] for e in self.kinds("counters.error")}, {"R1": "PARSE_ERROR", "R3": "TIMEOUT"})
        self.assertEqual(self.store.interface_rows(), [])
