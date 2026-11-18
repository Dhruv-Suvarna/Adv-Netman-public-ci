"""s2 -- bounded collectors and cross-vendor normalization.  Stable IDs: UT-013..UT-024, UT-053 (+ S2-* for adapter/contract/replay checks).

Dependency-free unit tests (stdlib ``unittest``): no device, Docker, InfluxDB, Django ORM or network is touched.  Tests named ``*_REPLAY_*`` read
sanitized evidence recorded from the execution gateway (``fixtures/troubleshooting_collectors/live``); REPLAY is NOT live evidence -- the live runs are
documented, with gateway sequence numbers, in docs/troubleshooting/collection.md.
"""

from __future__ import annotations

import json
import random
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from core.services.troubleshooting import collectors as c, normalization as nz
from core.services.troubleshooting.adapters import capabilities as caps, contracts_bridge as bridge, monitoring as mon, transports as tr

FIX = Path(__file__).parent / "fixtures" / "troubleshooting_collectors"
LIVE = FIX / "live"
T0 = datetime(2026, 11, 9, 12, 0, 0, tzinfo=timezone.utc)

EOS_IFACES = json.dumps({"interfaces": {
    "Ethernet1": {"name": "Ethernet1", "lineProtocolStatus": "up", "interfaceStatus": "connected", "mtu": 1500, "bandwidth": 1_000_000_000, "duplex": "duplexFull",
                  "interfaceCounters": {"inOctets": 1000, "outOctets": 2000, "inUcastPkts": 10, "outUcastPkts": 20, "totalInErrors": 3, "inDiscards": 1, "outDiscards": 0,
                                        "totalOutErrors": 0, "counterRefreshTime": T0.timestamp(), "inputErrorsDetail": {"fcsErrors": 2, "runtFrames": 1, "giantFrames": 0, "alignmentErrors": 0}}},
    "Ethernet2": {"name": "Ethernet2", "lineProtocolStatus": "down", "interfaceStatus": "notconnect", "mtu": 1500, "bandwidth": 1_000_000_000,
                  "interfaceCounters": {"inOctets": 0, "outOctets": 0, "counterRefreshTime": T0.timestamp()}}}})

IOS_IFACES = """GigabitEthernet1 is up, line protocol is up
  Hardware is vNIC, address is 0c00.b231.a400 (bia 0c00.b231.a400)
  MTU 1500 bytes, BW 1000000 Kbit/sec, DLY 10 usec,
  Full Duplex, 1000Mbps, link type is auto, media type is Virtual
  324 packets input, 23348 bytes, 0 no buffer
     0 runts, 0 giants, 0 throttles
     3 input errors, 2 CRC, 1 frame, 0 overrun, 0 ignored
  337 packets output, 60146 bytes, 0 underruns
     0 output errors, 0 collisions, 0 interface resets
GigabitEthernet2 is administratively down, line protocol is down
  Hardware is vNIC, address is 0c00.b231.a401 (bia 0c00.b231.a401)
  MTU 1500 bytes, BW 1000000 Kbit/sec, DLY 10 usec,
  0 packets input, 0 bytes, 0 no buffer
     0 runts, 0 giants, 0 throttles
     0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored
  0 packets output, 0 bytes, 0 underruns
     0 output errors, 0 collisions, 0 interface resets
"""

OC_IFACES = json.dumps({"openconfig-interfaces:interfaces": {"interface": [
    {"name": "Ethernet1", "state": {"admin-status": "UP", "oper-status": "UP", "mtu": 1500,
                                    "counters": {"in-octets": 1000, "out-octets": 2000, "in-errors": 3}}}]}})

SNMP_IFACES = {
    "1.3.6.1.2.1.31.1.1.1.1.1": "Ethernet1", "1.3.6.1.2.1.2.2.1.7.1": 1, "1.3.6.1.2.1.2.2.1.8.1": 1, "1.3.6.1.2.1.2.2.1.4.1": 1500,
    "1.3.6.1.2.1.31.1.1.1.15.1": 1000, "1.3.6.1.2.1.31.1.1.1.6.1": 1000, "1.3.6.1.2.1.31.1.1.1.10.1": 2000, "1.3.6.1.2.1.2.2.1.14.1": 3,
}


def ev(source="CLI", device="R1", collected=T0, **kw) -> dict:
    return c.build_evidence(seq=1, source_type=source, transport="t", adapter="a", device=device, platform="ceos", os_version="4.36.2F", command_or_api="cmd",
                            raw=kw.pop("raw", "raw"), started_at=collected, finished_at=collected, status="OK", **kw)


class Clock:
    """Deterministic monotonic clock + sleep for budget/rate tests."""

    def __init__(self):
        self.t = 0.0
        self.sleeps = []

    def __call__(self):
        return self.t

    def sleep(self, s):
        self.sleeps.append(s)
        self.t += s


class FakeTransport:
    def __init__(self, outputs=None, raises=None):
        self.outputs, self.raises, self.calls = outputs or {}, list(raises or []), []

    def execute(self, rendered):
        self.calls.append(rendered)
        if self.raises:
            exc = self.raises.pop(0)
            if exc is not None:
                raise exc
        key = rendered if isinstance(rendered, str) else tuple(rendered)
        return self.outputs.get(key, "")


def ceos(**kw):
    return c.Target(device="R1", platform="ceos", os_version="4.36.2F", capabilities={c.SourceType.CLI: "SUPPORTED"}, **kw)


def collector(cls=c.CliCollector, clock=None, **kw):
    clock = clock or Clock()
    kw.setdefault("budget", c.Budget())
    return cls(clock=clock, sleep=clock.sleep, now=lambda: T0, **kw), clock


# ====================================================================================================================
class UT013_PlatformCommandSelection(unittest.TestCase):
    def test_UT013_only_catalogued_read_only_commands_per_platform(self):
        for platform in ("ceos", "iosxe", "linux"):
            specs = c.commands_for(platform, {"ceos": "4.36.2F", "iosxe": "17.06.01a", "linux": "8.4.4"}[platform], include_config=True)
            self.assertTrue(specs)
            for spec in specs:
                rendered = c.render_command(spec, {"interface": "Ethernet1"} if spec.params else None)
                c.validate_read_only(platform, rendered)   # raises on any non-read-only command

    def test_UT013_domain_filter_and_platform_isolation(self):
        link = {s.key for s in c.commands_for("ceos", "4.36.2F", domains=["link_flap"])}
        self.assertIn("interfaces", link)
        self.assertNotIn("ospf_neighbors", link)
        self.assertEqual({s.platform for s in c.commands_for("iosxe", "17.06.01a")}, {"iosxe"})
        self.assertEqual(c.commands_for("nokia_srlinux", "24.3"), [])   # unknown platform: nothing is guessed
        self.assertNotIn("running_config", {s.key for s in c.commands_for("ceos", "4.36.2F")})   # config snapshots are opt-in

    def test_UT013_write_and_active_probe_commands_rejected(self):
        bad_ceos = ["configure terminal", "show version; reload", "show running-config | include secret", "clear counters", "ping 10.0.0.1", "show interfaces\nconfigure",
                    "write memory", "show version | bash", "shutdown", "show logging | grep x", "traceroute 1.1.1.1", "show ip route | json && reload"]
        for cmd in bad_ceos:
            with self.assertRaises(c.CommandNotAllowed, msg=cmd):
                c.validate_read_only("ceos", cmd)
        for cmd in ["show interfaces | json", "show ip ospf neighbor | json"]:
            c.validate_read_only("ceos", cmd)
        with self.assertRaises(c.CommandNotAllowed):
            c.validate_read_only("iosxe", "show interfaces | json")      # '| json' exists on EOS only
        for argv in [("ip", "addr", "add", "10.0.0.1/24", "dev", "eth1"), ("sh", "-c", "ip link"), ("vtysh", "-c", "clear ip bgp *"), ("vtysh", "-c", "configure terminal"),
                     ("ip", "-j", "addr", "show", "; reboot"), "ip -j addr show", ("nft", "flush", "ruleset")]:
            with self.assertRaises(c.CommandNotAllowed, msg=str(argv)):
                c.validate_read_only("linux", argv)
        c.validate_read_only("linux", ("vtysh", "-c", "show ip ospf neighbor json"))

    def test_UT013_parameters_validated_not_concatenated(self):
        spec = c.COMMAND_CATALOG["ceos"]["interface"]
        for bad in ("Ethernet1; reload", "Ethernet1 | json", "", "../x", "Et1\nconfigure", "$(id)"):
            with self.assertRaises(c.CommandNotAllowed, msg=bad):
                c.render_command(spec, {"interface": bad})
        with self.assertRaises(c.CommandNotAllowed):
            c.render_command(spec, {"interface": "Ethernet1", "extra": "x"})
        self.assertEqual(c.render_command(spec, {"interface": "Ethernet1"}), "show interfaces Ethernet1 | json")

    def test_UT013_uncatalogued_key_is_missing_not_executed(self):
        col, _ = collector()
        t = FakeTransport({"show interfaces | json": EOS_IFACES})
        res = col.collect(ceos(), ["interfaces", "reload", "nonexistent"], t)
        self.assertEqual(t.calls, ["show interfaces | json"])
        self.assertEqual([m["reason"] for m in res["missing"]], ["COMMAND_NOT_ALLOWED", "COMMAND_NOT_ALLOWED"])

    def test_UT013_version_gate_and_admission_gate_before_transport(self):
        col, _ = collector()
        for target, code in [(c.Target("R1", "ceos", "4.36.2F", withdrawn=True, capabilities={"CLI": "SUPPORTED"}), "NOT_ADMITTED"),
                             (c.Target("R1", "ceos", "4.36.2F", verified=False, capabilities={"CLI": "SUPPORTED"}), "NOT_ADMITTED"),
                             (c.Target("R1", "ceos", "4.36.2F", lifecycle_state="DECOMMISSIONED", capabilities={"CLI": "SUPPORTED"}), "NOT_ADMITTED"),
                             (c.Target("R1", "ceos", "4.36.2F", capabilities={}), "UNSUPPORTED_PLATFORM"),
                             (c.Target("R1", "ceos", "4.36.2F", capabilities={"CLI": "NOT_IMPLEMENTED"}), "UNSUPPORTED_PLATFORM")]:
            t = FakeTransport()
            res = col.collect(target, ["interfaces"], t)
            self.assertEqual(res["run"]["status"], "REFUSED")
            self.assertEqual(res["missing"][0]["reason"], code)
            self.assertEqual(t.calls, [])      # NOT probed
            self.assertEqual(res["observations"], [])

    def test_UT013_capability_probe_overrides_target_claims(self):
        probe = caps.make_capability_probe(health_capability=lambda p: {"status": "NOT_IMPLEMENTED", "evidence": "x"})
        col, _ = collector(capability_probe=probe)
        t = FakeTransport()
        res = col.collect(ceos(), ["interfaces"], t)
        self.assertEqual(res["missing"][0]["reason"], "UNSUPPORTED_PLATFORM")
        self.assertEqual(t.calls, [])


class UT014_GnmiStreaming(unittest.TestCase):
    def notif(self, ts, name="Ethernet1", leaf="state/oper-status", val="DOWN"):
        return {"timestamp": int(ts.timestamp() * 1e9), "prefix": f"/interfaces/interface[name={name}]", "update": [{"path": leaf, "val": val}]}

    def test_UT014_event_time_is_notification_time_not_arrival(self):
        event, arrival = T0 - timedelta(seconds=7), T0
        n = self.notif(event)
        n["_arrival"] = arrival.isoformat()
        col, _ = collector(c.GnmiCollector, capability_probe=lambda p, s: {"status": "SUPPORTED"})
        res = col.subscribe(ceos(), ["/interfaces/interface"], [n])
        obs = res["observations"]
        self.assertEqual(len(obs), 1)
        self.assertEqual((obs[0]["key"], obs[0]["value"], obs[0]["target"]["interface"]), ("interface.oper_state", "down", "Ethernet1"))
        self.assertEqual(obs[0]["observed_at"], nz.iso(event))
        self.assertEqual(obs[0]["collected_at"], res["evidence"][0]["collected_at"])
        self.assertNotEqual(obs[0]["observed_at"], nz.iso(arrival))
        self.assertEqual(res["run"]["source_type"], "GNMI_STREAM")

    def test_UT014_counters_admin_and_unmapped_paths(self):
        out = nz.normalize_gnmi_notification({"timestamp": int(T0.timestamp() * 1e9), "prefix": "/interfaces/interface[name=Et1]",
                                              "update": [{"path": "state/counters/in-errors", "val": 5}, {"path": "state/admin-status", "val": "UP"},
                                                         {"path": "state/something-new", "val": 1}], "delete": ["state/mtu"]},
                                             device="R1", platform="ceos", evidence=ev("GNMI_STREAM"), arrival=T0)
        by_key = {o["key"]: o for o in out["observations"]}
        self.assertEqual(by_key["interface.counter.in_errors"]["value"], 5)
        self.assertTrue(by_key["interface.counter.in_errors"]["extra"]["counter"]["cumulative"])
        self.assertEqual(by_key["interface.admin_state"]["target"]["interface"], "Ethernet1")     # Et1 alias canonicalized
        self.assertIn("/interfaces/interface[name=Et1]/state/something-new", out["unmapped_paths"])
        self.assertEqual(out["deleted_paths"], ["state/mtu"])

    def test_UT014_bad_or_future_timestamp_falls_back_and_is_flagged(self):
        for ts in (None, 0, int((T0 + timedelta(hours=1)).timestamp() * 1e9)):
            out = nz.normalize_gnmi_notification({"timestamp": ts, "prefix": "/interfaces/interface[name=Ethernet1]", "update": [{"path": "state/oper-status", "val": "UP"}]},
                                                 device="R1", evidence=ev("GNMI_STREAM"), arrival=T0)
            o = out["observations"][0]
            self.assertEqual((o["quality"], o["observed_at"]), ("PARTIAL", nz.iso(T0)))
            self.assertIn("TIMESTAMP_FALLBACK_TO_ARRIVAL", o["flags"])

    def test_UT014_device_clock_skew_corrected(self):
        clock = nz.estimate_skew(T0 + timedelta(seconds=30), T0)
        self.assertEqual(clock["status"], "SKEWED")
        n = self.notif(T0 + timedelta(seconds=25))
        out = nz.normalize_gnmi_notification(n, device="R1", evidence=ev("GNMI_STREAM"), arrival=T0, clock=clock)
        self.assertEqual(out["observations"][0]["observed_at"], nz.iso(T0 - timedelta(seconds=5)))
        self.assertIn("DEVICE_CLOCK_SKEW_CORRECTED", out["observations"][0]["flags"])

    def test_UT014_subscription_policy_path_allowlist_rate_bound_and_set_refused(self):
        col, _ = collector(c.GnmiCollector, capability_probe=lambda p, s: {"status": "SUPPORTED"})
        calls = []
        src = lambda: calls.append(1) or []  # noqa: E731
        self.assertEqual(col.subscribe(ceos(), ["/system/aaa"], src)["missing"][0]["reason"], "COMMAND_NOT_ALLOWED")
        self.assertEqual(col.subscribe(ceos(), ["/interfaces/interface"], src, sample_interval_ns=1_000_000)["missing"][0]["reason"], "BUDGET_EXCEEDED")
        self.assertEqual(col.subscribe(ceos(), ["/interfaces/interface"], src, mode="BOGUS")["missing"][0]["reason"], "UNSUPPORTED_OPERATION")
        self.assertEqual(col.set(ceos(), "/interfaces/interface[name=Ethernet1]/config/enabled", False)["missing"][0]["reason"], "UNSUPPORTED_OPERATION")
        self.assertEqual(calls, [])

    def test_UT014_backpressure_counts_dropped_notifications(self):
        col, _ = collector(c.GnmiCollector, budget=c.Budget(max_records=3), capability_probe=lambda p, s: {"status": "SUPPORTED"})
        res = col.subscribe(ceos(), ["/interfaces/interface"], [self.notif(T0 + timedelta(seconds=i)) for i in range(5)])
        self.assertEqual(res["run"]["stream"]["dropped_count"], 2)
        self.assertIn("DATA_LOSS", res["run"]["flags"])
        self.assertEqual(len(res["observations"]), 3)
        self.assertEqual(res["missing"][0]["reason"], "BUDGET_EXCEEDED")


class UT015_SnmpCounters(unittest.TestCase):
    def sample(self, value, seconds):
        return {"value": value, "at": T0 + timedelta(seconds=seconds)}

    def test_UT015_normal_rate_and_bits_conversion(self):
        r = nz.analyze_counter(self.sample(1000, 0), self.sample(1000 + 125_000, 10), width_bits=64, speed_bps=1e9)
        self.assertEqual((r["event"], r["delta"], r["rate_per_s"], r["rate_bps"]), ("NORMAL", 125_000, 12_500.0, 100_000.0))

    def test_UT015_32bit_wrap_detected_and_delta_modulo(self):
        prev, cur = 2**32 - 1000, 4000
        r = nz.analyze_counter(self.sample(prev, 0), self.sample(cur, 60), width_bits=32, speed_bps=1e9)
        self.assertEqual((r["event"], r["delta"]), ("WRAP", 5000))
        self.assertAlmostEqual(r["rate_bps"], 5000 * 8 / 60)

    def test_UT015_reset_is_not_a_wrap_and_has_no_fabricated_rate(self):
        r = nz.analyze_counter(self.sample(5_000_000_000, 0), self.sample(100, 60), width_bits=64, speed_bps=1e9)
        self.assertEqual(r["event"], "RESET")
        self.assertIsNone(r["rate_bps"])
        self.assertIsNone(r["delta"])
        # 32-bit counter that dropped from a LOW value: cannot be a wrap
        self.assertEqual(nz.analyze_counter(self.sample(1000, 0), self.sample(10, 60), width_bits=32)["event"], "RESET")
        # wrap that would imply > line rate is rejected as a reset
        self.assertEqual(nz.analyze_counter(self.sample(2**32 - 10, 0), self.sample(2**31, 1), width_bits=32, speed_bps=1e6)["event"], "RESET")

    def test_UT015_gap_duplicate_and_time_regression(self):
        gap = nz.analyze_counter(self.sample(0, 0), self.sample(10, 900), max_gap_s=180)
        self.assertEqual((gap["event"], gap["rate_per_s"]), ("GAP", None))
        self.assertEqual(gap["delta"], 10)
        self.assertEqual(nz.analyze_counter(self.sample(5, 0), self.sample(5, 0))["event"], "DUPLICATE_SAMPLE")
        self.assertEqual(nz.analyze_counter(self.sample(5, 10), self.sample(7, 0))["event"], "TIME_REGRESSION")
        self.assertEqual(nz.analyze_counter(None, self.sample(5, 0))["event"], "FIRST")
        self.assertEqual(nz.analyze_counter(self.sample(5, 0), self.sample(9, 30), last_clear_changed=True)["event"], "RESET")

    def test_UT015_line_rate_violation_marks_sample_untrusted(self):
        r = nz.analyze_counter(self.sample(0, 0), self.sample(10_000_000_000, 1), width_bits=64, speed_bps=1e9)
        self.assertIn("RATE_EXCEEDS_LINE_RATE", r["flags"])

    def test_UT015_polling_across_polls_emits_rates_wraps_and_resets(self):
        tracker = nz.CounterTracker(max_gap_s=180)
        values = [10_000, 70_000, 2**64 - 1, 500, 300, 90_000]
        per_poll = []
        for i, v in enumerate(values):
            t = T0 + timedelta(seconds=60 * i)
            snap = dict(SNMP_IFACES, **{"1.3.6.1.2.1.31.1.1.1.6.1": v})
            res = nz.normalize_snmp_poll(nz.parse_snmp_if_mib(snap).records, device="R1", evidence=ev("SNMP_POLL", collected=t), tracker=tracker, now=t, platform="ceos")
            per_poll.append({o["key"]: o for o in res["observations"] if o["key"] in ("interface.rate.in_octets", "interface.counter_event")
                             and o["extra"].get("counter", "in_octets") == "in_octets"})
        self.assertEqual(per_poll[0], {})                                                          # FIRST sample: no rate
        self.assertEqual(per_poll[1]["interface.rate.in_octets"]["value"], 60_000 * 8 / 60)          # bits/s from an octet counter
        self.assertEqual(per_poll[1]["interface.rate.in_octets"]["unit"], "bps")
        self.assertEqual(per_poll[2]["interface.rate.in_octets"]["value"], (2**64 - 1 - 70_000) * 8 / 60)
        self.assertEqual(per_poll[2]["interface.rate.in_octets"]["quality"], "UNTRUSTED_PARSE")       # 1.8e19 bytes/min on a 1G link is impossible telemetry
        wrap = per_poll[3]["interface.rate.in_octets"]                                              # 64-bit rollover near the top: handled
        self.assertIn("COUNTER_WRAP_HANDLED", wrap["flags"])
        self.assertEqual(wrap["value"], 501 * 8 / 60)
        self.assertEqual(per_poll[4]["interface.counter_event"]["value"], "reset")                    # 500 -> 300 is a reset, not a wrap
        self.assertNotIn("interface.rate.in_octets", per_poll[4])                                   # ... and no fabricated rate
        self.assertEqual(per_poll[5]["interface.rate.in_octets"]["value"], 89_700 * 8 / 60)         # recovers after the reset

    def test_UT015_sysuptime_ticks_to_seconds_and_restart_detection(self):
        tracker = nz.CounterTracker()
        e1, e2 = ev("SNMP_POLL", collected=T0), ev("SNMP_POLL", collected=T0 + timedelta(seconds=60))
        r1 = nz.normalize_snmp_poll([], device="R1", evidence=e1, tracker=tracker, now=T0, sys_uptime_ticks=1_000_000)
        r2 = nz.normalize_snmp_poll([], device="R1", evidence=e2, tracker=tracker, now=T0 + timedelta(seconds=60), sys_uptime_ticks=500)
        self.assertEqual((r1["observations"][0]["value"], r1["observations"][0]["unit"]), (10000.0, "seconds"))
        self.assertEqual([o["key"] for o in r2["observations"]], ["device.uptime", "device.restart_suspected"])

    def test_UT015_poll_via_collector_enforces_allowlist_and_hides_session(self):
        class Session:
            def __init__(self):
                self.walked = []

            def walk(self, oid):
                self.walked.append(oid)
                return {k: v for k, v in SNMP_IFACES.items() if k.startswith(oid + ".")}

            def get(self, oid):
                return 123456

        col, _ = collector(c.SnmpCollector, capability_probe=lambda p, s: {"status": "SUPPORTED"}, rng=random.Random(1))
        session = Session()
        res = col.poll(ceos(), session, columns=["ifName", "ifOperStatus", "ifAdminStatus", "ifMtu", "ifHCInOctets", "ifInErrors"])
        self.assertIn(res["run"]["status"], ("COMPLETE", "PARTIAL"))
        self.assertIn("interface.oper_state", {o["key"] for o in res["observations"]})
        self.assertNotIn("community", json.dumps(res).lower())
        bad = col.poll(ceos(), session, columns=["sysContact"])
        self.assertEqual(bad["missing"][0]["reason"], "COMMAND_NOT_ALLOWED")
        self.assertEqual(col.set(ceos())["missing"][0]["reason"], "UNSUPPORTED_OPERATION")
        for _ in range(20):
            self.assertGreaterEqual(col.next_poll_delay(), 10.0)

    def test_UT015_oids_equal_the_repository_catalog(self):
        self.assertEqual(mon.verify_oid_consistency(), [])


class UT016_SyslogDedup(unittest.TestCase):
    LINES = [
        "<189>Nov  9 12:00:05 R1 Ebra: %LINEPROTO-5-UPDOWN: Line protocol on Interface Ethernet1, changed state to down",
        "<189>Nov  9 12:00:05 R1 Ebra: %LINEPROTO-5-UPDOWN: Line protocol on Interface Ethernet1, changed state to down",
        "<189>Nov  9 12:00:06 R1 Ebra: %LINEPROTO-5-UPDOWN: Line protocol on Interface Ethernet1, changed state to down",
        "<189>Nov  9 12:00:20 R1 Ebra: %LINEPROTO-5-UPDOWN: Line protocol on Interface Ethernet1, changed state to up",
    ]

    def run_collect(self, lines):
        col, _ = collector(c.SyslogCollector, capability_probe=lambda p, s: {"status": "SUPPORTED"})
        return col.collect(ceos(), [(line, T0 + timedelta(seconds=i)) for i, line in enumerate(lines)])

    def test_UT016_duplicates_collapse_and_every_original_reference_is_kept(self):
        res = self.run_collect(self.LINES)
        obs = res["observations"]
        self.assertEqual([(o["value"], o["extra"]["occurrences"]) for o in obs], [("down", 3), ("up", 1)])
        refs = obs[0]["extra"]["source_event_refs"]
        self.assertEqual(len(refs), 3)
        self.assertEqual(len({r["raw_hash"] for r in refs}) , 2)    # lines 1 and 2 are byte-identical (same hash) but BOTH references preserved
        self.assertTrue(all(r["evidence_ref"].startswith(res["evidence"][0]["evidence_id"] + "#L") for r in refs))
        self.assertIn("DEDUPLICATED", obs[0]["flags"])
        self.assertEqual(obs[0]["target"]["interface"], "Ethernet1")
        self.assertEqual(res["run"]["syslog"], {"input_events": 4, "unique_events": 2})

    def test_UT016_same_message_far_apart_is_a_new_event(self):
        res = self.run_collect([self.LINES[0], self.LINES[0].replace("12:00:05", "12:05:05")])
        self.assertEqual(len(res["observations"]), 2)

    def test_UT016_secrets_in_messages_are_redacted(self):
        ev1 = nz.parse_syslog_line("<13>Nov  9 12:00:00 R1 sshd: login failed password=Sup3rSecret! community: public123", received_at=T0)
        self.assertNotIn("Sup3rSecret", ev1["message"])
        self.assertNotIn("public123", ev1["message"])
        self.assertGreaterEqual(ev1["redactions"], 1)

    def test_UT016_event_classes(self):
        cases = {
            "<189>Nov  9 12:00:00 R1 %OSPF-5-ADJCHG: Process 1, Nbr 10.0.0.2 on Gi2 from FULL to DOWN, Neighbor Down: Dead timer expired": ("ospf_adjacency", "down"),
            "<189>Nov  9 12:00:00 R1 %SPANTREE-6-TOPOTRAP: Topology change on VLAN 10": ("stp_topology_change", "change"),
            "<189>Nov  9 12:00:00 R1 %LINK-3-UPDOWN: Interface GigabitEthernet2, changed state to down": ("link_state", "down"),
            "<189>Nov  9 12:00:00 R1 transceiver rx power low alarm on Ethernet3": ("optics_warning", "warning"),
            "<189>Nov  9 12:00:00 R1 something unrelated": ("other", ""),
        }
        for line, (etype, state) in cases.items():
            e = nz.parse_syslog_line(line, received_at=T0)
            self.assertEqual((e["event_type"], e["state"]), (etype, state), line)


class UT017_NetFlow(unittest.TestCase):
    def rec(self, **kw):
        base = {"src": "10.1.1.5", "dst": "10.2.2.9", "sport": 40000, "dport": 443, "proto": 6, "bytes": 1500, "packets": 2, "last": T0.isoformat(), "exporter": "R1", "sampling_rate": 100}
        base.update(kw)
        return base

    def test_UT017_service_scoping_and_out_of_scope_counted_not_aggregated(self):
        records = [self.rec(), self.rec(), self.rec(dport=53, proto=17), self.rec(dst="192.0.2.1")]
        res = nz.normalize_flow_records(records, {"protocol": 6, "dst_ports": [443], "dst_prefixes": ["10.2.2.0/24"]}, device="R1", evidence=ev("NETFLOW"), now=T0)
        obs = {o["key"]: o for o in res["observations"]}
        self.assertEqual((res["in_scope"], res["out_of_scope"]), (2, 2))
        self.assertEqual(obs["flow.service.bytes"]["value"], 2 * 1500 * 100)
        self.assertEqual(obs["flow.service.sampled_records"]["extra"]["out_of_scope_records"], 2)

    def test_UT017_sampling_uncertainty_retained(self):
        res = nz.normalize_flow_records([self.rec() for _ in range(4)], {"protocol": 6}, device="R1", evidence=ev("NETFLOW"), now=T0)
        b = next(o for o in res["observations"] if o["key"] == "flow.service.bytes")
        u = b["extra"]["uncertainty"]
        self.assertTrue(u["estimated"])
        self.assertAlmostEqual(u["relative_error_95"], round(1.96 / 2, 4))
        self.assertIn("ESTIMATED_FROM_SAMPLES", b["flags"])
        self.assertEqual(b["extra"]["raw_sampled_bytes"], 6000)
        exact = nz.normalize_flow_records([self.rec(sampling_rate=1)], {"protocol": 6}, device="R1", evidence=ev("NETFLOW"), now=T0)
        self.assertFalse(next(o for o in exact["observations"] if o["key"] == "flow.service.bytes")["extra"]["uncertainty"]["estimated"])

    def test_UT017_unknown_sampling_rate_gives_no_estimate(self):
        res = nz.normalize_flow_records([self.rec(sampling_rate=None)], {"protocol": 6}, device="R1", evidence=ev("NETFLOW"), now=T0)
        b = next(o for o in res["observations"] if o["key"] == "flow.service.bytes")
        self.assertIsNone(b["value"])
        self.assertEqual(b["quality"], "UNKNOWN")
        self.assertIn("SAMPLING_RATE_UNKNOWN", b["flags"])

    def test_UT017_exporter_coverage_and_privacy_masking(self):
        res = nz.normalize_flow_records([self.rec()], {"protocol": 6}, device="R1", evidence=ev("NETFLOW"), expected_exporters=["R1", "R2"], now=T0)
        self.assertEqual(res["coverage"]["missing_exporters"], ["R2"])
        b = next(o for o in res["observations"] if o["key"] == "flow.service.bytes")
        self.assertEqual((b["quality"], "EXPORTER_COVERAGE_INCOMPLETE" in b["flags"]), ("PARTIAL", True))
        endpoints = next(o for o in res["observations"] if o["key"] == "flow.service.endpoints")["value"]
        self.assertEqual((endpoints[0]["src"], endpoints[0]["dst"]), ("10.1.1.0/24", "10.2.2.0/24"))
        self.assertNotIn("10.1.1.5", json.dumps(res["observations"]))

    def test_UT017_collector_requires_service_selector(self):
        col, _ = collector(c.FlowCollector, capability_probe=lambda p, s: {"status": "SUPPORTED"})
        res = col.collect(ceos(), [self.rec()], {})
        self.assertEqual((res["run"]["status"], res["missing"][0]["reason"]), ("REFUSED", "COMMAND_NOT_ALLOWED"))
        ok = col.collect(ceos(), [self.rec()], {"protocol": 6, "dst_ports": [443]})
        self.assertTrue(ok["observations"])
        none = col.collect(ceos(), [self.rec(dport=80)], {"protocol": 6, "dst_ports": [443]})
        self.assertEqual(none["missing"][0]["reason"], "EMPTY")      # no flow seen != no traffic

    def test_UT017_no_live_exporter_exists_for_any_platform(self):
        probe = caps.make_capability_probe()
        for p in caps.KNOWN_PLATFORMS:
            self.assertEqual(probe(p, "NETFLOW")["status"], "UNSUPPORTED")
        col, _ = collector(c.FlowCollector, capability_probe=probe)
        self.assertEqual(col.collect(ceos(), [self.rec()], {"protocol": 6})["missing"][0]["reason"], "UNSUPPORTED_PLATFORM")


class UT018_PacketMetadata(unittest.TestCase):
    META = {"capture_id": "cap1", "interface": "Ethernet1", "filter": "tcp port 443", "snaplen": 96, "packets": 500, "bytes": 40000, "duration_s": 10.0,
            "started_at": T0.isoformat(), "pcap_ref": "evidence://pcap/cap1", "summary": {"tcp_retransmissions": 4, "icmp_frag_needed": 0, "dns_nxdomain": 2}}
    AUTH = {"authorized_by": "operator-1", "ticket": "CHG-1", "expires_at": (T0 + timedelta(minutes=5)).isoformat(), "device": "R1", "interface": "Eth1"}

    def run_collect(self, meta, auth, **kw):
        col, _ = collector(c.CaptureMetadataCollector, capability_probe=lambda p, s: {"status": "SUPPORTED"})
        return col.collect(ceos(), meta, auth, **kw)

    def test_UT018_payload_never_reaches_evidence_or_observations(self):
        meta = {**self.META, "payload": "GET /secret HTTP/1.1\r\nAuthorization: Bearer abcdef0123456789", "hexdump": "47455420", "data": "x"}
        res = self.run_collect(meta, self.AUTH)
        blob = json.dumps(res)
        for needle in ("GET /secret", "abcdef0123456789", "47455420"):
            self.assertNotIn(needle, blob)
        self.assertTrue(any(f.startswith("PAYLOAD_FIELDS_DROPPED") for f in res["run"]["flags"]))
        md = next(o for o in res["observations"] if o["key"] == "capture.metadata")
        self.assertFalse(md["value"]["payload_included"])
        self.assertIn("capture.summary.tcp_retransmissions", {o["key"] for o in res["observations"]})
        self.assertEqual(md["value"]["pcap_ref"], "evidence://pcap/cap1")    # reference, not content

    def test_UT018_bounds_enforced(self):
        for patch, problem in [({"snaplen": 65535}, "SNAPLEN_EXCEEDS_HEADER_ONLY_BOUND"), ({"packets": 10**6}, "PACKET_COUNT_EXCEEDS_BOUND"),
                               ({"duration_s": 3600}, "DURATION_EXCEEDS_BOUND"), ({"bytes": 10**9}, "BYTES_EXCEED_BOUND"), ({"filter": ""}, "UNSCOPED_CAPTURE_NO_FILTER")]:
            res = self.run_collect({**self.META, **patch}, self.AUTH)
            self.assertEqual(res["observations"], [], problem)
            self.assertIn(problem, res["missing"][0]["detail"])
            self.assertEqual(res["missing"][0]["reason"], "UNAUTHORIZED_CAPTURE")

    def test_UT018_authorization_required_scoped_and_unexpired(self):
        self.assertIn("NO_AUTHORIZATION", self.run_collect(self.META, None)["missing"][0]["detail"])
        self.assertIn("AUTHORIZATION_EXPIRED", self.run_collect(self.META, {**self.AUTH, "expires_at": (T0 - timedelta(seconds=1)).isoformat()})["missing"][0]["detail"])
        self.assertIn("SCOPE_MISMATCH", self.run_collect(self.META, {**self.AUTH, "device": "R9"})["missing"][0]["detail"])
        self.assertIn("SCOPE_MISMATCH", self.run_collect(self.META, {**self.AUTH, "interface": "Ethernet7"})["missing"][0]["detail"])
        self.assertIn("MISSING_TICKET", self.run_collect(self.META, {**self.AUTH, "ticket": ""})["missing"][0]["detail"])
        self.assertEqual(self.run_collect(self.META, self.AUTH)["run"]["status"], "COMPLETE")

    def test_UT018_collector_cannot_start_a_capture(self):
        self.assertFalse(any(hasattr(c.CaptureMetadataCollector, n) for n in ("start", "capture", "run_capture", "execute")))


class UT019_CanonicalEquivalence(unittest.TestCase):
    def view(self, raw, parser_id, platform, version, **kw):
        res = nz.normalize_interfaces(raw, parser_id=parser_id, platform=platform, os_version=version, device="R1", evidence=ev(), now=T0, **kw)
        self.assertEqual(res["missing"], [], res["missing"])
        return res

    def test_UT019_eos_json_ios_text_openconfig_snmp_yield_the_same_canonical_model(self):
        eos = self.view(EOS_IFACES, "interfaces.state", "ceos", "4.36.2F")
        oc = self.view(OC_IFACES, "interfaces.openconfig", "ceos", "4.36.2F")
        snmp = self.view(SNMP_IFACES, "interfaces.snmp", "ceos", "4.36.2F")
        keys = ("interface.admin_state", "interface.oper_state", "interface.mtu", "interface.counter.in_octets", "interface.counter.out_octets", "interface.counter.in_errors")
        views = []
        for res in (eos, oc, snmp):
            v = nz.canonical_view(res["observations"])
            views.append({k: v[(k, "Ethernet1")] for k in keys})
        self.assertEqual(views[0], views[1])
        self.assertEqual(views[0], views[2])
        self.assertEqual(views[0]["interface.oper_state"], "up")

    def test_UT019_ios_text_maps_to_same_vocabulary_and_units(self):
        res = self.view(IOS_IFACES, "interfaces.state", "iosxe", "17.06.01a", raw_text_check=nz.ios_raw_text_check)
        v = nz.canonical_view(res["observations"])
        self.assertEqual(v[("interface.oper_state", "GigabitEthernet1")], "up")
        self.assertEqual(v[("interface.admin_state", "GigabitEthernet2")], "down")
        self.assertEqual(v[("interface.speed", "GigabitEthernet1")], 1_000_000_000)    # Kbit/sec -> bps
        self.assertEqual(v[("interface.counter.in_crc_errors", "GigabitEthernet1")], 2)
        self.assertEqual(res["quality"], "OK")
        self.assertEqual(res["parser"]["template"], "iosxe.show_interfaces.text")

    def test_UT019_eos_counter_refresh_time_is_the_event_time(self):
        res = self.view(EOS_IFACES, "interfaces.state", "ceos", "4.36.2F")
        o = next(o for o in res["observations"] if o["key"] == "interface.oper_state")
        self.assertEqual(o["observed_at"], nz.iso(T0))
        self.assertNotIn("OBSERVATION_TIME_IS_COLLECTION_TIME", o["flags"])

    def test_UT019_interface_aliases_and_linux_names(self):
        for alias, canon in [("Et1", "Ethernet1"), ("Eth1/1", "Ethernet1/1"), ("Gi2", "GigabitEthernet2"), ("Te0/0/1", "TenGigabitEthernet0/0/1"), ("Po10", "Port-Channel10"), ("Ma1", "Management1")]:
            self.assertEqual(nz.canonical_interface(alias), canon)
        self.assertEqual(nz.canonical_interface("eth1", platform="linux"), "eth1")     # Linux eth1 is NOT EOS Ethernet1

    def test_UT019_state_vocabulary(self):
        self.assertEqual([nz.norm_oper_state(x) for x in ("UP", "connected", 2, "notconnect", "lowerLayerDown", 6, "weird")],
                         ["up", "up", "down", "down", "lower_layer_down", "not_present", "unknown"])
        self.assertEqual([nz.norm_ospf_state(x) for x in ("Full/DR", "2-Way/DROTHER", "FULL", "ExStart")], ["full", "two_way", "full", "exstart"])
        self.assertEqual(nz.norm_bgp_state("Established"), "established")

    def test_UT019_routing_neighbors_across_vendors(self):
        eos = json.dumps({"vrfs": {"default": {"instList": {"1": {"ospfNeighborEntries": [{"routerId": "10.0.0.2", "interfaceName": "Ethernet1", "adjacencyState": "full"}]}}}}})
        frr = json.dumps({"neighbors": {"10.0.0.2": [{"nbrState": "Full/DR", "ifaceName": "eth1:10.0.0.1", "ifaceAddress": "10.0.0.2"}]}})
        ios = "Neighbor ID     Pri   State           Dead Time   Address         Interface\n10.0.0.2          1   FULL/DR         00:00:33    10.0.0.2        GigabitEthernet2\n"
        for parser, plat, ver, raw in [("ospf.neighbors", "ceos", "4.36.2F", eos), ("ospf.neighbors", "linux", "8.4.4", frr), ("ospf.neighbors", "iosxe", "17.06.01a", ios)]:
            res = nz.normalize_neighbors(raw, parser_id=parser, platform=plat, os_version=ver, device="R1", evidence=ev(), now=T0)
            self.assertEqual([(o["key"], o["value"], o["target"]["neighbor"]) for o in res["observations"]], [("routing.ospf.neighbor_state", "full", "10.0.0.2")], plat)

    def test_UT019_intent_is_a_separate_class_from_operational_state(self):
        res = nz.normalize_intent("R1", {"interfaces": {"Et1": {"mtu": 9214, "admin": "up", "addresses": ["2001:DB8::1/64"]}}, "neighbors": [{"protocol": "ospf", "neighbor": "10.0.0.2", "interface": "Et1"}]},
                                  evidence=ev("NETBOX_INTENT", collected=T0), now=T0, source="netbox", revision="r7", url="https://nmas.example/nsot/R1")
        self.assertTrue(res["observations"])
        self.assertTrue(all(o["evidence_class"] == "intent" and o["key"].startswith("intent.") for o in res["observations"]))
        self.assertIn("2001:db8::1/64", [o["value"] for o in res["observations"]])
        self.assertTrue(all("NO_OPERATOR_URL" not in o["flags"] for o in res["observations"]))
        nourl = nz.normalize_intent("R1", {"interfaces": {"Et1": {"mtu": 1500}}}, evidence=ev("NETBOX_INTENT"), now=T0)
        self.assertIn("NO_OPERATOR_URL", nourl["observations"][0]["flags"])
        self.assertIsNone(nourl["observations"][0]["extra"]["operator_url"])


class UT020_ParserFailClosed(unittest.TestCase):
    def test_UT020_wrong_nos_fails_closed_without_observations(self):
        # IOS text handed to the EOS JSON parser: parse failure, no observation
        res = nz.normalize_interfaces(IOS_IFACES, parser_id="interfaces.state", platform="ceos", os_version="4.36.2F", device="R1", evidence=ev(), now=T0)
        self.assertEqual((res["observations"], res["missing"][0]["reason"]), ([], "PARSE_FAILED"))
        # EOS JSON handed to the IOS text template: nothing recognised -> EMPTY, never invented interfaces
        res = nz.normalize_interfaces(EOS_IFACES, parser_id="interfaces.state", platform="iosxe", os_version="17.06.01a", device="R1", evidence=ev(), now=T0)
        self.assertEqual((res["observations"], res["missing"][0]["reason"]), ([], "EMPTY"))
        # a platform with no parser at all fails closed at selection time
        res = nz.normalize_interfaces(EOS_IFACES, parser_id="interfaces.state", platform="nokia_srlinux", os_version="24.3", device="R1", evidence=ev(), now=T0)
        self.assertEqual((res["observations"], res["missing"][0]["reason"], res["missing"][0]["extra"]["selection_error"]), ([], "PARSER_UNAVAILABLE", "WRONG_PLATFORM"))
        # right platform, unvalidated version
        res = nz.normalize_interfaces(EOS_IFACES, parser_id="interfaces.state", platform="ceos", os_version="3.1.0", device="R1", evidence=ev(), now=T0)
        self.assertEqual((res["observations"], res["missing"][0]["extra"]["selection_error"]), ([], "VERSION_UNSUPPORTED"))
        # OS version not known at all
        res = nz.normalize_interfaces(EOS_IFACES, parser_id="interfaces.state", platform="ceos", os_version="", device="R1", evidence=ev(), now=T0)
        self.assertEqual(res["missing"][0]["extra"]["selection_error"], "VERSION_UNKNOWN")

    def test_UT020_version_selection(self):
        with self.assertRaises(nz.ParserSelectionError) as e:
            nz.select_parser("interfaces.state", "ceos", "3.9.1")
        self.assertEqual(e.exception.code, "VERSION_UNSUPPORTED")
        with self.assertRaises(nz.ParserSelectionError) as e:
            nz.select_parser("interfaces.state", "ceos", "")
        self.assertEqual(e.exception.code, "VERSION_UNKNOWN")           # unknown version is NOT assumed compatible
        with self.assertRaises(nz.ParserSelectionError) as e:
            nz.select_parser("interfaces.state", "iosxe", "18.2.1")      # newer than validated range
        self.assertEqual(e.exception.code, "VERSION_UNSUPPORTED")
        with self.assertRaises(nz.ParserSelectionError) as e:
            nz.select_parser("interfaces.state", "nokia_srlinux", "24.3")
        self.assertEqual(e.exception.code, "WRONG_PLATFORM")
        with self.assertRaises(nz.ParserSelectionError) as e:
            nz.select_parser("nope", "ceos", "4.36.2F")
        self.assertEqual(e.exception.code, "PARSER_UNKNOWN")
        self.assertEqual(nz.select_parser("interfaces.state", "ceos", "EOS 4.36.2F-49692632.4362F.1 (engineering build)").version, "eos-json-1.0")
        self.assertEqual(nz.select_parser("ospf.neighbors", "linux", "FRR 8.4.4-1.1ubuntu6.7").version, "frr-json-1.0")
        self.assertEqual(nz.select_parser("ospf.neighbors", "iosxe", "Cisco IOS XE Software, Version 17.06.01a").version, "iosxe-text-1.0")
        self.assertEqual(nz.select_parser("interfaces.openconfig", "ceos", "").version, "openconfig-1.0")   # model parsers are version independent

    def test_UT020_partial_parse_marks_quality(self):
        truncated = IOS_IFACES.replace("  MTU 1500 bytes, BW 1000000 Kbit/sec, DLY 10 usec,\n  Full Duplex, 1000Mbps, link type is auto, media type is Virtual\n", "", 1)
        res = nz.normalize_interfaces(truncated, parser_id="interfaces.state", platform="iosxe", os_version="17.06.01a", device="R1", evidence=ev(), now=T0)
        mtu = [o for o in res["observations"] if o["key"] == "interface.mtu"]
        self.assertEqual([o["target"]["interface"] for o in mtu], ["GigabitEthernet2"])     # no MTU invented for Gi1
        gi1 = [o for o in res["observations"] if o["target"]["interface"] == "GigabitEthernet1"]
        self.assertTrue(gi1 and all(o["quality"] == "PARTIAL" and "MISSING_FIELD:mtu" in o["flags"] for o in gi1))
        unknown_header = IOS_IFACES + "Tunnel9 is up, line protocol is up (spoofing)\n  weird body\n"
        res2 = nz.normalize_interfaces(unknown_header, parser_id="interfaces.state", platform="iosxe", os_version="17.06.01a", device="R1", evidence=ev(), now=T0)
        self.assertTrue(res2["observations"])

    def test_UT020_parser_disagreement_with_raw_text_is_untrusted(self):
        tampered = IOS_IFACES.replace("GigabitEthernet1 is up, line protocol is up", "GigabitEthernet1 is up, line protocol is down", 1)
        # simulate a template that mis-reads the state: parse the original, check against the tampered raw text
        parsed = nz.parse_iosxe_interfaces_text(IOS_IFACES)
        self.assertIn("OPER_STATE_MISMATCH:GigabitEthernet1", nz.ios_raw_text_check(tampered, parsed))
        res = nz.normalize_interfaces(tampered, parser_id="interfaces.state", platform="iosxe", os_version="17.06.01a", device="R1", evidence=ev(), now=T0,
                                      raw_text_check=lambda raw, p: nz.ios_raw_text_check(raw, nz.parse_iosxe_interfaces_text(IOS_IFACES)))
        self.assertEqual(res["quality"], "UNTRUSTED_PARSE")
        self.assertTrue(all(o["quality"] == "UNTRUSTED_PARSE" for o in res["observations"]))
        self.assertTrue(all(nz.trusted_value(o) == "UNKNOWN" for o in res["observations"]))

    def test_UT020_cross_parser_disagreement_marks_only_the_disagreeing_values(self):
        cli = nz.normalize_interfaces(EOS_IFACES, parser_id="interfaces.state", platform="ceos", os_version="4.36.2F", device="R1", evidence=ev(), now=T0)["observations"]
        snmp_raw = dict(SNMP_IFACES)
        snmp_raw["1.3.6.1.2.1.2.2.1.8.1"] = 2          # telemetry says DOWN while the CLI says up
        snmp = nz.normalize_interfaces(snmp_raw, parser_id="interfaces.snmp", platform="ceos", os_version="4.36.2F", device="R1", evidence=ev("SNMP_POLL"), now=T0)["observations"]
        cmp_ = nz.compare_observations(cli, snmp, keys=["interface.oper_state", "interface.mtu"])
        self.assertEqual([(d["key"], d["a"], d["b"]) for d in cmp_["disagreements"]], [("interface.oper_state", "up", "down")])
        self.assertEqual([a["key"] for a in cmp_["agreed"]], ["interface.mtu"])
        marked = nz.mark_untrusted(cli, cmp_)
        by = {(o["key"], o["target"]["interface"]): o for o in marked}
        self.assertEqual(by[("interface.oper_state", "Ethernet1")]["quality"], "UNTRUSTED_PARSE")
        self.assertIn("PARSER_DISAGREEMENT", by[("interface.oper_state", "Ethernet1")]["flags"])
        self.assertEqual(by[("interface.mtu", "Ethernet1")]["quality"], "OK")
        self.assertEqual(nz.trusted_value(by[("interface.oper_state", "Ethernet1")]), "UNKNOWN")

    def test_UT020_malformed_and_empty_input_are_missing_records(self):
        for raw, reason in [("{not json", "PARSE_FAILED"), (json.dumps({"interfaces": {}}), "EMPTY"), (json.dumps([1, 2]), "PARSE_FAILED")]:
            res = nz.normalize_interfaces(raw, parser_id="interfaces.state", platform="ceos", os_version="4.36.2F", device="R1", evidence=ev(), now=T0)
            self.assertEqual((res["observations"], res["missing"][0]["reason"]), ([], reason))

    def test_UT020_inaccurate_telemetry_is_caught_by_plausibility(self):
        bad = json.loads(EOS_IFACES)
        bad["interfaces"]["Ethernet1"]["mtu"] = 999999
        bad["interfaces"]["Ethernet2"].update(interfaceStatus="disabled", lineProtocolStatus="up")
        res = nz.normalize_interfaces(json.dumps(bad), parser_id="interfaces.state", platform="ceos", os_version="4.36.2F", device="R1", evidence=ev(), now=T0)
        self.assertEqual(res["quality"], "UNTRUSTED_PARSE")
        flags = {f for o in res["observations"] for f in o["flags"]}
        self.assertTrue({"IMPLAUSIBLE_MTU:Ethernet1:999999", "OPER_UP_WHILE_ADMIN_DOWN:Ethernet2"} <= flags)
        # ... and a counter rate faster than the line is flagged by the SNMP path
        tracker = nz.CounterTracker()
        for i, v in enumerate((0, 10**12)):
            snap = dict(SNMP_IFACES, **{"1.3.6.1.2.1.31.1.1.1.6.1": v})
            out = nz.normalize_snmp_poll(nz.parse_snmp_if_mib(snap).records, device="R1", evidence=ev("SNMP_POLL", collected=T0 + timedelta(seconds=10 * i)), tracker=tracker,
                                         now=T0 + timedelta(seconds=10 * i), platform="ceos")
        rate = next(o for o in out["observations"] if o["key"] == "interface.rate.in_octets")
        self.assertEqual(rate["quality"], "UNTRUSTED_PARSE")


class UT021_TimeAndOrdering(unittest.TestCase):
    def test_UT021_timestamp_forms(self):
        e = T0
        self.assertEqual(nz.to_utc(e.timestamp()), e)
        self.assertEqual(nz.to_utc(int(e.timestamp() * 1000)), e)
        self.assertEqual(nz.to_utc(int(e.timestamp() * 1e9)), e)
        self.assertEqual(nz.to_utc(int(e.timestamp() * 1e6), unit="us"), e)
        self.assertEqual(nz.to_utc("2026-11-09T14:00:00+02:00"), e)
        self.assertEqual(nz.to_utc("2026-11-09T07:00:00", tz="America/New_York"), e)       # zone-less string in the device zone (EST, UTC-5)
        self.assertEqual(nz.to_utc("2026-11-09T12:00:00Z"), e)
        self.assertEqual(nz.to_utc("Nov  9 12:00:00", reference=e + timedelta(seconds=3)), e)
        self.assertEqual(nz.to_utc("Nov  9 07:00:00", tz="-05:00", reference=e), e)
        self.assertEqual(nz.to_utc("Dec 31 23:59:59", reference=e).year, 2025)           # year rollover: not a future date
        with self.assertRaises(ValueError):
            nz.to_utc("yesterday-ish")

    def test_UT021_skew_estimation_and_correction(self):
        ok = nz.estimate_skew(T0 + timedelta(seconds=1), T0)
        self.assertEqual(ok["status"], "OK")
        self.assertEqual(nz.correct_time(T0, ok), (T0, False))
        sk = nz.estimate_skew(T0 + timedelta(seconds=90), T0, rtt_s=0.2)
        self.assertEqual(sk["status"], "SKEWED")
        self.assertAlmostEqual(sk["skew_s"], 90.1)
        t, corrected = nz.correct_time(T0 + timedelta(seconds=90.1), sk)
        self.assertTrue(corrected)
        self.assertAlmostEqual((t - T0).total_seconds(), 0.0, places=3)
        self.assertEqual(nz.estimate_skew(None, T0)["status"], "UNKNOWN")

    def test_UT021_unordered_arrivals_and_skew_correlate_across_devices(self):
        """R1 (clock +60 s) and R2 (accurate) log the two ends of one link event; arrival order is reversed."""
        r1_clock = nz.estimate_skew(T0 + timedelta(seconds=60), T0)
        l_r1 = nz.parse_syslog_line("<189>Nov  9 12:01:10 R1 %LINEPROTO-5-UPDOWN: Line protocol on Interface Ethernet1, changed state to down", received_at=T0 + timedelta(seconds=10))
        l_r2 = nz.parse_syslog_line("<189>Nov  9 12:00:09 R2 %LINEPROTO-5-UPDOWN: Line protocol on Interface Ethernet1, changed state to down", received_at=T0 + timedelta(seconds=11))
        a = nz.normalize_syslog_events([l_r1], evidence=ev("SYSLOG", device="R1"), device="R1", clock=r1_clock, now=T0 + timedelta(minutes=2))["observations"][0]
        b = nz.normalize_syslog_events([l_r2], evidence=ev("SYSLOG", device="R2"), device="R2", now=T0 + timedelta(minutes=2))["observations"][0]
        self.assertEqual(a["observed_at"], nz.iso(T0 + timedelta(seconds=10)))
        self.assertEqual(b["observed_at"], nz.iso(T0 + timedelta(seconds=9)))
        self.assertLess(abs((nz.to_utc(a["observed_at"]) - nz.to_utc(b["observed_at"])).total_seconds()), 2.0)      # now correlatable
        self.assertIn("DEVICE_CLOCK_SKEW_CORRECTED", a["flags"])
        # unordered within one batch: output is time-sorted by corrected time
        evs = [nz.parse_syslog_line(f"<189>Nov  9 12:00:{s:02d} R1 %LINEPROTO-5-UPDOWN: Line protocol on Interface Ethernet{i}, changed state to down", received_at=T0 + timedelta(seconds=40 - s))
               for i, s in [(1, 30), (2, 10), (3, 20)]]
        out = nz.normalize_syslog_events(evs, evidence=ev("SYSLOG"), device="R1", now=T0 + timedelta(minutes=1))["observations"]
        self.assertEqual([o["target"]["interface"] for o in out], ["Ethernet2", "Ethernet3", "Ethernet1"])

    def test_UT021_missing_timestamp_uses_arrival_and_is_partial(self):
        e = nz.parse_syslog_line("<13>no timestamp here %LINK-3-UPDOWN: Interface GigabitEthernet2, changed state to down", received_at=T0)
        o = nz.normalize_syslog_events([e], evidence=ev("SYSLOG"), device="R1", now=T0)["observations"][0]
        self.assertEqual((o["observed_at"], o["quality"]), (nz.iso(T0), "PARTIAL"))
        self.assertIn("ARRIVAL_TIME_USED", o["flags"])

    def test_UT021_freshness_and_trusted_value(self):
        self.assertEqual(nz.freshness(T0, T0 + timedelta(seconds=30), 60)["status"], "FRESH")
        self.assertEqual(nz.freshness(T0, T0 + timedelta(seconds=300), 60)["status"], "STALE")
        self.assertEqual(nz.freshness(T0 + timedelta(minutes=5), T0, 60)["status"], "FUTURE")
        self.assertEqual(nz.freshness(None, T0, 60)["status"], "UNKNOWN")
        o = nz.make_observation("interface.oper_state", "up", device="R1", evidence=ev(), observed_at=T0, interface="Ethernet1", now=T0 + timedelta(seconds=10), max_age_s=60)
        self.assertEqual(nz.trusted_value(o, T0 + timedelta(seconds=30)), "up")
        self.assertEqual(nz.trusted_value(o, T0 + timedelta(hours=1)), "UNKNOWN")      # stale -> UNKNOWN, not "up"
        stale = nz.make_observation("interface.oper_state", "up", device="R1", evidence=ev(), observed_at=T0 - timedelta(hours=1), now=T0, max_age_s=60)
        self.assertEqual((stale["quality"], nz.trusted_value(stale)), ("STALE", "UNKNOWN"))
        future = nz.make_observation("interface.oper_state", "up", device="R1", evidence=ev(), observed_at=T0 + timedelta(hours=1), now=T0)
        self.assertEqual(nz.trusted_value(future), "UNKNOWN")
        self.assertEqual(nz.trusted_value(None), "UNKNOWN")


class UT022_Budgets(unittest.TestCase):
    OUT = {"show interfaces | json": EOS_IFACES, "show ip ospf neighbor | json": json.dumps({"vrfs": {}}), "show ip bgp summary | json": json.dumps({"vrfs": {}})}

    def test_UT022_command_budget_stops_further_requests(self):
        col, _ = collector(budget=c.Budget(max_commands=2))
        t = FakeTransport(self.OUT)
        res = col.collect(ceos(), ["interfaces", "ospf_neighbors", "bgp_summary", "ip_route"], t)
        self.assertEqual(len(t.calls), 2)
        self.assertEqual([m["reason"] for m in res["missing"] if m["reason"] == "BUDGET_EXCEEDED"].__len__(), 2)
        self.assertEqual(res["run"]["budget"]["used"]["commands"], 2)

    def test_UT022_time_budget_and_rate_spacing(self):
        col, clock = collector(budget=c.Budget(max_seconds=10, min_interval_s=6.0))
        t = FakeTransport(self.OUT)
        res = col.collect(ceos(), ["interfaces", "ospf_neighbors", "bgp_summary"], t)
        self.assertEqual(clock.sleeps[:1], [6.0])                       # second request waited out the spacing
        self.assertEqual(len(t.calls), 2)
        self.assertEqual([m["reason"] for m in res["missing"]], ["BUDGET_EXCEEDED"])      # 3rd request would start after the 10 s wall clock
        self.assertGreater(res["run"]["budget"]["used"]["throttled_s"], 0)

    def test_UT022_byte_budget_and_oversize_output(self):
        col, _ = collector(budget=c.Budget(max_bytes=500))
        res = col.collect(ceos(), ["interfaces"], FakeTransport(self.OUT))
        self.assertIn(res["missing"][0]["reason"], ("OUTPUT_TOO_LARGE", "BUDGET_EXCEEDED"))
        self.assertEqual(res["observations"], [])

    def test_UT022_timeout_retries_are_bounded_and_counted(self):
        col, clock = collector(budget=c.Budget(max_retries=2, backoff_s=1.0))
        t = FakeTransport(self.OUT, raises=[TimeoutError(), TimeoutError(), None])
        res = col.collect(ceos(), ["interfaces"], t)
        self.assertEqual((len(t.calls), res["run"]["retries"], res["missing"]), (3, 2, []))
        self.assertEqual(clock.sleeps, [1.0, 2.0])                       # linear backoff
        t2 = FakeTransport(self.OUT, raises=[TimeoutError()] * 5)
        res2 = col.collect(ceos(), ["interfaces"], t2)
        self.assertEqual((len(t2.calls), res2["missing"][0]["reason"]), (3, "TIMEOUT"))     # 1 + max_retries, then give up
        # non-transient errors are never retried
        t3 = FakeTransport(self.OUT, raises=[c.TransportError("CONNECTION_REFUSED", transient=False)])
        col.collect(ceos(), ["interfaces"], t3)
        self.assertEqual(len(t3.calls), 1)

    def test_UT022_retries_consume_the_command_budget(self):
        col, _ = collector(budget=c.Budget(max_commands=2, max_retries=5))
        t = FakeTransport(self.OUT, raises=[TimeoutError()] * 10)
        res = col.collect(ceos(), ["interfaces"], t)
        self.assertEqual(len(t.calls), 2)
        self.assertEqual(res["missing"][0]["reason"], "BUDGET_EXCEEDED")

    def test_UT022_buffer_rejects_and_counts(self):
        b = c.BoundedBuffer(2)
        self.assertEqual([b.offer(i) for i in range(4)], [True, True, False, False])
        self.assertEqual(b.dropped, 2)

    def test_UT022_syslog_and_flow_record_budgets(self):
        col, _ = collector(c.SyslogCollector, budget=c.Budget(max_records=2), capability_probe=lambda p, s: {"status": "SUPPORTED"})
        res = col.collect(ceos(), [(f"<13>Nov  9 12:00:0{i} R1 x{i}", T0) for i in range(5)])
        self.assertIn("DATA_LOSS", res["run"]["flags"])
        self.assertEqual(res["missing"][0]["reason"], "BUDGET_EXCEEDED")
        self.assertEqual(res["evidence"][0]["coverage"]["dropped"], 3)

    def test_UT022_snmp_budget_exhaustion_discards_half_table(self):
        class S:
            def walk(self, oid):
                return {k: v for k, v in SNMP_IFACES.items() if k.startswith(oid + ".")}

            def get(self, oid):
                return 1

        col, _ = collector(c.SnmpCollector, budget=c.Budget(max_commands=2), capability_probe=lambda p, s: {"status": "SUPPORTED"})
        res = col.poll(ceos(), S())
        self.assertEqual(res["observations"], [])
        self.assertEqual(res["missing"][0]["reason"], "BUDGET_EXCEEDED")


class UT023_StreamingVsPolling(unittest.TestCase):
    def test_UT023_independently_selectable(self):
        self.assertEqual(c.plan_telemetry(gnmi=True, snmp=True, prefer="stream")["selected"], ["GNMI_STREAM"])
        self.assertEqual(c.plan_telemetry(gnmi=True, snmp=True, prefer="poll")["selected"], ["SNMP_POLL", "GNMI_GET"])
        self.assertEqual(c.plan_telemetry(gnmi=True, snmp=True, prefer="both")["selected"], ["GNMI_STREAM", "SNMP_POLL", "GNMI_GET"])
        self.assertEqual(c.plan_telemetry(gnmi=True, snmp=True)["selected"], ["GNMI_STREAM"])
        self.assertEqual(c.plan_telemetry(gnmi=False, snmp=True)["selected"], ["SNMP_POLL"])
        r = c.plan_telemetry(gnmi=False, snmp=True, prefer="stream")
        self.assertEqual((r["selected"], r["unavailable"]), ([], ["GNMI_STREAM"]))      # reported, never silently substituted
        self.assertEqual(c.plan_telemetry(gnmi=True, snmp=True, prefer="bogus")["error"], "INVALID_PREFERENCE")

    def test_UT023_every_source_documents_mode_sampling_freshness_overhead_backpressure(self):
        cat = c.describe_sources()
        self.assertEqual(set(cat["sources"]), set(c.SourceType.ALL))
        for name, p in cat["sources"].items():
            for key in ("mode", "freshness_max_age_s", "overhead", "backpressure", "preferred_for"):
                self.assertTrue(p.get(key), (name, key))
            self.assertIn(p["mode"], ("push", "poll", "on_demand"))
        self.assertEqual(cat["sources"]["GNMI_STREAM"]["mode"], "push")
        self.assertEqual(cat["sources"]["SNMP_POLL"]["mode"], "poll")
        json.dumps(cat)

    def test_UT023_default_sample_interval_matches_repository_gnmi_catalog(self):
        self.assertEqual(mon.load_gnmi_stream_catalog()["sample_interval_ns"] / 1e9, c.SOURCE_PROFILES["GNMI_STREAM"]["default_sampling_s"])

    def test_UT023_allowed_gnmi_prefixes_derive_from_repository_catalog(self):
        prefixes = mon.gnmi_allowed_prefixes()
        self.assertIn("/interfaces/interface", prefixes)
        col, _ = collector(c.GnmiCollector, capability_probe=lambda p, s: {"status": "SUPPORTED"})
        self.assertEqual(col.subscribe(ceos(), ["/system/state/hostname"], [], allowed_prefixes=prefixes)["missing"][0]["reason"], "EMPTY")
        self.assertEqual(col.subscribe(ceos(), ["/system/state/hostname"], [], allowed_prefixes=("/interfaces",))["missing"][0]["reason"], "COMMAND_NOT_ALLOWED")


class UT024_ErrorsAreMissingData(unittest.TestCase):
    def test_UT024_permission_denied_in_output_or_transport(self):
        col, _ = collector()
        t = FakeTransport({"show interfaces | json": "% Authorization denied for command 'show interfaces | json'\n"})
        res = col.collect(ceos(), ["interfaces"], t)
        self.assertEqual((res["observations"], res["missing"][0]["reason"]), ([], "PERMISSION_DENIED"))
        self.assertEqual(res["evidence"][0]["status"], "PERMISSION_DENIED")     # the denial itself is evidence
        res2 = col.collect(ceos(), ["interfaces"], FakeTransport(raises=[c.PermissionDenied()]))
        self.assertEqual((res2["observations"], res2["missing"][0]["reason"], res2["run"]["status"]), ([], "PERMISSION_DENIED", "FAILED"))

    def test_UT024_unsupported_command_and_empty_and_device_note(self):
        col, _ = collector()
        t = FakeTransport({"show interfaces Ethernet1 transceiver": "                                       ^\n% Invalid input detected at '^' marker.\n",
                           "show ip bgp summary | json": json.dumps({"errors": ["BGP inactive"]}), "show ip ospf neighbor | json": ""})
        res = col.collect(ceos(), ["interface_transceiver", "bgp_summary", "ospf_neighbors"], t, params={"interface_transceiver": {"interface": "Ethernet1"}})
        self.assertEqual([m["reason"] for m in res["missing"]], ["UNSUPPORTED_OPERATION", "EMPTY", "EMPTY"])
        self.assertEqual(res["observations"], [])
        self.assertIn("BGP inactive", res["missing"][1]["detail"])
        self.assertEqual(res["missing"][0]["interpretation"], "UNKNOWN")
        self.assertFalse(res["missing"][0]["observation_emitted"])

    def test_UT024_transport_error_never_leaks_exception_text(self):
        col, _ = collector()
        res = col.collect(ceos(), ["interfaces"], FakeTransport(raises=[c.TransportError("CONNECTION_FAILED", transient=False)]))
        self.assertEqual(res["missing"][0]["detail"], "CONNECTION_FAILED")

    def test_UT024_partial_run_keeps_good_data_and_missing_side_by_side(self):
        col, _ = collector()
        t = FakeTransport({"show interfaces | json": EOS_IFACES, "show ip ospf neighbor | json": "% Authorization denied\n"})
        res = col.collect(ceos(), ["interfaces", "ospf_neighbors"], t)
        self.assertEqual(res["run"]["status"], "PARTIAL")
        self.assertTrue(res["observations"])
        self.assertEqual(res["coverage"]["missing_by_reason"], {"PERMISSION_DENIED": 1})
        self.assertFalse([o for o in res["observations"] if "ospf" in o["key"]])

    def test_UT024_provider_failures(self):
        pc = c.ProviderCollector(c.SourceType.NETBOX_INTENT, now=lambda: T0, capability_probe=lambda p, s: {"status": "SUPPORTED"})

        def boom():
            raise c.TransportError("DOWN")
        self.assertEqual(pc.collect(ceos(), boom)["missing"][0]["reason"], "TRANSPORT_ERROR")
        self.assertEqual(pc.collect(ceos(), lambda: {})["missing"][0]["reason"], "EMPTY")

        def deny():
            raise c.PermissionDenied()
        self.assertEqual(pc.collect(ceos(), deny)["missing"][0]["reason"], "PERMISSION_DENIED")

    def test_UT024_trusted_value_of_absent_observation_is_unknown(self):
        self.assertEqual(nz.trusted_value(None), "UNKNOWN")
        m = nz.missing_record("TIMEOUT", source_type="CLI", device="R1")
        self.assertEqual((m["observation_emitted"], m["interpretation"]), (False, "UNKNOWN"))


class UT053_UnsupportedNeverInvented(unittest.TestCase):
    def test_UT053_unsupported_operations_refused_without_touching_transport(self):
        t = FakeTransport()
        col, _ = collector(c.NetconfCollector, capability_probe=lambda p, s: {"status": "SUPPORTED"})
        for rpc in ("edit-config", "copy-config", "delete-config", "commit", "lock", "kill-session", "bogus"):
            res = col.get(ceos(), rpc, "interfaces", t)
            self.assertEqual((res["run"]["status"], res["missing"][0]["reason"]), ("REFUSED", "UNSUPPORTED_OPERATION"), rpc)
        self.assertEqual(col.get(ceos(), "get", "not-catalogued", t)["missing"][0]["reason"], "COMMAND_NOT_ALLOWED")
        self.assertEqual(col.edit_config(ceos())["missing"][0]["reason"], "UNSUPPORTED_OPERATION")
        self.assertEqual(t.calls, [])

    def test_UT053_unsupported_platforms_and_sources_are_named_not_faked(self):
        probe = caps.make_capability_probe(health_capability=lambda p: {"status": "SUPPORTED", "evidence": "health"})
        self.assertEqual(probe("nokia_srlinux", "CLI")["status"], "UNKNOWN")
        self.assertEqual(probe("iosxe", "CLI")["status"], "UNKNOWN")                       # health engine has no IOS XE session; not inferred from cEOS
        self.assertEqual(caps.make_capability_probe(gateway_platforms=["iosxe"])("iosxe", "CLI")["transport"], "gateway")
        for src in ("GNMI_STREAM", "SNMP_POLL", "SYSLOG", "NETCONF"):
            self.assertNotEqual(probe("iosxe", src)["status"], "SUPPORTED", src)
        self.assertEqual(probe("linux", "NETCONF")["status"], "UNSUPPORTED")
        matrix = caps.capability_matrix(probe)
        self.assertEqual(set(matrix), set(caps.KNOWN_PLATFORMS))
        json.dumps(matrix)

    def test_UT053_iosxe_has_no_bgp_or_fhrp_parser_and_says_so(self):
        res = nz.normalize_neighbors("BGP summary text", parser_id="bgp.summary", platform="iosxe", os_version="17.06.01a", device="R1", evidence=ev(), now=T0)
        self.assertEqual((res["observations"], res["missing"][0]["reason"]), ([], "PARSER_UNAVAILABLE"))

    def test_UT053_empty_stp_evidence_is_retained_but_yields_no_observation(self):
        col, _ = collector()
        t = FakeTransport({"show spanning-tree | json": '{"spanningTreeInstances": {}}'})
        res = col.collect(ceos(), ["spanning_tree"], t)
        self.assertEqual((res["observations"], res["missing"][0]["reason"], len(res["evidence"])), ([], "EMPTY", 1))

    def test_UT053_active_probes_and_writes_are_not_in_any_catalog(self):
        for plat, specs in c.COMMAND_CATALOG.items():
            for spec in specs.values():
                text = spec.command if isinstance(spec.command, str) else " ".join(spec.command)
                self.assertFalse(set(text.lower().split()) & {"ping", "traceroute", "configure", "clear", "reload", "write", "copy", "debug"}, (plat, text))

    def test_UT053_snmp_and_gnmi_set_refused(self):
        sc, _ = collector(c.SnmpCollector, capability_probe=lambda p, s: {"status": "SUPPORTED"})
        gc, _ = collector(c.GnmiCollector, capability_probe=lambda p, s: {"status": "SUPPORTED"})
        for res in (sc.set(ceos()), gc.set(ceos())):
            self.assertEqual(res["missing"][0]["reason"], "UNSUPPORTED_OPERATION")
            self.assertEqual(res["run"]["status"], "REFUSED")

    def test_UT053_xxe_in_netconf_reply_is_rejected(self):
        evil = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a SYSTEM "file:///etc/passwd">]><interfaces><interface><name>&a;</name></interface></interfaces>'

        class S:
            def execute(self, rpc, flt):
                return evil
        col, _ = collector(c.NetconfCollector, capability_probe=lambda p, s: {"status": "SUPPORTED"})
        res = col.get(ceos(), "get", "interfaces", S())
        self.assertEqual(res["missing"][0]["reason"], "PARSE_FAILED")
        self.assertNotIn("passwd", json.dumps(res))

    def test_UT053_netconf_read_maps_to_canonical_interface_state(self):
        xml = ('<data><interfaces xmlns="http://openconfig.net/yang/interfaces"><interface><name>Ethernet1</name><state><admin-status>UP</admin-status>'
               '<oper-status>UP</oper-status><mtu>1500</mtu><counters><in-octets>1000</in-octets><in-errors>3</in-errors></counters></state></interface></interfaces></data>')

        class S:
            def execute(self, rpc, flt):
                return xml
        col, _ = collector(c.NetconfCollector, capability_probe=lambda p, s: {"status": "SUPPORTED"})
        res = col.get(ceos(), "get", "interfaces", S())
        v = nz.canonical_view(res["observations"])
        self.assertEqual((v[("interface.oper_state", "Ethernet1")], v[("interface.mtu", "Ethernet1")], v[("interface.counter.in_errors", "Ethernet1")]), ("up", 1500, 3))


# ====================================================================================================================
class S2_Safety(unittest.TestCase):
    def test_secrets_redacted_in_stored_raw_and_snapshot_observations(self):
        cfg = "hostname R1\nusername admin secret 5 $1$abcdef$hash\nsnmp-server community PUBLICSECRET ro\nenable secret 9 $9$xyz\nrouter ospf 1\n  message-digest-key 1 md5 7 0822455D0A16\n"
        store = c.InMemoryRawStore()
        col, _ = collector(raw_store=store)
        t = FakeTransport({"show running-config": cfg})
        res = col.collect(ceos(), ["running_config"], t)
        blob = json.dumps(res) + json.dumps(store.items)
        for secret in ("$1$abcdef$hash", "PUBLICSECRET", "$9$xyz", "0822455D0A16"):
            self.assertNotIn(secret, blob)
        e = res["evidence"][0]
        self.assertEqual(e["redaction"]["status"], "REDACTED")
        self.assertNotEqual(e["raw_ref"]["hash"], e["raw_ref"]["stored_hash"])      # integrity hash of what arrived vs. of what was stored
        snap = res["observations"][0]
        self.assertEqual(snap["key"], "config.snapshot")
        self.assertNotIn("hostname R1", json.dumps(snap))                         # body never in the observation
        self.assertIsNone(snap["value"]["operator_url"])
        self.assertIn("NO_OPERATOR_URL", snap["flags"])

    def test_maintenance_mode_is_flagged_not_hidden(self):
        col, _ = collector()
        res = col.collect(ceos(maintenance=True), ["interfaces"], FakeTransport({"show interfaces | json": EOS_IFACES}))
        self.assertIn("MAINTENANCE_MODE", res["run"]["flags"])

    def test_provider_snapshots_golden_and_intent_provenance(self):
        pc = c.ProviderCollector(c.SourceType.GOLDEN_CONFIG, now=lambda: T0, capability_probe=lambda p, s: {"status": "SUPPORTED"})
        res = pc.collect(ceos(), lambda: {"kind": "golden", "content": "hostname R1\n", "revision": "g-42", "url": "https://nmas.example/bundles/golden/g-42",
                                          "approved_change_id": "CHG-7", "soak": {"state": "ACTIVE", "deadline": "2026-11-10T00:00:00Z"}})
        e = res["evidence"][0]
        self.assertEqual((e["extra"]["revision"], e["extra"]["operator_url"], e["extra"]["soak"]["state"]), ("g-42", "https://nmas.example/bundles/golden/g-42", "ACTIVE"))
        self.assertEqual(res["observations"][0]["value"]["revision"], "g-42")
        self.assertNotIn("NO_OPERATOR_URL", res["run"]["flags"])

    def test_evidence_contract_carries_full_provenance(self):
        col, _ = collector(raw_store=c.InMemoryRawStore())
        res = col.collect(ceos(), ["interfaces"], FakeTransport({"show interfaces | json": EOS_IFACES}), transport_name="netmiko")
        e = res["evidence"][0]
        for key in ("schema", "evidence_id", "source_type", "transport", "adapter", "adapter_version", "device", "platform", "os_version", "command_or_api", "started_at", "collected_at",
                    "status", "freshness_max_age_s", "raw_ref", "redaction", "parser"):
            self.assertIn(key, e)
        self.assertTrue(e["raw_ref"]["hash"].startswith("sha256:"))
        self.assertTrue(e["raw_ref"]["pointer"].startswith("mem:"))
        self.assertEqual(e["parser"]["version"], "eos-json-1.0")
        o = res["observations"][0]
        for key in ("schema", "observation_id", "key", "value", "unit", "target", "observed_at", "collected_at", "freshness", "source", "quality", "confidence", "parser", "raw_hash",
                    "redaction_status", "flags", "evidence_class"):
            self.assertIn(key, o)
        self.assertEqual(o["raw_hash"], e["raw_ref"]["hash"])
        self.assertEqual(o["source"]["evidence_id"], e["evidence_id"])
        json.dumps(res)       # serializable

    def test_bundles_are_deterministic_for_replay(self):
        def once():
            col, _ = collector()
            return json.dumps(col.collect(ceos(), ["interfaces"], FakeTransport({"show interfaces | json": EOS_IFACES})), sort_keys=True)
        self.assertEqual(once(), once())


class S2_Adapters(unittest.TestCase):
    def test_flux_query_is_validated_and_csv_parsed(self):
        q = mon.flux_syslog_query("nmas", "R1", start="-5m", pattern="changed state")
        self.assertIn('r.device == "R1"', q)
        for bad in ('R1" or true //', "R1;drop", ""):
            with self.assertRaises(ValueError):
                mon.flux_syslog_query("nmas", bad)
        with self.assertRaises(ValueError):
            mon.flux_syslog_query("nmas", "R1", start="-5m); drop")
        csv_text = ("#datatype,string,long,dateTime:RFC3339,string\n#group,false,false,false,false\n#default,_result,,,\n"
                    ",result,table,_time,_value\n,,0,2026-11-09T12:00:05Z,\"%LINEPROTO-5-UPDOWN: Line protocol on Interface Ethernet1, changed state to down\"\n")
        rows = mon.parse_flux_csv(csv_text)
        self.assertEqual(rows[0][1], "2026-11-09T12:00:05Z")

    def test_topology_telemetry_adapter_only_trusts_fresh_endpoints(self):
        class Snap:
            available = True
            nodes = {"R1": {"id": "R1", "health": "OK", "last_telemetry_timestamp": T0.isoformat()}}
            edges = [{"id": "e1", "endpoint_state": [{"node": "R1", "interface": "Ethernet1", "oper_status": "UP", "admin_status": "UP", "evidence_fresh": True},
                                                     {"node": "R1", "interface": "Ethernet2", "oper_status": "UP", "admin_status": "UP", "evidence_fresh": False}]}]

        col, _ = collector(mon.TopologyTelemetryCollector, capability_probe=lambda p, s: {"status": "SUPPORTED"})
        res = col.collect(ceos(), Snap())
        interfaces = {o["target"].get("interface") for o in res["observations"] if o["key"].startswith("interface.")}
        self.assertEqual(interfaces, {"Ethernet1"})
        self.assertEqual([m["reason"] for m in res["missing"]], ["STALE_SOURCE"])
        self.assertTrue(all("MONITORED_ENDPOINT_ONLY" in o["flags"] for o in res["observations"] if o["key"].startswith("interface.")))

        class Down(Snap):
            available = False
        self.assertEqual(col.collect(ceos(), Down())["missing"][0]["reason"], "TRANSPORT_ERROR")

    def test_health_live_transport_enforces_existing_allowlist(self):
        """Uses a fake ``core.services.health.live`` so the test needs no Django settings."""
        import sys
        import types
        fake = types.ModuleType("core.services.health.live")

        class LiveError(Exception):
            def __init__(self, code):
                self.code = code
        fake.LiveError = LiveError
        fake.CEOS_COMMANDS = {"interfaces": "show interfaces | json"}
        fake.LINUX_COMMANDS = {"addr": ("ip", "-j", "addr", "show")}
        fake.default_session_factory = lambda device: (lambda d: types.SimpleNamespace(run=lambda k: {"interfaces": EOS_IFACES}[k], close=lambda: None))
        pkg = types.ModuleType("core.services.health")
        pkg.live = fake
        saved = {k: sys.modules.get(k) for k in ("core.services.health", "core.services.health.live")}
        sys.modules["core.services.health"], sys.modules["core.services.health.live"] = pkg, fake
        try:
            t = tr.HealthLiveTransport({"name": "R1", "platform": "ceos"})
            self.assertEqual(t.execute("show interfaces | json"), EOS_IFACES)
            with self.assertRaises(c.CommandNotAllowed):
                t.execute("show spanning-tree | json")
        finally:
            for k, v in saved.items():
                if v is None:
                    sys.modules.pop(k, None)
                else:
                    sys.modules[k] = v

    def test_netmiko_like_transport_maps_errors_without_leaking(self):
        class Conn:
            def send_command(self, cmd):
                raise RuntimeError("password=hunter2 host=10.0.0.1")
        t = tr.NetmikoLikeTransport(Conn())
        with self.assertRaises(c.TransportError) as e:
            t.execute("show version")
        self.assertNotIn("hunter2", str(e.exception) + e.exception.code)
        with self.assertRaises(c.CommandNotAllowed):
            t.execute(("ip", "link"))

    def test_argv_runner_transport(self):
        import types
        t = tr.ArgvRunnerTransport(lambda argv: types.SimpleNamespace(stdout="[]", returncode=0))
        self.assertEqual(t.execute(("ip", "-j", "addr", "show")), "[]")
        with self.assertRaises(c.CommandNotAllowed):
            t.execute("ip addr")
        bad = tr.ArgvRunnerTransport(lambda argv: types.SimpleNamespace(stdout="", returncode=1))
        with self.assertRaises(c.TransportError):
            bad.execute(("ip", "link"))


class S2_ContractBridge(unittest.TestCase):
    def setUp(self):
        try:
            from core.services.troubleshooting import contracts
        except ImportError:   # s1 contracts not present: reported, not faked
            self.skipTest("s1 contracts module not available")
        self.contracts = contracts

    def test_bundle_maps_to_s1_collection_bundle_and_validates(self):
        col, _ = collector()
        t = FakeTransport({"show interfaces | json": EOS_IFACES, "show ip ospf neighbor | json": "% Authorization denied\n"})
        res = col.collect(ceos(), ["interfaces", "ospf_neighbors"], t)
        payload = bridge.to_contract_bundle(res, case_id="CASE-1")
        self.assertEqual(self.contracts.validate(payload, "collection_bundle/1"), [])
        missing = [o for o in payload["observations"] if o.get("is_missing_data")]
        self.assertEqual([(m["missing_reason"], m["quality"]) for m in missing], [("PERMISSION_DENIED", "MISSING")])
        self.assertEqual(payload["status"], "PARTIAL")
        again = bridge.to_contract_bundle(res, case_id="CASE-1")
        self.assertEqual(payload["idempotency_key"], again["idempotency_key"])

    def test_refused_run_maps_to_denied_and_untrusted_quality_maps(self):
        col, _ = collector()
        res = col.collect(c.Target("R1", "ceos", "4.36.2F", withdrawn=True), ["interfaces"], FakeTransport())
        payload = bridge.to_contract_bundle(res, case_id="CASE-1")
        self.assertEqual((payload["status"], self.contracts.validate(payload, "collection_bundle/1")), ("DENIED", []))
        o = nz.make_observation("k", 1, device="R1", evidence=ev(), observed_at=T0, quality="UNTRUSTED_PARSE", now=T0)
        self.assertEqual(bridge.to_contract_observation(o)["quality"], "UNTRUSTED")

    def test_intent_and_rates_are_derived_basis(self):
        intent = nz.normalize_intent("R1", {"interfaces": {"Et1": {"mtu": 9214}}}, evidence=ev("NETBOX_INTENT"), now=T0, url="https://x/y")["observations"][0]
        self.assertEqual(bridge.to_contract_observation(intent)["basis"], "DERIVED")
        self.assertEqual(self.contracts.validate({"schema": "observation/1", **bridge.to_contract_observation(intent)}, "observation/1"), [])


class S2_ReplayOfRecordedGatewayEvidence(unittest.TestCase):
    """REPLAY ONLY: parses the raw outputs captured from the gateway fixtures.  These tests prove the parsers against real cEOS 4.36.2F / Catalyst 8000V
    17.06.01a / FRR 8.4.4 text; they are not themselves live evidence (see docs/troubleshooting/collection.md for the live gateway run)."""

    @classmethod
    def load(cls, name):
        bundle = json.loads((LIVE / f"{name}.bundle.json").read_text())
        raw = json.loads((LIVE / f"{name}.raw.json").read_text())
        return bundle, {cmd: v["redacted_text"] for cmd, v in raw.items()}

    def test_REPLAY_recordings_declare_live_gateway_provenance(self):
        for name in ("ceos_r1", "iosxe_iosxe", "linux_peer"):
            bundle, _ = self.load(name)
            gw = bundle["run"]["gateway"]
            self.assertTrue(gw["live"])
            self.assertTrue(gw["gateway_evidence_seqs"])
            self.assertEqual(bundle["run"]["privileges"], "read-only")
            self.assertTrue(all(e["gateway"]["live"] for e in bundle["evidence"]))

    def test_REPLAY_ceos_interfaces_and_empty_protocols(self):
        _, raw = self.load("ceos_r1")
        res = nz.normalize_interfaces(raw["show interfaces | json"], parser_id="interfaces.state", platform="ceos", os_version="EOS 4.36.2F-49692632.4362F.1 (engineering build)",
                                      device="r1", evidence=ev(device="r1"), now=T0)
        v = nz.canonical_view(res["observations"])
        self.assertEqual(v[("interface.oper_state", "Ethernet1")], "up")
        self.assertEqual(v[("interface.mtu", "Ethernet1")], 9214)
        self.assertEqual(v[("interface.speed", "Ethernet1")], 1_000_000_000)
        self.assertEqual(res["quality"], "OK")
        ospf = nz.normalize_neighbors(raw["show ip ospf neighbor | json"], parser_id="ospf.neighbors", platform="ceos", os_version="4.36.2F", device="r1", evidence=ev(), now=T0)
        self.assertEqual((ospf["observations"], ospf["missing"]), ([], []))        # parsed, genuinely no neighbors
        self.assertEqual(c.classify_output(raw["show ip bgp summary | json"])[0], "DEVICE_NOTE")

    def test_REPLAY_iosxe_text_template_on_real_17_06_01a_output(self):
        _, raw = self.load("iosxe_iosxe")
        res = nz.normalize_interfaces(raw["show interfaces"], parser_id="interfaces.state", platform="iosxe", os_version="Cisco IOS XE Software, Version 17.06.01a", device="iosxe",
                                      evidence=ev(device="iosxe"), now=T0, raw_text_check=nz.ios_raw_text_check)
        self.assertEqual(res["quality"], "OK", res["parse"])
        v = nz.canonical_view(res["observations"])
        self.assertEqual(v[("interface.oper_state", "GigabitEthernet1")], "up")
        self.assertEqual(v[("interface.mtu", "GigabitEthernet1")], 1500)
        self.assertEqual(v[("interface.admin_state", "GigabitEthernet2")], "down")
        self.assertEqual(c.classify_output(raw["show interfaces GigabitEthernet2 transceiver detail"])[0], "UNSUPPORTED")    # truthful limitation on the virtual platform

    def test_REPLAY_frr_linux_addr_and_empty_vtysh(self):
        _, raw = self.load("linux_peer")
        res = nz.normalize_interfaces(raw["ip -j addr show"], parser_id="interfaces.state", platform="linux_frr", os_version="FRR 8.4.4-1.1ubuntu6.7", device="peer", evidence=ev(device="peer"), now=T0)
        names = {o["target"]["interface"] for o in res["observations"]}
        self.assertTrue({"lo", "eth0"} <= names)
        self.assertTrue(any(o["key"] == "interface.address" for o in res["observations"]))
        self.assertEqual(raw["vtysh -c show ip ospf neighbor json"], "")      # FRR ospfd not running on the fixture: empty output is reported as EMPTY, never as "no neighbors"

    def test_REPLAY_recorded_bundles_state_unparsed_and_empty_honestly(self):
        for name in ("ceos_r1", "iosxe_iosxe", "linux_peer"):
            bundle, _ = self.load(name)
            reasons = {m["reason"] for m in bundle["missing"]}
            self.assertTrue(reasons <= {"EMPTY", "PARSER_UNAVAILABLE", "UNSUPPORTED_OPERATION"}, (name, reasons))
            self.assertTrue(bundle["observations"])
            self.assertEqual([o for o in bundle["observations"] if o["quality"] not in ("OK", "PARTIAL")], [])


if __name__ == "__main__":
    unittest.main()
