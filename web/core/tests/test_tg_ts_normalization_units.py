"""Direct unit tests for the Troubleshooter normalization primitives (troubleshooting/normalization.py).

Each public helper is called directly with a valid input (its documented result) and with an invalid, boundary or
hostile input (its documented refusal: ``None`` / ``()`` / ``UNKNOWN`` / an exception -- never a fabricated value).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from django.test import SimpleTestCase

from core.services.troubleshooting import normalization as N

T0 = datetime(2026, 11, 9, 12, 0, 0, tzinfo=timezone.utc)
EVIDENCE = {"evidence_id": "ev-1", "source_type": "cli", "transport": "ssh", "adapter": "eos", "command_or_api": "show x",
            "collected_at": "2026-11-09T12:00:00Z", "raw_ref": {"hash": "sha256:ab"}, "redaction": {"status": "REDACTED"}}


class IdentityPrimitiveTests(SimpleTestCase):
    def test_platform_version_and_interface_names_return_their_canonical_form(self):
        self.assertEqual(N.canonical_platform(" CEOS "), "ceos")
        self.assertEqual(N.canonical_platform("ubuntu_frr"), "linux")
        self.assertEqual(N.parse_version("4.36.2F"), (4, 36, 2))
        self.assertEqual(N.parse_version("17.06.01a"), (17, 6, 1))
        self.assertEqual(N.canonical_interface("Et1"), "Ethernet1")
        self.assertEqual(N.canonical_interface("Gi2/0/1"), "GigabitEthernet2/0/1")
        self.assertEqual(N.canonical_interface("eth1", platform="linux"), "eth1")
        self.assertEqual(N.norm_oper_state("connected"), "up")
        self.assertEqual(N.norm_oper_state("administratively down"), "down")
        self.assertEqual(N.norm_admin_state("enabled"), "up")
        self.assertEqual(N.normalize_address("2001:DB8::1/64"), "2001:db8::1/64")
        self.assertEqual(N.normalize_address(" 10.0.0.1 "), "10.0.0.1")

    def test_unknown_or_malformed_identities_are_refused_never_guessed(self):
        with self.subTest("an unknown platform is refused as itself, not mapped"):
            self.assertEqual(N.canonical_platform("JunOS"), "junos")
        with self.subTest("an unparseable version is refused as empty"):
            self.assertEqual(N.parse_version("unknown"), ())
        with self.subTest("an unrecognized interface prefix is refused unchanged"):
            self.assertEqual(N.canonical_interface("Foo1"), "Foo1")
            self.assertEqual(N.canonical_interface(""), "")
        with self.subTest("an unknown oper state is refused as unknown"):
            self.assertEqual(N.norm_oper_state("sideways"), "unknown")
        with self.subTest("an unknown admin state is refused as unknown"):
            self.assertEqual(N.norm_admin_state(None), "unknown")
        with self.subTest("a non-address is refused as None"):
            self.assertIsNone(N.normalize_address("10.0.0.300"))
            self.assertIsNone(N.normalize_address("not-an-address/24"))


class TimePrimitiveTests(SimpleTestCase):
    def test_utcnow_returns_an_aware_utc_time(self):
        now = N.utcnow()
        self.assertEqual(now.utcoffset(), timedelta(0))

    def test_skew_correction_and_freshness_return_the_clock_model(self):
        skew = N.estimate_skew(T0 + timedelta(seconds=10), T0, rtt_s=2.0)
        self.assertEqual((skew["status"], skew["skew_s"]), ("SKEWED", 11.0))
        self.assertEqual(N.estimate_skew(T0 + timedelta(seconds=1), T0)["status"], "OK")
        corrected, changed = N.correct_time(T0 + timedelta(seconds=11), skew)
        self.assertEqual((corrected, changed), (T0, True))
        self.assertEqual(N.freshness(T0 - timedelta(seconds=10), T0, 60)["status"], "FRESH")
        self.assertEqual(N.freshness(T0 - timedelta(seconds=120), T0, 60)["status"], "STALE")

    def test_absent_or_implausible_times_are_refused_as_unknown_or_future(self):
        with self.subTest("an absent device time is refused as UNKNOWN skew"):
            self.assertEqual(N.estimate_skew(None, T0)["status"], N.UNKNOWN)
        with self.subTest("a clock within tolerance, or an absent clock, refuses to move the time"):
            self.assertEqual(N.correct_time(T0, {"status": "OK", "skew_s": 0.5}), (T0, False))
            self.assertEqual(N.correct_time(T0, None), (T0, False))
        with self.subTest("an absent observation time is refused as UNKNOWN freshness"):
            self.assertEqual(N.freshness(None, T0, 60)["status"], N.UNKNOWN)
        with self.subTest("an observation from the future is refused as FUTURE"):
            self.assertEqual(N.freshness(T0 + timedelta(seconds=30), T0, 60)["status"], "FUTURE")


class RedactionAndDigestTests(SimpleTestCase):
    def test_secrets_are_redacted_and_digests_are_stable(self):
        text, count = N.redact_text("username admin role network-admin secret 0 hunter2\nsnmp-server community public ro\n")
        self.assertNotIn("hunter2", text)
        self.assertNotIn("public", text)
        self.assertEqual(count, 2)
        self.assertEqual(N.sha256_text("abc"), "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        self.assertEqual(N.sha256_text(b"abc"), N.sha256_text("abc"))
        # regression: the key/value form used to redact only the "=" and leave the secret in the evidence
        for line in ("password = hunter2", "secret: hunter2", "username a secret = hunter2", "password hunter2", "enable secret 5 hunter2"):
            with self.subTest(line=line):
                redacted, n = N.redact_text(line)
                self.assertNotIn("hunter2", redacted)
                self.assertEqual(n, 1)
        self.assertEqual(N.sha256_json({"b": 1, "a": 2}), N.sha256_json({"a": 2, "b": 1}))

    def test_empty_or_secret_free_input_is_refused_no_redaction(self):
        with self.subTest("an empty or None text is refused with zero redactions"):
            self.assertEqual(N.redact_text(None), ("", 0))
            self.assertEqual(N.redact_text("interface Ethernet1\n   description uplink"), ("interface Ethernet1\n   description uplink", 0))
        with self.subTest("a private key block is refused verbatim"):
            begin, end = "-----BEGIN " + "RSA PRIVATE KEY" + "-----", "-----END " + "RSA PRIVATE KEY" + "-----"   # assembled at runtime: the tracked-secret scan (rightly) flags the literal header
            text, count = N.redact_text(f"{begin}\nMIIE\n{end}")
            self.assertEqual((text, count), (N.REDACTED, 1))
        with self.subTest("differing content is refused the same digest"):
            self.assertNotEqual(N.sha256_text("abc"), N.sha256_text("abd"))
            self.assertNotEqual(N.sha256_json([1, 2]), N.sha256_json([2, 1]))


class ObservationContractTests(SimpleTestCase):
    def test_missing_record_returns_a_non_observation(self):
        record = N.missing_record("PERMISSION_DENIED", source_type="cli", device="S1", detail="role", observed_at=T0, extra={"k": 1})
        self.assertEqual((record["kind"], record["interpretation"], record["observation_emitted"]), ("missing", N.UNKNOWN, False))
        self.assertEqual((record["recorded_at"], record["extra"]), ("2026-11-09T12:00:00Z", {"k": 1}))

    def test_missing_record_without_a_time_is_refused_an_absent_time(self):
        with self.subTest("an absent time is refused: the record still carries when it was recorded"):
            record = N.missing_record("UNSUPPORTED", source_type="gnmi")
            self.assertTrue(record["recorded_at"].endswith("Z"))
            self.assertNotIn("extra", record)

    def test_trusted_value_returns_only_a_fresh_trusted_value(self):
        obs = N.make_observation("if.oper", "up", device="S1", evidence=EVIDENCE, observed_at=T0, now=T0)
        self.assertEqual(N.trusted_value(obs, T0 + timedelta(seconds=5)), "up")

    def test_trusted_value_refuses_stale_untrusted_or_absent_observations(self):
        obs = N.make_observation("if.oper", "up", device="S1", evidence=EVIDENCE, observed_at=T0, now=T0)
        with self.subTest("a stale observation is refused as UNKNOWN"):
            self.assertEqual(N.trusted_value(obs, T0 + timedelta(hours=1)), N.UNKNOWN)
        with self.subTest("an untrusted parse is refused as UNKNOWN"):
            self.assertEqual(N.trusted_value({**obs, "quality": N.Quality.UNTRUSTED_PARSE}), N.UNKNOWN)
        with self.subTest("an absent observation is refused as UNKNOWN"):
            self.assertEqual(N.trusted_value(None), N.UNKNOWN)


class CounterTrackerTests(SimpleTestCase):
    def test_update_returns_first_then_a_normal_rate(self):
        tracker = N.CounterTracker()
        self.assertEqual(tracker.update(("S1", "Et1", "in_octets"), 1000, T0)["event"], "FIRST")
        second = tracker.update(("S1", "Et1", "in_octets"), 2000, T0 + timedelta(seconds=10))
        self.assertEqual((second["event"], second["rate_per_s"], second["rate_bps"]), ("NORMAL", 100.0, 800.0))

    def test_update_refuses_a_backwards_sample_and_keeps_the_last_good_one(self):
        tracker = N.CounterTracker(max_gap_s=60)
        tracker.update(("S1",), 1000, T0)
        with self.subTest("a sample earlier than the last is refused as TIME_REGRESSION"):
            self.assertEqual(tracker.update(("S1",), 900, T0 - timedelta(seconds=5))["event"], "TIME_REGRESSION")
        with self.subTest("a long gap is refused a rate"):
            gap = tracker.update(("S1",), 5000, T0 + timedelta(seconds=600))
            self.assertEqual((gap["event"], gap["rate_per_s"], gap["delta"]), ("GAP", None, 4000))


class ParserRegistryTests(SimpleTestCase):
    def setUp(self):
        self._saved = {k: list(v) for k, v in N.PARSERS.items()}

    def tearDown(self):
        N.PARSERS.clear()
        N.PARSERS.update(self._saved)

    def test_register_parser_returns_the_spec_and_makes_it_selectable(self):
        spec = N.register_parser(N.ParserSpec("tg.unit", "1", ("ceos",), min_version=(4, 30)))
        self.assertIs(spec, N.PARSERS["tg.unit"][-1])
        self.assertIs(N.select_parser("tg.unit", "ceos", "4.36.2F"), spec)

    def test_register_parser_refuses_selection_outside_its_platform_or_version(self):
        N.register_parser(N.ParserSpec("tg.unit", "1", ("ceos",), min_version=(4, 30), max_version=(4, 40)))
        for os_version, code in (("4.20.1", "VERSION_UNSUPPORTED"), ("", "VERSION_UNKNOWN")):
            with self.subTest(f"refused {code}"):
                with self.assertRaises(N.ParserSelectionError) as caught:
                    N.select_parser("tg.unit", "ceos", os_version)
                self.assertEqual(caught.exception.code, code)
        with self.assertRaises(N.ParserSelectionError):
            N.select_parser("tg.unit", "iosxe", "17.6.1")


class ParseResultTests(SimpleTestCase):
    def test_partial_and_over_parsed_return_false_for_a_complete_parse(self):
        result = N.ParseResult(records=[{"a": 1}, {"a": 2}], expected=2)
        self.assertFalse(result.partial)
        self.assertFalse(result.over_parsed)

    def test_partial_and_over_parsed_flag_missing_or_extra_records(self):
        self.assertTrue(N.ParseResult(records=[{"a": 1}], expected=2).partial)
        self.assertTrue(N.ParseResult(records=[], errors=["bad row"]).partial)
        self.assertTrue(N.ParseResult(records=[{"a": 1}, {"a": 2}, {"a": 3}], expected=2).over_parsed)


class TimeConversionTests(SimpleTestCase):
    def test_iso_and_to_utc_return_canonical_utc(self):
        self.assertEqual(N.iso(T0), "2026-11-09T12:00:00Z")
        self.assertEqual(N.to_utc("2026-11-09T13:00:00+01:00"), T0)
        self.assertEqual(N.to_utc(1793534400000), datetime.fromtimestamp(1793534400, tz=timezone.utc))   # ms inferred
        self.assertEqual(N.to_utc("Nov  9 12:00:00", reference=T0), T0)
        self.assertEqual(N.to_utc("2026-11-09 07:00:00", tz="-05:00"), T0)

    def test_absent_or_unrecognized_times_are_refused(self):
        with self.subTest("an absent time is refused as None"):
            self.assertIsNone(N.iso(None))
        for bad in ("yesterday-ish", True):
            with self.subTest(f"refused timestamp {bad!r}"):
                with self.assertRaises(ValueError):
                    N.to_utc(bad)


class CounterAnalysisTests(SimpleTestCase):
    def test_analyze_counter_returns_normal_and_wrap_rates(self):
        prev, cur = {"value": 100, "at": T0}, {"value": 1100, "at": T0 + timedelta(seconds=10)}
        self.assertEqual(N.analyze_counter(prev, cur)["rate_bps"], 800.0)
        top = (1 << 32) - 100
        wrapped = N.analyze_counter({"value": top, "at": T0}, {"value": 900, "at": T0 + timedelta(seconds=10)}, width_bits=32)
        self.assertEqual((wrapped["event"], wrapped["delta"]), ("WRAP", 1000))

    def test_analyze_counter_refuses_to_fabricate_a_rate(self):
        with self.subTest("an unexplained decrease is refused as RESET"):
            reset = N.analyze_counter({"value": 5000, "at": T0}, {"value": 10, "at": T0 + timedelta(seconds=10)}, width_bits=64)
            self.assertEqual((reset["event"], reset["delta"], reset["rate_per_s"]), ("RESET", None, None))
        with self.subTest("a device-reported clear is refused as RESET"):
            self.assertEqual(N.analyze_counter({"value": 1, "at": T0}, {"value": 2, "at": T0 + timedelta(seconds=1)},
                                               last_clear_changed=True)["event"], "RESET")
        with self.subTest("a zero interval is refused as DUPLICATE_SAMPLE"):
            self.assertEqual(N.analyze_counter({"value": 1, "at": T0}, {"value": 1, "at": T0})["event"], "DUPLICATE_SAMPLE")
        with self.subTest("an impossible line rate is flagged, refused as trustworthy"):
            fast = N.analyze_counter({"value": 0, "at": T0}, {"value": 10**9, "at": T0 + timedelta(seconds=1)}, speed_bps=1e6)
            self.assertIn("RATE_EXCEEDS_LINE_RATE", fast["flags"])


EOS_INTERFACES = {"interfaces": {"Ethernet1": {
    "name": "Ethernet1", "interfaceStatus": "connected", "lineProtocolStatus": "up", "mtu": 1500, "bandwidth": 1000000000,
    "duplex": "duplexFull", "physicalAddress": "00:1c:73:00:00:01",
    "interfaceCounters": {"inOctets": 10, "outOctets": 20, "totalInErrors": 1, "inputErrorsDetail": {"fcsErrors": 1},
                          "counterRefreshTime": 1793534400.0}}}}
IOS_TEXT = """GigabitEthernet2 is up, line protocol is up
  Hardware is CSR vNIC, address is 5254.0012.3456 (bia 5254.0012.3456)
  MTU 1500 bytes, BW 1000000 Kbit/sec, DLY 10 usec,
  Full Duplex, 1000Mbps, link type is auto, media type is Virtual
     5 packets input, 640 bytes, 0 no buffer
     0 runts, 0 giants, 0 throttles
     2 input errors, 1 CRC, 0 frame, 0 overrun, 0 ignored
     7 packets output, 900 bytes, 0 underruns
     0 output errors, 0 collisions, 0 interface resets
"""


class InterfaceParserTests(SimpleTestCase):
    def test_interface_parsers_return_canonical_records(self):
        eos = N.parse_eos_interfaces_json(EOS_INTERFACES)
        row = eos.records[0]
        self.assertEqual((row["name"], row["admin"], row["oper"], row["mtu"], row["duplex"]), ("Ethernet1", "up", "up", 1500, "full"))
        self.assertEqual((row["counters"]["in_crc_errors"], row["observed_at"]), (1, datetime.fromtimestamp(1793534400, tz=timezone.utc)))
        self.assertFalse(eos.partial)
        ios = N.parse_iosxe_interfaces_text(IOS_TEXT).records[0]
        self.assertEqual((ios["name"], ios["oper"], ios["counters"]["in_crc_errors"], ios["mac"]),
                         ("GigabitEthernet2", "up", 1, "5254.0012.3456"))
        oc = N.parse_openconfig_interfaces({"openconfig-interfaces:interfaces": {"interface": [{
            "name": "Ethernet2", "state": {"admin-status": "UP", "oper-status": "DOWN", "mtu": 9214, "counters": {"in-octets": "42"}},
            "openconfig-if-ethernet:ethernet": {"state": {"port-speed": "openconfig-if-ethernet:SPEED_10GB"}}}]}}).records[0]
        self.assertEqual((oc["name"], oc["admin"], oc["oper"], oc["speed_bps"], oc["counters"]), ("Ethernet2", "up", "down", 10**10, {"in_octets": 42}))
        snmp = N.parse_snmp_if_mib({"1.3.6.1.2.1.31.1.1.1.1.3": "Et3", "1.3.6.1.2.1.2.2.1.8.3": 1, "1.3.6.1.2.1.2.2.1.7.3": 1,
                                    "1.3.6.1.2.1.31.1.1.1.6.3": 99, "1.3.6.1.2.1.2.2.1.10.3": 7}).records[0]
        self.assertEqual((snmp["name"], snmp["oper"], snmp["counters"]["in_octets"], snmp["counter_widths"]["in_octets"]),
                         ("Ethernet3", "up", 99, 64))
        linux = N.parse_linux_ip_addr('[{"ifname": "eth1", "flags": ["UP"], "operstate": "UP", "mtu": 1500,'
                                      ' "addr_info": [{"local": "10.0.0.2", "prefixlen": 24}]}]').records[0]
        self.assertEqual((linux["name"], linux["admin"], linux["oper"], linux["addresses"]), ("eth1", "up", "up", ["10.0.0.2/24"]))

    def test_interface_parsers_refuse_malformed_documents(self):
        for parser, bad in ((N.parse_eos_interfaces_json, '{"nope": {}}'), (N.parse_eos_interfaces_json, "not json"),
                            (N.parse_openconfig_interfaces, {"interfaces": {}}), (N.parse_snmp_if_mib, "[1, 2]"),
                            (N.parse_linux_ip_addr, '{"ifname": "eth1"}')):
            with self.subTest(f"{parser.__name__} refuses {bad!r}"):
                with self.assertRaises(ValueError):
                    parser(bad)
        with self.subTest("an unrecognized IOS XE header is refused as a partial parse"):
            result = N.parse_iosxe_interfaces_text("Tunnel9 is up (looped), line protocol is up\n")
            self.assertEqual(result.records, [])
            self.assertTrue(result.partial)
        with self.subTest("an EOS row that is not an object is refused as an error"):
            self.assertTrue(N.parse_eos_interfaces_json({"interfaces": {"Ethernet9": "down"}}).partial)


class RoutingNeighborParserTests(SimpleTestCase):
    def test_state_vocabularies_return_their_canonical_states(self):
        self.assertEqual(N.norm_ospf_state("FULL/DR"), "full")
        self.assertEqual(N.norm_ospf_state("2-Way"), "two_way")
        self.assertEqual(N.norm_bgp_state("Established"), "established")

    def test_state_vocabularies_refuse_unknown_states(self):
        with self.subTest("an unknown OSPF state is refused as unknown"):
            self.assertEqual(N.norm_ospf_state("bogus"), "unknown")
        with self.subTest("an unknown BGP state is refused as unknown"):
            self.assertEqual(N.norm_bgp_state(None), "unknown")

    def test_neighbor_parsers_return_canonical_rows(self):
        eos = N.parse_eos_ospf_json({"vrfs": {"default": {"instList": {"1": {"ospfNeighborEntries": [
            {"routerId": "2.2.2.2", "adjacencyState": "full", "interfaceName": "Ethernet1", "interfaceAddress": "10.0.0.2"}]}}}}})
        self.assertEqual([(r["protocol"], r["neighbor"], r["state"], r["interface"]) for r in eos.records],
                         [("ospfv2", "2.2.2.2", "full", "Ethernet1")])
        frr = N.parse_frr_ospf_json({"neighbors": {"3.3.3.3": [{"nbrState": "Full/Backup", "ifaceName": "eth1:10.0.0.1",
                                                                 "ifaceAddress": "10.0.0.3"}]}})
        self.assertEqual((frr.records[0]["state"], frr.records[0]["interface"]), ("full", "eth1"))
        ios = N.parse_iosxe_ospf_text("Neighbor ID     Pri   State           Dead Time   Address         Interface\n"
                                      "4.4.4.4           1   FULL/DR         00:00:35    10.0.1.4        GigabitEthernet2\n")
        self.assertEqual((ios.records[0]["neighbor"], ios.records[0]["state"], ios.expected), ("4.4.4.4", "full", 1))
        bgp = N.parse_eos_bgp_json({"vrfs": {"default": {"peers": {"10.0.0.9": {"peerState": "Established", "asn": "65001",
                                                                             "prefixReceived": 3}}}}})
        self.assertEqual((bgp.records[0]["state"], bgp.records[0]["prefixes_received"]), ("established", 3))
        frr_bgp = N.parse_frr_bgp_json({"ipv4Unicast": {"peers": {"10.0.0.8": {"state": "Active", "remoteAs": 65002, "pfxRcd": 0}}}})
        self.assertEqual((frr_bgp.records[0]["state"], frr_bgp.records[0]["family"]), ("active", "ipv4Unicast"))

    def test_neighbor_parsers_refuse_malformed_documents(self):
        for parser, bad in ((N.parse_eos_ospf_json, {"instList": {}}), (N.parse_frr_ospf_json, "[]"),
                            (N.parse_eos_bgp_json, "[]"), (N.parse_frr_bgp_json, "garbage")):
            with self.subTest(f"{parser.__name__} refuses {bad!r}"):
                with self.assertRaises(ValueError):
                    parser(bad)
        with self.subTest("an IOS XE row the template cannot read is refused as partial"):
            result = N.parse_iosxe_ospf_text("4.4.4.4 1 WEIRD 10.0.1.4\n")
            self.assertEqual((result.records, result.partial), ([], True))


class HistoryMemoryTests(SimpleTestCase):
    def test_histories_return_the_last_recorded_sample_per_subject(self):
        for history in (N.StpHistory(), N.MacHistory(), N.AclHistory()):
            with self.subTest(history=type(history).__name__):
                history.record("S1", "VL10", {"at": T0, "n": 1})
                history.record("S1", "VL10", {"at": T0 + timedelta(seconds=5), "n": 2})
                self.assertEqual(history.previous("S1", "VL10"), {"at": T0 + timedelta(seconds=5), "n": 2})

    def test_histories_refuse_to_leak_samples_across_devices_or_subjects(self):
        for history in (N.StpHistory(), N.MacHistory(), N.AclHistory()):
            with self.subTest(f"{type(history).__name__} refuses an unrecorded device or subject"):
                history.record("S1", "VL10", {"n": 1})
                history.record("S2", "VL20", {"n": 2})
                self.assertIsNone(history.previous("S1", "VL20"))
                self.assertIsNone(history.previous("S3", "VL10"))
                self.assertEqual(history.previous("S2", "VL20"), {"n": 2})


STP_DOC = {"spanningTreeInstances": {"VL10": {
    "protocol": "rapidPvst", "rootBridge": {"priority": 32778, "macAddress": "00:1c:73:00:00:01"},
    "bridge": {"priority": 32778, "macAddress": "00:1c:73:00:00:01"}, "topologyChanges": 3, "timeSinceTopologyChange": 12.5,
    "interfaces": {"Ethernet1": {"state": "forwarding", "role": "designated", "portType": "edge", "bpduGuard": True,
                                 "bpduFilter": False, "loopGuard": False, "bpduReceived": 0, "bpduSent": 10}}}}}


class SwitchingParserTests(SimpleTestCase):
    def test_stp_mac_switchport_and_vlan_parsers_return_canonical_records(self):
        stp = N.parse_eos_stp_json(STP_DOC)
        record = stp.records[0]
        self.assertEqual((record["mode"], record["is_root"], record["topology_changes"], record["ports"][0]["state"]),
                         ("rapidpvst", True, 3, "forwarding"))
        self.assertEqual(record["protection"]["Ethernet1"]["link_type"], "edge")
        self.assertFalse(stp.partial)
        mac = N.parse_eos_mac_json({"unicastTable": {"totalMacAddresses": 1, "tableEntries": [
            {"vlanId": 10, "macAddress": "001c.7300.0002", "interface": "Et2", "entryType": "dynamic"}]}})
        self.assertEqual(mac.records, [{"vlan": "10", "mac": "00:1c:73:00:00:02", "interface": "Ethernet2", "dynamic": True}])
        ports = N.parse_eos_switchport_json({"switchports": {
            "Et1": {"switchportInfo": {"mode": "access", "accessVlanId": 10}},
            "Et2": {"switchportInfo": {"mode": "trunk", "trunkAllowedVlans": "10,20-22", "trunkingNativeVlanId": 1}}}})
        self.assertEqual([(r["name"], r["access_vlan"], r["allowed_vlans"], r["native_vlan"]) for r in ports.records],
                         [("Ethernet1", 10, [], None), ("Ethernet2", None, [10, 20, 21, 22], 1)])
        self.assertEqual(N.parse_vlan_list("NONE"), [])
        self.assertEqual(len(N.parse_vlan_list("ALL")), N.L2_MAX_VLAN)

    def test_switching_parsers_refuse_malformed_documents(self):
        for parser, bad in ((N.parse_eos_stp_json, {"spanningTree": {}}), (N.parse_eos_mac_json, {"unicastTable": {}}),
                            (N.parse_eos_switchport_json, "[]")):
            with self.subTest(f"{parser.__name__} refuses {bad!r}"):
                with self.assertRaises(ValueError):
                    parser(bad)
        for bad in ("", "10,abc", "0-5", "4000-4095"):
            with self.subTest(f"VLAN list {bad!r} is refused"):
                with self.assertRaises(ValueError):
                    N.parse_vlan_list(bad)
        with self.subTest("an STP port row with a non-boolean guard is refused as partial"):
            doc = {"spanningTreeInstances": {"VL10": {**STP_DOC["spanningTreeInstances"]["VL10"], "interfaces": {
                "Ethernet1": {"state": "forwarding", "role": "designated", "bpduGuard": "false"}}}}}
            self.assertTrue(N.parse_eos_stp_json(doc).partial)
        with self.subTest("a duplicate VLAN/MAC entry is refused as contradictory"):
            row = {"vlanId": 10, "macAddress": "001c.7300.0002", "interface": "Et2"}
            result = N.parse_eos_mac_json({"unicastTable": {"tableEntries": [row, dict(row, interface="Et3")]}})
            self.assertEqual((len(result.records), result.partial), (1, True))
        with self.subTest("an access port without a valid VLAN is refused as uncertain"):
            result = N.parse_eos_switchport_json({"switchports": {"Et1": {"switchportInfo": {"mode": "access", "accessVlanId": 5000}}}})
            self.assertEqual(result.records[0]["uncertain"], ["access_vlan_missing_or_invalid"])


class ForwardingParserTests(SimpleTestCase):
    def test_route_and_neighbor_parsers_return_canonical_rows(self):
        eos = N.parse_eos_route_json({"vrfs": {"default": {"routes": {"10.1.0.0/24": {
            "routeType": "OSPF intra", "metric": 20, "preference": 110,
            "vias": [{"nexthopAddr": "10.0.0.2", "interface": "Ethernet1"}]}}}}}, "ipv4")
        self.assertEqual([(r["prefix"], r["protocol"], r["next_hops"][0]["address"]) for r in eos.records], [("10.1.0.0/24", "ospf", "10.0.0.2")])
        linux = N.parse_linux_ip_route('[{"dst": "default", "gateway": "10.0.0.1", "dev": "eth0", "protocol": "static"},'
                                       ' {"dst": "192.0.2.0/24", "type": "blackhole"}]', "ipv4")
        self.assertEqual([(r["prefix"], r["discard"]) for r in linux.records], [("0.0.0.0/0", None), ("192.0.2.0/24", "blackhole")])
        nd = N.parse_eos_neighbors_json({"totalEntries": 1, "ipV4Neighbors": [
            {"address": "10.0.0.2", "hwAddress": "00:1c:73:00:00:02", "interface": "Ethernet1, Port-Channel1", "state": "reachable", "age": 30}]})
        self.assertEqual((nd.records[0]["interface"], nd.records[0]["state"], nd.partial), ("Ethernet1", "REACHABLE", False))
        neigh = N.parse_linux_ip_neigh('[{"dst": "fe80::1", "dev": "eth1", "lladdr": "52:54:00:00:00:01", "state": ["STALE"], "router": true}]')
        self.assertEqual((neigh.records[0]["family"], neigh.records[0]["router"]), ("ipv6", True))

    def test_forwarding_parsers_refuse_malformed_documents(self):
        for parser, bad in ((N.parse_eos_route_json, {"routes": {}}), (N.parse_linux_ip_route, "{}"),
                            (N.parse_eos_neighbors_json, {"neighbors": []}), (N.parse_linux_ip_neigh, "{}")):
            with self.subTest(f"{parser.__name__} refuses {bad!r}"):
                with self.assertRaises(ValueError):
                    parser(bad)
        with self.subTest("a default route without a family is refused, never assumed IPv4"):
            self.assertTrue(N.parse_linux_ip_route('[{"dst": "default", "gateway": "10.0.0.1"}]').partial)
        with self.subTest("an IPv6 route is refused from an IPv4 table"):
            result = N.parse_eos_route_json({"vrfs": {"default": {"routes": {"2001:db8::/64": {"vias": []}}}}}, "ipv4")
            self.assertEqual((result.records, result.partial), ([], True))
        with self.subTest("an unknown neighbor state is refused"):
            self.assertTrue(N.parse_eos_neighbors_json({"ipV4Neighbors": [{"address": "10.0.0.2", "state": "maybe"}]}).partial)
            self.assertTrue(N.parse_linux_ip_neigh('[{"dst": "10.0.0.3", "state": ["WEIRD"]}]').partial)


class AclParserTests(SimpleTestCase):
    def test_acl_parsers_return_rules_and_attachments(self):
        self.assertEqual(N.parse_acl_rule_text("permit tcp 10.0.0.0/24 host 10.1.1.1 eq 443 log"),
                         {"action": "permit", "proto": "tcp", "port": 443, "src": "10.0.0.0/24", "dst": "10.1.1.1/32"})
        acl = N.parse_eos_acl_json({"aclList": [{"name": "EDGE", "sequence": [
            {"sequenceNumber": 20, "text": "deny ip any any", "counterData": {"matchedPackets": 4}},
            {"sequenceNumber": 10, "text": "permit udp any any eq 53"},
            {"sequenceNumber": 5, "text": "remark dns first"}]}]})
        self.assertEqual([(r["seq"], r["action"], r["hits"]) for r in acl.records[0]["rules"]], [(10, "permit", None), (20, "deny", 4)])
        summary = N.parse_eos_acl_summary_json({"aclList": [{"name": "EDGE", "configuredIngressIntfs": ["Ethernet1", "Ethernet2"],
                                                             "activeIngressIntfs": ["Ethernet1"]}]})
        self.assertEqual([(r["interface"], r["direction"], r["uncertain"]) for r in summary.records],
                         [("Ethernet1", "in", []), ("Ethernet2", "in", ["configured_not_active"])])

    def test_acl_parsers_refuse_unsupported_or_malformed_input(self):
        for text, reason in (("permit", "unrecognised_rule_syntax"), ("permit gre any any", "unsupported_protocol:gre"),
                             ("permit tcp any eq 22 any", "source_port_match"), ("permit tcp any any range 1 2", "unsupported_port_match"),
                             ("permit ip any any established", "unsupported_option:established")):
            with self.subTest(f"rule {text!r} is refused"):
                self.assertEqual(N.parse_acl_rule_text(text)["unsupported"], reason)
        for parser in (N.parse_eos_acl_json, N.parse_eos_acl_summary_json):
            with self.subTest(f"{parser.__name__} refuses a document without aclList"):
                with self.assertRaises(ValueError):
                    parser({"acls": []})
        with self.subTest("a duplicate ACL name and a duplicate sequence are refused"):
            result = N.parse_eos_acl_json({"aclList": [{"name": "A", "sequence": [{"sequenceNumber": 10, "text": "deny ip any any"},
                                                                                  {"sequenceNumber": 10, "text": "permit ip any any"}]},
                                                       {"name": "A", "sequence": []}]})
            self.assertTrue(result.partial)
            self.assertEqual(len(result.records[0]["rules"]), 1)
        with self.subTest("a malformed interface list is refused"):
            self.assertTrue(N.parse_eos_acl_summary_json({"aclList": [{"name": "A", "configuredIngressIntfs": "Ethernet1"}]}).partial)


class DnsValidationTests(SimpleTestCase):
    def test_dns_names_servers_and_engine_keys_return_canonical_values(self):
        self.assertEqual(N.validate_dns_name("WWW.Example.COM."), ("www.example.com", ""))
        self.assertEqual(N.validate_dns_server("2001:DB8::53"), ("2001:db8::53", ""))
        self.assertEqual(N.validate_dns_server("ns1.example.net"), ("ns1.example.net", ""))
        self.assertEqual(N.dns_engine_key({"op": "query", "name": "www.example.com", "server": "10.0.0.53"}),
                         ("dns.query", "www.example.com/10.0.0.53"))
        self.assertEqual(N.dns_engine_key({"op": "soa", "zone": "example.com", "server": "10.0.0.53"}), ("dns.soa", "example.com/10.0.0.53"))
        self.assertEqual(N.dns_engine_key({"op": "resolver_config"}), ("dns.resolver_config", "resolv"))

    def test_invalid_dns_names_and_servers_are_refused(self):
        for bad in ("", " padded", "-bad.example", "a" * 64 + ".example", "*.example.com", 42):
            with self.subTest(f"name {bad!r} is refused"):
                name, error = N.validate_dns_name(bad)
                self.assertIsNone(name)
                self.assertTrue(error)
        for bad in ("224.0.0.1", "0.0.0.0", "255.255.255.255", "", "bad_label-.example"):
            with self.subTest(f"server {bad!r} is refused"):
                self.assertIsNone(N.validate_dns_server(bad)[0])
        with self.subTest("a query without a subject is refused an invented one"):
            self.assertEqual(N.dns_engine_key({"op": "query"}), ("dns.query", "/"))


def _obs(key, value, device="S1", interface="Ethernet1"):
    return N.make_observation(key, value, device=device, evidence=EVIDENCE, observed_at=T0, interface=interface, now=T0)


class PlausibilityAndAgreementTests(SimpleTestCase):
    def test_consistency_and_raw_text_checks_return_nothing_for_plausible_data(self):
        self.assertEqual(N.consistency_problems([{"name": "Ethernet1", "mtu": 1500, "admin": "up", "oper": "up", "counters": {"in_octets": 3}}]), [])
        parsed = N.parse_iosxe_interfaces_text(IOS_TEXT)
        self.assertEqual(N.ios_raw_text_check(IOS_TEXT, parsed), [])

    def test_consistency_and_raw_text_checks_refuse_implausible_telemetry(self):
        with self.subTest("an impossible MTU, oper up while admin down and a negative counter are refused"):
            problems = N.consistency_problems([{"name": "Ethernet1", "mtu": 20, "admin": "down", "oper": "up", "counters": {"in_errors": -1}}])
            self.assertEqual(problems, ["IMPLAUSIBLE_MTU:Ethernet1:20", "OPER_UP_WHILE_ADMIN_DOWN:Ethernet1", "NEGATIVE_COUNTER:Ethernet1:in_errors"])
        with self.subTest("an interface the template dropped and a contradicting oper state are refused"):
            parsed = N.ParseResult(records=[{"name": "GigabitEthernet2", "oper": "down"}])
            raw = IOS_TEXT + "GigabitEthernet3 is up (weird), line protocol is up\n"
            self.assertEqual(N.ios_raw_text_check(raw, parsed), ["MISSING_INTERFACE:GigabitEthernet3", "OPER_STATE_MISMATCH:GigabitEthernet2"])

    def test_compare_and_mark_return_agreement_for_identical_renderings(self):
        a, b = [_obs("interface.oper_state", "up")], [_obs("interface.oper_state", "up")]
        comparison = N.compare_observations(a, b)
        self.assertEqual((len(comparison["agreed"]), comparison["disagreements"]), (1, []))
        self.assertEqual(N.mark_untrusted(a, comparison)[0]["quality"], a[0]["quality"])

    def test_compare_and_mark_refuse_to_trust_disagreeing_renderings(self):
        a = [_obs("interface.oper_state", "up"), _obs("interface.mtu", 1500)]
        b = [_obs("interface.oper_state", "down"), _obs("interface.speed", 10**9)]
        with self.subTest("a disagreement and one-sided keys are refused as agreement"):
            comparison = N.compare_observations(a, b)
            self.assertEqual([d["key"] for d in comparison["disagreements"]], ["interface.oper_state"])
            self.assertEqual(([o["key"] for o in comparison["only_a"]], [o["key"] for o in comparison["only_b"]]),
                             (["interface.mtu"], ["interface.speed"]))
        with self.subTest("the disagreeing observation is refused trust"):
            marked = N.mark_untrusted(a, comparison)
            self.assertEqual((marked[0]["quality"], marked[0]["confidence"]), (N.Quality.UNTRUSTED_PARSE, 0.1))
            self.assertIn("PARSER_DISAGREEMENT", marked[0]["flags"])
            self.assertEqual(N.trusted_value(marked[0]), N.UNKNOWN)
            self.assertEqual(marked[1]["quality"], a[1]["quality"])


class SnmpPollTests(SimpleTestCase):
    def test_snmp_poll_returns_rates_after_two_polls(self):
        tracker = N.CounterTracker()
        rec = {"name": "Ethernet3", "admin": "up", "oper": "up", "mtu": 1500, "speed_bps": 10**9, "counters": {"in_octets": 1000},
               "counter_widths": {"in_octets": 64}}
        N.normalize_snmp_poll([rec], device="S1", evidence={**EVIDENCE, "collected_at": "2026-11-09T12:00:00Z"}, tracker=tracker, now=T0)
        out = N.normalize_snmp_poll([{**rec, "counters": {"in_octets": 2000}}], device="S1", tracker=tracker, now=T0 + timedelta(seconds=10),
                                    evidence={**EVIDENCE, "collected_at": "2026-11-09T12:00:10Z"})
        rate = next(o for o in out["observations"] if o["key"] == "interface.rate.in_octets")
        self.assertEqual(rate["value"], 800.0)

    def test_snmp_poll_refuses_a_rate_across_a_reset_and_flags_a_restart(self):
        tracker = N.CounterTracker()
        rec = {"name": "Ethernet3", "admin": "up", "oper": "up", "counters": {"in_octets": 5000}, "counter_widths": {"in_octets": 64}}
        N.normalize_snmp_poll([rec], device="S1", evidence={**EVIDENCE, "collected_at": "2026-11-09T12:00:00Z"}, tracker=tracker, now=T0,
                              sys_uptime_ticks=100000)
        with self.subTest("a counter decrease is refused a rate: it is a reset event"):
            out = N.normalize_snmp_poll([{**rec, "counters": {"in_octets": 10}}], device="S1", tracker=tracker, now=T0 + timedelta(seconds=10),
                                        evidence={**EVIDENCE, "collected_at": "2026-11-09T12:00:10Z"}, sys_uptime_ticks=500)
            keys = {o["key"]: o for o in out["observations"]}
            self.assertNotIn("interface.rate.in_octets", keys)
            self.assertEqual(keys["interface.counter_event"]["value"], "reset")
            self.assertIn("device.restart_suspected", keys)


class FlowAndCaptureTests(SimpleTestCase):
    def test_flow_selector_and_capture_bounds_accept_a_scoped_capture(self):
        record = {"proto": 6, "sport": 51000, "dport": 443, "src": "10.0.0.5", "dst": "192.0.2.10"}
        self.assertTrue(N.flow_matches(record, {"protocol": 6, "dst_ports": [443], "src_prefixes": ["10.0.0.0/24"], "dst_prefixes": ["192.0.2.0/24"]}))
        self.assertTrue(N.flow_matches(record, {}))
        meta = {"capture_id": "cap-1", "interface": "Ethernet1", "filter": "tcp port 443", "snaplen": 96, "packets": 10, "bytes": 960,
                "duration_s": 5, "started_at": "2026-11-09T12:00:00Z", "summary": {"tcp_resets": 2}}
        self.assertEqual(N.capture_bound_violations(meta), [])
        out = N.normalize_capture_metadata(meta, device="S1", evidence=EVIDENCE, now=T0)
        self.assertEqual([o["key"] for o in out["observations"]], ["capture.metadata", "capture.summary.tcp_resets"])
        self.assertFalse(out["observations"][0]["value"]["payload_included"])

    def test_flow_selector_and_capture_bounds_refuse_out_of_scope_input(self):
        record = {"proto": 17, "sport": 53, "dport": 5353, "src": "not-an-ip", "dst": "192.0.2.10"}
        for selector in ({"protocol": 6}, {"dst_ports": [53]}, {"src_ports": [123]}, {"src_prefixes": ["10.0.0.0/8"]},
                         {"dst_prefixes": ["198.51.100.0/24"]}):
            with self.subTest(f"selector {selector} refuses the record"):
                self.assertFalse(N.flow_matches(record, selector))
        meta = {"interface": "Ethernet1", "snaplen": 65535, "packets": 10**7, "bytes": 10**12, "duration_s": 10**5, "payload": "deadbeef"}
        with self.subTest("an unscoped, payload-bearing, unbounded capture is refused"):
            self.assertEqual(N.capture_bound_violations(meta), ["UNSCOPED_CAPTURE_NO_FILTER", "SNAPLEN_EXCEEDS_HEADER_ONLY_BOUND",
                                                                 "PACKET_COUNT_EXCEEDS_BOUND", "DURATION_EXCEEDS_BOUND", "BYTES_EXCEED_BOUND"])
            out = N.normalize_capture_metadata(meta, device="S1", evidence=EVIDENCE, now=T0)
            self.assertEqual((out["observations"], out["dropped_fields"], out["missing"][0]["reason"]),
                             ([], ["payload"], N.Missing.UNAUTHORIZED_CAPTURE))


class SnapshotIntentAndRejectTests(SimpleTestCase):
    def test_snapshot_and_intent_return_metadata_only_observations(self):
        out = N.normalize_snapshot("running-config", "hostname S1\nusername a secret 0 pw\n", device="S1", evidence=EVIDENCE,
                                   revision="r1", url="https://nmas.example/snap/1", now=T0)
        value = out["observations"][0]["value"]
        self.assertEqual((value["revision"], value["redactions"], value["operator_url"]), ("r1", 1, "https://nmas.example/snap/1"))
        self.assertNotIn("pw", out["redacted_text"])
        self.assertNotIn("hostname", str(value))
        intent = N.normalize_intent("S1", {"interfaces": {"Et1": {"mtu": 9214, "admin": "enabled", "addresses": ["10.0.0.1/31"]}},
                                           "neighbors": [{"protocol": "ospf", "neighbor": "2.2.2.2", "interface": "Et1"}]},
                                    evidence=EVIDENCE, now=T0, url="https://netbox.example/dcim/devices/1/")
        keys = sorted((o["key"], o["value"]) for o in intent["observations"])
        self.assertEqual(keys, [("intent.interface.address", "10.0.0.1/31"), ("intent.interface.admin_state", "up"),
                                ("intent.interface.mtu", 9214), ("intent.routing.ospf.neighbor", "expected")])
        self.assertTrue(all(o["evidence_class"] == N.EvidenceClass.INTENT for o in intent["observations"]))

    def test_snapshot_and_intent_refuse_to_invent_urls_or_addresses(self):
        with self.subTest("a snapshot without a URL is refused an invented one"):
            out = N.normalize_snapshot("running-config", {"k": "v"}, device="S1", evidence=EVIDENCE, now=T0)
            self.assertIsNone(out["observations"][0]["value"]["operator_url"])
            self.assertIn("NO_OPERATOR_URL", out["observations"][0]["flags"])
        with self.subTest("a malformed intent address is refused"):
            intent = N.normalize_intent("S1", {"interfaces": {"Et1": {"addresses": ["10.0.0.999/31"]}}}, evidence=EVIDENCE, now=T0)
            self.assertEqual(intent["observations"], [])

    def test_reject_all_helpers_each_builds_one_gap_per_engine_key(self):
        phy = N.phy_reject_all("UNSUPPORTED", "no optics API", device="S1", evidence=EVIDENCE, now=T0, interfaces=["Ethernet1"])
        self.assertEqual([m["extra"]["engine_key"] for m in phy["missing"]], list(N.PHY_ENGINE_KEYS))
        proto = N.proto_reject_all("UNSUPPORTED", "no API", device="S1", evidence=EVIDENCE, now=T0, request={"protocol": "ospf", "peer": "2.2.2.2"})
        self.assertEqual([(m["extra"]["engine_key"], m["extra"].get("subject")) for m in proto["missing"]],
                         [("capability.protocol", "ospf"), ("protocol.config", "ospf"), ("routing.neighbor.detail", "2.2.2.2")])

    def test_reject_all_helpers_refuse_every_key_never_an_observation(self):
        with self.subTest("a document-level refusal without interfaces is refused for every key"):
            phy = N.phy_reject_all("PARSE_FAILED", "x" * 500, device="S1", evidence=EVIDENCE, now=T0)
            self.assertEqual((phy["observations"], len(phy["missing"]), len(phy["missing"][0]["detail"])), ([], 3, 200))
        with self.subTest("a protocol refusal for an empty request is refused with no subject"):
            proto = N.proto_reject_all("PARSE_FAILED", "bad", device="S1", evidence=EVIDENCE, now=T0, request={})
            self.assertEqual(proto["observations"], [])
            self.assertTrue(all("subject" not in m["extra"] for m in proto["missing"]))

    def test_scrub_protocol_secrets_returns_a_redacted_copy(self):
        node = {"neighbor": "2.2.2.2", "authentication_key": "s3cr3t", "key_id": 7, "notes": ["password = hunter2"]}
        scrubbed, count = N.scrub_protocol_secrets(node)
        self.assertEqual((scrubbed["authentication_key"], scrubbed["key_id"], count), (N.REDACTED, 7, 2))
        self.assertNotIn("hunter2", str(scrubbed))
        self.assertEqual(node["authentication_key"], "s3cr3t")

    def test_scrub_protocol_secrets_refuses_nothing_secret_free(self):
        with self.subTest("a secret-free or scalar node is refused any redaction"):
            self.assertEqual(N.scrub_protocol_secrets({"neighbor": "2.2.2.2", "state": "full"}), ({"neighbor": "2.2.2.2", "state": "full"}, 0))
            self.assertEqual(N.scrub_protocol_secrets(42), (42, 0))


class AclAttachmentTests(SimpleTestCase):
    def test_acl_attachment_returns_one_observation_per_binding(self):
        out = N.normalize_acl_attachment({"aclList": [{"name": "EDGE", "configuredIngressIntfs": ["Ethernet1"], "activeIngressIntfs": ["Ethernet1"]}]},
                                         platform="ceos", os_version="4.36.2F", device="S1", evidence=EVIDENCE, now=T0, observed_at=T0)
        self.assertEqual([(o["value"]["acl"], o["value"]["interface"], o["value"]["direction"]) for o in out["observations"]],
                         [("EDGE", "Ethernet1", "in")])

    def test_acl_attachment_refuses_an_unreported_or_unsupported_binding(self):
        with self.subTest("zero attachments is refused as an EMPTY gap"):
            out = N.normalize_acl_attachment({"aclList": []}, platform="ceos", os_version="4.36.2F", device="S1", evidence=EVIDENCE, now=T0)
            self.assertEqual((out["observations"], out["missing"][0]["reason"]), ([], N.Missing.EMPTY))
        with self.subTest("an unsupported platform is refused a parser"):
            out = N.normalize_acl_attachment({"aclList": []}, platform="iosxe", os_version="17.6.1", device="S1", evidence=EVIDENCE, now=T0)
            self.assertEqual(out["missing"][0]["reason"], N.Missing.PARSER_UNAVAILABLE)


DNS_QUERY = {"op": "query", "name": "www.example.com", "qtype": "A", "server": "10.0.0.53", "transport": "udp", "role": "recursive"}


class DnsResponseTests(SimpleTestCase):
    def test_parse_dns_response_returns_the_answer_to_the_question_asked(self):
        doc = {"schema": N.DNS_SCHEMA, "op": "query", "status": "response", "rcode": "NOERROR", "name": "www.example.com", "qtype": "A",
               "server": "10.0.0.53", "transport": "udp", "flags": {"rd": True, "ra": True},
               "answers": [{"name": "www.example.com", "type": "CNAME", "ttl": 60, "data": "web.example.com"},
                           {"name": "web.example.com", "type": "A", "ttl": 30, "data": "192.0.2.10"}]}
        result = N.parse_dns_response(doc, request=DNS_QUERY)
        value = result.records[0]["value"]
        self.assertEqual((value["answers"], value["cname_chain"], value["ttl"], value["negative"]), (["192.0.2.10"], ["web.example.com"], 30, False))
        resolver = N.parse_dns_response({"schema": N.DNS_SCHEMA, "op": "resolver_config", "nameservers": ["10.0.0.53"], "search": ["Example.com"]},
                                        request={"op": "resolver_config"})
        self.assertEqual(resolver.records[0]["value"], {"nameservers": ["10.0.0.53"], "search": ["example.com"]})

    def test_parse_dns_response_refuses_documents_for_another_question(self):
        base = {"schema": N.DNS_SCHEMA, "op": "query", "status": "response", "rcode": "NOERROR", "name": "www.example.com", "qtype": "A",
                "server": "10.0.0.53", "answers": []}
        with self.subTest("a response without its request is refused"):
            with self.assertRaises(ValueError):
                N.parse_dns_response(base)
        with self.subTest("a document of another schema or op is refused"):
            with self.assertRaises(ValueError):
                N.parse_dns_response({**base, "schema": "other/1"}, request=DNS_QUERY)
        for change, why in (({"server": "10.9.9.9"}, "another server"), ({"rcode": "MAYBE"}, "an invented rcode"),
                            ({"answers": [{"name": "www.example.com", "type": "A", "ttl": -1, "data": "192.0.2.1"}]}, "a negative TTL"),
                            ({"flags": {"aa": "yes"}}, "a non-boolean flag")):
            with self.subTest(f"{why} is refused as untrusted"):
                result = N.parse_dns_response({**base, **change}, request=DNS_QUERY)
                self.assertTrue(result.partial, result)
        with self.subTest("a timeout is refused as no response"):
            result = N.parse_dns_response({"schema": N.DNS_SCHEMA, "op": "query", "status": "timeout", "error": "5s"}, request=DNS_QUERY)
            self.assertEqual(result.records[0]["no_response"], "timeout")
