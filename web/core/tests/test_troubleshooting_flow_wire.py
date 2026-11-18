"""NetFlow v9 / IPFIX wire decoding (adapters.flow_wire) with generated binary datagrams.  Spec IDs: UT-017 (sampling retained), UT-022 (bounds)."""

from __future__ import annotations

import ipaddress
import json
import random
import struct
import unittest
from datetime import datetime, timedelta, timezone

from core.services.troubleshooting import collectors as c
from core.services.troubleshooting.adapters import flow_wire as fw

T0 = datetime(2026, 11, 9, 12, 0, 0, tzinfo=timezone.utc)
EPOCH = int(T0.timestamp())
F_V4 = [(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (1, 4), (2, 4), (21, 4), (22, 4)]       # v9 5-tuple + sysUptime times


def ip4(a):
    return ipaddress.IPv4Address(a).packed


def v9_template(tid, fields):
    body = struct.pack("!HH", tid, len(fields)) + b"".join(struct.pack("!HH", i, ln) for i, ln in fields)
    return struct.pack("!HH", 0, 4 + len(body)) + body


def v9_options(tid, scope_len, opt_fields, scope_type=1):
    body = struct.pack("!HHH", tid, 4, 4 * len(opt_fields)) + struct.pack("!HH", scope_type, scope_len) + b"".join(struct.pack("!HH", i, ln) for i, ln in opt_fields)
    return struct.pack("!HH", 1, 4 + len(body)) + body


def dset(tid, payload, pad=True):
    n = 4 + len(payload)
    padding = b"\0" * ((-n) % 4) if pad else b""
    return struct.pack("!HH", tid, n + len(padding)) + payload + padding


def v9_rec(src, dst, sport, dport, proto, octets, pkts, last_ms=9000, first_ms=8000):
    return ip4(src) + ip4(dst) + struct.pack("!HHBIIII", sport, dport, proto, octets, pkts, last_ms, first_ms)


def v9(sets, seq=1, domain=0, uptime=10_000, count=None):
    return struct.pack("!HHIIII", 9, count if count is not None else len(sets), uptime, EPOCH, seq, domain) + b"".join(sets)


def ipfix(sets, seq=0, domain=7, length=None):
    body = b"".join(sets)
    return struct.pack("!HHIII", 10, length if length is not None else 16 + len(body), EPOCH, seq, domain) + body


def ipfix_template(tid, fields, setid=2):
    body = struct.pack("!HH", tid, len(fields))
    for f in fields:
        ie, ln = f[0], f[1]
        ent = f[2] if len(f) > 2 else None
        body += struct.pack("!HH", ie | (0x8000 if ent else 0), ln) + (struct.pack("!I", ent) if ent else b"")
    return struct.pack("!HH", setid, 4 + len(body)) + body


IPFIX_F = [(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (85, 8), (86, 8), (153, 8), (152, 8)]


def ipfix_rec(src, dst, sport, dport, proto, octets, pkts, end_ms=EPOCH * 1000, start_ms=EPOCH * 1000 - 500):
    return ip4(src) + ip4(dst) + struct.pack("!HHBQQQQ", sport, dport, proto, octets, pkts, end_ms, start_ms)


def decoder(**kw):
    return fw.FlowWireDecoder(fw.WireConfig(**kw), clock=lambda: T0)


class V9Decode(unittest.TestCase):
    def test_template_then_data_decodes_fields_and_times(self):
        d = decoder()
        r1 = d.decode(v9([v9_template(256, F_V4)], seq=1), "192.0.2.1", "R1")
        self.assertEqual(r1["templates_learned"], 1)
        pkt = v9([dset(256, v9_rec("10.1.1.5", "10.2.2.9", 40000, 443, 6, 1500, 2))], seq=2)
        r2 = d.decode(pkt, "192.0.2.1", "R1")
        rec = r2["records"][0]
        self.assertEqual((rec["src"], rec["dst"], rec["sport"], rec["dport"], rec["proto"], rec["bytes"], rec["packets"], rec["exporter"]),
                         ("10.1.1.5", "10.2.2.9", 40000, 443, 6, 1500, 2, "R1"))
        self.assertEqual(rec["last"], (T0 - timedelta(seconds=1)).isoformat().replace("+00:00", "Z") if rec["last"].endswith("Z") else (T0 - timedelta(seconds=1)).isoformat())
        self.assertEqual(rec["wire"]["time_source"], "sysUpTime")
        self.assertIsNone(rec["sampling_rate"])
        self.assertIn("SAMPLING_RATE_UNKNOWN", rec["wire"]["flags"])

    def test_padding_and_multiple_records(self):
        d = decoder()
        d.decode(v9([v9_template(256, F_V4)], seq=1), "a", "R1")
        recs = b"".join(v9_rec("10.1.1.5", "10.2.2.9", 1000 + i, 80, 6, 100, 1) for i in range(3))
        res = d.decode(v9([dset(256, recs + b"\0\0")], seq=2), "a", "R1")      # 2 bytes of padding < one record
        self.assertEqual(len(res["records"]), 3)

    def test_ipv6_and_missing_mandatory_field_dropped(self):
        d = decoder()
        d.decode(v9([v9_template(300, [(27, 16), (28, 16), (4, 1), (1, 4), (2, 4)]), v9_template(301, [(7, 2), (11, 2)])], seq=1), "a", "R1")
        pay = ipaddress.IPv6Address("2001:db8::1").packed + ipaddress.IPv6Address("2001:db8:0:1::2").packed + struct.pack("!BII", 17, 90, 1)
        res = d.decode(v9([dset(300, pay), dset(301, struct.pack("!HH", 1, 2))], seq=2), "a", "R1")
        self.assertEqual(res["records"][0]["src"], "2001:db8::1")
        self.assertEqual(res["records"][0]["wire"]["time_source"], "export_time")
        self.assertEqual(res["event_counts"][fw.Event.INCOMPLETE_RECORD], 1)


class IpfixDecode(unittest.TestCase):
    def test_ipfix_absolute_times_enterprise_and_variable_length(self):
        d = decoder()
        fields = [(8, 4), (12, 4), (4, 1), (85, 8), (86, 8), (153, 8), (999, 4, 29305), (96, 0xFFFF)]
        d.decode(ipfix([ipfix_template(400, fields)], seq=0), "a", "R1")
        pay = ip4("10.1.1.5") + ip4("10.2.2.9") + struct.pack("!BQQQ", 6, 4000, 4, EPOCH * 1000) + b"\xde\xad\xbe\xef" + b"\x03abc"
        res = d.decode(ipfix([dset(400, pay, pad=False)], seq=0), "a", "R1")
        rec = res["records"][0]
        self.assertEqual((rec["bytes"], rec["packets"], rec["wire"]["time_source"]), (4000, 4, "flowEndMilliseconds"))
        long_pay = pay[:-4] + b"\xff" + struct.pack("!H", 300) + b"x" * 300       # 3-byte variable length form
        res = d.decode(ipfix([dset(400, long_pay, pad=False)], seq=1), "a", "R1")
        self.assertEqual(len(res["records"]), 1)

    def test_withdrawal_and_redefinition(self):
        d = decoder()
        d.decode(ipfix([ipfix_template(256, IPFIX_F)], seq=0), "a", "R1")
        res = d.decode(ipfix([ipfix_template(256, IPFIX_F[:6])], seq=0), "a", "R1")
        self.assertEqual(res["event_counts"][fw.Event.TEMPLATE_CHANGED], 1)
        withdraw = struct.pack("!HHHH", 2, 8, 256, 0)
        res = d.decode(ipfix([withdraw], seq=0), "a", "R1")
        self.assertEqual(res["event_counts"][fw.Event.TEMPLATE_WITHDRAWN], 1)
        res = d.decode(ipfix([dset(256, b"\0" * 8)], seq=0), "a", "R1")
        self.assertEqual(res["event_counts"][fw.Event.UNKNOWN_TEMPLATE], 1)


class TemplateScoping(unittest.TestCase):
    def test_exporters_and_domains_do_not_share_templates(self):
        d = decoder()
        d.decode(v9([v9_template(256, F_V4)], seq=1, domain=0), "192.0.2.1", "R1")
        data = v9([dset(256, v9_rec("10.1.1.5", "10.2.2.9", 1, 80, 6, 10, 1))], seq=2)
        other_exporter = d.decode(data, "192.0.2.2", "R2")
        self.assertEqual(other_exporter["event_counts"].get(fw.Event.UNKNOWN_TEMPLATE), 1)
        other_domain = d.decode(v9([dset(256, v9_rec("10.1.1.5", "10.2.2.9", 1, 80, 6, 10, 1))], seq=2, domain=5), "192.0.2.1", "R1")
        self.assertEqual(other_domain["event_counts"].get(fw.Event.UNKNOWN_TEMPLATE), 1)
        self.assertEqual(len(d.decode(data, "192.0.2.1", "R1")["records"]), 1)

    def test_same_template_id_different_layout_per_exporter(self):
        d = decoder()
        d.decode(v9([v9_template(256, F_V4)], seq=1), "e1", "R1")
        d.decode(v9([v9_template(256, [(8, 4), (12, 4), (4, 1), (1, 4), (2, 4)])], seq=1), "e2", "R2")
        a = d.decode(v9([dset(256, v9_rec("10.1.1.5", "10.2.2.9", 1, 80, 6, 10, 1))], seq=2), "e1", "R1")["records"][0]
        b = d.decode(v9([dset(256, ip4("10.1.1.5") + ip4("10.2.2.9") + struct.pack("!BII", 17, 99, 3))], seq=2), "e2", "R2")["records"][0]
        self.assertEqual((a["proto"], a["bytes"], b["proto"], b["bytes"]), (6, 10, 17, 99))

    def test_template_expiry_drops_data_without_guessing(self):
        d = decoder(template_ttl_s=60)
        d.decode(v9([v9_template(256, F_V4)], seq=1), "a", "R1", received_at=T0)
        pkt = v9([dset(256, v9_rec("10.1.1.5", "10.2.2.9", 1, 80, 6, 10, 1))], seq=2)
        res = d.decode(pkt, "a", "R1", received_at=T0 + timedelta(seconds=61))
        self.assertEqual((res["records"], res["event_counts"][fw.Event.TEMPLATE_EXPIRED]), ([], 1))
        res = d.decode(v9([dset(256, v9_rec("10.1.1.5", "10.2.2.9", 1, 80, 6, 10, 1))], seq=3), "a", "R1", received_at=T0 + timedelta(seconds=62))
        self.assertEqual(res["event_counts"][fw.Event.UNKNOWN_TEMPLATE], 1)

    def test_refresh_keeps_template_alive(self):
        d = decoder(template_ttl_s=60)
        d.decode(v9([v9_template(256, F_V4)], seq=1), "a", "R1", received_at=T0)
        d.decode(v9([v9_template(256, F_V4)], seq=2), "a", "R1", received_at=T0 + timedelta(seconds=50))
        res = d.decode(v9([dset(256, v9_rec("10.1.1.5", "10.2.2.9", 1, 80, 6, 10, 1))], seq=3), "a", "R1", received_at=T0 + timedelta(seconds=100))
        self.assertEqual(len(res["records"]), 1)

    def test_v9_restart_flushes_templates(self):
        d = decoder()
        d.decode(v9([v9_template(256, F_V4)], seq=100, uptime=500_000), "a", "R1")
        res = d.decode(v9([dset(256, v9_rec("10.1.1.5", "10.2.2.9", 1, 80, 6, 10, 1))], seq=0, uptime=2_000), "a", "R1")
        self.assertEqual(res["event_counts"][fw.Event.EXPORTER_RESTART], 1)
        self.assertEqual(res["event_counts"][fw.Event.UNKNOWN_TEMPLATE], 1)
        self.assertEqual(res["records"], [])

    def test_ipfix_sequence_reset_is_restart(self):
        d = decoder()
        d.decode(ipfix([ipfix_template(256, IPFIX_F)], seq=5000), "a", "R1")
        res = d.decode(ipfix([dset(256, ipfix_rec("10.1.1.5", "10.2.2.9", 1, 80, 6, 10, 1))], seq=0), "a", "R1")
        self.assertEqual(res["event_counts"][fw.Event.EXPORTER_RESTART], 1)
        self.assertEqual(res["records"], [])


class Sequence(unittest.TestCase):
    def test_v9_gap_counts_export_packets(self):
        d = decoder()
        d.decode(v9([v9_template(256, F_V4)], seq=10), "a", "R1")
        res = d.decode(v9([dset(256, v9_rec("10.1.1.5", "10.2.2.9", 1, 80, 6, 10, 1))], seq=14), "a", "R1")
        self.assertEqual(res["event_counts"][fw.Event.SEQUENCE_GAP], 3)
        self.assertEqual(len(res["records"]), 1)
        self.assertEqual(d.loss[fw.Event.SEQUENCE_GAP], 3)

    def test_ipfix_gap_counts_records_and_duplicate_discarded(self):
        d = decoder()
        d.decode(ipfix([ipfix_template(256, IPFIX_F)], seq=0), "a", "R1")
        rec = ipfix_rec("10.1.1.5", "10.2.2.9", 1, 80, 6, 10, 1)
        self.assertEqual(len(d.decode(ipfix([dset(256, rec * 2, pad=False)], seq=0), "a", "R1")["records"]), 2)
        res = d.decode(ipfix([dset(256, rec, pad=False)], seq=7), "a", "R1")          # expected 2
        self.assertEqual(res["event_counts"][fw.Event.SEQUENCE_GAP], 5)
        dup = d.decode(ipfix([dset(256, rec, pad=False)], seq=7), "a", "R1")          # expected 8
        self.assertEqual((dup["records"], dup["event_counts"][fw.Event.DUPLICATE_OR_REORDERED]), ([], 1))


class Sampling(unittest.TestCase):
    def test_options_template_rate_applies_to_that_exporter_domain_only(self):
        d = decoder()
        opt = v9_options(260, 4, [(34, 4)]) + dset(260, struct.pack("!II", 0, 100))
        d.decode(v9([v9_template(256, F_V4), v9_options(260, 4, [(34, 4)]), dset(260, struct.pack("!II", 0, 100))], seq=1), "e1", "R1")
        d.decode(v9([v9_template(256, F_V4)], seq=1), "e2", "R2")
        pay = dset(256, v9_rec("10.1.1.5", "10.2.2.9", 1, 80, 6, 10, 1))
        r1 = d.decode(v9([pay], seq=2), "e1", "R1")["records"][0]
        r2 = d.decode(v9([pay], seq=2), "e2", "R2")["records"][0]
        self.assertEqual((r1["sampling_rate"], r1["sampling_source"]), (100, "options"))
        self.assertEqual((r2["sampling_rate"], r2["sampling_source"]), (None, "unknown"))
        self.assertTrue(opt)

    def test_inline_and_configured_and_conflict(self):
        d = decoder(default_sampling={"R2": 50})
        d.decode(v9([v9_template(256, F_V4 + [(34, 4)])], seq=1), "e1", "R1")
        rec = v9_rec("10.1.1.5", "10.2.2.9", 1, 80, 6, 10, 1) + struct.pack("!I", 1000)
        got = d.decode(v9([dset(256, rec)], seq=2), "e1", "R1")["records"][0]
        self.assertEqual((got["sampling_rate"], got["sampling_source"]), (1000, "record"))
        d.decode(v9([v9_template(256, F_V4)], seq=1), "e2", "R2")
        got = d.decode(v9([dset(256, v9_rec("10.1.1.5", "10.2.2.9", 1, 80, 6, 10, 1))], seq=2), "e2", "R2")["records"][0]
        self.assertEqual((got["sampling_rate"], got["sampling_source"]), (50, "configured"))
        d.decode(v9([v9_template(256, F_V4), v9_options(260, 4, [(34, 4)]), dset(260, struct.pack("!II", 0, 100) + struct.pack("!II", 1, 200))], seq=1), "e3", "R3")
        got = d.decode(v9([dset(256, v9_rec("10.1.1.5", "10.2.2.9", 1, 80, 6, 10, 1))], seq=2), "e3", "R3")
        self.assertIsNone(got["records"][0]["sampling_rate"])
        self.assertIn("SAMPLING_CONFLICT", got["records"][0]["wire"]["flags"])

    def test_ipfix_packet_interval_and_space(self):
        d = decoder()
        opt_tpl_body = struct.pack("!HHH", 270, 3, 1) + struct.pack("!HH", 302, 4) + struct.pack("!HH", 305, 4) + struct.pack("!HH", 306, 4)
        opt_tpl = struct.pack("!HH", 3, 4 + len(opt_tpl_body)) + opt_tpl_body
        d.decode(ipfix([ipfix_template(256, IPFIX_F), opt_tpl, dset(270, struct.pack("!III", 1, 1, 99))], seq=0), "a", "R1")
        got = d.decode(ipfix([dset(256, ipfix_rec("10.1.1.5", "10.2.2.9", 1, 80, 6, 10, 1), pad=False)], seq=1), "a", "R1")["records"][0]
        self.assertEqual((got["sampling_rate"], got["sampling_source"]), (100, "options"))


class MalformedAndBounds(unittest.TestCase):
    def test_bad_inputs_never_raise_and_are_counted(self):
        d = decoder()
        cases = {fw.Event.TRUNCATED_HEADER: [b"", b"\x00", struct.pack("!HH", 9, 1) + b"\0" * 5, struct.pack("!HH", 10, 16)],
                 fw.Event.BAD_VERSION: [struct.pack("!H", 5) + b"\0" * 30],
                 fw.Event.LENGTH_MISMATCH: [ipfix([], length=999)],
                 fw.Event.OVERSIZE_DATAGRAM: [b"\0" * 10_000]}
        for code, items in cases.items():
            for item in items:
                self.assertIn(code, d.decode(item, "a", "R1")["event_counts"], (code, item[:8]))

    def test_set_length_underflow_and_overrun(self):
        d = decoder()
        d.decode(v9([v9_template(256, F_V4)], seq=1), "a", "R1")
        for seq, bad in ((2, struct.pack("!HH", 256, 2)), (3, struct.pack("!HH", 256, 4000) + b"\0" * 8)):
            res = d.decode(v9([bad], seq=seq), "a", "R1")
            self.assertEqual(res["event_counts"][fw.Event.MALFORMED_SET], 1)
            self.assertEqual(res["records"], [])

    def test_hostile_templates_rejected(self):
        d = decoder(max_fields_per_template=4)
        self.assertIn(fw.Event.MALFORMED_TEMPLATE, d.decode(v9([v9_template(256, F_V4)], seq=1), "a", "R1")["event_counts"])       # too many fields
        self.assertIn(fw.Event.MALFORMED_TEMPLATE, d.decode(v9([v9_template(100, [(8, 4)])], seq=2), "a", "R1")["event_counts"])  # id < 256
        self.assertIn(fw.Event.MALFORMED_TEMPLATE, d.decode(v9([v9_template(257, [(8, 0)])], seq=3), "a", "R1")["event_counts"])  # zero length
        truncated = struct.pack("!HHHH", 0, 8, 258, 3)                                                                         # declares 3 fields, has none
        self.assertIn(fw.Event.MALFORMED_TEMPLATE, d.decode(v9([truncated], seq=4), "a", "R1")["event_counts"])
        self.assertEqual(d.domains[("a", 0)].templates, {})

    def test_undersized_address_field_is_malformed_record(self):
        d = decoder()
        d.decode(v9([v9_template(256, [(8, 3), (12, 4), (4, 1), (1, 4)])], seq=1), "a", "R1")
        res = d.decode(v9([dset(256, b"\x0a\x01\x01" + ip4("10.2.2.9") + struct.pack("!BI", 6, 5))], seq=2), "a", "R1")
        self.assertEqual(res["event_counts"][fw.Event.MALFORMED_RECORD], 1)

    def test_record_and_set_caps_per_datagram(self):
        d = decoder(max_records_per_datagram=5, max_sets_per_datagram=2)
        d.decode(v9([v9_template(256, F_V4)], seq=1), "a", "R1")
        recs = b"".join(v9_rec("10.1.1.5", "10.2.2.9", i, 80, 6, 10, 1) for i in range(20))
        res = d.decode(v9([dset(256, recs)], seq=2), "a", "R1")
        self.assertEqual((len(res["records"]), res["event_counts"][fw.Event.TOO_MANY_RECORDS]), (5, 1))
        res = d.decode(v9([dset(256, b"")] * 5, seq=3), "a", "R1")
        self.assertEqual(res["event_counts"][fw.Event.TOO_MANY_SETS], 1)

    def test_template_and_domain_table_caps(self):
        d = decoder(max_templates_per_domain=2, max_exporter_domains=2)
        res = d.decode(v9([v9_template(256 + i, [(8, 4), (12, 4)]) for i in range(4)], seq=1), "a", "R1")
        self.assertEqual((res["templates_learned"], res["event_counts"][fw.Event.TEMPLATE_LIMIT]), (2, 2))
        d.decode(v9([], seq=1, domain=1), "a", "R1")
        self.assertEqual(d.decode(v9([], seq=1, domain=2), "a", "R1")["event_counts"][fw.Event.EXPORTER_LIMIT], 1)

    def test_fuzz_never_raises_and_stays_bounded(self):
        rng = random.Random(1234)
        d = decoder()
        d.decode(v9([v9_template(256, F_V4)], seq=1), "a", "R1")
        base = v9([dset(256, v9_rec("10.1.1.5", "10.2.2.9", 1, 80, 6, 10, 1))], seq=2)
        for _ in range(500):
            buf = bytearray(base)
            for _ in range(rng.randint(1, 6)):
                buf[rng.randrange(len(buf))] = rng.randrange(256)
            res = d.decode(bytes(buf[:rng.randint(0, len(buf))]), "a", "R1")
            self.assertLessEqual(len(res["events"]), d.config.max_events_per_datagram + 1)
        for _ in range(200):
            d.decode(bytes(rng.randrange(256) for _ in range(rng.randint(0, 200))), "z", "R9")
        self.assertLessEqual(len(d.domains), d.config.max_exporter_domains)


class InputAdapterAndCollector(unittest.TestCase):
    def setUp(self):
        self.inp = fw.FlowWireInput({"192.0.2.1": "R1", "192.0.2.2": "R2"}, fw.WireConfig(max_pending_records=4), clock=lambda: T0)

    def feed(self, addr, n, seq_start=2, **kw):
        recs = b"".join(v9_rec(f"10.1.1.{5 + i}", "10.2.2.9", 40000 + i, 443, 6, 1500, 2) for i in range(n))
        return self.inp.ingest(v9([dset(256, recs)], seq=seq_start), addr)

    def test_unknown_exporter_discarded_and_counted(self):
        res = self.inp.ingest(v9([v9_template(256, F_V4)]), "203.0.113.9")
        self.assertFalse(res["accepted"])
        self.assertEqual(self.inp.health()["unknown_exporters"], {"203.0.113.9": 1})
        self.assertTrue(self.inp.health()["data_loss"])

    def test_backpressure_rejects_and_counts_not_silent(self):
        self.inp.ingest(v9([v9_template(256, F_V4)], seq=1), "192.0.2.1")
        res = self.feed("192.0.2.1", 7)
        self.assertEqual((res["records"], res["dropped_backpressure"]), (4, 3))
        h = self.inp.health()
        self.assertEqual((h["pending"], h["loss"][fw.Event.BACKPRESSURE], h["data_loss"]), (4, 3, True))

    def test_ingest_many_is_bounded(self):
        dg = [(v9([v9_template(256, F_V4)], seq=i), "192.0.2.1") for i in range(10)]
        self.assertEqual(self.inp.ingest_many(dg, max_datagrams=3), {"processed": 3, "not_processed": 7})
        self.assertEqual(self.inp.health()["datagrams_not_processed"], 7)

    def test_records_traverse_flowcollector_with_sampling_privacy_and_scoping(self):
        inp = fw.FlowWireInput({"192.0.2.1": "R1", "192.0.2.2": "R2"}, fw.WireConfig(default_sampling={"R1": 100}), clock=lambda: T0)
        inp.ingest(v9([v9_template(256, F_V4)], seq=1), "192.0.2.1")
        inp.ingest(v9([v9_template(256, F_V4)], seq=1), "192.0.2.2")
        mix = dset(256, v9_rec("10.1.1.5", "10.2.2.9", 40000, 443, 6, 1500, 2) + v9_rec("10.1.1.6", "10.2.2.9", 40001, 443, 6, 1500, 2)
                   + v9_rec("10.1.1.5", "192.0.2.77", 40002, 53, 17, 80, 1))
        inp.ingest(v9([mix], seq=2), "192.0.2.1")
        inp.ingest(v9([dset(256, v9_rec("10.1.1.5", "10.2.2.9", 40003, 443, 6, 700, 1))], seq=2), "192.0.2.2")   # R2: no sampling info
        col = c.FlowCollector(capability_probe=lambda p, s: {"status": "SUPPORTED"}, now=lambda: T0)
        target = c.Target(device="R1", platform="ceos", os_version="4.36.2F", capabilities={c.SourceType.NETFLOW: "SUPPORTED"})
        sel = {"protocol": 6, "dst_ports": [443], "dst_prefixes": ["10.2.2.9/32"]}
        bundle = inp.collect(col, target, sel, expected_exporters=["R1"])
        obs = {o["key"]: o for o in bundle["observations"]}
        self.assertEqual(obs["flow.service.sampled_records"]["value"], 2)
        self.assertEqual(obs["flow.service.bytes"]["value"], 2 * 1500 * 100)
        self.assertTrue(obs["flow.service.bytes"]["extra"]["uncertainty"]["estimated"])
        self.assertEqual(bundle["wire_ingest"]["out_of_scope_prefiltered"], 1)
        self.assertTrue(bundle["wire_ingest"]["selector_widened"])
        blob = json.dumps(bundle, default=str)
        for host in ("10.1.1.5", "10.1.1.6", "10.2.2.9", "192.0.2.77"):
            self.assertNotIn(host, blob.replace("10.2.2.9/32", ""), host)
        self.assertEqual(len(inp.queue), 1)           # R2's record untouched by R1's collection
        b2 = inp.collect(col, c.Target(device="R2", platform="ceos", os_version="4.36.2F", capabilities={c.SourceType.NETFLOW: "SUPPORTED"}), {"protocol": 6})
        o2 = {o["key"]: o for o in b2["observations"]}
        self.assertIsNone(o2["flow.service.bytes"]["value"])
        self.assertIn("SAMPLING_RATE_UNKNOWN", o2["flow.service.bytes"]["flags"])

    def test_loss_is_propagated_to_run_flags(self):
        self.inp.ingest(v9([v9_template(256, F_V4)], seq=1), "192.0.2.1")
        self.feed("192.0.2.1", 1, seq_start=5)           # export packets 2-4 lost
        col = c.FlowCollector(capability_probe=lambda p, s: {"status": "SUPPORTED"}, now=lambda: T0)
        target = c.Target(device="R1", platform="ceos", os_version="4.36.2F", capabilities={c.SourceType.NETFLOW: "SUPPORTED"})
        bundle = self.inp.collect(col, target, {"protocol": 6})
        self.assertIn("WIRE_DATA_LOSS", bundle["run"]["flags"])
        self.assertEqual(bundle["wire_ingest"]["health"]["loss"][fw.Event.SEQUENCE_GAP], 3)

    def test_no_listener_opened_by_module(self):
        import inspect
        self.assertNotIn("import socket", inspect.getsource(fw))


if __name__ == "__main__":
    unittest.main()
