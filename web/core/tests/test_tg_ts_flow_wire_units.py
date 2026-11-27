"""Direct tests for the NetFlow v9 / IPFIX wire input helpers (troubleshooting/adapters/flow_wire.py).

The reader is bounds-checked, templates are scoped per exporter domain, the pending queue is bounded and per exporter,
and any wire loss is carried into the collection run instead of being hidden.  Datagrams come from the wire suite's
generators.
"""

from __future__ import annotations

from datetime import datetime, timezone

from django.test import SimpleTestCase

from core.services.troubleshooting import collectors as c
from core.services.troubleshooting.adapters import flow_wire as fw
from core.tests import test_troubleshooting_flow_wire as W

T0 = W.T0


def target(device="R1"):
    return c.Target(device=device, platform="ceos", os_version="4.36.2F", capabilities={c.SourceType.NETFLOW: "SUPPORTED"})


def collector():
    return c.FlowCollector(capability_probe=lambda p, s: {"status": "SUPPORTED"}, now=lambda: T0)


class ReaderAndTemplateTests(SimpleTestCase):
    def test_reader_take_left_and_u16_walk_the_buffer(self):
        reader = fw._Reader(b"\x00\x05abc", 0, 5)           # pylint: disable=protected-access  # the bounds-checked cursor under test
        self.assertEqual((reader.u16(), reader.left(), reader.take(2), reader.left()), (5, 3, b"ab", 1))

    def test_reader_take_refuses_an_underflow_or_negative_length(self):
        reader = fw._Reader(b"\x00\x05", 0, 2)               # pylint: disable=protected-access  # the bounds-checked cursor under test
        for label, n in (("an underflow", 3), ("a negative length", -1)):
            with self.subTest(f"{label} is refused"), self.assertRaises(ValueError):
                reader.take(n)
        self.assertEqual(reader.left(), 2)

    def test_template_signature_and_min_length_describe_the_layout(self):
        layout = ((8, 4, None), (12, 4, None), (95, 0xFFFF, None))
        tpl = fw._Template(256, layout, 0, T0)              # pylint: disable=protected-access  # the template record under test
        self.assertEqual((tpl.min_length(), tpl.signature()), (9, (layout, 0, False)))

    def test_wire_config_as_dict_returns_every_bound(self):
        d = fw.WireConfig(default_sampling={"R1": 100}).as_dict()
        self.assertEqual((d["max_pending_records"], d["default_sampling"], d["require_known_exporter"]), (50_000, {"R1": 100}, True))


class DecoderStateTests(SimpleTestCase):
    def test_template_summary_returns_learned_templates_per_domain(self):
        d = W.decoder()
        d.decode(W.v9([W.v9_template(256, W.F_V4)], seq=1), "192.0.2.1", "R1")
        self.assertEqual(d.template_summary(), [{"exporter_addr": "192.0.2.1", "domain": 0, "templates": [256], "expected_seq": 2}])

    def test_forget_removes_only_that_exporter(self):
        d = W.decoder()
        for addr in ("192.0.2.1", "192.0.2.2"):
            d.decode(W.v9([W.v9_template(256, W.F_V4)], seq=1), addr, "R1")
        d.forget("192.0.2.1")
        self.assertEqual([row["exporter_addr"] for row in d.template_summary()], ["192.0.2.2"])

    def test_forget_never_decodes_data_against_a_forgotten_template(self):
        d = W.decoder()
        d.decode(W.v9([W.v9_template(256, W.F_V4)], seq=1), "192.0.2.1", "R1")
        d.forget("192.0.2.1")
        res = d.decode(W.v9([W.dset(256, W.v9_rec("10.1.1.5", "10.2.2.9", 40000, 443, 6, 1500, 2))], seq=2), "192.0.2.1", "R1")
        self.assertEqual(res["records"], [])
        self.assertTrue(res["events"])


class InputTests(SimpleTestCase):
    def setUp(self):
        self.inp = fw.FlowWireInput({"192.0.2.1": "R1", "192.0.2.2": "R2"}, fw.WireConfig(default_sampling={"R1": 100}), clock=lambda: T0)
        for addr in ("192.0.2.1", "192.0.2.2"):
            self.inp.ingest(W.v9([W.v9_template(256, W.F_V4)], seq=1), addr)

    def feed(self, addr, seq=2, n=1):
        recs = b"".join(W.v9_rec(f"10.1.1.{5 + i}", "10.2.2.9", 40000 + i, 443, 6, 1500, 2) for i in range(n))
        self.inp.ingest(W.v9([W.dset(256, recs)], seq=seq), addr)

    def test_drain_takes_this_exporters_records_up_to_the_limit(self):
        self.feed("192.0.2.1", n=3)
        self.feed("192.0.2.2")
        self.assertEqual(len(self.inp.drain(exporter="R1", limit=2)), 2)
        self.assertEqual(len(self.inp.queue), 2)

    def test_drain_never_takes_records_of_another_exporter(self):
        self.feed("192.0.2.2")
        self.assertEqual(self.inp.drain(exporter="R1"), [])
        self.assertEqual([r["exporter"] for r in self.inp.queue], ["R2"])

    def test_ingest_many_beyond_the_bound_is_not_processed(self):
        batch = [(W.v9([W.v9_template(256, W.F_V4)], seq=i), "192.0.2.1") for i in range(5)]
        self.assertEqual(self.inp.ingest_many(batch, max_datagrams=2), {"processed": 2, "not_processed": 3})
        self.assertTrue(self.inp.health()["data_loss"])

    def test_collect_of_a_lossy_stream_never_hides_the_loss(self):
        self.feed("192.0.2.1", seq=5)                     # export packets 2-4 lost
        bundle = self.inp.collect(collector(), target(), {"protocol": 6}, expected_exporters=["R1"])
        self.assertTrue(bundle["wire_ingest"]["health"]["data_loss"])
        self.assertIn("WIRE_DATA_LOSS", bundle["run"]["flags"])

    def test_collected_records_are_masked_to_prefixes(self):
        self.feed("192.0.2.1")
        bundle = self.inp.collect(collector(), target(), {"protocol": 6, "dst_prefixes": ["10.2.2.9/32"]}, expected_exporters=["R1"])
        self.assertEqual(bundle["wire_ingest"]["records_drained"], 1)
        self.assertNotIn("10.1.1.5", str(bundle["observations"]))


assert datetime(2026, 11, 9, 12, tzinfo=timezone.utc) == T0     # the suite's fixed clock
