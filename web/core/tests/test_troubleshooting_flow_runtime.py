"""FWRT: generated binary replay, never live evidence. Spec UT-004/006/017/022, IT-16/19."""
import json
from django.test import TestCase
from core import models as m
from core.services.troubleshooting import runtime as rt, repository as repo
from core.services.troubleshooting.adapters.flow_runtime import FlowRuntimeInput
from core.services.troubleshooting.adapters import flow_wire as fw
from core.tests.test_troubleshooting_flow_wire import T0, F_V4, v9, v9_template, v9_rec, dset
from core.tests.test_troubleshooting_runtime import ACTOR, make_case, deps


class FlowRuntimeTests(TestCase):
    def wire(self, **kwargs):
        w = fw.FlowWireInput({'192.0.2.1': 'R1', '192.0.2.2': 'R2'}, fw.WireConfig(**kwargs), clock=lambda: T0)
        w.ingest(v9([v9_template(256, F_V4)], seq=1, domain=7), '192.0.2.1')
        return w

    def feed(self, w, seq=2, count=1):
        payload = v9_rec('10.1.1.5', '10.2.2.9', 40000, 443, 6, 1500, 2) * count
        payload += v9_rec('10.1.1.6', '10.2.2.9', 40000, 443, 6, 9000, 8)
        w.ingest(v9([dset(256, payload)], seq=seq, domain=7), '192.0.2.1')

    def run_flow(self, w, key='fw', case=None):
        case = case or make_case('RB02', devices=('R1',), key=key)
        binding = FlowRuntimeInput(w, {'protocol': 6, 'dst_ports': [443], 'src_prefixes': ['10.1.1.5/32']}, ('R1',))
        d = deps(names=('R1',), snmp=False, syslog=False, flow_input=lambda info: binding)
        result = rt.run_case(ACTOR, case.case_id, d, run_key=key, now=T0)
        return case, result

    def evidence(self, case):
        return m.TsEvidenceRef.objects.get(case=case, source_type='netflow')

    def test_FWRT001_selector_provenance_privacy_uncertainty_persist(self):
        w = self.wire(default_sampling={'R1': 100})
        self.feed(w)
        case, result = self.run_flow(w)
        e = self.evidence(case)
        scope = e.scope
        wire = scope['wire_ingest']
        self.assertEqual(wire['out_of_scope_prefiltered'], 1)
        self.assertEqual(wire['records'][0]['wire']['domain'], 7)
        self.assertEqual(wire['records'][0]['exporter'], 'R1')
        self.assertEqual(wire['records'][0]['sampling_source'], 'configured')
        norm = {o['key']: o for o in scope['normalized_flow']}
        self.assertEqual(norm['flow.service.bytes']['value'], 150000)
        self.assertTrue(norm['flow.service.bytes']['extra']['uncertainty']['estimated'])
        self.assertFalse(scope['live'])
        self.assertTrue(scope['raw_hash_as_received'])
        self.assertIn(scope['raw_hash_as_received'], e.raw_pointer)
        self.assertNotIn('10.1.1.5', json.dumps(scope))
        self.assertIsNotNone(e.raw_blob)
        self.assertNotIn('10.1.1.5', e.raw_blob.content)
        self.assertIn('10.1.1.0', e.raw_blob.content)
        self.assertTrue(m.TsObservation.objects.filter(case=case, key='flow.health', is_missing_data=True).exists())
        self.assertFalse(m.TsObservation.objects.filter(case=case, key__startswith='flow.health', is_missing_data=False).exists())
        self.assertNotEqual(result['diagnosis']['outcome'], 'RESOLVED_VERIFIED')

    def test_FWRT002_restart_manifest_deduplicates_without_draining_new_input(self):
        w = self.wire()
        self.feed(w)
        case, _ = self.run_flow(w)
        counts = (m.TsEvidenceRef.objects.filter(case=case).count(), m.TsObservation.objects.filter(case=case).count())
        fresh = self.wire()
        self.feed(fresh)
        _, result = self.run_flow(fresh, case=case)
        self.assertEqual(result['collection']['resumed'], ['R1'])
        self.assertEqual(len(fresh.queue), 2)
        self.assertEqual(counts, (m.TsEvidenceRef.objects.filter(case=case).count(), m.TsObservation.objects.filter(case=case).count()))

    def test_FWRT003_missing_input_is_unknown(self):
        case = make_case('RB02', devices=('R1',), key='missing')
        rt.run_case(ACTOR, case.case_id, deps(names=('R1',), snmp=False, syslog=False), now=T0)
        row = m.TsObservation.objects.get(case=case, key='flow.health')
        self.assertTrue(row.is_missing_data)
        self.assertIn('NOT_CONFIGURED', row.missing_reason)

    def test_FWRT004_unknown_sampling_retained_without_estimate(self):
        w = self.wire()
        self.feed(w)
        case, _ = self.run_flow(w)
        norm = {o['key']: o for o in self.evidence(case).scope['normalized_flow']}
        self.assertIsNone(norm['flow.service.bytes']['value'])
        self.assertIn('SAMPLING_RATE_UNKNOWN', norm['flow.service.bytes']['flags'])

    def test_FWRT005_template_loss_backpressure_gaps_are_not_packet_loss(self):
        w = self.wire(max_pending_records=1)
        w.ingest(v9([dset(300, b'12345678')], seq=2, domain=7), '192.0.2.1')
        self.feed(w, seq=5, count=3)
        case, _ = self.run_flow(w)
        scope = self.evidence(case).scope
        loss = scope['wire_ingest']['health']['loss']
        for code in (fw.Event.UNKNOWN_TEMPLATE, fw.Event.SEQUENCE_GAP, fw.Event.BACKPRESSURE):
            self.assertGreater(loss[code], 0)
        self.assertIn('WIRE_DATA_LOSS', scope['collector_flags'])
        self.assertIsNone(scope['wire_ingest']['measured_packet_loss'])
        self.assertEqual(scope['wire_ingest']['production_health'], 'UNKNOWN')

    def test_FWRT006_exporter_scoping_and_capability_refusal(self):
        w = self.wire()
        self.feed(w)
        w.ingest(v9([v9_template(256, F_V4)], seq=1), '192.0.2.2')
        w.ingest(v9([dset(256, v9_rec('10.1.1.5', '10.2.2.9', 1, 443, 6, 99, 1))], seq=2), '192.0.2.2')
        self.run_flow(w)
        self.assertEqual([r['exporter'] for r in w.queue], ['R2'])
        from core.services.troubleshooting import collectors as col
        refused_wire = self.wire()
        self.feed(refused_wire)
        binding = FlowRuntimeInput(refused_wire, {'protocol': 6})
        b = binding.collect(col.FlowCollector(capability_probe=lambda p, s: {'status': 'UNSUPPORTED'}), col.Target(device='R1', platform='ceos'), limit=5)
        self.assertEqual(b['observations'], [])
        self.assertEqual(len(refused_wire.queue), 2)

    def test_FWRT007_unscoped_input_refused_before_queue_drain(self):
        from core.services.troubleshooting import collectors as col
        w = self.wire()
        self.feed(w)
        with self.assertRaisesMessage(ValueError, 'UNSCOPED_FLOW_QUERY'):
            FlowRuntimeInput(w, {}).collect(col.FlowCollector(), col.Target(device='R1', platform='ceos'), limit=5)
        self.assertEqual(len(w.queue), 2)

    def test_FWRT008_record_budget_preserves_remainder(self):
        from core.services.troubleshooting import collectors as col
        w = self.wire()
        self.feed(w, count=3)
        collector = col.FlowCollector(capability_probe=lambda p, s: {'status': 'SUPPORTED'}, now=lambda: T0)
        b = FlowRuntimeInput(w, {'protocol': 6}).collect(collector, col.Target(device='R1', platform='ceos'), limit=1)
        self.assertEqual(len(b['wire_ingest']['records']), 1)
        self.assertEqual(len(w.queue), 3)

    def test_FWRT009_duplicate_datagram_does_not_inflate_persistent_volume(self):
        w = self.wire(default_sampling={'R1': 1})
        self.feed(w, seq=2)
        self.feed(w, seq=2)
        case, _ = self.run_flow(w)
        scope = self.evidence(case).scope
        norm = {o['key']: o for o in scope['normalized_flow']}
        self.assertEqual(norm['flow.service.bytes']['value'], 1500)
        self.assertEqual(len(scope['wire_ingest']['records']), 1)
        self.assertEqual(scope['wire_ingest']['production_health'], 'UNKNOWN')

    def test_FWRT010_receiver_restart_without_templates_persists_uncertainty(self):
        w = fw.FlowWireInput({'192.0.2.1': 'R1'}, clock=lambda: T0)
        self.feed(w)
        case, result = self.run_flow(w)
        scope = self.evidence(case).scope
        self.assertGreater(scope['wire_ingest']['health']['loss'][fw.Event.UNKNOWN_TEMPLATE], 0)
        self.assertEqual(scope['wire_ingest']['records'], [])
        self.assertEqual(scope['wire_ingest']['production_health'], 'UNKNOWN')
        self.assertIsNone(scope['wire_ingest']['measured_packet_loss'])
        self.assertNotEqual(result['diagnosis']['outcome'], 'RESOLVED_VERIFIED')
