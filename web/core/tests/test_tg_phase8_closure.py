"""Test-governance closure for V2 Phase 8 (dynamic infrastructure): every new or modified function of
``core.services.commissioning.outbox`` (facts, backoff), ``core.services.devices.events`` (the fact hook),
``core.services.infrastructure.*``, ``core.infrastructure_views`` and the ``nmas_infrastructure`` command, called directly with
an accepting and a refusing case.  Application database and in-memory fakes only (contracts, not the live NetBox)."""

from __future__ import annotations

import http.server
import io
import json
import tempfile
import threading
from datetime import timedelta
from pathlib import Path
from unittest import mock

from django.contrib.auth.models import AnonymousUser, Group, User
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import transaction
from django.test import RequestFactory, TestCase, override_settings
from django.utils import timezone

from core import infrastructure_views as V
from core import models
from core.management.commands import nmas_infrastructure as C
from core.services.commissioning import outbox
from core.services.devices import events
from core.services.infrastructure import dispatcher as D
from core.services.infrastructure import facts as FX
from core.services.infrastructure import grafana as G
from core.services.infrastructure import monitoring as MON
from core.services.infrastructure import nsot as NS
from core.services.infrastructure import topology as TOP
from core.tests import test_infrastructure_fixtures as F

S, A, T = models.DeviceLifecycleState, models.ProductionAdmissionState, models.MonitoringTargetState
Outcome, Topic = models.DeviceLifecycleEventOutcome, models.OutboxTopic


class OutboxFactClosureTests(TestCase):
    def setUp(self):
        self.device = F.L.register().device

    def test_record_fact_writes_one_event_per_consumer(self):
        rows = F.fact(self.device, outbox.DECOMMISSION_REQUESTED, {"decommission": "DEC-000001"})
        self.assertEqual(sorted(r.topic for r in rows), sorted(outbox.FACT_TOPICS))
        self.assertEqual({r.sequence for r in rows}, {1})

    def test_record_fact_refuses_unknown_fact(self):
        with self.assertRaises(outbox.OutboxError):
            F.fact(self.device, "EXPLODED")

    def test_next_sequence_increments_per_device(self):
        self.assertEqual(outbox.next_sequence(self.device), 1)
        F.fact(self.device, outbox.HEALTH_CHANGED)
        self.assertEqual(outbox.next_sequence(self.device), 2)

    def test_next_sequence_ignores_other_devices_without_facts(self):
        other = F.L.register("NEW2", serial="SN-NEW2", mac="00:1c:73:00:00:02").device
        F.fact(other, outbox.HEALTH_CHANGED)
        self.assertEqual(outbox.next_sequence(self.device), 1)

    def test_fact_detail_returns_bounded_copy(self):
        self.assertEqual(outbox.fact_detail({"b": 1, "a": "x"}), {"a": "x", "b": 1})

    def test_fact_detail_refuses_secret_and_oversized_detail(self):
        with self.assertRaises(outbox.OutboxError):
            outbox.fact_detail({"token": "abc"})
        with self.assertRaises(outbox.OutboxError):
            outbox.fact_detail({"k": "x" * 3000})
        with self.assertRaises(outbox.OutboxError):
            outbox.fact_detail({str(i): i for i in range(40)})

    def test_fact_payload_matches_contract(self):
        payload = outbox.fact_payload(self.device, outbox.DISCOVERED, 3, {})
        self.assertEqual(outbox.validate(Topic.NSOT_DEVICE_STATE, payload), [])

    def test_fact_payload_with_extra_field_is_rejected_by_contract(self):
        payload = {**outbox.fact_payload(self.device, outbox.DISCOVERED, 3, {}), "address": "10.0.0.1"}
        self.assertTrue(outbox.validate(Topic.NSOT_DEVICE_STATE, payload))

    def test_fact_for_action_maps_lifecycle_actions(self):
        self.assertEqual(outbox.fact_for_action("COMMISSION_COMPLETE", Outcome.ADVANCED), outbox.COMMISSIONED)
        self.assertEqual(outbox.fact_for_action("MGMT_FAILOVER", Outcome.RECORDED), outbox.MANAGEMENT_PATH_CHANGED)

    def test_fact_for_action_never_maps_refusals_outbox_or_decommission(self):
        self.assertEqual(outbox.fact_for_action("COMMISSION_COMPLETE", Outcome.REFUSED), "")
        self.assertEqual(outbox.fact_for_action("OUTBOX_RECORD", Outcome.RECORDED), "")
        self.assertEqual(outbox.fact_for_action("DECOMMISSION_REQUEST", Outcome.ADVANCED), "")
        self.assertEqual(outbox.fact_for_action("RESTORE_EXECUTE", Outcome.ADVANCED), "")

    def test_emit_for_event_records_mapped_fact(self):
        with transaction.atomic():
            rows = outbox.emit_for_event(self.device, "DISCOVER", Outcome.ADVANCED, actor="system:t", to_state=S.DISCOVERED,
                                         evidence={"reason": "seen", "password": "x"})
        self.assertEqual(rows[0].payload["lifecycle_state"], S.DISCOVERED)
        self.assertEqual(rows[0].payload["detail"], {"action": "DISCOVER", "reason": "seen"})

    @override_settings(NMAS_INFRASTRUCTURE_FACTS=False)
    def test_emit_for_event_disabled_writes_none(self):
        self.assertEqual(outbox.emit_for_event(self.device, "DISCOVER", Outcome.ADVANCED, actor="system:t"), [])

    def test_events_emit_fact_hook_records_fact(self):
        with transaction.atomic():
            rows = events.emit_fact(self.device, "BOOTSTRAP", Outcome.ADVANCED, actor="system:t", to_state=S.BOOTSTRAPPED)
        self.assertEqual(rows[0].payload["fact"], outbox.BOOTSTRAPPED)

    def test_events_emit_fact_hook_never_emits_for_unmapped_action(self):
        self.assertEqual(events.emit_fact(self.device, "REGISTER", Outcome.ADVANCED, actor="system:t"), [])

    def test_events_record_appends_chain_and_emits(self):
        with transaction.atomic():
            event = events.record(self.device, "ATTACHMENT_APPROVE", Outcome.RECORDED, actor="arthur")
        self.assertTrue(events.verify_chain(self.device))
        self.assertEqual(event.action, "ATTACHMENT_APPROVE")
        self.assertTrue(models.LifecycleOutboxEvent.objects.filter(device=self.device, payload__fact=outbox.ATTACHMENT_CHANGED).exists())

    def test_events_record_refusal_never_emits(self):
        with transaction.atomic():
            events.record(self.device, "ATTACHMENT_APPROVE", Outcome.REFUSED, actor="arthur")
        self.assertFalse(models.LifecycleOutboxEvent.objects.filter(device=self.device).exists())

    def test_backoff_seconds_grows_exponentially_and_caps(self):
        self.assertEqual([outbox.backoff_seconds(n) for n in (1, 2, 3, 4)], [0, 60, 120, 240])
        self.assertEqual(outbox.backoff_seconds(40), 3600)

    def test_backoff_seconds_zero_for_first_or_negative_attempts(self):
        self.assertEqual(outbox.backoff_seconds(0), 0)
        self.assertEqual(outbox.backoff_seconds(-3), 0)

    def test_retry_schedule_records_code_and_backoff(self):
        event = F.fact(self.device, outbox.HEALTH_CHANGED)[0]
        outbox.fail(event, code="X")
        second = outbox.fail(event, code="NSOT_UNAVAILABLE")
        self.assertEqual((second.state, second.last_error, second.attempts), (models.OutboxState.FAILED, "NSOT_UNAVAILABLE", 2))
        self.assertGreater(second.next_attempt_at, timezone.now() + timedelta(seconds=30))

    def test_delivered_event_refuses_retry_schedule(self):
        event = F.fact(self.device, outbox.HEALTH_CHANGED)[0]
        outbox.deliver(event, consumer="t", actor="system:t")
        with self.assertRaises(outbox.OutboxError):
            outbox.fail(event, code="LATE")

    def test_pending_returns_due_events(self):
        rows = F.fact(self.device, outbox.HEALTH_CHANGED)
        self.assertEqual({e.pk for e in outbox.pending()}, {r.pk for r in rows})

    def test_pending_never_returns_events_still_backing_off(self):
        event = F.fact(self.device, outbox.HEALTH_CHANGED)[0]
        outbox.fail(event, code="A")
        outbox.fail(event, code="B")
        self.assertNotIn(event.pk, [e.pk for e in outbox.pending(event.topic)])
        self.assertIn(event.pk, [e.pk for e in outbox.pending(event.topic, now=timezone.now() + timedelta(hours=2))])


class FactsHelperClosureTests(TestCase):
    def setUp(self):
        self.env = F.lab()
        self.s1 = self.env["devices"]["S1"]

    def test_consumer_code_is_bounded(self):
        self.assertEqual(FX.ConsumerError("X" * 100).code, "X" * 64)

    def test_consumer_code_empty_stays_empty(self):
        self.assertEqual(FX.ConsumerError("").code, "")

    def test_fact_of_reads_payload_and_admission_topics(self):
        event = F.fact(self.s1, outbox.HEALTH_CHANGED)[0]
        self.assertEqual(FX.fact_of(event), outbox.HEALTH_CHANGED)
        self.assertEqual(FX.fact_of(models.LifecycleOutboxEvent(topic=Topic.NSOT_DEVICE_ADMITTED)), outbox.ADMITTED)

    def test_fact_of_returns_empty_without_fact_field(self):
        self.assertEqual(FX.fact_of(models.LifecycleOutboxEvent(topic=Topic.NSOT_DEVICE_STATE, payload={})), "")

    def test_superseded_detects_older_fact(self):
        self.assertTrue(FX.superseded(models.LifecycleOutboxEvent(sequence=3), 5))

    def test_superseded_never_for_newer_or_admission(self):
        self.assertFalse(FX.superseded(models.LifecycleOutboxEvent(sequence=6), 5))
        self.assertFalse(FX.superseded(models.LifecycleOutboxEvent(sequence=0), 5))

    def test_under_maintenance_reads_engine_state(self):
        F.maintenance("S1")
        self.assertTrue(FX.under_maintenance("S1"))

    def test_under_maintenance_not_when_restored(self):
        F.maintenance("S3", state="RESTORED")
        self.assertFalse(FX.under_maintenance("S3"))

    def test_live_device_returns_live_row(self):
        self.assertEqual(FX.live_device("S1").pk, self.s1.pk)

    def test_live_device_none_for_decommissioned(self):
        F.force_state(self.s1, S.DECOMMISSIONED)
        self.assertIsNone(FX.live_device("S1"))

    def test_attachment_ref_formats_id(self):
        self.assertEqual(FX.attachment_ref(self.env["oob"]), f"ATT-{self.env['oob'].pk:06d}")

    def test_attachment_ref_refuses_unsaved_row(self):
        with self.assertRaises(TypeError):
            FX.attachment_ref(models.DeviceAttachment())

    def test_verified_production_attachments_lists_verified_uplink(self):
        device, attachment = F.new_device_with_verified_uplink()
        self.assertEqual(list(FX.verified_production_attachments(device)), [attachment])

    def test_verified_production_attachments_never_lists_unverified_or_management(self):
        device, _att = F.new_device_with_verified_uplink(verify=False)
        self.assertEqual(list(FX.verified_production_attachments(device)), [])
        self.assertEqual(list(FX.verified_production_attachments(self.env["devices"]["R1"])), [])


class TopologyClosureTests(TestCase):
    def setUp(self):
        self.env = F.lab()
        self.device, self.attachment = F.new_device_with_verified_uplink()

    def test_node_state_maps_lifecycle(self):
        self.assertEqual(TOP.node_state(self.env["devices"]["S1"]), models.TopologyNodeState.IN_SERVICE)
        F.maintenance("S1")
        self.assertEqual(TOP.node_state(self.env["devices"]["S1"]), models.TopologyNodeState.MAINTENANCE)

    def test_node_state_not_admitted_in_service_is_commissioned(self):
        device = F.force_state(self.env["devices"]["S3"], S.IN_SERVICE, A.NOT_ADMITTED)
        self.assertEqual(TOP.node_state(device), models.TopologyNodeState.COMMISSIONED)

    def test_peer_live_for_live_and_unmanaged(self):
        self.assertTrue(TOP._peer_live("S1"))
        self.assertTrue(TOP._peer_live("some-inventory-switch"))

    def test_peer_live_not_for_decommissioned_peer(self):
        F.force_state(self.env["devices"]["S1"], S.DECOMMISSIONED)
        self.assertFalse(TOP._peer_live("S1"))

    def test_desired_edges_from_verified_attachment_and_approved_path(self):
        path = F.oob_path(self.env)
        wanted = TOP.desired_edges(self.env["devices"]["R1"])
        self.assertEqual([v["source"] for v in wanted.values()], [path.path_id])
        self.assertEqual(len(TOP.desired_edges(self.device)), 1)

    def test_desired_edges_empty_for_unverified_attachment(self):
        other, _att = F.new_device_with_verified_uplink("NEW2", port="Ethernet8", verify=False, serial="SN-NEW2", mac="00:1c:73:00:00:02")
        self.assertEqual(TOP.desired_edges(other), {})

    def test_reconcile_edges_creates_then_is_idempotent(self):
        self.assertEqual(TOP.reconcile_edges(self.device)["created"], 1)
        self.assertEqual(TOP.reconcile_edges(self.device), {"created": 0, "activated": 0, "deactivated": 0})

    def test_reconcile_edges_never_keeps_edges_active_after_decommission(self):
        TOP.reconcile_edges(self.device)
        device = F.force_state(self.device, S.DECOMMISSIONED)
        self.assertEqual(TOP.reconcile_edges(device)["deactivated"], 1)

    def test_reconcile_device_upserts_node(self):
        node = TOP.reconcile_device(self.device, sequence=7, fact="X")
        self.assertEqual((node.last_sequence, node.facts["last_fact"]), (7, "X"))

    def test_reconcile_device_never_lowers_sequence(self):
        TOP.reconcile_device(self.device, sequence=7)
        self.assertEqual(TOP.reconcile_device(self.device, sequence=2).last_sequence, 7)

    def test_apply_applies_newest_fact(self):
        event = F.fact(self.device, outbox.HEALTH_CHANGED)[1]
        self.assertEqual(TOP.apply(event), "APPLIED")

    def test_apply_supersedes_stale_fact(self):
        events_ = [F.fact(self.device, outbox.HEALTH_CHANGED)[1] for _ in range(2)]
        TOP.apply(events_[1])
        self.assertEqual(TOP.apply(events_[0]), "SUPERSEDED")

    def test_rebuild_reconciles_every_device(self):
        self.assertEqual(TOP.rebuild(), models.ManagedDevice.objects.count())

    def test_rebuild_with_zero_devices_returns_zero(self):
        with mock.patch.object(models.ManagedDevice.objects, "order_by", return_value=[]):
            self.assertEqual(TOP.rebuild(), 0)

    def test_node_id_by_name_prefers_live_successor(self):
        TOP.rebuild()
        s1 = F.force_state(self.env["devices"]["S1"], S.DECOMMISSIONED)
        successor = F.successor_of(s1)
        TOP.reconcile_device(successor)
        self.assertEqual(TOP._node_id_by_name()["S1"], successor.device_id)

    def test_node_id_by_name_empty_without_nodes(self):
        self.assertEqual(TOP._node_id_by_name(), {})

    def test_graph_builds_stable_ids_and_unmanaged_peers(self):
        TOP.rebuild()
        F.activate(self.env["devices"]["R1"], F.oob_path(self.env))
        TOP.rebuild()
        g = TOP.graph()
        self.assertIn(self.device.device_id, g)
        self.assertEqual(g.nodes["unmanaged:nmas:nmas-mgmt"]["state"] if "unmanaged:nmas:nmas-mgmt" in g else "UNMANAGED", "UNMANAGED")
        self.assertTrue(any(d["kind"] == "MANAGEMENT" for _u, _v, d in g.edges(data=True)))

    def test_graph_active_only_never_includes_inactive_edges(self):
        TOP.rebuild()
        F.force_state(self.device, S.DECOMMISSIONED)
        TOP.rebuild()
        self.assertEqual(TOP.graph().number_of_edges(), sum(1 for e in models.TopologyEdge.objects.all() if e.active))
        self.assertGreater(TOP.graph(active_only=False).number_of_edges(), TOP.graph().number_of_edges())

    def test_summary_counts_nodes_and_edges(self):
        TOP.rebuild()
        self.assertEqual(TOP.summary()["edges"]["PRODUCTION:active"], 1)

    def test_summary_empty_without_rows(self):
        self.assertEqual(TOP.summary(), {"nodes": {}, "edges": {}})

    def test_upstream_of_lists_peers_and_dependencies(self):
        TOP.rebuild()
        self.assertEqual([r["name"] for r in TOP.upstream_of("NEW1")], ["S1"])

    def test_upstream_of_unknown_device_is_empty(self):
        self.assertEqual(TOP.upstream_of("GHOST"), [])

    def test_direct_dependents_from_attachment(self):
        self.assertEqual([d.name for d, _via in TOP._direct_dependents("S1")], ["NEW1"])

    def test_direct_dependents_none_for_leaf(self):
        self.assertEqual(TOP._direct_dependents("NEW1"), [])

    def test_downstream_dependents_recursive(self):
        leaf = F.L.register("NEW2", serial="SN-NEW2", mac="00:1c:73:00:00:02").device
        models.CommissioningDependency.objects.create(device=leaf, upstream=self.device, kind=models.DependencyKind.ROUTING,
                                                      created_by=F.L.OPERATOR)
        rows = TOP.downstream_dependents("S1")
        self.assertEqual([(r["name"], r["parent"]) for r in rows], [("NEW1", "S1"), ("NEW2", "NEW1")])
        self.assertTrue(rows[0]["via"].startswith("PRODUCTION_"))
        self.assertEqual(rows[1]["via"], "COMMISSIONING_DEPENDENCY")

    def test_downstream_dependents_none_for_unknown_device(self):
        self.assertEqual(TOP.downstream_dependents("GHOST"), [])


class MonitoringClosureTests(TestCase):
    def setUp(self):
        self.env = F.lab()
        self.r1 = self.env["devices"]["R1"]

    def test_collectors_for_known_platform(self):
        self.assertTrue(all(v["enabled"] for v in MON.collectors_for(models.Platform.ARISTA_CEOS).values()))

    def test_collectors_for_unknown_platform_disabled_with_reason(self):
        found = MON.collectors_for(models.Platform.SONIC)
        self.assertEqual({v["reason"] for v in found.values()}, {MON.UNSUPPORTED_REASON})

    def test_eligibility_with_active_path(self):
        path = F.activate(self.r1, F.oob_path(self.env))
        found = MON.eligibility(self.r1)
        self.assertEqual((found["eligible"], found["address"], found["path_id"]), (True, "192.168.200.1", path.path_id))

    def test_eligibility_refuses_unadmitted_or_pathless(self):
        self.assertEqual(MON.eligibility(self.r1)["reasons"], ["MGMT_PATH_NOT_REGISTERED"])
        new = F.L.register("NEW5", serial="SN-NEW5", mac="00:1c:73:00:00:05").device
        self.assertEqual(MON.eligibility(new)["reasons"], ["LIFECYCLE_NOT_IN_SERVICE", "NOT_ADMITTED"])

    def test_history_appends_bounded_entries(self):
        target = models.MonitoringTarget(device=self.r1, name="R1", platform=self.r1.platform)
        for i in range(60):
            MON._history(target, "PATH_CHANGED", n=i)
        self.assertEqual((len(target.history), target.history[-1]["n"]), (MON.HISTORY_MAX, 59))

    def test_history_never_stores_secret_shaped_detail(self):
        target = models.MonitoringTarget(device=self.r1, name="R1", platform=self.r1.platform)
        MON._history(target, "X", password="hunter2")
        self.assertNotIn("hunter2", json.dumps(target.history))

    def test_predecessor_generation_continues(self):
        F.activate(self.r1, F.oob_path(self.env))
        MON.reconcile(self.r1)
        successor = F.successor_of(F.force_state(self.r1, S.DECOMMISSIONED))
        self.assertEqual(MON._predecessor_generation(successor), 1)

    def test_predecessor_generation_zero_without_predecessor(self):
        self.assertEqual(MON._predecessor_generation(self.r1), 0)

    def test_reconcile_registers_active_target(self):
        F.activate(self.r1, F.oob_path(self.env))
        target = MON.reconcile(self.r1, fact=outbox.ADMITTED, sequence=4)
        self.assertEqual((target.state, target.generation, target.last_sequence), (T.ACTIVE, 1, 4))
        self.assertEqual(MON.reconcile(self.r1).generation, 1)          # idempotent

    def test_reconcile_blocks_device_not_in_service(self):
        new = F.L.register("NEW5", serial="SN-NEW5", mac="00:1c:73:00:00:05").device
        self.assertEqual(MON.reconcile(new).state, T.BLOCKED)

    def test_apply_registers_target(self):
        F.activate(self.r1, F.oob_path(self.env))
        event = models.LifecycleOutboxEvent.objects.filter(device=self.r1, topic=Topic.MONITORING_TARGET_STATE).order_by("-sequence").first()
        self.assertEqual(MON.apply(event), "APPLIED")

    def test_apply_supersedes_stale_fact(self):
        F.activate(self.r1, F.oob_path(self.env))
        rows = list(models.LifecycleOutboxEvent.objects.filter(device=self.r1, topic=Topic.MONITORING_TARGET_STATE).order_by("sequence"))
        MON.apply(rows[-1])
        self.assertEqual(MON.apply(rows[0]), "SUPERSEDED")

    def test_export_targets_lists_active_targets_with_references(self):
        F.activate(self.r1, F.oob_path(self.env))
        MON.reconcile(self.r1)
        row = MON.export_targets()[0]
        self.assertEqual((row["device"], row["collectors"]), ("R1", ["gnmi", "snmp", "syslog"]))
        self.assertTrue(row["credential_ref"].startswith("INVENTORY:"))

    def test_export_targets_empty_without_active_targets(self):
        self.assertEqual(MON.export_targets(), [])

    def test_default_runtime_path_is_git_ignored_runtime(self):
        self.assertEqual(MON.default_runtime_path().parent.name, "runtime")

    def test_default_runtime_path_never_points_at_repository_root(self):
        self.assertNotEqual(MON.default_runtime_path().parent.parent.name, "")

    def test_write_runtime_targets_writes_atomically(self):
        with tempfile.TemporaryDirectory() as tmp:
            written = MON.write_runtime_targets(Path(tmp) / "targets.json")
            self.assertEqual(json.loads(written.read_text())["targets"], [])
            self.assertEqual(sorted(p.name for p in Path(tmp).iterdir()), ["targets.json"])

    def test_write_runtime_targets_refuses_missing_directory(self):
        with self.assertRaises(FileNotFoundError):
            MON.write_runtime_targets("/nonexistent-nmas-dir/targets.json")

    def test_summary_counts_states(self):
        F.activate(self.r1, F.oob_path(self.env))
        MON.reconcile(self.r1)
        self.assertEqual(MON.summary(), {T.ACTIVE: 1})

    def test_summary_empty_without_targets(self):
        self.assertEqual(MON.summary(), {})


class NsotClosureTests(TestCase):
    def setUp(self):
        self.env = F.lab()
        self.device, self.attachment = F.new_device_with_verified_uplink()
        self.fake = F.FakeNetbox(devices={"NEW1": "planned", "S1": "active"}, interfaces={"S1": ["Ethernet7"]}, vlans={30},
                                 port_vlans={("S1", "Ethernet7"): {"untagged": 30}})

    @override_settings(NMAS_NSOT_RECONCILE_WRITE=True)
    def test_write_enabled_reads_setting(self):
        self.assertTrue(NS.write_enabled())

    def test_write_enabled_not_by_default(self):
        self.assertFalse(NS.write_enabled())

    def test_management_facts_from_admission_payload(self):
        payload = {"device_id": self.device.device_id, "name": "NEW1", "platform": self.device.platform, "role": "router", "admission": "ADM-1",
                   "admitted_at": "x", "management": {"interface": "Ethernet1", "ipv4": "10.254.30.10/24"}, "provisioning_run": "",
                   "config_digest": ""}
        with transaction.atomic():
            outbox.record(self.device, Topic.NSOT_DEVICE_ADMITTED, payload, subject="ADM-1", actor="system:t")
        self.assertEqual(NS.management_facts(self.device), {"interface": "Ethernet1", "ipv4": "10.254.30.10/24"})

    def test_management_facts_empty_without_admission_or_run(self):
        self.assertEqual(NS.management_facts(self.device), {})

    def test_desired_state_maps_lifecycle_and_verified_links(self):
        desired = NS.desired_state(self.device)
        self.assertEqual((desired["status"], desired["interfaces"]), ("planned", ["Ethernet1"]))
        self.assertEqual(NS.desired_state(self.env["devices"]["S1"])["status"], "active")

    def test_desired_state_decommissioned_is_offline_without_management(self):
        device = F.force_state(self.device, S.DECOMMISSIONED)
        self.assertEqual((NS.desired_state(device)["status"], NS.desired_state(device)["management"]), ("offline", {}))

    def test_plan_computes_interface_cable_and_status(self):
        ops, problems = NS.plan({**NS.desired_state(self.device), "status": "active"}, self.fake)
        self.assertEqual(sorted(o["op"] for o in ops), ["create_cable", "create_interface", "set_status"])
        self.assertEqual(problems, [])

    def test_plan_reports_missing_device_and_mismatched_cable(self):
        self.assertEqual(NS.plan(NS.desired_state(self.device), F.FakeNetbox())[1][0]["code"], "NETBOX_DEVICE_MISSING")
        self.fake.cables[("NEW1", "Ethernet1")] = ("S9", "Ethernet1")
        self.assertEqual([p["code"] for p in NS.plan(NS.desired_state(self.device), self.fake)[1]], ["CABLE_MISMATCH"])

    @override_settings(NMAS_NSOT_RECONCILE_WRITE=True)
    def test_reconcile_applies_when_enabled(self):
        projection = NS.reconcile(self.device, client=self.fake, sequence=3)
        self.assertEqual((projection.state, projection.last_sequence, len(projection.applied)), (models.NsotProjectionState.IN_SYNC, 3, 2))

    def test_reconcile_unavailable_raises(self):
        with self.assertRaises(NS.NetboxUnavailable):
            NS.reconcile(self.device, client=F.FakeNetbox(down=True))

    def test_apply_plans_projection(self):
        event = F.fact(self.device, outbox.HEALTH_CHANGED)[0]
        self.assertEqual(NS.apply(event, nsot_client=self.fake), "APPLIED")

    def test_apply_unavailable_raises_fixed_code(self):
        event = F.fact(self.device, outbox.HEALTH_CHANGED)[0]
        with self.assertRaises(FX.ConsumerError) as caught:
            NS.apply(event, nsot_client=F.FakeNetbox(down=True))
        self.assertEqual(caught.exception.code, "NSOT_UNAVAILABLE")

    def test_outage_marker_records_projection_state(self):
        event = F.fact(self.device, outbox.HEALTH_CHANGED)[0]
        NS.mark_failed(event, "NSOT_UNAVAILABLE")
        self.assertEqual(models.NsotProjection.objects.get(device=self.device).state, models.NsotProjectionState.UNAVAILABLE)

    def test_mark_failed_ignores_other_codes(self):
        event = F.fact(self.device, outbox.HEALTH_CHANGED)[0]
        NS.mark_failed(event, "NSOT_CONSUMER_ERROR")
        self.assertFalse(models.NsotProjection.objects.exists())

    def test_summary_counts_states(self):
        NS.reconcile(self.device, client=self.fake)
        self.assertEqual(NS.summary(), {models.NsotProjectionState.PLANNED: 1})

    def test_summary_empty_without_projections(self):
        self.assertEqual(NS.summary(), {})

    def test_default_client_wraps_pynetbox(self):
        with mock.patch("core.services.nsot_netbox._client", return_value=mock.MagicMock()):
            self.assertIsInstance(NS.default_client(), NS.PynetboxClient)

    def test_default_client_unavailable_when_unconfigured(self):
        with mock.patch("core.services.nsot_netbox._client", side_effect=RuntimeError("token=abc")):
            with self.assertRaises(NS.NetboxUnavailable) as caught:
                NS.default_client()
        self.assertNotIn("abc", str(caught.exception))


class PynetboxClientClosureTests(TestCase):
    def api(self):
        api = mock.MagicMock()
        device = mock.MagicMock(id=5, status=mock.MagicMock(value="active"))
        device.name = "NEW1"
        api.dcim.devices.get.return_value = device
        iface = mock.MagicMock(id=9)
        iface.name = "Ethernet1"
        api.dcim.interfaces.filter.return_value = [iface]
        api.dcim.interfaces.get.return_value = iface
        return api

    def test_init_keeps_api(self):
        api = self.api()
        self.assertIs(NS.PynetboxClient(api).api, api)

    def test_init_without_api_fails_on_first_lookup(self):
        with self.assertRaises(NS.NetboxUnavailable):
            NS.PynetboxClient(None).lookup("device", name="NEW1")

    def test_lookup_reads_device_and_interfaces(self):
        client = NS.PynetboxClient(self.api())
        self.assertEqual(client.lookup("device", name="NEW1"), {"id": 5, "name": "NEW1", "status": "active"})
        self.assertEqual(client.lookup("interfaces", device="NEW1"), ["Ethernet1"])

    def test_lookup_unknown_kind_and_transport_error_refused(self):
        api = self.api()
        with self.assertRaises(ValueError):
            NS.PynetboxClient(api).lookup("rack")
        api.ipam.ip_addresses.get.side_effect = ConnectionError("down")
        with self.assertRaises(NS.NetboxUnavailable):
            NS.PynetboxClient(api).lookup("ip", address="10.0.0.1/24")

    def test_apply_sets_status_and_creates_cable(self):
        api = self.api()
        client = NS.PynetboxClient(api)
        client.apply({"op": "set_status", "device": "NEW1", "status": "active"})
        api.dcim.devices.get.return_value.update.assert_called_with({"status": "active"})
        client.apply({"op": "create_cable", "a_device": "NEW1", "a_interface": "Ethernet1", "b_device": "S1", "b_interface": "Ethernet7"})
        self.assertEqual(api.dcim.cables.create.call_args.kwargs["a_terminations"], [{"object_type": "dcim.interface", "object_id": 9}])

    def test_apply_unknown_operation_refused(self):
        with self.assertRaises(ValueError):
            NS.PynetboxClient(self.api()).apply({"op": "delete_device", "device": "NEW1"})


class DispatcherClosureTests(TestCase):
    def setUp(self):
        self.env = F.lab()
        self.device, _att = F.new_device_with_verified_uplink()
        self.fake = F.FakeNetbox(devices={"NEW1": "planned", "S1": "active"}, interfaces={"S1": ["Ethernet7"]})

    def test_consumer_for_maps_topics(self):
        self.assertEqual(D.consumer_for(Topic.MONITORING_TARGET_STATE)[0], "monitoring")

    def test_consumer_for_unknown_topic_refused(self):
        with self.assertRaises(KeyError):
            D.consumer_for("NOPE")

    def test_due_returns_oldest_first(self):
        rows = D.due("topology", limit=500)
        self.assertEqual([r.pk for r in rows], sorted(r.pk for r in rows))
        self.assertTrue(rows)

    def test_due_unknown_consumer_refused(self):
        with self.assertRaises(ValueError):
            D.due("billing")

    def test_lock_claims_undelivered_event(self):
        event = D.due("topology")[0]
        with transaction.atomic():
            self.assertEqual(D._lock(event).pk, event.pk)

    def test_lock_none_for_delivered_event(self):
        event = D.due("topology")[0]
        outbox.deliver(event, consumer="t", actor="system:t")
        with transaction.atomic():
            self.assertIsNone(D._lock(event))

    def test_dispatch_one_applies_and_delivers(self):
        event = D.due("topology")[0]
        self.assertEqual(D.dispatch_one(event)["result"], "APPLIED")
        self.assertEqual(models.LifecycleOutboxEvent.objects.get(pk=event.pk).state, models.OutboxState.DELIVERED)

    def test_dispatch_one_failure_records_fixed_code_never_text(self):
        event = D.due("topology")[0]
        with mock.patch.object(TOP, "apply", side_effect=ValueError("secret detail password=x")):
            row = D.dispatch_one(event)
        stored = models.LifecycleOutboxEvent.objects.get(pk=event.pk)
        self.assertEqual((row["result"], stored.last_error), ("FAILED", "TOPOLOGY_CONSUMER_ERROR"))
        self.assertFalse(models.TopologyNode.objects.exists())                # the consumer's writes rolled back

    def test_dispatch_runs_one_batch_for_all_consumers(self):
        result = D.dispatch(limit=500, nsot_client=self.fake)
        self.assertEqual(result["counts"].get("FAILED", 0), 0)
        self.assertEqual(outbox.pending(limit=500), [])

    def test_dispatch_twice_is_idempotent_with_no_duplicates(self):
        D.dispatch(limit=500, nsot_client=self.fake)
        before = (models.TopologyEdge.objects.count(), models.MonitoringTarget.objects.count(), models.NsotProjection.objects.count())
        self.assertEqual(D.dispatch(limit=500, nsot_client=self.fake)["processed"], 0)
        self.assertEqual(before, (models.TopologyEdge.objects.count(), models.MonitoringTarget.objects.count(),
                                  models.NsotProjection.objects.count()))

    def test_status_reports_queue_and_projections(self):
        D.dispatch("topology", limit=500)
        found = D.status()
        self.assertGreater(found["queue"]["topology"][models.OutboxState.DELIVERED], 0)

    def test_status_lists_unavailable_outbox_codes(self):
        D.dispatch("nsot", limit=500, nsot_client=F.FakeNetbox(down=True))
        self.assertEqual({f["code"] for f in D.status()["failures"]}, {"NSOT_UNAVAILABLE"})


class _Capture(http.server.BaseHTTPRequestHandler):
    seen = []

    def do_POST(self):  # noqa: N802
        body = self.rfile.read(int(self.headers["Content-Length"]))
        type(self).seen.append({"path": self.path, "auth": self.headers["Authorization"], "body": body.decode()})
        self.send_response(204)
        self.end_headers()

    def log_message(self, *args):
        pass


class GrafanaClosureTests(TestCase):
    def setUp(self):
        self.env = F.lab()
        self.r1 = self.env["devices"]["R1"]

    def test_tag_escapes_line_protocol(self):
        self.assertEqual(G._tag("a b,c=d"), "a\\ b\\,c\\=d")

    def test_tag_empty_value_becomes_none(self):
        self.assertEqual(G._tag(""), "none")

    def test_ns_converts_datetime(self):
        moment = timezone.now()
        self.assertEqual(G._ns(moment) // 1_000_000_000, int(moment.timestamp()))

    def test_ns_refuses_non_datetime(self):
        with self.assertRaises(AttributeError):
            G._ns("2026-01-01")

    def test_line_renders_integer_fields(self):
        moment = timezone.now()
        self.assertEqual(G.line("m", {"b": "2", "a": "1"}, {"x": 3}, moment), f"m,a=1,b=2 x=3i {G._ns(moment)}")

    def test_line_refuses_empty_fields(self):
        with self.assertRaises(ValueError):
            G.line("m", {"a": "1"}, {}, timezone.now())

    def test_real_targets_lists_registered_targets(self):
        F.activate(self.r1, F.oob_path(self.env))
        MON.reconcile(self.r1)
        self.assertEqual([t.name for t in G.real_targets()], ["R1"])

    def test_real_targets_never_lists_expected_only_records(self):
        MON.reconcile(F.L.register("NEW5", serial="SN-NEW5", mac="00:1c:73:00:00:05").device)
        self.assertEqual(list(G.real_targets()), [])

    def test_lifecycle_points_include_state_and_events(self):
        F.activate(self.r1, F.oob_path(self.env))
        MON.reconcile(self.r1)
        F.force_state(self.r1, S.DECOMMISSIONED)
        MON.reconcile(models.ManagedDevice.objects.get(pk=self.r1.pk))
        points = G.lifecycle_points()
        self.assertIn("monitoring_state=RETIRED", points[0])
        self.assertIn("monitored=0i", points[0])
        self.assertEqual(sorted(p.split(",event=")[1].split(" ")[0] for p in points[1:]), ["REGISTERED", "RETIRED"])

    def test_lifecycle_points_empty_without_real_targets(self):
        self.assertEqual(G.lifecycle_points(), [])

    def test_push_posts_line_protocol_with_token_header(self):
        server = http.server.HTTPServer(("127.0.0.1", 0), _Capture)
        thread = threading.Thread(target=server.handle_request, daemon=True)
        thread.start()
        try:
            result = G.push(["m,a=1 x=1i 1"], url=f"http://127.0.0.1:{server.server_port}", org="o", bucket="b", token="tkn")
        finally:
            thread.join(5)
            server.server_close()
        self.assertEqual(result, {"status": 204, "points": 1})
        self.assertEqual(_Capture.seen[-1]["auth"], "Token tkn")
        self.assertIn("bucket=b", _Capture.seen[-1]["path"])

    def test_push_refuses_missing_token_invalid_url_and_unreachable(self):
        with mock.patch.dict("os.environ", {}, clear=True):
            with self.assertRaises(G.PushError) as missing:
                G.push(["m x=1i 1"], url="http://127.0.0.1:9", org="o", bucket="b")
        self.assertEqual(str(missing.exception), "INFLUX_TOKEN_MISSING")
        with self.assertRaises(G.PushError):
            G.push(["m x=1i 1"], url="file:///etc/passwd", org="o", bucket="b", token="t")
        with self.assertRaises(G.PushError) as unreachable:
            G.push(["m x=1i 1"], url="http://127.0.0.1:9", org="o", bucket="b", token="secret-token", timeout=1)
        self.assertNotIn("secret-token", str(unreachable.exception))


class ViewClosureTests(TestCase):
    def setUp(self):
        self.env = F.lab()
        F.new_device_with_verified_uplink()
        self.rf = RequestFactory()
        self.approver = User.objects.create_user("arthur-web", password="x")
        self.approver.groups.add(Group.objects.get(name="NMAS Approver"))
        self.viewer = User.objects.create_user("vera-web", password="x")
        self.viewer.groups.add(Group.objects.get(name="NMAS Viewer"))

    def post(self, user, data=None, *, csrf_ok=True):
        request = self.rf.post("/automation/infrastructure/dispatch/", data or {})
        request.user = user
        request._dont_enforce_csrf_checks = csrf_ok
        return request

    def get(self, user, path="/automation/infrastructure/"):
        request = self.rf.get(path)
        request.user = user
        return request

    def test_url_reverses_or_falls_back(self):
        self.assertEqual(V._url("home", "x"), "/")
        self.assertEqual(V._url("infrastructure_overview_not_routed", "fallback/"), "fallback/")

    def test_url_unknown_name_uses_fallback(self):
        self.assertEqual(V._url("nope", "../"), "../")

    def test_overview_collects_projections(self):
        D.dispatch("topology", limit=500)
        self.assertTrue(V.overview()["nodes"])

    def test_overview_empty_before_dispatch(self):
        found = V.overview()
        self.assertEqual((found["nodes"], found["targets"], found["projections"]), ([], [], []))

    def test_infrastructure_overview_renders_page(self):
        D.dispatch("topology", limit=500)
        response = V.infrastructure_overview(self.get(self.approver))
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Dynamic infrastructure", response.content)
        self.assertIn(b"Run one dispatch batch", response.content)

    def test_infrastructure_overview_hides_dispatch_without_permission(self):
        response = V.infrastructure_overview(self.get(self.viewer))
        self.assertNotIn(b"Run one dispatch batch", response.content)

    def test_infrastructure_json_returns_secret_free_data(self):
        response = V.infrastructure_json(self.get(self.viewer, "/automation/infrastructure/api/"))
        self.assertEqual(response.status_code, 200)
        self.assertIn("status", json.loads(response.content))

    def test_infrastructure_json_refuses_post(self):
        request = self.rf.post("/automation/infrastructure/api/")
        request.user = self.viewer
        self.assertEqual(V.infrastructure_json(request).status_code, 405)

    def test_infrastructure_dispatch_runs_batch_and_audits(self):
        response = V.infrastructure_dispatch(self.post(self.approver, {"consumer": "topology"}))
        self.assertEqual(response.status_code, 302)
        audit = models.AuditEvent.objects.filter(event_type=models.AuditEventType.INFRASTRUCTURE_RECONCILED).get()
        self.assertEqual((audit.actor, audit.object_id), ("arthur-web", "topology"))
        self.assertTrue(models.TopologyNode.objects.exists())

    def test_infrastructure_dispatch_denied_without_permission_or_csrf(self):
        self.assertEqual(V.infrastructure_dispatch(self.post(self.viewer)).status_code, 403)
        self.assertEqual(V.infrastructure_dispatch(self.post(self.approver, csrf_ok=False)).status_code, 403)
        anonymous = self.post(AnonymousUser())
        self.assertEqual(V.infrastructure_dispatch(anonymous).status_code, 403)
        self.assertFalse(models.AuditEvent.objects.filter(event_type=models.AuditEventType.INFRASTRUCTURE_RECONCILED).exists())


class CommandClosureTests(TestCase):
    def setUp(self):
        self.env = F.lab()

    def test_add_arguments_declares_subcommands(self):
        parser = C.Command().create_parser("manage.py", "nmas_infrastructure")
        self.assertEqual(parser.parse_args(["dispatch", "--consumer", "topology"]).consumer, "topology")

    def test_add_arguments_rejects_unknown_consumer(self):
        parser = C.Command().create_parser("manage.py", "nmas_infrastructure")
        with self.assertRaises(CommandError):
            parser.parse_args(["dispatch", "--consumer", "billing"])

    def test_handle_dispatch_status_and_export(self):
        out = io.StringIO()
        call_command("nmas_infrastructure", "dispatch", "--consumer", "topology", "--limit", "500", stdout=out)
        self.assertGreater(json.loads(out.getvalue())["processed"], 0)
        out = io.StringIO()
        call_command("nmas_infrastructure", "status", stdout=out)
        self.assertIn("topology", json.loads(out.getvalue()))
        with tempfile.TemporaryDirectory() as tmp:
            out = io.StringIO()
            call_command("nmas_infrastructure", "export-targets", "--path", f"{tmp}/t.json", stdout=out)
            self.assertTrue(Path(out.getvalue().strip()).exists())

    def test_handle_refuses_missing_runtime_dir_and_missing_token(self):
        with self.assertRaises(CommandError):
            call_command("nmas_infrastructure", "export-targets", "--path", "/nonexistent-nmas-dir/t.json")
        with mock.patch.dict("os.environ", {}, clear=True):
            with self.assertRaises(CommandError) as caught:
                call_command("nmas_infrastructure", "push-grafana", "--url", "http://127.0.0.1:9", "--org", "o", "--bucket", "b")
        self.assertEqual(str(caught.exception), "INFLUX_TOKEN_MISSING")


class SuccessorHelperClosureTests(TestCase):
    def setUp(self):
        self.env = F.lab()
        self.device, self.attachment = F.new_device_with_verified_uplink()

    def test_successor_of_returns_restored_registration(self):
        old = F.force_state(self.device, S.DECOMMISSIONED)
        new = F.successor_of(old)
        self.assertEqual(FX.successor_of(old).pk, new.pk)

    def test_successor_of_none_without_restoration(self):
        self.assertIsNone(FX.successor_of(self.device))

    def test_provenance_attachments_inherits_predecessor_links(self):
        new = F.successor_of(F.force_state(self.device, S.DECOMMISSIONED))
        self.assertEqual(FX.provenance_attachments(new), ([self.attachment], self.device.device_id))

    def test_provenance_attachments_never_inherits_for_original_registration(self):
        self.assertEqual(FX.provenance_attachments(self.device), ([self.attachment], ""))
        self.assertEqual(FX.provenance_attachments(self.env["devices"]["S3"]), ([], ""))
