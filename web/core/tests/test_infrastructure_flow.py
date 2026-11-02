"""V2 Phase 8 behaviour: lifecycle facts -> outbox -> dispatcher -> NetBox / topology / monitoring projections.

Application database and in-memory fakes only (``FakeNetbox``): these prove the contracts, not the live NetBox.
"""

from __future__ import annotations

from datetime import timedelta

from django.db import transaction
from django.test import TestCase, override_settings
from django.utils import timezone

from core import models
from core.services.commissioning import outbox
from core.services.infrastructure import dispatcher, grafana, monitoring, nsot, topology
from core.tests import test_infrastructure_fixtures as F

S, A, T, N = models.DeviceLifecycleState, models.ProductionAdmissionState, models.MonitoringTargetState, models.TopologyNodeState
Topic = models.OutboxTopic


class FactEmissionTests(TestCase):
    def test_lifecycle_actions_emit_ordered_facts_for_every_consumer(self):
        F.L.adopt()
        device, _attachment = F.new_device_with_verified_uplink()
        rows = models.LifecycleOutboxEvent.objects.filter(device=device, topic=Topic.TOPOLOGY_DEVICE_STATE).order_by("sequence")
        facts_seen = [r.payload["fact"] for r in rows]
        self.assertEqual(facts_seen[0], "ATTACHMENT_CHANGED")
        self.assertIn("DISCOVERED", facts_seen)
        self.assertEqual([r.sequence for r in rows], list(range(1, len(rows) + 1)))
        self.assertEqual(models.LifecycleOutboxEvent.objects.filter(device=device, sequence=1).count(), 3)
        self.assertTrue(all(r.contract_version == 2 for r in rows))

    def test_refused_and_outbox_actions_never_emit_facts(self):
        device = F.L.register().device
        before = models.LifecycleOutboxEvent.objects.count()
        F.L.attach(device, upstream="NOPE")                                     # refused: unknown upstream
        self.assertEqual(models.LifecycleOutboxEvent.objects.count(), before)
        self.assertEqual(outbox.fact_for_action("OUTBOX_DELIVER", models.DeviceLifecycleEventOutcome.RECORDED), "")
        self.assertEqual(outbox.fact_for_action("DECOMMISSION", models.DeviceLifecycleEventOutcome.ADVANCED), "")

    def test_secret_shaped_detail_is_refused(self):
        device = F.L.register().device
        with self.assertRaises(outbox.OutboxError):
            F.fact(device, outbox.DECOMMISSION_REQUESTED, {"password": "hunter2"})
        self.assertFalse(models.LifecycleOutboxEvent.objects.filter(device=device).exists())


class TopologyTests(TestCase):
    def setUp(self):
        self.env = F.lab()

    def test_verified_attachment_creates_one_production_edge_and_repeats_create_no_duplicates(self):
        device, attachment = F.new_device_with_verified_uplink()
        first = dispatcher.dispatch("topology", limit=100)
        self.assertNotIn("FAILED", first["counts"])
        edges = models.TopologyEdge.objects.filter(device=device, kind=models.TopologyEdgeKind.PRODUCTION)
        self.assertEqual([(e.peer, e.peer_interface, e.active, e.source) for e in edges], [("S1", "Ethernet7", True, f"ATT-{attachment.pk:06d}")])
        F.fact(device, outbox.ATTACHMENT_CHANGED)
        dispatcher.dispatch("topology", limit=100)
        topology.rebuild()
        self.assertEqual(models.TopologyEdge.objects.filter(device=device).count(), 1)
        self.assertEqual(models.TopologyNode.objects.filter(device=device).count(), 1)
        g = topology.graph()
        self.assertTrue(g.has_edge(device.device_id, self.env["devices"]["S1"].device_id))
        self.assertEqual(g.nodes[device.device_id]["state"], N.DISCOVERED)

    def test_unverified_attachment_never_creates_an_edge(self):
        device, _attachment = F.new_device_with_verified_uplink(verify=False)
        dispatcher.dispatch("topology", limit=100)
        self.assertFalse(models.TopologyEdge.objects.filter(device=device).exists())
        self.assertEqual(topology.downstream_dependents("S1"), [])

    def test_decommission_deactivates_edges_and_a_restored_successor_reactivates_inbound_edges(self):
        device, _att = F.new_device_with_verified_uplink()
        dispatcher.dispatch("topology", limit=100)
        self.assertEqual([d["name"] for d in topology.downstream_dependents("S1")], ["NEW1"])
        s1 = F.force_state(self.env["devices"]["S1"], S.DECOMMISSIONED)
        F.fact(s1, outbox.DECOMMISSIONED)
        dispatcher.dispatch("topology", limit=100)
        self.assertFalse(models.TopologyEdge.objects.get(device=device).active)
        self.assertEqual(models.TopologyNode.objects.get(device=s1).state, N.DECOMMISSIONED)
        successor = F.successor_of(s1, admission=A.LEGACY_PREEXISTING)
        F.fact(successor, outbox.RESTORED)
        dispatcher.dispatch("topology", limit=100)
        self.assertTrue(models.TopologyEdge.objects.get(device=device).active)
        self.assertEqual(topology.graph().nodes[successor.device_id]["state"], N.IN_SERVICE)

    def test_out_of_order_fact_is_superseded_without_regressing(self):
        device, _att = F.new_device_with_verified_uplink()
        old = models.LifecycleOutboxEvent.objects.filter(device=device, topic=Topic.TOPOLOGY_DEVICE_STATE).order_by("sequence").first()
        newest = models.LifecycleOutboxEvent.objects.filter(device=device, topic=Topic.TOPOLOGY_DEVICE_STATE).order_by("-sequence").first()
        self.assertEqual(dispatcher.dispatch_one(newest)["result"], "APPLIED")
        self.assertEqual(dispatcher.dispatch_one(old)["result"], "SUPERSEDED")
        self.assertEqual(models.TopologyNode.objects.get(device=device).last_sequence, newest.sequence)
        self.assertEqual(models.LifecycleOutboxEvent.objects.get(pk=old.pk).state, models.OutboxState.DELIVERED)


class MonitoringTests(TestCase):
    def setUp(self):
        self.env = F.lab()
        self.r1 = self.env["devices"]["R1"]

    def test_failover_bumps_generation_and_changes_address(self):
        oob = F.activate(self.r1, F.oob_path(self.env))
        dispatcher.dispatch("monitoring", limit=200)
        target = models.MonitoringTarget.objects.get(device=self.r1)
        self.assertEqual((target.state, target.address, target.management_path_id, target.generation), (T.ACTIVE, "192.168.200.1", oob.pk, 1))
        vrf = F.vrf_path(self.r1, self.env)
        F.activate(self.r1, vrf, previous=oob, kind=F.K.FAILOVER)
        dispatcher.dispatch("monitoring", limit=200)
        target.refresh_from_db()
        self.assertEqual((target.address, target.management_path_id, target.generation), ("10.99.0.1", vrf.pk, 2))
        self.assertEqual(target.history[-1]["event"], "PATH_CHANGED")
        self.assertTrue(target.history[-1]["reconnect_required"])
        exported = monitoring.export_targets()
        self.assertEqual([(t["device"], t["address"], t["generation"]) for t in exported], [("R1", "10.99.0.1", 2)])
        self.assertNotIn("password", str(exported).lower())

    def test_lost_path_suspends_and_legacy_device_without_paths_is_never_registered(self):
        oob = F.activate(self.r1, F.oob_path(self.env))
        dispatcher.dispatch("monitoring", limit=200)
        F.lose_paths(self.r1, oob)
        F.fact(self.env["devices"]["S3"], outbox.HEALTH_CHANGED)
        dispatcher.dispatch("monitoring", limit=200)
        self.assertEqual(models.MonitoringTarget.objects.get(device=self.r1).state, T.SUSPENDED)
        s3 = models.MonitoringTarget.objects.get(device=self.env["devices"]["S3"])
        self.assertEqual((s3.state, s3.registered_at, s3.address), (T.PENDING, None, ""))

    def test_decommission_retires_and_restored_successor_continues_generation(self):
        F.activate(self.r1, F.oob_path(self.env))
        dispatcher.dispatch("monitoring", limit=200)
        r1 = F.force_state(self.r1, S.DECOMMISSIONED)
        F.fact(r1, outbox.DECOMMISSIONED, {"decommission": "DEC-000001"})
        dispatcher.dispatch("monitoring", limit=200)
        retired = models.MonitoringTarget.objects.get(device=r1)
        self.assertEqual(retired.state, T.RETIRED)
        self.assertEqual([h["event"] for h in retired.history], ["REGISTERED", "RETIRED"])
        successor = F.successor_of(r1)
        F.activate(successor, F.vrf_path(successor, self.env, endpoint="10.99.0.5"))
        F.fact(successor, outbox.RESTORED)
        dispatcher.dispatch("monitoring", limit=200)
        restored = models.MonitoringTarget.objects.get(device=successor)
        self.assertEqual((restored.state, restored.generation, restored.history[-1]["event"]), (T.ACTIVE, 2, "RESTORED"))
        self.assertEqual(models.MonitoringTarget.objects.get(device=r1).state, T.RETIRED)

    def test_maintenance_keeps_target_active_and_flags_it(self):
        F.activate(self.r1, F.oob_path(self.env))
        F.maintenance("R1")
        F.fact(self.r1, outbox.MAINTENANCE_ENTERED)
        dispatcher.dispatch("monitoring", limit=200)
        target = models.MonitoringTarget.objects.get(device=self.r1)
        self.assertEqual(target.state, T.ACTIVE)
        self.assertEqual(target.history[-1]["event"], outbox.MAINTENANCE_ENTERED)
        self.assertTrue(monitoring.export_targets()[0]["maintenance"])

    def test_expected_only_device_yields_no_grafana_point(self):
        F.L.register("NEW9", serial="SN-NEW9", mac="00:1c:73:00:00:09")
        F.fact(models.ManagedDevice.objects.get(name="NEW9"), outbox.DISCOVERED)
        dispatcher.dispatch("monitoring", limit=200)
        self.assertEqual(grafana.lifecycle_points(), [])
        F.activate(self.r1, F.oob_path(self.env))
        dispatcher.dispatch("monitoring", limit=200)
        points = grafana.lifecycle_points()
        self.assertTrue(points[0].startswith("nmas_device_lifecycle,device=R1,"))
        self.assertIn("monitored=1i", points[0])
        self.assertFalse(any("NEW9" in p for p in points))


class NsotTests(TestCase):
    def setUp(self):
        self.env = F.lab()

    def netbox(self, **extra):
        return F.FakeNetbox(devices={"NEW1": "planned", "S1": "active"}, interfaces={"S1": ["Ethernet7"]}, vlans={30},
                            port_vlans={("S1", "Ethernet7"): {"untagged": 30}}, **extra)

    def test_write_disabled_plans_operations_without_writing(self):
        device, _att = F.new_device_with_verified_uplink()
        fake = self.netbox()
        result = dispatcher.dispatch("nsot", limit=100, nsot_client=fake)
        self.assertNotIn("FAILED", result["counts"])
        projection = models.NsotProjection.objects.get(device=device)
        self.assertEqual(projection.state, models.NsotProjectionState.PLANNED)
        self.assertEqual(sorted(op["op"] for op in projection.desired["planned_operations"]), ["create_cable", "create_interface"])
        self.assertEqual(fake.applied, [])

    @override_settings(NMAS_NSOT_RECONCILE_WRITE=True)
    def test_write_enabled_applies_and_converges_in_sync(self):
        device, _att = F.new_device_with_verified_uplink()
        fake = self.netbox()
        dispatcher.dispatch("nsot", limit=100, nsot_client=fake)
        self.assertEqual(models.NsotProjection.objects.get(device=device).state, models.NsotProjectionState.IN_SYNC)
        self.assertEqual(fake.cables[("NEW1", "Ethernet1")], ("S1", "Ethernet7"))
        applied = len(fake.applied)
        F.fact(device, outbox.ATTACHMENT_CHANGED)
        dispatcher.dispatch("nsot", limit=100, nsot_client=fake)
        self.assertEqual(len(fake.applied), applied)                         # nothing duplicated

    def test_missing_management_ip_is_a_discrepancy_never_invented(self):
        desired = {"name": "NEW1", "status": "active", "interfaces": [], "cables": [],
                   "management": {"interface": "Ethernet1", "ipv4": "10.254.30.10/24"}}
        fake = self.netbox()
        ops, problems = nsot.plan(desired, fake)
        self.assertEqual([p["code"] for p in problems], ["MGMT_IP_NOT_IN_IPAM"])
        self.assertFalse(any(op["op"] == "assign_ip" for op in ops))
        self.assertEqual(fake.created_ips, [])

    def test_netbox_unavailable_marks_projection_and_retries_with_backoff(self):
        device, _att = F.new_device_with_verified_uplink()
        result = dispatcher.dispatch("nsot", limit=100, nsot_client=F.FakeNetbox(down=True))
        self.assertEqual({r["code"] for r in result["results"]}, {"NSOT_UNAVAILABLE"})
        self.assertEqual(models.NsotProjection.objects.get(device=device).state, models.NsotProjectionState.UNAVAILABLE)
        dispatcher.dispatch("nsot", limit=100, nsot_client=F.FakeNetbox(down=True))     # second failure -> backoff
        failed = models.LifecycleOutboxEvent.objects.filter(device=device, topic=Topic.NSOT_DEVICE_STATE).first()
        self.assertEqual(failed.attempts, 2)
        self.assertGreater(failed.next_attempt_at, timezone.now())
        self.assertEqual(dispatcher.due("nsot"), [])
        later = dispatcher.due("nsot", now=timezone.now() + timedelta(hours=2))
        self.assertTrue(later)
        dispatcher.dispatch("nsot", limit=100, nsot_client=self.netbox(), now=timezone.now() + timedelta(hours=2))
        self.assertEqual(models.NsotProjection.objects.get(device=device).state, models.NsotProjectionState.PLANNED)


class AdmissionHandoffTests(TestCase):
    def test_admission_topic_event_is_consumed_by_its_consumer(self):
        env = F.lab()
        r1 = env["devices"]["R1"]
        F.activate(r1, F.oob_path(env))
        payload = {"device_id": r1.device_id, "name": "R1", "platform": r1.platform, "admission": "ADM-000009", "address": "192.168.200.1",
                   "management_source": "COMMISSIONING", "checks": ["reachability"]}
        with transaction.atomic():
            event = outbox.record(r1, Topic.MONITORING_TARGET_ADMITTED, payload, subject="ADM-000009", actor="system:test")
        self.assertEqual(dispatcher.dispatch_one(event)["result"], "APPLIED")
        self.assertEqual(models.MonitoringTarget.objects.get(device=r1).state, T.ACTIVE)


class RestoredSuccessorTests(TestCase):
    """Phase 7 restores a decommissioned device as a NEW successor registration (same name, origin RESTORED, predecessor FK)."""

    def setUp(self):
        self.env = F.lab()
        self.device, self.attachment = F.new_device_with_verified_uplink()
        self.fake = F.FakeNetbox(devices={"NEW1": "active", "S1": "active"}, interfaces={"S1": ["Ethernet7"], "NEW1": ["Ethernet1"]},
                                 cables={("NEW1", "Ethernet1"): ("S1", "Ethernet7")})
        D = dispatcher
        D.dispatch(limit=500, nsot_client=self.fake)
        self.old = F.force_state(self.device, S.DECOMMISSIONED)
        F.fact(self.old, outbox.DECOMMISSIONED, {"decommission": "DEC-000001"})
        D.dispatch(limit=500, nsot_client=self.fake)
        self.new = F.successor_of(self.old, admission=A.ADMITTED)
        F.fact(self.new, outbox.RESTORED, {"restoration": "RST-000001"})
        D.dispatch(limit=500, nsot_client=self.fake)

    def test_successor_reactivates_one_node_and_inherited_edge_per_name(self):
        g = topology.graph()
        names = [data["name"] for _node, data in g.nodes(data=True)]
        self.assertEqual(names.count("NEW1"), 1)
        self.assertEqual(g.nodes[self.new.device_id]["state"], N.IN_SERVICE)
        edge = models.TopologyEdge.objects.get(device=self.new)
        self.assertEqual((edge.active, edge.facts["inherited_from"]), (True, self.old.device_id))
        self.assertFalse(models.TopologyEdge.objects.get(device=self.old).active)
        self.assertEqual(models.TopologyNode.objects.get(device=self.old).state, N.DECOMMISSIONED)     # history kept

    def test_replayed_fact_of_old_registration_never_touches_netbox(self):
        applied = len(self.fake.applied)
        F.fact(self.old, outbox.DECOMMISSIONED)
        dispatcher.dispatch("nsot", limit=500, nsot_client=self.fake)
        self.assertEqual(len(self.fake.applied), applied)
        self.assertEqual(models.NsotProjection.objects.get(device=self.old).desired["superseded_by"], self.new.device_id)
        self.assertEqual(models.NsotProjection.objects.get(device=self.new).desired["status"], "active")
