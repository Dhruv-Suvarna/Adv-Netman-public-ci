"""V2 Phase 8 -- the NetworkX topology is reconstructable: what the dispatcher builds fact by fact equals what ``rebuild()``
derives from the database alone, and replaying every fact changes nothing.

Found against the live NetBox run (docs/evidence/v2-phase8-closure): an adopted legacy switch that emitted no fact since Phase 8
(``mgmt_swt``) had no node, so the incremental graph showed it UNMANAGED while a rebuild showed it IN_SERVICE.
"""

from __future__ import annotations

from django.test import TestCase

from core import models
from core.services.infrastructure import dispatcher, topology
from core.tests import test_infrastructure_fixtures as F


def signature() -> dict:
    g = topology.graph()
    return {"nodes": sorted((data["name"], data["state"]) for _n, data in g.nodes(data=True)),
            "edges": sorted((*sorted((g.nodes[a]["name"], g.nodes[b]["name"])), data["kind"]) for a, b, data in g.edges(data=True))}


class ReconstructionTests(TestCase):
    def setUp(self):
        self.env = F.lab()
        self.r1 = self.env["devices"]["R1"]

    def test_peer_without_its_own_fact_is_the_managed_node_and_rebuild_reproduces_the_graph(self):
        F.activate(self.r1, F.oob_path(self.env))
        F.new_device_with_verified_uplink()
        dispatcher.dispatch("topology", limit=500)
        incremental = signature()
        self.assertIn(("mgmt_swt", models.TopologyNodeState.IN_SERVICE), incremental["nodes"])
        self.assertNotIn("UNMANAGED", {state for _name, state in incremental["nodes"]})
        models.TopologyEdge.objects.all().delete()
        models.TopologyNode.objects.all().delete()
        topology.rebuild()
        self.assertEqual(signature(), incremental)

    def test_replaying_every_delivered_fact_changes_nothing(self):
        F.activate(self.r1, F.oob_path(self.env))
        dispatcher.dispatch("topology", limit=500)
        before, rows = signature(), models.TopologyEdge.objects.count()
        models.LifecycleOutboxEvent.objects.filter(topic=models.OutboxTopic.TOPOLOGY_DEVICE_STATE).update(state=models.OutboxState.PENDING)
        result = dispatcher.dispatch("topology", limit=500)
        self.assertTrue(set(result["counts"]) <= {"APPLIED", "SUPERSEDED"}, result["counts"])
        self.assertEqual((signature(), models.TopologyEdge.objects.count()), (before, rows))

    def test_an_unmanaged_inventory_peer_never_becomes_a_managed_node(self):
        F.activate(self.r1, F.vrf_path(self.r1, self.env))         # routed path: peer is NMAS's own attachment, not a device
        dispatcher.dispatch("topology", limit=500)
        names = {name: state for name, state in signature()["nodes"]}
        unmanaged = [name for name in names if name.startswith("nmas:")]
        self.assertTrue(unmanaged)
        self.assertTrue(all(names[name] == topology.UNMANAGED for name in unmanaged))
