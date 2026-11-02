"""V2 Phase 6: the generic commissioning dependency graph (no device name is special): add / remove / derive, cycle refusal,
ordering and satisfaction -- the R4 -> R6 -> R7 shape with arbitrary names."""

from __future__ import annotations

from django.test import SimpleTestCase, TestCase

from core import models
from core.services.commissioning import dependencies as D
from core.tests.helpers import lifecycle as L

K = models.DependencyKind


def new(name, n):
    return L.register(name, serial=f"SN-{name}", mac=f"00:1c:73:00:01:{n:02x}").device


def set_state(device, **fields):
    models.ManagedDevice.objects.compare_and_swap(device.pk, device.version, **fields)
    device.refresh_from_db()


class GraphTests(SimpleTestCase):
    def test_reaches_cycles_and_order(self):
        graph = {3: {2}, 2: {1}}
        self.assertTrue(D.reaches(graph, 3, 1))
        self.assertFalse(D.reaches(graph, 1, 3))
        self.assertEqual(D.cycles(graph), [])
        self.assertEqual(D.order([3, 2, 1], graph), [1, 2, 3])
        self.assertEqual(D.order([3, 1], graph), [1, 3])                     # only the wanted devices are ordered
        cyclic = {1: {2}, 2: {3}, 3: {1}}
        self.assertEqual(len(D.cycles(cyclic)), 1)
        with self.assertRaises(ValueError):
            D.order([1, 2, 3], cyclic)


class DependencyTests(TestCase):
    def setUp(self):
        L.adopt("R4", role="router")
        self.legacy = models.ManagedDevice.objects.get(name="R4")
        self.mid, self.leaf = new("CORE-A", 1), new("EDGE-B", 2)

    def test_add_is_idempotent_and_recorded(self):
        first = D.add(self.leaf, self.mid, kind=K.DECLARED, actor=L.OPERATOR, reason="EDGE-B rides on CORE-A")
        self.assertTrue(first.ok)
        self.assertEqual(D.add(self.leaf, self.mid, kind=K.DECLARED, actor=L.OPERATOR).dependency.pk, first.dependency.pk)
        self.assertTrue(self.leaf.lifecycle_events.filter(action="COM_DEPENDENCY_ADD", outcome="RECORDED").exists())

    def test_add_refuses_self_unknown_kind_and_cycles(self):
        self.assertEqual(D.add(self.leaf, self.leaf, kind=K.DECLARED, actor=L.OPERATOR).codes, ["COMMISSIONING_DEPENDENCY_INVALID"])
        self.assertEqual(D.add(self.leaf, self.mid, kind="NOPE", actor=L.OPERATOR).codes, ["COMMISSIONING_DEPENDENCY_INVALID"])
        self.assertEqual(D.add(self.leaf, None, kind=K.DECLARED, actor=L.OPERATOR).codes, ["COMMISSIONING_DEPENDENCY_INVALID"])
        self.assertTrue(D.add(self.leaf, self.mid, kind=K.DECLARED, actor=L.OPERATOR).ok)
        third = new("AGG-C", 3)
        self.assertTrue(D.add(self.mid, third, kind=K.DECLARED, actor=L.OPERATOR).ok)
        self.assertEqual(D.add(third, self.leaf, kind=K.DECLARED, actor=L.OPERATOR).codes, ["COMMISSIONING_DEPENDENCY_CYCLE"])
        self.assertEqual(D.cycles(), [])

    def test_unmet_until_the_upstream_is_admitted(self):
        D.add(self.leaf, self.mid, kind=K.DECLARED, actor=L.OPERATOR)
        D.add(self.mid, self.legacy, kind=K.DECLARED, actor=L.OPERATOR)
        self.assertEqual([b["code"] for b in D.unmet(self.leaf)], ["COMMISSIONING_DEPENDENCY_UNMET"])
        self.assertEqual(D.unmet(self.mid), [])                               # a legacy in-service device satisfies
        set_state(self.mid, lifecycle_state=models.DeviceLifecycleState.IN_SERVICE, admission_state=models.ProductionAdmissionState.ADMITTED)
        ok, reason = D.satisfied(self.mid)
        self.assertFalse(ok)                                                  # admitted is claimed, but no admission record
        self.assertIn("without an ADMITTED", reason)
        self.assertEqual(D.order([self.leaf.pk, self.mid.pk]), [self.mid.pk, self.leaf.pk])

    def test_satisfied_reasons(self):
        self.assertFalse(D.satisfied(None)[0])
        self.assertIn("REGISTERED", D.satisfied(self.mid)[1])
        self.assertTrue(D.satisfied(self.legacy)[0])

    def test_remove_requires_a_reason_and_keeps_history(self):
        row = D.add(self.leaf, self.mid, kind=K.DECLARED, actor=L.OPERATOR).dependency
        self.assertEqual(D.remove(row, actor=L.OPERATOR, reason="").codes, ["COMMISSIONING_DEPENDENCY_INVALID"])
        removed = D.remove(row, actor=L.OPERATOR, reason="re-cabled")
        self.assertEqual(removed.dependency.state, models.DependencyState.REMOVED)
        self.assertEqual(D.remove(removed.dependency, actor=L.OPERATOR, reason="again").codes, ["COMMISSIONING_DEPENDENCY_INVALID"])
        with self.assertRaises(ValueError):
            row.delete()

    def test_derive_from_attachments_on_natively_onboarded_upstreams_only(self):
        # an attachment on a NEW device is accepted only once that device is IN_SERVICE and ADMITTED (Phase 2 rule); before that
        # the operator declares the dependency instead
        refused = L.attach(self.leaf, upstream="CORE-A", port="Ethernet3", vlan=None, connectivity=models.AttachmentConnectivity.ROUTED)
        self.assertIn("UPSTREAM_NOT_TRUSTED", refused.codes)
        set_state(self.mid, lifecycle_state=models.DeviceLifecycleState.IN_SERVICE, admission_state=models.ProductionAdmissionState.ADMITTED)
        self.assertTrue(L.attach(self.leaf, upstream="CORE-A", port="Ethernet3", vlan=None,
                                 connectivity=models.AttachmentConnectivity.ROUTED).ok)
        L.attach(self.mid, upstream="R4", port="Ethernet5", vlan=None, connectivity=models.AttachmentConnectivity.ROUTED)
        results = D.derive(self.leaf, actor=L.OPERATOR)
        self.assertEqual([(r.dependency.upstream.name, r.dependency.kind) for r in results if r.ok], [("CORE-A", K.ATTACHMENT_UPSTREAM)])
        self.assertEqual(D.derive(self.mid, actor=L.OPERATOR), [])           # a legacy upstream implies no row
        row = results[0].dependency
        self.assertIn("still live", str(D.remove(row, actor=L.OPERATOR, reason="x").blockers))
        view = D.graph_view([self.leaf])
        # no ADMITTED ProductionAdmission row backs CORE-A's state here: the edge is still unsatisfied
        self.assertEqual([(e["device"], e["upstream"], e["satisfied"]) for e in view["edges"]], [("EDGE-B", "CORE-A", False)])
        self.assertEqual(view["cycles"], [])
