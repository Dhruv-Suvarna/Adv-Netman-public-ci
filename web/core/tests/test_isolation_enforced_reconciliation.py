"""RECONCILED_AS_ENFORCED: an interrupted trusted-isolation APPLY run whose policy is proven enforced (Lab 8 R7 / CHG-20261027-0008).

Pure gate (``problems``), mark binding (``is_reconciled_as_enforced``), the narrow ``unresolved_runs`` scope, and the cEOS RIP
control-plane regression: a RIP process active on the isolated port's subnet, or a route learned through it, fails ROUTING, so
an unadmitted device's RIP can never satisfy the reconciliation.
"""

import json
from datetime import timedelta
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase
from django.utils import timezone

from core import models
from core.services.execution.codes import Outcome
from core.services.isolation import eos, enforced_reconciliation as er, transaction

NOW = timezone.now()
ALL_OK = {kind: {"ok": True, "code": ""} for kind in er.REQUIRED_CHECKS}


def _fixture(**overrides):
    change = SimpleNamespace(pk=8, change_id="CHG-20261027-0008",
                             metadata={"transition": {"kind": er.APPLY_KIND, "policy": "ISO-000002", "device": "DEV-000003"}})
    run = SimpleNamespace(run_id="5a7efcc5-b89a-4311-9181-fca2d880c2b2", change=change, change_id=8,
                          state=models.ExecutionRunState.FINISHED, outcome=Outcome.INTERRUPTED, plan_hash="e35f")
    device = SimpleNamespace(pk=3, device_id="DEV-000003", identity_state=models.IdentityVerificationState.VERIFIED,
                             expected_serial="NMASDEMO7", verified_serial="NMASDEMO7",
                             expected_base_mac="02:5a:de:00:00:07", verified_base_mac="02:5A:DE:00:00:07")
    policy = SimpleNamespace(policy_id="ISO-000002", apply_change_id=8, device_id=3, device=device, plan_hash="e35f",
                             intent_hash="ih", state="VERIFIED", enforced_at=NOW - timedelta(days=7))
    verification = {"at": (NOW - timedelta(seconds=30)).isoformat(), "with_device": True, "checks": json.loads(json.dumps(ALL_OK))}
    args = {"policy": policy, "run": run, "device": device, "approved_plan_hash": "e35f", "verification": verification,
            "now": NOW, "max_age_seconds": 3600.0}
    args.update(overrides)
    return args


def _codes(args):
    return [p["code"] for p in er.problems(**args)]


class GateTests(SimpleTestCase):
    def test_enforced_interrupted_apply_with_fresh_complete_evidence_passes(self):
        self.assertEqual(_codes(_fixture()), [])

    def test_run_that_is_not_interrupted_is_refused(self):
        args = _fixture()
        args["run"].outcome = Outcome.SUCCEEDED
        self.assertIn("RECONCILE_RUN_NOT_INTERRUPTED", _codes(args))

    def test_run_of_another_change_or_policy_is_refused(self):
        args = _fixture()
        args["policy"].apply_change_id = 99
        self.assertIn("RECONCILE_WRONG_POLICY", _codes(args))
        args = _fixture()
        args["run"].change.metadata["transition"]["policy"] = "ISO-000009"
        self.assertIn("RECONCILE_WRONG_POLICY", _codes(args))

    def test_wrong_device_identity_is_refused(self):
        for field, value in (("verified_serial", "OTHER"), ("verified_base_mac", "02:00:00:00:00:99"),
                             ("identity_state", models.IdentityVerificationState.UNVERIFIED)):
            args = _fixture()
            setattr(args["device"], field, value)
            self.assertIn("RECONCILE_IDENTITY_MISMATCH", _codes(args), field)
        args = _fixture()
        args["policy"].device_id = 4
        self.assertIn("RECONCILE_IDENTITY_MISMATCH", _codes(args))

    def test_wrong_plan_hash_is_refused(self):
        for target, value in (("run", "beef"), ("policy", "beef")):
            args = _fixture()
            args[target].plan_hash = value
            self.assertIn("RECONCILE_PLAN_HASH_MISMATCH", _codes(args), target)
        self.assertIn("RECONCILE_PLAN_HASH_MISMATCH", _codes(_fixture(approved_plan_hash="beef")))

    def test_insufficient_evidence_is_refused(self):
        args = _fixture()
        del args["verification"]["checks"]["TRAFFIC"]
        self.assertIn("RECONCILE_EVIDENCE_INSUFFICIENT", _codes(args))
        args = _fixture()
        args["verification"]["with_device"] = False
        self.assertIn("RECONCILE_EVIDENCE_INSUFFICIENT", _codes(args))
        self.assertIn("RECONCILE_EVIDENCE_INSUFFICIENT", _codes(_fixture(verification=None)))

    def test_actual_drift_is_refused(self):
        args = _fixture()
        args["verification"]["checks"]["READ_BACK"] = {"ok": False, "code": "ISOLATION_DRIFTED"}
        self.assertIn("RECONCILE_DRIFT", _codes(args))
        args = _fixture()
        args["policy"].state = "DRIFTED"
        self.assertIn("RECONCILE_POLICY_NOT_ENFORCED", _codes(args))

    def test_stale_observation_is_refused(self):
        args = _fixture()
        args["verification"]["at"] = (NOW - timedelta(hours=2)).isoformat()
        self.assertIn("RECONCILE_EVIDENCE_STALE", _codes(args))
        args = _fixture()
        args["policy"].enforced_at = NOW - timedelta(seconds=5)
        self.assertIn("RECONCILE_EVIDENCE_STALE", _codes(args))

    def test_routing_leak_including_rip_is_refused(self):
        args = _fixture()
        args["verification"]["checks"]["ROUTING"] = {"ok": False, "code": "ISOLATION_LEAK"}
        self.assertIn("ISOLATION_LEAK", _codes(args))


class _Marks(list):
    def order_by(self, *_):
        return self


class MarkBindingTests(SimpleTestCase):
    def _check(self, *, meta_overrides=None, state="VERIFIED"):
        args = _fixture()
        policy, run, device = args["policy"], args["run"], args["device"]
        policy.state = state
        meta = {"reconciliation": er.MARK, **er.binding(policy, run, device), **(meta_overrides or {})}
        query = mock.Mock()
        query.select_related.return_value.first.return_value = policy
        with mock.patch.object(er, "_marks", return_value=_Marks([SimpleNamespace(metadata=meta)])), \
                mock.patch.object(er.models.IsolationPolicy.objects, "filter", return_value=query):
            return er.is_reconciled_as_enforced(run)

    def test_matching_mark_resolves_the_run(self):
        self.assertTrue(self._check())

    def test_mark_bound_to_another_plan_hash_or_device_does_not_resolve(self):
        self.assertFalse(self._check(meta_overrides={"plan_hash": "beef"}))
        self.assertFalse(self._check(meta_overrides={"serial": "OTHER"}))

    def test_mark_does_not_survive_later_drift(self):
        self.assertFalse(self._check(state="DRIFTED"))
        self.assertFalse(self._check(state="UNCERTAIN"))

    def test_no_mark_means_unresolved(self):
        args = _fixture()
        with mock.patch.object(er, "_marks", return_value=_Marks([])):
            self.assertFalse(er.is_reconciled_as_enforced(args["run"]))


class UnresolvedScopeTests(SimpleTestCase):
    def test_only_the_marked_run_stops_blocking(self):
        ours = SimpleNamespace(run_id="ours", devices=["R6"], change=SimpleNamespace(
            change_id="CHG-A", metadata={"transition": {"kind": er.APPLY_KIND}}))
        other = SimpleNamespace(run_id="other", devices=["R6"], change=SimpleNamespace(
            change_id="CHG-B", metadata={"transition": {"kind": er.APPLY_KIND}}))
        query = mock.Mock()
        query.select_related.return_value = [ours, other]
        with mock.patch.object(transaction.models.ChangeExecutionRun.objects, "exclude", return_value=query), \
                mock.patch.object(er, "is_reconciled_as_enforced", side_effect=lambda run: run is ours), \
                mock.patch.object(transaction, "reconciled", return_value=False, create=True):
            self.assertEqual(transaction.unresolved_runs("R6"), ["CHG-B"])


R6_RUNNING = """interface Ethernet2
   no switchport
   ip address 10.254.96.1/29
   ip access-group NMAS-ISO-DEV-000003-V4 in
!
router rip
   network 10.254.96.0/29
   {state}
!
"""


class CeosRipControlPlaneRegressionTests(SimpleTestCase):
    def test_active_rip_on_the_isolated_port_is_a_routing_failure(self):
        facts = eos.routing_facts(R6_RUNNING.format(state="no shutdown"), "Ethernet2")
        self.assertEqual([u["protocol"] for u in facts["unsupported"]], ["RIP"])

    def test_suspended_rip_does_not_reach_the_isolated_port(self):
        facts = eos.routing_facts(R6_RUNNING.format(state="shutdown"), "Ethernet2")
        self.assertEqual(facts["unsupported"], [])

    def test_a_rip_route_learned_through_the_isolated_port_is_a_leak(self):
        table = {"vrfs": {"default": {"routes": {
            "10.254.10.0/24": {"routeType": "RIP", "vias": [{"nexthopAddr": "10.254.96.2", "interface": "Ethernet2"}]},
            "10.254.96.0/29": {"routeType": "connected", "vias": [{"interface": "Ethernet2"}]},
            "10.254.90.0/29": {"routeType": "connected", "vias": [{"interface": "Ethernet1"}]}}}}}
        self.assertEqual(eos.routes_via(json.dumps(table), "Ethernet2", ["10.254.96.1/29"]), ["10.254.10.0/24"])
