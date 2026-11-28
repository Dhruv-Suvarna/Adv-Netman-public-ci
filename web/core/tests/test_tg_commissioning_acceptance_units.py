"""Direct governance tests for the live commissioning acceptance gates (commissioning/acceptance.py) and the runbook of
nmas_commissioning_acceptance.

A broken lifecycle chain, an unverified identity, an unmet dependency, a DEPLOYING Change, a failed traffic run and an
overdue renewal are FAILs; a missing prerequisite is BLOCKED; a prerequisite a scoped step produces is PLANNED only until the
step is declared completed; nothing here writes or contacts a device.
"""

from __future__ import annotations

from datetime import timedelta
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from core import models
from core.management.commands import nmas_commissioning_acceptance as cmd
from core.services.commissioning import acceptance as A
from core.services.commissioning import dependencies as D
from core.services.devices import attachments, stage_report
from core.tests import test_commissioning_acceptance as T
from core.tests import test_lifecycle_stage_report as SR
from core.tests.helpers import lifecycle as L

HOST_KEY = L.HOST_KEY


def report_for(*, ready=True, host_key=HOST_KEY, reconcile=False):
    return {"verdicts": {"identity": {"verified": {"host_key": host_key, "serial": "SN", "base_mac": "m", "at": None, "by": "x"}},
                         "readiness": {"ready": ready, "reasons": [] if ready else ["lifecycle REGISTERED"]}, "maintenance": {},
                         "management": {"status": "OK", "reconciliation_required": reconcile}}}


class Qs(list):
    def order_by(self, *_):
        return self

    def first(self):
        return self[0] if self else None


def policy_ns(**overrides):
    checks = {k: {"ok": True} for k in ("READ_BACK", "L2", "MANAGEMENT_PLANE", "ROUTING", "ATTACHMENT", "TRAFFIC")}
    base = dict(policy_id="ISO-1", state=models.IsolationState.RELEASED, upstream_device="UP", upstream_interface="Ethernet2",
                upstream_platform="arista_ceos", intent={"elements": {"IPV4": {"acl": "a"}, "IPV6": {"acl": "b"}}},
                verification={"checks": checks}, plan={"ops": [{"line": "x"}]}, verified_at=None, released_at=None,
                apply_change_id=1, release_change_id=2)
    base.update(overrides)
    return SimpleNamespace(**base)


# ================================================================================================ pure helpers
class HelperTests(SimpleTestCase):
    def test_blocker_raises_for_an_unknown_code(self):
        with self.assertRaises(KeyError):
            A.blocker("NOT_A_REGISTERED_CODE")

    def test_scope_digest_of_no_scope_is_the_empty_document_digest(self):
        self.assertEqual(A.scope_digest(None), A.scope_digest({}))

    def test_scoped_operations_of_an_unknown_device_is_empty(self):
        self.assertEqual(A.scoped_operations(T.scope(), "OTHER"), set())

    def test_plan_aware_keeps_a_blocker_that_no_scoped_step_produces(self):
        gate = A._gate("TRAFFIC_BASELINE", A.BLOCKED, ["TRAFFIC_BASELINE_STALE"])
        self.assertIs(A.plan_aware(gate, set(A.OPERATIONS), set()), gate)

    def test_overall_is_ready_when_every_gate_passes(self):
        self.assertEqual(A.overall([{"status": A.PASS}, {"status": A.NOT_APPLICABLE}]), A.READY)

    def test_continuity_gate_passes_for_an_approved_outage_window(self):
        window = T.scope(traffic_continuity={"mode": "APPROVED_OUTAGE_WINDOW", "max_outage_seconds": 120})
        gate = A.continuity_gate(SimpleNamespace(name="MID"), {"evidence": {"single_homed": True}}, [{"through": ["MID"]}], window)
        self.assertEqual((gate["status"], gate["evidence"]["flows_through"]), (A.PASS, 1))

    def test_identity_gate_passes_a_verified_identity_with_a_pinned_host_key(self):
        device = SimpleNamespace(identity_state=models.IdentityVerificationState.VERIFIED)
        self.assertEqual(A.identity_gate(device, report_for())["status"], A.PASS)

    def test_identity_gate_fails_without_a_pinned_host_key(self):
        device = SimpleNamespace(identity_state=models.IdentityVerificationState.VERIFIED)
        self.assertEqual(A.identity_gate(device, report_for(host_key=""))["codes"], ["IDENTITY_HOST_KEY_NOT_PINNED"])
        unverified = SimpleNamespace(identity_state=models.IdentityVerificationState.UNVERIFIED)
        self.assertEqual(A.identity_gate(unverified, report_for())["codes"], ["IDENTITY_NOT_VERIFIED"])

    def test_isolation_gate_passes_a_released_dual_stack_policy_with_its_inverse(self):
        device = SimpleNamespace(lifecycle_state=models.DeviceLifecycleState.IN_SERVICE)
        attachment = SimpleNamespace(pk=1, isolation_policies=Qs([policy_ns()]))
        with mock.patch.object(A, "live_attachments", return_value=[attachment]):
            gate = A.isolation_gate(device)
        self.assertEqual(gate["status"], A.PASS)
        self.assertEqual(gate["evidence"]["policies"][0]["elements"], ["IPV4", "IPV6"])

    def test_isolation_gate_fails_a_single_family_policy_without_an_inverse(self):
        device = SimpleNamespace(lifecycle_state=models.DeviceLifecycleState.IN_SERVICE)
        bad = policy_ns(intent={"elements": {"IPV4": {"acl": "a"}}}, plan={}, state=models.IsolationState.DRIFTED)
        with mock.patch.object(A, "live_attachments", return_value=[SimpleNamespace(pk=1, isolation_policies=Qs([bad]))]):
            gate = A.isolation_gate(device)
        self.assertEqual(gate["codes"], ["ISOLATION_FAMILY_UNCOVERED", "ISOLATION_INVERSE_MISSING", "ISOLATION_STATE_UNSAFE",
                                         "ISOLATION_NOT_RELEASED"])

    def test_management_gate_passes_an_approved_healthy_vlan_200_path(self):
        path = SimpleNamespace(path_id="MP-1", path_type=models.ManagementPathType.VLAN_ADJACENT_SWITCH, vrf="", vlan=200,
                               approval_state=models.ManagementApproval.APPROVED, health_state=models.ManagementPathHealth.HEALTHY)
        with mock.patch.object(models.ManagementPath.objects, "filter", return_value=Qs([path])):
            gate = A.management_gate(SimpleNamespace(), report_for())
        self.assertEqual(gate["status"], A.PASS)

    def test_management_gate_fails_while_reconciliation_is_required(self):
        with mock.patch.object(models.ManagementPath.objects, "filter", return_value=Qs([])):
            gate = A.management_gate(SimpleNamespace(), report_for(reconcile=True))
        self.assertEqual(gate["codes"], ["MANAGEMENT_RECONCILIATION_REQUIRED"])

    def test_prerequisites_lists_each_open_gate_as_a_checklist(self):
        report = {"global": [A._gate("LIVE_SCOPE", A.BLOCKED, ["LIVE_SCOPE_NOT_PROVIDED"])],
                  "devices": [{"name": "R6", "gates": [A._gate("MANAGEMENT", A.FAIL, ["X"]), A._gate("IDENTITY", A.PASS)]}]}
        self.assertEqual([(p["device"], p["gate"]) for p in A.prerequisites(report)], [("*", "LIVE_SCOPE"), ("R6", "MANAGEMENT")])

    def test_prerequisites_of_a_ready_report_is_empty(self):
        self.assertEqual(A.prerequisites({"global": [A._gate("ORDER", A.PASS)], "devices": [{"name": "R6", "gates": []}]}), [])

    def test_runbook_lists_scoped_steps_with_cumulative_gates(self):
        report = {"requested": ["UPA"], "devices": [{"name": "UPA"}]}
        steps = cmd.runbook(report, T.scope())
        self.assertEqual([s["action"] for s in steps], ["GATE", "ISOLATION_ENFORCE", "GATE", "ADMISSION", "GATE", "CLOSE"])
        self.assertIn("--completed UPA:ISOLATION_ENFORCE --completed UPA:ADMISSION", steps[4]["run"])

    def test_runbook_without_scoped_operations_has_no_step_beyond_gate_and_close(self):
        steps = cmd.runbook({"requested": ["UPA"], "devices": [{"name": "UPA"}]}, None)
        self.assertEqual([s["action"] for s in steps], ["GATE", "CLOSE"])

    def test_quiescence_gate_passes_a_ready_quiet_device(self):
        device = SimpleNamespace(name="NEWX", attachments=None)
        with mock.patch.object(A, "live_attachments", return_value=[]), \
                mock.patch.object(models.ChangeTarget.objects, "select_related", return_value=SimpleNamespace(filter=lambda **_: [])):
            gate = A.quiescence_gate(device, report_for())
        self.assertEqual(gate["status"], A.PASS)

    def test_quiescence_gate_blocks_a_device_that_is_not_ready_and_fails_a_deploying_change(self):
        device = SimpleNamespace(name="NEWX")
        deploying = SimpleNamespace(change=SimpleNamespace(change_id="CHG-1", lifecycle_state=models.ChangeLifecycleState.DEPLOYING))
        pending = SimpleNamespace(change=SimpleNamespace(change_id="CHG-2", lifecycle_state=models.ChangeLifecycleState.READY_TO_DEPLOY))
        with mock.patch.object(A, "live_attachments", return_value=[]):
            with mock.patch.object(models.ChangeTarget.objects, "select_related", return_value=SimpleNamespace(filter=lambda **_: [pending])):
                self.assertEqual(A.quiescence_gate(device, report_for(ready=False))["codes"], ["CHANGE_PENDING", "DEVICE_NOT_READY"])
            with mock.patch.object(models.ChangeTarget.objects, "select_related", return_value=SimpleNamespace(filter=lambda **_: [deploying])):
                self.assertEqual(A.quiescence_gate(device, report_for())["codes"], ["CHANGE_IN_FLIGHT"])


# ================================================================================================ database-backed gates
class DeviceGateTests(TestCase):
    def setUp(self):
        self.device, self.attachment, _auth = L.ready_device()

    def test_live_attachments_lists_the_approved_attachment(self):
        self.assertEqual([a.pk for a in A.live_attachments(self.device)], [self.attachment.pk])

    def test_live_attachments_never_lists_a_revoked_attachment(self):
        attachments.revoke_attachment(self.device, self.attachment.pk, actor=L.APPROVER, reason="re-cabled")
        self.assertEqual(A.live_attachments(models.ManagedDevice.objects.get(pk=self.device.pk)), [])

    def test_lifecycle_gate_passes_an_intact_chain(self):
        gate = A.lifecycle_gate(self.device, stage_report.device_report(self.device))
        self.assertEqual(gate["status"], A.PASS)
        self.assertTrue(gate["evidence"]["head_digest"])

    def test_lifecycle_gate_fails_a_tampered_chain(self):
        event = self.device.lifecycle_events.order_by("sequence").first()
        SR.raw_update(models.DeviceLifecycleEvent, "evidence", '{"tampered": true}', event.pk)
        gate = A.lifecycle_gate(self.device, stage_report.device_report(self.device))
        self.assertEqual(gate["codes"], ["LIFECYCLE_CHAIN_BROKEN"])

    def test_upstream_gate_passes_for_an_adopted_upstream(self):
        gate = A.upstream_gate(self.device)
        self.assertEqual(gate["status"], A.PASS)
        self.assertTrue(gate["evidence"]["single_homed"])

    def test_dependency_gate_fails_until_the_upstream_is_admitted(self):
        other = L.register("UPX", serial="SN-UPX", mac="00:1c:73:00:03:01").device
        D.add(self.device, other, kind=models.DependencyKind.DECLARED, actor=L.OPERATOR)
        self.assertEqual(A.dependency_gate(self.device)["codes"], ["COMMISSIONING_DEPENDENCY_UNMET"])

    def test_device_gates_reports_every_gate_in_order(self):
        result = A.device_gates(self.device)
        self.assertEqual([g["gate"] for g in result["gates"]],
                         ["LIFECYCLE", "IDENTITY", "DEPENDENCY", "UPSTREAM", "BOOTSTRAP_AUTHORIZATION", "DHCP_LEASE_RELAY", "ISOLATION",
                          "MANAGEMENT", "QUIESCENCE", "CONTINUITY"])

    def test_device_gates_fails_an_open_grant_outside_a_scope_and_blocks_without_management(self):
        result = A.device_gates(self.device)
        by = {g["gate"]: g for g in result["gates"]}
        self.assertEqual(by["BOOTSTRAP_AUTHORIZATION"]["codes"], ["BOOTSTRAP_AUTHORIZATION_OPEN_OUTSIDE_SCOPE"])
        self.assertEqual(by["MANAGEMENT"]["status"], A.BLOCKED)
        self.assertEqual(result["verdict"], A.FAIL)

    def test_dhcp_gate_passes_the_recorded_session_evidence(self):
        session = SimpleNamespace(session_id="ZTP-1", stage="BOOTSTRAPPED", adapter="arista_ceos", network=SimpleNamespace(name="n"))
        device = SimpleNamespace(ztp_sessions=SimpleNamespace(select_related=lambda *_: Qs([session])))
        with mock.patch.object(A.ztp_policy, "stored_network_problems", return_value=[]), \
                mock.patch.object(A.ztp_policy, "relay_for", return_value="10.0.0.1"), \
                mock.patch.object(A, "live_attachments", return_value=[SimpleNamespace(upstream_device="UP")]), \
                mock.patch.object(A.ztp_lease, "renewal_status", return_value={"state": A.ztp_lease.NOT_EXPECTED}), \
                mock.patch.object(A.ztp_lease, "status", return_value={"state": A.ztp_lease.ENDED}):
            gate = A.dhcp_gate(device, set(), timezone.now())
        self.assertEqual(gate["status"], A.PASS)
        self.assertEqual(gate["evidence"]["relays"], {"UP": "10.0.0.1"})

    def test_traffic_gate_passes_with_a_fresh_passed_run(self):
        now = timezone.now()
        models.TrafficRun.objects.create(operator="t", source="H1", destination="H2", address_family="IPV4", family="ICMP",
                                         protocol="ICMP", status=models.TrafficRunStatus.PASSED, finished_at=now - timedelta(seconds=10))
        gate = A.traffic_gate([T.TrafficGateTests.FLOW], now=now)
        self.assertEqual((gate["status"], gate["evidence"]["flows"][0]["state"]), (A.PASS, "FRESH_PASS"))
