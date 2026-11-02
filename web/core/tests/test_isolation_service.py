"""V2 Phase 5: the trusted-upstream isolation workflow on an in-memory upstream driven by the REAL cEOS executor and the
governed transaction (plan / precheck / separate approval / apply with read-back and digest-verified compensation), the
verification, drift, reconciliation, release, and the gates it adds to native ZTP, DHCP and the ISOLATE edge."""

from __future__ import annotations

from datetime import timedelta

from django.test import TestCase
from django.utils import timezone

from core import models
from core.services.devices import lifecycle
from core.services.execution.executors.base import ExecutorError
from core.services.execution.executors.ceos import _eos_commands
from core.services.isolation import eos, service as iso
from core.services.ztp import policy as ztp_policy
from core.tests.helpers import isolation as I
from core.tests.helpers import lifecycle as L
from core.tests.helpers import ztp as Z

St = models.IsolationState


class Base(Z.ZtpTestMixin, TestCase):
    real_isolation_gate = True

    def flow(self, **kwargs):
        return I.Flow(self, **kwargs)


class RequireTests(Base):
    def test_require_binds_device_routed_attachment_and_network(self):
        flow = self.flow()
        result = flow.required()
        self.assertEqual((result.policy.state, result.policy.upstream_device, result.policy.upstream_interface), (St.REQUIRED, "S1", I.PORT))
        self.assertEqual(result.policy.policy_id, f"ISO-{result.policy.pk:06d}")
        self.assertTrue(flow.device.lifecycle_events.filter(action="ISO_REQUIRE", outcome="RECORDED").exists())

    def test_require_refuses_access_attachment_unknown_upstream_missing_network_and_duplicates(self):
        flow = self.flow()
        access = L.attach(flow.device, port="Ethernet8", vlan=30).attachment
        self.assertIn("ISOLATION_ATTACHMENT_INELIGIBLE", iso.require(flow.device, access, network=flow.network, actor=L.OPERATOR).codes)
        self.assertIn("BOOTSTRAP_NETWORK_NOT_FOUND", iso.require(flow.device, flow.attachment, network=None, actor=L.OPERATOR).codes)
        other = L.register("NEW2", serial="SN-NEW2", mac="00:1c:73:00:00:02").device
        self.assertIn("ISOLATION_ATTACHMENT_INELIGIBLE", iso.require(other, flow.attachment, network=flow.network, actor=L.OPERATOR).codes)
        flow.required()
        self.assertIn("ISOLATION_EXISTS", iso.require(flow.device, flow.attachment, network=flow.network, actor=L.OPERATOR).codes)

    def test_require_refuses_an_untrusted_upstream(self):
        flow = self.flow()
        rogue = L.attach(flow.device, upstream="R9", port="Ethernet1", vlan=None, connectivity=models.AttachmentConnectivity.ROUTED)
        if rogue.ok:
            self.assertIn("ISOLATION_UPSTREAM_UNTRUSTED", iso.require(flow.device, rogue.attachment, network=flow.network, actor=L.OPERATOR).codes)
        else:
            self.assertTrue(rogue.codes)                  # the attachment service itself refuses an unknown upstream

    def test_require_refuses_an_admitted_or_terminal_device(self):
        flow = self.flow()
        models.ManagedDevice.objects.compare_and_swap(flow.device.pk, flow.device.version, admission_state=models.ProductionAdmissionState.ADMITTED)
        flow.device.refresh_from_db()
        self.assertIn("ISOLATION_DEVICE_INELIGIBLE", iso.require(flow.device, flow.attachment, network=flow.network, actor=L.OPERATOR).codes)


class PlanTests(Base):
    def test_plan_creates_the_governed_change_and_exact_operations(self):
        flow = self.flow()
        result = flow.planned()
        policy = result.policy
        self.assertEqual(policy.state, St.PLANNED)
        self.assertEqual(policy.apply_change.metadata["transition"]["kind"], iso.APPLY_KIND)
        self.assertEqual([op["key"] for op in iso.ops_of(policy)][:2], ["acl-v4", "acl-v6"])
        self.assertTrue(policy.plan_hash and policy.intent_hash and policy.basis_digest)
        self.assertEqual(flow.session.sent, [])                                  # planning sends nothing

    def test_plan_blocked_when_the_upstream_cannot_enforce(self):
        flow = self.flow(text=I.upstream_config(extra="router rip\n   network 10.0.0.0/8"))
        flow.required()
        result = iso.plan(flow.policy, actor=L.OPERATOR, access=flow.access)
        self.assertFalse(result.ok)
        self.assertEqual(result.policy.state, St.BLOCKED)
        self.assertIn("ISOLATION_ROUTING_UNSUPPORTED", result.codes)
        self.assertIsNone(result.policy.apply_change)

    def test_plan_refused_when_the_upstream_is_unreadable_or_state_wrong(self):
        flow = self.flow()
        flow.required()

        class Broken:
            def __init__(self, device):
                pass

            def connect(self):
                raise ExecutorError("CONNECTION_FAILED")

            def close(self):
                pass

        result = iso.plan(flow.policy, actor=L.OPERATOR, access=iso.Access(executor_factory=Broken))
        self.assertEqual(result.codes, ["ISOLATION_UPSTREAM_UNREADABLE"])
        flow.refresh()
        self.assertEqual(flow.policy.state, St.REQUIRED)
        iso.plan(flow.policy, actor=L.OPERATOR, access=flow.access)
        self.assertEqual(iso.plan(flow.refresh(), actor=L.OPERATOR, access=flow.access).codes, ["ISOLATION_STATE_INVALID"])

    def test_precheck_detects_an_upstream_changed_since_planning(self):
        flow = self.flow()
        flow.planned()
        flow.session.send_config_set(["interface Ethernet7", "ip access-group OPERATOR in"])
        result = iso.precheck(flow.refresh(), actor=L.OPERATOR, access=flow.access)
        self.assertFalse(result.ok)
        self.assertIn("ISOLATION_FOREIGN_ACL", result.codes)

    def test_approve_requires_a_separate_approver_the_plan_hash_and_a_passing_precheck(self):
        flow = self.flow()
        flow.planned()
        self.assertEqual(iso.approve(flow.refresh(), actor=L.OPERATOR, confirmation=flow.policy.plan_hash).codes, ["ISOLATION_SELF_APPROVAL"])
        self.assertIn("ISOLATION_PRECHECK_FAILED", iso.approve(flow.refresh(), actor=L.APPROVER, confirmation=flow.policy.plan_hash).codes)
        self.assertTrue(iso.precheck(flow.refresh(), actor=L.OPERATOR, access=flow.access).ok)
        self.assertIn("ISOLATION_CONFIRMATION_MISMATCH", iso.approve(flow.refresh(), actor=L.APPROVER, confirmation="0" * 64).codes)
        self.assertTrue(iso.approve(flow.refresh(), actor=L.APPROVER, confirmation=flow.policy.plan_hash).ok)

    def test_cancel_only_before_the_upstream_holds_anything(self):
        flow = self.flow()
        flow.planned()
        self.assertEqual(iso.cancel(flow.refresh(), actor=L.OPERATOR, reason="").codes, ["ISOLATION_STATE_INVALID"])
        result = iso.cancel(flow.refresh(), actor=L.OPERATOR, reason="wrong port")
        self.assertEqual((result.ok, result.policy.state, result.policy.failure["code"]), (True, St.RELEASED, "CANCELLED"))
        self.assertEqual(flow.session.sent, [])
        self.assertEqual(iso.cancel(flow.refresh(), actor=L.OPERATOR, reason="again").codes, ["ISOLATION_STATE_INVALID"])


class ApplyTests(Base):
    def test_apply_enforces_and_reads_back(self):
        flow = self.flow()
        result = flow.enforced()
        self.assertEqual(result.policy.state, St.ENFORCED)
        self.assertTrue(result.policy.enforced_digest)
        text = flow.session.config.text()
        self.assertEqual(set(iso.intent_service.presence(text, iso.ops_of(result.policy)).values()), {"PRESENT"})
        self.assertIn(f"ip access-group NMAS-ISO-{flow.device.device_id}-V4 in", text)
        self.assertIn(f"passive-interface {I.PORT}", text)

    def test_apply_refused_unapproved(self):
        flow = self.flow()
        flow.planned()
        self.assertEqual(iso.apply(flow.refresh(), actor=L.APPROVER, confirmation=flow.policy.plan_hash, access=flow.access).codes,
                         ["ISOLATION_STATE_INVALID"])
        self.assertEqual(flow.session.sent, [])

    def test_apply_failure_restores_the_upstream_exactly(self):
        flow = self.flow()
        flow.approved()
        baseline = flow.session.config.text()
        flow.session.reject = lambda commands: any("access-group" in c and "-V6 in" in c for c in commands)
        result = iso.apply(flow.refresh(), actor=L.APPROVER, confirmation=flow.policy.plan_hash, access=flow.access)
        self.assertFalse(result.ok)
        self.assertEqual(result.policy.state, St.REQUIRED)
        self.assertTrue(result.policy.failure["restored"])
        self.assertEqual(result.policy.approved_by, "")
        self.assertEqual(flow.session.config.text(), baseline)

    def test_apply_routing_leak_fails_the_postcheck_and_restores(self):
        flow = self.flow(outputs={"show ip ospf neighbor": I.ospf_neighbors(("10.255.0.9", "FULL/DR", "10.254.30.10", I.PORT))})
        flow.approved()
        baseline = flow.session.config.text()
        result = iso.apply(flow.refresh(), actor=L.APPROVER, confirmation=flow.policy.plan_hash, access=flow.access)
        self.assertEqual(result.policy.state, St.REQUIRED)
        self.assertEqual(result.detail["outcome"], "POSTCHECK_FAILED_ROLLED_BACK")
        self.assertEqual(flow.session.config.text(), baseline)

    def test_apply_unproven_restoration_is_uncertain_and_reconcile_never_removes(self):
        flow = self.flow()
        flow.approved()
        state = {"applied": 0}

        def reject(commands):
            if any(c.startswith("no ") for c in commands):
                return True                                   # compensation is refused: restoration cannot be proven
            if any("-V6-OUT out" in c for c in commands):
                return True
            state["applied"] += 1
            return False

        flow.session.reject = reject
        result = iso.apply(flow.refresh(), actor=L.APPROVER, confirmation=flow.policy.plan_hash, access=flow.access)
        self.assertEqual(result.policy.state, St.UNCERTAIN)
        flow.session.reject = None
        sent = len(flow.session.sent)
        reconciled = iso.reconcile(flow.refresh(), actor=L.APPROVER, access=flow.access)
        self.assertEqual(reconciled.policy.state, St.UNCERTAIN)                  # partially present: never guessed
        self.assertEqual(len(flow.session.sent), sent)                            # reconcile sends nothing


class VerifyTests(Base):
    def test_verify_with_traffic_and_moving_counters_is_verified(self):
        flow = self.flow()
        result = flow.verified()
        self.assertEqual(result.policy.state, St.VERIFIED)
        kinds = set(result.policy.checks.filter(ok=True).values_list("kind", flat=True))
        self.assertEqual(kinds, {"READ_BACK", "L2", "ROUTING", "MANAGEMENT_PLANE", "TRAFFIC"})

    def test_verify_without_traffic_stays_enforced(self):
        flow = self.flow()
        flow.enforced()
        result = iso.verify(flow.refresh(), actor=L.APPROVER, access=flow.access)
        self.assertEqual((result.policy.state, result.policy.failure["code"]), (St.ENFORCED, "ISOLATION_TRAFFIC_UNVERIFIED"))

    def test_verify_leak_or_uncorroborated_denial_is_not_verified(self):
        flow = self.flow()
        flow.enforced()
        flow.counters(step=0)                                                     # denied flows that never hit the deny entry
        result = iso.verify(flow.refresh(), actor=L.APPROVER, access=flow.access, traffic=I.traffic_ok)
        self.assertEqual((result.policy.state, result.policy.failure["code"]), (St.ENFORCED, "ISOLATION_LEAK"))
        flow.counters()
        leak = lambda p, d: [{"flow": "probe -> service", "expect": "DENY", "observed": "PERMIT"},       # noqa: E731
                             {"flow": "device -> http", "expect": "PERMIT", "observed": "PERMIT"}]
        self.assertIn("ISOLATION_LEAK", iso.verify(flow.refresh(), actor=L.APPROVER, access=flow.access, traffic=leak).codes)
        only_permit = lambda p, d: [{"flow": "device -> http", "expect": "PERMIT", "observed": "PERMIT"}]   # noqa: E731
        self.assertFalse(iso.verify(flow.refresh(), actor=L.APPROVER, access=flow.access, traffic=only_permit).ok)

    def test_verify_detects_drift_and_drift_check_never_reapplies(self):
        flow = self.flow()
        flow.verified()
        flow.session.send_config_set(["interface Ethernet7", f"no ip access-group NMAS-ISO-{flow.device.device_id}-V4 in"])
        sent = len(flow.session.sent)
        drift = iso.check_drift(flow.refresh(), actor=L.APPROVER, access=flow.access)
        self.assertEqual((drift.ok, drift.policy.state), (False, St.DRIFTED))
        self.assertEqual(len(flow.session.sent), sent)
        self.assertEqual(iso.verify(flow.refresh(), actor=L.APPROVER, access=flow.access).policy.state, St.DRIFTED)

    def test_drift_check_passes_on_an_intact_policy(self):
        flow = self.flow()
        flow.verified()
        result = iso.check_drift(flow.refresh(), actor=L.APPROVER, access=flow.access)
        self.assertEqual((result.ok, result.policy.state), (True, St.VERIFIED))

    def test_status_is_bounded_and_names_limitations(self):
        flow = self.flow()
        flow.verified()
        found = iso.status(flow.refresh())
        self.assertEqual(found["state"], St.VERIFIED)
        self.assertEqual(len(found["limitations"]), 2)
        self.assertTrue(found["checks"]["TRAFFIC"]["ok"])


class GateTests(Base):
    def test_ztp_gate_requires_enforced_fresh_policy(self):
        flow = self.flow()
        self.assertEqual([b["code"] for b in iso.ztp_problems(flow.device, flow.attachment)], ["ISOLATION_NOT_FOUND"])
        flow.planned()
        self.assertEqual([b["code"] for b in iso.ztp_problems(flow.device, flow.attachment)], ["ISOLATION_NOT_ENFORCED"])
        self.assertFalse(iso.enforced(flow.attachment))
        iso.precheck(flow.refresh(), actor=L.OPERATOR, access=flow.access)
        iso.approve(flow.refresh(), actor=L.APPROVER, confirmation=flow.policy.plan_hash)
        iso.apply(flow.refresh(), actor=L.APPROVER, confirmation=flow.policy.plan_hash, access=flow.access)
        self.assertTrue(iso.enforced(flow.attachment))
        self.assertTrue(iso.ztp_problems(flow.device, flow.attachment))        # enforced but no recorded verification yet
        iso.verify(flow.refresh(), actor=L.APPROVER, access=flow.access)
        self.assertEqual(iso.ztp_problems(flow.device, flow.attachment), [])
        later = timezone.now() + timedelta(seconds=iso.evidence_max_age_seconds() + 60)
        self.assertEqual({b["code"] for b in iso.ztp_problems(flow.device, flow.attachment, now=later)}, {"ISOLATION_NOT_VERIFIED"})

    def test_ztp_session_cannot_open_without_isolation(self):
        from core.services.devices import authorization
        from core.services.ztp import workflow

        flow = self.flow()
        auth = L.request_auth(flow.device, flow.attachment).authorization
        auth = authorization.approve(auth, actor=L.APPROVER, confirm_digest=auth.binding_digest).authorization
        result = workflow.open_session(flow.device, authorization=auth, network=flow.network, actor=L.OPERATOR)
        self.assertFalse(result.ok)
        self.assertIn("ISOLATION_NOT_FOUND", str(result.blockers))
        flow.enforced()
        iso.verify(flow.refresh(), actor=L.APPROVER, access=flow.access)
        self.assertTrue(workflow.open_session(flow.device, authorization=auth, network=flow.network, actor=L.OPERATOR).ok)

    def test_dhcp_policy_answers_only_isolated_ports(self):
        from core.services.devices import authorization
        from core.services.ztp import workflow

        flow = self.flow()
        flow.verified()
        auth = L.request_auth(flow.device, flow.attachment).authorization
        auth = authorization.approve(auth, actor=L.APPROVER, confirm_digest=auth.binding_digest).authorization
        session = workflow.open_session(flow.device, authorization=auth, network=flow.network, actor=L.OPERATOR).session
        self.assertEqual([r.session_id for r in ztp_policy.build_policy(flow.network).reservations], [session.session_id])
        flow.session.send_config_set(["interface Ethernet7", f"no ip access-group NMAS-ISO-{flow.device.device_id}-V4 in"])
        iso.check_drift(flow.refresh(), actor=L.APPROVER, access=flow.access)
        self.assertFalse(iso.enforced(flow.attachment))
        self.assertEqual(ztp_policy.build_policy(flow.network).reservations, ())

    def test_isolate_edge_requires_verified_policy_with_the_device_observed(self):
        flow = self.flow()
        flow.verified()
        flow.bootstrapped()
        refused = lifecycle.transition(flow.device, models.DeviceLifecycleState.ISOLATED, actor=L.APPROVER)
        self.assertFalse(refused.ok)
        self.assertIn("ISOLATION_NOT_VERIFIED", refused.codes)
        flow.verified_with_device()
        flow.attachment.refresh_from_db()
        self.assertEqual(flow.attachment.verification_state, models.AttachmentVerification.VERIFIED)
        moved = flow.isolated()
        self.assertEqual(flow.device.lifecycle_state, models.DeviceLifecycleState.ISOLATED)
        self.assertEqual(moved.event.evidence["isolation_policy"], flow.policy.policy_id)

    def test_device_not_observed_on_the_port_fails_attachment_check(self):
        flow = self.flow()
        flow.verified()
        flow.bootstrapped()
        flow.session.outputs[f"show ip arp {flow.ztp.reserved_address}"] = I.arp(flow.ztp.reserved_address, interface="Ethernet3")
        flow.counters()
        result = iso.verify(flow.refresh(), actor=L.APPROVER, access=flow.access, traffic=I.traffic_ok, with_device=True)
        self.assertIn("ISOLATION_DEVICE_NOT_OBSERVED", result.codes)
        self.assertEqual(result.policy.failure["code"], "ISOLATION_DEVICE_NOT_OBSERVED")


class ReleaseTests(Base):
    def released_flow(self):
        flow = self.flow()
        flow.verified()
        created = iso.create_release(flow.refresh(), actor=L.OPERATOR, reference={"test": True})
        self.assertTrue(created.ok, created.codes)
        flow.refresh()
        self.assertTrue(iso.release_precheck(flow.policy, actor=L.OPERATOR, access=flow.access).ok)
        plan_hash = iso.transaction.latest_plan(flow.policy.release_change).plan_hash
        approved = iso.approve_release(flow.refresh(), actor=L.APPROVER, requested_by=L.OPERATOR, confirmation=plan_hash, extra={})
        self.assertTrue(approved.ok, approved.codes)
        return flow, plan_hash

    def test_release_removes_exactly_what_was_applied(self):
        flow, plan_hash = self.released_flow()
        baseline = I.FakeEosSession(I.upstream_config()).config.text()
        result = iso.execute_release(flow.refresh(), actor=L.APPROVER, confirmation=plan_hash, access=flow.access, verify_admission=lambda e: [])
        self.assertTrue(result.ok, result.codes)
        self.assertEqual(result.policy.state, St.RELEASED)
        self.assertEqual(flow.session.config.text(), baseline)

    def test_release_with_failed_admission_restores_isolation(self):
        flow, plan_hash = self.released_flow()
        enforced_text = flow.session.config.text()
        result = iso.execute_release(flow.refresh(), actor=L.APPROVER, confirmation=plan_hash, access=flow.access,
                                     verify_admission=lambda e: [{"check": "ospf_adjacency", "detail": "absent"}])
        self.assertFalse(result.ok)
        self.assertTrue(result.detail["restored"])
        self.assertEqual(result.policy.state, St.ENFORCED)
        self.assertEqual(flow.session.config.text(), enforced_text)

    def test_release_refused_for_non_verified_and_self_approval(self):
        flow = self.flow()
        flow.enforced()
        self.assertEqual(iso.create_release(flow.refresh(), actor=L.OPERATOR, reference={}).codes, ["ISOLATION_NOT_VERIFIED"])
        flow.counters()
        iso.verify(flow.refresh(), actor=L.APPROVER, access=flow.access, traffic=I.traffic_ok)
        iso.create_release(flow.refresh(), actor=L.OPERATOR, reference={})
        iso.release_precheck(flow.refresh(), actor=L.OPERATOR, access=flow.access)
        plan_hash = iso.transaction.latest_plan(flow.refresh().release_change).plan_hash
        self.assertIn("ISOLATION_SELF_APPROVAL",
                      iso.approve_release(flow.refresh(), actor=L.OPERATOR, requested_by=L.OPERATOR, confirmation=plan_hash, extra={}).codes)

    def test_reconcile_release_proves_state(self):
        flow, _plan_hash = self.released_flow()
        policy = flow.refresh()
        iso._save(policy, state=St.RELEASE_PENDING)                                  # a crash right after the write-ahead
        result = iso.reconcile_release(flow.refresh(), actor=L.APPROVER, access=flow.access)
        self.assertEqual(result.policy.state, St.ENFORCED)                           # nothing was removed: isolation proven intact
        iso._save(flow.refresh(), state=St.UNCERTAIN)
        for op in eos.render_release(flow.policy.intent):
            flow.session.send_config_set(_eos_commands(op["lines"]))
        self.assertEqual(iso.reconcile_release(flow.refresh(), actor=L.APPROVER, access=flow.access, verify_admission=lambda e: []).policy.state,
                         St.RELEASED)

    def test_reconcile_release_unproven_admission_stays_uncertain(self):
        flow, _plan_hash = self.released_flow()
        iso._save(flow.refresh(), state=St.RELEASE_PENDING)
        for op in eos.render_release(flow.policy.intent)[:2]:
            flow.session.send_config_set(_eos_commands(op["lines"]))
        result = iso.reconcile_release(flow.refresh(), actor=L.APPROVER, access=flow.access, verify_admission=lambda e: [])
        self.assertEqual((result.ok, result.policy.state), (False, St.UNCERTAIN))
        self.assertEqual(iso.reconcile_release(flow.refresh(), actor=L.APPROVER, access=flow.access).codes, ["ISOLATION_UNCERTAIN"])
