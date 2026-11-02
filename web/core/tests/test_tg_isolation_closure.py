"""Test-governance closure for V2 Phase 5 trusted-upstream isolation: each public function of ``core.services.isolation`` (and
the cEOS executor's admission ``reachable``) called directly, with an accepting and a refusing case where it has both.

The behaviour is the one the workflow tests (``test_isolation_eos`` / ``test_isolation_service``) prove end to end; here every
function is driven on its own over the same in-memory upstream and the REAL cEOS executor (``helpers.isolation``)."""

from __future__ import annotations

from types import SimpleNamespace

from django.test import SimpleTestCase, TestCase, override_settings
from django.utils import timezone

from core import models
from core.services.execution import locking
from core.services.execution.codes import Outcome
from core.services.execution.executors.base import ConfigletSpec, ExecutorError
from core.services.execution.executors.ceos import CeosExecutor, _eos_commands
from core.services.execution.scope import resolve_scope
from core.services.isolation import eos, intent, service as iso, transaction as T
from core.tests.helpers import isolation as I
from core.tests.helpers import lifecycle as L
from core.tests.helpers import ztp as Z

St = models.IsolationState
NET = SimpleNamespace(ipv4_prefix="10.254.30.0/24", gateway=I.GATEWAY, service_address=I.SERVICE, http_port=8080)
BOOTSTRAP = {"prefix": "10.254.30.0/24", "service_address": I.SERVICE, "http_port": 8080}


def built(text=None):
    return intent.build(device_id="DEV-000002", upstream="S1", interface=I.PORT, network=NET, config_text=text or I.upstream_config(),
                        nmas_sources=["192.168.200.100"])


class EosClosureTests(SimpleTestCase):
    def test_eos_renderers(self):
        it, ops, _problems, _facts = built()
        with self.subTest("builds the exact port and service entries"):
            self.assertEqual(eos.ipv4_entries(BOOTSTRAP)[-1], "1000 deny ip any any")
            self.assertIn(f"10 permit tcp host {I.SERVICE} eq 8080 10.254.30.0/24", eos.ipv4_egress_entries(BOOTSTRAP))
            self.assertEqual(eos.management_entries("v4", ["10.254.30.0/24"]), ["10 deny ip 10.254.30.0/24 any", "20 permit ip any any"])
            self.assertEqual([op["key"] for op in eos.render_apply(it)], [op["key"] for op in ops])
            plan = eos.management_plan(I.upstream_config(), eos.management_denied(["10.254.30.1/24"], []), "", eos.acl_names("DEV-000002"))
            self.assertEqual(((plan["V4"] or {}).get("mode"), plan["blocked"]), ("ADD", []))
            error = eos.RenderError("ISOLATION_PORT_NOT_FOUND", "x" * 300)
            self.assertEqual((error.code, len(error.detail)), ("ISOLATION_PORT_NOT_FOUND", 200))
        with self.subTest("refuses an operator ACL that does not deny and a malformed render"):
            text = I.upstream_config(mgmt_acl="ip access-list OPS\n   10 permit ip any any\nmanagement ssh\n   ip access-group OPS in")
            plan = eos.management_plan(text, eos.management_denied(["10.254.30.1/24"], []), "", eos.acl_names("DEV-000002"))
            self.assertIsNone(plan["V4"])
            self.assertTrue(plan["blocked"])
            error = eos.RenderError("ISOLATION_PLAN_STALE")
            self.assertEqual((error.code, error.detail, str(error)), ("ISOLATION_PLAN_STALE", "", "ISOLATION_PLAN_STALE"))

    def test_management_plan_refuses_an_operator_acl_that_does_not_deny(self):
        text = I.upstream_config(mgmt_acl="ip access-list OPS\n   10 permit ip any any\nmanagement ssh\n   ip access-group OPS in")
        plan = eos.management_plan(text, eos.management_denied(["10.254.30.1/24"], []), "", eos.acl_names("DEV-000002"))
        self.assertIsNone(plan["V4"])
        self.assertIn("operator ACL OPS does not deny", plan["blocked"][0])

    def test_isolation_error_refuses_with_its_code_and_without_a_detail(self):
        error = eos.RenderError("ISOLATION_PLAN_STALE")
        self.assertEqual((error.code, error.detail, str(error)), ("ISOLATION_PLAN_STALE", "", "ISOLATION_PLAN_STALE"))
        with self.assertRaises(ValueError):
            raise eos.RenderError("ISOLATION_DEVICE_INELIGIBLE", None)

    def test_eos_parsers_refuse_missing_unknown_or_unreadable_input(self):
        text = I.upstream_config(ospf=False)
        self.assertEqual(eos.acl_counters("% Invalid input"), {})
        self.assertFalse(eos.acl_denies_ssh_from(None, "10.254.30.0/24")[0])
        self.assertIsNone(eos.acl_entries(text, "NOPE"))
        self.assertEqual(eos.arp_entry("% no entry", "10.254.30.10"), {})
        self.assertFalse(eos.interface_facts(text, "Ethernet99")["exists"])
        self.assertFalse(eos.locks_out("not-an-address", {"v4": ["10.254.30.0/24"], "v6": []}))
        self.assertEqual(eos.management_exposure(I.upstream_config(mgmt_acl="management ssh\n   shutdown"),
                                                 eos.management_denied(["10.254.30.1/24"], [])), [])
        self.assertEqual(eos.ospf_neighbors_on(I.ospf_neighbors(("10.255.0.2", "FULL/BDR", "10.0.12.1", "Ethernet1")), I.PORT), [])
        self.assertIsNone(eos.routes_via("not json", I.PORT, []))
        self.assertEqual(eos.routing_facts(text, I.PORT)["ospf"], [])

    def test_intent_helpers_refuse_drifted_or_unknown_content(self):
        it, ops, _problems, _facts = built()
        self.assertEqual(set(intent.presence(I.upstream_config(), ops).values()), {"ABSENT"})
        changed = I.upstream_config(extra=f"ip access-list {it['elements']['IPV4']['acl']}\n   10 permit ip any any")
        self.assertIn(it["elements"]["IPV4"]["acl"], intent.acl_exact(changed, it))
        self.assertNotEqual(intent.digest({"a": 1}), intent.digest({"a": None}))


class Base(Z.ZtpTestMixin, TestCase):
    real_isolation_gate = True

    def flow(self, **kwargs):
        return I.Flow(self, **kwargs)

    def executor(self, flow):
        executor = flow.access.executor_factory(iso.upstream_device(flow.policy))
        executor.connect()
        return executor


class ServiceClosureTests(Base):
    def test_settings_access_and_upstream_identity_return_configured_values(self):
        with override_settings(NMAS_ISOLATION_ROUTING_SETTLE_SECONDS=7):
            self.assertEqual(iso.routing_settle_seconds(), 7.0)
        access = iso.default_access()
        self.assertIs(access.executor_factory, CeosExecutor)
        self.assertTrue(all(isinstance(source, str) for source in access.nmas_sources))
        flow = self.flow()
        flow.required()
        self.assertEqual(iso.upstream_device(flow.policy), {"name": "S1", "platform": "ceos"})

    def test_upstream_device_of_another_policy_never_names_this_upstream(self):
        flow = self.flow()
        flow.required()
        self.assertNotEqual(iso.upstream_device(SimpleNamespace(upstream_device="S2"))["name"], flow.policy.upstream_device)

    def test_lookups(self):
        flow = self.flow()
        flow.required()
        with self.subTest("returns the live policy by id, attachment and device"):
            self.assertEqual(iso.get_policy(flow.policy.policy_id).pk, flow.policy.pk)
            self.assertEqual(iso.get_policy(str(flow.policy.pk)).pk, flow.policy.pk)
            self.assertEqual(iso.live_policy(flow.attachment).pk, flow.policy.pk)
            self.assertEqual(iso.device_policy(flow.device).pk, flow.policy.pk)
        with self.subTest("refuses unknown ids and missing attachments"):
            self.assertIsNone(iso.get_policy("ISO-XYZ"))
            self.assertIsNone(iso.get_policy(None))
            self.assertIsNone(iso.live_policy(None))
            self.assertIsNone(iso.device_policy(L.register("NEW2", serial="SN-NEW2", mac="00:1c:73:00:00:02").device))

    def test_read_config(self):
        flow = self.flow()
        flow.required()
        executor = self.executor(flow)
        with self.subTest("returns the sanitized running configuration"):
            text = iso.read_config(executor)
            self.assertIn(f"interface {I.PORT}", text)
            self.assertNotIn("$6$x", text)
        with self.subTest("refuses an unreadable upstream"):
            broken = SimpleNamespace(show=lambda command: (_ for _ in ()).throw(ExecutorError("CONNECTION_FAILED")))
            with self.assertRaises(ExecutorError):
                iso.read_config(broken)

    def test_require_problems(self):
        flow = self.flow()
        with self.subTest("accepts a registered device on its routed attachment"):
            self.assertEqual(iso.require_problems(flow.device, flow.attachment, flow.network), [])
        with self.subTest("refuses a missing network and a foreign attachment"):
            other = L.register("NEW2", serial="SN-NEW2", mac="00:1c:73:00:00:02").device
            self.assertIn("BOOTSTRAP_NETWORK_NOT_FOUND", [b["code"] for b in iso.require_problems(flow.device, flow.attachment, None)])
            self.assertIn("ISOLATION_ATTACHMENT_INELIGIBLE", [b["code"] for b in iso.require_problems(other, flow.attachment, flow.network)])

    def test_derive_and_ops(self):
        flow = self.flow()
        flow.planned()
        with self.subTest("builds the policy's exact operations"):
            _it, ops, problems, _facts = iso.derive(flow.policy, I.upstream_config(), flow.access)
            self.assertEqual(problems, [])
            self.assertEqual(ops, iso.ops_of(flow.policy))
        with self.subTest("refuses a switchport upstream and an unplanned policy"):
            _it, _ops, problems, _facts = iso.derive(flow.policy, I.upstream_config(switchport=True), flow.access)
            self.assertIn("ISOLATION_PORT_NOT_ROUTED", [p["code"] for p in problems])
            self.assertEqual(iso.ops_of(SimpleNamespace(plan=None)), [])

    def test_config_and_routing_findings(self):
        flow = self.flow()
        flow.enforced()
        executor = self.executor(flow)
        text = flow.session.config.text()
        with self.subTest("passes on the enforced upstream"):
            self.assertTrue(all(ok for ok, _c, _f in iso.config_findings(flow.policy, text).values()))
            self.assertTrue(iso.routing_findings(flow.policy, executor, text)[0])
        with self.subTest("refuses a drifted port and a leaked route"):
            drifted = text.replace(f"ip access-group NMAS-ISO-{flow.device.device_id}-V4 in", "")
            self.assertFalse(iso.config_findings(flow.policy, drifted)[models.IsolationCheckKind.READ_BACK][0])
            flow.session.outputs["show ip route | json"] = I.routes("10.9.0.0/16")
            ok, code, facts = iso.routing_findings(flow.policy, executor, text)
            self.assertEqual((ok, code, facts["leaked_ipv4"]), (False, "ISOLATION_LEAK", ["10.9.0.0/16"]))

    def test_counters(self):
        flow = self.flow()
        flow.enforced()
        executor = self.executor(flow)
        with self.subTest("returns the deny-entry counters of the four port ACLs"):
            flow.counters(step=5)
            self.assertEqual(set(iso.counters(executor, flow.policy.intent).values()), {5})
        with self.subTest("refuses to invent counters for ACLs that never matched"):
            for key in list(flow.session.outputs):
                if "access-lists" in key:
                    flow.session.outputs[key] = ""
            self.assertEqual(set(iso.counters(executor, flow.policy.intent).values()), {0})

    def test_freshness_and_gates(self):
        flow = self.flow()
        flow.enforced()
        self.assertTrue(iso.verify(flow.refresh(), actor=L.APPROVER, access=flow.access).ok)      # configuration checks, no traffic
        policy = flow.refresh()
        with self.subTest("passes recent configuration checks"):
            self.assertEqual(iso.fresh_problems(policy, iso.CONFIG_CHECKS), [])
        with self.subTest("refuses stale evidence, a missing policy and an unenforced port"):
            later = timezone.now() + timezone.timedelta(seconds=iso.evidence_max_age_seconds() + 60)
            self.assertEqual({b["code"] for b in iso.fresh_problems(policy, iso.CONFIG_CHECKS, now=later)}, {"ISOLATION_NOT_VERIFIED"})
            other = L.register("NEW2", serial="SN-NEW2", mac="00:1c:73:00:00:02").device
            self.assertEqual([b["code"] for b in iso.ztp_problems(other, flow.attachment)], ["ISOLATION_NOT_FOUND"])
            self.assertEqual([b["code"] for b in iso.isolate_problems(flow.device)], ["ISOLATION_NOT_VERIFIED"])
            self.assertFalse(iso.enforced(None))
        with self.subTest("accepts the enforced port for DHCP answers"):
            self.assertEqual(policy.state, St.ENFORCED)
            self.assertTrue(iso.enforced(flow.attachment))

    def test_isolate_problems_returns_nothing_once_verified_with_the_device(self):
        flow = self.flow()
        flow.verified()
        flow.bootstrapped()
        flow.verified_with_device()
        self.assertEqual(iso.isolate_problems(flow.device), [])

    def test_release_helpers(self):
        flow = self.flow()
        flow.enforced()
        policy = flow.refresh()
        enforced_text = flow.session.config.text()
        with self.subTest("builds the release and accepts the enforced upstream"):
            ops = iso.release_ops(policy)
            self.assertTrue(ops and all(op["kind"] == "REMOVE" for op in ops))
            self.assertEqual(iso.release_preflight_problems(policy, enforced_text), [])
        with self.subTest("refuses a drifted upstream and statements still present"):
            self.assertEqual(iso.release_preflight_problems(policy, I.upstream_config())[0]["code"], "ISOLATION_DRIFTED")
            self.assertTrue(iso.release_absent_problems(policy, enforced_text))
            stale = SimpleNamespace(intent={**policy.intent, "upstream": {**policy.intent["upstream"], "interface": "Eth 7; reload"}})
            with self.assertRaises(eos.RenderError):
                iso.release_ops(stale)
        with self.subTest("accepts an upstream the release emptied"):
            for op in iso.release_ops(policy):
                flow.session.send_config_set(_eos_commands(op["lines"]))
            self.assertEqual(iso.release_absent_problems(policy, flow.session.config.text()), [])

    def test_cancel_refuses_an_enforced_policy_or_an_empty_reason(self):
        flow = self.flow()
        flow.enforced()
        self.assertEqual(iso.cancel(flow.refresh(), actor=L.OPERATOR, reason=" ").codes, ["ISOLATION_STATE_INVALID"])
        self.assertEqual(iso.cancel(flow.refresh(), actor=L.OPERATOR, reason="window").codes, ["ISOLATION_STATE_INVALID"])
        self.assertEqual(flow.refresh().state, St.ENFORCED)

    def test_reconcile_returns_enforced_for_an_upstream_that_holds_the_policy(self):
        flow = self.flow()
        flow.enforced()
        iso._save(flow.refresh(), state=St.UNCERTAIN)
        result = iso.reconcile(flow.refresh(), actor=L.APPROVER, access=flow.access)
        self.assertEqual((result.ok, result.policy.state), (True, St.ENFORCED))

    def test_reconcile_release_refuses_a_policy_never_released(self):
        flow = self.flow()
        flow.verified()
        self.assertEqual(iso.reconcile_release(flow.refresh(), actor=L.APPROVER, access=flow.access).codes, ["ISOLATION_STATE_INVALID"])

    def test_status_names_no_secret_and_no_device_change_for_a_cancelled_policy(self):
        flow = self.flow()
        flow.required()
        cancelled = iso.cancel(flow.refresh(), actor=L.OPERATOR, reason="not needed").policy
        found = iso.status(cancelled)
        self.assertEqual((found["state"], found["failure"]["device_changed"]), (St.RELEASED, False))
        self.assertNotIn("secret", str(found).lower())


class ReachableClosureTests(SimpleTestCase):
    def test_reachable(self):
        session = I.FakeEosSession(I.upstream_config(), pings={"10.9.0.1": True})
        executor = CeosExecutor({"name": "S1"}, connection_factory=lambda device: session, reader=I._facts)
        executor.connect()
        with self.subTest("returns true for an answering address"):
            self.assertTrue(executor.reachable("10.9.0.1"))
            self.assertEqual(session.commands[-1], "ping 10.9.0.1 repeat 2")
        with self.subTest("refuses a name, a silent address and a broken session"):
            self.assertFalse(executor.reachable("router-a"))
            self.assertFalse(executor.reachable("10.9.0.2"))
            session.send_command = lambda command, **_: (_ for _ in ()).throw(OSError("closed"))
            self.assertFalse(executor.reachable("10.9.0.1"))


class TransactionClosureTests(Base):
    def approved_change(self):
        flow = self.flow()
        flow.approved()
        policy = flow.refresh()
        return flow, policy, policy.apply_change, iso.ops_of(policy)

    def attempt(self, flow, policy, change, ops, **hooks):
        plan = T.latest_plan(change)
        scope, _blockers = resolve_scope(plan, models.ExecutionMode.COMPLETE)
        run = locking.acquire(change=change, plan=plan, precheck_run=T.latest_precheck(change, plan), mode=models.ExecutionMode.COMPLETE,
                              actor=L.APPROVER, scope=scope, devices=["S1"], now=timezone.now())
        return T._Attempt(run=run, change=change, plan=plan, ops=list(ops), specs=[ConfigletSpec.from_configlet(row) for row in scope.selected],
                          actor=L.APPROVER, executor=flow.access.executor_factory(iso.upstream_device(policy)), **hooks)

    def test_pure_helpers(self):
        _flow, policy, change, ops = self.approved_change()
        with self.subTest("returns stable blockers, hashes and kinds"):
            self.assertEqual(T.blocker("PLAN_STALE", "x"), {"code": "PLAN_STALE", "message": "x"})
            self.assertEqual(T.plan_hash(ops), policy.plan_hash)
            self.assertEqual(T.kind_of(change), iso.APPLY_KIND)
        with self.subTest("refuses changed operations and an ordinary change"):
            self.assertEqual(T.blocker("SELF_APPROVAL")["message"], "SELF_APPROVAL")
            self.assertNotEqual(T.plan_hash(ops[:-1]), policy.plan_hash)
            self.assertEqual(T.kind_of(SimpleNamespace(metadata={})), "")

    def test_change_validation_plan_and_precheck_records(self):
        _flow, _policy, change, ops = self.approved_change()
        with self.subTest("creates the governed change, its validation, plan and precheck"):
            created = T.create_change(kind=iso.RELEASE_KIND, device="S1", title="t", description="d", actor=L.OPERATOR, reference={"x": 1})
            self.assertEqual(T.kind_of(created), iso.RELEASE_KIND)
            run = T.validate(created, ops, actor=L.OPERATOR, findings=[], source={"upstream": "S1"})
            self.assertEqual((run.status, T.latest_validation(created).pk), (models.ValidationRunStatus.PASS, run.pk))
            plan = T.build_plan(created, ops, actor=L.OPERATOR, device="S1", summary={})
            self.assertEqual(T.build_plan(created, ops, actor=L.OPERATOR, device="S1", summary={}).pk, plan.pk)
            self.assertEqual(T.plan_problems(plan, ops, "S1"), [])
            check = T.record_precheck(created, plan, actor=L.OPERATOR, blockers=[], facts={})
            self.assertEqual((check.status, T.latest_precheck(created, plan).pk), ("PASS", check.pk))
        with self.subTest("refuses a failing validation, a stale plan and a blocked precheck"):
            refused = T.create_change(kind=iso.RELEASE_KIND, device="S1", title="t", description="d", actor=L.OPERATOR, reference={})
            bad = T.validate(refused, ops, actor=L.OPERATOR, findings=[{"code": "X"}], source={})
            self.assertEqual((bad.status, T.latest_validation(refused).status), (models.ValidationRunStatus.BLOCKED, models.ValidationRunStatus.BLOCKED))
            with self.assertRaises(T.TransactionError):
                T.build_plan(refused, ops, actor=L.OPERATOR, device="S1", summary={})
            plan = T.latest_plan(change)
            self.assertEqual(T.plan_problems(plan, ops[:-1], "S1")[0]["code"], "PLAN_STALE")
            blocked = T.record_precheck(refused, plan, actor=L.OPERATOR, blockers=[T.blocker("X")], facts={})
            self.assertEqual(blocked.status, "BLOCKED")
            self.assertIsNone(T.latest_precheck(refused, None))
            self.assertIsNone(T.latest_validation(T.create_change(kind="K", device="S1", title="t", description="d", actor="a", reference={})))

    def test_approval_and_gate(self):
        _flow, policy, change, ops = self.approved_change()
        with self.subTest("returns the recorded approval and passes the gate"):
            self.assertEqual(T.approval(change)["plan_hash"], policy.plan_hash)
            plan, _precheck, blockers = T.gate(change, ops, device="S1", confirmation=policy.plan_hash, now=timezone.now())
            self.assertEqual((blockers, plan.plan_hash), ([], policy.plan_hash))
            self.assertEqual(T.unresolved_runs("S1"), [])
        with self.subTest("refuses self approval, a wrong confirmation and an unapproved change"):
            with self.assertRaises(T.TransactionError) as raised:
                T.approve(change, ops, actor=L.OPERATOR, requested_by=L.OPERATOR, confirmation="0" * 64, device="S1")
            self.assertEqual({b["code"] for b in raised.exception.blockers}, {"SELF_APPROVAL", "CONFIRMATION_MISMATCH"})
            fresh = T.create_change(kind=iso.APPLY_KIND, device="S1", title="t", description="d", actor=L.OPERATOR, reference={})
            self.assertEqual(T.approval(fresh), {})
            self.assertEqual(T.gate(fresh, ops, device="S1", confirmation="", now=timezone.now())[2][0]["code"], "PLAN_MISSING")
            self.assertIn("CONFIRMATION_MISMATCH", [b["code"] for b in T.gate(change, ops, device="S1", confirmation="x", now=timezone.now())[2]])
            self.assertEqual(T.unresolved_runs("S9"), [])

    def test_approve_records_the_approval_of_exactly_this_plan(self):
        flow = self.flow()
        flow.planned()
        policy = flow.refresh()
        self.assertTrue(iso.precheck(policy, actor=L.OPERATOR, access=flow.access).ok)
        event = T.approve(policy.apply_change, iso.ops_of(policy), actor=L.APPROVER, requested_by=L.OPERATOR, confirmation=policy.plan_hash,
                          device="S1", extra={"policy": policy.policy_id})
        self.assertEqual(event.metadata["approval"]["plan_hash"], policy.plan_hash)
        self.assertEqual(T.approval(policy.apply_change)["policy"], policy.policy_id)

    def test_unresolved_runs_names_an_interrupted_transaction(self):
        flow, policy, change, ops = self.approved_change()
        attempt = self.attempt(flow, policy, change, ops)
        self.assertEqual(T.unresolved_runs("S1"), [change.change_id])                  # RUNNING: not resolved
        attempt.close()

    def test_execute(self):
        flow, policy, change, ops = self.approved_change()
        with self.subTest("refuses an unconfirmed plan without touching the upstream"):
            before = flow.session.config.text()
            refused = T.execute(change, ops, actor=L.APPROVER, confirmation="x", device=iso.upstream_device(policy),
                                executor_factory=flow.access.executor_factory)
            self.assertEqual((refused.outcome, refused.succeeded, refused.restored), (Outcome.BLOCKED, False, True))
            self.assertEqual(flow.session.config.text(), before)
        with self.subTest("succeeds and returns the applied report"):
            result = T.execute(change, ops, actor=L.APPROVER, confirmation=policy.plan_hash, device=iso.upstream_device(policy),
                               executor_factory=flow.access.executor_factory, final=lambda executor: [])
            self.assertEqual((result.outcome, result.succeeded), (Outcome.SUCCEEDED, True))
            self.assertEqual(len(result.report["state"]["applied"]), len(ops))

    def test_result_properties_returns_success_and_restoration(self):
        self.assertTrue(T.Result(None, Outcome.SUCCEEDED).succeeded)
        self.assertTrue(T.Result(None, Outcome.POSTCHECK_FAILED_ROLLED_BACK).restored)
        self.assertFalse(T.Result(None, Outcome.POSTCHECK_FAILED_COMPENSATION_INCOMPLETE).restored)

    def test_attempt_steps(self):
        flow, policy, change, ops = self.approved_change()
        seen = []
        with self.subTest("drives every operation, passes the postcheck and returns its report"):
            attempt = self.attempt(flow, policy, change, ops, observer=lambda event, key: seen.append((event, key)), final=lambda e: [])
            self.assertEqual(attempt.drive(), Outcome.SUCCEEDED)
            attempt.note("extra", "PASS", detail="ok")
            attempt.notify("after", "extra")
            report = attempt.report(Outcome.SUCCEEDED)
            self.assertEqual((report["postcheck"]["result"], report["compensation"]["status"]), ("PASS", "NOT_ATTEMPTED"))
            self.assertIn(("before", "postcheck"), seen)
            self.assertEqual(attempt.steps[-1]["step"], "extra")
            attempt.close()
            self.assertFalse(attempt.connected)
        with self.subTest("accepts the first failure code as the run's failure"):
            attempt.fail("POSTCHECK_FAILED", "routing", "ospf-passive-1")
            attempt.fail("INTERNAL_ERROR")
            self.assertEqual((attempt.failure["code"], attempt.failure["operation"]), ("POSTCHECK_FAILED", "ospf-passive-1"))

    def test_attempt_compensation_restores_the_upstream_exactly(self):
        flow, policy, change, ops = self.approved_change()
        baseline = flow.session.config.text()
        attempt = self.attempt(flow, policy, change, ops, final=lambda e: [])
        attempt.executor.connect()
        attempt.connected = True
        attempt.baseline = attempt.executor.config_state_digest()
        self.assertTrue(attempt.apply(ops[0], attempt.specs[0]))
        self.assertTrue(attempt.apply(ops[1], attempt.specs[1]))
        attempt.postcheck()
        attempt.compensate()
        self.assertTrue(attempt.restored)
        self.assertEqual(flow.session.config.text(), baseline)
        self.assertEqual(attempt.report(Outcome.FAILED_ROLLED_BACK)["compensation"]["status"], "COMPENSATED")
        attempt.close()

    def test_attempt_refuses_an_out_of_band_change_a_failing_postcheck_and_a_raising_observer(self):
        flow, policy, change, ops = self.approved_change()
        attempt = self.attempt(flow, policy, change, ops, final=lambda e: [{"check": "ROUTING", "detail": "leak"}])
        attempt.executor.connect()
        attempt.connected = True
        attempt.baseline = "0" * 64                                    # the device moved since the preflight
        self.assertFalse(attempt.apply(ops[0], attempt.specs[0]))
        self.assertEqual(attempt.failure["code"], "OUT_OF_BAND_CHANGE")
        attempt.fail("SECOND", "ignored")                              # the first failure is kept
        self.assertEqual([b["code"] for b in attempt.blockers], ["OUT_OF_BAND_CHANGE"])
        attempt.note("abort", "BLOCKED")
        report = attempt.report(Outcome.FAILED_NO_MUTATION)
        self.assertEqual((report["failure"]["code"], report["state"]["applied"]), ("OUT_OF_BAND_CHANGE", []))
        attempt.failure, attempt.blockers = {}, []
        attempt.postcheck()
        self.assertEqual(attempt.failure["code"], "POSTCHECK_FAILED")
        attempt.observer = lambda event, key: (_ for _ in ()).throw(RuntimeError("observer refused"))
        with self.assertRaises(RuntimeError):
            attempt.notify("before", ops[0]["key"])
        attempt.close()

    def test_attempt_drive_refuses_a_preflight_blocker(self):
        flow, policy, change, ops = self.approved_change()
        attempt = self.attempt(flow, policy, change, ops, preflight=lambda executor: [T.blocker("PLAN_STALE")])
        self.assertEqual(attempt.drive(), Outcome.BLOCKED)
        self.assertEqual(flow.session.sent, [])
        attempt.close()
