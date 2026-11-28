"""Live commissioning acceptance gates (read-only): live-scope validation, PLANNED-by-step prerequisites, R6-before-R7 ordering,
dependency / authorization / management / traffic / continuity gates, the runbook and the command's exit codes."""

from __future__ import annotations

import io
import json
import os
import tempfile
from datetime import timedelta
from types import SimpleNamespace

from django.core.management import call_command
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from core import models
from core.management.commands import nmas_commissioning_acceptance as cmd
from core.services.commissioning import acceptance as A
from core.services.commissioning import dependencies as D
from core.tests.helpers import lifecycle as L


def scope(**overrides):
    now = timezone.now()
    base = {"schema": A.SCOPE_SCHEMA, "change": "CHG-T", "prepared_by": "olivia", "approved_by": "arthur",
            "window": {"start": (now - timedelta(minutes=5)).isoformat(), "end": (now + timedelta(hours=1)).isoformat()},
            "devices": [{"name": "UPA", "operations": ["ISOLATION_ENFORCE", "ADMISSION"]}],
            "traffic_continuity": {"mode": "ZERO_LOSS"}, "retain_management": True,
            "flows": [{"source": "H1", "destination": "H2", "protocol": "ICMP", "family": "IPV4"}]}
    base.update(overrides)
    return base


def codes(problems):
    return [p["code"] for p in problems]


class ScopeTests(SimpleTestCase):
    def test_a_complete_second_person_scope_is_valid(self):
        self.assertEqual(A.scope_problems(scope()), [])

    def test_no_scope_blocks(self):
        self.assertEqual(codes(A.scope_problems(None)), ["LIVE_SCOPE_NOT_PROVIDED"])

    def test_self_approval_and_missing_approval_are_refused(self):
        self.assertIn("LIVE_SCOPE_SELF_APPROVAL", codes(A.scope_problems(scope(approved_by="olivia"))))
        self.assertIn("LIVE_SCOPE_NOT_APPROVED", codes(A.scope_problems(scope(approved_by=""))))

    def test_window_must_be_aware_open_and_unexpired(self):
        now = timezone.now()
        self.assertIn("LIVE_SCOPE_WINDOW_INVALID", codes(A.scope_problems(scope(window={"start": "2026-01-01T00:00:00",
                                                                                        "end": "2026-01-01T01:00:00"}))))
        past = {"start": (now - timedelta(hours=2)).isoformat(), "end": (now - timedelta(hours=1)).isoformat()}
        self.assertIn("LIVE_SCOPE_EXPIRED", codes(A.scope_problems(scope(window=past))))
        future = {"start": (now + timedelta(hours=1)).isoformat(), "end": (now + timedelta(hours=2)).isoformat()}
        self.assertIn("LIVE_SCOPE_NOT_YET_OPEN", codes(A.scope_problems(scope(window=future))))

    def test_unknown_operations_continuity_management_and_flows(self):
        found = codes(A.scope_problems(scope(devices=[{"name": "UPA", "operations": ["SHUTDOWN_EVERYTHING"]}],
                                             traffic_continuity={"mode": "APPROVED_OUTAGE_WINDOW"}, retain_management=False, flows=[])))
        self.assertEqual(found, ["LIVE_SCOPE_OPERATION_UNKNOWN", "LIVE_SCOPE_CONTINUITY_INVALID", "LIVE_SCOPE_MANAGEMENT_NOT_RETAINED",
                                 "TRAFFIC_FLOWS_NOT_DECLARED"])
        self.assertIn("LIVE_SCOPE_SCHEMA_INVALID", codes(A.scope_problems(scope(schema="x"))))
        self.assertIn("LIVE_SCOPE_DEVICES_INVALID", codes(A.scope_problems(scope(devices=[]))))

    def test_digest_is_stable_and_order_independent(self):
        self.assertEqual(A.scope_digest({"a": 1, "b": 2}), A.scope_digest({"b": 2, "a": 1}))
        self.assertEqual(A.scoped_operations(scope(), "UPA"), {"ISOLATION_ENFORCE", "ADMISSION"})
        self.assertEqual(A.scoped_operations(None, "UPA"), set())

    def test_every_code_resolves_to_a_message(self):
        for code in A.CODES:
            self.assertTrue(A.blocker(code)["remediation"])
        self.assertEqual(A.blocker("NATIVE_RETRY_UNDOCUMENTED")["code"], "NATIVE_RETRY_UNDOCUMENTED")   # shared registry reused


class VerdictTests(SimpleTestCase):
    def test_overall_ranks_fail_then_blocked_and_planned_never_blocks(self):
        g = lambda s: {"status": s}                                                                         # noqa: E731
        self.assertEqual(A.overall([g(A.PASS), g(A.BLOCKED), g(A.FAIL)]), A.FAIL)
        self.assertEqual(A.overall([g(A.PASS), g(A.BLOCKED)]), A.BLOCKED)
        self.assertEqual(A.overall([g(A.PASS), g(A.PLANNED), g(A.NOT_APPLICABLE)]), A.READY)

    def test_plan_aware_only_until_the_producing_step_is_declared_completed(self):
        gate = A._gate("MANAGEMENT", A.BLOCKED, ["MANAGEMENT_PATH_NOT_APPROVED"])
        self.assertEqual(A.plan_aware(gate, {"MANAGEMENT_PATH_APPROVE"}, set())["status"], A.PLANNED)
        self.assertEqual(A.plan_aware(gate, {"MANAGEMENT_PATH_APPROVE"}, {"MANAGEMENT_PATH_APPROVE"})["status"], A.BLOCKED)
        self.assertEqual(A.plan_aware(gate, set(), set())["status"], A.BLOCKED)                    # not scoped: a real prerequisite
        other = A._gate("QUIESCENCE", A.BLOCKED, ["CHANGE_PENDING"])
        self.assertEqual(A.plan_aware(other, set(A.OPERATIONS), set())["status"], A.BLOCKED)        # no step produces it

    def test_continuity_refuses_zero_loss_through_a_single_homed_device(self):
        device = SimpleNamespace(name="MID")
        upstream = {"evidence": {"single_homed": True}}
        flows = [{"source": "H5", "destination": "WS", "through": ["MID"]}]
        self.assertEqual(A.continuity_gate(device, upstream, flows, scope())["codes"], ["NO_REDUNDANT_PATH"])
        window = scope(traffic_continuity={"mode": "APPROVED_OUTAGE_WINDOW", "max_outage_seconds": 300})
        self.assertEqual(A.continuity_gate(device, upstream, flows, window)["status"], A.PASS)
        self.assertEqual(A.continuity_gate(device, upstream, [{"through": ["OTHER"]}], scope())["status"], A.PASS)

    def test_flow_parsing(self):
        self.assertEqual(cmd.parse_flow("H5:WebServer:icmp:ipv6:R4+R6"),
                         {"source": "H5", "destination": "WebServer", "protocol": "ICMP", "family": "IPV6", "through": ["R4", "R6"]})
        with self.assertRaises(Exception):
            cmd.parse_flow("H5:WebServer")


class GraphGateTests(TestCase):
    """The R4 -> R6 -> R7 shape with arbitrary names: LEG (adopted) -> UPA -> DNB."""

    def setUp(self):
        L.adopt("LEG", role="router")
        self.up = L.register("UPA", serial="SN-UPA", mac="00:1c:73:00:02:01").device
        self.down = L.register("DNB", serial="SN-DNB", mac="00:1c:73:00:02:02").device

    def test_order_must_follow_the_dependency_graph(self):
        D.add(self.down, self.up, kind=models.DependencyKind.DECLARED, actor=L.OPERATOR)
        good = A.evaluate(["UPA", "DNB"])
        bad = A.evaluate(["DNB", "UPA"])
        self.assertEqual(good["global"][0]["status"], A.PASS)
        self.assertEqual(bad["global"][0]["codes"], ["ORDER_VIOLATES_DEPENDENCY"])
        self.assertEqual(bad["global"][0]["evidence"]["required"], ["UPA", "DNB"])
        self.assertEqual([d["name"] for d in bad["devices"]], ["UPA", "DNB"])                        # evaluated in dependency order
        self.assertEqual(bad["verdict"], A.FAIL)

    def test_unknown_device_fails(self):
        report = A.evaluate(["UPA", "NOPE"])
        self.assertEqual(report["global"][0]["codes"], ["DEVICE_NOT_FOUND"])

    def test_downstream_dependency_is_unmet_until_the_upstream_is_admitted(self):
        D.add(self.down, self.up, kind=models.DependencyKind.DECLARED, actor=L.OPERATOR)
        gate = A.dependency_gate(self.down)
        self.assertEqual(gate["status"], A.FAIL)
        self.assertEqual(gate["codes"], ["COMMISSIONING_DEPENDENCY_UNMET"])

    def test_an_attachment_on_an_onboarded_upstream_must_be_declared(self):
        models.ManagedDevice.objects.compare_and_swap(self.up.pk, self.up.version, lifecycle_state=models.DeviceLifecycleState.IN_SERVICE,
                                                      admission_state=models.ProductionAdmissionState.ADMITTED)
        self.assertTrue(L.attach(self.down, upstream="UPA", port="Ethernet2", vlan=None,
                                 connectivity=models.AttachmentConnectivity.ROUTED).ok)
        self.assertIn("COMMISSIONING_DEPENDENCY_NOT_DECLARED", A.dependency_gate(self.down)["codes"])

    def test_no_attachment_blocks_the_upstream_gate(self):
        self.assertEqual(A.upstream_gate(self.up)["codes"], ["ATTACHMENT_NOT_REGISTERED"])

    def test_management_without_an_approved_in_band_path_blocks(self):
        from core.services.devices import stage_report

        gate = A.management_gate(self.up, stage_report.device_report(self.up))
        self.assertEqual((gate["status"], gate["codes"]), (A.BLOCKED, ["MANAGEMENT_PATH_NOT_APPROVED"]))

    def test_isolation_without_a_policy_fails(self):
        L.adopt()
        L.attach(self.up)
        self.assertEqual(A.isolation_gate(self.up)["codes"], ["ISOLATION_POLICY_NOT_FOUND"])

    def test_dhcp_not_applicable_without_a_session_unless_a_rebootstrap_is_scoped(self):
        now = timezone.now()
        self.assertEqual(A.dhcp_gate(self.up, set(), now)["status"], A.NOT_APPLICABLE)
        self.assertEqual(A.dhcp_gate(self.up, {"ZTP_REBOOTSTRAP"}, now)["codes"], ["ZTP_SESSION_NOT_FOUND"])

    def test_the_gates_write_nothing(self):
        before = (models.DeviceLifecycleEvent.objects.count(), models.AuditEvent.objects.count(), models.ManagedDevice.objects.get(pk=self.up.pk).version)
        A.evaluate(["UPA", "DNB"], scope=scope())
        self.assertEqual(before, (models.DeviceLifecycleEvent.objects.count(), models.AuditEvent.objects.count(),
                                  models.ManagedDevice.objects.get(pk=self.up.pk).version))


class AuthorizationGateTests(TestCase):
    def setUp(self):
        self.device, self.attachment, self.auth = L.ready_device()

    def test_an_open_grant_outside_a_scoped_bootstrap_fails(self):
        gate = A.authorization_gate(self.device, set(), None, timezone.now())
        self.assertEqual(gate["codes"], ["BOOTSTRAP_AUTHORIZATION_OPEN_OUTSIDE_SCOPE"])

    def test_a_scoped_rebootstrap_needs_a_grant_covering_the_window(self):
        now = timezone.now()
        covered = A.authorization_gate(self.device, {"ZTP_REBOOTSTRAP"}, now + timedelta(minutes=30), now)
        self.assertEqual(covered["status"], A.PASS)
        beyond = A.authorization_gate(self.device, {"ZTP_REBOOTSTRAP"}, now + timedelta(hours=5), now)
        self.assertEqual(beyond["codes"], ["BOOTSTRAP_AUTHORIZATION_REQUIRED"])

    def test_an_expired_grant_is_refused_and_no_longer_counts(self):
        later = self.auth.valid_until + timedelta(seconds=1)
        gate = A.authorization_gate(self.device, set(), None, later)
        self.assertEqual(gate["status"], A.PASS)
        self.assertEqual(gate["evidence"]["authorizations"][0]["refused_now"], ["EXPIRED"])


class TrafficGateTests(TestCase):
    FLOW = {"source": "H1", "destination": "H2", "protocol": "ICMP", "family": "IPV4"}

    def run_(self, status, finished):
        return models.TrafficRun.objects.create(operator="t", source="H1", destination="H2", address_family="IPV4", family="ICMP",
                                                protocol="ICMP", status=status, finished_at=finished)

    def test_no_flows_no_evidence_stale_failed_and_fresh(self):
        now = timezone.now()
        self.assertEqual(A.traffic_gate([], now=now)["codes"], ["TRAFFIC_FLOWS_NOT_DECLARED"])
        self.assertEqual(A.traffic_gate([self.FLOW], now=now)["codes"], ["TRAFFIC_BASELINE_STALE"])
        self.run_(models.TrafficRunStatus.PASSED, now - timedelta(hours=2))
        self.assertEqual(A.traffic_gate([self.FLOW], now=now)["evidence"]["flows"][0]["state"], "STALE")
        self.run_(models.TrafficRunStatus.PASSED, now - timedelta(seconds=30))
        self.assertEqual(A.traffic_gate([self.FLOW], now=now)["status"], A.PASS)
        self.run_(models.TrafficRunStatus.FAILED, now)
        self.assertEqual(A.traffic_gate([self.FLOW], now=now)["codes"], ["TRAFFIC_BASELINE_FAILED"])


class CommandTests(TestCase):
    def setUp(self):
        L.adopt("LEG", role="router")
        L.register("UPA", serial="SN-UPA", mac="00:1c:73:00:02:01")

    def call(self, *args):
        out = io.StringIO()
        try:
            call_command("nmas_commissioning_acceptance", *args, stdout=out)
            code = 0
        except SystemExit as exc:
            code = exc.code
        return code, out.getvalue()

    def test_check_exits_blocked_without_a_scope_and_writes_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "gates.json")
            code, text = self.call("check", "--devices", "UPA", "--out", path)
            self.assertIn(code, (2, 3))
            with open(path, encoding="utf-8") as fh:
                report = json.load(fh)
        self.assertEqual(report["schema"], A.SCHEMA)
        self.assertIn("LIVE_SCOPE_NOT_PROVIDED", text)
        self.assertEqual(code, cmd.EXIT[report["verdict"]])

    def test_plan_lists_each_scoped_step_with_its_rollback_and_a_cumulative_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "scope.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(scope(), fh)
            _, text = self.call("plan", "--devices", "UPA", "--scope", path, "--json")
        plan = json.loads(text)
        actions = [s["action"] for s in plan["steps"]]
        self.assertEqual(actions, ["GATE", "ISOLATION_ENFORCE", "GATE", "ADMISSION", "GATE", "CLOSE"])
        self.assertIn("--completed UPA:ISOLATION_ENFORCE --completed UPA:ADMISSION", plan["steps"][4]["run"])
        self.assertTrue(all(s["rollback"] for s in plan["steps"]))
        self.assertTrue(plan["prerequisites"])

    def test_scope_template_is_unapproved(self):
        _, text = self.call("scope-template", "--devices", "UPA")
        template = json.loads(text)
        self.assertEqual(template["approved_by"], "")
        self.assertIn("LIVE_SCOPE_NOT_APPROVED", codes(A.scope_problems(template)))

    def test_an_unreadable_scope_is_refused(self):
        from django.core.management.base import CommandError

        with self.assertRaises(CommandError):
            call_command("nmas_commissioning_acceptance", "check", "--devices", "UPA", "--scope", "/nonexistent/scope.json",
                         stdout=io.StringIO())
