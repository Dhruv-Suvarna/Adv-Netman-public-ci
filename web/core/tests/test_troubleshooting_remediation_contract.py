"""propose_remediation contract: one schema shared by the model-facing tool and the server-side planner."""

from __future__ import annotations

from django.test import SimpleTestCase

from core import models as m
from core.services.troubleshooting import ai, ai_runtime as air
from core.services.troubleshooting import governance as gov
from core.tests.test_troubleshooting_ai import AiBase, rt
from core.tests.test_troubleshooting_governance import ROLLBACK, T0, make_ports

VALID = {"kind": "config_hotfix", "device": "r1", "interface": "Ethernet1", "intended_state": "admin_up"}


class OperationSchemaTests(SimpleTestCase):
    def test_model_and_server_share_one_schema(self):
        spec = ai.TOOLS["propose_remediation"]["schema"]
        self.assertIs(spec["operations"]["items"], gov.OPERATION_SCHEMA)
        self.assertIs(spec["rollback_plan"], gov.ROLLBACK_SCHEMA)
        req = air.build_request({}, identity={}, catalog=[], seq=1)
        self.assertEqual(req["tools"]["propose_remediation"]["schema"]["operations"]["items"], gov.OPERATION_SCHEMA)
        self.assertEqual(set(gov.OPERATION_SCHEMA["properties"]["kind"]["enum"]), set(gov.OP_KINDS))

    def test_valid_operation_accepted(self):
        self.assertEqual(gov.validate_operation(VALID), "")
        self.assertEqual(gov.validate_operation({"kind": "acl_change", "device": "r1", "change_id": "CHG-20261117-001"}), "")

    def test_malformed_operations_rejected(self):
        bad = [
            ("no shutdown", "must be an object"),                                       # the string that previously crashed the planner
            ({"device": "r1"}, "missing required field 'kind'"),
            ({"kind": "config_hotfix"}, "missing required field 'device'"),
            ({**VALID, "kind": "interface_magic"}, "not supported"),                   # unregistered kind is never invented
            ({**VALID, "config": "no shutdown"}, "unsupported operation field"),         # no configuration text through the model
            ({**VALID, "intended_state": "on"}, "not supported"),
            ({**VALID, "device": "r1; reload"}, "malformed"),
            ({**VALID, "change_id": "../../etc"}, "malformed"),
            ({**VALID, "interface": 1}, "must be a string"),
        ]
        for op, expected in bad:
            with self.subTest(op=op):
                self.assertIn(expected, gov.validate_operation(op))


class ProposalLifecycleTests(AiBase):
    def setUp(self):
        super().setUp()
        self.h = self.handoff()
        self.ag = self.agent_for(self.h)
        self.ports = make_ports()

    def call(self, args):
        self._n = getattr(self, "_n", 0) + 1
        return ai.call_tool(self.ag, self.h.record_id, "propose_remediation", args, nonce=f"contract-{self._n:05d}",
                            rt=rt(self.case, ports=self.ports), now=T0)

    def base(self, **kw):
        return {"addressed_fault": "r1 Ethernet1 admin down but intended up", "causal_evidence_ids": [self.ev.evidence_id],
                "rollback_plan": ROLLBACK, "operations": [VALID], **kw}

    def test_valid_proposal_persists_as_governed_plan_without_execution(self):
        out = self.call(self.base())
        self.assertTrue(out["ok"], out)
        plan = m.TsRemediationPlan.objects.get(record_id=out["data"]["plan_id"])
        self.assertEqual((plan.status, plan.tier, plan.basis), ("RISK_ASSESSED", 2, "AI_INFERRED"))
        self.assertEqual(plan.operations, [VALID])
        self.assertEqual(plan.approval["approved_by"], "")
        self.assertEqual(self.ports.executor.applied, [])                          # proposing never writes
        with self.assertRaises(gov.GovernanceRefused):
            gov.execute(self.ag, plan.record_id, self.ports, idempotency_key="agent-exec", now=T0)
        self.assertTrue(m.TsAuditEvent.objects.filter(case=self.case, operation="propose_remediation").exists())

    def test_string_operations_are_denied_not_crashed(self):
        out = self.call(self.base(operations=["interface Ethernet1", "no shutdown"]))
        self.assertEqual((out["status"], out["error_code"]), ("DENIED", "INVALID_OPERATION"))
        self.assertEqual(m.TsRemediationPlan.objects.filter(case=self.case).count(), 0)

    def test_unsupported_kind_and_missing_rollback_rejected(self):
        self.assertEqual(self.call(self.base(operations=[{**VALID, "kind": "interface_magic"}]))["error_code"], "INVALID_OPERATION")
        self.assertEqual(self.call(self.base(rollback_plan={"steps": []}))["error_code"], "NO_ROLLBACK_PLAN")
        self.assertEqual(m.TsRemediationPlan.objects.filter(case=self.case).count(), 0)

    def test_out_of_scope_device_still_denied(self):
        out = self.call(self.base(operations=[{**VALID, "device": "r9"}]))
        self.assertFalse(out["ok"])
        self.assertEqual(m.TsRemediationPlan.objects.filter(case=self.case).count(), 0)


class InterfaceEnableTests(SimpleTestCase):
    OP = {"kind": "interface_enable", "device": "R2", "interface": "Ethernet1", "intended_state": "admin_up"}

    def test_registered_and_schema_valid(self):
        self.assertIn("interface_enable", gov.OP_KINDS)
        self.assertIn("interface_enable", gov.OPERATION_SCHEMA["properties"]["kind"]["enum"])
        self.assertEqual(gov.validate_operation(self.OP), "")

    def test_requires_exact_interface_and_admin_up_intent(self):
        no_if = {k: v for k, v in self.OP.items() if k != "interface"}
        self.assertIn("requires field 'interface'", gov.validate_operation(no_if))
        self.assertIn("requires intended_state='admin_up'", gov.validate_operation({**self.OP, "intended_state": "admin_down"}))
        self.assertIn("malformed", gov.validate_operation({**self.OP, "interface": "Ethernet*"}))

    def test_traffic_affecting_high_risk_is_never_tier3_even_if_preauthorized(self):
        ports = gov.Ports(preauthorizations=lambda op: {"id": "PA-R2-E1", "devices": ["R2"], "idempotent": True,
                                                         "expires_at": "2999-01-01T00:00:00Z"})
        risk = gov.assess([self.OP], ports=ports)
        self.assertEqual((risk["tier"], risk["traffic_affecting"], risk["preauth"]), (2, True, []))
