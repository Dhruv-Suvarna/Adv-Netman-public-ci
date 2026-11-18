"""Troubleshooting routes behind the NMAS website access boundary (port of JOB-9AA10B4E7CA7 into the authoritative repository).

Two independent layers must both allow a request:
  * ``NmasAccessMiddleware`` -- authenticated session, website MFA and the NMAS action the route is classified with in
    ``core.services.identity.policy``;
  * the troubleshooting view -- a ``ts-*`` role, tenant and device scope, and server-side remediation availability.

TSACC-* tests prove each layer refuses on its own, that the route classification matches the views' action map, and that
the UI never shows an enabled remediation button the NMAS layer would refuse (UT-089).
"""

from __future__ import annotations

import json

from django.test import TestCase, override_settings
from django.urls import get_resolver

from core import models as m
from core.services.identity import policy
from core.services.identity.policy import Action
from core.services.troubleshooting import governance as gov
from core.services.troubleshooting import repository as repo
from core.tests.helpers.troubleshooting import anonymous, ts_sign_in, ts_user
from core.tests.test_troubleshooting_governance import FakeExecutor, make_case, make_ports, propose, seed_deterministic
from core.tests.test_troubleshooting_views import PORTS_FACTORY, _PORTS, api
from core import troubleshooting_urls, troubleshooting_views

TS_ROUTE_PREFIXES = ("troubleshooting_", "ts_api_")


def ts_route_names():
    return sorted(n for n in get_resolver().reverse_dict.keys() if isinstance(n, str) and n.startswith(TS_ROUTE_PREFIXES))


class RouteClassificationTests(TestCase):
    def test_TSACC_001_every_troubleshooting_route_is_classified_exactly_once(self):
        names = [p.name for p in troubleshooting_urls.urlpatterns]
        self.assertEqual(len(names), len(set(names)))
        for name in names:
            in_read, in_mut = name in policy.READ_ROUTES, name in policy.MUTATION_ROUTES
            self.assertTrue(in_read ^ in_mut, f"{name}: must be in exactly one of READ_ROUTES / MUTATION_ROUTES")
            self.assertNotEqual(policy.required_action(name, "GET")[0], policy.Decision.DENY, name)

    def test_TSACC_002_plan_action_routes_match_the_view_permission_map(self):
        self.assertEqual(set(troubleshooting_urls.PLAN_ACTIONS), set(troubleshooting_views.PLAN_ACTION_PERMISSION))
        for prefix in ("troubleshooting_plan_", "ts_api_plan_"):
            for action, needed in troubleshooting_views.PLAN_ACTION_PERMISSION.items():
                self.assertEqual(policy.MUTATION_ROUTES[prefix + action], needed, prefix + action)
        # no generic "<action>" route survives: an action that is not listed has no URL at all
        self.assertFalse(any(n.endswith("plan_action") for n in ts_route_names()))

    def test_TSACC_003_writes_and_diagnostics_need_more_than_view(self):
        self.assertEqual(policy.MUTATION_ROUTES["ts_api_run"], Action.VALIDATE)         # read-only device collection
        self.assertEqual(policy.MUTATION_ROUTES["ts_api_exception"], Action.APPROVE)    # alarm suppression is an approval
        self.assertEqual(policy.MUTATION_ROUTES["ts_api_plan_execute"], Action.EXECUTE)
        for name in ("ts_api_case", "ts_api_report", "ts_api_export", "troubleshooting_detail"):
            self.assertEqual(policy.required_action(name, "POST")[0], policy.Decision.METHOD_NOT_ALLOWED, name)

    def test_TSACC_004_raw_evidence_export_report_and_audit_are_audited_reads(self):
        for name in ("ts_api_evidence_item", "ts_api_export", "ts_api_report", "ts_api_audit"):
            self.assertEqual(policy.action_category(name, "GET"), "sensitive_read", name)


class LayeredAccessTests(TestCase):
    def setUp(self):
        self.case = make_case(actor=repo.Actor("alice", "user", tenant="acme"))
        self.ev = seed_deterministic(self.case)

    def test_TSACC_010_nmas_permission_without_ts_role_is_refused_by_the_view(self):
        full = ts_user("nmas-only", nmas=set(Action))           # every NMAS permission, no ts-* role
        ts_sign_in(self.client, full)
        r = self.client.get(api(self.case.case_id))
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.json()["error"]["code"], "UNAUTHENTICATED")

    def test_TSACC_011_ts_role_without_nmas_permission_is_refused_by_the_middleware(self):
        bare = ts_user("ts-only", "ts-admin", "ts-tenant:acme", nmas=set())
        ts_sign_in(self.client, bare)
        r = self.client.get(api(self.case.case_id))
        self.assertEqual(r.status_code, 403)
        self.assertEqual(r.json()["status"], "forbidden")
        self.assertTrue(m.AuditEvent.objects.filter(event_type=m.AuditEventType.ACCESS_DENIED).exists())

    def test_TSACC_012_mfa_pending_session_reaches_no_case_data(self):
        admin = ts_user("pending", "ts-admin", "ts-tenant:acme")
        ts_sign_in(self.client, admin, mfa_verified=False)
        r = self.client.get(api(self.case.case_id))
        self.assertEqual(r.status_code, 302)
        self.assertIn("/accounts/mfa/", r["Location"])
        self.assertNotIn(self.case.case_id.encode(), r.content)

    def test_TSACC_013_anonymous_api_gets_json_401_and_page_gets_login(self):
        anonymous(self.client)
        r = self.client.post(api(self.case.case_id, "run/"), json.dumps({}), content_type="application/json")
        self.assertEqual((r.status_code, r.json()["status"]), (401, "unauthenticated"))
        self.assertEqual(m.TsCollectionRun.objects.filter(case=self.case).count(), 0)
        page = self.client.get(f"/troubleshooting/{self.case.case_id}/")
        self.assertEqual(page.status_code, 302)

    def test_TSACC_014_tenant_scope_still_applies_with_full_nmas_permissions(self):
        other = ts_user("other-tenant", "ts-admin", "ts-tenant:zzz")
        ts_sign_in(self.client, other)
        self.assertEqual(self.client.get(api(self.case.case_id)).status_code, 404)   # no existence oracle across tenants


@override_settings(NMAS_TS_PORTS_FACTORY=PORTS_FACTORY)
class ButtonGatingTests(TestCase):
    def setUp(self):
        self.case = make_case(actor=repo.Actor("alice", "user", tenant="acme"))
        self.ev = seed_deterministic(self.case)
        self.ports = make_ports(FakeExecutor())
        _PORTS["ports"] = self.ports
        self.plan = propose(self.case, self.ev, ports=self.ports)

    def test_TSACC_020_ts_approver_without_nmas_approve_sees_disabled_approve_and_is_refused(self):
        op = ts_user("op", "ts-operator", "ts-tenant:acme")
        ts_sign_in(self.client, op)
        base = api(self.case.case_id, f"remediation/{self.plan.record_id}/")
        self.assertEqual(self.client.post(base + "dry_run/", "{}", content_type="application/json").status_code, 200)
        # holds the ts-approver role but only operator-level NMAS permissions
        half = ts_user("half", "ts-approver", "ts-tenant:acme", nmas={Action.VIEW, Action.EDIT, Action.VALIDATE, Action.PLAN})
        ts_sign_in(self.client, half)
        actions = self.client.get(api(self.case.case_id, "remediation/")).json()["data"]["plans"][0]["actions"]
        self.assertFalse(actions["approve"]["enabled"])
        self.assertIn("core.nmas_approve", actions["approve"]["reason"])
        html = self.client.get(f"/troubleshooting/{self.case.case_id}/").content.decode()
        self.assertNotIn(f'remediation/{self.plan.record_id}/approve/"', html)
        r = self.client.post(base + "approve/", json.dumps({"reason": "trying without permission", "acknowledgements": ["x"]}),
                             content_type="application/json")
        self.assertEqual(r.status_code, 403)
        self.assertEqual(m.TsRemediationPlan.objects.get(pk=self.plan.pk).status, "DRY_RUN_PASS")

    def test_TSACC_021_server_side_recheck_refuses_without_nmas_permission_even_past_the_route(self):
        # The view's own re-check (defence in depth) refuses an action whose NMAS permission the principal lacks,
        # independently of the middleware -- e.g. a custom principal resolver or a future route alias.
        p = troubleshooting_views.Principal(repo.Actor("bob", "user", tenant="acme"), frozenset({"approver"}),
                                            frozenset({Action.VIEW, Action.VALIDATE}))
        gov.dry_run(p.actor, self.plan.record_id, self.ports)
        with self.assertRaises(gov.GovernanceRefused) as ctx:
            troubleshooting_views._run_plan_action(p, self.case.case_id, self.plan.record_id, "approve",
                                                   {"reason": "approve without permission", "acknowledgements": ["x"]})
        self.assertEqual(ctx.exception.code, "ACTION_DISABLED")
        self.assertEqual(m.TsRemediationPlan.objects.get(pk=self.plan.pk).status, "DRY_RUN_PASS")


class DispositionRenderingTests(TestCase):
    """Campaign 017 regression: intake closes a non-remediated case with a disposition that has an ``outcome`` but neither
    ``why`` nor ``reason``.  ``{{ x.why|default:x.reason }}`` raises VariableDoesNotExist for a missing FILTER ARGUMENT, so the
    case page returned HTTP 500 for every such case (TS-20261117-73612A0C/-DE55BBB8/-DFBE1EB8)."""

    def test_TSACC_030_safe_non_remediation_disposition_without_reason_renders(self):
        case = make_case(actor=repo.Actor("alice", "user", tenant="acme"))
        seed_deterministic(case)
        case.disposition = {"outcome": "SAFE_NON_REMEDIATION", "remediation_decision": "DIAGNOSE_AND_ESCALATE",
                            "fault_category": "OPERATIONAL_LINK_DOWN", "cleared_externally": True, "nmas_performed_repair": False}
        case.save(update_fields=["disposition"])
        ts_sign_in(self.client, ts_user("viewer", "ts-admin", "ts-tenant:acme"))
        page = self.client.get(f"/troubleshooting/{case.case_id}/")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b"SAFE_NON_REMEDIATION", page.content)
        case.disposition = {**case.disposition, "reason": "fault cleared externally"}
        case.save(update_fields=["disposition"])
        self.assertIn(b"fault cleared externally", self.client.get(f"/troubleshooting/{case.case_id}/").content)


class TopologyPathPageTests(TestCase):
    """Topology-wide path evidence is persisted as TsTopologyPath rows and rendered (every ECMP branch, incident hits marked)."""

    def test_TSACC_031_paths_are_recorded_and_rendered_with_incident_traversal(self):
        from datetime import datetime, timezone
        from types import SimpleNamespace

        from core.services.troubleshooting import intake
        from core.tests.test_troubleshooting_routing import lab

        ribs4, ribs6, addrs, links = lab()
        snapshot = {"ribs4": ribs4, "ribs6": ribs6, "addresses": addrs, "links": links, "unreadable": [], "collected_at": "x"}
        case = make_case(actor=repo.Actor("alice", "user", tenant="acme"))
        seed_deterministic(case)
        scope_device = sorted(repo._case_devices(case))[0]  # pylint: disable=protected-access
        incident = SimpleNamespace(devices=[scope_device], samples=[SimpleNamespace(device="S1", interface="Ethernet1")], members=[])
        actor = repo.Actor("nmas-intake", "system", tenant="acme", devices=frozenset({scope_device}))
        ids = intake.record_topology_paths(actor, case, incident, None, datetime.now(timezone.utc), snapshot=snapshot)
        self.assertEqual(len(ids), 6)                                   # 1 + 1 protected branches, 2 + 2 ECMP service branches
        rows = m.TsTopologyPath.objects.filter(case=case)
        web = [r for r in rows if r.service.startswith("H1-WEB-v4")]
        self.assertEqual(len(web), 2)
        self.assertTrue(all("egresses incident interface S1:Ethernet1" in r.divergence for r in web))
        self.assertTrue(all(not r.divergence for r in rows if r.service.startswith("H1-H2")))
        audit = m.TsAuditEvent.objects.get(case=case, action="TOPOLOGY_PATHS")
        self.assertEqual(audit.result, "AFFECTED")
        ts_sign_in(self.client, ts_user("viewer", "ts-admin", "ts-tenant:acme"))
        page = self.client.get(f"/troubleshooting/{case.case_id}/").content.decode()
        self.assertIn("Topology-aware investigation", page)
        self.assertIn("H1-WEB-v6 (service)", page)
        section = page.split("Topology-aware investigation", 1)[1].split("Configuration drift vs live service impact", 1)[0]
        self.assertEqual(section.count("egresses incident interface S1:Ethernet1"), 4)          # 4 service branches; also in the report
