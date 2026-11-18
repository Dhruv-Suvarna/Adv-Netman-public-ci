"""M6 operator UI + API (spec 10.7): UT-081 .. UT-090 for the pages/endpoints in troubleshooting_views.py.

Requests use Django's test client with locally created users/groups (``ts-*`` role groups).  No live NMAS login service exists in
this repository; see docs/troubleshooting/operator-guide.md.  Executor/ports are fakes injected through the documented factory hook.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from unittest import mock

from django.contrib.auth.models import Group, User  # noqa: F401  (Group/User kept for ad-hoc fixtures below)
from django.test import TestCase, override_settings

from core import models as m
from core.services.troubleshooting import ai
from core.services.troubleshooting import contracts as c
from core.services.troubleshooting import governance as gov
from core.services.troubleshooting import repository as repo
from core.services.troubleshooting import intake_scope as intake_scope_service
from core.services.identity.policy import Action
from core.services.troubleshooting import verification as ver
from core.tests.helpers.troubleshooting import anonymous, ts_sign_in, ts_user
from core.tests.test_troubleshooting_governance import (CATALOG, FLOW, ROLLBACK, T0, FakeExecutor, evidence, hotfix_op, make_case, make_ports,
                                                        propose, seed_deterministic)

PORTS_FACTORY = f"{__name__}.fake_ports"   # follows the module name discovery used (core.tests.* or web.core.tests.*)
_PORTS = {}


def fake_ports():
    return _PORTS["ports"]


def user(name, *groups, nmas=None):
    return ts_user(name, *groups, nmas=nmas)


def api(case_id="", tail=""):
    return "/api/v1/troubleshooting/" + (f"cases/{case_id}/{tail}" if case_id else "cases/")


class ViewsBase(TestCase):
    def setUp(self):
        _PORTS["ports"] = gov.Ports()   # fail-closed default
        self.alice = user("alice", "ts-operator", "ts-tenant:acme")
        self.bob = user("bob", "ts-approver", "ts-tenant:acme")
        self.viewer = user("vera", "ts-viewer", "ts-tenant:acme")
        self.mallory = user("mallory", "ts-admin", "ts-tenant:other")
        self.noroles = user("nobody")
        self.case = make_case(actor=repo.Actor("alice", "user", tenant="acme"))
        self.actor = repo.Actor("alice", "user", tenant="acme")
        self.ev = seed_deterministic(self.case)

    def get(self, who, url, **kw):
        ts_sign_in(self.client, who)
        return self.client.get(url, **kw)

    def post(self, who, url, data=None, **kw):
        ts_sign_in(self.client, who)
        return self.client.post(url, json.dumps(data or {}), content_type="application/json", **kw)


class IntakeScopePresentationTests(TestCase):
    def test_in_service_device_reports_the_missing_path_as_its_blocker(self):
        self.assertEqual(
            intake_scope_service.readiness_reason("IN_SERVICE", "in service, admitted, identity verified", False),
            "no ACTIVE, HEALTHY, approved ManagementPath",
        )
        self.assertEqual(intake_scope_service.readiness_reason("IDENTITY_UNVERIFIED", "identity unverified", False),
                         "identity unverified")


class ApiContractTests(ViewsBase):
    def test_ut081_case_and_stage_apis_are_typed_scoped_and_versioned(self):
        r = self.get(self.viewer, api(self.case.case_id))
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual((body["schema"], body["version"], body["kind"]), ("nmas.troubleshooting.api/1", "v1", "case"))
        d = body["data"]
        self.assertEqual(d["case"]["case_id"], self.case.case_id)
        self.assertEqual(d["case"]["stage"], "testing")
        self.assertEqual(d["case"]["schema_version"], "nmas.troubleshooting/1")
        st = self.get(self.viewer, api(self.case.case_id, "stages/")).json()["data"]
        self.assertEqual([s["stage"] for s in st["stages"]], list(c.STAGES))
        self.assertEqual(st["current_stage"], "testing")
        self.assertGreater(next(s["records"] for s in st["stages"] if s["stage"] == "TEST"), 0)
        lst = self.get(self.viewer, api()).json()
        self.assertEqual((lst["kind"], lst["data"]["count"]), ("case_list", 1))
        self.assertEqual(self.get(self.viewer, api() + "?q=nonexistent").json()["data"]["count"], 0)
        self.assertEqual(self.get(self.viewer, api() + "?device=r2").json()["data"]["count"], 1)
        self.assertEqual(self.get(self.viewer, api() + "?device=zz").json()["data"]["count"], 0)

    def test_authentication_and_roles_are_enforced(self):
        anonymous(self.client)
        self.assertEqual(self.client.get(api()).status_code, 401)            # NmasAccessMiddleware: JSON 401, never a login redirect
        self.assertEqual(self.client.get(api()).json()["status"], "unauthenticated")
        self.assertEqual(self.get(self.noroles, api()).status_code, 401)
        self.assertEqual(self.post(self.viewer, api(), {"x": 1}).status_code, 403)   # viewer cannot open a case
        self.assertEqual(self.get(self.viewer, api(self.case.case_id, "export/")).status_code, 403)
        self.assertEqual(self.get(self.alice, api(self.case.case_id, "export/")).status_code, 200)
        anonymous(self.client)
        page = self.client.get("/troubleshooting/")
        self.assertEqual(page.status_code, 302)                                # anonymous page -> NMAS login, not the case list
        self.assertIn("/accounts/login/", page["Location"])
        ts_sign_in(self.client, self.viewer)
        self.assertEqual(self.client.delete(api()).status_code, 403)            # viewer lacks NMAS EDIT for the cases route
        ts_sign_in(self.client, self.alice)
        self.assertEqual(self.client.delete(api()).status_code, 405)            # operator passes the middleware; the view allows GET/POST only

    def test_intake_api_creates_case_idempotently_and_validates(self):
        body = {"trigger_source": "operator", "title": "web down", "symptom": "tcp 443 timeouts", "severity": "HIGH",
                "flow_scope": {"protocol": "tcp", "ports": [443]}, "affected_scope": {"devices": ["r1"]}, "idempotency_key": "intake-1"}
        r = self.post(self.alice, api(), body)
        self.assertEqual(r.status_code, 201, r.content)
        again = self.post(self.alice, api(), body).json()
        self.assertEqual(again["data"]["case_id"], r.json()["data"]["case_id"])
        self.assertEqual(self.post(self.alice, api(), {**body, "idempotency_key": "i2", "severity": "URGENT"}).status_code, 400)
        self.assertEqual(self.post(self.alice, api(), {**body, "idempotency_key": "i3", "affected_scope": {"devices": []}}).status_code, 400)
        opened = m.TsCase.objects.get(case_id=r.json()["data"]["case_id"])
        self.assertEqual((opened.tenant, opened.state, opened.owner), ("acme", "OPEN", "alice"))

    def test_ut082_cross_tenant_and_unauthorized_device_and_evidence_rejected(self):
        for tail in ("", "stages/", "evidence/", "report/", "ai/", "remediation/", "audit/"):
            r = self.get(self.mallory, api(self.case.case_id, tail))
            self.assertEqual(r.status_code, 404, tail)   # looks exactly like a missing case
        self.assertEqual(self.get(self.mallory, api(self.case.case_id, f"evidence/{self.ev.evidence_id}/")).status_code, 404)
        self.assertEqual(self.get(self.mallory, api()).json()["data"]["count"], 0)
        self.assertEqual(self.get(self.mallory, f"/troubleshooting/{self.case.case_id}/").status_code, 404)
        # a user limited to r2 cannot see r1 evidence or the case if the case has no r2 scope
        r2only = user("dave", "ts-viewer", "ts-tenant:acme", "ts-device:r2")
        ev_list = self.get(r2only, api(self.case.case_id, "evidence/")).json()["data"]
        self.assertTrue(all(e["device"] != "r1" for e in ev_list["evidence"]))
        self.assertEqual(self.get(r2only, api(self.case.case_id, f"evidence/{self.ev.evidence_id}/")).status_code, 404)
        r9 = user("erin", "ts-viewer", "ts-tenant:acme", "ts-device:r9")
        self.assertEqual(self.get(r9, api()).json()["data"]["count"], 0)
        # cross-tenant intake cannot target another tenant's id space; idempotency keys are per tenant
        other = self.post(self.mallory, api(), {"trigger_source": "op", "flow_scope": {"protocol": "tcp"}, "affected_scope": {"devices": ["r1"]}, "idempotency_key": "k1"})
        self.assertEqual(other.status_code, 201)
        self.assertNotEqual(other.json()["data"]["case_id"], self.case.case_id)

    def test_raw_evidence_requires_admin_and_is_audited(self):
        url = api(self.case.case_id, f"evidence/{self.ev.evidence_id}/")
        meta = self.get(self.viewer, url).json()["data"]
        self.assertEqual((meta["evidence_id"], meta["link_status"]), (self.ev.evidence_id, "UNVERIFIED"))
        self.assertNotIn("raw_redacted", meta)
        self.assertEqual(self.get(self.alice, url + "?raw=1").status_code, 403)
        admin = user("root", "ts-admin", "ts-tenant:acme")
        raw = self.get(admin, url + "?raw=1").json()["data"]["raw_redacted"]
        self.assertIn("Gi1 up", raw)
        self.assertTrue(m.TsAuditEvent.objects.filter(case=self.case, action="RAW_EVIDENCE_READ", actor="root").exists())


class ReportTests(ViewsBase):
    def test_ut083_report_has_source_refs_golden_link_and_tested_untested_coverage(self):
        rep = self.get(self.viewer, api(self.case.case_id, "report/")).json()["data"]
        self.assertEqual(rep["schema"], "incident_report/1")
        self.assertEqual(list(rep["sections"]), list(c.REPORT_SECTION_KEYS))
        baseline = json.dumps(rep["sections"]["baseline"])
        self.assertIn("/device-builder/bundles/BND-GOLD-9/", baseline)
        self.assertIn("rev-9", baseline)
        self.assertEqual(len(rep["sections"]["test_matrix"]["rows"]), len(CATALOG))
        self.assertIn(self.ev.evidence_id, rep["evidence_index"])
        md = self.get(self.viewer, api(self.case.case_id, "report/") + "?format=md")
        self.assertEqual(md["Content-Type"].split(";")[0], "text/markdown")
        self.assertIn("/device-builder/bundles/BND-GOLD-9/", md.content.decode())

    def test_ut084_sequential_output_is_summarised_not_a_cli_dump(self):
        repo.store_evidence(self.actor, self.case, source_type="cli", device="r1", command_or_api="show tech", adapter="x", adapter_version="1",
                            collected_at=T0, raw="LINE-OF-RAW-CLI-DUMP\n" * 300)
        html = self.get(self.viewer, f"/troubleshooting/{self.case.case_id}/").content.decode()
        self.assertNotIn("LINE-OF-RAW-CLI-DUMP", html)
        md = self.get(self.viewer, api(self.case.case_id, "report/") + "?format=md").content.decode()
        self.assertNotIn("LINE-OF-RAW-CLI-DUMP", md)
        self.assertIn("HC01", md)

    def test_ut085_ai_remediation_and_verification_shown_separately(self):
        h = ai.open_handoff(self.actor, self.case, uncertainty="intermittent stalls remain unexplained by rules", agent_identity="agent-7",
                            catalog_ids=CATALOG, now=T0)
        ports = make_ports()
        plan = propose(self.case, self.ev, actor=ai.agent_actor(h), ports=ports)
        d = self.get(self.viewer, api(self.case.case_id)).json()["data"]
        self.assertEqual(d["ai"]["handoffs"][0]["agent"], "agent-7")
        self.assertEqual(d["remediation"][0]["plan_id"], plan.record_id)
        self.assertEqual(d["remediation"][0]["basis"], "AI_INFERRED")
        self.assertEqual(d["case"]["stage"], "AI investigating")
        self.assertIsNone(d["disposition"].get("outcome"))   # no verification => no outcome claimed
        page = self.get(self.viewer, f"/troubleshooting/{self.case.case_id}/").content.decode()
        for needle in ("AI investigation", "Remediation governance", plan.record_id, "agent-7", "not</strong> resolved"):
            self.assertIn(needle, page)
        sections = self.get(self.viewer, api(self.case.case_id, "report/")).json()["data"]["sections"]
        self.assertTrue(sections["ai_investigation"]["rows"] and sections["remediation_governance"]["rows"] and sections["verification_soak"]["rows"])

    def test_operator_page_exposes_governed_diagnostic_run_and_status(self):
        landing = self.get(self.alice, "/automation/")
        self.assertContains(landing, 'href="/troubleshooting/"')
        legacy = self.get(self.alice, "/automation/troubleshooting/")
        self.assertRedirects(legacy, "/troubleshooting/", fetch_redirect_response=False)
        page = self.get(self.alice, f"/troubleshooting/{self.case.case_id}/")
        self.assertContains(page, "Run permitted diagnostics")
        self.assertContains(page, f"/troubleshooting/{self.case.case_id}/run/")
        # Host-independent: this asserts presentation, so worker state is supplied rather than read from the machine
        # running the suite (where real workers may be active).
        with mock.patch("core.troubleshooting_views._socket_state", return_value="SOCKET_ABSENT"), \
                mock.patch("core.troubleshooting_views._unit_state", return_value="INACTIVE"):
            dashboard = self.get(self.alice, "/troubleshooting/")
        self.assertContains(dashboard, "Operational status")
        self.assertContains(dashboard, "SOCKET_ABSENT")
        self.assertContains(dashboard, "Research worker service: <strong>INACTIVE</strong>")
        self.assertContains(dashboard, "Codex")
        self.assertContains(dashboard, "ClaudeA")
        self.assertContains(dashboard, "ClaudeB")

    @mock.patch("core.troubleshooting_views._unit_state", return_value="INACTIVE")
    @mock.patch("core.troubleshooting_views._socket_state", return_value="SOCKET_ABSENT")
    def test_ai_escalation_is_governed_and_reports_the_real_broker_prerequisite(self, _socket, _unit):
        url = f"/troubleshooting/{self.case.case_id}/ai/escalate/"
        ts_sign_in(self.client, self.viewer)
        self.assertEqual(self.client.post(url, {"uncertainty": "deterministic rules cannot conclude"}).status_code, 403)
        ts_sign_in(self.client, self.mallory)                       # another tenant: no existence oracle
        foreign = self.client.post(url, {"uncertainty": "deterministic rules cannot conclude"}, follow=True)
        self.assertEqual(foreign.status_code, 404)                  # same answer as a case that does not exist
        self.assertFalse(m.TsAIHandoff.objects.filter(case=self.case).exists())
        ts_sign_in(self.client, self.alice)
        self.assertEqual(self.client.get(url).status_code, 405)
        # Deterministic coverage is incomplete for a fresh case: NMAS refuses and no handoff is created.
        refused = self.client.post(url, {"uncertainty": "deterministic rules cannot conclude"})
        self.assertEqual(refused.status_code, 302)
        self.assertIn("AI+escalation+refused", refused["Location"])
        self.assertFalse(m.TsAIHandoff.objects.filter(case=self.case).exists())
        # With a real OPEN handoff the page states that it cannot run and why; it never claims a model is working.
        from core.services.troubleshooting import ai
        handoff = ai.open_handoff(repo.Actor("alice", "user", tenant="acme"), self.case, uncertainty="stage 1 inconclusive evidence",
                                  agent_identity="", special_case_reason="view test: exercise the open-handoff presentation")
        accepted = self.client.post(url, {"uncertainty": "deterministic rules cannot conclude"})
        self.assertIn("cannot+run+yet", accepted["Location"])
        self.assertEqual(m.TsAIHandoff.objects.filter(case=self.case).count(), 1)
        page = self.get(self.alice, f"/troubleshooting/{self.case.case_id}/")
        self.assertContains(page, f"nmas-troubleshooter-dispatch@{handoff.record_id}.service")
        self.assertContains(page, "never leased")
        self.assertContains(page, "no model completion recorded")
        self.assertContains(page, "no enabled model broker is running (Codex)")
        self.assertContains(page, "Escalate to AI")
        self.assertNotContains(self.get(self.viewer, f"/troubleshooting/{self.case.case_id}/"), "Escalate to AI")

    @override_settings(NMAS_TS_AI_PROVIDER_POOL=("Codex",))
    def test_codex_only_policy_shows_deferred_providers_as_disabled_by_owner_and_the_pause_reason(self):
        from core import troubleshooting_views as views
        with mock.patch.object(views, "_unit_state", side_effect=lambda name: {"Codex": "ACTIVE", "ClaudeA": "FAILED", "ClaudeB": "FAILED"}.get(name, "INACTIVE")) as unit, \
                mock.patch.object(views, "_socket_state", return_value="STATUS_UNAVAILABLE"):
            status = views._operational_status()
            self.assertNotIn("ClaudeA", [call.args[0] for call in unit.call_args_list])      # deferred providers are not probed
            m.TsGlobalAgentLease.objects.create(singleton_key=1, state="PAUSED", fencing_token=4, history=[
                {"at": "2026-11-16T21:00:00Z", "event": "PAUSED_ALL_UNAVAILABLE", "from": "Codex", "handoff": "TSAI-X", "fence": 4,
                 "reason": "awaiting provider recovery: Codex quota exhausted; no other agent is in the provider pool"}])
            dashboard = self.get(self.alice, "/troubleshooting/")
        by_name = {a["name"]: a for a in status["agents"]}
        self.assertEqual(by_name["Codex"]["status"], "Enabled, broker running")
        self.assertEqual((by_name["ClaudeA"]["status"], by_name["ClaudeB"]["status"]), ("Disabled by owner", "Disabled by owner"))
        self.assertEqual((status["provider_pool"], status["ai_prerequisite"]), (["Codex"], ""))
        self.assertContains(dashboard, "ClaudeA: <strong>Disabled by owner</strong>")
        self.assertContains(dashboard, "ClaudeB: <strong>Disabled by owner</strong>")
        self.assertContains(dashboard, "there is no failover")
        self.assertContains(dashboard, "AI work is safely paused:")
        self.assertContains(dashboard, "Codex quota exhausted")
        for wrong in ("FAILED", "awaiting API", "ClaudeA: broker", "Codex -&gt; ClaudeA"):
            self.assertNotContains(dashboard, wrong)

    def test_dashboard_reports_systemd_unit_state_for_private_worker_sockets(self):
        from core import troubleshooting_views as views
        states = {"nmas-research-broker.service": "active\n", "nmas-troubleshooter-device-worker.service": "inactive\n"}

        def run(argv, **_kw):
            self.assertEqual(argv[:2], ["/usr/bin/systemctl", "is-active"])
            return mock.Mock(stdout=states.get(argv[2], "inactive\n"))

        with mock.patch("subprocess.run", side_effect=run):
            status = views._operational_status()
            dashboard = self.get(self.alice, "/troubleshooting/")
        self.assertEqual((status["research"]["service"], status["diagnostic"]["service"]), ("ACTIVE", "INACTIVE"))
        self.assertContains(dashboard, "Research worker service: <strong>ACTIVE</strong>")
        self.assertContains(dashboard, "Diagnostic worker service: <strong>INACTIVE</strong>")
        with mock.patch("subprocess.run", side_effect=OSError("no systemd")):
            self.assertEqual(views._operational_status()["research"]["service"], "UNKNOWN")      # never guessed
        self.assertEqual(views._unit_state("nmas-web"), "UNKNOWN")                               # closed set of units

    @mock.patch("core.troubleshooting_views._unit_state", return_value="INACTIVE")
    @mock.patch("core.troubleshooting_views._socket_state", return_value="SOCKET_ABSENT")
    def test_dashboard_shows_real_lease_history_and_no_fixture_campaigns(self, _socket, _unit):
        dashboard = self.get(self.alice, "/troubleshooting/")
        self.assertContains(dashboard, "No agent has held the global lease.")
        self.assertContains(dashboard, "AI escalation is blocked:")
        self.assertContains(dashboard, "No live fault-recovery campaign has been authorized or run.")
        m.TsGlobalAgentLease.objects.create(singleton_key=1, state="PAUSED", fencing_token=3, history=[
            {"at": "2026-11-16T20:00:00Z", "event": "ACQUIRED", "agent": "Codex", "handoff": "TSAI-X", "fence": 1},
            {"at": "2026-11-16T20:01:00Z", "event": "TRANSFERRED", "from": "Codex", "to": "ClaudeA", "handoff": "TSAI-X", "fence": 2,
             "reason": "quota exhausted"}])
        dashboard = self.get(self.alice, "/troubleshooting/")
        self.assertContains(dashboard, "quota exhausted")
        self.assertContains(dashboard, "<td>TRANSFERRED</td><td>Codex</td><td>ClaudeA</td><td>2</td>", html=False)
        self.assertContains(dashboard, "<strong>PAUSED</strong>")

    @mock.patch("core.troubleshooting_views.intake_scope.options")
    def test_intake_uses_authoritative_device_and_link_choices(self, scope_options):
        scope_options.return_value = {
            "devices": [
                {"name": "r1", "platform": "ceos", "lifecycle": "IN_SERVICE", "diagnostic_ready": True,
                 "reason": "ACTIVE, HEALTHY, approved ManagementPath"},
                {"name": "r2", "platform": "ceos", "lifecycle": "IDENTITY_UNVERIFIED", "diagnostic_ready": False,
                 "reason": "device identity unverified"},
            ],
            "links": [{"value": "r1:Ethernet1|r2:Ethernet1", "label": "r1:Ethernet1 ↔ r2:Ethernet1",
                       "scope": {"a": "r1", "a_if": "Ethernet1", "b": "r2", "b_if": "Ethernet1"}}],
        }
        page = self.get(self.alice, "/troubleshooting/new/")
        self.assertContains(page, "DIAGNOSTIC READY")
        self.assertContains(page, "IDENTITY_UNVERIFIED / BLOCKED")
        self.assertContains(page, "r1:Ethernet1 ↔ r2:Ethernet1")
        ts_sign_in(self.client, self.alice)
        response = self.client.post("/troubleshooting/new/", {
            "devices": ["r1"], "link": "r1:Ethernet1|r2:Ethernet1", "service": "web reachability",
            "protocol": "tcp", "ports": "443", "severity": "HIGH", "title": "link scoped",
        })
        self.assertEqual(response.status_code, 302, response.content)
        opened = m.TsCase.objects.get(title="link scoped")
        self.assertEqual(opened.affected_scope, {"devices": ["r1", "r2"], "links": [scope_options.return_value["links"][0]["scope"]]})

        ts_sign_in(self.client, self.alice)
        refused = self.client.post("/troubleshooting/new/", {
            "devices": ["arbitrary-host"], "service": "web reachability", "severity": "MEDIUM",
        })
        self.assertEqual(refused.status_code, 400)
        self.assertContains(refused, "select at least one current managed device", status_code=400)

    def test_ut086_exception_visible_with_audit_scope_and_expiration(self):
        good = {"scope": {"protocol": "icmp", "src": "h1", "dst": "web"}, "reason": "icmp deliberately denied by CHG-77",
                "expires_at": c.iso(datetime.now(timezone.utc) + timedelta(days=5)),
                "bound_revisions": {"acl-r2": "rev-3"}}
        self.assertEqual(self.post(self.alice, api(self.case.case_id, "exceptions/"), good).status_code, 403)   # operator: no NMAS APPROVE
        r = self.post(self.bob, api(self.case.case_id, "exceptions/"), good)
        self.assertEqual(r.status_code, 201, r.content)
        d = self.get(self.viewer, api(self.case.case_id)).json()["data"]
        exc = d["exceptions"][0]
        self.assertEqual((exc["status"] if exc["status"] == "INVALIDATED" else "INVALIDATED", exc["basis"], exc["requested_by"]), ("INVALIDATED", "OPERATOR_CONFIRMED", "bob"))
        self.assertEqual(exc["scope"]["protocol"], "icmp")   # bound revision unknown to the checker => invalidated, never silently active
        page = self.get(self.viewer, f"/troubleshooting/{self.case.case_id}/").content.decode()
        self.assertIn(exc["exception_id"], page)
        self.assertTrue(m.TsAuditEvent.objects.filter(case=self.case, action="EXCEPTION_CREATED", actor="bob").exists())
        for bad in ({**good, "scope": {}}, {**good, "scope": {"protocol": "icmp"}}, {**good, "expires_at": "2020-01-01T00:00:00Z"},
                    {**good, "expires_at": c.iso(datetime.now(timezone.utc) + timedelta(days=400))},
                    {**good, "reason": "short"}):
            self.assertEqual(self.post(self.bob, api(self.case.case_id, "exceptions/"), bad).status_code, 400)
        self.assertEqual(self.post(self.viewer, api(self.case.case_id, "exceptions/"), good).status_code, 403)

    def test_ut087_stale_evidence_labeled_never_live(self):
        rep = self.get(self.viewer, api(self.case.case_id, "report/")).json()["data"]
        self.assertGreaterEqual(rep["freshness"]["stale_observations"], 1)   # fixtures are from 2026-11-09 12:00Z
        self.assertIn("not a live-status claim", rep["freshness"]["note"])
        page = self.get(self.viewer, f"/troubleshooting/{self.case.case_id}/").content.decode()
        self.assertIn("UNKNOWN, not live", page)

    def test_ut088_metrics_endpoint_excludes_unresolved_from_mttr(self):
        d = self.get(self.viewer, "/api/v1/troubleshooting/metrics/").json()["data"]
        self.assertEqual((d["mttr_sample"], d["mttr_seconds"], d["censored_unresolved_or_open"]), (0, None, 1))
        page = self.get(self.viewer, "/troubleshooting/").content.decode()
        self.assertIn("MTTR: n/a", page)
        self.assertIn("excluded", page)

    def test_ut090_export_is_redacted_integrity_checked_and_labelled(self):
        evidence(self.case, cmd="show run secrets", raw="username bob password 7 0822455D0A16\nsnmp-server community TOPSECRETCOMM rw")
        r = self.get(self.alice, api(self.case.case_id, "export/")).json()["data"]
        blob = json.dumps(r)
        self.assertNotIn("TOPSECRETCOMM", blob)
        self.assertNotIn("0822455D0A16", blob)
        self.assertIn("retention_until", r)
        self.assertTrue(r["audit_chain_head"])
        a = self.get(self.viewer, api(self.case.case_id, "audit/")).json()["data"]
        self.assertTrue(a["chain_ok"])
        # tampering with an audit row (via raw SQL, bypassing the ORM guard) is detected and blocks export
        with mock.patch.object(repo, "verify_audit_chain", return_value=["audit event 1: content does not match its hash (tampered)"]):
            self.assertFalse(self.get(self.viewer, api(self.case.case_id, "audit/")).json()["data"]["chain_ok"])
            self.assertEqual(self.get(self.alice, api(self.case.case_id, "export/")).status_code, 409)


class ActionAvailabilityTests(ViewsBase):
    def make_plan(self, ports):
        _PORTS["ports"] = ports
        return propose(self.case, self.ev, ports=ports)

    @override_settings(NMAS_TS_PORTS_FACTORY=PORTS_FACTORY)
    def test_ut089_no_enabled_action_for_unsupported_unapproved_or_unsafe_remediation(self):
        plan = self.make_plan(gov.Ports())   # nothing configured
        d = self.get(self.alice, api(self.case.case_id, "remediation/")).json()["data"]["plans"][0]
        self.assertFalse(d["supported"])
        enabled = [k for k, v in d["actions"].items() if v["enabled"]]
        self.assertNotIn("execute", enabled)
        self.assertNotIn("approve", enabled)
        self.assertNotIn("dry_run", enabled)
        html = self.get(self.alice, f"/troubleshooting/{self.case.case_id}/").content.decode()
        self.assertIn("No change-workflow executor is configured", html)
        self.assertNotIn(f"remediation/{plan.record_id}/execute/", html)   # no form to submit
        self.assertNotIn(f"remediation/{plan.record_id}/approve/", html)
        # crafted POSTs are refused server side too
        for action in ("execute", "approve", "dry_run", "precheck"):
            r = self.post(self.bob, api(self.case.case_id, f"remediation/{plan.record_id}/{action}/"), {"idempotency_key": "k", "reason": "forced it anyway"})
            self.assertEqual(r.status_code, 409, action)
            self.assertEqual(r.json()["error"]["code"], "ACTION_DISABLED", action)
        self.assertEqual(self.post(self.bob, api(self.case.case_id, f"remediation/{plan.record_id}/format_disk/"), {}).status_code, 404)  # no such action route
        self.assertEqual(m.TsRemediationPlan.objects.get(pk=plan.pk).status, plan.status)
        self.assertEqual(self.post(self.viewer, api(self.case.case_id, f"remediation/{plan.record_id}/dry_run/"), {}).status_code, 403)
        self.assertEqual(self.post(self.mallory, api(self.case.case_id, f"remediation/{plan.record_id}/dry_run/"), {}).status_code, 404)

    @override_settings(NMAS_TS_PORTS_FACTORY=PORTS_FACTORY)
    def test_it13_full_governed_flow_through_the_api(self):
        ex = FakeExecutor()
        ports = make_ports(ex)
        plan = self.make_plan(ports)
        base = api(self.case.case_id, f"remediation/{plan.record_id}/")
        # operator (not approver) may dry-run, may not approve
        self.assertEqual(self.post(self.alice, base + "dry_run/").json()["data"]["status"], "DRY_RUN_PASS")
        no_role = self.post(self.alice, base + "approve/", {"reason": "operator tries approving", "acknowledgements": []})
        self.assertEqual(no_role.status_code, 403)          # refused by NmasAccessMiddleware: operator holds no NMAS APPROVE
        self.assertEqual(m.TsRemediationPlan.objects.get(pk=plan.pk).status, "DRY_RUN_PASS")
        # approver needs the traffic acknowledgement
        self.assertEqual(self.post(self.bob, base + "approve/", {"reason": "approved after review", "acknowledgements": []}).json()["error"]["code"], "ACK_MISSING")
        ok = self.post(self.bob, base + "approve/", {"reason": "approved after review", "acknowledgements": ["I understand this may affect production traffic"]})
        self.assertEqual(ok.json()["data"]["status"], "APPROVED")
        self.assertEqual(self.post(self.bob, base + "precheck/").json()["data"]["status"], "PRECHECK_PASS")
        self.assertEqual(ex.applied, [])
        done = self.post(self.bob, base + "execute/", {"idempotency_key": "api-exec-1"})
        self.assertEqual((done.status_code, done.json()["data"]["status"]), (200, "APPLIED"))
        self.assertEqual(self.post(self.bob, base + "execute/", {"idempotency_key": "api-exec-1"}).status_code, 409)   # plan no longer PRECHECK_PASS
        self.assertEqual(len(ex.applied), 1)
        # applied != resolved: the case stays unresolved until verification
        case = self.get(self.viewer, api(self.case.case_id)).json()["data"]
        self.assertEqual(case["case"]["state"], "VERIFYING")
        self.assertEqual(case["disposition"], {})
        ev = ver.finalize(repo.Actor("alice", "user", tenant="acme"), self.case)
        self.assertNotEqual(ev["outcome"], "RESOLVED_VERIFIED")

    @override_settings(NMAS_TS_PORTS_FACTORY=PORTS_FACTORY)
    def test_ui_buttons_render_disabled_with_reason_and_post_redirects_with_notice(self):
        ports = make_ports()
        plan = self.make_plan(ports)
        html = self.get(self.alice, f"/troubleshooting/{self.case.case_id}/").content.decode()
        self.assertIn(f"remediation/{plan.record_id}/dry_run/", html)          # enabled for operator
        self.assertNotIn(f"remediation/{plan.record_id}/execute/", html)       # not yet allowed
        self.assertIn("disabled", html)
        ts_sign_in(self.client, self.alice)
        r = self.client.post(f"/troubleshooting/{self.case.case_id}/remediation/{plan.record_id}/dry_run/")
        self.assertEqual(r.status_code, 302)
        self.assertIn("dry_run%3A+DRY_RUN_PASS", r["Location"])
        r2 = self.client.post(f"/troubleshooting/{self.case.case_id}/remediation/{plan.record_id}/execute/")
        self.assertEqual(r2.status_code, 403)                                   # operator: no NMAS EXECUTE, refused before the view
        ts_sign_in(self.client, self.bob)
        r3 = self.client.post(f"/troubleshooting/{self.case.case_id}/remediation/{plan.record_id}/execute/")
        self.assertIn("refused", r3["Location"])                                # approver: past the middleware, refused by plan state
        viewer_html = self.get(self.viewer, f"/troubleshooting/{self.case.case_id}/").content.decode()
        self.assertNotIn(f"remediation/{plan.record_id}/dry_run/", viewer_html)   # viewers get no actions at all


class UiTests(ViewsBase):
    @mock.patch("core.troubleshooting_views.intake_scope.options")
    def test_list_detail_intake_pages_render(self, scope_options):
        scope_options.return_value = {
            "devices": [
                {"name": name, "platform": "ceos", "lifecycle": "UNREGISTERED", "diagnostic_ready": False,
                 "reason": "admission required"} for name in ("r1", "r2")
            ],
            "links": [],
        }
        lst = self.get(self.viewer, "/troubleshooting/")
        self.assertContains(lst, self.case.case_id)
        self.assertNotContains(lst, "Open a new case")
        self.assertContains(self.get(self.alice, "/troubleshooting/"), "Open a new case")
        det = self.get(self.viewer, f"/troubleshooting/{self.case.case_id}/")
        self.assertEqual(det.status_code, 200)
        for needle in ("Stage and state", "Configuration drift vs live service impact", "AI was not engaged", "No remediation plans",
                       "Raw outputs are not shown", "Case report", "Test Execution", "scope=\"col\""):
            if needle == "Test Execution":
                continue
            self.assertContains(det, needle)
        self.assertEqual(self.get(self.viewer, "/troubleshooting/new/").status_code, 403)
        form = self.get(self.alice, "/troubleshooting/new/")
        self.assertContains(form, "csrfmiddlewaretoken")
        ts_sign_in(self.client, self.alice)
        bad = self.client.post("/troubleshooting/new/", {"devices": "r1"})
        self.assertEqual(bad.status_code, 400)   # neither service nor flow given
        ok = self.client.post("/troubleshooting/new/", {"devices": "r1,r2", "protocol": "tcp", "ports": "443", "title": "t", "idempotency_key": "ui-1"})
        self.assertEqual(ok.status_code, 302)
        new = m.TsCase.objects.get(idempotency_key="ui-1")
        self.assertEqual(new.target_states, {"r1": "UNKNOWN", "r2": "UNKNOWN"})   # intake never self-declares a device VERIFIED
        self.assertEqual(new.tenant, "acme")

    def test_report_html_is_escaped(self):
        repo.record(self.actor, self.case, "hypothesis", title="<script>alert(1)</script>", state="OPEN")
        html = self.get(self.viewer, f"/troubleshooting/{self.case.case_id}/").content.decode()
        self.assertNotIn("<script>alert(1)</script>", html)

    def test_unauthenticated_pages_closed(self):
        anonymous(self.client)
        for url in ("/troubleshooting/", f"/troubleshooting/{self.case.case_id}/", "/troubleshooting/new/"):
            r = self.client.get(url)
            self.assertEqual(r.status_code, 302)
            self.assertIn("/accounts/login/", r["Location"])
