"""M1 troubleshooting substrate: persistence, contracts, evidence, audit chain, freshness, redaction and the eleven-section report.

Spec IDs covered (NMAS_V2_TROUBLESHOOTING_IMPLEMENTATION_SPEC.md section 10.1 / 10.7): UT-001 .. UT-012, plus the
persistence/contract/security parts of UT-024, UT-081, UT-082, UT-083, UT-084, UT-087, UT-090.  Each test method name carries its ID.
Everything is replay/fixture data created in-test: nothing here claims live device verification.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from django.db import connection
from django.test import SimpleTestCase, TestCase

from core import models as m
from core.services.troubleshooting import contracts as c
from core.services.troubleshooting import repository as repo
from core.services.troubleshooting import reporting

T0 = datetime(2026, 11, 9, 12, 0, tzinfo=timezone.utc)
ACTOR = repo.Actor("alice", "user", tenant="acme")
SECRET_CLI = "hostname r1\nenable secret 5 $1$abcd$HASHHASH\nsnmp-server community PUBLICRW rw\nusername bob password 7 0822455D0A16\nGi1 up"


def make_case(actor=ACTOR, **kw):
    args = dict(trigger_source="alert:link-flap", trigger_ref="ALRT-1", idempotency_key="k1", service_intent={"service": "web"},
                flow_scope={"protocol": "tcp", "ports": [443], "vrf": "PROD"}, severity="HIGH",
                affected_scope={"devices": ["r1", "r2"]}, target_states={"r1": "VERIFIED", "r2": "VERIFIED", "r3": "WITHDRAWN"},
                symptom="web slow", worked_before=True, changed_recently=None, now=T0)
    args.update(kw)
    return repo.open_case(actor, **args)


def evid(case, **kw):
    args = dict(source_type="cli", device="r1", command_or_api="show interfaces Gi1", adapter="netmiko", adapter_version="1",
                collected_at=T0, raw="Gi1 is up", operator_url="/troubleshooting/evidence/1")
    args.update(kw)
    return repo.store_evidence(ACTOR, case, **args)


class CaseIntakeTests(TestCase):
    def test_ut001_valid_intake_initializes_identity_state_and_scope(self):
        case = make_case()
        self.assertRegex(case.case_id, r"^TS-20261109-[0-9A-F]{8}$")
        self.assertEqual((case.state, case.tenant, case.opened_at, case.owner), ("OPEN", "acme", T0, "alice"))
        self.assertEqual(case.flow_scope["vrf"], "PROD")
        self.assertEqual(case.service_intent, {"service": "web"})
        self.assertIsNone(case.changed_recently)  # unknown stays unknown
        self.assertEqual(case.audit_events.get().action, "CASE_OPENED")
        self.assertEqual(case.schema_version, "nmas.troubleshooting/1")

    def test_ut001_intake_is_idempotent_and_validated(self):
        self.assertEqual(make_case().pk, make_case().pk)
        self.assertEqual(m.TsCase.objects.count(), 1)
        with self.assertRaises(ValueError):
            make_case(idempotency_key="k2", service_intent=None, flow_scope=None)
        with self.assertRaises(ValueError):
            make_case(idempotency_key="k3", affected_scope={"devices": []})
        with self.assertRaises(ValueError):
            make_case(idempotency_key="k4", severity="URGENT")

    def test_ut001_case_identity_immutable_and_closed_case_frozen(self):
        case = make_case()
        case.case_id = "TS-x"
        with self.assertRaises(ValueError):
            case.save()
        with self.assertRaises(ValueError):
            case.delete()

    def test_ut002_unverified_withdrawn_unknown_unauthorized_targets_cannot_be_probed(self):
        case = make_case(affected_scope={"devices": ["r1", "r2", "r3", "r4"]}, target_states={"r1": "VERIFIED", "r3": "WITHDRAWN", "r4": "UNVERIFIED"})
        repo.authorize_probe(ACTOR, case, "r1", now=T0)
        for dev in ("r3", "r4", "r2", "ghost", "", None):
            with self.assertRaises(repo.TargetRefused, msg=dev):
                repo.authorize_probe(ACTOR, case, dev, now=T0)
        narrow = repo.Actor("bob", tenant="acme", devices=frozenset({"r2"}))
        with self.assertRaises(repo.TargetRefused):
            repo.authorize_probe(narrow, case, "r1", now=T0)
        refusals = case.audit_events.filter(action="PROBE_REFUSED").count()
        self.assertEqual(refusals, 7)  # every refusal is audited
        with self.assertRaises(repo.TargetRefused):  # a collection run cannot be planned against a withdrawn device
            repo.begin_collection_run(ACTOR, case, idempotency_key="x", collector="cli", targets=["r3"], command_or_api="show version")
        with self.assertRaises(repo.TargetRefused):  # write privileges are never accepted
            repo.begin_collection_run(ACTOR, case, idempotency_key="y", collector="cli", targets=["r1"], command_or_api="clear counters", privileges="write")


class AppendOnlyTests(TestCase):
    def setUp(self):
        self.case = make_case()
        self.ev = evid(self.case)

    def _obs(self):
        return repo.record_observation(ACTOR, self.case, key="interface.oper_state", target="r1", observed_at=T0, value="up", evidence=self.ev)

    def test_ut003_observation_test_audit_evidence_reject_mutation_and_deletion(self):
        obs = self._obs()
        test = repo.record_test(ACTOR, self.case, _verdict(self.ev))
        audit = self.case.audit_events.first()
        for obj, field, val in ((obs, "value", "down"), (test, "verdict", "FAIL"), (audit, "result", "forged"), (self.ev, "device", "r9"),
                                (self.ev.raw_blob, "content", "x")):
            setattr(obj, field, val)
            with self.assertRaises(ValueError, msg=type(obj).__name__):
                obj.save()
            with self.assertRaises(ValueError):
                obj.delete()
        for model in (m.TsObservation, m.TsDiagnosticTest, m.TsAuditEvent, m.TsEvidenceRef, m.TsEvidenceBlob):
            with self.assertRaises(ValueError):
                model.objects.all().update(created_at=T0) if hasattr(model, "created_at") else model.objects.all().update(seq=1)
            with self.assertRaises(ValueError):
                model.objects.all().delete()
        obs.refresh_from_db()
        self.assertEqual(obs.value, "up")

    def test_ut003_audit_chain_detects_out_of_band_tampering(self):
        repo.record_observation(ACTOR, self.case, key="k", target="r1", observed_at=T0, value=1, evidence=self.ev)
        self.assertEqual(repo.verify_audit_chain(self.case), [])
        with connection.cursor() as cur:  # bypasses every ORM guard
            cur.execute("UPDATE core_tsauditevent SET result='forged' WHERE seq=1")
        problems = repo.verify_audit_chain(self.case)
        self.assertTrue(any("tampered" in p for p in problems), problems)
        with connection.cursor() as cur:
            cur.execute("DELETE FROM core_tsauditevent WHERE seq=1")
        self.assertTrue(any("gap" in p or "link" in p for p in repo.verify_audit_chain(self.case)))

    def test_ut003_collection_run_freezes_once_final(self):
        run = repo.begin_collection_run(ACTOR, self.case, idempotency_key="r", collector="cli", targets=["r1"], command_or_api="show version")
        repo.finish_run(ACTOR, run, "SUCCEEDED", now=T0)
        run.refresh_from_db()
        run.status = "FAILED"
        with self.assertRaises(ValueError):
            run.save()
        self.assertEqual(repo.finish_run(ACTOR, run, "FAILED").status, "SUCCEEDED")  # duplicate completion is ignored


def _verdict(ev, **kw):
    doc = {"schema": "test_verdict/1", "test_id": "HC01", "test_version": "1", "target": "r1", "expected": "oper up", "verdict": "PASS",
           "reason": "interface up", "evidence_ids": [ev.evidence_id], "observed_summary": "Gi1 up", "executed_at": c.iso(T0)}
    doc.update(kw)
    return doc


class EvidenceTests(TestCase):
    def setUp(self):
        self.case = make_case()

    def test_ut004_reference_preserves_source_hash_time_parser_and_operator_url(self):
        ev = evid(self.case, parser="textfsm", parser_version="2.1", raw="Gi1 is up")
        self.assertEqual((ev.source_type, ev.device, ev.command_or_api), ("cli", "r1", "show interfaces Gi1"))
        self.assertEqual((ev.adapter, ev.adapter_version, ev.parser, ev.parser_version), ("netmiko", "1", "textfsm", "2.1"))
        self.assertEqual(ev.collected_at, T0)
        self.assertEqual(ev.raw_sha256, c.sha256_text("Gi1 is up"))
        self.assertEqual(ev.operator_url, "/troubleshooting/evidence/1")
        self.assertEqual(ev.link_status, "UNVERIFIED")
        self.assertEqual(evid(self.case).pk, ev.pk)  # idempotent

    def test_ut005_secrets_redacted_in_blob_values_audit_and_outputs(self):
        ev = evid(self.case, raw=SECRET_CLI)
        stored = ev.raw_blob.content
        for leak in ("$1$abcd", "PUBLICRW", "0822455D0A16", "HASHHASH"):
            self.assertNotIn(leak, stored)
        self.assertIn("Gi1 up", stored)
        self.assertEqual(ev.redaction_status, "REDACTED")
        self.assertEqual(ev.raw_sha256, c.sha256_text(SECRET_CLI))  # provenance hash is of the original; original never stored
        self.assertEqual(c.sha256_text(stored), ev.raw_blob.stored_sha256)
        obs = repo.record_observation(ACTOR, self.case, key="cfg", target="r1", observed_at=T0, evidence=ev,
                                      value={"api_token": "abc123", "note": "password: hunter2", "snmp_community_ref": "vault:x"})
        self.assertEqual(obs.value["api_token_redacted_ref"], c.REDACTED)
        self.assertNotIn("abc123", repr(obs.value))
        self.assertNotIn("hunter2", obs.value["note"])
        self.assertEqual(obs.value["snmp_community_ref"], "vault:x")  # *_ref keys are safe references
        with self.assertRaises(ValueError):  # secret-shaped keys in structured metadata are rejected at the model layer
            m.TsHypothesis.objects.create(record_id="H", case=self.case, title="t", supporting_evidence=[{"password": "x"}])
        text = reporting.to_markdown(reporting.build_report(ACTOR, self.case, now=T0)) + reporting.to_html(reporting.build_report(ACTOR, self.case, now=T0))
        for leak in ("PUBLICRW", "hunter2", "$1$abcd"):
            self.assertNotIn(leak, text)
        self.assertEqual(c.redact_text(c.redact_text(SECRET_CLI)[0]), (c.redact_text(SECRET_CLI)[0], 0))  # idempotent
        for pat in ("-----BEGIN " + "RSA PRIVATE KEY-----\nMIIabc\n-----END " + "RSA PRIVATE KEY-----", "ghp_" + "a" * 30, "Authorization: Bearer abcdefgh12345678"):
            self.assertIn(c.REDACTED, c.redact_text(pat)[0])

    def test_ut005_raw_requires_privilege_and_is_audited(self):
        ev = evid(self.case, raw="Gi1 up")
        with self.assertRaises(repo.AccessDenied):
            repo.read_raw_evidence(ACTOR, ev.evidence_id)
        self.assertEqual(repo.read_raw_evidence(ACTOR, ev.evidence_id, privileged=True), "Gi1 up")
        self.assertTrue(self.case.audit_events.filter(action="RAW_EVIDENCE_READ").exists())
        # integrity: corrupt the blob out of band
        with connection.cursor() as cur:
            cur.execute("UPDATE core_tsevidenceblob SET content='tampered'")
        with self.assertRaises(repo.IntegrityError_):
            repo.read_raw_evidence(ACTOR, ev.evidence_id, privileged=True)
        with self.assertRaises(repo.IntegrityError_):
            repo.export_case(ACTOR, self.case)

    def test_ut011_missing_or_broken_link_is_surfaced_never_invented(self):
        none = evid(self.case, command_or_api="show ip route", operator_url="")
        bad = evid(self.case, command_or_api="show version", operator_url="/golden/rev/9", link_checker=lambda u: False)
        good = evid(self.case, command_or_api="show clock", operator_url="/golden/rev/1", link_checker=lambda u: True)
        self.assertEqual((none.operator_url, none.link_status), ("", "MISSING"))
        self.assertEqual((bad.link_status, good.link_status), ("BROKEN", "OK"))
        repo.record_observation(ACTOR, self.case, key="route.count", target="r1", observed_at=T0, value=3, evidence=none)
        repo.record_observation(ACTOR, self.case, key="clock", target="r1", observed_at=T0, value="12:00", evidence=good)
        repo.record(ACTOR, self.case, "baseline", baseline_type="GOLDEN_CONFIG", subject="r1", revision="BND-GOLD-000003",
                    revision_hash="a" * 64, operator_url="", link_status="MISSING", evidence_ids=[bad.evidence_id], stage_decision="golden attached")
        rep = reporting.build_report(ACTOR, self.case, now=T0)
        text = " ".join(rep["limitations"])
        self.assertIn(f"Evidence {none.evidence_id}: operator link is MISSING", text)
        self.assertIn(f"Evidence {bad.evidence_id}: operator link is BROKEN", text)
        self.assertIn("not replaced with an invented URL", text)
        md = reporting.to_markdown(rep)
        self.assertIn(f"{none.evidence_id} (link MISSING)", md)
        self.assertIn(f"[{good.evidence_id}](/golden/rev/1)", md)
        self.assertNotIn(f"[{bad.evidence_id}](", md)  # broken link is not rendered as a working hyperlink
        self.assertIn("MISSING", rep["sections"]["baseline"]["rows"][0]["operator URL"])

    def test_ut012_primary_view_references_raw_but_excludes_it(self):
        ev = evid(self.case, raw="UNIQUE-RAW-LINE-9f3 Gi1 is up\n" * 50)
        repo.record_observation(ACTOR, self.case, key="interface.oper_state", target="r1", observed_at=T0, value="up", evidence=ev)
        rep = reporting.build_report(ACTOR, self.case, now=T0)
        entry = rep["evidence_index"][ev.evidence_id]
        self.assertEqual(entry["raw_sha256"], ev.raw_sha256)
        self.assertGreater(entry["raw_size_bytes"], 1000)
        blob = repr(rep) + reporting.to_markdown(rep) + reporting.to_html(rep)
        self.assertNotIn("UNIQUE-RAW-LINE", blob)
        self.assertIn(ev.evidence_id, blob)


class ObservationFreshnessTests(TestCase):
    def setUp(self):
        self.case = make_case()
        self.ev = evid(self.case)

    def test_ut006_missing_stale_untrusted_yield_unknown_never_healthy_or_fault(self):
        now = T0 + timedelta(hours=1)
        up = lambda v: v == "up"  # noqa: E731
        self.assertEqual(repo.current_state(ACTOR, self.case, "oper", "r1", now, up)["state"], "UNKNOWN")  # nothing collected
        repo.record_observation(ACTOR, self.case, key="oper", target="r1", observed_at=T0, value="down", evidence=self.ev, max_age_seconds=300)
        st = repo.current_state(ACTOR, self.case, "oper", "r1", now, up)
        self.assertEqual((st["state"], st["freshness"]), ("UNKNOWN", "STALE"))  # old FAULT is not claimed live
        repo.record_observation(ACTOR, self.case, key="oper", target="r1", observed_at=now - timedelta(seconds=10), value="up", evidence=self.ev)
        self.assertEqual(repo.current_state(ACTOR, self.case, "oper", "r1", now, up)["state"], "HEALTHY")
        repo.record_observation(ACTOR, self.case, key="oper", target="r1", observed_at=now - timedelta(seconds=1), value="down", evidence=self.ev, quality="UNTRUSTED")
        self.assertEqual(repo.current_state(ACTOR, self.case, "oper", "r1", now, up)["state"], "UNKNOWN")
        repo.record_observation(ACTOR, self.case, key="oper", target="r1", observed_at=now + timedelta(hours=5), value="up", evidence=self.ev)
        self.assertEqual(repo.current_state(ACTOR, self.case, "oper", "r1", now, up)["freshness"], "UNTRUSTED")  # future timestamp
        repo.record_missing_data(ACTOR, self.case, key="oper", target="r1", reason="permission denied", observed_at=now + timedelta(seconds=200))
        # a later missing-data record must not be read as healthy
        self.assertEqual(repo.current_state(ACTOR, self.case, "oper", "r1", now + timedelta(seconds=300), up)["state"], "UNKNOWN")

    def test_ut024_permission_denied_is_a_missing_data_record_not_an_observation(self):
        o = repo.record_missing_data(ACTOR, self.case, key="bgp.neighbors", target="r1", reason="authorization failed: password=hunter2", observed_at=T0)
        self.assertTrue(o.is_missing_data)
        self.assertIsNone(o.value)
        self.assertEqual(o.quality, "MISSING")
        self.assertNotIn("hunter2", o.missing_reason)
        with self.assertRaises(ValueError):  # an OBSERVED value must cite evidence
            repo.record_observation(ACTOR, self.case, key="x", target="r1", observed_at=T0, value=1)
        with self.assertRaises(ValueError):  # evidence must exist in this case
            repo.record_observation(ACTOR, self.case, key="x", target="r1", observed_at=T0, value=1, evidence_ids=["EV-nope"])

    def test_ut007_stage_records_stay_ordered_through_retry_and_restart(self):
        r1 = repo.begin_collection_run(ACTOR, self.case, idempotency_key="a", collector="gnmi", targets=["r1"], command_or_api="/interfaces")
        r2 = repo.begin_collection_run(ACTOR, self.case, idempotency_key="b", collector="snmp", targets=["r2"], command_or_api="ifTable")
        self.assertEqual((r1.seq, r2.seq), (1, 2))
        repo.start_attempt(ACTOR, r1, now=T0)
        # --- simulated restart: replay the same requests; nothing duplicates, order is preserved
        again = repo.begin_collection_run(ACTOR, self.case, idempotency_key="a", collector="gnmi", targets=["r1"], command_or_api="/interfaces")
        self.assertEqual(again.pk, r1.pk)
        self.assertEqual([r.seq for r in repo.resumable_runs(ACTOR, self.case)], [1, 2])
        for i in range(5):  # retries are bounded
            r = repo.start_attempt(ACTOR, r2, now=T0)
        self.assertEqual((r.status, r.error), ("FAILED", "retry budget exhausted"))
        self.assertEqual(r.attempts, 3)
        self.assertEqual([x.seq for x in repo.resumable_runs(ACTOR, self.case)], [1])
        repo.finish_run(ACTOR, r1, "SUCCEEDED", now=T0)
        repo.record(ACTOR, self.case, "hypothesis", title="h", failure_domain="L1", state="OPEN", stage_decision="open")
        t = repo.record_test(ACTOR, self.case, _verdict(self.ev))
        journal = repo.stage_journal(ACTOR, self.case)
        stages = [j["stage"] for j in journal]
        self.assertEqual(stages, sorted(stages, key=c.STAGES.index))
        self.assertEqual([j["record_id"] for j in journal if j["kind"] == "collection_run"], [r1.record_id, r2.record_id])
        self.assertEqual(t.seq, 1)
        # retry of the same test keeps its sequence slot and adds an attempt
        t2 = repo.record_test(ACTOR, self.case, _verdict(self.ev, attempt=2, verdict="INCONCLUSIVE", reason="timeout on retry", evidence_ids=[]))
        self.assertEqual((t2.seq, t2.attempt), (1, 2))
        actions = list(self.case.audit_events.values_list("seq", flat=True))
        self.assertEqual(actions, sorted(actions))
        self.assertEqual(repo.verify_audit_chain(self.case), [])

    def test_collection_bundle_contract_and_replay_idempotency(self):
        bundle = {"schema": "collection_bundle/1", "case_id": self.case.case_id, "collector": "cli", "adapter": "netmiko", "adapter_version": "4",
                  "idempotency_key": "bundle-1", "targets": ["r1"], "command_or_api": "show interfaces", "status": "SUCCEEDED",
                  "started_at": c.iso(T0), "finished_at": c.iso(T0 + timedelta(seconds=2)),
                  "raw": {"source_type": "cli", "text": "Gi1 up\nenable secret 5 $1$zzzz$yyyy", "parser": "textfsm", "parser_version": "1"},
                  "observations": [{"schema": "observation/1", "key": "interface.oper_state", "target": "r1", "observed_at": c.iso(T0),
                                    "source": "cli", "quality": "GOOD", "basis": "OBSERVED", "value": "up", "dedupe_key": "d1"},
                                   {"schema": "observation/1", "key": "bgp.neighbors", "target": "r1", "observed_at": c.iso(T0), "source": "cli",
                                    "quality": "MISSING", "basis": "OBSERVED", "is_missing_data": True, "missing_reason": "command unsupported on this NOS"}]}
        run = repo.ingest_collection_bundle(ACTOR, bundle, now=T0)
        self.assertEqual((run.status, run.observations.count()), ("SUCCEEDED", 2))
        self.assertEqual(repo.ingest_collection_bundle(ACTOR, bundle, now=T0).pk, run.pk)
        self.assertEqual((m.TsObservation.objects.count(), m.TsCollectionRun.objects.count()), (2, 1))
        self.assertTrue(m.TsObservation.objects.get(key="bgp.neighbors").is_missing_data)
        self.assertNotIn("zzzz", run.raw_ref.raw_blob.content)
        bad = dict(bundle, status="MAYBE")
        self.assertTrue(c.validate(bad))
        with self.assertRaises(ValueError):
            repo.ingest_collection_bundle(ACTOR, bad)


class ContractTests(SimpleTestCase):
    def test_every_schema_is_versioned_and_unknown_or_extra_fields_fail(self):
        self.assertEqual(set(c.CONTRACT_NAMES), {"observation/1", "collection_bundle/1", "test_verdict/1", "incident_report/1", "ai_handoff/1"})
        ok = {"schema": "observation/1", "key": "k", "target": "r1", "observed_at": "2026-11-09T12:00:00Z", "source": "s", "quality": "GOOD", "basis": "OBSERVED"}
        self.assertEqual(c.validate(ok), [])
        self.assertTrue(c.validate({**ok, "schema": "observation/2"}))
        self.assertTrue(c.validate({**ok, "extra": 1}))
        self.assertTrue(c.validate({**ok, "quality": "WONDERFUL"}))
        self.assertTrue(c.validate({**ok, "observed_at": "yesterday"}))
        self.assertTrue(c.validate({k: v for k, v in ok.items() if k != "key"}))
        self.assertTrue(c.validate("x"))
        h = {"schema": "ai_handoff/1", "case_id": "C", "coverage_manifest": {}, "trigger_uncertainty": "u", "allowed_tools": [], "allowed_targets": [],
             "budget": {}, "evidence_ids": [], "return_conditions": []}
        self.assertEqual(c.validate(h), [])
        self.assertEqual(c.validate({"schema": "test_verdict/1", "test_id": "HC1", "test_version": "1", "target": "r", "expected": "e", "verdict": "SKIPPED", "reason": "r"}), [])
        self.assertTrue(c.validate({"schema": "test_verdict/1", "test_id": "HC1", "test_version": "1", "target": "r", "expected": "e", "verdict": "OK", "reason": "r"}))

    def test_freshness_and_tristate_primitives(self):
        now = T0
        self.assertEqual(c.freshness(now - timedelta(seconds=10), 60, now), "FRESH")
        self.assertEqual(c.freshness(now - timedelta(seconds=100), 60, now), "STALE")
        self.assertEqual(c.freshness(None, 60, now), "MISSING")
        self.assertEqual(c.freshness(now + timedelta(days=1), 60, now), "UNTRUSTED")
        self.assertEqual(c.tri_state("STALE", True), "UNKNOWN")
        self.assertEqual(c.tri_state("FRESH", None), "UNKNOWN")
        self.assertEqual((c.tri_state("FRESH", True), c.tri_state("FRESH", False)), ("HEALTHY", "FAULT"))


class TraceAndReportTests(TestCase):
    def setUp(self):
        self.case = make_case()
        self.ev = evid(self.case, operator_url="/ev/1", link_checker=lambda u: True)
        self.ev2 = evid(self.case, device="r2", command_or_api="show lldp neighbors", operator_url="/ev/2", link_checker=lambda u: True)
        now = T0
        run = repo.begin_collection_run(ACTOR, self.case, idempotency_key="r", collector="cli", targets=["r1"], command_or_api="show interfaces")
        repo.start_attempt(ACTOR, run, now=now)
        repo.finish_run(ACTOR, run, "SUCCEEDED", raw_ref=self.ev, now=now)
        repo.record_observation(ACTOR, self.case, key="interface.oper_state", target="r1", observed_at=T0, value="up", evidence=self.ev, run=run)
        repo.record_observation(ACTOR, self.case, key="interface.input_errors", target="r2", observed_at=T0 - timedelta(hours=3), value=412, unit="count",
                                evidence=self.ev2, max_age_seconds=300)
        repo.record_missing_data(ACTOR, self.case, key="bgp.neighbors", target="r1", reason="permission denied", observed_at=T0)
        self.base = repo.record(ACTOR, self.case, "baseline", baseline_type="GOLDEN_CONFIG", subject="r1", revision="BND-GOLD-000007",
                                revision_hash="b" * 64, operator_url="/device-builder/bundles/BND-GOLD-000007/", link_status="OK",
                                soak_state="ACTIVE", evidence_ids=[self.ev.evidence_id], stage_decision="golden attached")
        repo.record(ACTOR, self.case, "drift", baseline=self.base, subject="r1 acl 110", expected={"icmp": "permit"}, observed={"icmp": "deny"},
                    drift_kind="APPROVED", approved_change_id="CHG-12", production_impact="NONE", conclusion="expected drift", basis="DERIVED",
                    evidence_ids=[self.ev.evidence_id], stage_decision="approved change matches intent")
        repo.record(ACTOR, self.case, "correlation", alert_ids=["a1", "a2", "a3"], common_fault_candidate="r1:Gi1 flap", role="CAUSE", confidence=0.8,
                    basis="DERIVED", evidence_ids=[self.ev.evidence_id], stage_decision="grouped by topology edge")
        self.hyp = repo.record(ACTOR, self.case, "hypothesis", title="Gi1 optics degraded", failure_domain="L1", state="OPEN", ranking=1, stage_decision="hypothesis opened")
        self.hyp_el = repo.record(ACTOR, self.case, "hypothesis", title="Admin shut", failure_domain="L1", state="OPEN", ranking=2)
        repo.update_hypothesis(ACTOR, self.hyp_el, state="ELIMINATED", rationale="oper/admin both up in fresh observation", contradicting=[self.ev.evidence_id])
        repo.update_hypothesis(ACTOR, self.hyp, state="SUPPORTED", supporting=[self.ev2.evidence_id], confidence=0.6)
        for i, (v, reason) in enumerate([("PASS", "ok"), ("FAIL", "input errors rising"), ("INCONCLUSIVE", "counter reset detected mid-window"),
                                         ("SKIPPED", "unsafe: would require interface bounce"), ("UNAVAILABLE", "platform has no such command (capability probe)")]):
            ids = [self.ev.evidence_id] if v in ("PASS", "FAIL") else []
            repo.record_test(ACTOR, self.case, _verdict(self.ev, test_id=f"HC0{i+1}", verdict=v, reason=reason, evidence_ids=ids,
                                                         hypothesis=self.hyp.record_id))
        repo.record(ACTOR, self.case, "ai_handoff", trigger_uncertainty="two L1 hypotheses remain", agent_identity="agent-x", allowed_tools=["show"],
                    budget={"tools": 5}, basis="AI_INFERRED", reasoning_log=[{"hypothesis": "optics", "tool": "show interfaces transceiver", "rationale": "discriminate",
                    "result": "rx power -22 dBm", "conclusion": "optics suspect", "evidence_ids": [self.ev2.evidence_id]}])
        plan = repo.record(ACTOR, self.case, "remediation_plan", tier=2, operations=["replace SFP (manual)"], risk="LOW", status="PROPOSED", basis="DERIVED")
        m.TsActionExecution.objects.create(record_id="ACT-1", case=self.case, plan=plan, idempotency_key="act-1", status="BLOCKED", stop_reason="awaiting approval")
        repo.record(ACTOR, self.case, "verification", original_symptom="web slow", outcome="INCONCLUSIVE", soak_status="SOAKING", basis="OBSERVED")
        repo.record(ACTOR, self.case, "flow_monitor", selector={"protocol": "tcp", "port": 443}, baseline={"loss_pct": 0}, current_loss_pct=None, classification="PRODUCTION")

    def test_ut008_report_has_all_eleven_populated_sections(self):
        rep = reporting.build_report(ACTOR, self.case, now=T0 + timedelta(seconds=30))
        self.assertEqual(c.validate(rep, "incident_report/1"), [])
        self.assertEqual(list(rep["sections"]), list(c.REPORT_SECTION_KEYS))
        self.assertEqual(len(rep["sections"]), 11)
        for key, sec in rep["sections"].items():
            self.assertTrue(sec["rows"], key)
            self.assertNotIn("_placeholder", sec["rows"][0], f"{key} unexpectedly empty")
            self.assertGreaterEqual(len(sec["columns"]), 4, key)
        md = reporting.to_markdown(rep)
        for title in reporting.SECTION_TITLES.values():
            self.assertIn(f"## {title}", md)
        self.assertIn("<table>", reporting.to_html(rep))

    def test_ut008_empty_stage_renders_not_performed_not_blank(self):
        empty = make_case(idempotency_key="empty")
        rep = reporting.build_report(ACTOR, empty, now=T0)
        for key in ("collection", "normalization", "baseline", "correlation", "test_matrix", "ai_investigation", "verification_soak"):
            row = rep["sections"][key]["rows"][0]
            self.assertIn("NOT PERFORMED", str(list(row.values())[0]), key)
            self.assertEqual(rep["sections"][key]["row_count"], 0)
        self.assertIn("cannot be reported as resolved", reporting.to_markdown(rep))

    def test_ut009_every_verdict_stays_visible_with_specific_reasons(self):
        rows = reporting.build_report(ACTOR, self.case, now=T0)["sections"]["test_matrix"]["rows"]
        self.assertEqual([r["verdict"] for r in rows], ["PASS", "FAIL", "INCONCLUSIVE", "SKIPPED", "UNAVAILABLE"])
        self.assertTrue(all(r["reason"] not in ("", "—") for r in rows))
        diag = reporting.build_report(ACTOR, self.case, now=T0)["sections"]["deterministic_diagnosis"]["summary"]
        self.assertEqual(diag["verdict_counts"], {"PASS": 1, "FAIL": 1, "INCONCLUSIVE": 1, "SKIPPED": 1, "UNAVAILABLE": 1})
        self.assertTrue(diag["exhaustiveness"].startswith("INCOMPLETE"))
        # filters
        only_fail = reporting.build_report(ACTOR, self.case, now=T0, verdict="FAIL")["sections"]["test_matrix"]["rows"]
        self.assertEqual([r["verdict"] for r in only_fail], ["FAIL"])
        with self.assertRaises(ValueError):  # a PASS/FAIL without evidence is refused; a skip without a reason is refused
            repo.record_test(ACTOR, self.case, _verdict(self.ev, test_id="HC09", evidence_ids=[]))
        with self.assertRaises(ValueError):
            repo.record_test(ACTOR, self.case, _verdict(self.ev, test_id="HC10", verdict="SKIPPED", reason="", evidence_ids=[]))

    def test_ut010_every_claim_traces_to_evidence_and_stage_decision(self):
        for kind, model in (("observation", m.TsObservation), ("test", m.TsDiagnosticTest), ("drift", m.TsDriftAssessment), ("correlation", m.TsCorrelationRecord)):
            for obj in model.objects.filter(case=self.case).exclude(is_missing_data=True) if kind == "observation" else model.objects.filter(case=self.case):
                tr = repo.trace_claim(ACTOR, self.case, obj.record_id)
                if obj.evidence_ids:
                    self.assertTrue(tr["traceable"], (kind, obj.record_id))
                    self.assertTrue(tr["evidence"][0]["raw_sha256"])
                self.assertIn(tr["basis"], c.BASES)
                self.assertTrue(tr["stage"])
        with self.assertRaises(ValueError):  # a derived claim with no evidence is refused
            repo.record(ACTOR, self.case, "drift", subject="x", drift_kind="UNAPPROVED", basis="DERIVED")
        guess = repo.record(ACTOR, self.case, "hypothesis", title="AI guess", basis="AI_INFERRED", state="OPEN")
        self.assertEqual(guess.state, "UNVERIFIED")
        with self.assertRaises(ValueError):
            repo.record(ACTOR, self.case, "hypothesis", title="unsupported", state="CONFIRMED")
        with self.assertRaises(ValueError):
            repo.update_hypothesis(ACTOR, guess, state="CONFIRMED")
        rep = reporting.build_report(ACTOR, self.case, now=T0)
        self.assertTrue(any("UNVERIFIED" in x for x in rep["limitations"]))
        for key in ("normalization", "test_matrix", "correlation"):
            for row in rep["sections"][key]["rows"]:
                self.assertIn(row["basis"], c.BASES) if "basis" in row else self.fail(key)

    def test_ut083_report_has_golden_link_sources_and_coverage(self):
        md = reporting.to_markdown(reporting.build_report(ACTOR, self.case, now=T0))
        self.assertIn("[/device-builder/bundles/BND-GOLD-000007/](/device-builder/bundles/BND-GOLD-000007/)", md)  # direct golden hyperlink
        self.assertIn('<a href="/device-builder/bundles/BND-GOLD-000007/">', reporting.to_html(reporting.build_report(ACTOR, self.case, now=T0)))
        rep = reporting.build_report(ACTOR, self.case, now=T0)
        b = rep["sections"]["baseline"]["rows"][0]
        self.assertEqual((b["revision"], b["operator URL"], b["link"], b["soak state"]), ("BND-GOLD-000007", "/device-builder/bundles/BND-GOLD-000007/", "OK", "ACTIVE"))
        self.assertIn(f"[{self.ev.evidence_id}](/ev/1)", md)
        self.assertIn("directly observed", md)
        self.assertIn("deterministically derived", md)
        self.assertIn("AI-inferred", md)

    def test_ut084_matrix_is_summarized_not_cli_dump(self):
        rows = reporting.build_report(ACTOR, self.case, now=T0)["sections"]["test_matrix"]["rows"]
        self.assertTrue(all(len(str(r["actual (summary)"])) <= 140 for r in rows))
        long = repo.record_test(ACTOR, self.case, _verdict(self.ev, test_id="HC77", observed_summary="line\n" * 500, evidence_ids=[self.ev.evidence_id]))
        row = [r for r in reporting.build_report(ACTOR, self.case, now=T0)["sections"]["test_matrix"]["rows"] if r["test"].startswith("HC77")][0]
        self.assertLessEqual(len(row["actual (summary)"]), 140)
        self.assertLessEqual(len(long.observed_summary), 512)

    def test_ut087_stale_and_missing_data_labelled_prominently(self):
        rep = reporting.build_report(ACTOR, self.case, now=T0 + timedelta(minutes=1))
        fr = {r["standardized metric"] + "@" + r["target"]: r["freshness"] for r in rep["sections"]["normalization"]["rows"]}
        self.assertEqual(fr["interface.input_errors@r2"], "STALE")
        self.assertEqual(fr["bgp.neighbors@r1"], "MISSING")
        self.assertEqual(rep["freshness"]["stale_observations"], 1)
        joined = "\n".join(rep["limitations"])
        self.assertIn("interface.input_errors on r2) is STALE", joined)
        self.assertIn("reported state is UNKNOWN, not live", joined)
        self.assertIn("Missing data: bgp.neighbors on r1 — permission denied", joined)
        self.assertIn("not a live-status claim", reporting.to_markdown(rep))

    def test_ut081_ut082_scoped_access_tenant_and_device(self):
        other = repo.Actor("eve", tenant="globex")
        with self.assertRaises(repo.AccessDenied):
            repo.get_case(other, self.case.case_id)
        with self.assertRaises(repo.AccessDenied):
            reporting.build_report(other, self.case)
        with self.assertRaises(repo.AccessDenied):
            repo.get_evidence(other, self.ev.evidence_id)
        with self.assertRaises(repo.AccessDenied):
            repo.store_evidence(other, self.case, source_type="cli", collected_at=T0)
        self.assertEqual(repo.list_cases(other), [])
        r1_only = repo.Actor("bob", tenant="acme", devices=frozenset({"r1"}))
        with self.assertRaises(repo.AccessDenied):
            repo.get_evidence(r1_only, self.ev2.evidence_id)  # r2 evidence
        rep = reporting.build_report(r1_only, self.case, now=T0)
        self.assertNotIn(self.ev2.evidence_id, rep["evidence_index"])
        self.assertTrue(all(r["target"] != "r2" for r in rep["sections"]["normalization"]["rows"]))
        self.assertEqual(repo.list_cases(r1_only)[0].case_id, self.case.case_id)
        self.assertEqual(rep["schema"], "incident_report/1")

    def test_ut090_export_is_redacted_integrity_checked_and_retention_labelled(self):
        evid(self.case, command_or_api="show run", raw=SECRET_CLI)
        doc = repo.export_case(ACTOR, self.case, now=T0, retention_days=30)
        self.assertEqual(doc["retention_until"], c.iso(T0 + timedelta(days=30)))
        self.assertEqual(len(doc["audit_chain_head"]), 64)
        text = repr(doc)
        for leak in ("PUBLICRW", "$1$abcd", "0822455D0A16"):
            self.assertNotIn(leak, text)
        self.assertNotIn("content", text.replace("command_or_api", ""))  # no raw bodies in the export
        with connection.cursor() as cur:
            cur.execute("UPDATE core_tsauditevent SET decision='x' WHERE seq=1")
        with self.assertRaises(repo.IntegrityError_):
            repo.export_case(ACTOR, self.case)
        rep = reporting.build_report(ACTOR, self.case, now=T0)
        self.assertTrue(any(x.startswith("AUDIT INTEGRITY") for x in rep["limitations"]))
        self.assertIn("BROKEN", rep["sections"]["final_disposition"]["rows"][-1]["audit / evidence"])

    def test_closed_case_rejects_new_records_and_resolved_needs_verified_service_check(self):
        with self.assertRaises(ValueError):
            repo.close_case(ACTOR, self.case, "RESOLVED_VERIFIED", disposition={"resolved": "x"})
        for s in ("COLLECTING", "TESTING", "UNRESOLVED"):
            repo.transition_case(ACTOR, self.case, s, now=T0)
        closed = repo.get_case(ACTOR, self.case.case_id)
        self.assertEqual(repo.close_case(ACTOR, closed, "UNRESOLVED", disposition={"remaining_to_fix": "replace optics"}, now=T0).state, "UNRESOLVED")
        closed = repo.get_case(ACTOR, self.case.case_id)
        self.assertEqual(closed.state, "UNRESOLVED")
        self.assertIsNotNone(closed.closed_at)
        with self.assertRaises(ValueError):
            repo.record_observation(ACTOR, closed, key="k", target="r1", observed_at=T0, value=1, evidence=self.ev)
        with self.assertRaises(ValueError):
            repo.transition_case(ACTOR, closed, "TESTING")
        row = reporting.build_report(ACTOR, closed, now=T0)["sections"]["final_disposition"]["rows"][-1]
        self.assertEqual(row["status"], "UNRESOLVED")

    def test_exception_policy_expiry_and_revision_invalidation(self):
        with self.assertRaises(ValueError):
            repo.record(ACTOR, self.case, "exception", scope={}, expires_at=T0 + timedelta(days=1))
        pol = repo.record(ACTOR, self.case, "exception", scope={"service": "web", "protocol": "icmp", "path": "h1->svc"}, expires_at=T0 + timedelta(days=1),
                          bound_revisions={"golden": "r7", "acl": "r2"}, basis="OPERATOR_CONFIRMED", approvals=[{"by": "ops", "at": c.iso(T0)}])
        revs = {"golden": "r7", "acl": "r2"}
        self.assertEqual(repo.exception_status(pol, revs, T0), "ACTIVE")
        self.assertEqual(repo.exception_status(pol, revs, T0 + timedelta(days=2)), "EXPIRED")
        self.assertEqual(repo.exception_status(pol, {**revs, "acl": "r3"}, T0), "INVALIDATED")
