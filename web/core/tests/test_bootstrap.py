"""One-time LEGACY BASELINE bootstrap: policy, sanitization, capture, immutability, the 30-minute observation, approval and the one-time lockout.

A CONTROLLED CLOCK and a simulated network (see ``helpers/bootstrap.py``): the REAL 30-minute policy runs, no real time passes and no device is touched.
"""

from __future__ import annotations

import json
import os
from datetime import timedelta
from unittest import mock

from django.core.exceptions import ImproperlyConfigured
from django.db import IntegrityError, transaction
from django.test import SimpleTestCase, TestCase

from core import models
from core.services import bootstrap_service as bs, bundle_service, soak_service
from core.services.bootstrap import capture, evaluator, evidence, interference
from core.services.bundles import canonical, legacy, legacy_sanitize as san
from core.services.health import live
from core.tests.helpers import bootstrap as bh, bundles as bundles_helper, health as h, soak as sh

KIND, PROV = models.BundleKind, models.BundleProvenance
SR, SS, SRES = models.SoakSampleResult, models.SoakState, models.SoakResult


def codes_of(blockers):
    return [b["code"] for b in blockers]


def everything_persisted() -> str:
    """Every text the application persisted (bundles, audit, notifications, runs, samples, decisions) as one string -- for secret scans."""
    parts = []
    for model in (models.ConfigurationBundle, models.AuditEvent, models.Notification, models.LegacyBootstrapRun, models.LegacyBootstrapSample,
                  models.LegacyBootstrapDecision):
        for row in model._base_manager.all().values():
            parts.append(json.dumps(row, default=str))
    return "\n".join(parts)


class PolicyTests(TestCase):
    def test_normal_probation_soak_is_still_seven_days_and_the_bootstrap_policy_is_separate(self):
        production = soak_service.current_policy()
        boot = bs.current_policy()
        self.assertEqual((production.duration_seconds, production.duration_seconds // 3600, production.is_production_duration), (604800, 168, True))
        self.assertEqual(production.version, "20.0.0")
        self.assertEqual((boot.duration_seconds, boot.sample_interval_seconds, boot.max_gap_seconds, boot.min_coverage_percent), (1800, 300, 600, 80))
        self.assertEqual(boot.version, "LEGACY_BOOTSTRAP_POLICY_V1")
        self.assertFalse(boot.is_production_duration)
        self.assertEqual(boot.production_duration_seconds, 604800, "the bootstrap knows the production duration it is NOT")
        self.assertEqual(boot.total_buckets, 6)   # T+0 .. T+25 covered intervals, the closing sample at / after T+30

    def test_duration_is_server_owned_and_the_environment_can_only_raise_it(self):
        from config import settings as project_settings

        self.assertEqual(project_settings.LEGACY_BOOTSTRAP_MIN_DURATION_SECONDS, 1800)
        for value, ok in (("60", False), ("1799", False), ("1800", True), ("3600", True)):
            with self.subTest(env=value), mock.patch.dict(os.environ, {"LEGACY_BOOTSTRAP_DURATION_SECONDS": value}):
                call = lambda: project_settings._bounded_seconds("LEGACY_BOOTSTRAP_DURATION_SECONDS", "1800", project_settings.LEGACY_BOOTSTRAP_MIN_DURATION_SECONDS, 7200)  # noqa: E731
                if ok:
                    self.assertGreaterEqual(call(), 1800)
                else:
                    self.assertRaises(ImproperlyConfigured, call)
        self.assertEqual(project_settings.PROBATION_SOAK_DURATION_SECONDS, 7 * 24 * 3600, "the production soak default is untouched")

    def test_a_run_pins_its_policy_and_a_later_setting_change_never_re_judges_it(self):
        run, _candidate, _world = bh.started()
        self.assertEqual((run.required_end_at - run.started_at).total_seconds(), 1800)
        with self.settings(LEGACY_BOOTSTRAP_DURATION_SECONDS=3600, LEGACY_BOOTSTRAP_MIN_COVERAGE_PERCENT=100):
            again = models.LegacyBootstrapRun.objects.get(pk=run.pk)
            self.assertEqual(again.policy["duration_seconds"], 1800)
            self.assertEqual(again.policy["min_coverage_percent"], 80)
            self.assertEqual(again.policy_version, "LEGACY_BOOTSTRAP_POLICY_V1")


class SanitizerTests(TestCase):
    def test_every_secret_bearing_line_is_redacted_deterministically_without_losing_structure(self):
        cases = [
            ("username admin privilege 15 role network-admin secret sha512 $6$abc/DEF", "username admin privilege 15 role network-admin secret <REDACTED>"),
            ("enable secret sha512 topsecret", "enable secret <REDACTED>"),
            ("snmp-server community S3cr3t ro", "snmp-server community <REDACTED>"),
            ("snmp-server user u g v3 auth sha256 0123456789abcdef priv aes fedcba9876543210", "snmp-server user u g v3 auth sha256 <REDACTED>"),
            ("tacacs-server key 7 070C285F4D06", "tacacs-server key <REDACTED>"),
            ("radius-server host 10.1.1.1 key 7 ABCDEF", "radius-server host 10.1.1.1 key <REDACTED>"),
            ("   neighbor 10.0.0.2 password 7 AbCdEf", "   neighbor 10.0.0.2 password <REDACTED>"),
            ("   ip ospf message-digest-key 1 md5 OspfKey", "   ip ospf message-digest-key <REDACTED>"),
            ("ntp authentication-key 5 md5 NtpKey", "ntp authentication-key <REDACTED>"),
            ("      key-string 7 0822455D0A16", "      key-string <REDACTED>"),
            ("   description password is hunter2", "   description password <REDACTED>"),
        ]
        for line, expected in cases:
            with self.subTest(line=line):
                cleaned = san.sanitize_config(f"hostname R1\n{line}\n")
                self.assertEqual(cleaned.text.splitlines()[1], expected)
                self.assertEqual(cleaned.redacted_lines, 1)
                self.assertEqual(san.residual_secret_lines(cleaned.text), [])
                self.assertEqual(san.sanitize_config(cleaned.text).text, cleaned.text, "idempotent")
                self.assertEqual(san.sanitize_config(f"hostname R1\n{line}\n").text, cleaned.text, "deterministic")

    def test_pem_blocks_comments_blank_lines_and_line_endings(self):
        begin, end = "-----BEGIN " + "RSA PRIVATE KEY" + "-----", "-----END " + "RSA PRIVATE KEY" + "-----"   # assembled at runtime: the repository's own hygiene scan (rightly) flags the literal header
        raw = f"! Command: show running-config\r\n!\r\nhostname R1  \r\n\r\n{begin}\r\nMIIEowIBAAKCAQEA\r\n{end}\r\ninterface Ethernet1\r\n   ip address 10.0.0.1/24\r\n"
        cleaned = san.sanitize_config(raw)
        self.assertEqual(cleaned.text, "hostname R1\n<REDACTED-PEM-BLOCK>\ninterface Ethernet1\n   ip address 10.0.0.1/24\n")
        self.assertNotIn("MIIEowIBAAKCAQEA", cleaned.text)
        self.assertIn("PEM_BLOCK", cleaned.patterns)

    def test_benign_lines_are_never_touched(self):
        text = "hostname R1\ninterface Ethernet1\n   description uplink to R2 Ethernet3\n   ip address 10.0.0.1/24\nrouter bgp 65001\n   neighbor 10.0.0.2 send-community\n"
        cleaned = san.sanitize_config(text)
        self.assertEqual((cleaned.text, cleaned.redacted_lines, cleaned.patterns), (text, 0, []))

    def test_oversized_or_non_text_input_fails_closed(self):
        for value in (None, 5, b"bytes"):
            with self.subTest(value=repr(value)):
                self.assertRaises(san.SanitizeError, san.sanitize_config, value)
        self.assertRaises(san.SanitizeError, san.sanitize_config, "line\n" * 400_000)


class CaptureTests(TestCase):
    def test_the_capture_records_every_managed_device_sanitized_sorted_and_with_full_provenance(self):
        candidate, _world = bh.candidate_of()
        payload = candidate.payload
        devices = payload["baseline"]["devices"]
        self.assertEqual([d["device"] for d in devices], sorted(bh.MANAGED), "every inventory device, sorted deterministically")
        self.assertEqual(payload["scope"]["devices"], sorted(bh.MANAGED))
        self.assertEqual(payload["baseline"]["excluded_devices"], [])
        for record in devices:
            with self.subTest(device=record["device"]):
                self.assertEqual(record["platform"], bh.PLATFORM[record["device"]])
                self.assertEqual(record["read_status"], "OK")
                self.assertEqual(record["captured_at"], "2035-03-01T12:00:00Z")
                self.assertTrue(record["capture_method"])
                self.assertEqual(record["config_digest"], legacy.device_config_digest(record["sections"]))
                for section in record["sections"]:
                    self.assertEqual(section["sha256"], canonical.text_hash(section["sanitized"]))
        ceos = next(d for d in devices if d["platform"] == "ceos")["sections"]
        self.assertEqual([s["command"] for s in ceos], ["show running-config"])
        frr = next(d for d in devices if d["platform"] == "linux")["sections"]
        self.assertEqual([s["command"] for s in frr], ["vtysh -c 'show running-config'", "nft list ruleset"])
        self.assertEqual(payload["baseline"]["sanitization"]["stored_text"], "SANITIZED_NOT_BYTE_IDENTICAL")
        self.assertGreater(payload["baseline"]["sanitization"]["redacted_lines"], 0)
        self.assertEqual(candidate.payload_digest, canonical.payload_digest(payload))
        self.assertEqual((candidate.kind, candidate.provenance), (KIND.LEGACY_BASELINE, PROV.LEGACY_BOOTSTRAP))
        self.assertTrue(candidate.bundle_id.startswith("BND-LEGACY-"))
        self.assertEqual(payload["baseline"]["capture_assessment"]["result"], "PASS")

    def test_no_change_plan_validation_execution_uat_or_soak_is_fabricated(self):
        before = {m.__name__: m._base_manager.count() for m in (models.Change, models.ChangePlan, models.ChangeValidationRun, models.ChangeExecutionRun,
                                                                models.ConfigletExecutionResult, models.OperationalCheckRun, models.ProbationSoakRun, models.GoldenDecision)}
        run, candidate, world = bh.passed()
        after = {m.__name__: m._base_manager.count() for m in (models.Change, models.ChangePlan, models.ChangeValidationRun, models.ChangeExecutionRun,
                                                               models.ConfigletExecutionResult, models.OperationalCheckRun, models.ProbationSoakRun, models.GoldenDecision)}
        self.assertEqual(before, after)
        self.assertEqual(models.ConfigurationBundle.objects.exclude(kind=KIND.LEGACY_BASELINE).count(), 0, "no UAT / Probation bundle either")
        for name in ("change_id", "plan_id", "validation_run_id", "execution_run_id", "postcheck_run_id", "source_uat_id", "parent_id"):
            self.assertIsNone(getattr(candidate, name), name)

    def test_no_secret_material_is_persisted_anywhere_and_the_export_is_secret_free(self):
        run, candidate, world = bh.passed()
        result = bs.approve(run, actor="operator", confirm=bh.confirm_of(run), now=run.finished_at + timedelta(seconds=30), session_factory=world.factory)
        self.assertIsNotNone(result.bundle, codes_of(result.blockers))
        persisted = everything_persisted()
        exports = "".join(bundle_service.export_json(b) for b in models.ConfigurationBundle.objects.all())
        for secret in bh.SECRETS:
            with self.subTest(secret=secret):
                self.assertNotIn(secret, persisted)
                self.assertNotIn(secret, exports)
        self.assertIn("<REDACTED>", persisted)

    def test_capture_is_all_or_nothing(self):
        failures = [
            ("device unreachable (timeout)", lambda w: w.take_down("R2", "TIMEOUT")),
            ("device rejects credentials", lambda w: w.take_down("S1", "AUTH_FAILED")),
            ("FRR host unreachable", lambda w: w.take_down("R3")),
            ("configuration command fails", lambda w: w.outputs["R1"].__setitem__("running_config", live.LiveError("COMMAND_FAILED"))),
            ("configuration is empty", lambda w: w.outputs["S2"].__setitem__("running_config", "! nothing\n!\n")),
            ("interface evidence unparseable", lambda w: w.outputs["S3"].__setitem__("interfaces", "not json")),
        ]
        for label, break_it in failures:
            with self.subTest(label), transaction.atomic():
                world = bh.World()
                break_it(world)
                result, _ = bh.captured(world)
                self.assertTrue(result.refused)
                self.assertIsNone(result.bundle)
                self.assertEqual(codes_of(result.blockers), ["BOOTSTRAP_BASELINE_INCOMPLETE"])
                self.assertEqual(models.ConfigurationBundle.objects.count(), 0, "nothing is created and no device is silently omitted")
                transaction.set_rollback(True)

    def test_topology_unavailable_makes_the_baseline_incomplete(self):
        result, _ = bh.captured(snap=h.snapshot(summary=h.unavailable_topology()))
        self.assertEqual(codes_of(result.blockers), ["BOOTSTRAP_BASELINE_INCOMPLETE"])

    def test_an_unhealthy_or_unobservable_network_is_not_adopted_as_known_good(self):
        cases = [
            ("OSPF adjacency not FULL", lambda w: w.outputs["R1"].update(ospf=json.dumps({"vrfs": {"default": {"instList": {"10": {"ospfNeighborEntries": [
                {"routerId": "10.255.0.9", "interfaceName": "Ethernet1", "adjacencyState": "ExStart"}]}}}}})), {}, "BASELINE_UNHEALTHY"),
            ("addressed interface down", lambda w: w.outputs["S1"].update(interfaces=json.dumps({"interfaces": {"Ethernet1": {"interfaceStatus": "connected", "lineProtocolStatus": "down"}}})), {}, "BASELINE_UNHEALTHY"),
            ("a link is DOWN", lambda w: None, {"links": [h.edge("R1", "R2", "DOWN")]}, "BASELINE_UNHEALTHY"),
            ("critical CPU", lambda w: None, {"cpu": {"R1": 97}}, "BASELINE_UNHEALTHY"),
            ("stale telemetry", lambda w: None, {"ages": {"S4": 500}}, "BASELINE_EVIDENCE_UNAVAILABLE"),
            ("monitoring backend down", lambda w: None, {"backend": "ERROR"}, "BASELINE_EVIDENCE_UNAVAILABLE"),
        ]
        for label, mutate, telemetry, expected in cases:
            with self.subTest(label), transaction.atomic():
                world = bh.World()
                mutate(world)
                result, _ = bh.captured(world, snap=bh.snapshot(**telemetry))
                self.assertEqual(codes_of(result.blockers), [expected])
                self.assertEqual(models.ConfigurationBundle.objects.count(), 0)
                transaction.set_rollback(True)

    def test_the_canonical_digest_is_deterministic_and_independent_of_key_order(self):
        world = bh.World()
        reads = capture.read_all(capture.managed_scope(), session_factory=world.factory, now=bh.T0)
        args = dict(capture_started_at=bh.T0, capture_finished_at=bh.T0, snapshot=bh.snapshot(), repository_head="abc123", policy_version="P")
        first, problems = capture.build_payload(reads, **args)
        second, _ = capture.build_payload(capture.read_all(capture.managed_scope(), session_factory=world.factory, now=bh.T0), **args)
        self.assertEqual(problems, [])
        self.assertEqual(canonical.payload_digest(first), canonical.payload_digest(second))
        reordered = json.loads(json.dumps(first), object_pairs_hook=lambda pairs: dict(reversed(pairs)))
        self.assertEqual(canonical.payload_digest(reordered), canonical.payload_digest(first))
        changed = json.loads(json.dumps(first))
        changed["baseline"]["devices"][0]["sections"][0]["sanitized"] += "x"
        self.assertNotEqual(canonical.payload_digest(changed), canonical.payload_digest(first))
        self.assertNotIn("repr", canonical.canonical_json(first)[:5])

    def test_the_candidate_is_immutable_and_verifies(self):
        candidate, _world = bh.candidate_of()
        self.assertTrue(bundle_service.verify_bundle_integrity(candidate).ok)
        refusals = [
            ("save", lambda: candidate.save()),
            ("delete", lambda: candidate.delete()),
            ("queryset update", lambda: models.ConfigurationBundle.objects.filter(pk=candidate.pk).update(created_by="x")),
            ("queryset delete", lambda: models.ConfigurationBundle.objects.filter(pk=candidate.pk).delete()),
        ]
        for label, attempt in refusals:
            with self.subTest(label):
                self.assertRaises(ValueError, attempt)

    def test_tampering_with_the_stored_baseline_is_detected(self):
        def edit(mutator):
            def apply(candidate):
                manifest = json.loads(json.dumps(candidate.manifest))
                mutator(manifest)
                bundles_helper.oob(models.ConfigurationBundle).filter(pk=candidate.pk).update(manifest=manifest)
            return apply

        def set_text(m):
            m["payload"]["baseline"]["devices"][0]["sections"][0]["sanitized"] += "ip route 0.0.0.0/0 1.1.1.1\n"

        def leak(m):
            section = m["payload"]["baseline"]["devices"][0]["sections"][0]
            section["sanitized"] += "username evil secret sha512 $6$leak\n"
            section["sha256"] = canonical.text_hash(section["sanitized"])
            m["payload"]["baseline"]["devices"][0]["config_digest"] = legacy.device_config_digest(m["payload"]["baseline"]["devices"][0]["sections"])

        cases = [
            ("edited configuration text", edit(set_text), {"LEGACY_BASELINE_MALFORMED", "PAYLOAD_DIGEST_MISMATCH"}),
            ("dropped provenance block", edit(lambda m: m["lineage"].pop("legacy_bootstrap")), {"LEGACY_PROVENANCE_MISSING", "BUNDLE_DIGEST_MISMATCH"}),
            ("unredacted secret smuggled in", edit(leak), {"SECRET_SHAPED_CONTENT", "PAYLOAD_DIGEST_MISMATCH"}),
            ("kind rewritten", edit(lambda m: m.update(kind="GOLDEN")), {"KIND_MISMATCH"}),
        ]
        for label, tamper, expected in cases:
            with self.subTest(label), transaction.atomic():
                candidate, _world = bh.candidate_of()
                tamper(candidate)
                candidate.refresh_from_db()
                report = bundle_service.verify_bundle_integrity(candidate)
                self.assertFalse(report.ok)
                self.assertTrue(expected <= set(report.codes), (label, report.codes))
                transaction.set_rollback(True)


class ObservationTests(TestCase):
    def test_start_pins_a_server_owned_thirty_minute_window_and_is_idempotent(self):
        run, candidate, _world = bh.started()
        self.assertEqual((run.started_at, run.required_end_at), (bh.T0, bh.END))
        self.assertEqual((run.state, run.duration_seconds, run.started_by), (SS.RUNNING, 1800, "tester"))
        again = bs.start_bootstrap(candidate, actor="tester", now=bh.T0 + timedelta(seconds=5))
        self.assertEqual((again.run.pk, again.created), (run.pk, False))
        self.assertEqual(models.LegacyBootstrapRun.objects.count(), 1)
        self.assertTrue(models.AuditEvent.objects.filter(event_type="LEGACY_BOOTSTRAP_STARTED").exists())

    def test_a_healthy_observation_takes_seven_samples_and_ends_technically_passed_without_creating_golden(self):
        run, candidate, world = bh.passed()
        samples = list(run.samples.order_by("bucket"))
        self.assertEqual([s.bucket for s in samples], list(range(7)), "T+0, T+5 ... T+25 and the closing sample")
        self.assertEqual([int((s.sampled_at - bh.T0).total_seconds()) for s in samples], [0, 300, 600, 900, 1200, 1500, 1800])
        self.assertEqual((run.state, run.result, run.terminal_reason), (SS.COMPLETED, SRES.PASS, "TECHNICAL_PASS"))
        self.assertEqual(run.finished_at, bh.END)
        stats = run.evaluation["coverage"]
        self.assertEqual((stats["expected_intervals"], stats["covered_intervals"], stats["coverage_percent"], stats["max_gap_seconds"]), (6, 6, 100.0, 300.0))
        self.assertEqual((run.evaluation["config_drift"], run.evaluation["interference"], run.evaluation["integrity"]), ("NONE", "NONE", "INTACT"))
        self.assertEqual(run.evaluation["resources"]["samples_with_config_comparison"], 7)
        self.assertEqual(evaluator.verify_run(run), [])
        # a technical PASS is NOT an approval
        self.assertFalse(models.ConfigurationBundle.objects.filter(kind=KIND.GOLDEN).exists())
        self.assertFalse(models.LegacyBootstrapDecision.objects.exists())
        self.assertIsNone(bs.decision_of(run))
        self.assertTrue(models.AuditEvent.objects.filter(event_type="LEGACY_BOOTSTRAP_READY").exists())

    def test_thirty_minutes_minus_one_second_is_not_complete_and_exactly_thirty_minutes_is_eligible(self):
        run, _candidate, world = bh.started()
        bh.drive(world, start=bh.T0, until=bh.T0 + timedelta(seconds=1500))
        before = bh.tick(bh.T0 + timedelta(seconds=1799), world)
        run.refresh_from_db()
        self.assertEqual((run.state, [r.action for r in before.runs]), (SS.RUNNING, ["NOT_DUE"]))
        self.assertIsNone(run.finished_at)
        exactly = bh.tick(bh.END, world)
        run.refresh_from_db()
        self.assertEqual([r.action for r in exactly.runs], ["FINALIZED"])
        self.assertEqual((run.state, run.result), (SS.COMPLETED, SRES.PASS))

    def test_the_run_can_never_be_shortened_backdated_or_completed_early(self):
        run, _candidate, world = bh.started()
        for offset in (0, 300, 900, 1799):
            with self.subTest(offset=offset):
                bh.tick(bh.T0 + timedelta(seconds=offset), world)
                run.refresh_from_db()
                self.assertEqual(run.state, SS.RUNNING)
        for label, edit in (("required_end_at", {"required_end_at": bh.T0 + timedelta(seconds=60)}), ("started_at", {"started_at": bh.T0 - timedelta(hours=1)}),
                            ("policy", {"policy": {**run.policy, "duration_seconds": 1}})):
            with self.subTest(edit=label):
                run.refresh_from_db()
                for name, value in edit.items():
                    setattr(run, name, value)
                self.assertRaises(ValueError, run.save)

    def test_required_conditions_decide_the_outcome(self):
        """(label, mutation from bucket N on, telemetry at that instant) -> (state, result, reason, the sample result of the first bad sample)"""
        cases = [
            ("stale telemetry from the start", 0, lambda w: None, {"ages": {"R1": 400}}, (SS.COMPLETED, SRES.INCOMPLETE, "COVERAGE_INSUFFICIENT"), SR.INCOMPLETE),
            ("OSPF adjacency lost", 2, lambda w: w.outputs["R1"].update(ospf=json.dumps({"vrfs": {"default": {"instList": {"10": {"ospfNeighborEntries": []}}}}})), {},
             (SS.COMPLETED, SRES.FAIL, "EXPECTED_STATE_FAILED"), SR.FAIL),
            ("OSPF neighbor no longer FULL", 2, lambda w: w.outputs["S1"].update(ospf=json.dumps({"vrfs": {"default": {"instList": {"10": {"ospfNeighborEntries": [
                {"routerId": "10.255.0.9", "interfaceName": "Ethernet1", "adjacencyState": "Init"}]}}}}})), {}, (SS.COMPLETED, SRES.FAIL, "EXPECTED_STATE_FAILED"), SR.FAIL),
            ("required route disappears", 2, lambda w: w.outputs["R2"].update(ip_routes=json.dumps({"vrfs": {"default": {"routes": {}}}})), {},
             (SS.COMPLETED, SRES.FAIL, "EXPECTED_STATE_FAILED"), SR.FAIL),
            ("required interface goes down", 2, lambda w: w.outputs["S2"].update(interfaces=json.dumps({"interfaces": {
                "Ethernet1": {"interfaceStatus": "connected", "lineProtocolStatus": "down"}, "Management0": {"interfaceStatus": "connected", "lineProtocolStatus": "up"}}})), {},
             (SS.COMPLETED, SRES.FAIL, "EXPECTED_STATE_FAILED"), SR.FAIL),
            ("an interface disappears", 2, lambda w: w.outputs["S3"].update(interfaces=json.dumps({"interfaces": {"Management0": {"interfaceStatus": "connected", "lineProtocolStatus": "up"}}})), {},
             (SS.COMPLETED, SRES.FAIL, "EXPECTED_STATE_FAILED"), SR.FAIL),
            ("required link DOWN", 2, lambda w: None, {"links": [h.edge("R1", "R2", "DOWN"), h.edge("R2", "R3"), h.edge("S1", "S2")]},
             (SS.COMPLETED, SRES.FAIL, "EXPECTED_STATE_FAILED"), SR.FAIL),
            ("required link vanishes from the topology", 2, lambda w: None, {"links": [h.edge("R2", "R3"), h.edge("S1", "S2")]},
             (SS.COMPLETED, SRES.FAIL, "EXPECTED_STATE_FAILED"), SR.FAIL),
            ("monitoring backend down", 0, lambda w: None, {"backend": "ERROR"}, (SS.COMPLETED, SRES.INCOMPLETE, "COVERAGE_INSUFFICIENT"), SR.INCOMPLETE),
        ]
        for label, from_bucket, mutate, telemetry, expected, first_bad in cases:
            with self.subTest(label), transaction.atomic():
                world = bh.World()
                run, _candidate, _ = bh.started(world)
                start_bad = bh.T0 + timedelta(seconds=300 * from_bucket)

                def degrade(moment, telemetry=telemetry, start_bad=start_bad):
                    return telemetry if moment >= start_bad else {}

                moment = bh.T0
                while moment <= bh.END + timedelta(seconds=300) and models.LegacyBootstrapRun.objects.filter(state=SS.RUNNING).exists():
                    if moment >= start_bad and not getattr(world, "_mutated", False):
                        mutate(world)
                        world._mutated = True
                    bh.tick(moment, world, **degrade(moment))
                    moment += timedelta(seconds=150)
                run.refresh_from_db()
                self.assertEqual((run.state, run.result, run.terminal_reason), expected, (label, run.evaluation.get("problems")))
                self.assertEqual(run.samples.order_by("-bucket").first().result, first_bad)
                self.assertFalse(models.ConfigurationBundle.objects.filter(kind=KIND.GOLDEN).exists())
                transaction.set_rollback(True)

    def test_critical_cpu_or_memory_is_judged_by_the_projects_consecutive_sample_policy(self):
        """One critical sample is tolerated (five of six intervals still covered); two consume the coverage (INCOMPLETE, never adopted); three
        consecutive samples -- the project's own ``consecutive_samples`` -- end the run FAILED."""
        cases = [
            ("one critical CPU sample", lambda t: {"cpu": {"S1": 96}} if 300 <= t < 600 else {}, (SS.COMPLETED, SRES.PASS, "TECHNICAL_PASS")),
            ("two critical CPU samples then recovery", lambda t: {"cpu": {"S1": 96}} if 300 <= t < 900 else {}, (SS.COMPLETED, SRES.INCOMPLETE, "COVERAGE_INSUFFICIENT")),
            ("three consecutive critical CPU samples", lambda t: {"cpu": {"S1": 96}} if 300 <= t < 1200 else {}, (SS.COMPLETED, SRES.FAIL, "RESOURCE_CRITICAL_SUSTAINED")),
            ("three consecutive critical memory samples", lambda t: {"memory": {"R3": 97}} if 600 <= t < 1500 else {}, (SS.COMPLETED, SRES.FAIL, "RESOURCE_CRITICAL_SUSTAINED")),
        ]
        for label, telemetry_at, expected in cases:
            with self.subTest(label), transaction.atomic():
                run, _c, world = bh.started()
                bh.drive(world, start=bh.T0, until=bh.END + timedelta(seconds=300), telemetry_at=lambda m, f=telemetry_at: f((m - bh.T0).total_seconds()))
                run.refresh_from_db()
                self.assertEqual((run.state, run.result, run.terminal_reason), expected, (label, run.evaluation.get("problems")))
                transaction.set_rollback(True)

    def test_coverage_and_gap_rules(self):
        """The Phase-20 rules at the bootstrap's own numbers: >= 80 % of six intervals (five) and no unobserved stretch over 600 s."""
        cases = [
            ("one missed sample is tolerated", lambda t: t == 600, (SS.COMPLETED, SRES.PASS, "TECHNICAL_PASS")),
            ("two consecutive missed samples open a 900 s gap", lambda t: t in (600, 900), (SS.COMPLETED, SRES.INCOMPLETE, "COVERAGE_INSUFFICIENT")),
            ("only the first and last samples exist", lambda t: 0 < t < 1800, (SS.COMPLETED, SRES.INCOMPLETE, "COVERAGE_INSUFFICIENT")),
            ("a collector outage for the last quarter hour", lambda t: 900 <= t < 1800, (SS.COMPLETED, SRES.INCOMPLETE, "COVERAGE_INSUFFICIENT")),
            ("two isolated missed samples leave 4 of 6", lambda t: t in (300, 900), (SS.COMPLETED, SRES.INCOMPLETE, "COVERAGE_INSUFFICIENT")),
        ]
        for label, missing, expected in cases:
            with self.subTest(label), transaction.atomic():
                run, _c, world = bh.started()
                bh.drive(world, start=bh.T0, until=bh.END + timedelta(seconds=600), step=300, skip=lambda m, f=missing: f((m - bh.T0).total_seconds()))
                run.refresh_from_db()
                if run.state == SS.RUNNING:   # the closing tick was skipped by the matrix: the operator restarts the collector after the end
                    bh.tick(bh.END + timedelta(seconds=1), world)
                    run.refresh_from_db()
                self.assertEqual((run.state, run.result, run.terminal_reason), expected, (label, run.evaluation.get("problems")))
                transaction.set_rollback(True)

    def test_a_single_unreadable_device_makes_only_that_sample_incomplete(self):
        run, _c, world = bh.started()
        moment = bh.T0
        while moment <= bh.END + timedelta(seconds=300) and models.LegacyBootstrapRun.objects.filter(state=SS.RUNNING).exists():
            if moment == bh.T0 + timedelta(seconds=600):
                world.take_down("S4", "TIMEOUT")
            elif moment == bh.T0 + timedelta(seconds=750):
                world.down.clear()
            bh.tick(moment, world)
            moment += timedelta(seconds=150)
        run.refresh_from_db()
        self.assertEqual(run.samples.get(bucket=2).result, SR.INCOMPLETE)
        self.assertEqual((run.state, run.result), (SS.COMPLETED, SRES.PASS), "unavailable evidence is missing evidence (never PASS, never FAIL); coverage still holds")
        self.assertEqual(run.evaluation["coverage"]["covered_intervals"], 5)

    def test_configuration_drift_invalidates_and_is_never_adopted(self):
        cases = [
            ("a cEOS line added", "R1", lambda w: w.edit_config("R1", "hostname R1", "hostname R1\nip route 0.0.0.0/0 9.9.9.9"), True),
            ("a cEOS line removed", "S1", lambda w: w.edit_config("S1", "router ospf 10\n   network 10.0.0.0/8 area 0\n", "router ospf 10\n"), True),
            ("an FRR line changed", "R3", lambda w: w.edit_config("R3", "network 10.0.0.0/8 area 0", "network 10.0.0.0/8 area 1"), True),
            ("an nft ruleset changed", "R4", lambda w: w.outputs["R4"].__setitem__("nft", bh.NFT + "table ip filter {\n}\n"), True),
            ("only a comment / whitespace changed", "R2", lambda w: w.edit_config("R2", "!\nend", "! Time: 12:30\n\nend  "), False),
        ]
        for label, device, mutate, drifts in cases:
            with self.subTest(label), transaction.atomic():
                run, candidate, world = bh.started()
                bh.drive(world, start=bh.T0, until=bh.T0 + timedelta(seconds=600))
                mutate(world)
                bh.drive(world, start=bh.T0 + timedelta(seconds=750), until=bh.END + timedelta(seconds=300))
                run.refresh_from_db()
                if drifts:
                    self.assertEqual((run.state, run.result, run.terminal_reason), (SS.INVALIDATED, "", "CONFIG_DRIFT_DETECTED"))
                    bad = run.samples.order_by("-bucket").first()
                    self.assertTrue(bad.config_drift)
                    self.assertEqual(bad.result, SR.INVALIDATED)
                    self.assertEqual(bad.findings[0]["device"], device)
                    self.assertEqual(run.evaluation["config_drift"], "DETECTED")
                    self.assertEqual(bundle_service.verify_bundle_integrity(candidate).ok, True, "the candidate itself is untouched; the network moved")
                else:
                    self.assertEqual((run.state, run.result), (SS.COMPLETED, SRES.PASS))
                self.assertFalse(models.ConfigurationBundle.objects.filter(kind=KIND.GOLDEN).exists())
                transaction.set_rollback(True)

    def test_documented_limitation_a_change_to_only_a_redacted_value_is_not_visible(self):
        run, _candidate, world = bh.started()
        bh.drive(world, start=bh.T0, until=bh.T0 + timedelta(seconds=300))
        world.edit_config("R1", "$6$SALTsalt$hashHASHhash", "$6$DIFFERENT$hashHASHhash")
        bh.drive(world, start=bh.T0 + timedelta(seconds=450), until=bh.END + timedelta(seconds=300))
        run.refresh_from_db()
        self.assertEqual((run.state, run.result), (SS.COMPLETED, SRES.PASS), "the baseline holds managed configuration SEMANTICS, not literal secret bytes")

    def test_a_network_configuration_execution_invalidates_the_observation(self):
        fixture = sh.probation()      # real Change / plan / validation rows (stamped with WALL-CLOCK times, all long before the controlled timeline)

        def history(devices, *, outcome="SUCCEEDED", state="FINISHED", before=False):
            when = bh.T0 - timedelta(hours=2) if before else bh.T0 + timedelta(seconds=400)
            return models.ChangeExecutionRun.objects.create(
                change=fixture.prob.change, plan=fixture.prob.plan, validation_run=fixture.prob.validation_run, mode="COMPLETE", state=state,
                outcome=outcome if state == "FINISHED" else "", engine_version="t", plan_hash="0" * 64, validation_input_hash="0" * 64, validation_source_hash="0" * 64,
                devices=list(devices), started_at=when, finished_at=when + timedelta(seconds=30) if state == "FINISHED" else None,
                lease_expires_at=when + timedelta(seconds=1800))

        cases = [
            ("a later successful execution on an included device", dict(devices=["R1"]), True),
            ("a still-RUNNING execution on an included device", dict(devices=["S2"], state="RUNNING"), True),
            ("a later BLOCKED (no mutation) execution", dict(devices=["R1"], outcome="BLOCKED"), False),
            ("a later execution on a device NOT in the baseline", dict(devices=["H1"]), False),
            ("an execution that finished before the baseline was captured", dict(devices=["R1"], before=True), False),
        ]
        for label, spec, invalidates in cases:
            with self.subTest(label), transaction.atomic():
                run, candidate, world = bh.started()
                history(**spec)
                bh.drive(world, start=bh.T0, until=bh.END + timedelta(seconds=300))
                run.refresh_from_db()
                if invalidates:
                    self.assertEqual((run.state, run.terminal_reason), (SS.INVALIDATED, "OVERLAPPING_EXECUTION"))
                    self.assertEqual(run.evaluation["interference"], "DETECTED")
                else:
                    self.assertEqual((run.state, run.result), (SS.COMPLETED, SRES.PASS))
                transaction.set_rollback(True)

    def test_an_execution_before_start_blocks_starting_at_all(self):
        candidate, world = bh.candidate_of()
        fixture = sh.probation()
        models.ChangeExecutionRun.objects.create(
            change=fixture.prob.change, plan=fixture.prob.plan, validation_run=fixture.prob.validation_run, mode="COMPLETE", state="FINISHED", outcome="SUCCEEDED",
            engine_version="t", plan_hash="0" * 64, validation_input_hash="0" * 64, validation_source_hash="0" * 64, devices=["R2"],
            started_at=bh.T0 + timedelta(seconds=20), finished_at=bh.T0 + timedelta(seconds=40), lease_expires_at=bh.T0 + timedelta(seconds=900))
        result = bs.start_bootstrap(candidate, actor="tester", now=bh.T0 + timedelta(seconds=60))
        self.assertEqual(codes_of(result.blockers), ["CANDIDATE_INTERFERED"])

    def test_an_integrity_failure_of_the_candidate_invalidates_the_observation(self):
        run, candidate, world = bh.started()
        bh.drive(world, start=bh.T0, until=bh.T0 + timedelta(seconds=300))
        bundles_helper.oob(models.ConfigurationBundle).filter(pk=candidate.pk).update(payload_digest="f" * 64)
        bh.drive(world, start=bh.T0 + timedelta(seconds=450), until=bh.END + timedelta(seconds=300))
        run.refresh_from_db()
        self.assertEqual((run.state, run.terminal_reason), (SS.INVALIDATED, "BUNDLE_INTEGRITY_FAILED"))

    def test_a_stale_candidate_cannot_start(self):
        candidate, _world = bh.candidate_of()
        result = bs.start_bootstrap(candidate, actor="tester", now=bh.T0 + timedelta(hours=2))
        self.assertEqual(codes_of(result.blockers), ["CANDIDATE_STALE"])

    def test_the_collector_is_idempotent_and_never_backfills(self):
        run, _c, world = bh.started()
        first = bh.tick(bh.T0, world)
        second = bh.tick(bh.T0, world)
        self.assertEqual([r.action for r in first.runs] + [r.action for r in second.runs], ["SAMPLED", "NOT_DUE"])
        self.assertEqual(run.samples.count(), 1)
        bh.tick(bh.T0 + timedelta(seconds=1500), world)   # a long outage: exactly ONE sample for the current bucket, none for the downtime
        self.assertEqual([s.bucket for s in run.samples.order_by("bucket")], [0, 5])
        dry = bs.run_tick(now=bh.T0 + timedelta(seconds=1600), dry_run=True)
        self.assertEqual(dry.runs[0].action, "NOT_DUE")
        self.assertEqual(run.samples.count(), 2, "a dry run writes nothing")

    def test_an_interruption_is_resumable_when_coverage_still_holds_and_incomplete_otherwise(self):
        for label, gap_from, gap_to, expected in (("one missed interval", 600, 900, SRES.PASS), ("half an hour of silence", 300, 1800, SRES.INCOMPLETE)):
            with self.subTest(label), transaction.atomic():
                run, _c, world = bh.started()
                bh.drive(world, start=bh.T0, until=bh.END + timedelta(seconds=600), skip=lambda m, a=gap_from, b=gap_to: a <= (m - bh.T0).total_seconds() < b)
                run.refresh_from_db()
                if run.state == SS.RUNNING:
                    bh.tick(bh.END + timedelta(seconds=1), world)
                    run.refresh_from_db()
                self.assertEqual((run.state, run.result), (SS.COMPLETED, expected))
                stamps = [int((s.sampled_at - bh.T0).total_seconds()) for s in run.samples.order_by("bucket")]
                self.assertTrue(all(t % 150 == 0 or t == 1801 for t in stamps), stamps)   # only real tick instants -- nothing fabricated or edited
                transaction.set_rollback(True)

    def test_the_operator_command_loop_waits_never_busy_loops_and_honours_the_real_duration(self):
        run, _c, world = bh.started()
        clock = {"now": bh.T0, "sleeps": []}

        def sleep(seconds):
            clock["sleeps"].append(seconds)
            clock["now"] += timedelta(seconds=seconds)

        finished = bs.drive(run, snapshot_fn=lambda: bh.snapshot(clock["now"]), session_factory=world.factory, dhcp_state=bh.DHCP, sleep=sleep, clock=lambda: clock["now"])
        self.assertEqual((finished.state, finished.result), (SS.COMPLETED, SRES.PASS))
        self.assertGreaterEqual(clock["now"], bh.END)
        self.assertLess(clock["now"], bh.END + timedelta(seconds=60))
        self.assertTrue(all(0 < s <= 15 for s in clock["sleeps"]), "bounded, non-zero waits: never a busy loop")
        self.assertLess(len(clock["sleeps"]), 400)

    def test_cancelling_keeps_the_evidence_and_can_never_become_golden(self):
        run, candidate, world = bh.started()
        bh.tick(bh.T0, world)
        result = bs.cancel_bootstrap(run, actor="operator", now=bh.T0 + timedelta(seconds=10))
        run.refresh_from_db()
        self.assertEqual((result.cancelled, run.state, run.terminal_reason), (True, SS.CANCELLED, "CANCELLED_BY_OPERATOR"))
        self.assertEqual(run.samples.count(), 1)
        self.assertEqual(codes_of(bs.cancel_bootstrap(run, actor="operator").blockers), ["NOT_RUNNING"])
        approval = bs.approve(run, actor="operator", confirm=bh.confirm_of(run), now=bh.T0 + timedelta(seconds=20), session_factory=world.factory)
        self.assertIn("OBSERVATION_NOT_PASSED", codes_of(approval.blockers))

    def test_a_finished_run_and_its_samples_are_immutable(self):
        run, _c, _w = bh.passed()
        for label, attempt in (("run save", lambda: (setattr(run, "result", "FAIL"), run.save())), ("run delete", run.delete),
                               ("sample save", lambda: run.samples.first().save()), ("sample delete", lambda: run.samples.first().delete()),
                               ("run queryset update", lambda: models.LegacyBootstrapRun.objects.filter(pk=run.pk).update(result="FAIL")),
                               ("sample queryset delete", lambda: models.LegacyBootstrapSample.objects.filter(run=run).delete())):
            with self.subTest(label):
                self.assertRaises(ValueError, attempt)

    def test_the_whole_lifecycle_sends_only_allowlisted_read_only_commands(self):
        world = bh.World()
        run, candidate, world = bh.passed(world)
        bs.approve(run, actor="operator", confirm=bh.confirm_of(run), now=run.finished_at + timedelta(seconds=30), session_factory=world.factory)
        self.assertTrue(world.opened)
        allowed = set(live.CEOS_COMMANDS) | set(live.LINUX_COMMANDS)
        self.assertEqual(live.LINUX_COMMANDS["frr_config"], ("vtysh", "-c", "show running-config"))
        seen = set()
        original = h.FakeSession.run

        def spy(self, key):
            seen.add(key)
            return original(self, key)

        # re-run one full sample with a spy to inspect every command KEY sent
        with mock.patch.object(h.FakeSession, "run", spy):
            bs.readiness_probe(now=bh.T0, session_factory=world.factory, snapshot=bh.snapshot(), dhcp_state=bh.DHCP)
        self.assertTrue(seen and seen <= allowed, seen - allowed)


class ApprovalAndGoldenTests(TestCase):
    def test_operator_approval_creates_the_initial_golden_with_legacy_bootstrap_provenance(self):
        result, run, candidate, world = bh.approved()
        self.assertIsNotNone(result.bundle, codes_of(result.blockers))
        golden = result.bundle
        self.assertTrue(result.created)
        self.assertEqual((golden.kind, golden.provenance, golden.parent_id), (KIND.GOLDEN, PROV.LEGACY_BOOTSTRAP, candidate.pk))
        self.assertTrue(golden.bundle_id.startswith("BND-GOLD-"))
        self.assertEqual(golden.payload_digest, candidate.payload_digest, "the Golden pins the EXACT baseline the candidate captured")
        self.assertNotEqual(golden.bundle_digest, candidate.bundle_digest)
        self.assertEqual(golden.manifest["payload"], candidate.manifest["payload"])
        block = golden.lineage["legacy_bootstrap"]
        self.assertEqual((block["provenance_type"], block["role"], block["decision"], block["decided_by"]), ("LEGACY_BOOTSTRAP", "INITIAL_GOLDEN", "APPROVE", "operator"))
        self.assertEqual((block["candidate_bundle_id"], block["candidate_bundle_digest"], block["baseline_digest"]), (candidate.bundle_id, candidate.bundle_digest, candidate.payload_digest))
        self.assertEqual((block["observation_run_id"], block["observation_duration_seconds"], block["policy_version"]), (run.run_id, 1800, "LEGACY_BOOTSTRAP_POLICY_V1"))
        self.assertEqual((block["observation_started_at"], block["observation_required_end_at"], block["observation_completed_at"]),
                         ("2035-03-01T12:00:00Z", "2035-03-01T12:30:00Z", "2035-03-01T12:30:00Z"))
        self.assertEqual((block["evidence_digest"], block["predates_automation_framework"], block["config_recheck_result"]), (run.evidence_digest, True, "MATCH"))
        self.assertIsNone(golden.lineage.get("promotion"), "it is NOT presented as a normal soak promotion")
        decision = models.LegacyBootstrapDecision.objects.get(golden_bundle=golden)
        self.assertEqual((decision.run_id, decision.decided_by, decision.evidence_digest), (run.pk, "operator", run.evidence_digest))
        for name in ("change_id", "plan_id", "validation_run_id", "execution_run_id", "postcheck_run_id", "source_uat_id"):
            self.assertIsNone(getattr(golden, name), name)
        self.assertTrue(bundle_service.verify_bundle_integrity(golden).ok)
        self.assertTrue(bundle_service.verify_bundle_integrity(candidate).ok)
        audit = models.AuditEvent.objects.get(event_type="LEGACY_GOLDEN_APPROVED")
        self.assertEqual((audit.metadata["provenance_type"], audit.metadata["baseline_digest"]), ("LEGACY_BOOTSTRAP", candidate.payload_digest))
        self.assertIsNotNone(golden.created_at)
        document = json.loads(bundle_service.export_json(golden))
        self.assertEqual(document["bundle"]["provenance"], "LEGACY_BOOTSTRAP")
        self.assertEqual(document["sources"]["change_id"], "")
        self.assertTrue(bundle_service.verify_export(document).ok, bundle_service.verify_export(document).codes)

    def test_approval_is_idempotent(self):
        first, run, _c, world = bh.approved()
        again = bs.approve(run, actor="operator", confirm=bh.confirm_of(run), now=run.finished_at + timedelta(seconds=99), session_factory=world.factory)
        self.assertEqual((again.bundle.pk, again.created), (first.bundle.pk, False))
        self.assertEqual(models.ConfigurationBundle.objects.filter(kind=KIND.GOLDEN).count(), 1)

    def test_confirmation_and_comment_are_checked(self):
        run, candidate, world = bh.passed()
        when = run.finished_at + timedelta(seconds=30)
        good = bh.confirm_of(run)
        cases = [
            ("wrong run", {**good, "run_id": "BOOT-999999"}, "", "CONFIRMATION_MISMATCH"),
            ("wrong candidate", {**good, "candidate_id": "BND-LEGACY-999999"}, "", "CONFIRMATION_MISMATCH"),
            ("wrong digest", {**good, "candidate_digest": "0" * 64}, "", "CONFIRMATION_MISMATCH"),
            ("wrong baseline digest", {**good, "baseline_digest": "0" * 64}, "", "CONFIRMATION_MISMATCH"),
            ("nothing confirmed", {}, "", "CONFIRMATION_MISMATCH"),
            ("secret in the comment", good, "enable secret sha512 hunter2-enable", "REASON_SECRET_SHAPED"),
        ]
        for label, confirm, reason, expected in cases:
            with self.subTest(label):
                result = bs.approve(run, actor="operator", confirm=confirm, reason=reason, now=when, session_factory=world.factory)
                self.assertTrue(result.refused)
                self.assertIn(expected, codes_of(result.blockers))
        self.assertFalse(models.ConfigurationBundle.objects.filter(kind=KIND.GOLDEN).exists())

    def test_the_configuration_is_re_read_immediately_before_approval_and_a_change_blocks_it(self):
        cases = [
            ("a cEOS device changed after the observation", lambda w: w.edit_config("S3", "hostname S3", "hostname S3\nvlan 999"), "CONFIG_DRIFT_DETECTED"),
            ("an FRR device changed", lambda w: w.edit_config("R4", "hostname R4", "hostname R4-renamed"), "CONFIG_DRIFT_DETECTED"),
            ("a device cannot be read at decision time", lambda w: w.take_down("R1", "TIMEOUT"), "DRIFT_CHECK_INCOMPLETE"),
            ("the configuration cannot be read", lambda w: w.outputs["S1"].__setitem__("running_config", live.LiveError("COMMAND_FAILED")), "DRIFT_CHECK_INCOMPLETE"),
        ]
        for label, mutate, expected in cases:
            with self.subTest(label), transaction.atomic():
                run, candidate, world = bh.passed()
                mutate(world)
                result = bs.approve(run, actor="operator", confirm=bh.confirm_of(run), now=run.finished_at + timedelta(seconds=30), session_factory=world.factory)
                self.assertTrue(result.refused)
                self.assertEqual(codes_of(result.blockers), [expected])
                self.assertFalse(models.ConfigurationBundle.objects.filter(kind=KIND.GOLDEN).exists(), "the changed configuration is never adopted")
                self.assertFalse(models.LegacyBootstrapDecision.objects.exists())
                transaction.set_rollback(True)

    def test_the_golden_payload_is_the_pinned_baseline_never_a_post_approval_read(self):
        run, candidate, world = bh.passed()
        result = bs.approve(run, actor="operator", confirm=bh.confirm_of(run), now=run.finished_at + timedelta(seconds=30), session_factory=world.factory)
        world.edit_config("R1", "hostname R1", "hostname R1-changed-after-approval")
        golden = models.ConfigurationBundle.objects.get(pk=result.bundle.pk)
        text = json.dumps(golden.manifest["payload"])
        self.assertNotIn("changed-after-approval", text)
        self.assertEqual(golden.payload_digest, candidate.payload_digest)

    def test_only_a_technically_passed_current_observation_can_be_approved(self):
        def approve_after(run, world, seconds=30):
            return bs.approve(run, actor="operator", confirm=bh.confirm_of(run), now=run.finished_at + timedelta(seconds=seconds), session_factory=world.factory)

        with self.subTest("decision window expired"), transaction.atomic():
            run, _c, world = bh.passed()
            result = approve_after(run, world, seconds=3601)
            self.assertIn("OBSERVATION_EXPIRED", codes_of(result.blockers))
            transaction.set_rollback(True)
        with self.subTest("evidence tampered"), transaction.atomic():
            run, _c, world = bh.passed()
            bundles_helper.oob(models.LegacyBootstrapSample).filter(run=run, bucket=3).update(result="PASS_WITH_WARNINGS")
            self.assertIn("OBSERVATION_EVIDENCE_INVALID", codes_of(approve_after(run, world).blockers))
            transaction.set_rollback(True)
        with self.subTest("candidate tampered"), transaction.atomic():
            run, candidate, world = bh.passed()
            bundles_helper.oob(models.ConfigurationBundle).filter(pk=candidate.pk).update(payload_digest="e" * 64)
            self.assertIn("CANDIDATE_INTEGRITY_FAILED", codes_of(approve_after(run, world).blockers))
            transaction.set_rollback(True)
        with self.subTest("an execution touched a device after the pass"), transaction.atomic():
            run, candidate, world = bh.passed()
            fixture = sh.probation()
            models.ChangeExecutionRun.objects.create(
                change=fixture.prob.change, plan=fixture.prob.plan, validation_run=fixture.prob.validation_run, mode="COMPLETE", state="FINISHED", outcome="SUCCEEDED",
                engine_version="t", plan_hash="0" * 64, validation_input_hash="0" * 64, validation_source_hash="0" * 64, devices=["R1"],
                started_at=bh.END + timedelta(seconds=5), finished_at=bh.END + timedelta(seconds=9), lease_expires_at=bh.END + timedelta(seconds=900))
            self.assertIn("INTERFERENCE_DETECTED", codes_of(approve_after(run, world).blockers))
            transaction.set_rollback(True)
        for label, mutate in (("FAIL", lambda w: w.outputs["R1"].update(ospf=json.dumps({"vrfs": {"default": {"instList": {"10": {"ospfNeighborEntries": []}}}}}))),
                              ("INVALIDATED", lambda w: w.edit_config("R1", "hostname R1", "hostname R1\nvlan 5"))):
            with self.subTest(label), transaction.atomic():
                run, candidate, world = bh.started()
                bh.drive(world, start=bh.T0, until=bh.T0 + timedelta(seconds=600))
                mutate(world)
                bh.drive(world, start=bh.T0 + timedelta(seconds=750), until=bh.END + timedelta(seconds=300))
                run.refresh_from_db()
                self.assertFalse(run.is_technical_pass)
                self.assertIn("OBSERVATION_NOT_PASSED", codes_of(bs.approve(run, actor="operator", confirm=bh.confirm_of(run), now=bh.END + timedelta(seconds=60),
                                                                            session_factory=world.factory).blockers))
                transaction.set_rollback(True)

    def test_a_stale_recheck_can_never_be_replayed_to_seal_golden(self):
        run, candidate, world = bh.passed()
        when = run.finished_at + timedelta(seconds=30)
        old = capture.recheck_configuration(candidate, session_factory=world.factory, now=when - timedelta(seconds=600))
        result = legacy.create_initial_golden(candidate, evidence=run, recheck=old, actor="operator", now=when)
        self.assertIn("DRIFT_CHECK_INCOMPLETE", codes_of(result.blockers))
        forged = {**old, "checked_at_dt": when, "baseline_digest": "0" * 64}
        self.assertIn("DRIFT_CHECK_INCOMPLETE", codes_of(legacy.create_initial_golden(candidate, evidence=run, recheck=forged, actor="operator", now=when).blockers))
        self.assertFalse(models.ConfigurationBundle.objects.filter(kind=KIND.GOLDEN).exists())


class OneTimeLockoutTests(TestCase):
    def test_after_the_initial_golden_the_shortcut_is_refused_forever(self):
        result, run, candidate, world = bh.approved()
        self.assertIsNotNone(result.bundle)
        later = bh.T0 + timedelta(days=1)
        checks = {
            "capture": bs.capture_candidate(actor="tester", now=later, session_factory=world.factory, snapshot=bh.snapshot(later), dhcp_state=bh.DHCP).blockers,
            "start (old candidate)": bs.start_bootstrap(candidate, actor="tester", now=later).blockers,
            "seal": legacy.seal_candidate(json.loads(json.dumps(candidate.manifest["payload"])), actor="tester", policy_version="P").blockers,
            "probe": bs.readiness_probe(now=later, session_factory=world.factory, snapshot=bh.snapshot(later), dhcp_state=bh.DHCP)["blockers"],
        }
        for label, blockers in checks.items():
            with self.subTest(label):
                self.assertIn("LEGACY_BOOTSTRAP_ALREADY_COMPLETED", codes_of(blockers))
        self.assertEqual(models.ConfigurationBundle.objects.filter(kind=KIND.LEGACY_BASELINE).count(), 1)
        self.assertEqual(models.ConfigurationBundle.objects.filter(kind=KIND.GOLDEN).count(), 1)
        self.assertEqual(models.LegacyBootstrapRun.objects.count(), 1)

    def test_the_lockout_is_persisted_state_not_a_flag(self):
        """The gate is computed from rows alone -- no setting, no module flag, nothing in memory: remove the rows (out of band, inside a savepoint) and
        the shortcut would reopen; restore them and it is closed again.  A server restart therefore changes nothing."""
        result, run, candidate, world = bh.approved()
        self.assertEqual(codes_of(legacy.gate_blockers()), ["LEGACY_BOOTSTRAP_ALREADY_COMPLETED"])
        with transaction.atomic():
            bundles_helper.oob(models.LegacyBootstrapDecision).filter(pk=result.decision.pk)._raw_delete("default")
            bundles_helper.oob(models.ConfigurationBundle).filter(pk=result.bundle.pk)._raw_delete("default")
            self.assertEqual(legacy.gate_blockers(), [])
            transaction.set_rollback(True)
        self.assertEqual(codes_of(legacy.gate_blockers()), ["LEGACY_BOOTSTRAP_ALREADY_COMPLETED"])

    def test_the_database_itself_refuses_a_second_legacy_golden_even_around_the_service(self):
        result, run, candidate, world = bh.approved()
        other = models.ConfigurationBundle(bundle_id="BND-LEGACY-000002", kind=KIND.LEGACY_BASELINE, provenance=PROV.LEGACY_BOOTSTRAP, sequence=2, schema_version=1,
                                           builder_version="x", payload_digest="a" * 64, bundle_digest="a" * 64, manifest={})
        bundles_helper.oob(models.ConfigurationBundle).bulk_create([other])       # bulk_create bypasses model validation: this is the DATABASE speaking
        second_golden = models.ConfigurationBundle(bundle_id="BND-GOLD-000099", kind=KIND.GOLDEN, provenance=PROV.LEGACY_BOOTSTRAP, sequence=99, schema_version=1,
                                                   builder_version="x", payload_digest="a" * 64, bundle_digest="b" * 64, manifest={}, parent=other)
        with self.assertRaises(IntegrityError) as caught, transaction.atomic():
            bundles_helper.oob(models.ConfigurationBundle).bulk_create([second_golden])
        self.assertIn("provenance", str(caught.exception))

    def test_a_normal_golden_also_closes_the_shortcut(self):
        fixture = sh.probation()
        sh.golden_from(fixture.prob)
        result, _world = bh.captured()
        self.assertEqual(codes_of(result.blockers), ["GOLDEN_EXISTS"])
        self.assertEqual(models.ConfigurationBundle.objects.filter(kind=KIND.LEGACY_BASELINE).count(), 0)

    def test_future_normal_probation_stays_seven_days_after_the_bootstrap(self):
        approved_result, _run, _candidate, _world = bh.approved()
        self.assertIsNotNone(approved_result.bundle)
        fixture = sh.probation()
        started = soak_service.start_soak(fixture.prob, actor="tester", now=bh.T0 + timedelta(days=1))
        self.assertIsNotNone(started.run, codes_of(started.blockers))
        self.assertEqual((started.run.duration_seconds, started.run.policy["duration_seconds"]), (604800, 604800))
        self.assertEqual(started.run.required_end_at - started.run.started_at, timedelta(days=7))
        self.assertEqual(started.run.policy_version, "20.0.0")


class ProvenanceConstraintTests(TestCase):
    """The exception is narrow: a normal bundle can NEVER have parent = NULL or missing sources, and legacy provenance fits nothing but the candidate and
    its single Golden.  Enforced by the model AND by database CHECK constraints (proved with ``bulk_create``, which bypasses the model)."""

    @staticmethod
    def make(kind, seq, **over):
        return models.ConfigurationBundle(bundle_id=f"{models.BUNDLE_ID_PREFIX[kind]}{seq:06d}", kind=kind, sequence=seq, schema_version=1, builder_version="x",
                                          payload_digest="a" * 64, bundle_digest=f"{seq:x}".rjust(64, "c"), manifest={}, **over)

    def test_the_model_refuses_bundles_that_would_widen_the_exception(self):
        prob = sh.probation().prob
        uat = prob.source_uat
        refs = dict(change=prob.change, plan=prob.plan, validation_run=prob.validation_run, execution_run=prob.execution_run)
        candidate, _w = bh.candidate_of()
        cases = [
            ("a normal Golden without a parent", lambda: self.make(KIND.GOLDEN, 71, **refs)),
            ("a normal Golden with no Change / plan / execution", lambda: self.make(KIND.GOLDEN, 72, parent=prob, source_uat=uat)),
            ("a normal Golden whose parent is a legacy candidate", lambda: self.make(KIND.GOLDEN, 73, parent=candidate, source_uat=uat, **refs)),
            ("a UAT bundle claiming legacy provenance", lambda: self.make(KIND.UAT, 74, provenance=PROV.LEGACY_BOOTSTRAP)),
            ("a Probation bundle claiming legacy provenance", lambda: self.make(KIND.PROBATION, 75, parent=uat, source_uat=uat, provenance=PROV.LEGACY_BOOTSTRAP, **refs)),
            ("a legacy candidate with a Change attached", lambda: self.make(KIND.LEGACY_BASELINE, 76, provenance=PROV.LEGACY_BOOTSTRAP, change=prob.change)),
            ("a legacy candidate with execution-lineage provenance", lambda: self.make(KIND.LEGACY_BASELINE, 77, **refs)),
            ("a legacy Golden whose parent is a Probation bundle", lambda: self.make(KIND.GOLDEN, 78, parent=prob, provenance=PROV.LEGACY_BOOTSTRAP)),
            ("a legacy Golden with a different payload than its candidate", lambda: models.ConfigurationBundle(
                bundle_id="BND-GOLD-000079", kind=KIND.GOLDEN, sequence=79, schema_version=1, builder_version="x", payload_digest="9" * 64, bundle_digest="d" * 64,
                manifest={}, parent=candidate, provenance=PROV.LEGACY_BOOTSTRAP)),
        ]
        for label, build in cases:
            with self.subTest(label):
                self.assertRaises(ValueError, lambda build=build: build().save())

    def test_the_database_enforces_the_same_rules_around_the_model(self):
        prob = sh.probation().prob
        refs = dict(change=prob.change, plan=prob.plan, validation_run=prob.validation_run, execution_run=prob.execution_run)
        cases = [
            ("execution-lineage UAT with no Change", lambda: self.make(KIND.UAT, 81)),
            ("normal Golden with no parent", lambda: self.make(KIND.GOLDEN, 82, **refs)),
            ("legacy candidate carrying a Change", lambda: self.make(KIND.LEGACY_BASELINE, 83, provenance=PROV.LEGACY_BOOTSTRAP, change=prob.change)),
            ("legacy provenance on a UAT bundle", lambda: self.make(KIND.UAT, 84, provenance=PROV.LEGACY_BOOTSTRAP)),
            ("execution-lineage legacy candidate", lambda: self.make(KIND.LEGACY_BASELINE, 85, **refs)),
        ]
        for label, build in cases:
            with self.subTest(label), self.assertRaises(IntegrityError), transaction.atomic():
                bundles_helper.oob(models.ConfigurationBundle).bulk_create([build()])

    def test_only_one_bootstrap_run_can_be_active_and_one_sample_exists_per_bucket(self):
        run, candidate, _w = bh.started()
        with self.assertRaises(IntegrityError), transaction.atomic():
            bundles_helper.oob(models.LegacyBootstrapRun).bulk_create([models.LegacyBootstrapRun(
                candidate=candidate, candidate_digest=candidate.bundle_digest, policy_version="x", policy={}, started_at=bh.T0, required_end_at=bh.END)])
        rows = [models.LegacyBootstrapSample(run=run, bucket=0, sampled_at=bh.T0, result="PASS", integrity_ok=True, interference=False, config_drift=False,
                                             collector_version="x") for _ in range(2)]
        with self.assertRaises(IntegrityError), transaction.atomic():
            bundles_helper.oob(models.LegacyBootstrapSample).bulk_create(rows)


class Phase21EntryTests(TestCase):
    def test_no_golden_means_no_valid_entry(self):
        entry = bundle_service.known_good_baseline()
        self.assertEqual((entry.valid, entry.blockers), (False, ["NO_GOLDEN"]))

    def test_the_bootstrap_golden_is_a_valid_entry_and_its_source_is_never_hidden(self):
        result, _run, _candidate, _world = bh.approved()
        entry = bundle_service.known_good_baseline()
        self.assertTrue(entry.valid)
        self.assertEqual((entry.golden.pk, entry.source), (result.bundle.pk, "LEGACY_BOOTSTRAP"))
        self.assertIn("did NOT pass a seven-day soak", entry.note)
        self.assertTrue(entry.integrity.ok)

    def test_a_normal_lifecycle_golden_is_a_valid_entry_reported_as_such(self):
        golden = sh.golden_from(sh.probation().prob)
        entry = bundle_service.known_good_baseline()
        self.assertEqual((entry.valid, entry.golden.pk, entry.source), (True, golden.pk, "NORMAL_LIFECYCLE"))
        self.assertNotIn("did NOT", entry.note)

    def test_a_golden_that_no_longer_verifies_is_not_an_entry(self):
        result, _run, _candidate, _world = bh.approved()
        bundles_helper.oob(models.ConfigurationBundle).filter(pk=result.bundle.pk).update(payload_digest="0" * 64)
        entry = bundle_service.known_good_baseline()
        self.assertEqual((entry.valid, entry.blockers), (False, ["GOLDEN_INTEGRITY_FAILED"]))


class ReadinessProbeTests(TestCase):
    def test_the_probe_reports_devices_support_monitoring_and_blockers_and_persists_nothing(self):
        world = bh.World()
        world.take_down("R2", "TIMEOUT")
        before = (models.ConfigurationBundle._base_manager.count(), models.AuditEvent.objects.count(), models.LegacyBootstrapRun._base_manager.count())
        report = bs.readiness_probe(now=bh.T0, session_factory=world.factory, snapshot=bh.snapshot(), dhcp_state=bh.DHCP)
        self.assertEqual(before, (models.ConfigurationBundle._base_manager.count(), models.AuditEvent.objects.count(), models.LegacyBootstrapRun._base_manager.count()))
        self.assertEqual(report["managed_devices"], sorted(bh.MANAGED))
        self.assertEqual(report["unreachable"], ["R2"])
        self.assertFalse(report["ready"])
        self.assertIn("BOOTSTRAP_BASELINE_INCOMPLETE", codes_of(report["blockers"]))
        self.assertEqual(report["monitoring"], {"topology_available": True, "backend_status": "OK", "fresh_devices": 10, "total_devices": 10})
        self.assertEqual({d["device"] for d in report["devices"] if d["capability"] == "SUPPORTED"}, set(bh.MANAGED))
        self.assertTrue(report["evaluators"])
        self.assertEqual(report["policy"]["duration_seconds"], 1800)

    def test_a_healthy_network_is_ready(self):
        report = bs.readiness_probe(now=bh.T0, session_factory=bh.World().factory, snapshot=bh.snapshot(), dhcp_state=bh.DHCP)
        self.assertEqual((report["ready"], report["blockers"], report["assessment"]["result"]), (True, [], "PASS"))


class DockerEosSessionTests(TestCase):
    """R5's management address is Containerlab-assigned ('auto'), so it has no SSH target: it is read through the repository's credential-free
    ``docker exec <container> Cli -p 15 -c`` pattern -- and only then."""

    def test_only_a_ceos_device_without_an_inventory_address_uses_docker_exec(self):
        from core.services.health import inventory

        chosen = {name: live.default_session_factory(entry).__name__ for name, entry in inventory.managed_devices().items()}
        self.assertEqual(chosen["R5"], "DockerEosSession")
        self.assertEqual({n for n, c in chosen.items() if c == "DockerEosSession"}, {"R5"})
        self.assertEqual({chosen[n] for n in ("R3", "R4")}, {"LinuxSession"})
        self.assertEqual({chosen[n] for n in ("R1", "R2", "S1", "S2", "S3", "S4", "mgmt_swt")}, {"EosSession"})

    def test_the_argv_is_fixed_shell_free_and_addressed_by_allowlist_key_only(self):
        calls = []

        def fake_run(argv, **kwargs):
            calls.append((argv, kwargs))
            return mock.Mock(returncode=0, stdout="output", stderr="")

        session = live.DockerEosSession({"name": "R5", "container": "clab-srlceos01-R5"})
        with mock.patch.object(live.subprocess, "run", fake_run):
            self.assertEqual(session.run("running_config"), "output")
            self.assertEqual(session.run("interfaces"), "output")
            for hostile in ("configure terminal", "show running-config; reload", "$(reboot)", ""):
                with self.subTest(key=hostile):
                    self.assertRaises(live.LiveError, session.run, hostile)
        self.assertEqual(calls[0][0], ["docker", "exec", "clab-srlceos01-R5", "Cli", "-p", "15", "-c", "show running-config"])
        self.assertEqual(calls[1][0][-1], "show interfaces | json")
        self.assertEqual(len(calls), 2, "a key that is not in the allowlist never reaches subprocess")
        for _argv, kwargs in calls:
            self.assertIs(kwargs["shell"], False)
        self.assertTrue(all(command.startswith("show ") for command in [v.partition(" | ")[0] for v in live.CEOS_COMMANDS.values()]))

    def test_failures_become_sanitized_codes(self):
        session = live.DockerEosSession({"name": "R5", "container": "clab-srlceos01-R5"})
        import subprocess

        for label, effect, expected in (("no docker", FileNotFoundError(), "DOCKER_UNAVAILABLE"), ("timeout", subprocess.TimeoutExpired("docker", 1), "TIMEOUT"),
                                        ("os error", OSError("boom"), "DOCKER_UNAVAILABLE")):
            with self.subTest(label), mock.patch.object(live.subprocess, "run", side_effect=effect):
                with self.assertRaises(live.LiveError) as caught:
                    session.run("running_config")
                self.assertEqual(caught.exception.code, expected)
        with mock.patch.object(live.subprocess, "run", return_value=mock.Mock(returncode=1, stdout="", stderr="Error: No such container secret-name")):
            with self.assertRaises(live.LiveError) as caught:
                session.run("interfaces")
            self.assertEqual(caught.exception.code, "CONNECTION_FAILED")
            self.assertNotIn("secret-name", str(caught.exception))
        self.assertRaises(live.LiveError, live.DockerEosSession, {"name": "R5"})
        self.assertEqual(live.LiveError("anything-else").code, "COMMAND_FAILED")


class BootstrapBoundaryTests(SimpleTestCase):
    """The bootstrap READS the network through the existing read-only sessions and can reach the initial Golden through ONE path."""

    @staticmethod
    def package_sources():
        import pathlib

        root = pathlib.Path(__file__).resolve().parents[1] / "services"
        files = sorted((root / "bootstrap").glob("*.py")) + [root / "bootstrap_service.py"]
        return {f"{f.parent.name}/{f.name}": f.read_text() for f in files}

    def test_no_device_client_shell_engine_netbox_or_orchestrator_is_ever_imported(self):
        import ast

        forbidden = {"netmiko", "paramiko", "subprocess", "socket", "requests", "urllib", "docker", "pynetbox", "ncclient", "pygnmi", "os", "shutil", "master", "modules"}
        forbidden_from = ("execution", "nsot_netbox", "nsot_git", "change_service", "lifecycle_service", "execution_service", "raw_configlet_service", "planning")
        for name, text in self.package_sources().items():
            imports, relative = set(), set()
            for node in ast.walk(ast.parse(text)):
                if isinstance(node, ast.Import):
                    imports |= {a.name.split(".")[0] for a in node.names}
                elif isinstance(node, ast.ImportFrom):
                    imports.add((node.module or "").split(".")[0])
                    relative |= {(node.module or "").split(".")[0]} | {a.name for a in node.names}
            with self.subTest(module=name):
                self.assertEqual(imports & forbidden, set())
                self.assertEqual(relative & set(forbidden_from), set())

    def test_nothing_here_configures_a_device_or_runs_a_shell_or_a_lifecycle_tool(self):
        import ast

        forbidden_identifiers = {"send_config", "send_config_set", "config_mode", "save_config", "execute_" + "change", "push_eos", "ConnectHandler", "Popen", "check_output",
                                 "check_call", "system", "popen", "rmtree", "remove_configuration", "rollback_change"}
        forbidden_text = ("configure terminal", "write memory", "copy running", "containerlab deploy", "containerlab destroy", "snmp-only", "master.py", "shell=True", "reload now", "reboot")
        for name, text in self.package_sources().items():
            tree = ast.parse(text)
            docstrings = {id(node.body[0].value) for node in ast.walk(tree) if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef))
                          and node.body and isinstance(node.body[0], ast.Expr) and isinstance(getattr(node.body[0], "value", None), ast.Constant)}
            identifiers = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)} | {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
            strings = [n.value.lower() for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in docstrings]
            with self.subTest(module=name, check="identifiers"):
                self.assertEqual(identifiers & forbidden_identifiers, set())
            for token in forbidden_text:
                with self.subTest(module=name, token=token):
                    self.assertEqual([t for t in strings if token in t], [])

    def test_only_the_approval_module_can_reach_the_initial_golden_creation_path(self):
        import pathlib
        import re

        root = pathlib.Path(__file__).resolve().parents[2]
        referers = set()
        for path in (root / "core").rglob("*.py"):
            rel = path.relative_to(root).as_posix()
            if "/tests/" in rel or "/migrations/" in rel:
                continue
            if "create_initial_golden" in path.read_text():
                referers.add(rel)
        self.assertEqual(referers, {"core/services/bundles/legacy.py", "core/services/bootstrap/decision.py"})
        lifecycle = (root / "core/services/bootstrap/lifecycle.py").read_text()
        for token in ("create_initial_golden", "decision", "seal_bundle"):
            self.assertNotIn(f"import {token}", lifecycle)
        self.assertNotIn("create_initial_golden", lifecycle, "the collector can never create Golden")
        # the normal soak code is untouched by the bootstrap: it does not know the bootstrap exists
        for rel in ("core/services/soak/lifecycle.py", "core/services/soak/decision.py", "core/services/soak/sampling.py", "core/services/soak/policy.py",
                    "core/services/bundles/golden.py"):
            with self.subTest(module=rel):
                self.assertNotRegex((root / rel).read_text().lower(), re.compile(r"legacy_bootstrap|bootstrap_service|legacybootstrap"))

    def test_the_normal_seven_day_policy_source_is_untouched_by_the_bootstrap(self):
        import pathlib

        root = pathlib.Path(__file__).resolve().parents[2]
        for rel in ("core/services/soak/policy.py",):
            self.assertNotIn("LEGACY_BOOTSTRAP", (root / rel).read_text())
        settings_text = (root / "config/settings.py").read_text()
        self.assertIn('PROBATION_SOAK_DURATION_SECONDS = _bounded_seconds(\n    "PROBATION_SOAK_DURATION_SECONDS", str(SOAK_PRODUCTION_DURATION_SECONDS), SOAK_PRODUCTION_DURATION_SECONDS', settings_text)
        self.assertIn("SOAK_PRODUCTION_DURATION_SECONDS = 7 * 24 * 60 * 60", settings_text)
