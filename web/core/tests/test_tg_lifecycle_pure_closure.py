"""Lab 7 closure -- the pure parts of the bootstrap / soak / bundle lifecycle, each called directly.

``bootstrap.codes`` / ``bundles.codes`` / ``soak.codes`` catalogue helpers, the canonical digests' refusal of non-JSON values,
``SoakPolicy`` round-trips, the bootstrap candidate age, ``legacy_sanitize`` detection, the soak evaluator's facts / statistics /
resource streak / final summary / evidence digest, and the bootstrap evaluator's verdict / digests / summary / re-verification.

Pure: no database, no device, no clock (every instant is explicit).  Runs and samples are plain namespaces carrying exactly the fields
the code reads.  POSITIVE: exact catalogue entries, digests that are stable and domain-separated, exact statistics and verdicts.
NEGATIVE: unknown codes raise, NaN / non-JSON values are refused, incomplete policies raise, secret-shaped lines are detected and
never "clean", drift / interference / integrity failures invalidate a run, a tampered summary never re-verifies.
"""
from __future__ import annotations

import math
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from django.test import SimpleTestCase, override_settings

from core import models
from core.services.bootstrap import codes as boot_codes, evaluator as boot_eval, policy as boot_policy
from core.services.bundles import canonical, codes as bundle_codes, export, legacy_sanitize as san
from core.services.soak import codes as soak_codes, evaluator as soak_eval
from core.services.soak.policy import SoakPolicy

SR = models.SoakSampleResult
T0 = datetime(2026, 10, 19, 12, 0, tzinfo=timezone.utc)
POLICY = SoakPolicy(version="LEGACY_BOOTSTRAP_POLICY_V1", duration_seconds=1800, sample_interval_seconds=300, max_gap_seconds=600,
                    min_coverage_percent=80, resource_consecutive_samples=3, decision_max_age_seconds=3600, freshness_healthy_seconds=60.0,
                    freshness_stale_seconds=120.0, production_duration_seconds=604800)
END = T0 + timedelta(seconds=1800)


def sample(bucket, result=SR.PASS, *, critical=(), drift=False, integrity=True, interference=False, terminal=False, counts=None, evidence=None,
           at=None):
    return SimpleNamespace(bucket=bucket, sampled_at=at or T0 + timedelta(seconds=300 * bucket), result=result, integrity_ok=integrity,
                           interference=interference, terminal_failure=terminal, resource_critical=list(critical), expected_state_result="PASS",
                           telemetry_freshness="FRESH", counts=counts if counts is not None else {"warning": 0}, config_drift=drift,
                           evidence=evidence or {})


def healthy_samples():
    return [sample(b, evidence={"devices": {"R1": {"cpu_percent": 10 + b, "memory_percent": 40.04}}, "config": {"compared": 5}}) for b in range(7)]


class CatalogueTests(SimpleTestCase):
    def test_blocker_and_finding_return_catalogue_entries_with_details(self):
        with self.subTest("catalogue entries"):
            self._catalogue_entries()

    def _catalogue_entries(self):
        self.assertEqual(boot_codes.blocker("BASELINE_UNHEALTHY", devices=["R1"]),
                         {"code": "BASELINE_UNHEALTHY", "message": boot_codes.BOOTSTRAP_BLOCKERS["BASELINE_UNHEALTHY"][0],
                          "remediation": boot_codes.BOOTSTRAP_BLOCKERS["BASELINE_UNHEALTHY"][1], "details": {"devices": ["R1"]}})
        self.assertEqual(bundle_codes.blocker(bundle_codes.UAT_BLOCKERS, "RUN_NOT_FINISHED")["remediation"],
                         "Wait for the run to finish; an active run is never bundled.")
        self.assertEqual(bundle_codes.finding("ITEMS_MISMATCH", count=3),
                         {"code": "ITEMS_MISMATCH", "message": bundle_codes.INTEGRITY_FINDINGS["ITEMS_MISMATCH"], "details": {"count": 3}})
        self.assertEqual(soak_codes.blocker(soak_codes.START_BLOCKERS, "SOAK_ACTIVE")["code"], "SOAK_ACTIVE")
        self.assertNotIn("details", soak_codes.blocker(soak_codes.START_BLOCKERS, "SOAK_ACTIVE"))

    def test_blocker_and_finding_of_unknown_codes_raise(self):
        for label, call in (("unknown bootstrap code", lambda: boot_codes.blocker("NOPE")),
                            ("unknown bundle code", lambda: bundle_codes.blocker(bundle_codes.GOLDEN_BLOCKERS, "RUN_NOT_FINISHED")),
                            ("unknown finding", lambda: bundle_codes.finding("NOPE")),
                            ("unknown soak code", lambda: soak_codes.blocker(soak_codes.START_BLOCKERS, "NOPE"))):
            with self.subTest(label), self.assertRaises(KeyError):
                call()


class CanonicalDigestTests(SimpleTestCase):
    def test_digests_refuse_values_that_are_not_plain_json(self):
        for label, call, error in (
                ("refused NaN payload digest", lambda: canonical.bundle_digest(kind="UAT", payload_digest=math.nan), ValueError),
                ("refused datetime promotion", lambda: canonical.bundle_digest(kind="GOLDEN", payload_digest="a", promotion={"at": T0}), TypeError),
                ("refused set item", lambda: canonical.item_digest({"devices": {"R1"}}), TypeError),
                ("refused object export", lambda: canonical.export_digest({"bundle": object()}), TypeError)):
            with self.subTest(label), self.assertRaises(error):
                call()

    def test_export_filename_of_an_unsaved_bundle_without_an_id_raises(self):
        with self.assertRaises(AttributeError):
            export.export_filename(SimpleNamespace())


class PolicyTests(SimpleTestCase):
    def test_soak_policy_to_dict_round_trips_through_from_dict(self):
        data = POLICY.to_dict()
        self.assertEqual((data["duration_seconds"], data["min_coverage_percent"], SoakPolicy.from_dict(dict(data, extra="ignored"))),
                         (1800, 80, POLICY))

    def test_soak_policy_from_dict_missing_a_field_raises(self):
        data = POLICY.to_dict()
        del data["max_gap_seconds"]
        with self.assertRaisesRegex(KeyError, "max_gap_seconds"):
            SoakPolicy.from_dict(data)

    @override_settings(LEGACY_BOOTSTRAP_CANDIDATE_MAX_AGE_SECONDS="5400")
    def test_candidate_max_age_seconds_returns_the_configured_integer(self):
        self.assertEqual(boot_policy.candidate_max_age_seconds(), 5400)


class LegacySanitizeTests(SimpleTestCase):
    def test_detect_returns_pattern_names_only(self):
        names = san.detect("username admin secret sha512 $6$abcdefgh$ijklmnop")
        self.assertTrue(names)
        self.assertNotIn("$6$abcdefgh", " ".join(names))
        self.assertEqual(san.detect("  pre-shared-key psk ZZZ"), sorted(set(san.detect("  pre-shared-key psk ZZZ"))))
        self.assertIn("KEYWORD:passphrase", san.detect("wpa passphrase hunter2hunter2"))

    def test_detect_of_plain_configuration_is_empty(self):
        for line in ("interface Ethernet1", "   description uplink to R2", "router ospf 1", "", "secret"):
            with self.subTest("none for " + repr(line)):
                self.assertEqual(san.detect(line), [])

    def test_is_clean_accepts_redacted_and_plain_lines(self):
        self.assertTrue(san.is_clean("username admin secret <REDACTED>"))
        self.assertTrue(san.is_clean("hostname R1"))

    def test_is_clean_refuses_unredacted_secrets(self):
        for line in ("username admin secret sha512 $6$abc$def", "wpa passphrase hunter2hunter2", "snmp-server community public123 ro"):
            with self.subTest("refused " + line.split()[0]):
                self.assertFalse(san.is_clean(line))

    def test_residual_secret_lines_flags_lines_missing_redaction(self):
        text = "hostname R1\nusername admin secret <REDACTED>\nwpa passphrase hunter2hunter2\n"
        hits = san.residual_secret_lines(text)
        self.assertEqual([h["line"] for h in hits], [3])
        self.assertNotIn("hunter2", repr(hits))
        many = "\n".join("wpa passphrase s%02dsecretvalue" % i for i in range(30))
        self.assertEqual(len(san.residual_secret_lines(many)), 20)


class SoakEvaluatorTests(SimpleTestCase):
    def test_facts_of_returns_the_persisted_fields(self):
        facts = soak_eval.facts_of(sample(2, SR.PASS_WITH_WARNINGS, critical=["R1:CPU"], counts={"warning": 4}, drift=True))
        self.assertEqual((facts.bucket, facts.result, facts.resource_critical, facts.warnings, facts.config_drift),
                         (2, SR.PASS_WITH_WARNINGS, ("R1:CPU",), 4, True))

    def test_facts_of_a_sample_without_counts_or_levels_has_zero_warnings(self):
        row = sample(0, counts={})
        row.counts, row.resource_critical = None, None
        with self.subTest("none counts"):
            facts = soak_eval.facts_of(row)
        self.assertEqual((facts.warnings, facts.resource_critical), (0, ()))
        with self.assertRaises(AttributeError):
            soak_eval.facts_of(SimpleNamespace(bucket=0))

    def test_statistics_returns_full_coverage_for_a_healthy_window(self):
        facts = [soak_eval.facts_of(s) for s in healthy_samples()]
        stats = soak_eval.statistics(POLICY, T0, END, facts)
        self.assertEqual((stats["expected_intervals"], stats["covered_intervals"], stats["coverage_percent"], stats["max_gap_seconds"]),
                         (6, 6, 100.0, 300.0))
        self.assertEqual((stats["first_sample_at"], stats["last_sample_at"], stats["clock_anomalies"]), ("2026-10-19T12:00:00Z", "2026-10-19T12:30:00Z", 0))

    def test_statistics_of_unusable_and_out_of_order_samples_reports_gaps_and_anomalies(self):
        facts = [soak_eval.facts_of(sample(0, SR.INCOMPLETE)), soak_eval.facts_of(sample(1, at=T0 - timedelta(seconds=5))),
                 soak_eval.facts_of(sample(2, SR.FAIL))]
        with self.subTest("refused unusable samples"):
            stats = soak_eval.statistics(POLICY, T0, END, facts)
        self.assertEqual((stats["usable_samples"], stats["covered_intervals"], stats["incomplete_samples"], stats["failed_samples"],
                          stats["clock_anomalies"], stats["max_gap_seconds"]), (0, 0, 1, 1, 2, 1800.0))
        self.assertEqual(soak_eval.statistics(POLICY, T0, END, [])["first_sample_at"], None)

    def test_resource_streak_returns_the_longest_consecutive_critical_run(self):
        facts = [soak_eval.facts_of(s) for s in (sample(0, critical=["R1:CPU"]), sample(1, SR.INCOMPLETE), sample(2, critical=["R1:CPU", "R2:MEM"]),
                                                  sample(3, critical=["R1:CPU"]), sample(4, critical=["R2:MEM"]))]
        self.assertEqual(soak_eval.resource_streak(facts), (3, "R1:CPU"))

    def test_resource_streak_without_critical_levels_is_zero(self):
        self.assertEqual(soak_eval.resource_streak([soak_eval.facts_of(s) for s in healthy_samples()]), (0, ""))

    def soak_run(self):
        return SimpleNamespace(soak_id="SOAK-000001", bundle_digest="b" * 64, policy_version="20.0.0", started_at=T0, required_end_at=END)

    def test_final_summary_and_evidence_digest_are_stable(self):
        facts = [soak_eval.facts_of(s) for s in healthy_samples()]
        verdict = soak_eval.evaluate(POLICY, T0, END, facts, END)
        summary = soak_eval.final_summary(self.soak_run(), POLICY, facts, verdict, END)
        self.assertEqual((summary["technical_result"], summary["interference"], summary["integrity"], summary["expected_state"]),
                         (models.SoakResult.PASS, "NONE", "INTACT", {"PASS": 7}))
        self.assertEqual(soak_eval.evidence_digest(summary), soak_eval.evidence_digest(dict(reversed(list(summary.items())))))

    def test_final_summary_of_an_interfered_run_and_a_non_json_digest_input(self):
        facts = [soak_eval.facts_of(sample(0, interference=True)), soak_eval.facts_of(sample(1, integrity=False))]
        verdict = soak_eval.evaluate(POLICY, T0, END, facts, END)
        with self.subTest("invalid interfered run"):
            summary = soak_eval.final_summary(self.soak_run(), POLICY, facts, verdict, END)
        self.assertEqual((summary["state"], summary["interference"], summary["integrity"]), (models.SoakState.INVALIDATED, "DETECTED", "FAILED"))
        with self.assertRaises(TypeError):
            soak_eval.evidence_digest({"completed_at": END})


class BootstrapEvaluatorTests(SimpleTestCase):
    def boot_run(self, samples, *, finished_at=END, technical_pass=True):
        run = SimpleNamespace(run_id="LBR-000001", candidate_digest="c" * 64, policy_version=POLICY.version, policy=POLICY.to_dict(),
                              started_at=T0, required_end_at=END, finished_at=finished_at, is_technical_pass=technical_pass,
                              samples=SimpleNamespace(all=lambda: list(samples)))
        facts = [boot_eval.facts_of(s) for s in samples]
        verdict = boot_eval.evaluate(POLICY, T0, END, facts, END)
        run.evaluation = boot_eval.final_summary(run, POLICY, samples, verdict, END)
        run.evidence_digest = boot_eval.evidence_digest(run.evaluation)
        return run

    def test_facts_of_returns_boot_facts_with_drift(self):
        facts = boot_eval.facts_of(sample(3, drift=True, counts={"warning": 2}))
        self.assertIsInstance(facts, boot_eval.BootFacts)
        self.assertEqual((facts.bucket, facts.config_drift, facts.warnings), (3, True, 2))

    def test_facts_of_a_row_missing_the_drift_column_raises(self):
        row = sample(0)
        del row.config_drift
        with self.assertRaises(AttributeError):
            boot_eval.facts_of(row)

    def test_evaluate_returns_technical_pass_for_a_healthy_window(self):
        verdict = boot_eval.evaluate(POLICY, T0, END, [boot_eval.facts_of(s) for s in healthy_samples()], END)
        self.assertEqual((verdict.state, verdict.result, verdict.reason), (models.SoakState.COMPLETED, models.SoakResult.PASS, boot_codes.TECHNICAL_PASS))

    def test_evaluate_invalidates_on_guard_integrity_interference_or_drift(self):
        facts = [boot_eval.facts_of(s) for s in healthy_samples()]
        for label, guard, expected in (
                ("refused integrity", SimpleNamespace(integrity_ok=False, interference=[]), boot_codes.BUNDLE_INTEGRITY_FAILED),
                ("refused interference", SimpleNamespace(integrity_ok=True, interference=["CER-1"]), boot_codes.OVERLAPPING_EXECUTION),
                ("refused drift", SimpleNamespace(integrity_ok=True, interference=[], config_drift=True), boot_codes.CONFIG_DRIFT_DETECTED)):
            with self.subTest(label):
                verdict = boot_eval.evaluate(POLICY, T0, END, facts, END, guard=guard)
                self.assertEqual((verdict.state, verdict.reason), (models.SoakState.INVALIDATED, expected))

    def test_samples_digest_binds_the_drift_marker(self):
        clean = [boot_eval.facts_of(sample(0))]
        self.assertEqual(boot_eval.samples_digest(clean), boot_eval.samples_digest(list(reversed(clean))))
        self.assertRegex(boot_eval.samples_digest(clean), r"^[0-9a-f]{64}$")

    def test_samples_digest_differs_when_drift_is_present(self):
        with self.subTest("refused drift hidden"):
            self.assertNotEqual(boot_eval.samples_digest([boot_eval.facts_of(sample(0))]),
                                boot_eval.samples_digest([boot_eval.facts_of(sample(0, drift=True))]))

    def test_final_summary_returns_resources_and_coverage(self):
        run = self.boot_run(healthy_samples())
        summary = run.evaluation
        self.assertEqual(summary["resources"], {"max_cpu_percent": 16.0, "max_memory_percent": 40.0, "samples_with_config_comparison": 7,
                                                "devices_compared_per_sample": [5], "warning_findings": 0})
        self.assertEqual((summary["run_id"], summary["config_drift"], summary["coverage"]["covered_intervals"]), ("LBR-000001", "NONE", 6))
        self.assertEqual(boot_eval.evidence_digest(summary), run.evidence_digest)

    def test_final_summary_of_a_drifted_run_without_resource_evidence(self):
        run = self.boot_run([sample(0, drift=True), sample(1)])
        self.assertEqual((run.evaluation["config_drift"], run.evaluation["state"], run.evaluation["resources"]["max_cpu_percent"]),
                         ("DETECTED", models.SoakState.INVALIDATED, None))
        with self.assertRaises(TypeError):
            boot_eval.evidence_digest({"started_at": T0})

    def test_evidence_digest_is_domain_separated_from_the_soak_digest(self):
        summary = {"run_id": "LBR-000001"}
        self.assertNotEqual(boot_eval.evidence_digest(summary), soak_eval.evidence_digest(summary))

    def test_verify_run_reports_tampering_and_never_repairs(self):
        self.assertEqual(boot_eval.verify_run(SimpleNamespace(is_technical_pass=False)), ["NOT_TECHNICAL_PASS"])
        run = self.boot_run(healthy_samples())
        self.assertEqual(boot_eval.verify_run(run), [])
        run.evaluation = dict(run.evaluation, run_id="LBR-999999")
        self.assertEqual(boot_eval.verify_run(run), ["EVIDENCE_DIGEST", "SUMMARY_IDENTITY"])
        early = self.boot_run(healthy_samples(), finished_at=END - timedelta(seconds=1))
        self.assertEqual(boot_eval.verify_run(early), ["DURATION_NOT_ELAPSED"])
