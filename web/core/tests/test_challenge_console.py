"""V2 Phase 6 -- the standalone challenge console, as seen from the NMAS project.

The console (``challenge_console/`` at the repository root) is deliberately NOT a Django application and imports nothing from this
project.  Two things still tie it to the website's code, and both are pinned here so the ordinary project gate catches a break:

1. Its automation transport reads the deployment database with fixed SELECT statements.  Those statements name tables and columns that
   the Django models own; ``SchemaContractTests`` prepares every one of them against the real migrated schema, so a migration that
   renames or drops something the console reads fails here, not silently on the operations desk.
2. Its vocabulary for soak collector freshness / eligibility and for telemetry freshness is the project's.  ``VocabularyContractTests``
   compares the console's own definitions with the project's on the same inputs.

The console's own test-suite (collectors, lifecycle, logging, close workflow, read-only boundary) is added to this module through
``load_tests`` so the full Django gate runs it too.  Its Tk tests skip themselves where no display is available.
"""

from __future__ import annotations

import sys
import unittest
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

from django.db import connection
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from challenge_console.adapters import automation_db, telemetry  # noqa: E402

from core import models  # noqa: E402
from core.services.health import thresholds  # noqa: E402
from core.services.soak import overview  # noqa: E402
from core.services.soak.policy import current_policy  # noqa: E402


class SchemaContractTests(TestCase):
    def test_every_console_query_is_valid_against_the_migrated_schema(self):
        with connection.cursor() as cursor:
            for name, sql in automation_db.QUERIES.items():
                with self.subTest(query=name):
                    cursor.execute("EXPLAIN " + sql.replace("?", "%s"), [1] * sql.count("?"))      # prepares it: tables and columns must exist
                    self.assertTrue(cursor.fetchall())

    def test_no_console_query_is_treated_as_optional_once_the_schema_has_the_table(self):
        tables = set(connection.introspection.table_names())
        for name, sql in automation_db.QUERIES.items():
            for table in {word for word in sql.replace(",", " ").split() if word.startswith("core_")}:
                self.assertIn(table, tables, f"{name} reads {table}")

    def test_the_console_reads_no_secret_bearing_column(self):
        secret_columns = {"secret_ref", "ssh_key_ref", "ssh_public_key", "prior_secret_version", "new_secret_version", "raw_output", "manifest",
                          "candidate_config", "report", "previous_state"}
        for name, sql in automation_db.QUERIES.items():
            self.assertFalse(secret_columns & set(sql.replace(",", " ").replace(".", " ").split()), name)

    def test_soak_identifier_matches_the_model(self):
        described = automation_db.describe_soak(
            {"id": 1, "state": "RUNNING", "result": "", "terminal_reason": "", "policy": "{}", "baseline": "{}", "started_by": "x",
             "started_at": "2026-10-06T10:56:22Z", "required_end_at": "2026-10-13T10:56:22Z", "finished_at": "", "bundle_id": "BND-PROB-000001"},
            None, {}, None, now=timezone.now())
        self.assertEqual(described["soak_id"], models.ProbationSoakRun(pk=1).soak_id)
        self.assertEqual({"RUNNING", "COMPLETED"} - set(models.SoakState.values), set())
        self.assertIn("PASS", models.SoakResult.values)


class VocabularyContractTests(SimpleTestCase):
    def test_telemetry_freshness_classes_and_boundaries_are_the_projects(self):
        project = thresholds.load_thresholds()["freshness"]
        console = telemetry.load_thresholds(REPO_ROOT / thresholds.TOPOLOGY_CONFIG_FILE)
        self.assertEqual(console, project)
        for age in (None, -1, 0, project["healthy"], project["healthy"] + 0.001, project["stale"], project["stale"] + 0.001, 10 ** 6):
            self.assertEqual(telemetry.classify_age(age, console), thresholds.classify_age(age, project), age)
        payload = {"healthy_max": 30, "stale_max": 45}
        self.assertEqual(telemetry.load_thresholds(REPO_ROOT / thresholds.TOPOLOGY_CONFIG_FILE, payload),
                         thresholds.load_thresholds(payload)["freshness"])

    def test_soak_collector_freshness_follows_the_overview_rule(self):
        policy = current_policy()
        now = timezone.now()
        started = now - timedelta(hours=3)
        base = {"id": 1, "state": "RUNNING", "result": "", "terminal_reason": "", "baseline": "{}", "started_by": "x", "bundle_id": "B",
                "policy": '{"sample_interval_seconds": %d}' % policy.sample_interval_seconds, "started_at": started.isoformat(),
                "required_end_at": (started + timedelta(days=7)).isoformat(), "finished_at": ""}
        for seconds in (1, policy.sample_interval_seconds, 2 * policy.sample_interval_seconds - 5, 2 * policy.sample_interval_seconds + 5, 86400):
            sampled = now - timedelta(seconds=seconds)
            latest = {"bucket": 0, "sampled_at": sampled.isoformat(), "result": "PASS", "integrity_ok": 1, "interference": 0, "expected_state_result": "PASS",
                      "device_health": "HEALTHY", "telemetry_freshness": "FRESH", "monitoring_state": "OK", "config_drift": 0, "evidence": "{}"}
            expected = overview.collector_status(SimpleNamespace(started_at=started), SimpleNamespace(sampled_at=sampled), policy, now)["state"]
            self.assertEqual(automation_db.describe_soak(base, latest, {"PASS": 1}, None, now=now)["collector"]["state"], expected, seconds)
        for age in (10, 2 * policy.sample_interval_seconds + 5):
            begun = now - timedelta(seconds=age)
            fresh = dict(base, started_at=begun.isoformat(), required_end_at=(begun + timedelta(days=7)).isoformat())
            expected = overview.collector_status(SimpleNamespace(started_at=begun), None, policy, now)["state"]
            self.assertEqual(automation_db.describe_soak(fresh, None, {}, None, now=now)["collector"]["state"], expected, age)
        self.assertEqual((automation_db.FRESH, automation_db.STALE, automation_db.NO_SAMPLE), (overview.FRESH, overview.STALE, overview.NO_SAMPLE))

    def test_the_console_is_not_a_django_application(self):
        from django.conf import settings

        self.assertFalse([app for app in settings.INSTALLED_APPS if "challenge_console" in app])
        self.assertFalse((REPO_ROOT / "web" / "challenge_console").exists())
        from core import urls

        self.assertFalse([pattern for pattern in urls.urlpatterns if "console" in str(pattern.pattern)])


def load_tests(loader, standard_tests, pattern):
    """Add the console's own (Django-free) test-suite to this module, so the full project gate runs it."""
    suite = unittest.TestSuite()
    suite.addTests(standard_tests)
    suite.addTests(unittest.defaultTestLoader.discover(str(REPO_ROOT / "challenge_console" / "tests"), pattern="test_*.py",
                                                       top_level_dir=str(REPO_ROOT)))
    return suite
