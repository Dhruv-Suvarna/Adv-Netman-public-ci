"""Automation transport: read-only SQLite access, the soak picture, busy / missing database, and the absence of any write path."""

from __future__ import annotations

import inspect
import json
import re
import sqlite3
from datetime import datetime, timedelta, timezone

from challenge_console import models as m
from challenge_console.adapters import automation_db
from challenge_console.collectors import AutomationCollector
from challenge_console.supervisor import CollectorError

from .helpers import ConsoleTestCase

SCHEMA = """
CREATE TABLE core_change (id INTEGER PRIMARY KEY, change_id TEXT, title TEXT, category TEXT, execution_mode TEXT, lifecycle_state TEXT,
    validation_state TEXT, created_by TEXT, created_at TEXT, updated_at TEXT);
CREATE TABLE core_changeexecutionrun (id INTEGER PRIMARY KEY, run_id TEXT, mode TEXT, state TEXT, outcome TEXT, actor TEXT, devices TEXT,
    started_at TEXT, finished_at TEXT, precheck_run_id INTEGER, postcheck_run_id INTEGER, change_id INTEGER, report TEXT);
CREATE TABLE core_changevalidationrun (id INTEGER PRIMARY KEY, run_id TEXT, status TEXT, created_by TEXT, created_at TEXT, change_id INTEGER);
CREATE TABLE core_networkconfigvalidationrun (id INTEGER PRIMARY KEY, run_id TEXT, operation_type TEXT, status TEXT, device TEXT, platform TEXT,
    created_at TEXT, change_id INTEGER);
CREATE TABLE core_operationalcheckrun (id INTEGER PRIMARY KEY, run_id TEXT, mode TEXT, status TEXT, device TEXT, started_at TEXT, finished_at TEXT,
    change_id INTEGER);
CREATE TABLE core_configurationbundle (id INTEGER PRIMARY KEY, bundle_id TEXT, kind TEXT, provenance TEXT, parent_id INTEGER, change_id INTEGER,
    created_by TEXT, created_at TEXT, manifest TEXT);
CREATE TABLE core_trafficrun (id INTEGER PRIMARY KEY, run_id TEXT, operator TEXT, source TEXT, destination TEXT, address_family TEXT, family TEXT,
    protocol TEXT, status TEXT, failure_reason TEXT, started_at TEXT, finished_at TEXT, raw_output TEXT);
CREATE TABLE core_provisioningrun (id INTEGER PRIMARY KEY, device_name TEXT, platform TEXT, role TEXT, status TEXT, bootstrap_state TEXT,
    requested_by TEXT, created_at TEXT, updated_at TEXT, finished_at TEXT);
CREATE TABLE core_devicecredential (id INTEGER PRIMARY KEY, device_name TEXT, username TEXT, account_kind TEXT, secret_ref TEXT, ssh_key_ref TEXT,
    ssh_public_key TEXT, rotation_enabled INTEGER, rotation_interval_days INTEGER, last_rotated_at TEXT, next_due_at TEXT, last_status TEXT);
CREATE TABLE core_credentialrotationrun (id INTEGER PRIMARY KEY, run_id TEXT, trigger_reason TEXT, phase TEXT, final_status TEXT, error_category TEXT,
    started_at TEXT, completed_at TEXT, credential_id INTEGER, prior_secret_version TEXT, new_secret_version TEXT);
CREATE TABLE core_probationsoakrun (id INTEGER PRIMARY KEY, state TEXT, result TEXT, terminal_reason TEXT, policy TEXT, started_at TEXT,
    required_end_at TEXT, finished_at TEXT, started_by TEXT, baseline TEXT, bundle_id INTEGER);
CREATE TABLE core_probationsoaksample (id INTEGER PRIMARY KEY, run_id INTEGER, bucket INTEGER, sampled_at TEXT, result TEXT, integrity_ok INTEGER,
    interference INTEGER, expected_state_result TEXT, device_health TEXT, telemetry_freshness TEXT, monitoring_state TEXT, config_drift INTEGER,
    evidence TEXT);
CREATE TABLE core_goldendecision (id INTEGER PRIMARY KEY, decision TEXT, decided_by TEXT, decided_at TEXT, run_id INTEGER);
"""
START = datetime(2026, 10, 6, 10, 56, 22, 446525, tzinfo=timezone.utc)
DIGEST = "9cd6f5a17cf1374ce6c60b6b08f63784923b087b6db6466fd9130c6338fbc0bb"


def db_time(moment):
    return moment.strftime("%Y-%m-%d %H:%M:%S.%f")                       # how Django stores a datetime in SQLite: naive UTC


def build(path, *, soak_state="RUNNING", soak_result="", samples=1, finished=None, drift=False):
    db = sqlite3.connect(path)
    db.executescript(SCHEMA)
    db.executemany("INSERT INTO core_change VALUES (?,?,?,?,?,?,?,?,?,?)", [
        (3, "CHG-20261006-0001", "R1_SOAK_TEST", "CONFIGURATION_CHANGE", "COMPLETE", "DRAFT", "PENDING", "dhruv", db_time(START), db_time(START)),
        (4, "CHG-20261006-0002", "Phase 5 soak: R1 Loopback105", "CONFIGURATION_CHANGE", "COMPLETE", "DRAFT", "PENDING", "dhruv", db_time(START), db_time(START))])
    db.executemany("INSERT INTO core_changeexecutionrun VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", [
        (1, "c0d5bd3c", "COMPLETE", "FINISHED", "BLOCKED", "dhruv", '["R1"]', db_time(START), db_time(START), 2, None, 3, "secret report body"),
        (2, "d666f36e", "COMPLETE", "FINISHED", "SUCCEEDED", "dhruv", '["R1"]', db_time(START), db_time(START), 3, 4, 4, "secret report body"),
        (3, "aaaa0000", "COMPLETE", "RUNNING", "", "dhruv", '["R2"]', db_time(START), None, 5, None, 4, "")])
    db.execute("INSERT INTO core_changevalidationrun VALUES (1,'f92ead2c','PASS','dhruv',?,4)", (db_time(START),))
    db.execute("INSERT INTO core_networkconfigvalidationrun VALUES (1,'58a46ff2','CHANGE','PASS','R1','ceos',?,4)", (db_time(START),))
    db.executemany("INSERT INTO core_operationalcheckrun VALUES (?,?,?,?,?,?,?,?)", [
        (3, "a6c26afa", "CHANGE_PRECHECK", "PASS", "", db_time(START), db_time(START), 4),
        (4, "c3714049", "CHANGE_POSTCHECK", "PASS", "", db_time(START), db_time(START), 4),
        (5, "0367b5d1", "CHANGE_PRECHECK", "INCOMPLETE", "", db_time(START), db_time(START), 3)])
    db.executemany("INSERT INTO core_configurationbundle VALUES (?,?,?,?,?,?,?,?,?)", [
        (1, "BND-DEP-000001", "DEPLOYED", "EXECUTION_LINEAGE", None, 4, "dhruv", db_time(START), "manifest-with-config"),
        (2, "BND-PROB-000001", "PROBATION", "EXECUTION_LINEAGE", 1, 4, "dhruv", db_time(START), "manifest-with-config")])
    db.executemany("INSERT INTO core_trafficrun VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", [
        (1, "39902e6f", "dhruv", "H1", "H2", "IPV4", "ICMP", "ICMP", "PASSED", "", db_time(START), db_time(START), "raw ping output"),
        (2, "bbbb1111", "dhruv", "H1", "H2", "IPV4", "TCP", "TCP", "FAILED", "CONNECTION_REFUSED", db_time(START), db_time(START), "")])
    db.execute("INSERT INTO core_devicecredential VALUES (26,'S4','nmas-automation','MACHINE','runtime://device-credentials/s4','runtime://key',"
               "'ssh-ed25519 AAAAC3Nza',1,30,?,?,'SUCCESS')", (db_time(START), db_time(START + timedelta(days=30))))
    db.execute("INSERT INTO core_devicecredential VALUES (27,'R1','admin','HUMAN','runtime://r1-secret','', '',0,0,NULL,NULL,'')")
    db.execute("INSERT INTO core_credentialrotationrun VALUES (1,'16175f32','SCHEDULED','COMPLETE','SUCCESS','',?,?,26,'v1-secret-version','v2-secret-version')",
               (db_time(START), db_time(START)))
    policy = {"duration_seconds": 604800, "sample_interval_seconds": 900, "max_gap_seconds": 7200, "min_coverage_percent": 90}
    baseline = {"probation": {"bundle_id": "BND-PROB-000001"}, "devices": {"R1": {"digest": DIGEST}}}
    db.execute("INSERT INTO core_probationsoakrun VALUES (1,?,?,?,?,?,?,?,?,?,2)", (
        soak_state, soak_result, "CONFIGURATION_DRIFT" if soak_state == "INVALIDATED" else "", json.dumps(policy), db_time(START),
        db_time(START + timedelta(days=7)), db_time(finished) if finished else None, "dhruv", json.dumps(baseline)))
    for bucket in range(samples):
        evidence = {"config": {"R1": {"state": "DRIFT" if drift else "MATCH", "baseline": DIGEST, "current": "ffff" * 16 if drift else DIGEST,
                                      "changed_sections": ["interface Loopback105"] if drift else []}}}
        db.execute("INSERT INTO core_probationsoaksample VALUES (?,1,?,?,?,1,0,'PASS','HEALTHY','FRESH','OK',?,?)", (
            bucket + 1, bucket, db_time(START + timedelta(seconds=96 + 900 * bucket)), "INVALIDATED" if drift else "PASS", int(drift), json.dumps(evidence)))
    db.commit()
    db.close()


class DatabaseTestCase(ConsoleTestCase):
    def setUp(self):
        super().setUp()
        self.path = self.tmp / "db.sqlite3"
        self.config = self.config.with_overrides(automation_db_path=self.path)
        self.now = START + timedelta(minutes=14)

    def read(self, **kwargs):
        return automation_db.read_snapshot(self.path, now=kwargs.pop("now", self.now), **kwargs)


class SnapshotTests(DatabaseTestCase):
    def test_current_soak_representation(self):
        build(self.path)
        soak = self.read()["soaks"][0]
        self.assertEqual((soak["soak_id"], soak["bundle_id"], soak["root_bundle"], soak["change_id"], soak["devices"], soak["state"]),
                         ("SOAK-000001", "BND-PROB-000001", "BND-DEP-000001", "CHG-20261006-0002", ["R1"], "RUNNING"))
        self.assertEqual((soak["started_at"], soak["due_at"]), ("2026-10-06T10:56:22.446Z", "2026-10-13T10:56:22.446Z"))
        self.assertAlmostEqual(soak["elapsed_seconds"], 840.0, delta=0.01)                          # timestamps are carried at millisecond precision
        self.assertAlmostEqual(soak["remaining_seconds"], 604800.0 - 840.0, delta=0.01)
        self.assertEqual(soak["duration_seconds"], 604800.0)
        self.assertEqual(soak["collector"]["state"], "FRESH")
        self.assertEqual(soak["collector"]["expected_every_seconds"], 900)
        self.assertEqual((soak["latest_sample"]["result"], soak["latest_sample"]["bucket"], soak["latest_sample"]["telemetry_freshness"]), ("PASS", 0, "FRESH"))
        self.assertEqual((soak["drift_state"], soak["drift"][0]["device"], soak["drift"][0]["state"]), ("MATCH", "R1", "MATCH"))
        self.assertEqual((soak["health"], soak["samples"], soak["sample_counts"]), ("HEALTHY", 1, {"PASS": 1}))
        self.assertEqual(soak["eligibility"]["code"], "IN_PROBATION")

    def test_soak_state_is_read_not_assumed(self):
        build(self.path, soak_state="INVALIDATED", finished=START + timedelta(hours=2), samples=3, drift=True)
        soak = self.read(now=START + timedelta(hours=3))["soaks"][0]
        self.assertEqual((soak["state"], soak["terminal_reason"], soak["drift_state"]), ("INVALIDATED", "CONFIGURATION_DRIFT", "DRIFT"))
        self.assertEqual(soak["eligibility"]["code"], "NOT_ELIGIBLE")
        self.assertEqual(soak["elapsed_seconds"], 7200.0)                                            # frozen at the finish instant
        self.assertEqual(soak["drift"][0]["changed_sections"], ["interface Loopback105"])

    def test_collector_freshness_follows_the_project_rule(self):
        build(self.path, samples=0)
        self.assertEqual(self.read(now=START + timedelta(minutes=5))["soaks"][0]["collector"]["state"], "NO_SAMPLE")   # only just started
        self.assertEqual(self.read(now=START + timedelta(minutes=31))["soaks"][0]["collector"]["state"], "STALE")      # nothing after 2 intervals
        self.assertEqual(self.read()["soaks"][0]["drift"][0]["state"], "NOT_SAMPLED")
        self.path.unlink()
        build(self.path, samples=2)
        self.assertEqual(self.read(now=START + timedelta(minutes=40))["soaks"][0]["collector"]["state"], "FRESH")
        self.assertEqual(self.read(now=START + timedelta(minutes=50))["soaks"][0]["collector"]["state"], "STALE")      # > 2 x 900 s since the last

    def test_passed_soak_awaits_the_operator_then_shows_the_decision(self):
        build(self.path, soak_state="COMPLETED", soak_result="PASS", finished=START + timedelta(days=7), samples=2)
        later = START + timedelta(days=7, hours=1)
        soak = self.read(now=later)["soaks"][0]
        self.assertEqual((soak["eligibility"]["code"], soak["remaining_seconds"], soak["percent_elapsed"]), ("ELIGIBLE_DECISION_REQUIRED", 0.0, 100.0))
        db = sqlite3.connect(self.path)
        db.execute("INSERT INTO core_goldendecision VALUES (1,'APPROVE','dhruv',?,1)", (db_time(later),))
        db.commit()
        db.close()
        self.assertEqual(self.read(now=later)["soaks"][0]["eligibility"]["code"], "DECIDED_APPROVE")

    def test_running_completed_and_failed_items(self):
        build(self.path)
        snapshot = self.read()
        executions = {row["run_id"]: row for row in snapshot["executions"]}
        self.assertEqual([row["run_id"] for row in snapshot["executions"]], ["aaaa0000", "d666f36e", "c0d5bd3c"])       # newest first
        self.assertEqual((executions["aaaa0000"]["state"], executions["aaaa0000"]["finished_at"]), ("RUNNING", ""))     # active
        self.assertEqual((executions["d666f36e"]["outcome"], executions["d666f36e"]["change_id"]), ("SUCCEEDED", "CHG-20261006-0002"))
        self.assertEqual(executions["c0d5bd3c"]["outcome"], "BLOCKED")                                                  # failed
        self.assertEqual({(row["mode"], row["status"]) for row in snapshot["checks"]},
                         {("CHANGE_PRECHECK", "PASS"), ("CHANGE_POSTCHECK", "PASS"), ("CHANGE_PRECHECK", "INCOMPLETE")})
        self.assertEqual([(row["status"], row["failure_reason"]) for row in snapshot["traffic"]], [("FAILED", "CONNECTION_REFUSED"), ("PASSED", "")])
        self.assertEqual([(row["bundle_id"], row["kind"], row["parent"]) for row in snapshot["bundles"]],
                         [("BND-PROB-000001", "PROBATION", "BND-DEP-000001"), ("BND-DEP-000001", "DEPLOYED", None)])
        self.assertEqual(snapshot["validations"][0]["status"], "PASS")
        self.assertEqual((snapshot["rotation_runs"][0]["device_name"], snapshot["rotation_runs"][0]["final_status"]), ("S4", "SUCCESS"))
        self.assertEqual([row["device_name"] for row in snapshot["rotation_policy"]], ["S4"])
        self.assertIsNone(snapshot["golden"])
        self.assertEqual(snapshot["provisioning"], [])
        self.assertEqual(len(self.read(limit=1)["executions"]), 1)

    def test_no_secret_or_payload_column_is_ever_read(self):
        build(self.path)
        text = json.dumps(self.read())
        for forbidden in ("runtime://", "ssh-ed25519", "secret report body", "raw ping output", "manifest-with-config", "secret-version"):
            self.assertNotIn(forbidden, text)
        sql = " ".join(automation_db.QUERIES.values())
        for column in ("secret_ref", "ssh_key_ref", "ssh_public_key", "secret_version", "raw_output", "manifest", "report", "candidate_config",
                       "previous_state", "password"):
            self.assertNotIn(column, sql)
        self.assertNotIn("*", sql.replace("COUNT(*)", ""))                                           # every column is named


class ReadOnlyTests(DatabaseTestCase):
    def test_the_connection_cannot_write(self):
        build(self.path)
        before = self.path.read_bytes()
        connection = automation_db.connect(self.path)
        self.addCleanup(connection.close)
        for statement in ("UPDATE core_probationsoakrun SET state='COMPLETED'", "DELETE FROM core_change", "CREATE TABLE x (y)",
                          "INSERT INTO core_goldendecision VALUES (9,'APPROVE','x','x',1)", "PRAGMA journal_mode=WAL", "VACUUM"):
            with self.assertRaises(sqlite3.Error, msg=statement):
                connection.execute(statement)
                connection.commit()
        connection.close()
        self.read()
        self.assertEqual(self.path.read_bytes(), before)                                             # byte-identical after reads
        self.assertFalse(list(self.tmp.glob("db.sqlite3-*")))                                        # no journal / WAL side file created

    def test_each_read_only_layer_refuses_writes_on_its_own(self):
        build(self.path)
        before = self.path.read_bytes()
        connection = automation_db.connect(self.path)
        self.addCleanup(connection.close)
        self.assertEqual(connection.execute("PRAGMA query_only").fetchone()[0], 1)                   # layer 1: the pragma is on
        connection.execute("PRAGMA query_only = OFF")                                                # take layer 1 away ...
        for statement in ("UPDATE core_probationsoakrun SET state='COMPLETED'", "DELETE FROM core_change", "CREATE TABLE x (y)"):
            with self.assertRaises(sqlite3.OperationalError, msg=statement) as caught:               # ... layer 2 (URI mode=ro) still refuses
                connection.execute(statement)
                connection.commit()
            self.assertIn("readonly", str(caught.exception).lower())
        connection.close()
        self.assertEqual(self.path.read_bytes(), before)

    def test_no_write_statement_and_no_dynamic_sql_exist_in_the_transport(self):
        for name, sql in automation_db.QUERIES.items():
            self.assertTrue(sql.lstrip().upper().startswith("SELECT "), name)
            self.assertIsNone(re.search(r"\b(INSERT|UPDATE|DELETE|REPLACE|CREATE|DROP|ALTER|ATTACH|VACUUM|REINDEX)\b", sql, re.I), name)
        source = inspect.getsource(automation_db)
        self.assertIn("mode=ro", source)
        self.assertIn("PRAGMA query_only = ON", source)
        self.assertEqual(len(re.findall(r"\.execute\(", source)), 3)                                 # the pragma and the two fixed-query sites
        self.assertNotIn("executescript", source)
        self.assertNotIn("executemany", source)
        self.assertNotIn(".commit(", source)
        self.assertIsNone(re.search(r"^\s*(import|from)\s+django", source, re.M))
        self.assertFalse([name for name in dir(automation_db) if re.search(r"promot|approv|execut|rollback|provision|rotate|write|save|update|delete", name, re.I)])

    def test_missing_database_is_an_error_never_a_new_file(self):
        with self.assertRaises(automation_db.AutomationUnavailable) as caught:
            self.read()
        self.assertEqual(caught.exception.code, "DB_NOT_FOUND")
        self.assertFalse(self.path.exists())

    def test_locked_database_is_reported_busy_within_the_timeout(self):
        build(self.path)
        writer = sqlite3.connect(self.path, isolation_level=None)
        self.addCleanup(writer.close)
        writer.execute("BEGIN EXCLUSIVE")
        with self.assertRaises(automation_db.AutomationUnavailable) as caught:
            self.read(busy_timeout=0.1)
        self.assertEqual(caught.exception.code, "DB_BUSY")
        writer.execute("ROLLBACK")
        self.assertEqual(self.read()["soaks"][0]["soak_id"], "SOAK-000001")

    def test_schema_mismatch_is_classified_and_optional_sections_degrade_to_empty(self):
        build(self.path)
        db = sqlite3.connect(self.path)
        db.execute("DROP TABLE core_provisioningrun")
        db.commit()
        self.assertEqual(self.read()["provisioning"], [])
        db.execute("DROP TABLE core_changeexecutionrun")
        db.commit()
        db.close()
        with self.assertRaises(automation_db.AutomationUnavailable) as caught:
            self.read()
        self.assertEqual(caught.exception.code, "DB_SCHEMA_MISMATCH")


class CollectorTests(DatabaseTestCase):
    def test_snapshot_event_and_soak_change_event(self):
        build(self.path)
        collector = AutomationCollector(self.config, self.store, self.bus)
        collector.collect()
        document = self.store.document(m.AUTOMATION)
        self.assertTrue(document["available"])
        event = self.kinds("automation.snapshot")[0]
        self.assertEqual(event.data["soaks"][0]["soak_id"], "SOAK-000001")
        self.assertEqual(event.data["latest_execution"]["run_id"], "aaaa0000")
        db = sqlite3.connect(self.path)
        db.execute("UPDATE core_probationsoakrun SET state='CANCELLED'")                             # the website changed it; the console only notices
        db.commit()
        db.close()
        collector.collect()
        change = self.kinds("automation.soak_change")[0]
        self.assertEqual((change.target, change.data["from"][0], change.data["to"][0]), ("SOAK-000001", "RUNNING", "CANCELLED"))
        self.assertEqual(self.store.document(m.AUTOMATION)["data"]["soaks"][0]["state"], "CANCELLED")

    def test_busy_database_degrades_the_view_and_keeps_the_last_read(self):
        build(self.path)
        collector = AutomationCollector(self.config.with_overrides(db_busy_timeout=0.05), self.store, self.bus)
        collector.collect()
        writer = sqlite3.connect(self.path, isolation_level=None)
        self.addCleanup(writer.close)
        writer.execute("BEGIN EXCLUSIVE")
        with self.assertRaises(CollectorError) as caught:
            collector.collect()
        self.assertEqual((caught.exception.code, caught.exception.target), ("DB_BUSY", "automation-db"))
        document = self.store.document(m.AUTOMATION)
        self.assertEqual((document["available"], document["stale"], document["reason"]), (False, True, "DB_BUSY"))
        self.assertEqual(document["data"]["soaks"][0]["soak_id"], "SOAK-000001")
        writer.execute("ROLLBACK")
        collector.collect()
        self.assertTrue(self.store.document(m.AUTOMATION)["available"])

    def test_the_collector_has_no_control_surface(self):
        public = {name for name in dir(AutomationCollector) if not name.startswith("_")}
        self.assertEqual(public, {"name", "backoff_on_error", "stopping", "emit", "setup", "collect", "teardown"})
