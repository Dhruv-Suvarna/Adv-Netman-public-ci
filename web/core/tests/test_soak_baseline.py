"""V2 Phase 5C -- the probation start-time baseline, configuration drift and the exact seven-day policy.

A CONTROLLED CLOCK and a simulated network (``helpers.soak``): no real time passes and no device is read.  Simulated clock advancement
exists ONLY here; nothing in the production code can shorten or skip the real window.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import timedelta
from unittest import mock

from django.test import SimpleTestCase, TestCase, override_settings

from core import models
from core.services import bundle_service as bs, soak_service as ss
from core.services.health import live
from core.services.health.evidence import DeviceEvidence
from core.services.soak import baseline as baseline_module, config_state, evaluator
from core.tests.helpers import health as h, soak as sh

R1_CONFIG = "hostname R1\ninterface Ethernet1\n   ip address 192.0.2.0/31\nusername admin secret sha512 $6$abcdefSECRETHASH\nend\n"
R2_CONFIG = "hostname R2\ninterface Ethernet1\n   ip address 192.0.2.1/31\nend\n"


@contextmanager
def configs(world: dict):
    """The allowlisted raw read returns ``world[device]["running_config"]``; a missing device / key is an unreadable device."""
    def read(device, raw_keys=(), *, session_factory=None, now=None):
        mine = world.get(device["name"])
        evidence = DeviceEvidence(device=device["name"], platform=device.get("platform", ""))
        if mine is None:
            return evidence, {}, {key: "CONNECTION_FAILED" for key in raw_keys}
        return evidence, {k: mine[k] for k in raw_keys if k in mine}, {k: "COMMAND_FAILED" for k in raw_keys if k not in mine}
    with mock.patch.object(live, "read_device_with_raw", side_effect=read) as patched:
        yield patched


def healthy():
    return {"R1": {"running_config": R1_CONFIG}, "R2": {"running_config": R2_CONFIG}}


def start(fixture, world, *, now=sh.T0):
    with configs(world), sh.simulated(fixture.world):
        return ss.start_soak(fixture.prob, actor="operator", now=now, snapshot=h.snapshot(now=now))


def tick(fixture, world, now):
    with configs(world):
        return sh.tick(now, fixture.world)


@override_settings(PROBATION_SOAK_REQUIRE_BASELINE_DIGEST=True)
class SevenDayPolicyTests(TestCase):
    def test_normal_policy_is_exactly_seven_days_and_due_is_start_plus_seven_days(self):
        policy = ss.current_policy()
        self.assertEqual((policy.duration_seconds, policy.is_production_duration), (7 * 24 * 60 * 60, True))
        fixture = sh.probation()
        result = start(fixture, healthy())
        run = result.run
        self.assertIsNotNone(run, result.blockers)
        self.assertEqual(run.required_end_at - run.started_at, timedelta(days=7))
        self.assertEqual(run.required_end_at, sh.T0 + timedelta(days=7))
        self.assertEqual((run.baseline["policy"]["duration_days"], run.baseline["policy"]["is_production_duration"]), (7.0, True))
        self.assertEqual(run.baseline["window"], {"started_at": evaluator.iso(run.started_at), "required_end_at": evaluator.iso(run.required_end_at)})

    def test_no_request_or_setting_can_shorten_the_production_window(self):
        from django.conf import settings
        self.assertGreaterEqual(settings.PROBATION_SOAK_DURATION_SECONDS, settings.SOAK_PRODUCTION_DURATION_SECONDS)
        self.assertEqual(settings.SOAK_PRODUCTION_DURATION_SECONDS, 604800)
        import inspect
        self.assertNotIn("duration", inspect.signature(ss.start_soak).parameters)
        self.assertNotIn("required_end_at", inspect.signature(ss.start_soak).parameters)

    def test_a_seven_day_soak_is_not_eligible_one_second_early_and_is_never_promoted_automatically(self):
        fixture = sh.probation()
        run = start(fixture, healthy()).run
        early = sh.T0 + timedelta(days=7) - timedelta(seconds=1)
        self.assertEqual(ss.progress(run, now=early)["verdict"].state, models.SoakState.RUNNING)
        self.assertEqual(ss.progress(run, now=early)["remaining_seconds"], 1)
        tick(fixture, healthy(), sh.T0 + timedelta(hours=1))
        run.refresh_from_db()
        self.assertEqual((run.state, run.result), (models.SoakState.RUNNING, ""))
        self.assertEqual((models.GoldenDecision.objects.count(), models.ConfigurationBundle.objects.filter(kind="GOLDEN").count()), (0, 0))
        self.assertEqual(bs.check_golden_eligibility(fixture.prob, run).eligible, False)


@override_settings(PROBATION_SOAK_REQUIRE_BASELINE_DIGEST=True)
class BaselineTests(TestCase):
    def test_baseline_pins_configuration_digests_and_references(self):
        fixture = sh.probation()
        run = start(fixture, healthy()).run
        base, bundle = run.baseline, fixture.prob
        self.assertEqual(sorted(base["devices"]), ["R1", "R2"])
        for row in base["devices"].values():
            self.assertEqual((row["state"], len(row["digest"]), sorted(row["sections"])), ("OK", 64, ["running-config"]))
        self.assertNotEqual(base["devices"]["R1"]["digest"], base["devices"]["R2"]["digest"])
        self.assertEqual(base["probation"], {"bundle_id": bundle.bundle_id, "bundle_digest": bundle.bundle_digest, "payload_digest": bundle.payload_digest,
                                             "root_bundle_id": fixture.uat.bundle_id, "root_kind": "UAT"})
        self.assertEqual(base["change"]["change_id"], bundle.change.change_id)
        evidence = base["evidence"]
        self.assertEqual(evidence["validation"]["run_id"], str(bundle.validation_run.run_id))
        self.assertEqual((evidence["execution"]["run_id"], evidence["execution"]["mode"]), (str(bundle.execution_run.run_id), "PARTIAL_UAT"))
        self.assertEqual((evidence["postcheck"]["run_id"], evidence["postcheck"]["result"]), (str(bundle.postcheck_run.run_id), bundle.postcheck_run.status))
        self.assertEqual((base["health"]["sample_result"], base["health"]["expected_state"]), ("PASS", "PASS"))
        self.assertEqual((base["topology"]["available"], base["topology"]["backend_status"]), (True, "OK"))
        self.assertEqual(base["configuration"]["change"]["source"], "NOT_RECORDED")       # honest: this lineage recorded no pre-change digest
        self.assertEqual((base["collector"]["scheduler_unit"], base["collector"]["status_at_start"]), ("nmas-probation-soak-tick.timer", "NO_SAMPLE_YET"))
        self.assertEqual(len(base["deployment"]["repository_head"]) in (0, 40), True)
        self.assertEqual(base["started_by"], "operator")

    def test_baseline_stores_digests_never_configuration_text_or_secrets(self):
        fixture = sh.probation()
        run = start(fixture, healthy()).run
        blob = repr(run.baseline)
        for needle in ("hostname R1", "192.0.2.0/31", "SECRETHASH", "secret sha512", "username admin"):
            self.assertNotIn(needle, blob)

    def test_baseline_digest_reproduces_and_the_baseline_is_immutable(self):
        fixture = sh.probation()
        run = start(fixture, healthy()).run
        self.assertEqual(run.baseline_digest, baseline_module.digest(run.baseline))
        fresh = models.ProbationSoakRun.objects.get(pk=run.pk)
        fresh.baseline = {**fresh.baseline, "devices": {}}
        with self.assertRaises(ValueError):
            fresh.save()
        fresh = models.ProbationSoakRun.objects.get(pk=run.pk)
        fresh.baseline_digest = "0" * 64
        with self.assertRaises(ValueError):
            fresh.save()

    def test_a_soak_does_not_start_without_a_real_baseline_digest(self):
        fixture = sh.probation()
        world = healthy()
        del world["R2"]                                   # R2 cannot be read
        result = start(fixture, world)
        self.assertIsNone(result.run)
        self.assertEqual([b["code"] for b in result.blockers], ["BASELINE_UNREADABLE"])
        self.assertEqual(sorted(result.blockers[0]["details"]["devices"]), ["R2"])
        self.assertEqual(models.ProbationSoakRun.objects.count(), 0)
        empty = healthy(); empty["R1"]["running_config"] = "   \n"      # an empty running-config is not a configuration
        self.assertEqual([b["code"] for b in start(fixture, empty).blockers], ["BASELINE_UNREADABLE"])

    def test_nothing_is_read_for_a_soak_that_cannot_start(self):
        fixture = sh.probation()
        with configs(healthy()) as reads:
            self.assertEqual(ss.start_soak(fixture.uat, actor="operator").blockers[0]["code"], "NOT_PROBATION")
        reads.assert_not_called()

    def test_start_is_idempotent_and_does_not_recapture(self):
        fixture = sh.probation()
        first = start(fixture, healthy()).run
        changed = healthy(); changed["R1"]["running_config"] += "ntp server 192.0.2.9\n"
        again = start(fixture, changed)
        self.assertEqual((again.run.pk, again.created), (first.pk, False))
        self.assertEqual(again.run.baseline_digest, first.baseline_digest)

    def test_provisioning_lineage_records_the_pre_and_post_change_digests(self):
        from core.services import provisioning_service as ps
        from core.tests.helpers import provisioning as p
        with override_settings(PROBATION_SOAK_REQUIRE_BASELINE_DIGEST=False):
            lab = p.Lab()
            lab.through("sync")
            self.assertTrue(ps.start_probation(lab.run, actor="approver").ok)
        change = lab.run.soak_run.baseline["configuration"]["change"]
        self.assertEqual((change["source"], change["prov_id"]), ("PROVISIONING_RUN", lab.run.prov_id))
        self.assertEqual((change["pre_change"], change["post_change"]), (lab.run.pre_config_digest, lab.run.post_config_digest))
        self.assertEqual(lab.run.soak_run.baseline["probation"]["root_kind"], "DEPLOYED")
        self.assertEqual(lab.run.soak_run.baseline["change"]["provisioning"], lab.run.prov_id)


@override_settings(PROBATION_SOAK_REQUIRE_BASELINE_DIGEST=True)
class ConfigurationDriftTests(TestCase):
    def test_unchanged_configuration_matches_the_baseline(self):
        fixture = sh.probation()
        run = start(fixture, healthy()).run
        tick(fixture, healthy(), sh.T0 + timedelta(minutes=1))
        sample = run.samples.get()
        self.assertEqual((sample.result, sample.config_drift), (models.SoakSampleResult.PASS, False))
        self.assertEqual({name: row["state"] for name, row in sample.evidence["config"].items()}, {"R1": "MATCH", "R2": "MATCH"})

    def test_drift_invalidates_the_soak_and_never_resets_its_clock(self):
        fixture = sh.probation()
        run = start(fixture, healthy()).run
        tick(fixture, healthy(), sh.T0 + timedelta(minutes=1))
        drifted = healthy(); drifted["R1"]["running_config"] += "ip route 203.0.113.0/24 192.0.2.1\n"
        tick(fixture, drifted, sh.T0 + timedelta(minutes=16))
        run.refresh_from_db()
        self.assertEqual((run.state, run.result, run.terminal_reason), (models.SoakState.INVALIDATED, "", "CONFIGURATION_DRIFT"))
        sample = run.samples.order_by("-bucket").first()
        self.assertEqual((sample.result, sample.config_drift), (models.SoakSampleResult.INVALIDATED, True))
        self.assertEqual(sample.evidence["config"]["R1"]["state"], "DRIFT")
        self.assertEqual(sample.evidence["config"]["R1"]["changed_sections"], ["running-config"])
        self.assertEqual(sample.evidence["config"]["R2"]["state"], "MATCH")
        self.assertEqual((sample.findings[0]["check_code"], sample.findings[0]["device"]), ("CONFIGURATION_DRIFT", "R1"))
        self.assertNotIn("203.0.113.0", repr(sample.evidence) + repr(sample.findings))           # digests only
        self.assertEqual((run.started_at, run.required_end_at), (sh.T0, sh.T0 + timedelta(days=7)))   # the clock was not reset
        self.assertFalse(bs.check_golden_eligibility(fixture.prob, run).eligible)                  # can never become Golden
        self.assertTrue(models.AuditEvent.objects.filter(event_type=models.AuditEventType.PROBATION_SOAK_INVALIDATED).exists())

    def test_restoring_the_configuration_does_not_revive_an_invalidated_soak(self):
        fixture = sh.probation()
        run = start(fixture, healthy()).run
        drifted = healthy(); drifted["R2"]["running_config"] += "ntp server 192.0.2.9\n"
        tick(fixture, drifted, sh.T0 + timedelta(minutes=1))
        tick(fixture, healthy(), sh.T0 + timedelta(minutes=16))
        run.refresh_from_db()
        self.assertEqual((run.state, run.samples.count()), (models.SoakState.INVALIDATED, 1))
        again = start(fixture, healthy(), now=sh.T0 + timedelta(hours=1))                           # a retry is a NEW run with a NEW clock
        self.assertNotEqual(again.run.pk, run.pk)
        self.assertEqual(again.run.started_at, sh.T0 + timedelta(hours=1))

    def test_an_unreadable_configuration_is_missing_evidence_never_a_pass_or_a_drift(self):
        fixture = sh.probation()
        run = start(fixture, healthy()).run
        world = healthy(); del world["R1"]
        tick(fixture, world, sh.T0 + timedelta(minutes=1))
        run.refresh_from_db()
        sample = run.samples.get()
        self.assertEqual((sample.result, sample.config_drift, run.state), (models.SoakSampleResult.INCOMPLETE, False, models.SoakState.RUNNING))
        self.assertEqual(sample.evidence["config"]["R1"]["state"], "UNAVAILABLE")
        self.assertIn("CONFIG_READ_UNAVAILABLE", [f["check_code"] for f in sample.findings])
        tick(fixture, healthy(), sh.T0 + timedelta(minutes=16))                                     # evidence returns: the soak recovers
        self.assertEqual(run.samples.order_by("-bucket").first().result, models.SoakSampleResult.PASS)

    def test_health_degradation_still_fails_and_is_distinct_from_drift(self):
        fixture = sh.probation()
        run = start(fixture, healthy()).run
        fixture.world.state["R1"] = {"interfaces": {}, "addresses": {}, "routes": []}                # the intended state is gone
        tick(fixture, healthy(), sh.T0 + timedelta(minutes=1))
        run.refresh_from_db()
        self.assertEqual((run.state, run.result, run.terminal_reason), (models.SoakState.COMPLETED, models.SoakResult.FAIL, "EXPECTED_STATE_FAILED"))

    def test_stale_monitoring_evidence_is_incomplete_not_a_pass(self):
        fixture = sh.probation()
        run = start(fixture, healthy()).run
        with configs(healthy()):
            sh.tick(sh.T0 + timedelta(minutes=1), fixture.world, ages={"R1": 9999})
        sample = run.samples.get()
        self.assertEqual(sample.result, models.SoakSampleResult.INCOMPLETE)
        self.assertNotEqual(sample.telemetry_freshness, "FRESH")

    @sh.short_soak()
    def test_simulated_full_window_becomes_eligible_only_at_the_end_and_is_not_promoted(self):
        fixture = sh.probation()
        run = start(fixture, healthy()).run
        with configs(healthy()):
            sh.drive(fixture.world, start=sh.T0, until=sh.END - timedelta(seconds=1))
        run.refresh_from_db()
        self.assertEqual(run.state, models.SoakState.RUNNING)                                        # one second early: still running
        with configs(healthy()):
            sh.drive(fixture.world, start=sh.END, until=sh.END + timedelta(seconds=sh.INTERVAL))
        run.refresh_from_db()
        self.assertEqual((run.state, run.result, run.terminal_reason), (models.SoakState.COMPLETED, models.SoakResult.PASS, "TECHNICAL_PASS"))
        self.assertTrue(all(s.evidence["config"]["R1"]["state"] == "MATCH" for s in run.samples.all()))
        self.assertEqual(ss.verify_run(run), [])                                                     # the stored verdict reproduces from its own rows
        self.assertEqual((models.GoldenDecision.objects.count(), models.ConfigurationBundle.objects.filter(kind="GOLDEN").count()), (0, 0))


class ConfigStateTests(SimpleTestCase):
    def test_volatile_fields_do_not_look_like_drift(self):
        a = config_state._normalize("nft", "table ip nat {\n counter packets 10 bytes 840 masquerade\n}")
        b = config_state._normalize("nft", "table ip nat {\n counter packets 99 bytes 9999 masquerade\n}")
        self.assertEqual(a, b)
        one = '[{"ifname":"eth1","ifindex":7,"operstate":"UP","addr_info":[{"local":"10.0.0.1","prefixlen":24,"scope":"global","valid_life_time":100},{"local":"fe80::1","prefixlen":64,"scope":"link"}]}]'
        two = '[{"ifname":"eth1","ifindex":9,"operstate":"UNKNOWN","addr_info":[{"local":"10.0.0.1","prefixlen":24,"scope":"global","valid_life_time":42}]}]'
        self.assertEqual(config_state._normalize("addr", one), config_state._normalize("addr", two))
        three = two.replace("10.0.0.1", "10.0.0.2")
        self.assertNotEqual(config_state._normalize("addr", one), config_state._normalize("addr", three))

    def test_compare_semantics(self):
        pinned = {"R1": {"digest": "a" * 64, "sections": {"running-config": "1"}}, "R2": {"digest": "", "sections": {}}}
        same = {"R1": {"state": "OK", "digest": "a" * 64, "sections": {"running-config": "1"}}}
        self.assertEqual(config_state.compare(pinned, same)["R1"]["state"], "MATCH")
        self.assertNotIn("R2", config_state.compare(pinned, same))                 # nothing was pinned for R2: nothing is claimed
        other = {"R1": {"state": "OK", "digest": "b" * 64, "sections": {"running-config": "2"}}}
        self.assertEqual((config_state.compare(pinned, other)["R1"]["state"], config_state.compare(pinned, other)["R1"]["changed_sections"]),
                         ("DRIFT", ["running-config"]))
        self.assertEqual(config_state.compare(pinned, {})["R1"]["state"], "UNAVAILABLE")

    def test_a_drift_marker_never_changes_a_pre_existing_samples_digest(self):
        import hashlib
        from core.services.validation.findings import canonical_json
        fact = evaluator.SampleFacts(bucket=0, sampled_at=sh.T0, result="PASS", integrity_ok=True, interference=False, terminal_failure=False,
                                     resource_critical=(), expected_state_result="PASS", telemetry_freshness="FRESH", warnings=0)
        legacy_rows = [[0, evaluator.iso(sh.T0), "PASS", "PASS", "FRESH", True, False, False]]
        legacy = hashlib.sha256(canonical_json({"domain": "clab.soak.samples", "schema": evaluator.EVIDENCE_SCHEMA_VERSION, "value": legacy_rows}).encode("ascii")).hexdigest()
        self.assertEqual(evaluator.samples_digest([fact]), legacy)
        import dataclasses
        self.assertNotEqual(evaluator.samples_digest([dataclasses.replace(fact, config_drift=True)]), legacy)

    def test_soak_package_never_shells_out_for_the_repository_head(self):
        from pathlib import Path
        source = Path(baseline_module.__file__).read_text() + Path(config_state.__file__).read_text()
        self.assertNotIn("subprocess", source)
        self.assertIn(len(baseline_module.repository_head()), (0, 40))


@override_settings(PROBATION_SOAK_REQUIRE_BASELINE_DIGEST=True)
class OverviewTests(TestCase):
    def _page(self):
        from django.urls import reverse
        return self.client.get(reverse("core:probation_overview"))

    def test_empty_overview_states_the_seven_day_policy_and_no_golden(self):
        page = self._page()
        self.assertContains(page, "7 days")
        self.assertContains(page, "No valid Golden bundle exists.")
        self.assertContains(page, "No candidate is in probation.")
        self.assertNotContains(page, "30 minutes")
        self.assertNotContains(page, "30-minute")

    def test_active_candidate_shows_window_digests_collector_and_is_never_called_golden(self):
        fixture = sh.probation()
        run = start(fixture, healthy()).run
        now = sh.T0 + timedelta(hours=1)
        described = ss.describe(run, now=now)
        self.assertEqual((described["policy_days"], described["elapsed_seconds"], described["remaining_seconds"]), (7.0, 3600, 7 * 86400 - 3600))
        self.assertEqual(described["due_at"], sh.T0 + timedelta(days=7))
        self.assertEqual(described["eligibility"]["code"], "IN_PROBATION")
        self.assertEqual(described["collector"]["state"], "STALE")                 # an hour without a sample: said plainly, not assumed
        self.assertEqual([d["drift_state"] for d in described["devices"]], ["NOT_SAMPLED", "NOT_SAMPLED"])
        tick(fixture, healthy(), now)
        described = ss.describe(run, now=now + timedelta(minutes=1))
        self.assertEqual((described["collector"]["state"], described["health"]["sample_result"]), ("FRESH", "PASS"))
        self.assertEqual([d["drift_state"] for d in described["devices"]], ["MATCH", "MATCH"])
        self.assertEqual(described["devices"][0]["baseline_digest"], run.baseline["devices"]["R1"]["digest"])
        page = self._page()
        for text in (run.soak_id, "IN PROBATION", run.baseline["devices"]["R1"]["digest"], run.baseline_digest, "Not eligible for Golden before the full policy period"):
            self.assertContains(page, text)
        self.assertContains(page, "No valid Golden bundle exists.")                # in probation is not Golden

    def test_fresh_soak_without_a_sample_is_no_sample_not_stale(self):
        fixture = sh.probation()
        run = start(fixture, healthy()).run
        self.assertEqual(ss.describe(run, now=sh.T0 + timedelta(minutes=2))["collector"]["state"], "NO_SAMPLE")

    def test_drift_and_degraded_samples_are_listed_as_events(self):
        fixture = sh.probation()
        run = start(fixture, healthy()).run
        world = healthy(); del world["R1"]
        tick(fixture, world, sh.T0 + timedelta(minutes=1))
        events = ss.describe(run, now=sh.T0 + timedelta(minutes=2))["events"]
        self.assertEqual((events[0]["result"], "CONFIG_READ_UNAVAILABLE" in events[0]["codes"]), ("INCOMPLETE", True))
        drifted = healthy(); drifted["R1"]["running_config"] += "ntp server 192.0.2.9\n"
        tick(fixture, drifted, sh.T0 + timedelta(minutes=16))
        overview = ss.overview(now=sh.T0 + timedelta(minutes=17))
        self.assertEqual(overview["active"], [])
        self.assertEqual([(r.state, r.terminal_reason) for r in overview["finished"]], [("INVALIDATED", "CONFIGURATION_DRIFT")])
        self.assertContains(self._page(), "CONFIGURATION_DRIFT")

    @sh.short_soak()
    def test_passed_soak_is_eligible_for_a_decision_and_still_not_golden(self):
        fixture = sh.probation()
        run = start(fixture, healthy()).run
        with configs(healthy()):
            sh.drive(fixture.world, start=sh.T0, until=sh.END + timedelta(seconds=sh.INTERVAL))
        overview = ss.overview(now=sh.END + timedelta(seconds=sh.INTERVAL + 1))
        self.assertEqual([p["eligibility"]["code"] for p in overview["awaiting_decision"]], ["ELIGIBLE_DECISION_REQUIRED"])
        self.assertFalse(overview["golden"].valid)
        page = self._page()
        self.assertContains(page, "operator decision required")
        self.assertContains(page, "not Golden")


class SchedulerCommandTests(TestCase):
    """The unit the timer starts is ``manage.py probation_soak_tick``: it must start cleanly with nothing to do and sample what is due."""

    def test_tick_command_with_no_soak_and_as_a_dry_run(self):
        from io import StringIO
        from django.core.management import call_command
        out = StringIO()
        call_command("probation_soak_tick", "--dry-run", stdout=out)
        self.assertIn("dry run", out.getvalue())
        self.assertIn("0 running soak(s)", out.getvalue())
        out = StringIO()
        call_command("probation_soak_tick", stdout=out)
        self.assertIn("0 running soak(s)", out.getvalue())
        self.assertEqual(models.ProbationSoakSample.objects.count(), 0)

    @override_settings(PROBATION_SOAK_REQUIRE_BASELINE_DIGEST=True)
    def test_repeated_ticks_take_one_sample_per_interval(self):
        fixture = sh.probation()
        run = start(fixture, healthy()).run
        for seconds in (60, 120, 300, 600, 840):          # five timer firings inside ONE 900-second interval
            tick(fixture, healthy(), sh.T0 + timedelta(seconds=seconds))
        self.assertEqual(run.samples.count(), 1)
        tick(fixture, healthy(), sh.T0 + timedelta(seconds=905))
        self.assertEqual(run.samples.count(), 2)
