"""Unattended incident intake: detection, debounce, link correlation, dedup/cooldown/budget, restart safety, dispatch."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from django.test import TestCase

from core import models
from core.services.troubleshooting import intake

T0 = datetime(2026, 11, 17, 9, 4, 14, tzinfo=timezone.utc)
INTENT = {"R2": {"Ethernet1": "up", "Ethernet2": "up"}, "S4": {"Ethernet3": "up"}}
PEERS = {("R2", "Ethernet1"): ("S4", "Ethernet3"), ("S4", "Ethernet3"): ("R2", "Ethernet1")}


def ob(dev, iface, link="connected", proto="up"):
    return intake.Observation(dev, iface, link, proto)


class World:
    def __init__(self):
        self.state = {"R2": {"Ethernet1": ("connected", "up"), "Ethernet2": ("connected", "up"), "Management0": ("disabled", "down")},
                      "S4": {"Ethernet3": ("connected", "up")}}
        self.unreadable: set[str] = set()

    def read(self, device, cfg):
        if device in self.unreadable:
            return None
        return [ob(device, i, *v) for i, v in self.state[device].items()]

    def shut_r2_e1(self):
        self.state["R2"]["Ethernet1"] = ("disabled", "down")
        self.state["S4"]["Ethernet3"] = ("notconnect", "down")

    def heal(self):
        self.state["R2"]["Ethernet1"] = ("connected", "up")
        self.state["S4"]["Ethernet3"] = ("connected", "up")


class IntakeTests(TestCase):
    def setUp(self):
        self.world = World()
        self.opened, self.dispatched, self.mail = [], [], []

        def open_handoff(actor, case, **kw):
            self.assertEqual((actor.name, actor.actor_type), ("nmas-intake", "system"))
            return SimpleNamespace(record_id="AIH-0123456789ab")

        self.deps = intake.IntakeDeps(run_case=lambda actor, cid, deps: self.opened.append(cid), open_handoff=open_handoff,
                                      dispatch=lambda hid: self.dispatched.append(hid) or True,
                                      notify=lambda s, b: self.mail.append(s))
        self.engine = self.make()

    def make(self):
        cfg = intake.IntakeConfig(devices=("R2", "S4"), confirm_seconds=30, cooldown_seconds=900, max_cases_per_hour=4)
        return intake.Intake(cfg=cfg, reader=self.world.read, intent=INTENT.get, deps=self.deps, _peers=PEERS)

    def test_healthy_network_opens_nothing_and_management_is_ignored(self):
        self.assertEqual(self.engine.poll(T0), [])
        self.assertEqual(models.TsCase.objects.count(), 0)

    def test_fault_is_confirmed_after_the_window_then_one_correlated_case_is_opened_and_dispatched(self):
        self.world.shut_r2_e1()
        self.assertEqual(self.engine.poll(T0), [])                                       # not yet confirmed
        out = self.engine.poll(T0 + timedelta(seconds=31))
        self.assertEqual(len(out), 1, out)                                                # both link ends -> ONE incident
        self.assertEqual(out[0]["fingerprint"], "LINK:R2:Ethernet1|S4:Ethernet3")
        case = models.TsCase.objects.get(case_id=out[0]["case"])
        self.assertEqual((case.trigger_source, case.trigger_ref, case.affected_scope["devices"]),
                         ("monitoring", "LINK:R2:Ethernet1|S4:Ethernet3", ["R2"]))          # scoped to the disabled side
        self.assertIn("R2 Ethernet1 link=disabled", case.symptom)
        self.assertEqual((self.opened, self.dispatched), ([case.case_id], ["AIH-0123456789ab"]))
        self.assertTrue(models.TsAuditEvent.objects.filter(case=case, action="INTAKE_DISPATCH").exists())

    def test_a_flap_shorter_than_the_window_is_not_an_incident(self):
        self.world.shut_r2_e1()
        self.engine.poll(T0)
        self.world.heal()
        self.engine.poll(T0 + timedelta(seconds=20))
        self.world.shut_r2_e1()
        self.assertEqual(self.engine.poll(T0 + timedelta(seconds=40)), [])                # window restarted
        self.assertEqual(models.TsCase.objects.count(), 0)

    def test_no_duplicate_case_while_open_even_after_a_restart(self):
        self.world.shut_r2_e1()
        self.engine.poll(T0)
        self.engine.poll(T0 + timedelta(seconds=31))
        restarted = self.make()                                                          # new process: in-memory state lost
        restarted.poll(T0 + timedelta(seconds=40))
        out = restarted.poll(T0 + timedelta(seconds=75))
        self.assertEqual(out, [{"fingerprint": "LINK:R2:Ethernet1|S4:Ethernet3", "skipped": "OPEN_CASE_EXISTS",
                                "category": "ADMIN_STATE_MISMATCH"}])
        self.assertEqual(models.TsCase.objects.count(), 1)
        self.assertEqual(len(self.dispatched), 1)

    def test_recurrence_inside_cooldown_goes_to_a_human_not_a_new_case(self):
        self.world.shut_r2_e1()
        self.engine.poll(T0)
        case_id = self.engine.poll(T0 + timedelta(seconds=31))[0]["case"]
        models.TsCase.objects.filter(case_id=case_id).update(state="RESOLVED_VERIFIED")
        self.engine.poll(T0 + timedelta(seconds=100))
        out = self.engine.poll(T0 + timedelta(seconds=140))
        self.assertEqual(out[0]["skipped"], "COOLDOWN_ACTIVE")
        self.engine.poll(T0 + timedelta(seconds=150))
        self.assertEqual(sum("COOLDOWN_ACTIVE" in s for s in self.mail), 1)               # notified once, not every pass
        self.assertEqual(models.TsCase.objects.count(), 1)

    def test_hourly_case_budget_bounds_automatic_cases(self):
        engine = self.make()
        engine.cfg.max_cases_per_hour = 0
        self.world.shut_r2_e1()
        engine.poll(T0)
        self.assertEqual(engine.poll(T0 + timedelta(seconds=31))[0]["skipped"], "HOURLY_CASE_BUDGET_EXHAUSTED")

    def test_replay_cases_do_not_consume_the_live_hourly_budget(self):
        engine = self.make()
        engine.cfg.max_cases_per_hour = 1
        models.TsCase.objects.create(case_id="TS-20261117-REPLAY01", tenant="default", trigger_source="monitoring",
                                     trigger_ref="REPLAY:LINK:R2:Ethernet1|S4:Ethernet3", opened_at=T0, idempotency_key="replay-1")
        self.world.shut_r2_e1()
        engine.poll(T0)
        self.assertIn("case", engine.poll(T0 + timedelta(seconds=31))[0])

    def test_unreadable_device_is_not_treated_as_healed(self):
        self.world.shut_r2_e1()
        self.engine.poll(T0)
        self.world.unreadable = {"R2"}
        self.engine.poll(T0 + timedelta(seconds=15))
        self.assertIn(("R2", "Ethernet1"), self.engine.first_seen)
        self.assertEqual(self.engine.first_seen[("R2", "Ethernet1")], T0)

    def test_intent_down_interface_is_not_a_fault(self):
        self.world.state["R2"]["Ethernet2"] = ("disabled", "down")
        engine = intake.Intake(cfg=self.engine.cfg, reader=self.world.read, intent={"R2": {"Ethernet2": "down"}, "S4": {}}.get,
                               deps=self.deps, _peers=PEERS)
        engine.poll(T0)
        self.assertEqual(engine.poll(T0 + timedelta(seconds=60)), [])

    def test_dispatch_only_accepts_a_well_formed_handoff_id(self):
        self.assertFalse(intake.start_dispatch("AIH-0123; systemctl stop nmas-web"))
        self.assertFalse(intake.start_dispatch("../../etc"))

    def test_failed_dispatch_start_is_audited_and_emailed(self):
        self.deps.dispatch = lambda hid: False
        self.world.shut_r2_e1()
        self.engine.poll(T0)
        out = self.engine.poll(T0 + timedelta(seconds=31))
        self.assertFalse(out[0]["dispatch_started"])
        self.assertTrue(any("could not start Codex dispatch" in s for s in self.mail))


class ConfidenceParsingTests(TestCase):
    """Replay finding: Codex sent confidence 'high' and the submit tool crashed (float('high')), discarding a valid conclusion."""

    def test_labels_and_numbers_are_accepted(self):
        from core.services.troubleshooting import ai
        self.assertEqual([ai.confidence_value(v) for v in ("high", "Low", "0.6", 0.3, None, "")], [0.75, 0.25, 0.6, 0.3, 0.0, 0.0])

    def test_garbage_is_a_typed_validation_error_not_a_crash(self):
        from core.services.troubleshooting import ai
        for bad in ("certain", 1.5, -0.1, True):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                ai.confidence_value(bad)


class IdleOpenCaseTests(IntakeTests):
    """Campaign 010 finding: a case diagnosed without a proposal stays open; the intake must surface it, never duplicate it."""

    def test_idle_open_case_is_escalated_once_and_never_duplicated(self):
        self.world.shut_r2_e1()
        self.engine.poll(T0)
        case_id = self.engine.poll(T0 + timedelta(seconds=31))[0]["case"]
        later = datetime.now(timezone.utc) + timedelta(seconds=intake.IDLE_AFTER_SECONDS + 5)    # audit events carry real time
        out = self.engine.poll(later)
        self.assertTrue(out[0]["skipped"].startswith("OPEN_CASE_IDLE"), out)
        self.engine.poll(later + timedelta(seconds=10))
        self.assertEqual(sum("OPEN_CASE_IDLE" in s for s in self.mail), 1)
        self.assertEqual(models.TsCase.objects.count(), 1)

    def test_handoff_text_names_the_propose_before_submit_workflow(self):
        captured = {}
        self.deps.open_handoff = lambda actor, case, **kw: captured.update(kw) or SimpleNamespace(record_id="AIH-0123456789ab")
        self.world.shut_r2_e1()
        self.engine.poll(T0)
        self.engine.poll(T0 + timedelta(seconds=31))
        self.assertIn("call propose_remediation", captured["uncertainty"])
        self.assertIn("BEFORE submit_investigation_result", captured["uncertainty"])
        self.assertNotIn("HC29", captured["uncertainty"])                                 # generic: no test or answer named
        self.assertNotIn("interface_enable", captured["uncertainty"])
