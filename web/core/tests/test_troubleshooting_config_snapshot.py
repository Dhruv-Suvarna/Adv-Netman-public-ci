"""Runtime -> running-config snapshot -> baseline comparison (stable IDs CFGSNAP-001 .. CFGSNAP-010; spec 3.3 / 6.3).

PROVENANCE: SIMULATED -- replayed through the real CliCollector / runtime / repository / ORM test database with injected transports.  No device, socket,
credential or default network runner; nothing here is gateway-recorded live evidence.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

from django.test import TestCase

from core import models as m
from core.services.troubleshooting import baselines as bl
from core.services.troubleshooting import collectors as col
from core.services.troubleshooting import repository as repo
from core.services.troubleshooting import runtime as rt
from core.services.troubleshooting.adapters import config_snapshot as cs
from core.tests.test_troubleshooting_runtime import ACTOR, GW, OUT, T0, Transport, make_case

GOLD = "interface Ethernet1\n   mtu 9214\nrouter ospf 1\n   router-id 1.1.1.1\n"
CMD = "show running-config"
RUNNING = GOLD + "hostname R1\nusername admin secret 0 hunter2topsecret\n"
H = lambda t: hashlib.sha256(t.encode()).hexdigest()  # noqa: E731


def golden(devs):
    return {"status": "available", "approved_change_id": "CHG-1", "reason": "", "device_scope": [
        {"device": d, "status": "COVERED", "revision": "BND-GOLD-1", "digest": "d" * 64, "url": "/b/1/", "created_at": (T0 - timedelta(days=2)).isoformat(),
         "items": [{"cfg_id": f"CFG-{d}", "payload_hash": H(GOLD), "operation": "CREATE_DEFINE", "sequence": 1}]} for d in devs]}


def loader(dev, bundle, cfgs):
    return [{"cfg_id": i, "platform": "ceos", "operation": "CREATE_DEFINE", "payload": GOLD, "payload_hash": H(GOLD), "integrity": "OK"} for i in cfgs]


class Spy:
    """BaselineSources: real snapshot adapter for configs(); records what configs() saw AT ENGINE TIME (i.e. before correlation/testing)."""

    def __init__(self, actor=ACTOR):
        self.real = cs.baseline_sources(actor, now=lambda: T0, payload_loader=loader, overrides={
            "golden": golden, "intent": lambda d, f: bl.unavailable("intent", "t"), "changes": lambda d, s, u: bl.unavailable("changes", "t"),
            "history": lambda f, d, n: bl.unavailable("history", "t"), "slo": lambda f: bl.unavailable("slo", "t")})
        self.seen = []

    def configs(self, devices):
        out = self.real.configs(devices)
        self.seen.append(out)
        return out

    def __getattr__(self, name):
        return getattr(self.real, name)


def deps(transport=None, spy=None, **kw):
    clock = [0.0]
    return rt.RuntimeDeps(
        admission=rt.InventoryAdmission(inventory=lambda: {n: {"platform": kw.pop("platform", "ceos"), "os_version": "4.36.2F"} for n in ("R1", "R2")}),
        cli_transport=(lambda info: transport) if transport else None, sources=spy or Spy(), clock=lambda: clock[0], sleep=lambda s: None, now=lambda: T0,
        capability_probe=kw.pop("capability_probe", lambda plat, src: {"status": "SUPPORTED", "evidence": "test", "transport": "test"}), **kw)


def snaps(case=None, device="R1"):
    q = m.TsEvidenceRef.objects.filter(device=device, source_type="config_snapshot")
    return q.filter(case=case) if case else q


class RuntimeToBaselineTests(TestCase):
    def test_cfgsnap_001_usable_snapshot_redacted_scoped_and_compared_before_baseline(self):
        case, spy = make_case("RB02", key="c1"), Spy()
        tr = Transport({**OUT, CMD: RUNNING}, provenance=GW)
        rt.run_case(ACTOR, case.case_id, deps(tr, spy), run_key="r1", now=T0)
        self.assertIn(CMD, tr.calls)
        self.assertEqual(tr.calls.count(CMD), 2)                          # once per admitted scoped device (R1, R2)
        ref = snaps(case).get()
        self.assertEqual((ref.scope["platform"], ref.scope["snapshot_kind"], ref.scope["live"], ref.scope["gateway"]["pin_id"]), ("ceos", "running-config", True, "pin-1"))
        self.assertEqual(ref.redaction_status, "REDACTED")
        self.assertNotIn("hunter2topsecret", ref.raw_blob.content)
        self.assertIn("interface Ethernet1", ref.raw_blob.content)
        first = spy.seen[0]                                                # engine's baseline stage, i.e. after collection of this very run
        self.assertEqual(first["status"], "available")
        d = first["devices"]["R1"]
        self.assertEqual((d["diffs"], d["compared_lines"], d["snapshot_evidence_id"], d["platform_verified"]), ([], 4, ref.evidence_id, True))
        self.assertEqual(bl.assess_drift(first, changes=[], production_impact="NONE")[0]["drift_kind"], "NONE")

    def test_cfgsnap_002_missing_snapshot_no_transport_is_unknown_and_nothing_contacted(self):
        case, spy = make_case("RB02", key="c2"), Spy()
        rt.run_case(ACTOR, case.case_id, deps(None, spy), run_key="r1", now=T0)
        self.assertFalse(snaps(case).exists())
        out = spy.seen[0]
        self.assertEqual((out["status"], out["unknown_devices"]["R1"]["reason"]), ("unavailable", "NO_SNAPSHOT"))
        self.assertTrue(m.TsObservation.objects.filter(case=case, target="R1", is_missing_data=True, key__contains="config").exists())

    def test_cfgsnap_003_partial_empty_output_is_not_a_usable_snapshot(self):
        case, spy = make_case("RB02", key="c3"), Spy()
        rt.run_case(ACTOR, case.case_id, deps(Transport({**OUT, CMD: ""}), spy), run_key="r1", now=T0)
        ref = snaps(case).get(command_or_api=CMD) if snaps(case).count() == 1 else snaps(case).first()
        self.assertEqual(ref.quality, "PARTIAL")
        u = spy.seen[0]["unknown_devices"]["R1"]
        self.assertEqual(u["reason"], "SNAPSHOT_INTEGRITY")
        self.assertIn("PARTIAL", u["detail"])
        self.assertEqual(bl.assess_drift(spy.seen[0], changes=[], production_impact="NONE")[0]["drift_kind"], "UNKNOWN")

    def test_cfgsnap_004_stale_snapshot_is_unknown(self):
        case, spy = make_case("RB02", key="c4"), Spy()
        repo.store_evidence(ACTOR, case, source_type="config_snapshot", device="R1", command_or_api=CMD, collected_at=T0 - timedelta(days=3), raw=RUNNING,
                            scope={"platform": "ceos"})
        rt.run_case(ACTOR, case.case_id, deps(None, spy), run_key="r1", now=T0)
        u = spy.seen[0]["unknown_devices"]["R1"]
        self.assertEqual(u["reason"], "STALE_SNAPSHOT")

    def test_cfgsnap_005_transport_permission_denied_is_explicit_gap(self):
        class Denying(Transport):
            def execute(self, rendered):
                if rendered == CMD:
                    raise col.PermissionDenied()
                return super().execute(rendered)
        case, spy = make_case("RB02", key="c5"), Spy()
        rt.run_case(ACTOR, case.case_id, deps(Denying(OUT), spy), run_key="r1", now=T0)
        self.assertFalse(snaps(case).exists())
        miss = m.TsObservation.objects.filter(case=case, target="R1", is_missing_data=True, key="config.snapshot")
        self.assertTrue(miss.exists())
        self.assertIn("PERMISSION_DENIED", miss.first().value_json.get("reason", "") if isinstance(getattr(miss.first(), "value_json", None), dict) else str(vars(miss.first())))
        self.assertEqual(spy.seen[0]["unknown_devices"]["R1"]["reason"], "NO_SNAPSHOT")

    def test_cfgsnap_006_capability_refusal_does_not_touch_device(self):
        case, spy = make_case("RB02", key="c6"), Spy()
        tr = Transport({**OUT, CMD: RUNNING})
        probe = lambda plat, src: {"status": "UNSUPPORTED" if src == col.SourceType.CONFIG_SNAPSHOT else "SUPPORTED", "evidence": "t", "transport": "t"}  # noqa: E731
        rt.run_case(ACTOR, case.case_id, deps(tr, spy, capability_probe=probe), run_key="r1", now=T0)
        self.assertNotIn(CMD, tr.calls)
        self.assertFalse(snaps(case).exists())
        self.assertEqual(spy.seen[0]["unknown_devices"]["R1"]["reason"], "NO_SNAPSHOT")

    def test_cfgsnap_007_command_budget_is_preserved(self):
        case = make_case("RB02", key="c7")
        tr = Transport({**OUT, CMD: RUNNING})
        res = rt.run_case(ACTOR, case.case_id, deps(tr), run_key="r1", now=T0, budget={"max_commands": 1})
        self.assertNotIn(CMD, tr.calls)
        self.assertLessEqual(len(tr.calls) / 2, res["budget"]["max_commands"])
        self.assertFalse(snaps(case).exists())

    def test_cfgsnap_008_unknown_platform_has_no_catalogued_read(self):
        self.assertIsNone(cs.snapshot_key("arista-unknown-os"))
        self.assertEqual((cs.snapshot_key("ceos"), cs.snapshot_key("iosxe"), cs.snapshot_key("linux")), ("running_config", "running_config", "frr_config"))

    def test_cfgsnap_009_duplicate_and_restart_are_idempotent_newest_wins(self):
        case, spy = make_case("RB02", key="c9"), Spy()
        tr = Transport({**OUT, CMD: RUNNING})
        d = deps(tr, spy)
        rt.run_case(ACTOR, case.case_id, d, run_key="r1", now=T0)
        calls, n = len(tr.calls), snaps(case).count()
        rt.run_case(ACTOR, case.case_id, d, run_key="r1", now=T0)           # restart: finished devices are not recontacted
        self.assertEqual((len(tr.calls), snaps(case).count()), (calls, n))
        rt.run_case(ACTOR, case.case_id, d, run_key="r2", now=T0)           # new run_key, identical content+time: same evidence row / blob
        self.assertEqual(snaps(case).count(), n)
        self.assertEqual(m.TsEvidenceBlob.objects.filter(stored_sha256=snaps(case).first().raw_blob.stored_sha256).count(), 1)
        newer = repo.store_evidence(ACTOR, case, source_type="config_snapshot", device="R1", command_or_api=CMD, collected_at=T0 + timedelta(seconds=5),
                                    raw=GOLD.replace("9214", "1500"), scope={"platform": "ceos"})
        out = cs.baseline_sources(ACTOR, now=lambda: T0 + timedelta(seconds=10), payload_loader=loader, overrides={"golden": golden}).configs(["R1"])
        self.assertEqual(out["devices"]["R1"]["snapshot_evidence_id"], newer.evidence_id)
        self.assertEqual(out["devices"]["R1"]["diff_total"], 1)

    def test_cfgsnap_010_actor_without_device_visibility_is_denied_per_device(self):
        case = make_case("RB02", key="c10")
        rt.run_case(ACTOR, case.case_id, deps(Transport({**OUT, CMD: RUNNING})), run_key="r1", now=T0)
        limited = repo.Actor("bob", "user", tenant="acme", devices=frozenset({"R2"}))
        out = cs.baseline_sources(limited, now=lambda: T0, payload_loader=loader, overrides={"golden": golden}).configs(["R1", "R2"])
        self.assertEqual(sorted(out["devices"]), ["R2"])
        self.assertIn("DENIED", out["unknown_devices"]["R1"]["detail"])
