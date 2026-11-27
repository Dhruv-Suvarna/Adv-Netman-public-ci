"""Direct tests for the running-configuration snapshot helpers (troubleshooting/adapters/config_snapshot.py).

A snapshot is read only through the catalogued command of a known platform, behind the CONFIG_SNAPSHOT admission gate;
an empty read is degraded to PARTIAL with an explicit missing record; and the baseline-side reader withholds the text of
a device the actor may not see, or whose snapshot is partial or empty.
"""

from __future__ import annotations

from datetime import timedelta

from django.test import SimpleTestCase, TestCase

from core.services.troubleshooting import collectors as col
from core.services.troubleshooting import repository as repo
from core.services.troubleshooting.adapters import config_snapshot as cs
from core.tests.test_troubleshooting_config_snapshot import CMD, GOLD, RUNNING
from core.tests.test_troubleshooting_runtime import ACTOR, T0, Transport, make_case


def supported(_platform, _source):
    return {"status": "SUPPORTED", "evidence": "unit", "transport": "unit"}


def refusing_snapshot(_platform, source):
    return {"status": "UNSUPPORTED" if source == col.SourceType.CONFIG_SNAPSHOT else "SUPPORTED", "evidence": "unit", "transport": "unit"}


def cli(probe=supported):
    return col.CliCollector(clock=lambda: 0.0, sleep=lambda s: None, now=lambda: T0, capability_probe=probe)


def target(platform="ceos", **kw):
    return col.Target(device="R1", platform=platform, os_version="4.36.2F", **kw)


class SelectionTests(SimpleTestCase):
    def test_snapshot_key_returns_the_catalogued_read(self):
        self.assertEqual((cs.snapshot_key("ceos"), cs.snapshot_key("linux")), ("running_config", "frr_config"))

    def test_requested_returns_true_when_configs_are_wanted(self):
        self.assertTrue(cs.requested(["interfaces", cs.WANT_KEY]))

    def test_requested_without_configs_is_not_requested(self):
        self.assertFalse(cs.requested(["interfaces"]))

    def test_evidence_scope_returns_the_platform_scope(self):
        self.assertEqual(cs.evidence_scope({"platform": "ceos", "os_version": "4.36.2F"}),
                         {"platform": "ceos", "os_version": "4.36.2F", "snapshot_kind": "running-config", "config_snapshot_adapter": cs.ADAPTER_VERSION})

    def test_evidence_scope_of_missing_provenance_is_empty_not_guessed(self):
        scope = cs.evidence_scope({})
        self.assertEqual((scope["platform"], scope["os_version"]), ("", ""))

    def test_admission_accepts_a_supported_admitted_device(self):
        self.assertTrue(cs.admission(cli(), target()).ok)

    def test_admission_refuses_an_unsupported_or_unverified_device(self):
        with self.subTest("an unsupported capability is refused"):
            self.assertEqual(cs.admission(cli(refusing_snapshot), target()).code, col.Missing.UNSUPPORTED_PLATFORM)
        with self.subTest("an unverified device is refused"):
            self.assertEqual(cs.admission(cli(), target(verified=False)).code, col.Missing.NOT_ADMITTED)


class CollectionTests(SimpleTestCase):
    def test_collect_returns_a_redacted_snapshot(self):
        transport = Transport({CMD: RUNNING})
        bundle = cs.collect(cli(), target(), transport)
        self.assertEqual(transport.calls, [CMD])
        snap = [e for e in bundle["evidence"] if e["source_type"] == col.SourceType.CONFIG_SNAPSHOT]
        self.assertEqual(len(snap), 1)
        self.assertNotIn("hunter2topsecret", str(bundle))

    def test_collect_of_an_unknown_platform_never_contacts_the_device(self):
        transport = Transport({CMD: RUNNING})
        self.assertIsNone(cs.collect(cli(), target("arista-unknown-os"), transport))
        self.assertEqual(transport.calls, [])

    def test_degrade_empty_preserves_a_non_empty_snapshot(self):
        bundle = cs.collect(cli(), target(), Transport({CMD: RUNNING}))
        statuses = [e.get("status") for e in bundle["evidence"]]
        self.assertEqual([e.get("status") for e in cs.degrade_empty(bundle)["evidence"]], statuses)
        self.assertNotIn("PARTIAL", statuses)

    def test_degrade_empty_marks_an_empty_read_partial_with_a_missing_record(self):
        bundle = cli().collect(target(), ["running_config"], Transport({CMD: ""}))
        bundle = cs.degrade_empty(bundle)
        snap = [e for e in bundle["evidence"] if e["source_type"] == col.SourceType.CONFIG_SNAPSHOT][0]
        self.assertEqual(snap["status"], "PARTIAL")
        self.assertTrue(any("UNKNOWN" in m.get("detail", "") for m in bundle["missing"]))


class GuardedReaderTests(TestCase):
    def setUp(self):
        self.case = make_case("RB02", key="tg-cfgsnap")

    def store(self, raw, device="R1"):
        return repo.store_evidence(ACTOR, self.case, source_type="config_snapshot", device=device, command_or_api=CMD,
                                   collected_at=T0 - timedelta(seconds=30), raw=raw, scope={"platform": "ceos"})

    def test_guarded_reader_returns_the_newest_visible_snapshot(self):
        ref = self.store(GOLD)
        out = cs.guarded_reader(ACTOR, now=lambda: T0)(["R1"])
        self.assertEqual((out["R1"]["integrity"], out["R1"]["evidence_id"]), ("OK", ref.evidence_id))
        self.assertIn("interface Ethernet1", out["R1"]["text"])

    def test_guarded_reader_withholds_a_denied_or_blank_snapshot(self):
        self.store(GOLD, "R1")
        self.store("   \n", "R2")
        limited = repo.Actor("bob", "user", tenant="acme", devices=frozenset({"R2"}))
        out = cs.guarded_reader(limited, now=lambda: T0)(["R1", "R2"])
        self.assertEqual((out["R1"]["integrity"], out["R1"]["text"]), ("DENIED", None))
        self.assertIsNone(out["R2"]["text"])
        self.assertNotEqual(out["R2"]["integrity"], "OK")
