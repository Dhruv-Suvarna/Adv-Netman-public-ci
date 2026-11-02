"""Lab 7 closure -- ``config_templates.service`` (library rows, versions, extraction from captures, retirement,
TemplateError) and the read-only ``config_workbench.snapshots`` / ``scope`` helpers it is built on, each called directly.

Hermetic: devices are the fake read-only session factory of ``test_config_templates`` (it records which devices were
"contacted"; nothing is sent), NetBox scope is the fake managed list, the repository state is patched.  Database writes
are test-database only.  POSITIVE: exact content / provenance / rows / sections / ids.  NEGATIVE: unknown families,
blank names, unsupported platforms, retired / mismatched rows, stale snapshots and unknown devices are refused or
yield nothing, and a refused capture never contacts the device.
"""
from __future__ import annotations

import json
from types import SimpleNamespace
from unittest import mock

from django.test import TestCase

from core import models
from core.services.config_templates import package, service
from core.services.config_workbench import scope, snapshots
from core.tests.helpers import health as h
from core.tests.helpers.workbench import use_scope
from core.tests.test_config_templates import SECRET, Recorder, lab_outputs

CEOS_INTENT = {"device": {"hostname": "S9"}, "interfaces": [{"name": "Vlan10", "kind": "SVI"}],
               "routing": [{"family": "ospf", "fields": {}}]}


class Case(TestCase):
    def setUp(self):
        use_scope(self)
        self.factory = Recorder()

    def snapshot(self, device="S1"):
        snapshot, error = snapshots.capture_snapshot(device, actor="tester", session_factory=self.factory)
        self.assertEqual(error, "")
        return snapshot


class TemplateErrorAndContentTests(Case):
    def test_template_error_returns_a_coded_problem_list(self):
        error = service.TemplateError("PUBLICATION_REFUSED", ["first", 2])
        self.assertEqual((error.code, error.problems, str(error)), ("PUBLICATION_REFUSED", ["first", "2"], "PUBLICATION_REFUSED: first; 2"))

    def test_template_error_of_a_single_refusal_string_is_one_problem(self):
        error = service.TemplateError("INVALID_TEMPLATE", "A template name is required.")
        self.assertEqual(error.problems, ["A template name is required."])

    def test_new_template_id_returns_a_unique_upper_hex_id(self):
        first, second = service.new_template_id(), service.new_template_id()
        self.assertRegex(first, r"^TPL-[0-9A-F]{12}$")
        self.assertNotEqual(first, second)

    def test_repository_head_returns_the_available_head(self):
        with mock.patch.object(service.nsot_git, "get_repo_state", return_value={"status": "available", "head_commit": "abc123"}):
            self.assertEqual(service.repository_head(), "abc123")
        with mock.patch.object(service.nsot_git, "get_repo_state", return_value={"status": "unavailable"}):
            self.assertEqual(service.repository_head(), "")

    def test_build_content_returns_derived_features_and_platforms(self):
        content = service.build_content(family=models.TemplateFamily.CUSTOM, intent=CEOS_INTENT, parameters={}, notes="n")
        self.assertEqual(content["required_features"], ["interface.SVI", "routing.OSPFV2"])
        self.assertEqual(content["platforms"], ["arista_ceos", "ubuntu_frr"])
        self.assertEqual((content["schema_version"], content["family"], content["parameter_sets"], content["exclusions"], content["notes"]),
                         (1, "CUSTOM", {}, [], "n"))

    def test_build_content_of_a_non_deployable_template_has_no_platforms(self):
        content = service.build_content(family="CUSTOM", intent=CEOS_INTENT, parameters={}, constraints={"deployable": False})
        self.assertEqual((content["platforms"], content["constraints"]), ([], {"deployable": False}))

    def test_create_template_returns_an_audited_template(self):
        template = service.create_template(name="  Access  ", family=models.TemplateFamily.CUSTOM, origin=models.TemplateOrigin.DERIVED,
                                           actor="tester", template_id="TPL-FIXED0000001")
        self.assertEqual((template.template_id, template.name, template.family, template.origin), ("TPL-FIXED0000001", "Access", "CUSTOM", "DERIVED"))
        event = models.AuditEvent.objects.get(event_type=models.AuditEventType.TEMPLATE_CREATED)
        self.assertEqual((event.actor, event.object_id, event.metadata["family"]), ("tester", "TPL-FIXED0000001", "CUSTOM"))

    def test_create_template_refuses_unknown_family_origin_or_blank_name_and_creates_nothing(self):
        for label, kwargs in (("unknown family", {"name": "x", "family": "WORMHOLE", "origin": "DERIVED"}),
                              ("unknown origin", {"name": "x", "family": "CUSTOM", "origin": "STOLEN"}),
                              ("blank name", {"name": "   ", "family": "CUSTOM", "origin": "DERIVED"})):
            with self.subTest(case=f"refused {label}"):
                with self.assertRaises(service.TemplateError) as raised:
                    service.create_template(**kwargs)
                self.assertEqual(raised.exception.code, "INVALID_TEMPLATE")
        self.assertFalse(models.ConfigurationTemplate.objects.exists())


class LibraryTests(Case):
    def setUp(self):
        super().setUp()
        self.access = service.publish(service.extract_from_snapshot(self.snapshot("S1"), actor="tester", name="Access S1",
                                                                    family=models.TemplateFamily.ACCESS_SWITCH), actor="approver")
        self.frr = service.extract_from_snapshot(self.snapshot("R3"), actor="tester", name="Router R3")

    def test_list_templates_returns_rows_filtered_by_family_platform_origin_and_query(self):
        rows = service.list_templates()
        self.assertEqual({row["template"].name for row in rows}, {"Access S1", "Router R3"})
        access = next(row for row in rows if row["template"].name == "Access S1")
        self.assertEqual((access["published"], access["shown"], access["latest"], access["version_count"]), (self.access, self.access, self.access, 1))
        self.assertEqual([r["template"].name for r in service.list_templates(family="ACCESS_SWITCH")], ["Access S1"])
        self.assertEqual([r["template"].name for r in service.list_templates(platform="ubuntu_frr", query="r3")], ["Router R3"])
        self.assertEqual({r["template"].name for r in service.list_templates(origin="EXTRACTED")}, {"Access S1", "Router R3"})

    def test_list_templates_never_lists_retired_mismatched_or_versionless_templates(self):
        service.retire(self.frr.template, actor="tester")
        service.create_template(name="Empty", family="CUSTOM", origin="DERIVED")
        with self.subTest(case="retired hidden"):
            self.assertEqual([r["template"].name for r in service.list_templates()], ["Access S1"])
        with self.subTest(case="no platform match"):
            self.assertEqual(service.list_templates(platform="sonic"), [])
        with self.subTest(case="no query match"):
            self.assertEqual(service.list_templates(query="nothing-like-this"), [])
        self.assertEqual({r["template"].name for r in service.list_templates(include_retired=True)}, {"Access S1", "Router R3"})

    def test_get_version_returns_the_numbered_version(self):
        self.assertEqual(service.get_version(self.access.template.template_id, 1), self.access)

    def test_get_version_of_an_unknown_template_or_number_is_none(self):
        self.assertIsNone(service.get_version(self.access.template.template_id, 9))
        self.assertIsNone(service.get_version("TPL-UNKNOWN", 1))

    def test_discard_draft_returns_after_removing_the_draft_and_its_empty_template(self):
        template_id = self.frr.template.template_id
        self.assertIsNone(service.discard_draft(self.frr, actor="tester"))
        self.assertFalse(models.ConfigurationTemplate.objects.filter(template_id=template_id).exists())
        self.assertTrue(models.AuditEvent.objects.filter(event_type=models.AuditEventType.TEMPLATE_DRAFT_DISCARDED).exists())

    def test_retire_of_an_already_retired_template_never_audits_again(self):
        template = service.retire(self.access.template, actor="first")
        stamped = template.retired_at
        again = service.retire(template, actor="second")
        self.assertEqual((again.retired_at, again.retired_by), (stamped, "first"))
        self.assertEqual(models.AuditEvent.objects.filter(event_type=models.AuditEventType.TEMPLATE_RETIRED).count(), 1)
        self.assertEqual(self.access.template.versions.count(), 1)

    def test_publication_problems_refuse_tampered_digest_unknown_platform_and_gaps(self):
        draft = service.create_version(self.access.template, package.version_content(self.access), actor="tester")
        draft.platforms, draft.digest = ["arista_ceos", "sonic", "atari"], "0" * 64     # in memory only: stored rows are immutable
        problems = service.publication_problems(draft)
        self.assertIn("Unknown platform 'atari'.", problems)
        self.assertTrue(any(p.startswith("Platform sonic cannot render:") for p in problems))
        self.assertIn("The stored digest does not match the content.", problems)


class ExtractionTests(Case):
    def test_parse_capture_returns_ceos_and_frr_records(self):
        parsed = service.parse_capture(models.Platform.ARISTA_CEOS, {"running_config": "hostname S9\ninterface Loopback0\n"})
        self.assertEqual((parsed.hostname, [i.name for i in parsed.interfaces]), ("S9", ["Loopback0"]))
        frr = service.parse_capture(models.Platform.UBUNTU_FRR, {"frr_config": "frr version 8.4.4\nhostname R9\nend\n"})
        self.assertEqual(frr.hostname, "R9")

    def test_parse_capture_refuses_unsupported_platforms(self):
        with self.assertRaises(service.TemplateError) as raised:
            service.parse_capture(models.Platform.SONIC, {"running_config": "hostname x"})
        self.assertEqual(raised.exception.code, "UNSUPPORTED_PLATFORM")

    def test_snapshot_sections_returns_the_primary_section_for_the_platform(self):
        snapshot = self.snapshot("S1")
        self.assertEqual(service.snapshot_sections(snapshot), {"running_config": snapshot.text})
        self.assertEqual(list(service.snapshot_sections(SimpleNamespace(platform=models.Platform.UBUNTU_FRR, text="t"))), ["frr_config"])

    def test_snapshot_sections_of_an_unknown_platform_is_empty(self):
        self.assertEqual(service.snapshot_sections(SimpleNamespace(platform="sonic", text="hostname x")), {})

    def test_device_intent_returns_cleaned_intent_exclusions_and_provenance(self):
        snapshot = self.snapshot("S1")
        intent, exclusions, source = service.device_intent(snapshot)
        self.assertEqual(intent["device"], {"hostname": "S1"})
        self.assertNotIn("Management0", [row["name"] for row in intent["interfaces"]])
        self.assertTrue(exclusions and all(row["device"] == "S1" for row in exclusions))
        self.assertEqual((source["device"], source["snapshot_id"], source["running_config_digest"], source["platform"]),
                         ("S1", str(snapshot.snapshot_id), snapshot.digest, "arista_ceos"))
        self.assertNotIn("note", source)
        self.assertNotIn(SECRET, json.dumps([intent, exclusions, source]))

    def test_device_intent_of_a_stored_frr_snapshot_without_addresses_is_marked_partial(self):
        _intent, _exclusions, source = service.device_intent(self.snapshot("R3"))
        self.assertEqual(source["note"], "Stored snapshot only: Linux interface addresses and NAT rules need a live capture.")

    def test_extraction_content_returns_content_generalized_over_the_sources(self):
        with mock.patch.object(service, "repository_head", return_value="abc123"):
            content = service.extraction_content([(self.snapshot("S1"), None), (self.snapshot("S2"), None)],
                                                 family="ACCESS_SWITCH", method="unit-test")
        provenance = content["provenance"]
        self.assertEqual((provenance["method"], provenance["source_devices"], provenance["platforms"], provenance["repository_head"]),
                         ("unit-test", ["S1", "S2"], ["arista_ceos"], "abc123"))
        self.assertEqual(set(content["parameter_sets"]), {"S1", "S2"})
        self.assertEqual(content["family"], "ACCESS_SWITCH")
        self.assertNotIn(SECRET, json.dumps(content))

    def test_extraction_content_without_captures_raises(self):
        with self.assertRaises(ValueError):
            service.extraction_content([], family="CUSTOM", method="unit-test")

    def test_extract_from_snapshot_returns_a_draft_without_contacting_the_device(self):
        snapshot = self.snapshot("S1")
        self.factory.devices.clear()
        version = service.extract_from_snapshot(snapshot, actor="tester", name="Stored S1")
        self.assertEqual((version.status, version.template.name, version.provenance["method"]), ("DRAFT", "Stored S1", "stored-running-config-snapshot"))
        self.assertEqual(self.factory.devices, [])


class SnapshotHelperTests(Case):
    def test_workbench_scope_and_devices_return_the_managed_selectable_devices(self):
        scope_row = snapshots.workbench_scope()
        names = [row["name"] for row in snapshots.workbench_devices()]
        self.assertEqual(names, sorted(names))
        self.assertTrue({"R1", "R3", "S1"} <= set(names))
        self.assertNotIn("R5", names)
        self.assertEqual(scope_row.get("S1")["platform"], models.Platform.ARISTA_CEOS)

    def test_workbench_scope_get_of_an_unmanaged_or_unknown_device_is_none(self):
        current = snapshots.workbench_scope()
        for name in ("R5", "H1", ""):
            with self.subTest(case=f"none for {name or 'blank'}"):
                self.assertIsNone(current.get(name))
        self.assertIsInstance(current, scope.WorkbenchScope)

    def test_device_platform_returns_the_inventory_platform(self):
        self.assertEqual((snapshots.device_platform("S1"), snapshots.device_platform("R3")), (models.Platform.ARISTA_CEOS, models.Platform.UBUNTU_FRR))

    def test_device_platform_of_an_unmanaged_or_unknown_device_is_none(self):
        self.assertEqual((snapshots.device_platform("R5"), snapshots.device_platform("NOPE")), (None, None))

    def test_capture_with_sections_returns_the_snapshot_and_every_sanitized_section(self):
        outcome, sections = snapshots.capture_with_sections("R3", actor="tester", session_factory=self.factory)
        self.assertEqual((outcome.snapshot.device_name, outcome.snapshot.platform), ("R3", "ubuntu_frr"))
        self.assertIn("frr_config", sections)
        self.assertIn("addr", sections)
        self.assertNotIn(SECRET, json.dumps(sections))
        self.assertEqual(self.factory.devices, ["R3"])

    def test_capture_with_sections_refuses_unmanaged_devices_and_failed_reads_without_a_snapshot(self):
        cases = (("out of scope", "R5", self.factory, "DEVICE_OUT_OF_SCOPE"),
                 ("failed read", "S1", h.session_factory({}, fail={"S1": "TIMEOUT"}), None))
        for label, device, factory, code in cases:
            with self.subTest(case=f"refused {label}"):
                outcome, sections = snapshots.capture_with_sections(device, actor="tester", session_factory=factory)
                self.assertEqual((outcome.snapshot, sections), (None, {}))
                if code:
                    self.assertEqual(outcome.code, code)
        self.assertEqual(self.factory.devices, [])
        self.assertFalse(models.RunningConfigSnapshot.objects.exists())

    def test_get_snapshot_returns_the_snapshot_for_its_device(self):
        snapshot = self.snapshot("S1")
        self.assertEqual(snapshots.get_snapshot(snapshot.snapshot_id), snapshot)
        self.assertEqual(snapshots.get_snapshot(snapshot.snapshot_id, "S1"), snapshot)

    def test_get_snapshot_of_another_device_or_unknown_id_is_none(self):
        snapshot = self.snapshot("S1")
        self.assertIsNone(snapshots.get_snapshot(snapshot.snapshot_id, "S2"))
        self.assertIsNone(snapshots.get_snapshot("00000000-0000-0000-0000-000000000000"))

    def test_numbered_of_an_empty_snapshot_is_empty(self):
        self.assertEqual(snapshots.numbered(SimpleNamespace(text=""), highlight=[1]), [])

    def test_recheck_returns_current_for_an_unchanged_device(self):
        snapshot = self.snapshot("S1")
        self.assertEqual(snapshots.recheck(snapshot, session_factory=self.factory), {"current": True, "digest": snapshot.digest, "error": ""})

    def test_recheck_reports_a_stale_snapshot_or_a_failed_read_never_current(self):
        snapshot = self.snapshot("S1")
        outputs = lab_outputs()
        outputs["S1"] = h.eos_outputs(config="hostname S1\ninterface Loopback9\nend\n")
        with self.subTest(case="stale snapshot"):
            result = snapshots.recheck(snapshot, session_factory=h.session_factory(outputs))
            self.assertEqual((result["current"], result["error"]), (False, "SNAPSHOT_STALE"))
            self.assertNotEqual(result["digest"], snapshot.digest)
        with self.subTest(case="failed read"):
            result = snapshots.recheck(snapshot, session_factory=h.session_factory({}, fail={"S1": "TIMEOUT"}))
            self.assertEqual((result["current"], result["digest"]), (False, ""))
            self.assertTrue(result["error"])
