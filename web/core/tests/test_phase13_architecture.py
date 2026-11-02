from __future__ import annotations

import ast
import re
import socket
import subprocess
import urllib.request
from pathlib import Path
from unittest import mock

from django.test import SimpleTestCase, TestCase

from core import models
from core.services import change_validation_service as cvs
from core.services.validation import findings as findings_module
from core.tests.helpers.validation import Dev, make_sources, nb_prefix, netbox_data, new_change, validate

WEB_ROOT = Path(__file__).resolve().parents[2]
REPO_ROOT = WEB_ROOT.parent
PACKAGE = WEB_ROOT / "core/services/validation"
SERVICE = WEB_ROOT / "core/services/change_validation_service.py"
DOC = REPO_ROOT / "docs/CHANGE_VALIDATION_AND_DEPENDENCIES.md"


def python_files():
    return [*sorted(PACKAGE.glob("*.py")), SERVICE]


def imports_of(path):
    tree = ast.parse(path.read_text())
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            base = ("." * node.level) + (node.module or "")
            found.add(base)
            found.update(f"{base}.{alias.name}" for alias in node.names)
    return found


class ImportBoundaryTests(SimpleTestCase):
    FORBIDDEN_TOP = {"netmiko", "paramiko", "pynetbox", "subprocess", "requests", "socket", "urllib", "http", "github",
                     "ncclient", "pygnmi", "importlib", "telnetlib", "ftplib", "smtplib"}

    def test_no_device_network_git_or_dynamic_import_modules(self):
        for path in python_files():
            tops = {name.lstrip(".").split(".")[0] for name in imports_of(path) if not name.startswith(".")}
            self.assertFalse(tops & self.FORBIDDEN_TOP, f"{path.name}: {tops & self.FORBIDDEN_TOP}")

    def test_no_eval_exec_dynamic_import_or_shell(self):
        for path in python_files():
            for node in ast.walk(ast.parse(path.read_text())):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    self.assertNotIn(node.func.id, {"eval", "exec", "compile", "__import__"}, path.name)
                if isinstance(node, ast.Attribute):
                    self.assertNotIn(node.attr, {"system", "popen", "check_output"}, path.name)

    def test_no_netbox_write_verbs_in_validation_or_the_facts_reader(self):
        # writes through a NetBox client/endpoint, or any of the repository's NetBox write helpers
        verbs = re.compile(r"(\b(client|nb|netbox|pynetbox|endpoint|api)\b[\w\.\[\]\"']*\.(create|update|delete|save|post|put|patch)\("
                           r"|\b(reconcile_object|ensure_tag|ensure_custom_field|ensure_interface_mac|set_dhcpv6_identity|"
                           r"mark_mac_authoritative|clear_stale_mac_identity_status|clear_stale_dhcpv6_identity)\()")
        for path in sorted(PACKAGE.glob("*.py")):
            self.assertIsNone(verbs.search(path.read_text()), path.name)
        source = (WEB_ROOT / "core/services/nsot_netbox.py").read_text()
        facts = source[source.index("def project_facts"):]
        self.assertIsNone(verbs.search(facts))

    def test_validation_touches_no_phase14_lifecycle_configlet_or_notification_code(self):
        banned_modules = {"configlet_service", "lifecycle_service", "notification_service", "slack_service", "automation_service"}
        banned_calls = {"create_configlet", "add_configlet_dependency", "record_lifecycle_event", "publish_event", "send_slack"}
        for path in python_files():
            for name in imports_of(path):
                self.assertNotIn(name.split(".")[-1], banned_modules, path.name)
            for node in ast.walk(ast.parse(path.read_text())):
                if isinstance(node, ast.Call):
                    fn = node.func
                    called = fn.id if isinstance(fn, ast.Name) else getattr(fn, "attr", "")
                    self.assertNotIn(called, banned_calls, path.name)

    def test_no_deployment_or_orchestration_text(self):
        for path in python_files():
            text = path.read_text().lower()
            for phrase in ("configure terminal", "write memory", "containerlab deploy", "containerlab destroy", "netmiko",
                           "vtysh", "commit confirmed"):
                self.assertNotIn(phrase, text, f"{path.name}: {phrase}")

    def test_only_one_candidate_renderer_and_validation_defines_none(self):
        self.assertEqual([p.name for p in (WEB_ROOT / "core/services").glob("*candidate_renderer*.py")], ["candidate_renderer.py"])
        for path in sorted(PACKAGE.glob("*.py")):
            names = {n.name for n in ast.walk(ast.parse(path.read_text())) if isinstance(n, ast.FunctionDef)}
            self.assertFalse(names & {"render", "render_candidate"}, path.name)

    def test_views_stay_thin(self):
        source = (WEB_ROOT / "core/views.py").read_text()
        self.assertNotIn("core.services.validation", source)
        self.assertNotIn("from .services.validation", source)
        self.assertNotIn("import ipaddress", source)
        section = source[source.index("Phase 13 -- Tier-2"):]
        for name in ("ipaddress", "netbox_conflicts", "build_graph", "find_cycles", "evaluate(", "run_validation", "ProjectModel"):
            self.assertNotIn(name, section)
        self.assertIn("change_validation_service.validate_change", section)

    def test_sources_are_fixed_repository_paths(self):
        from core.services.validation import sources
        for path in (sources.INVENTORY_PATH, sources.TOPOLOGY_CONFIG_PATH):
            self.assertTrue(path.is_relative_to(REPO_ROOT))


class MigrationAndDocsTests(SimpleTestCase):
    def test_single_append_only_model_migration(self):
        text = (WEB_ROOT / "core/migrations/0003_phase13_change_validation_run.py").read_text()
        self.assertIn("CreateModel", text)
        self.assertIn("ChangeValidationRun", text)
        self.assertEqual(text.count("CreateModel"), 1)      # no per-finding table
        self.assertNotIn("DeleteModel", text)
        self.assertEqual(sorted(p.name for p in (WEB_ROOT / "core/migrations").glob("0*.py"))[:2],
                         ["0001_notification.py", "0002_phase8_device_intent_change_model.py"])

    def test_documentation_exists_and_documents_every_finding_code(self):
        self.assertTrue(DOC.exists())
        text = DOC.read_text()
        missing = [code for code in findings_module.CODE_CATALOG if code not in text]
        self.assertEqual(missing, [])

    def test_documentation_covers_the_required_topics(self):
        text = DOC.read_text().lower()
        for phrase in ("tier-1", "tier-2", "accepted", "stale", "input hash", "self-match", "auto address", "race",
                       "dependency graph", "phase 14", "no deployment", "netbox is passive", "explicit post"):
            self.assertIn(phrase, text, phrase)

    def test_current_state_records_phase13(self):
        # Later phases prepend their own update note, so Phase 13's stays in the file rather than at a fixed offset.
        self.assertIn("Phase 13 update", (REPO_ROOT / "docs/CURRENT_STATE.md").read_text())


class SideEffectProofTests(TestCase):
    """Run a full validation with every outward door slammed shut."""

    @classmethod
    def setUpTestData(cls):
        cls.change = new_change()
        r1, r2 = Dev(cls.change, "R1"), Dev(cls.change, "R2")
        a = r1.iface("Ethernet1"); r1.address(a, "192.0.2.0/31"); r1.auto_address(r1.iface("Ethernet2"), "198.51.100.0/29")
        z = r2.iface("Ethernet1"); r2.address(z, "192.0.2.1/31")
        o = r1.ospf(); r1.bind("ospf", o, a)
        r1.bgp(65001)
        cls.sources = make_sources(netbox=netbox_data(prefixes=[nb_prefix("198.51.100.0/29")]))

    def test_no_device_connection_no_dns_no_github_no_git_no_subprocess(self):
        boom = AssertionError("validation attempted an outward action")
        with mock.patch.object(socket, "socket", side_effect=boom), mock.patch.object(socket, "getaddrinfo", side_effect=boom), \
                mock.patch.object(subprocess, "run", side_effect=boom), mock.patch.object(subprocess, "Popen", side_effect=boom), \
                mock.patch.object(urllib.request, "urlopen", side_effect=boom):
            run = validate(self.change, self.sources)
        self.assertEqual(run.status, "PASS")

    def test_full_real_bundle_path_uses_only_read_only_git(self):
        seen = []
        canned = self.sources
        from core.services import nsot_git
        from core.services.validation import sources as sources_module

        def fake_git(args):
            seen.append(args[0])
            return "abc\n"

        with mock.patch.object(nsot_git, "_run_git", side_effect=fake_git), \
                mock.patch.object(sources_module, "collect_netbox", return_value=canned.netbox), \
                mock.patch.object(sources_module, "collect_topology", return_value=canned.topology), \
                mock.patch.object(sources_module, "collect_inventory", return_value=canned.inventory):
            run = cvs.validate_change(self.change, actor="t")
        self.assertTrue(seen)
        self.assertLessEqual(set(seen), {"rev-parse", "log", "status"})
        self.assertEqual(run.repository_head, "abc")

    def test_accepted_intent_and_project_state_are_untouched(self):
        before = {i.pk: (i.latest_revision().sections, i.platform) for i in self.change.device_intents.all()}
        hash_before = cvs.hash_snapshot(cvs.build_change_snapshot(self.change))
        validate(self.change, self.sources)
        after = {i.pk: (i.latest_revision().sections, i.platform) for i in self.change.device_intents.all()}
        self.assertEqual(before, after)
        self.assertEqual(hash_before, cvs.hash_snapshot(cvs.build_change_snapshot(self.change)))

    def test_only_validation_runs_capability_evidence_and_their_audits_are_written(self):
        counts = lambda: {m.__name__: m.objects.count() for m in (
            models.Change, models.DeviceIntent, models.DeviceIntentRevision, models.IntentFieldState, models.Configlet,
            models.ConfigletDependency, models.ChangeLifecycleEvent, models.Notification, models.ChangeTarget)}
        before = counts()
        runs = models.ChangeValidationRun.objects.count()
        network_runs = models.NetworkConfigValidationRun.objects.count()
        evidence = models.CapabilityEvidence.objects.count()
        audits = models.AuditEvent.objects.count()
        validate(self.change, self.sources)
        self.assertEqual(before, counts())
        self.assertEqual(models.ChangeValidationRun.objects.count(), runs + 1)
        self.assertEqual(models.NetworkConfigValidationRun.objects.count(), network_runs + 1)
        evidence_written = models.CapabilityEvidence.objects.count() - evidence
        self.assertGreater(evidence_written, 0)
        # One audit belongs to each validation domain and one belongs to every empirical capability observation.
        self.assertEqual(models.AuditEvent.objects.count(), audits + 2 + evidence_written)

    def test_change_remains_draft_and_no_configlets_exist(self):
        validate(self.change, self.sources)
        self.change.refresh_from_db()
        self.assertEqual(self.change.lifecycle_state, models.ChangeLifecycleState.DRAFT)
        self.assertFalse(models.Configlet.objects.exists())
        self.assertEqual(self.change.git_commit_ref, "")
        self.assertEqual(self.change.github_actions_run_ref, "")
        self.assertEqual(self.change.deployment_reference, "")
