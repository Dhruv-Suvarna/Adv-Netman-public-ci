"""Configuration Changes / Remove Configuration: the ONE shared capture path, its device scope and its error taxonomy.

Regression cover for the live defects: cEOS capture reported ``NOT_CONFIGURED`` when the runtime credential store was absent,
Ubuntu capture crashed with ``no such table: core_runningconfigsnapshot`` on an unmigrated database, and R5 (NetBox-unmanaged)
was selectable.  No test contacts a device, NetBox or the network.
"""
from __future__ import annotations

import tempfile
from pathlib import Path
from unittest import mock

from django.core.management import call_command
from django.db import OperationalError
from django.db.migrations.loader import MigrationLoader
from django.db.migrations.operations import CreateModel
from django.test import SimpleTestCase, TestCase
from django.urls import reverse

from core import models
from core.services import nsot_live
from core.services.bootstrap import capture as bootstrap_capture
from core.services.config_workbench import scope, snapshots
from core.services.health import live
from core.tests.helpers import health as h
from core.tests.helpers.workbench import LAB_MANAGED, managed, unavailable, use_scope
from modules import device_credentials

CEOS = ("R1", "R2", "S1", "S2", "S3", "S4", "mgmt_swt")
LINUX = ("R3", "R4")
EOS_CONFIG = "hostname {name}\nusername admin privilege 15 secret sha512 TEST_ONLY_WORKBENCH_SECRET_NEVER_REAL\nvlan 200\n   name MANAGEMENT\n"
FRR_CONFIG = "frr version 8.4\nhostname {name}\nrouter ospf\n ospf router-id 3.3.3.3\nexit\n"
WORKFLOWS = ("CONFIGURATION_CHANGES", "REMOVE_CONFIGURATION")


def lab_factory(**overrides):
    outputs = {name: h.eos_outputs(config=EOS_CONFIG.format(name=name)) for name in CEOS}
    outputs.update({name: h.linux_outputs(frr_config=FRR_CONFIG.format(name=name)) for name in LINUX})
    outputs.update(overrides)
    return h.session_factory(outputs)


class ScopeTests(SimpleTestCase):
    def setUp(self):
        use_scope(self)

    def test_exactly_the_nine_netbox_managed_devices_are_selectable_and_r5_is_not(self):
        rows = snapshots.workbench_devices()
        self.assertEqual([row["name"] for row in rows], sorted(LAB_MANAGED))
        self.assertNotIn("R5", {row["name"] for row in rows})
        for name in LAB_MANAGED:
            with self.subTest(device=name):
                self.assertEqual(scope.resolve(name), (scope.workbench_scope().get(name), ""))

    def test_r5_is_out_of_scope_not_unknown_and_an_unknown_name_is_not_found(self):
        self.assertEqual(scope.resolve("R5"), (None, "DEVICE_OUT_OF_SCOPE"))
        for name in ("R9", "10.0.0.1", "r1", ""):
            with self.subTest(name=name):
                self.assertEqual(scope.resolve(name), (None, "DEVICE_NOT_FOUND"))

    def test_scope_comes_from_netbox_not_from_a_name_list(self):
        with mock.patch.object(scope, "NETBOX_MANAGED", managed(("R1", "R5"))):   # NetBox, not code, decides
            self.assertEqual([row["name"] for row in snapshots.workbench_devices()], ["R1", "R5"])

    def test_netbox_unavailable_fails_closed(self):
        with mock.patch.object(scope, "NETBOX_MANAGED", unavailable):
            current = scope.workbench_scope()
            self.assertEqual(current.devices, [])
            self.assertTrue(current.unavailable)
            self.assertEqual(scope.resolve("R1"), (None, "MANAGEMENT_SCOPE_UNAVAILABLE"))

    def test_platform_mapping_and_transport(self):
        for name in CEOS:
            with self.subTest(device=name):
                row = scope.workbench_scope().get(name)
                self.assertEqual(row["platform"], models.Platform.ARISTA_CEOS)
                self.assertTrue(row["transport"].startswith("netmiko-ssh"))
                self.assertIs(live.default_session_factory(bootstrap_capture.managed_scope()[name]), live.EosSession)
        for name in LINUX:
            with self.subTest(device=name):
                row = scope.workbench_scope().get(name)
                self.assertEqual(row["platform"], models.Platform.UBUNTU_FRR)
                self.assertIs(live.default_session_factory(bootstrap_capture.managed_scope()[name]), live.LinuxSession)

    def test_legacy_bootstrap_capture_scope_is_not_narrowed(self):
        self.assertIn("R5", bootstrap_capture.managed_scope())


class CaptureTests(TestCase):
    def setUp(self):
        use_scope(self)

    def test_every_managed_device_captures_persists_digest_and_timestamp(self):
        factory = lab_factory()
        for name in CEOS + LINUX:
            with self.subTest(device=name):
                outcome = snapshots.capture(name, actor="tester", session_factory=factory, now=h.NOW)
                self.assertEqual((outcome.code, outcome.message), ("", ""))
                stored = models.RunningConfigSnapshot.objects.get(snapshot_id=outcome.snapshot.snapshot_id)
                self.assertEqual(stored.device_name, name)
                self.assertEqual(len(stored.digest), 64)
                self.assertIsNotNone(stored.captured_at)
                self.assertIn(f"hostname {name}", stored.text)
                self.assertNotIn("TEST_ONLY_WORKBENCH_SECRET_NEVER_REAL", stored.text)

    def test_ubuntu_capture_uses_only_linux_allowlist_keys(self):
        factory = lab_factory()
        for name in LINUX:
            snapshots.capture(name, session_factory=factory, now=h.NOW)
        ran = {key for device, session in factory.created if device in LINUX for key in session.ran}
        self.assertTrue(ran and ran <= set(live.LINUX_COMMANDS), ran)
        self.assertNotIn("running_config", ran)   # the EOS command key is never used for R3/R4

    def test_r5_and_unknown_names_are_refused_before_any_device_contact(self):
        factory = lab_factory(R5=h.eos_outputs(config="hostname R5\n"))
        for name, code in (("R5", "DEVICE_OUT_OF_SCOPE"), ("R9", "DEVICE_NOT_FOUND")):
            with self.subTest(device=name):
                outcome = snapshots.capture(name, session_factory=factory)
                self.assertEqual(outcome.code, code)
                self.assertTrue(outcome.refused_request)
        self.assertEqual(factory.created, [])
        self.assertFalse(models.RunningConfigSnapshot.objects.exists())

    def test_distinct_sanitized_outcomes(self):
        cases = {
            "CREDENTIAL_NOT_CONFIGURED": live.LiveError("CREDENTIAL_NOT_CONFIGURED"),
            "ACCESS_TARGET_NOT_CONFIGURED": live.LiveError("NOT_CONFIGURED"),
            "AUTHENTICATION_FAILED": live.LiveError("AUTH_FAILED"),
            "CONNECTION_FAILED": live.LiveError("TIMEOUT"),
        }
        seen = set()
        for code, error in cases.items():
            with self.subTest(code=code):
                outcome = snapshots.capture("R2", session_factory=h.session_factory(fail={"R2": error}))
                self.assertEqual(outcome.code, code)
                self.assertTrue(outcome.message.startswith(f"{code}: "))
                self.assertFalse(outcome.refused_request)
                seen.add(outcome.code)
        broken = h.eos_outputs(config="x")
        broken["running_config"] = live.LiveError("COMMAND_FAILED")
        self.assertEqual(snapshots.capture("R2", session_factory=h.session_factory({"R2": broken})).code, "RETRIEVAL_FAILED")
        odd = {"R7": {"name": "R7", "platform": "srlinux", "address": "", "address_v6": "", "container": ""}}
        with mock.patch.object(bootstrap_capture, "managed_scope", return_value=odd), \
                mock.patch.object(scope, "NETBOX_MANAGED", managed(("R7",))):
            self.assertEqual(snapshots.capture("R7").code, "UNSUPPORTED_PLATFORM")
        with mock.patch.object(scope, "NETBOX_MANAGED", unavailable):
            self.assertEqual(snapshots.capture("R1").code, "MANAGEMENT_SCOPE_UNAVAILABLE")
        self.assertEqual(len(seen), len(cases))
        self.assertFalse(models.RunningConfigSnapshot.objects.exists())

    def test_database_unavailable_is_reported_and_the_device_is_not_contacted(self):
        factory = lab_factory()
        with mock.patch.object(models.RunningConfigSnapshot.objects, "exists", side_effect=OperationalError("no such table: core_runningconfigsnapshot")):
            outcome = snapshots.capture("R3", session_factory=factory)
        self.assertEqual(outcome.code, "SNAPSHOT_DATABASE_UNAVAILABLE")
        self.assertNotIn("core_runningconfigsnapshot", outcome.message)
        self.assertEqual(factory.created, [])
        with mock.patch.object(models.RunningConfigSnapshot.objects, "create", side_effect=OperationalError("disk I/O error")):
            self.assertEqual(snapshots.capture("R4", session_factory=factory).code, "SNAPSHOT_DATABASE_UNAVAILABLE")

    def test_recheck_reports_a_stale_snapshot(self):
        snapshot = snapshots.capture("S1", session_factory=lab_factory(), now=h.NOW).snapshot
        self.assertEqual(snapshots.recheck(snapshot, session_factory=lab_factory())["error"], "")
        changed = lab_factory(S1=h.eos_outputs(config="hostname S1\nvlan 99\n"))
        self.assertEqual(snapshots.recheck(snapshot, session_factory=changed), {"current": False, "digest": mock.ANY, "error": "SNAPSHOT_STALE"})


class CredentialRoutingTests(TestCase):
    """The cEOS capture reaches the device only through the canonical device-aware resolver (never a GUI-chosen account)."""

    def setUp(self):
        use_scope(self)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Path(self.tmp.name) / "store.json"
        patcher = mock.patch.object(device_credentials, "DEFAULT_STORE", self.store)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_missing_runtime_credential_store_is_credential_not_configured(self):
        """The live R1 symptom: a checkout without the runtime store used to surface as NOT_CONFIGURED."""
        with mock.patch("netmiko.ConnectHandler", side_effect=AssertionError("must not connect")):
            for name in CEOS:
                with self.subTest(device=name):
                    self.assertEqual(snapshots.capture(name).code, "CREDENTIAL_NOT_CONFIGURED")

    def test_capture_uses_the_resolver_route_and_only_show_commands(self):
        provider = device_credentials.FileSecretProvider(self.store)
        provider.initialize("runtime://device-credentials/r1-nmas-automation", "TEST_ONLY_R1_VALUE")
        provider.initialize("runtime://device-credentials/r2-nmas-automation", "TEST_ONLY_R2_VALUE")
        conn = mock.MagicMock()
        conn.check_enable_mode.return_value = True
        conn.send_command.side_effect = lambda command, **kw: "hostname X\n" if command == "show running-config" else "{}"
        for forbidden in ("config_mode", "send_config_set", "send_config_from_file", "save_config", "commit"):
            getattr(conn, forbidden).side_effect = AssertionError(f"{forbidden} must never be called")
        with mock.patch("netmiko.ConnectHandler", return_value=conn) as connect, \
                mock.patch.object(nsot_live, "get_live_target", wraps=nsot_live.get_live_target) as resolver:
            migrated = snapshots.capture("R1")
            first_user = connect.call_args.kwargs["username"]
            second = snapshots.capture("R2")
            second_user = connect.call_args.kwargs["username"]
        self.assertEqual((migrated.code, second.code), ("", ""))
        self.assertEqual([c.args[0] for c in resolver.call_args_list], ["R1", "R2"])
        self.assertEqual(first_user, "nmas-automation")
        self.assertEqual(second_user, "nmas-automation")
        self.assertTrue(all(c.args[0].startswith("show ") for c in conn.send_command.call_args_list))
        for outcome in (migrated, second):
            self.assertNotIn("TEST_ONLY", outcome.snapshot.text + outcome.message)

    def test_eos_session_distinguishes_absent_target_from_absent_credential(self):
        with self.assertRaises(live.LiveError) as raised:
            live.EosSession({"name": "R2"})
        self.assertEqual(raised.exception.code, "CREDENTIAL_NOT_CONFIGURED")
        with self.assertRaises(live.LiveError) as raised:
            live.EosSession({"name": "R5"})       # address: auto -> no SSH target at all
        self.assertEqual(raised.exception.code, "NOT_CONFIGURED")


class PageTests(TestCase):
    def setUp(self):
        use_scope(self)
        patcher = mock.patch.object(snapshots, "SESSION_FACTORY", lab_factory())
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_both_dropdowns_offer_the_nine_managed_devices_and_never_r5(self):
        for page in ("core:workbench_changes", "core:workbench_remove"):
            html = self.client.get(reverse(page)).content.decode()
            with self.subTest(page=page):
                for name in LAB_MANAGED:
                    self.assertIn(f'<option value="{name}"', html)
                self.assertNotIn('<option value="R5"', html)

    def test_both_workflows_use_the_one_shared_capture(self):
        with mock.patch.object(snapshots, "capture", wraps=snapshots.capture) as shared:
            for workflow in WORKFLOWS:
                response = self.client.post(reverse("core:workbench_snapshot"), {"device": "R3", "workflow": workflow})
                self.assertEqual(response.status_code, 302)
                self.assertIn("snapshot=", response["Location"])
        self.assertEqual([c.args[0] for c in shared.call_args_list], ["R3", "R3"])

    def test_captured_page_shows_numbered_config_timestamp_and_digest(self):
        for workflow, page in zip(WORKFLOWS, ("core:workbench_changes", "core:workbench_remove")):
            location = self.client.post(reverse("core:workbench_snapshot"), {"device": "R1", "workflow": workflow})["Location"]
            html = self.client.get(location).content.decode()
            with self.subTest(page=page):
                self.assertIn('<span class="rc-no" aria-hidden="true">1</span><code>hostname R1</code>', html)
                self.assertIn("captured ", html)
                self.assertIn("digest <code", html)
                self.assertNotIn("TEST_ONLY_WORKBENCH_SECRET_NEVER_REAL", html)

    def test_crafted_r5_post_is_refused_as_out_of_scope(self):
        for workflow in WORKFLOWS:
            response = self.client.post(reverse("core:workbench_snapshot"), {"device": "R5", "workflow": workflow})
            self.assertEqual(response.status_code, 400)
            self.assertTrue(response.content.decode().startswith("DEVICE_OUT_OF_SCOPE: "))
            self.assertTrue(response["Content-Type"].startswith("text/plain"))
        response = self.client.post(reverse("core:workbench_snapshot"), {"device": "<b>R9</b>", "workflow": WORKFLOWS[0]})
        self.assertEqual((response.status_code, response["Content-Type"].split(";")[0]), (400, "text/plain"))
        self.assertFalse(models.RunningConfigSnapshot.objects.exists())

    def test_runtime_failure_redirects_with_the_sanitized_code(self):
        failing = h.session_factory(fail={"R2": live.LiveError("AUTH_FAILED")})
        with mock.patch.object(snapshots, "SESSION_FACTORY", failing):
            response = self.client.post(reverse("core:workbench_snapshot"), {"device": "R2", "workflow": WORKFLOWS[1]})
        self.assertEqual(response.status_code, 302)
        html = self.client.get(response["Location"]).content.decode()
        self.assertIn("AUTHENTICATION_FAILED", html)
        self.assertNotIn("NOT_CONFIGURED", html)

    def test_scope_unavailable_page_explains_and_offers_nothing(self):
        with mock.patch.object(scope, "NETBOX_MANAGED", unavailable):
            html = self.client.get(reverse("core:workbench_remove")).content.decode()
        self.assertIn('data-component="scope-unavailable"', html)
        self.assertNotIn('<option value="R1"', html)


class SchemaTests(TestCase):
    def test_running_config_snapshot_table_is_created_by_a_migration_and_there_is_no_drift(self):
        loader = MigrationLoader(None, ignore_no_migrations=True)
        creators = [key for key, migration in loader.disk_migrations.items() if key[0] == "core"
                    and any(isinstance(op, CreateModel) and op.name == "RunningConfigSnapshot" for op in migration.operations)]
        self.assertEqual(creators, [("core", "0013_automation_config_workflows")])
        call_command("makemigrations", "core", "--check", "--dry-run", verbosity=0)
