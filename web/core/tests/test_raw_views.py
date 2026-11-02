"""Phase-18 HTTP boundaries.  Representative rows only: the behaviour lives in the services (see ``test_raw_configlets`` /
``test_raw_integration``); these tests prove the browser can do nothing but what the boundary allows."""

from __future__ import annotations

from types import SimpleNamespace
from unittest import mock

from core.tests.runner import OperatorClient  # V2 Phase 1: authenticated, MFA-verified operator
from django.test import TestCase
from django.urls import reverse

from core import models
from core.services import raw_configlet_service as rcs
from core.services.raw_configlets import adapters
from core.tests.helpers import raw as rh
from core.tests.helpers.validation import Dev

TOKEN = "gh" + "p_" + "A1b2C3d4E5" * 4


def url(name, change, *args):
    return reverse(f"core:{name}", args=[change.change_id, *args])


def counts():
    return tuple((m.domain if m is models.AuditEvent else m.objects).count() for m in (models.RawConfiglet, models.RawConfigletRevision, models.RawConfigletVerificationRun,
                                            models.ChangePlan, models.ChangeValidationRun, models.ChangeExecutionRun, models.AuditEvent))


def form(**overrides):
    return {"target_device": "R1", "name": "Loopback", "description": "", "priority": "6", "content": rh.EOS_TEXT,
            "dependencies": "", "assertions": "", **overrides}


class RawViewTests(TestCase):
    def setUp(self):
        self.p = rh.raw_change()
        self.change, self.raw = self.p.change, self.p.raw
        self.client = OperatorClient()

    def scripted_registry(self):
        registry, ceos, frr = rh.fakes()
        return mock.patch.dict(adapters.REGISTRY, registry), ceos

    def test_get_pages_never_verify_plan_or_execute_and_show_the_raw_status_unmistakably(self):
        pages = [url("raw_configlets", self.change), url("raw_configlet_new", self.change), url("raw_configlet_detail", self.change, "RAW-001"),
                 url("raw_configlet_revision", self.change, "RAW-001", 1), url("device_builder_change_detail", self.change)]
        before = counts()
        with mock.patch.object(rcs.verification, "request_verification", side_effect=AssertionError("GET must not verify")), \
                mock.patch("core.services.raw_configlets.verifier.verify_raw_configlet", side_effect=AssertionError("GET must not start a sandbox")), \
                mock.patch("core.views.execution_service.execute_change", side_effect=AssertionError("GET must not execute")):
            for page in pages:
                with self.subTest(page=page):
                    response = self.client.get(page)
                    self.assertEqual(response.status_code, 200)
        self.assertEqual(counts(), before)
        body = self.client.get(url("raw_configlet_detail", self.change, "RAW-001")).content.decode()
        self.assertIn("RAW", body)
        self.assertIn("Never verified", body)
        self.assertIn("Typing here changes nothing", body)
        self.assertIn(url("raw_configlets", self.change), self.client.get(url("device_builder_change_detail", self.change)).content.decode())

    def test_every_mutation_is_post_only_and_csrf_protected(self):
        targets = [url("raw_configlet_create", self.change), url("raw_configlet_save", self.change, "RAW-001"),
                   url("raw_configlet_verify", self.change, "RAW-001"), url("raw_configlet_toggle", self.change, "RAW-001")]
        strict = OperatorClient(enforce_csrf_checks=True)
        before = counts()
        for target in targets:
            with self.subTest(target=target):
                self.assertEqual(self.client.get(target).status_code, 405)
                self.assertEqual(strict.post(target, form()).status_code, 403)
        self.assertEqual(counts(), before)
        self.assertIn("csrfmiddlewaretoken", self.client.get(url("raw_configlet_detail", self.change, "RAW-001")).content.decode())

    def test_saving_creates_immutable_revisions_and_the_server_rejects_every_unsafe_or_unsupported_input(self):
        Dev(self.change, "SRL", platform=models.Platform.NOKIA_SRLINUX)
        created = self.client.post(url("raw_configlet_create", self.change), form(name="second", content=rh.EOS_TEXT_2))
        self.assertEqual((created.status_code, created["Location"].split("?")[0]), (302, url("raw_configlet_detail", self.change, "RAW-002")))
        saved = self.client.post(url("raw_configlet_save", self.change, "RAW-001"), form(content=rh.EOS_TEXT + "   no shutdown\n"))
        self.assertEqual(saved.status_code, 302)
        self.assertEqual(list(self.raw.revisions.values_list("revision", flat=True)), [1, 2])
        self.assertEqual(self.raw.revisions.get(revision=1).content, rh.EOS_TEXT)            # the old revision is untouched
        rows = [
            ("secret", form(content="username x secret sha512 $6$abc\n"), "RAW_SECRET_SHAPED_CONTENT"),
            ("token", form(description=TOKEN), "RAW_NAME_INVALID"),
            ("host shell", form(content="bash -c id\n"), "RAW_HOST_SHELL_COMMAND"),
            ("unsupported platform", form(target_device="SRL"), "RAW_PLATFORM_UNSUPPORTED"),
            ("assertion outside the catalogue", form(assertions="SHOW_COMMAND cmd=version"), "RAW_ASSERTION_INVALID"),
            ("oversized", form(content="hostname r1\n" + "!" * 40_000), "RAW_TOO_LARGE"),
        ]
        before = counts()
        for case, data, code in rows:
            with self.subTest(case=case):
                response = self.client.post(url("raw_configlet_save", self.change, "RAW-001"), data)
                self.assertEqual(response.status_code, 400)
                self.assertContains(response, code, status_code=400)
                self.assertNotContains(response, TOKEN, status_code=400)          # a refused secret is never echoed back
        self.assertEqual(counts(), before)                                       # nothing persisted, no audit noise

    def test_verify_is_an_explicit_post_that_names_only_a_revision_number_and_never_takes_text_from_the_browser(self):
        patcher, ceos = self.scripted_registry()
        with patcher:
            stale_editor = self.client.post(url("raw_configlet_verify", self.change, "RAW-001"), {"revision": "99"})
            self.assertIn("error=REVISION_SUPERSEDED", stale_editor["Location"])
            self.assertEqual(ceos.calls, [])
            response = self.client.post(url("raw_configlet_verify", self.change, "RAW-001"),
                                        {"revision": "1", "content": "bash -c evil", "command": "rm -rf /", "image": "attacker/img", "platform": "x"})
            self.assertEqual(response.status_code, 302)
            self.assertEqual(ceos.calls, [self.p.revision.content])                   # the sandbox saw the stored revision, nothing the browser sent
            run = models.RawConfigletVerificationRun.objects.get()
            self.assertEqual((run.result, run.revision_id), ("PASS", self.p.revision.pk))
            self.client.post(url("raw_configlet_verify", self.change, "RAW-001"), {"revision": "1"})
            self.assertEqual(len(ceos.calls), 1)                                      # a CURRENT acceptable result is reused, not re-run
        detail = self.client.get(response["Location"])
        self.assertContains(detail, "CURRENT")
        self.assertContains(detail, "Append-only")
        self.assertContains(self.client.get(url("raw_configlet_detail", self.change, "RAW-001")), "Current / PASS")

    def test_stale_and_never_verified_render_correctly_and_a_new_revision_starts_unverified(self):
        patcher, _ = self.scripted_registry()
        with patcher:
            self.client.post(url("raw_configlet_verify", self.change, "RAW-001"), {"revision": "1"})
            with mock.patch("core.services.raw_configlets.codes.POLICY_VERSION", "18.9.9-static"):
                stale = self.client.get(url("raw_configlet_detail", self.change, "RAW-001")).content.decode()
            self.assertIn("Stale", stale)
            self.assertIn("POLICY_VERSION_CHANGED", stale)
            self.client.post(url("raw_configlet_save", self.change, "RAW-001"), form(content=rh.EOS_TEXT + "   no shutdown\n"))
            self.assertIn("Never verified", self.client.get(url("raw_configlet_detail", self.change, "RAW-001")).content.decode())
            self.assertIn("Current / PASS", self.client.get(url("raw_configlet_revision", self.change, "RAW-001", 1)).content.decode())   # rev 1 keeps its own

    def test_historical_revisions_and_verification_runs_are_read_only(self):
        self.client.post(url("raw_configlet_save", self.change, "RAW-001"), form(content=rh.EOS_TEXT + "   no shutdown\n"))
        page = self.client.get(url("raw_configlet_revision", self.change, "RAW-001", 1))
        body = page.content.decode()
        self.assertEqual(page.status_code, 200)
        self.assertIn("Read-only", body)
        self.assertNotIn("<textarea", body)                                             # no editor ...
        self.assertNotIn('name="content"', body)
        self.assertNotIn(url("raw_configlet_save", self.change, "RAW-001"), body)     # ... and no save / verify / toggle action on a revision
        self.assertNotIn(url("raw_configlet_verify", self.change, "RAW-001"), body)
        self.assertEqual(self.client.post(url("raw_configlet_revision", self.change, "RAW-001", 1), form()).status_code, 405)
        self.assertEqual(self.client.get(url("raw_configlet_revision", self.change, "RAW-001", 7)).status_code, 404)
        other = rh.verified()                                                          # another Change's verification is not addressable here
        before = counts()
        self.assertEqual(self.client.get(url("raw_configlet_detail", self.change, "RAW-009")).status_code, 404)
        self.assertEqual(self.client.get(url("raw_configlet_verification", self.change, "RAW-001", other.run.run_id)).status_code, 404)
        self.assertEqual(counts(), before)

    def test_removing_from_the_change_is_soft_and_accepts_only_zero_or_one(self):
        self.assertEqual(self.client.post(url("raw_configlet_toggle", self.change, "RAW-001"), {"enabled": "maybe"}).status_code, 400)
        self.client.post(url("raw_configlet_toggle", self.change, "RAW-001"), {"enabled": "0"})
        self.raw.refresh_from_db()
        self.assertFalse(self.raw.enabled)
        self.assertEqual(self.raw.revisions.count(), 1)                                # history preserved
        self.assertIn("removed", self.client.get(url("raw_configlets", self.change)).content.decode())

    def test_the_browser_cannot_inject_an_execution_payload_and_there_is_no_raw_execute_route(self):
        with mock.patch("core.views.execution_service.execute_change", return_value=SimpleNamespace(run=None)) as engine:
            self.client.post(url("change_execute_run", self.change), {
                "confirm_mode": "COMPLETE", "through_cfg_id": "CFG-001", "content": "bash -c evil", "command": "reload", "raw_id": "RAW-001",
                "raw_revision": "1", "device": "R9",
            })
        kwargs = engine.call_args.kwargs
        self.assertEqual(set(kwargs), {"actor", "through_cfg_id", "acknowledgements", "confirm_mode"})
        self.assertNotIn("bash", repr(kwargs))
        for suffix in ("execute/", "run/", "apply/"):
            self.assertEqual(self.client.post(url("raw_configlet_detail", self.change, "RAW-001") + suffix, form()).status_code, 404)
