"""Platform driver registry and the candidate-renderer contract (accepted vs draft, diff, honesty)."""

from __future__ import annotations

import ast
import inspect

from django.test import TestCase

from core import models
from core.services import candidate_renderer, intent_service, platform_drivers
from core.tests.helpers.candidates import commit, make_candidate


class PlatformDriverRegistryTests(TestCase):
    def test_registry_covers_every_platform_and_rejects_unknown_ones(self):
        self.assertEqual(set(platform_drivers.PLATFORM_DRIVERS), set(models.Platform.values))
        with self.assertRaises(ValueError):
            platform_drivers.get_driver("junos")

    def test_drivers_return_descriptors_and_never_fabricate_vendor_cli(self):
        for driver in platform_drivers.PLATFORM_DRIVERS.values():
            with self.subTest(platform=driver.name):
                descriptors = driver.render_candidate(field_values={"device.hostname": "R1"})
                self.assertIsInstance(descriptors, list)
                self.assertTrue(all(d["kind"] in ("static", "field") for d in descriptors))
        unsupported = {
            "SR Linux": (platform_drivers.SrLinuxDriver(), ""),
            "Ubuntu/FRR without a hostname": (platform_drivers.UbuntuFrrDriver(), ""),
            "Catalyst 8000V / IOS XE": (platform_drivers.C8000vIosXeDriver(), ""),
            "IOS XR": (platform_drivers.IosXrDriver(), ""),
            # SONiC now genuinely renders config_db JSON (Phase 20.5); the honest "nothing to
            # render" gate is the same as the other platforms: no hostname AND no other intent.
            "SONiC (nothing configured)": (platform_drivers.SonicDriver(), ""),
        }
        for label, (driver, hostname) in unsupported.items():
            with self.subTest(driver=label):
                self.assertEqual(driver.render_candidate(field_values={"device.hostname": hostname}), [platform_drivers.NOT_IMPLEMENTED_LINE])

    def test_no_hostname_conditionals_in_the_driver_or_renderer_source(self):
        """Behavior comes from platform + structured intent, never ``if hostname == "R1"``."""
        forbidden = {"R1", "R2", "R3", "R4", "R5"}
        for module in (platform_drivers, candidate_renderer):
            literals = [
                node.value for node in ast.walk(ast.parse(inspect.getsource(module)))
                if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value in forbidden
            ]
            with self.subTest(module=module.__name__):
                self.assertEqual(literals, [], "hardcoded device-name literal")
        self.assertIn("get_driver(intent.platform)", inspect.getsource(candidate_renderer))


class CandidateRendererTests(TestCase):
    def test_render_reflects_accepted_state_and_only_shows_drafts_when_asked(self):
        change, intent, revision = make_candidate()
        candidate = candidate_renderer.render(intent, revision)
        for fragment in ("hostname R1", "Candidate Configuration", "Not deployed"):
            self.assertIn(fragment, candidate["text"])
        self.assertEqual(candidate["header_lines"][0], "! Candidate Configuration")  # the browser reuses the server's header
        commit(change, intent, revision, "device.hostname", "R1-new")
        self.assertIn("hostname R1-new", candidate_renderer.render(intent, revision)["text"])
        intent_service.set_draft_field(revision=revision, path="device.hostname", draft_value="UNACCEPTED-DRAFT")
        self.assertIn("hostname R1-new", candidate_renderer.render(intent, revision, use_draft=False)["text"])
        self.assertIn("hostname UNACCEPTED-DRAFT", candidate_renderer.render(intent, revision, use_draft=True)["text"])

    def test_a_platform_with_nothing_configured_says_so_instead_of_inventing_config(self):
        """SONiC now genuinely renders config_db JSON for real intent (Phase
        20.5); with truly nothing configured it still honestly says so
        rather than fabricating output."""
        _, intent, revision = make_candidate(platform=models.Platform.SONIC, device_name="S1")
        revision.field_states.filter(path="device.hostname").update(accepted_value="")
        text = candidate_renderer.render(intent, revision)["text"]
        self.assertIn("not implemented yet", text)
        self.assertNotIn("hostname S1", text)
        self.assertNotIn("DEVICE_METADATA", text)

    def test_diff_is_identical_without_draft_and_shows_divergence_with_one(self):
        _, intent, revision = make_candidate()
        diff = candidate_renderer.diff_accepted_vs_draft(intent, revision)
        self.assertTrue(diff["identical"])
        self.assertEqual(diff["diff_lines"], [])
        intent_service.set_draft_field(revision=revision, path="device.hostname", draft_value="DIFFERENT")
        diff = candidate_renderer.diff_accepted_vs_draft(intent, revision)
        self.assertFalse(diff["identical"])
        self.assertTrue(any("DIFFERENT" in line for line in diff["diff_lines"]))
