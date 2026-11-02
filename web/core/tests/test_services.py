from django.test import TestCase

from core.services import (
    automation_service,
    device_builder_service,
    monitoring_service,
    nsot_service,
    topology_service,
)

# Remaining placeholder summaries must be honest "not yet integrated" shapes.
# Monitoring graduated from this list in Phase 6, NSOT in Phase 7, Device
# Builder in Phase 9 (Device Identity editing is now real); all four are
# tested separately as real adapters below.
SUMMARY_FUNCTIONS = [
    automation_service.get_automation_summary,
]


class ServiceBoundaryTests(TestCase):
    def test_graduated_subsystems_are_real_adapters_not_placeholders(self):
        adapters = {
            "topology": topology_service.get_topology_summary,
            "monitoring": monitoring_service.get_monitoring_summary,
            "nsot": nsot_service.get_nsot_summary,
            "device_builder": device_builder_service.get_device_builder_summary,
        }
        for name, fn in adapters.items():
            with self.subTest(subsystem=name):
                self.assertTrue(callable(fn))
                self.assertNotIn(fn, SUMMARY_FUNCTIONS)
        result = device_builder_service.get_device_builder_summary()
        self.assertEqual(result["status"], "operational")
        self.assertIn("total_changes", result)

    def test_remaining_placeholder_summaries_are_honest_and_fabricate_nothing(self):
        forbidden_keys = {"devices_up", "devices_down", "health", "cpu_percent"}
        for fn in SUMMARY_FUNCTIONS:
            with self.subTest(fn=fn.__qualname__):
                result = fn()
                self.assertEqual(result["status"], "not_integrated")
                self.assertTrue(result["message"])
                self.assertTrue(forbidden_keys.isdisjoint(result.keys()))

    def test_monitoring_dashboard_metadata_matches_taxonomy(self):
        resources = monitoring_service.get_dashboard_metadata("resources")
        self.assertEqual(resources["grafana_uid"], "nmas-resources")
        link_events = monitoring_service.get_dashboard_metadata("link_events")
        self.assertEqual(link_events["grafana_uid"], "nmas-link-events")
        traffic = monitoring_service.get_dashboard_metadata("link_state_traffic")
        self.assertEqual(traffic["grafana_uid"], "nmas-link-state-traffic")

    def test_only_graduated_automation_sections_are_marked_implemented(self):
        # Phase 15 graduated Fleet Health / Per-Device Health; the one-time legacy bootstrap added "Initial Golden
        # Bootstrap"; Phase 20 graduated Soak Management; Phase 22 points "Configuration Changes" / "Change History"
        # at the real Device Builder Change lifecycle (Draft/Validate/Plan/Render/Execute/Verify, Phases 8-21).
        # Phase 23 added the read-only "Device Credentials" page, and the automation workbench gave "Configuration
        # Changes" its own incremental-patch page (no longer Device Builder's Changes list) and "Remove Configuration" a
        # real, dependency-aware removal page.  "Rollback / Recovery" and "Troubleshooting" have no dedicated operator
        # page yet and remain honest shells (docs/AUTOMATION_CONFIGURATION_WORKFLOWS.md).  V2 Phase 3 added the
        # "Template Library" (intent templates; using one only ever creates a Draft Change).  V2 Phase 5A added "New Device
        # Provisioning" (the staged request over the ordinary Change lifecycle).  V2 Maintenance Mode added "Maintenance
        # Mode" (its entry and restore are queued for the maintenance worker; the page itself contacts no device).  Lab 7 added the
        # read-only "Unit Test Matrix" and "Code Coverage" pages (persisted Tier-3 evidence; nothing runs on a page view).
        sections = automation_service.get_automation_sections()
        self.assertEqual(len(sections), 16)
        implemented = {section["slug"] for section in sections if section["implemented"]}
        self.assertEqual(implemented, {"fleet-health", "per-device-health", "initial-golden-bootstrap", "configuration-changes",
                                       "remove-configuration", "change-history", "soak-management", "credential-management",
                                       "template-library", "new-device-provisioning", "traffic-test-workbench", "maintenance-mode",
                                       "unit-test-matrix", "code-coverage"})
        self.assertEqual(automation_service.IMPLEMENTED_SECTIONS["new-device-provisioning"], "core:provisioning_list")
        self.assertEqual(automation_service.IMPLEMENTED_SECTIONS["template-library"], "core:template_library")
        self.assertEqual(automation_service.IMPLEMENTED_SECTIONS["configuration-changes"], "core:workbench_changes")
        self.assertEqual(automation_service.IMPLEMENTED_SECTIONS["remove-configuration"], "core:workbench_remove")
        self.assertEqual(implemented, set(automation_service.IMPLEMENTED_SECTIONS))

    def test_automation_section_slugs_are_unique(self):
        sections = automation_service.get_automation_sections()
        slugs = [s["slug"] for s in sections]
        self.assertEqual(len(slugs), len(set(slugs)))
