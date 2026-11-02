from django.test import TestCase
from django.urls import reverse

from core.services.automation_service import get_automation_sections
from core.tests.helpers.candidates import make_candidate
from core.tests.helpers.fakes import netbox_unreachable


class RouteSmokeTests(TestCase):
    """Every top-level page loads (HTTP 200), with external sources faked.

    This is the ONE route-smoke test.  Earlier phases each re-asserted "home /
    NSOT / monitoring still load" in their own module (three copies); add a
    route here instead.  NetBox is faked unreachable so the NSOT page degrades
    instantly rather than making a real connection.
    """

    def test_every_top_level_route_loads(self):
        change, intent, _ = make_candidate()
        names = {
            "core:home": [],
            "core:monitoring_landing": [],
            "core:monitoring_resources": [],
            "core:monitoring_link_events": [],
            "core:monitoring_link_state_traffic": [],
            "core:device_builder": [],
            "core:device_builder_changes": [],
            "core:device_builder_change_detail": [change.change_id],
            "core:nsot": [],
            "core:automation_landing": [],
            "core:notifications": [],
            "core:profile": [],
        }
        with netbox_unreachable():
            for name, args in names.items():
                with self.subTest(route=name):
                    self.assertEqual(self.client.get(reverse(name, args=args)).status_code, 200)

    def test_changes_list_loads_when_empty_and_get_never_mutates(self):
        from core import models

        self.assertEqual(self.client.get(reverse("core:device_builder_changes")).status_code, 200)
        change, _, _ = make_candidate()
        before = models.Change.objects.count()
        self.client.get(reverse("core:device_builder_change_detail", args=[change.change_id]))
        self.client.get(reverse("core:device_builder_changes"))
        change.refresh_from_db()
        self.assertEqual(models.Change.objects.count(), before)
        self.assertEqual(change.lifecycle_state, models.ChangeLifecycleState.DRAFT)

    def test_automation_section_shells_load_and_unknown_section_is_404(self):
        for section in get_automation_sections():
            with self.subTest(slug=section["slug"]):
                self.assertEqual(self.client.get(reverse("core:automation_section", args=[section["slug"]])).status_code, 200)
        self.assertEqual(self.client.get(reverse("core:automation_section", args=["not-a-real-section"])).status_code, 404)
