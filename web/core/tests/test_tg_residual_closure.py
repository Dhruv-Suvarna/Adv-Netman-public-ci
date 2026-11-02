"""Lab 7 closure: the last offline current-scope cases found by the full evidence run.

* durable-history model guards (``delete`` on LegacyBootstrapDecision / CredentialRotationRun / ProvisionedDevice, the
  template-version queryset's ``bulk_update`` / ``delete``), called directly;
* the offline capability probe-case builders (``probe_cases.interface_name`` / ``iface`` / ``author``) and
  ``assessment.from_row``;
* the offline ``plan`` / ``imported`` helpers of the IOS XE and SR Linux capability batches (render, then parse);
* the governance schema loader with its cache cleared, so the call is a real load.

Every call is direct from the test body. The rows are created in the test database only; ``author`` reaches the
operator mutation API through a mock, so no revision is changed.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase, TestCase

from core import models
from core.services import interface_intent_service as interfaces
from core.services.capabilities import assessment, batch_iosxe, batch_srlinux, probe_cases
from core.services.test_governance import schema

HEX = "b" * 64


class DurableHistoryGuardTests(SimpleTestCase):
    """Each ``delete`` raises before touching the database, so unsaved instances prove the guard."""

    def test_durable_history_rows_raise_on_delete(self):
        for model, message in ((models.LegacyBootstrapDecision, "durable history"),
                               (models.CredentialRotationRun, "durable history"),
                               (models.ProvisionedDevice, "retire the device")):
            with self.subTest(model=model.__name__), self.assertRaisesMessage(ValueError, message):
                model().delete()


class TemplateVersionQuerySetTests(TestCase):
    def _draft(self):
        template = models.ConfigurationTemplate(template_id="TPL-R-001", name="r")
        template.save()
        version = models.ConfigurationTemplateVersion(template=template, version=1, digest=HEX)
        version.save()
        return template, version

    def test_bulk_update_raises_for_any_input(self):
        _template, version = self._draft()
        with self.assertRaisesMessage(ValueError, "cannot be bulk-updated"):
            models.ConfigurationTemplateVersion.objects.all().bulk_update([version], ["digest"])
        self.assertEqual(models.ConfigurationTemplateVersion.objects.get(pk=version.pk).digest, HEX)

    def test_a_draft_only_queryset_deletes_and_returns_the_count(self):
        template, version = self._draft()
        deleted, per_model = models.ConfigurationTemplateVersion.objects.filter(template=template).delete()
        self.assertEqual((deleted, per_model), (1, {"core.ConfigurationTemplateVersion": 1}))
        self.assertFalse(models.ConfigurationTemplateVersion.objects.filter(pk=version.pk).exists())


class ProbeCaseBuilderTests(SimpleTestCase):
    def test_interface_name_returns_each_platform_naming(self):
        self.assertEqual(probe_cases.interface_name("arista_ceos", "ROUTED_PHYSICAL"), "Ethernet1")
        self.assertEqual(probe_cases.interface_name("ubuntu_frr", "LOOPBACK"), "loopback44")
        self.assertEqual(probe_cases.interface_name("nokia_srlinux", "LOOPBACK"), "lo44")
        self.assertEqual(probe_cases.interface_name("cisco_c8000v_iosxe", "SUBINTERFACE"), "GigabitEthernet2.44")
        self.assertEqual(probe_cases.interface_name("ubuntu_frr", "SVI"), "vlan44")
        self.assertEqual(probe_cases.interface_name("arista_ceos", "MANAGEMENT"), "Management1")
        self.assertEqual(probe_cases.interface_name("ubuntu_frr", "BOND"), "bond44")

    def test_interface_name_of_an_unknown_platform_raises(self):
        with self.assertRaises(KeyError):
            probe_cases.interface_name("juniper_vmx", "ROUTED_PHYSICAL")

    def test_iface_builds_a_dual_stack_subinterface_row(self):
        row = probe_cases.iface("ubuntu_frr", "SUBINTERFACE")
        self.assertEqual((row["id"], row["name"], row["kind"], row["mode"]),
                         (probe_cases.IF, "eth1.44", "SUBINTERFACE", interfaces.KIND_MODES["SUBINTERFACE"]))
        self.assertEqual((row["parent_id"], row["encapsulation_vlan"], row["vlan_id"]), (probe_cases.PARENT, 44, None))
        self.assertEqual(sorted((a["family"], a["cidr"]) for a in row["addresses"].values()),
                         [("IPV4", "198.18.0.1/30"), ("IPV6", "2001:db8:44::1/64")])

    def test_iface_access_port_carries_its_vlan_only(self):
        row = probe_cases.iface("arista_ceos", "ACCESS")
        self.assertEqual((row["access_vlan"], row["addresses"], row["trunk_allowed_vlans"]), (44, {}, []))

    def test_iface_of_an_unknown_kind_raises(self):
        with self.assertRaises(KeyError):
            probe_cases.iface("arista_ceos", "HOLOGRAM")

    def test_author_dispatches_an_interface_feature_to_add_interface(self):
        feature = SimpleNamespace(family="interface", code="LOOPBACK", key="interface.LOOPBACK")
        with mock.patch.object(probe_cases.interfaces, "add_interface", return_value="added") as add:
            self.assertEqual(probe_cases.author("REV", "arista_ceos", feature), "added")
        add.assert_called_once_with(revision="REV", kind="LOOPBACK", name="Loopback44")

    def test_author_of_the_local_dhcp_server_is_a_field_boundary_only(self):
        feature = SimpleNamespace(family="service_policy", code="DHCP_LOCAL_SERVER", key="service_policy.DHCP_LOCAL_SERVER")
        self.assertIsNone(probe_cases.author(object(), "ubuntu_frr", feature))

    def test_author_of_an_unknown_feature_raises(self):
        feature = SimpleNamespace(family="service_policy", code="TELEPORT_IPV4", key="service_policy.TELEPORT_IPV4")
        with self.assertRaisesMessage(ValueError, "No authoring probe for service_policy.TELEPORT_IPV4"):
            probe_cases.author(object(), "arista_ceos", feature)


class AssessmentRowTests(TestCase):
    def test_from_row_returns_the_stored_assessment(self):
        row = models.CapabilityAssessment.objects.create(
            platform="arista_ceos", feature="routing.OSPFV2", probes={"RENDER": "PASS"}, evidence_ids=[3, 4],
            repository_head="c" * 40, runtime_version="4.32")
        cell = assessment.from_row(row)
        self.assertEqual((cell.platform, cell.feature, cell.repository_head, cell.runtime_version),
                         ("arista_ceos", "routing.OSPFV2", "c" * 40, "4.32"))
        self.assertEqual((cell.probes, cell.evidence_ids, cell.assessment_id), ({"RENDER": "PASS"}, [3, 4], row.pk))
        self.assertEqual(cell.assessed_at, row.recorded_at.isoformat())


class SchemaLoaderTests(SimpleTestCase):
    def test_load_schema_returns_the_report_schema(self):
        schema.load_schema.cache_clear()
        loaded = schema.load_schema()
        self.assertEqual(loaded["type"], "object")
        self.assertIn("payload_sha256", loaded["required"])
        self.assertIs(schema.load_schema(), loaded)


def _plan_text(module, key, *, object_types=None):
    """Prerequisites plus the rendered Configlet lines ``plan`` produced, optionally only some object types."""
    prerequisites, specs, _requirements, expected = module.plan(key)
    lines = list(prerequisites) + [line for spec in specs if object_types is None or spec.object_type in object_types
                                   for line in spec.lines]
    return expected, "\n".join(lines)


class CapabilityBatchOfflineHelperTests(SimpleTestCase):
    """``plan`` / ``imported`` of the IOS XE and SR Linux batches are offline: plan renders, imported parses text."""

    IOSXE_LOOPBACK = ("hostname R\n!\ninterface Loopback44\n ip address 198.18.0.1 255.255.255.252\n"
                      " ipv6 address 2001:DB8:44::1/64\n!\n")

    def test_plan_of_an_unknown_feature_raises(self):
        for module in (batch_iosxe, batch_srlinux):
            with self.subTest(module=module.__name__), self.assertRaises(KeyError):
                module.plan("interface.HOLOGRAM")

    def test_iosxe_imported_accepts_the_planned_route_and_a_running_loopback(self):
        expected, text = _plan_text(batch_iosxe, "routing.STATIC_IPV4")
        self.assertEqual(expected, {"prefix": "203.0.113.0/24", "next_hop": "198.18.0.2"})
        self.assertTrue(batch_iosxe.imported("routing.STATIC_IPV4", expected, text))
        expected = batch_iosxe.plan("interface.LOOPBACK")[3]
        self.assertTrue(batch_iosxe.imported("interface.LOOPBACK", expected, self.IOSXE_LOOPBACK))

    def test_iosxe_imported_is_false_when_the_route_or_interface_is_missing(self):
        route = {"prefix": "203.0.113.0/24", "next_hop": "198.18.0.2"}
        self.assertFalse(batch_iosxe.imported("routing.STATIC_IPV4", route, self.IOSXE_LOOPBACK))
        wrong_kind = {"interface": "Loopback44", "kind": "SUBINTERFACE", "addresses": ["198.18.0.1/30"]}
        self.assertFalse(batch_iosxe.imported("interface.SUBINTERFACE", wrong_kind, self.IOSXE_LOOPBACK))
        absent = {"interface": "Loopback45", "kind": "LOOPBACK", "addresses": []}
        self.assertFalse(batch_iosxe.imported("interface.LOOPBACK", absent, self.IOSXE_LOOPBACK))

    def test_srlinux_imported_accepts_the_planned_route_and_subinterface(self):
        for key in ("routing.STATIC_IPV4", "interface.SUBINTERFACE"):
            expected, text = _plan_text(batch_srlinux, key)
            with self.subTest(key=key):
                self.assertTrue(batch_srlinux.imported(key, expected, text))

    def test_srlinux_imported_is_false_without_the_planned_addresses(self):
        expected, text = _plan_text(batch_srlinux, "interface.SUBINTERFACE", object_types={"interface"})
        self.assertEqual(expected["addresses"], ["198.18.0.1/30", "2001:db8:44::1/64"])
        self.assertFalse(batch_srlinux.imported("interface.SUBINTERFACE", expected, text))
