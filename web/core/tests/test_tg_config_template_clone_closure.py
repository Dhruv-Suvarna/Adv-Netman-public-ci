"""Lab 7 closure -- ``config_templates.clone`` (parameter form, INCREMENTAL overlay, template sources, push record),
``config_templates.combine`` (semantic Multilayer-Switch combination) and ``config_templates.baselines`` (end-device /
MLS content, package write / load), each called directly.

Hermetic: overlay / combine / content builders are pure; the end-device baseline reads only the tracked repository lab
definition (H1-H4 are never contacted); package write / load use a temporary directory and the test database; the
repository head is patched.  POSITIVE: exact form rows, overlay buckets, combined intent and content.  NEGATIVE:
missing presets fall back to defaults, a Change without template sources records no push, colliding roles are reported
as explicit conflicts (never silently merged), no published baseline writes no package, and a tampered package is
refused on load.
"""
from __future__ import annotations

import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import yaml
from django.conf import settings
from django.test import SimpleTestCase, TestCase

from core import models
from core.services.config_templates import baselines, clone, combine, service


def version(parameters, parameter_sets=None, **extra):
    return SimpleNamespace(parameters=parameters, parameter_sets=parameter_sets or {}, **extra)


class ParameterFormTests(SimpleTestCase):
    PARAMETERS = {"hostname": {"type": "hostname", "description": "Device hostname", "required": True},
                  "vlans": {"type": "vlan_list"}, "flag": {"type": "boolean", "default": True}, "mtu": {"type": "integer", "default": 1500}}

    def test_parameter_form_returns_rows_prefilled_from_the_parameter_set(self):
        rows = clone.parameter_form(version(self.PARAMETERS, {"S1": {"hostname": "S1", "vlans": [10, 20], "flag": False}}), parameter_set="S1")
        self.assertEqual(rows, [
            {"name": "hostname", "type": "hostname", "description": "Device hostname", "required": True, "value": "S1", "is_boolean": False, "checked": False},
            {"name": "vlans", "type": "vlan_list", "description": "", "required": False, "value": "10,20", "is_boolean": False, "checked": False},
            {"name": "flag", "type": "boolean", "description": "", "required": False, "value": False, "is_boolean": True, "checked": False},
            {"name": "mtu", "type": "integer", "description": "", "required": False, "value": 1500, "is_boolean": False, "checked": False}])

    def test_parameter_form_without_a_preset_uses_defaults_and_the_target_device_name(self):
        rows = {row["name"]: row for row in clone.parameter_form(version(self.PARAMETERS), parameter_set="missing", device_name="S9")}
        self.assertEqual((rows["hostname"]["value"], rows["vlans"]["value"], rows["flag"]["checked"], rows["mtu"]["value"]), ("S9", "", True, 1500))


class OverlayAndSourcesTests(SimpleTestCase):
    def test_overlay_returns_new_objects_operations_context_and_differences(self):
        template = {
            "device": {"hostname": "S1"},
            "interfaces": [{"name": "Vlan10", "kind": "SVI", "addresses": [{"cidr": "10.0.10.2/24"}, {"cidr": "10.0.11.2/24", "role": "SECONDARY"}],
                            "dhcp_relays": [{"family": "IPV4", "destination": "10.9.9.9"}], "mtu": 9000, "fhrp": [{"address": "10.0.10.1"}]},
                           {"name": "Vlan30", "kind": "SVI"}],
            "static_routes": [{"family": "IPV4", "destination": "0.0.0.0/0", "next_hop_address": "10.0.0.1"},
                              {"family": "IPV4", "destination": "10.8.0.0/16", "next_hop_address": "10.0.0.1"}],
            "routing": [{"family": "bgp", "fields": {"local_asn": 65001}, "neighbors": [{"peer_address": "10.0.0.2", "remote_asn": 65002}],
                         "networks": [{"cidr": "10.0.10.0/24"}]},
                        {"family": "ospf", "fields": {"process_id": 1}, "bindings": [{"interface_name": "Vlan10", "area": "0"},
                                                                                     {"interface_name": "Ethernet9", "area": "0"}],
                         "networks": [{"prefix": "10.0.0.0/8", "area": "0"}]},
                        {"family": "rip", "fields": {}}],
            "acls": [{"family": "IPV4", "name": "EDGE"}, {"family": "IPV4", "name": "NEW"}],
            "nat_rules": [{"original_source": "10.0.0.0/8"}],
        }
        running = {"interfaces": [{"name": "Vlan10", "kind": "SVI", "addresses": [{"cidr": "10.0.10.2/24"}], "mtu": 1500}],
                   "static_routes": [{"family": "IPV4", "destination": "0.0.0.0/0", "next_hop_address": "10.0.0.1"}],
                   "routing": [{"family": "bgp", "fields": {"local_asn": 65001}}, {"family": "ospf", "fields": {"process_id": 2}}],
                   "acls": [{"family": "IPV4", "name": "EDGE"}], "nat_rules": [{"original_source": "10.0.0.0/8"}]}
        result = clone.overlay(template, running)
        self.assertEqual(result["new"], {"device": {"hostname": "S1"}, "interfaces": [{"name": "Vlan30", "kind": "SVI"}],
                                         "static_routes": [template["static_routes"][1]], "routing": [{"family": "rip", "fields": {}}],
                                         "acls": [{"family": "IPV4", "name": "NEW"}]})
        self.assertEqual(result["operations"], [
            {"op": "interface_address", "interface": "Vlan10", "cidr": "10.0.11.2/24", "role": "SECONDARY"},
            {"op": "dhcp_relay", "interface": "Vlan10", "destination": "10.9.9.9"},
            {"op": "bgp_neighbor", "peer_address": "10.0.0.2", "remote_asn": 65002}, {"op": "bgp_network", "cidr": "10.0.10.0/24"},
            {"op": "ospf_interface", "interface": "Vlan10", "area": "0"}])
        self.assertEqual(result["context"], ["interface Vlan10", "static route 0.0.0.0/0", "bgp process", "ospf process", "ACL EDGE", "NAT 10.0.0.0/8"])
        self.assertEqual(result["differs"], ["interface Vlan10 mtu", "interface Vlan10 fhrp", "ospf process fields", "ospf binding on Ethernet9",
                                             "ospf network statements"])

    def test_overlay_with_several_running_processes_attaches_nothing(self):
        result = clone.overlay({"routing": [{"family": "ospf", "bindings": [{"interface_name": "E1", "area": "0"}]}]},
                               {"routing": [{"family": "ospf"}, {"family": "ospf"}]})
        self.assertEqual((result["operations"], result["differs"]), ([], ["ospf: the device has several processes; nothing was attached"]))

    def test_template_sources_returns_the_recorded_sources(self):
        change = SimpleNamespace(metadata={"template_sources": [{"template_id": "TPL-X", "version": 1}]})
        self.assertEqual(clone.template_sources(change), [{"template_id": "TPL-X", "version": 1}])

    def test_template_sources_of_a_change_without_metadata_is_empty(self):
        self.assertEqual(clone.template_sources(SimpleNamespace(metadata=None)), [])


class RecordPushTests(TestCase):
    def test_record_push_without_template_sources_records_no_audit_event(self):
        run = SimpleNamespace(change=SimpleNamespace(metadata={}, change_id="CHG-1"), run_id="r")
        self.assertIsNone(clone.record_push(run, SimpleNamespace(status="PASSED", run_id="v", operation_type="DEPLOY"), actor="tester"))
        self.assertFalse(models.AuditEvent.objects.filter(event_type=models.AuditEventType.TEMPLATE_PUSH_RECORDED).exists())


ACCESS = {"intent": {"device": {"hostname": "{{ hostname }}"},
                     "interfaces": [{"name": "Ethernet1", "kind": "ROUTED_PHYSICAL", "addresses": [{"cidr": "{{ ethernet1_ipv4 }}"}]},
                                    {"name": "Ethernet3", "kind": "ACCESS", "access_vlan": 200},
                                    {"name": "Vlan200", "kind": "SVI", "vlan_id": 200, "addresses": [{"cidr": "{{ mgmt_ipv4 }}"}]},
                                    {"name": "Vlan10", "kind": "SVI", "vlan_id": 10, "addresses": [{"cidr": "10.0.10.2/24"}]},
                                    {"name": "Loopback0", "kind": "LOOPBACK", "addresses": [{"family": "IPV4", "cidr": "{{ loopback_ipv4 }}"}]}],
                     "static_routes": [{"family": "IPV4", "destination": "0.0.0.0/0", "next_hop_address": "10.0.0.1"}],
                     "routing": [{"family": "ospf", "fields": {"process_id": 1}, "bindings": [{"interface_name": "Vlan10", "area": "0"}]}]},
          "parameters": {"hostname": {"type": "hostname"}, "ethernet1_ipv4": {"type": "ipv4_interface"}, "mgmt_ipv4": {"type": "ipv4_interface"},
                         "loopback_ipv4": {"type": "ipv4_interface"}, "uplink": {"type": "string"}}}
GATEWAY = {"intent": {"device": {"hostname": "{{ hostname }}"},
                      "interfaces": [{"name": "Ethernet1", "kind": "TRUNK", "trunk_allowed_vlans": [101], "description": "{{ uplink }}"},
                                     {"name": "Ethernet3", "kind": "ACCESS", "access_vlan": 200, "mtu": 9000},
                                     {"name": "Vlan200", "kind": "SVI", "vlan_id": 200, "addresses": [{"cidr": "{{ mgmt_ipv4 }}"}]},
                                     {"name": "Vlan10", "kind": "SVI", "vlan_id": 10, "addresses": [{"cidr": "10.0.10.3/24"}]},
                                     {"name": "Loopback0", "kind": "LOOPBACK", "addresses": [{"family": "IPV6", "cidr": "{{ loopback_ipv6 }}"}]}],
                       "static_routes": [{"family": "IPV4", "destination": "0.0.0.0/0", "next_hop_address": "10.0.0.9"}],
                       "routing": [{"family": "ospf", "fields": {"process_id": 10}, "bindings": [{"interface_name": "Ethernet1", "area": "0"}]}]},
           "parameters": {"hostname": {"type": "hostname"}, "mgmt_ipv4": {"type": "ipv4_interface"}, "loopback_ipv6": {"type": "ipv6_interface"},
                          "uplink": {"type": "string"}}}


class CombineTests(SimpleTestCase):
    def test_combine_reports_every_collision_as_an_explicit_conflict_never_silently_merging(self):
        result = combine.combine(ACCESS, GATEWAY)
        codes = [c["code"] for c in result["conflicts"]]
        for code in ("PARAMETER_COLLISION", "DUPLICATE_INTERFACE", "DUPLICATE_MANAGEMENT", "OVERLAPPING_ADDRESSING", "LOOPBACK_ROUTER_ID",
                     "ROUTING_PROCESS_COLLISION", "DEFAULT_GATEWAY_ROLE", "VLAN_WITHOUT_SVI"):
            with self.subTest(case=f"refused silent {code}"):
                self.assertIn(code, codes)
        names = [row["name"] for row in result["intent"]["interfaces"]]
        self.assertEqual(names.count("Ethernet3"), 1)
        moved = next(row for row in result["intent"]["interfaces"] if row.get("kind") == "TRUNK")
        self.assertEqual((moved["name"], moved["description"]), ("Ethernet2", "{{ gw_uplink }}"))
        self.assertEqual(result["intent"]["routing"][0]["bindings"], [{"interface_name": "Vlan10", "area": "0"}, {"interface_name": "Ethernet2", "area": "0"}])
        self.assertEqual(result["intent"]["static_routes"], [{"family": "IPV4", "destination": "0.0.0.0/0", "next_hop_address": "10.0.0.9"}])
        loopback = next(row for row in result["intent"]["interfaces"] if row["name"] == "Loopback0")
        self.assertEqual(len(loopback["addresses"]), 2)
        self.assertIn("gw_uplink", result["parameters"])


class BaselineContentTests(TestCase):
    def test_end_device_content_returns_a_non_deployable_host_template_from_the_lab_definition(self):
        with mock.patch.object(service, "repository_head", return_value="abc123"):
            content = baselines.end_device_content()
        hosts = sorted((yaml.safe_load((Path(settings.REPO_ROOT) / "inventory.yml").read_text()) or {}).get("hosts") or {})
        self.assertEqual((content["family"], content["platforms"], content["constraints"]["deployable"]), ("END_DEVICE", [], False))
        self.assertEqual(sorted(content["parameter_sets"]), hosts)
        self.assertEqual(content["provenance"]["source_devices"], hosts)
        self.assertEqual(content["provenance"]["repository_head"], "abc123")
        self.assertEqual(content["intent"]["host"]["access_interface"], "eth1")

    def mls_versions(self):
        def v(spec, role, devices):
            return SimpleNamespace(intent=spec["intent"], parameters=spec["parameters"], version=1, digest=role * 64,
                                   template=SimpleNamespace(template_id=f"TPL-{role.upper()}"),
                                   provenance={"source_devices": devices, "platforms": ["arista_ceos"], "extracted_at": "2026-10-1" + role[-1]})
        return v(ACCESS, "a", ["S1", "S2"]), v(GATEWAY, "b", ["R1", "R2"])

    def test_mls_content_returns_a_combined_multilayer_switch_template(self):
        access, gateway = self.mls_versions()
        with mock.patch.object(service, "repository_head", return_value="abc123"):
            content = baselines.mls_content(access, gateway)
        provenance = content["provenance"]
        self.assertEqual((content["family"], provenance["method"], provenance["source_devices"]), ("MULTILAYER_SWITCH", "semantic-combination", ["R1", "R2", "S1", "S2"]))
        self.assertEqual([d["role"] for d in provenance["derived_from"]], ["access", "gateway"])
        self.assertEqual(provenance["extracted_at"], "2026-10-1b")
        self.assertEqual(content["parameter_sets"], {})

    def test_mls_content_records_role_conflicts_never_hiding_them(self):
        access, gateway = self.mls_versions()
        with mock.patch.object(service, "repository_head", return_value=""):
            content = baselines.mls_content(access, gateway)
        self.assertTrue(content["provenance"]["conflicts"])
        self.assertIn("DUPLICATE_MANAGEMENT", {c["code"] for c in content["provenance"]["conflicts"]})

    def test_write_packages_without_published_baselines_writes_no_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(baselines.write_packages(Path(tmp) / "out", actor="tester"), [])
            self.assertEqual(list((Path(tmp) / "out").iterdir()), [])

    def test_load_packages_refuses_a_tampered_package_and_registers_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / f"bad{baselines.package.FILE_SUFFIX}").write_text("kind: nmas-configuration-template\nschema_version: 99\n")
            with self.assertRaises(service.TemplateError) as raised:
                baselines.load_packages(Path(tmp), actor="tester")
        self.assertEqual(raised.exception.code, "UNSUPPORTED_SCHEMA_VERSION")
        self.assertFalse(models.ConfigurationTemplate.objects.exists())
