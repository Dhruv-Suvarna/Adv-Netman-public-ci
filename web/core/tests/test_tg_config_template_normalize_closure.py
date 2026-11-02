"""Lab 7 closure -- ``config_templates.normalize`` (``clean`` and the ``_Generalizer`` steps) and
``config_templates.package`` (``PackageError``, the alias-refusing ``_StrictLoader`` and ``build_document``), each called
directly.

Pure: no database, no device.  POSITIVE: exact parameters / parameter sets / differences / guarded objects, a composed
YAML node, an exact package document.  NEGATIVE: runtime management plumbing, link-local addresses, management-network
routes and secret-shaped values are removed and recorded; conflicting parameter names never collide; objects only some
sources have are guarded off by default; YAML aliases are refused; a version without a creation time exports an empty
timestamp.
"""
from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

import yaml
from django.test import SimpleTestCase

from core.services.config_templates import normalize, package


class CleanTests(SimpleTestCase):
    def test_clean_removes_runtime_link_local_management_routes_and_secrets_recording_each(self):
        intent = {
            "device": {"hostname": "R3"},
            "interfaces": [{"name": "eth0", "addresses": [{"cidr": "172.20.20.3/24"}, {"cidr": "bad"}]},
                           {"name": "Vlan10", "addresses": [{"cidr": "fe80::1/64"}]},
                           {"name": "Ethernet3", "kind": "ROUTED_PHYSICAL", "access_vlan": 10},
                           {"name": "Vlan20", "description": "password Sup3rSecretValue!", "addresses": [{"cidr": "10.0.0.1/24"}, {"cidr": "fe80::2/64"}]}],
            "static_routes": [{"destination": "0.0.0.0/0", "next_hop_address": "172.20.20.1"},
                              {"destination": "10.9.0.0/16", "next_hop_address": "not-an-ip"},
                              {"destination": "10.8.0.0/16", "next_hop_address": "10.0.0.2"}],
        }
        cleaned, exclusions = normalize.clean(intent, "ubuntu_frr")
        self.assertEqual([row["name"] for row in cleaned["interfaces"]], ["Vlan10", "Ethernet3", "Vlan20"])
        self.assertNotIn("addresses", cleaned["interfaces"][0])
        self.assertEqual(cleaned["interfaces"][1]["kind"], "ACCESS")
        self.assertEqual(cleaned["interfaces"][2]["addresses"], [{"cidr": "10.0.0.1/24"}])
        self.assertEqual(cleaned["interfaces"][2]["description"], "")
        self.assertEqual([r["destination"] for r in cleaned["static_routes"]], ["10.9.0.0/16", "10.8.0.0/16"])
        self.assertEqual([e["category"] for e in exclusions[:5]], ["RUNTIME_MANAGEMENT", "DEVICE_IDENTITY", "NORMALIZED", "DEVICE_IDENTITY",
                                                                   "RUNTIME_MANAGEMENT"])
        secrets = exclusions[5:]
        self.assertTrue(secrets)
        self.assertEqual({(e["category"], e["label"]) for e in secrets}, {("SECRET_REDACTED", "intent.interfaces[2].description")})
        self.assertNotIn("Sup3rSecretValue", repr([cleaned, exclusions]))

    def test_clean_of_an_unknown_platform_keeps_management_and_drops_empty_sections(self):
        cleaned, exclusions = normalize.clean({"device": {"hostname": "X"}, "interfaces": [{"name": "Management0"}], "static_routes": []},
                                              "sonic")
        self.assertEqual((cleaned, exclusions), ({"device": {"hostname": "X"}, "interfaces": [{"name": "Management0"}]}, []))


class GeneralizerTests(SimpleTestCase):
    def test_generalizer_init_returns_empty_state_per_device(self):
        worker = normalize._Generalizer(["S1", "S2"])
        self.assertEqual((worker.devices, worker.parameters, worker.sets, worker.differences), (["S1", "S2"], {}, {"S1": {}, "S2": {}}, []))

    def test_generalizer_init_without_devices_has_no_parameter_sets(self):
        self.assertEqual(normalize._Generalizer([]).sets, {})

    def test_parameter_returns_a_placeholder_with_typed_spec_and_sets(self):
        worker = normalize._Generalizer(["S1", "S2"])
        placeholder = worker.parameter(("interfaces", "Vlan10"), "mtu", {"S1": 1500, "S2": 9000}, default=1500)
        self.assertEqual(placeholder, "{{ vlan10_mtu }}")
        self.assertEqual(worker.parameters["vlan10_mtu"], {"type": "integer", "description": "interfaces / Vlan10 mtu", "required": True, "default": 1500})
        self.assertEqual(worker.sets, {"S1": {"vlan10_mtu": 1500}, "S2": {"vlan10_mtu": 9000}})
        long = worker.parameter(("interfaces", "x" * 60), "description", {"S1": "a", "S2": "b"})
        self.assertRegex(long, r"^\{\{ x{44}_[0-9a-f]{8} \}\}$")

    def test_parameter_never_reuses_a_name_whose_type_or_values_conflict(self):
        worker = normalize._Generalizer(["S1"])
        first = worker.parameter(("device",), "hostname", {"S1": "S1"}, forced="name", kind="hostname")
        conflicting_type = worker.parameter(("device",), "x", {"S1": 5}, forced="name")
        conflicting_value = worker.parameter(("device",), "y", {"S1": "other"}, forced="name", kind="hostname")
        same = worker.parameter(("device",), "z", {"S1": "S1"}, forced="name", kind="hostname")
        self.assertEqual((first, conflicting_type, conflicting_value, same), ("{{ name }}", "{{ name_2 }}", "{{ name_3 }}", "{{ name }}"))
        self.assertEqual(worker.sets["S1"], {"name": "S1", "name_2": 5, "name_3": "other"})

    def test_node_returns_literals_for_shared_values_and_parameters_for_identity_and_differences(self):
        worker = normalize._Generalizer(["R1", "R2"])
        out = worker.node({"R1": {"hostname": "R1", "mtu": 9000, "description": "core", "fields": {"router_id": "1.1.1.1"}},
                           "R2": {"hostname": "R2", "mtu": 9000, "description": "edge", "fields": {"router_id": "2.2.2.2"}}}, ("device",))
        self.assertEqual(out["hostname"], "{{ hostname }}")
        self.assertEqual(out["mtu"], 9000)
        self.assertEqual(out["description"], "{{ description }}")
        self.assertEqual(worker.differences, [{"path": "device/description", "kind": "VALUE_DIFFERS", "values": {"R1": "core", "R2": "edge"}},
                                              {"path": "device/fields/router_id", "kind": "VALUE_DIFFERS",
                                               "values": {"R1": "1.1.1.1", "R2": "2.2.2.2"}}])

    def test_node_with_a_value_missing_on_one_source_is_optional_never_required(self):
        worker = normalize._Generalizer(["R1", "R2"])
        out = worker.node({"R1": {"notes": "x", "tags": ["a"]}, "R2": {}}, ("device",))
        self.assertEqual(out, {"notes": "{{ notes }}", "tags": "{{ tags }}"})
        self.assertEqual((worker.parameters["notes"]["required"], worker.parameters["notes"]["default"]), (False, ""))
        self.assertEqual((worker.parameters["tags"]["default"], worker.sets["R2"]["tags"]), ([], []))

    def test_keyed_list_returns_rows_matched_by_identity_with_forced_identity_parameters(self):
        worker = normalize._Generalizer(["S1", "S2"])
        rows = worker.keyed_list("interfaces", {
            "S1": [{"name": "Vlan200", "addresses": [{"family": "IPV4", "cidr": "192.168.200.11/24"}]}, {"name": "Loopback0", "description": "S1 loop"}],
            "S2": [{"name": "Vlan200", "addresses": [{"family": "IPV4", "cidr": "192.168.200.12/24"}]}, {"name": "Loopback0", "description": "S2 loop"}],
        }, ("interfaces",))
        self.assertEqual(rows[0], {"name": "Vlan200", "addresses": [{"family": "IPV4", "cidr": "{{ mgmt_ipv4 }}"}]})
        self.assertEqual(rows[1]["description"], "{{ loopback0_description }}")
        self.assertEqual(worker.sets["S2"]["mgmt_ipv4"], "192.168.200.12/24")
        self.assertEqual(worker.parameters["loopback0_description"]["required"], False)

    def test_keyed_list_guards_objects_missing_on_some_sources_disabled_by_default(self):
        worker = normalize._Generalizer(["S1", "S2"])
        rows = worker.keyed_list("acls", {"S1": [{"name": "EDGE"}], "S2": []}, ("acls",))
        flag = rows[0]["_when"]
        self.assertEqual(rows, [{"_when": flag, "name": "EDGE"}])
        self.assertEqual((worker.parameters[flag]["type"], worker.parameters[flag]["default"]), ("boolean", False))
        self.assertEqual((worker.sets["S1"][flag], worker.sets["S2"][flag]), (True, False))
        self.assertEqual(worker.differences, [{"path": "acls/EDGE", "kind": "ONLY_ON_SOME_SOURCES", "present_on": ["S1"]}])


class PackageTests(SimpleTestCase):
    def version(self, created_at):
        template = SimpleNamespace(template_id="TPL-ABC123", name="Access", family="ACCESS_SWITCH", origin="EXTRACTED", description="d")
        return SimpleNamespace(template=template, schema_version=1, version=2, created_by="tester", created_at=created_at, digest="f" * 64,
                               platforms=["arista_ceos"], required_features=["interface.SVI"], constraints={}, provenance={"method": "m"},
                               parameters={}, parameter_sets={}, intent={"device": {"hostname": "S1"}}, exclusions=[], notes="")

    def test_package_error_returns_a_coded_problem_list(self):
        error = package.PackageError("INVALID_PACKAGE", ["a", 1])
        self.assertEqual((error.code, error.problems, str(error)), ("INVALID_PACKAGE", ["a", "1"], "INVALID_PACKAGE: a; 1"))

    def test_package_error_of_a_single_refusal_string_is_one_problem(self):
        self.assertEqual(package.PackageError("EMPTY_PACKAGE", "The package is empty.").problems, ["The package is empty."])

    def test_strict_loader_compose_node_returns_a_plain_node(self):
        loader = package._StrictLoader("a: [1, 2]\n")
        try:
            loader.get_event(), loader.get_event()      # stream start, document start
            node = loader.compose_node(None, None)
        finally:
            loader.dispose()
        self.assertIsInstance(node, yaml.MappingNode)
        self.assertEqual(node.value[0][0].value, "a")

    def test_strict_loader_compose_node_refuses_aliases(self):
        loader = package._StrictLoader("- &x 1\n- *x\n")
        try:
            loader.get_event(), loader.get_event()
            with self.assertRaisesRegex(yaml.YAMLError, "aliases are not allowed"):
                loader.compose_node(None, None)
        finally:
            loader.dispose()

    def test_build_document_returns_the_exact_package_document(self):
        document = package.build_document(self.version(datetime(2026, 10, 19, tzinfo=timezone.utc)), feature_templates=["ceos/b.j2", "ceos/a.j2"])
        self.assertEqual((document["kind"], document["schema_version"]), ("nmas-configuration-template", 1))
        self.assertEqual(document["manifest"], {"template_id": "TPL-ABC123", "name": "Access", "family": "ACCESS_SWITCH", "origin": "EXTRACTED",
                                                "description": "d", "version": 2, "created_by": "tester",
                                                "created_at": "2026-10-19T00:00:00+00:00", "digest_algorithm": "sha256", "digest": "f" * 64})
        self.assertEqual(document["compatibility"], {"platforms": ["arista_ceos"], "required_features": ["interface.SVI"], "constraints": {}})
        self.assertEqual(document["rendering"]["feature_templates"], ["ceos/a.j2", "ceos/b.j2"])

    def test_build_document_without_a_creation_time_has_an_empty_timestamp(self):
        document = package.build_document(self.version(None), feature_templates=[])
        self.assertEqual((document["manifest"]["created_at"], document["rendering"]["feature_templates"]), ("", []))
