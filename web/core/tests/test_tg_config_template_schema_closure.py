"""Lab 7 closure -- the portable configuration-template model: ``config_templates.schema`` (ParsedConfig <-> intent,
typed parameters, placeholders, ``_when`` flags, structural validation), ``config_templates.features`` (capability
keys, platform compatibility, feature-template references), ``config_templates.working_intent`` (working revision
-> name-keyed intent) and ``config_templates.secret_scan`` (redaction / rejection), each called directly.

Pure: no database, no device, no repository write.  POSITIVE: exact intents, typed values, platform lists, template
references and clean pass-through.  NEGATIVE: raw CLI never enters a template (label-only exclusions), invalid /
unknown / missing parameters and malformed intents are refused with operator-facing problems, unsupported feature
mixes have no platform, unknown platforms have no templates, and secret-shaped keys / values are flagged or removed
without echoing the secret text.
"""
from __future__ import annotations

from django.test import SimpleTestCase

from core.services.config_import.schema import (
    ParsedAcl, ParsedConfig, ParsedInterface, ParsedNatRule, ParsedRoutingInstance, ParsedStaticRoute, UnmanagedBlock,
)
from core.services.config_templates import features, schema, secret_scan, working_intent

SECRET_VALUE = "Sup3rSecretValue!"


def parsed_config():
    return ParsedConfig(
        hostname="R1",
        interfaces=[ParsedInterface(name="Ethernet1", kind="ROUTED_PHYSICAL", mtu=9000,
                                    addresses=[{"family": "IPV4", "cidr": "10.0.0.1/30"}],
                                    ospf_bindings=[{"area": "0"}], preserved_lines=["   speed forced 10g"])],
        static_routes=[ParsedStaticRoute(family="IPV4", destination="0.0.0.0/0", next_hop_address="10.0.0.2", lines=["ip route ..."])],
        routing_instances=[ParsedRoutingInstance(family="ospf", fields={"process_id": 1}, bindings=[{"interface_name": "Ethernet1", "area": "0"}])],
        acls=[ParsedAcl(name="EDGE", family="IPV4", acl_type="EXTENDED", entries=[{"action": "PERMIT"}])],
        nat_rules=[ParsedNatRule(original_source="10.0.0.0/8", outside_interface="Ethernet1")],
        unmanaged_blocks=[UnmanagedBlock(label="username admin", classification="SECRET_BEARING", lines=["username admin secret x"]),
                          UnmanagedBlock(label="username admin", classification="SECRET_BEARING", lines=["a", "b"])],
    )


class ParsedConversionTests(SimpleTestCase):
    def test_from_parsed_returns_a_pruned_name_keyed_intent(self):
        intent, _ = schema.from_parsed(parsed_config())
        self.assertEqual(intent["device"], {"hostname": "R1"})
        self.assertEqual(intent["interfaces"], [{"name": "Ethernet1", "kind": "ROUTED_PHYSICAL", "mtu": 9000, "admin_state": "ENABLED",
                                                 "addresses": [{"family": "IPV4", "cidr": "10.0.0.1/30"}]}])
        self.assertEqual(intent["static_routes"], [{"family": "IPV4", "destination": "0.0.0.0/0", "next_hop_address": "10.0.0.2"}])
        self.assertEqual(intent["routing"], [{"family": "ospf", "fields": {"process_id": 1},
                                              "bindings": [{"interface_name": "Ethernet1", "area": "0"}]}])
        self.assertEqual(intent["nat_rules"], [{"family": "NAT44", "mode": "PAT", "original_source": "10.0.0.0/8", "outside_interface": "Ethernet1"}])

    def test_from_parsed_never_carries_raw_cli_only_label_exclusions(self):
        intent, exclusions = schema.from_parsed(parsed_config())
        self.assertEqual(exclusions, [
            {"category": "UNMODELLED_CONFIGURATION", "label": "Additional interface configuration (Ethernet1)",
             "classification": "RECOGNIZED_UNSUPPORTED", "lines": 1,
             "reason": "Not representable as semantic intent; the raw text is deliberately not carried by the template."},
            {"category": "UNMODELLED_CONFIGURATION", "label": "username admin", "classification": "SECRET_BEARING", "lines": 3,
             "reason": "Not representable as semantic intent; the raw text is deliberately not carried by the template."},
        ])
        text = repr(intent)
        for raw in ("speed forced", "username admin secret", "ip route ...", "ospf_bindings"):
            self.assertNotIn(raw, text)
        empty, none = schema.from_parsed(ParsedConfig(hostname=""))
        self.assertEqual((empty, none), ({"device": {"hostname": ""}}, []))

    def test_to_parsed_returns_importer_records(self):
        intent, _ = schema.from_parsed(parsed_config())
        parsed = schema.to_parsed(intent)
        self.assertEqual((parsed.hostname, parsed.parser_version), ("R1", "nmas-template-1"))
        self.assertEqual(parsed.interfaces[0].addresses, [{"family": "IPV4", "cidr": "10.0.0.1/30"}])
        self.assertEqual(parsed.routing_instances[0].bindings, [{"interface_name": "Ethernet1", "area": "0"}])
        self.assertEqual((parsed.acls[0].name, parsed.nat_rules[0].outside_interface), ("EDGE", "Ethernet1"))
        self.assertEqual(parsed.interfaces[0].preserved_lines, [])

    def test_to_parsed_of_an_empty_intent_is_an_empty_config_ignoring_unknown_fields(self):
        parsed = schema.to_parsed({"routing": [{"family": "bgp"}], "interfaces": [{"name": "E1", "bogus": 1}]})
        self.assertEqual((parsed.hostname, parsed.routing_instances[0].fields, parsed.interfaces[0].name), ("", {}, "E1"))
        self.assertEqual(schema.to_parsed({}).interfaces, [])


class ParameterTests(SimpleTestCase):
    def test_infer_type_returns_the_parameter_type_for_each_field(self):
        cases = {("enabled", True): "boolean", ("trunk_allowed_vlans", "10,20"): "vlan_list", ("access_vlan", 10): "vlan_id",
                 ("remote_asn", 65001): "asn", ("mtu", 9000): "integer", ("hostname", "R1"): "hostname",
                 ("next_hop_interface", "Ethernet1"): "interface_name", ("next_hop_address", "10.0.0.1"): "ipv4_address",
                 ("peer_address", "2001:db8::1"): "ipv6_address", ("cidr", "10.0.0.1/30"): "ipv4_interface",
                 ("destination", "10.0.0.0/8"): "ip_prefix", ("destination", "10.0.0.1/8"): "ip_interface"}
        for (key, value), expected in cases.items():
            with self.subTest(case=f"returns {expected} for {key}"):
                self.assertEqual(schema.infer_type(key, value), expected)

    def test_infer_type_of_unrecognised_text_is_string_never_an_address(self):
        self.assertEqual(schema.infer_type("description", "uplink 10.0.0.1"), "string")

    def test_resolve_parameters_returns_typed_values_and_defaults(self):
        params = {"host": {"type": "hostname"}, "vlan": {"type": "vlan_id", "default": 10}, "vlans": {"type": "vlan_list"},
                  "flag": {"type": "boolean"}, "addr": {"type": "ipv4_interface"}, "note": {"type": "string"}}
        values, problems = schema.resolve_parameters(params, {"host": "R9", "vlans": "30, 20 20", "addr": " 10.0.0.1/24 ", "note": " x "})
        self.assertEqual(problems, [])
        self.assertEqual(values, {"host": "R9", "vlan": 10, "vlans": [20, 30], "flag": False, "addr": "10.0.0.1/24", "note": " x "})

    def test_resolve_parameters_refuses_unknown_missing_and_invalid_values(self):
        params = {"host": {"type": "hostname"}, "vlan": {"type": "vlan_id"}, "asn": {"type": "asn"}, "flag": {"type": "boolean"},
                  "v6": {"type": "ipv6_address"}, "unused": {"type": "integer"}}
        values, problems = schema.resolve_parameters(
            params, {"host": "bad host!", "vlan": "5000", "asn": True, "flag": "maybe", "v6": "10.0.0.1", "extra": 1},
            needed={"host", "vlan", "asn", "flag", "v6"})
        self.assertEqual(problems, [
            "Unknown parameter 'extra'.", "Parameter host: 1-64 letters, digits, underscore or hyphen.",
            "Parameter vlan: must be between 1 and 4094.", "Parameter asn: an integer is required.",
            "Parameter flag: true or false is required.", "Parameter v6: an IPv6 value is required."])
        self.assertEqual(values, {})
        _, missing = schema.resolve_parameters({"host": {"type": "hostname"}}, {"host": "  "})
        self.assertEqual(missing, ["Parameter host is required."])

    def test_validate_parameter_definitions_refuses_bad_names_types_attributes_and_defaults(self):
        self.assertEqual(schema.validate_parameter_definitions([]), ["parameters must be a mapping."])
        problems = schema.validate_parameter_definitions({
            "Bad-Name": {"type": "string"}, "untyped": {}, "odd": {"type": "string", "colour": "red"},
            "vlan": {"type": "vlan_id", "default": 0}, "ok": {"type": "boolean", "default": True}})
        self.assertEqual(problems, ["Parameter name 'Bad-Name' is not a valid identifier.", "Parameter untyped: unknown or missing type.",
                                    "Parameter odd: unknown attribute(s) ['colour'].",
                                    "Parameter vlan: default is invalid (must be between 1 and 4094)."])

    def test_template_schema_error_returns_joined_operator_messages(self):
        error = schema.TemplateSchemaError(["first", 2])
        self.assertEqual((error.problems, str(error)), (["first", "2"], "first; 2"))

    def test_template_schema_error_of_no_problems_is_empty(self):
        error = schema.TemplateSchemaError([])
        self.assertEqual((error.problems, str(error)), ([], ""))


class PlaceholderAndValidationTests(SimpleTestCase):
    INTENT = {"device": {"hostname": "{{ host }}"},
              "interfaces": [{"name": "Vlan{{ vlan }}", "description": "users {{ site }}", "_when": "with_svi"},
                             {"name": "Ethernet1", "access_vlan": "{{ vlan }}"}]}

    def test_placeholders_returns_every_parameter_name(self):
        self.assertEqual(schema.placeholders(self.INTENT), {"host", "vlan", "site"})

    def test_placeholders_of_literal_text_is_empty(self):
        self.assertEqual(schema.placeholders({"device": {"hostname": "R1"}, "mtu": 9000}), set())

    def test_when_flags_returns_every_conditional_flag(self):
        self.assertEqual(schema.when_flags(self.INTENT), {"with_svi"})

    def test_when_flags_without_conditions_is_empty(self):
        self.assertEqual(schema.when_flags({"interfaces": [{"name": "E1", "_when": 5}]}), set())

    def test_validate_intent_refuses_malformed_structures_and_undefined_parameters(self):
        self.assertEqual(schema.validate_intent([], {}), ["intent must be a mapping."])
        problems = schema.validate_intent({
            "device": {}, "extras": {}, "static_routes": {}, "acls": ["x"],
            "interfaces": [{"name": "E1", "speed": 1}, {"name": "E1", "description": "{% if x %}"}, {"description": "a\x01"},
                           {"name": "{{ undefined_param }}", "mtu": 1.5, "_when": "flag"}],
        }, {"flag": {"type": "string"}})
        for expected in ("Unknown intent section 'extras'.", "intent.device.hostname is required.",
                         "intent.interfaces[1].description: only '{{ parameter }}' placeholders are allowed (no other template syntax).",
                         "intent.interfaces[2].description: text is too long or contains control characters.",
                         "intent.interfaces[3].mtu: unsupported value type float.", "intent.static_routes must be a list.",
                         "intent.acls[0] must be a mapping.", "intent.interfaces[0]: unknown field(s) ['speed'].",
                         "Every interface needs a name.", "Duplicate interface name(s): E1.",
                         "Placeholder {{ undefined_param }} has no parameter definition.", "_when flag 'flag' must be a boolean parameter."):
            with self.subTest(case=f"refused {expected[:40]}"):
                self.assertIn(expected, problems)
        deep = {"device": {"hostname": "R1"}, "host": {"a": {"b": {"c": {"d": {"e": {"f": {"g": {"h": 1}}}}}}}}}
        self.assertEqual(schema.validate_intent(deep, {}), ["The intent is too large or too deeply nested."])


class FeatureTests(SimpleTestCase):
    INTENT = {"interfaces": [{"name": "Vlan10", "kind": "SVI", "dhcp_relays": [{"family": "IPV4"}],
                              "fhrp": [{"protocol": "VARP", "address_family": "IPV4"}], "acl_attachments": [{"family": "IPV4"}]}],
              "static_routes": [{"family": "IPV6"}],
              "routing": [{"family": "rip", "fields": {"address_family": "IPV4"}}, {"family": "rip", "fields": {}},
                          {"family": "ospf", "fields": {}}, {"family": "bgp", "neighbors": [{"family": "IPV6"}]},
                          {"family": "bgp"}, {"family": "isis"}, {"family": "eigrp", "fields": {"address_family": "IPV4"}}],
              "acls": [{"family": "IPV4", "acl_type": "EXTENDED"}], "nat_rules": [{"family": "NAT44", "mode": "PAT"}]}

    def test_required_features_returns_every_catalogued_feature_key(self):
        self.assertEqual(features.required_features(self.INTENT), sorted([
            "interface.SVI", "service_policy.DHCP_RELAY_IPV4", "service_policy.FHRP_VARP_IPV4", "service_policy.ACL_ATTACH_IPV4",
            "routing.STATIC_IPV6", "routing.RIPV2", "routing.RIPNG", "routing.OSPFV2", "routing.BGP_IPV6", "routing.BGP_IPV4",
            "routing.ISIS", "routing.EIGRP_IPV4", "service_policy.ACL_IPV4_EXTENDED", "service_policy.NAT_NAT44_PAT"]))

    def test_required_features_drops_uncatalogued_kinds_and_is_empty_for_no_intent(self):
        self.assertEqual(features.required_features({"interfaces": [{"name": "x", "kind": "WORMHOLE"}]}), [])
        self.assertEqual(features.required_features({}), [])

    def test_unknown_features_returns_nothing_for_catalogued_keys(self):
        self.assertEqual(features.unknown_features(["interface.SVI", "routing.OSPFV2"]), [])

    def test_unknown_features_flags_uncatalogued_and_truncated_keys(self):
        self.assertEqual(features.unknown_features(["routing.WARP", "x" * 100, "interface.SVI"]), ["routing.WARP", "x" * 80])

    def test_supported_platforms_returns_platforms_rendering_every_feature(self):
        self.assertEqual(features.supported_platforms(["interface.SVI", "routing.OSPFV2", "service_policy.ACL_IPV4_EXTENDED"]),
                         ["arista_ceos", "ubuntu_frr"])     # Ubuntu/FRR nftables ACLs since V2 Phase 9
        self.assertEqual(features.supported_platforms(["interface.SVI", "service_policy.FHRP_VARP_IPV4"]), ["arista_ceos"])
        self.assertEqual(features.supported_platforms(["service_policy.NAT_NAT44_PAT"]), ["ubuntu_frr"])

    def test_supported_platforms_of_an_unsupported_feature_mix_is_empty(self):
        with self.subTest(case="refused incompatible feature mix"):
            self.assertEqual(features.supported_platforms(["service_policy.FHRP_VARP_IPV4", "service_policy.NAT_NAT44_PAT"]), [])

    def test_platform_gaps_returns_nothing_for_a_fully_supported_platform(self):
        self.assertEqual(features.platform_gaps(["interface.SVI", "routing.OSPFV2"], "arista_ceos"), [])

    def test_platform_gaps_lists_unsupported_features(self):
        self.assertEqual(features.platform_gaps(["interface.SVI", "service_policy.FHRP_VARP_IPV4", "routing.WARP"], "ubuntu_frr"),
                         ["service_policy.FHRP_VARP_IPV4"])

    def test_feature_templates_returns_tracked_template_references(self):
        self.assertEqual(features.feature_templates(["interface.SVI", "routing.OSPFV2", "service_policy.ACL_IPV4_EXTENDED"], ["arista_ceos"]),
                         ["ceos/acl_ipv4.j2", "ceos/interface_svi.j2", "ceos/routing_ospfv2.j2"])

    def test_feature_templates_of_unknown_platforms_or_untemplated_features_is_empty(self):
        self.assertEqual(features.feature_templates(["interface.SVI"], ["sonic", "unknown_os"]), [])
        self.assertEqual(features.feature_templates(["routing.ISIS"], ["arista_ceos"]), [])


class WorkingIntentTests(SimpleTestCase):
    def test_intent_from_sections_returns_a_name_keyed_intent(self):
        sections = {
            "interfaces": {"if_b": {"id": "if_b", "sequence": 2, "name": "Ethernet1.10", "kind": "SUBINTERFACE", "parent_id": "if_a",
                                    "addresses": {"a1": {"id": "a1", "family": "IPV4", "cidr": "10.0.0.1/30"}, "a2": {"id": "a2", "cidr": ""}}},
                           "if_a": {"id": "if_a", "sequence": 1, "name": "Ethernet1", "kind": "ROUTED_PHYSICAL", "mtu": 9000, "description": ""}},
            "services": {"dhcp": {"relays": {"r": {"id": "r", "interface_id": "if_a", "family": "IPV4", "destination": "10.9.9.9"}}}},
            "fhrp": {"instances": {"f": {"id": "f", "interface_id": "if_a", "protocol": "VARP", "address_family": "IPV4",
                                         "virtual_ips": {"v": {"id": "v", "address": "10.0.0.254"}}}}},
            "security": {"acls": {"acl": {"id": "acl", "name": "EDGE", "family": "IPV4", "acl_type": "EXTENDED",
                                          "entries": {"e": {"id": "e", "action": "PERMIT", "protocol": "IP"}}}},
                         "attachments": {"t": {"id": "t", "acl_id": "acl", "interface_id": "if_a", "direction": "IN"},
                                         "t2": {"id": "t2", "acl_id": "gone", "interface_id": "if_a", "direction": "OUT"}}},
            "routing": {"static_routes": {"s": {"id": "s", "family": "IPV4", "destination": "0.0.0.0/0", "next_hop_interface_id": "if_a"}},
                        "ospf": {"o": {"id": "o", "version": "OSPFV2", "process_id": 1, "router_id": "",
                                       "interfaces": {"b": {"id": "b", "interface_id": "if_a", "area": "0", "cost": None}},
                                       "networks": {"n": {"id": "n", "prefix": "10.0.0.0/8", "area": "0"}}}},
                        "bgp": {"g": {"id": "g", "local_asn": 65001, "neighbors": {"p": {
                            "id": "p", "peer_address": "10.0.0.2", "remote_asn": 65002, "activate_ipv4": False,
                            "update_source_interface_id": "if_a", "password_ref": "vault://bgp"}}}}},
            "nat": {"rules": {"x": {"id": "x", "family": "NAT44", "mode": "PAT", "original_source": "10.0.0.0/8", "outside_interface_id": "if_a"}}},
        }
        intent = working_intent.intent_from_sections(sections, hostname="R1")
        self.assertEqual(intent["device"], {"hostname": "R1"})
        self.assertEqual(intent["interfaces"][0], {
            "name": "Ethernet1", "kind": "ROUTED_PHYSICAL", "mtu": 9000, "dhcp_relays": [{"family": "IPV4", "destination": "10.9.9.9"}],
            "fhrp": [{"protocol": "VARP", "address_family": "IPV4", "address": "10.0.0.254"}],
            "acl_attachments": [{"family": "IPV4", "name": "EDGE", "direction": "IN"}]})
        self.assertEqual(intent["interfaces"][1], {"name": "Ethernet1.10", "kind": "SUBINTERFACE", "parent_name": "Ethernet1",
                                                   "addresses": [{"family": "IPV4", "cidr": "10.0.0.1/30"}]})
        self.assertEqual(intent["static_routes"], [{"family": "IPV4", "destination": "0.0.0.0/0", "next_hop_interface": "Ethernet1"}])
        self.assertEqual(intent["routing"], [
            {"family": "ospf", "fields": {"version": "OSPFV2", "process_id": 1}, "bindings": [{"interface_name": "Ethernet1", "area": "0"}],
             "networks": [{"prefix": "10.0.0.0/8", "area": "0"}]},
            {"family": "bgp", "fields": {"local_asn": 65001}, "neighbors": [
                {"peer_address": "10.0.0.2", "remote_asn": 65002, "activate_ipv4": False, "update_source_interface": "Ethernet1"}]}])
        self.assertEqual(intent["acls"], [{"name": "EDGE", "family": "IPV4", "acl_type": "EXTENDED", "entries": [{"action": "PERMIT", "protocol": "IP"}]}])
        self.assertEqual(intent["nat_rules"], [{"family": "NAT44", "mode": "PAT", "original_source": "10.0.0.0/8", "outside_interface": "Ethernet1"}])
        self.assertNotIn("vault://bgp", repr(intent))

    def test_intent_from_sections_of_empty_sections_has_only_the_device(self):
        self.assertEqual(working_intent.intent_from_sections(None, hostname="R2"), {"device": {"hostname": "R2"}})


class SecretScanTests(SimpleTestCase):
    def test_redact_returns_clean_content_unchanged(self):
        content = {"interfaces": [{"name": "Ethernet1", "description": "uplink"}], "mtu": 9000}
        self.assertEqual(secret_scan.redact(content), (content, []))

    def test_redact_removes_secret_keys_values_and_blanks_references_without_echoing_them(self):
        clean, findings = secret_scan.redact({
            "neighbors": [{"peer": "10.0.0.2", "password": SECRET_VALUE, "password_ref": "vault://bgp/r1"}],
            "description": f"password {SECRET_VALUE}", "notes": ["-----BEGIN " "RSA PRIVATE KEY-----"]})
        self.assertEqual(clean, {"neighbors": [{"peer": "10.0.0.2", "password_ref": ""}], "description": "", "notes": [""]})
        self.assertIn({"path": "neighbors[0].password", "pattern": "SECRET_SHAPED_KEY"}, findings)
        self.assertIn({"path": "neighbors[0].password_ref", "pattern": "SECRET_SHAPED_KEY"}, findings)
        self.assertIn({"path": "notes[0]", "pattern": "PRIVATE_KEY_BLOCK"}, findings)
        self.assertIn("description", {f["path"] for f in findings})
        self.assertNotIn(SECRET_VALUE, repr(findings))

    def test_scan_flags_secret_keys_unsafe_references_and_values_without_echoing_them(self):
        findings = secret_scan.scan({"bgp": {"password": SECRET_VALUE, "password_ref": "plaintext", "key_ref": "vault://ok"},
                                     "lines": ("token: ghp_" + "a" * 30,)})
        self.assertIn({"path": "bgp.password", "pattern": "SECRET_SHAPED_KEY"}, findings)
        self.assertIn({"path": "bgp.password_ref", "pattern": "UNSAFE_SECRET_REFERENCE"}, findings)
        self.assertNotIn("bgp.key_ref", {f["path"] for f in findings})
        self.assertIn({"path": "lines[0]", "pattern": "VENDOR_TOKEN"}, findings)
        self.assertNotIn(SECRET_VALUE, repr(findings))
