"""Lab 7 -- Tier-1 field validators (the Device Builder's input boundary), one positive and one negative case each.

Every ``validate_*`` function of core.services.field_validators gets:

* POSITIVE  a valid sample -> ``(True, <exact normalized value>, message)``
* NEGATIVE  wrong JSON types (int / float / bool / list / object where text is expected), boundary values (MTU, VLAN, ASN,
            distance, metric, port, prefix length ...) and malformed text -> ``(False, raw_value, message)`` and NEVER an
            exception: the commit endpoint takes a JSON body, so a crafted value must become an INVALID field state.

Two Lab 7 findings are pinned as regression cases: F1 a line break in any description was rendered as an extra
configuration line (CLI injection); F4 a non-text JSON value raised AttributeError (HTTP 500) instead of INVALID.
"""

from __future__ import annotations

import inspect
import json

from django.test import SimpleTestCase, TestCase
from django.urls import reverse

from core.services import candidate_renderer, field_validators as fv, platform_drivers
from core.services.capabilities import features, probe_cases
from core.services.test_governance.cases import NEGATIVE, POSITIVE, case

FV = "web/core/services/field_validators.py"
WRONG_TYPES = (("int", 7), ("float", 1.5), ("bool", True), ("list", [1]), ("object", {"a": 1}))

# name -> (valid sample, kwargs, exact normalized value, negatives (value) that must be refused, wrong types refused?)
TABLE = {
    "validate_acl_name": ("EDGE-IN", {}, "EDGE-IN", ["bad name!", ""], True),
    "validate_area_id": ("0", {}, "0.0.0.0", ["1.2.3", "area"], False),
    "validate_as_number": ("65001", {}, 65001, ["0", "4294967296", "-1", "1.5"], False),
    "validate_bool": ("true", {}, True, ["maybe", "yes please"], False),
    "validate_bounded_label": (" core ", {}, "core", ["x" * 101, "tab\there"], True),
    "validate_cidr": ("192.0.2.1/24", {}, "192.0.2.1/24", ["192.0.2.1/33", "300.1.1.1/24", "not-a-prefix"], True),
    "validate_description": ("  uplink  ", {}, "uplink", ["x" * 501, "line1\nline2", "cr\rinjected"], True),
    "validate_distance": ("10", {}, 10, ["0", "256", "ten"], False),
    "validate_domain_name": ("Lab.Example.", {}, "lab.example", ["bad_domain..x", "-x.example"], True),
    "validate_enum": ("A", {"allowed": ("A", "B"), "label": "Mode"}, "A", ["C", "a"], True),
    "validate_hostname": ("R1", {}, "R1", ["-bad", "a" * 65, "with space", ""], True),
    "validate_image_reference": ("ceos:4.36.2F", {}, "ceos:4.36.2F", ["/abs:path", "x" * 300], True),
    "validate_interface_description": ("to S1", {}, "to S1", ["line1\nusername evil privilege 15", "x" * 501], True),
    "validate_interface_name": ("Ethernet1", {}, "Ethernet1", ["Eth 1", "1Ethernet", ""], True),
    "validate_ip_host": ("192.0.2.1", {"family": 4, "label": "Gateway"}, "192.0.2.1", ["2001:db8::1", "192.0.2.0/24", "x"], True),
    "validate_ip_or_prefix": ("2001:db8::/64", {"family": 6}, "2001:db8::/64", ["192.0.2.0/24", "2001:db8::/129"], True),
    "validate_isis_net": ("49.0001.0000.0000.0044.00", {}, "49.0001.0000.0000.0044.00", ["49.0001", "invalid"], True),
    "validate_mac_address": ("00:1C:73:00:00:44", {}, "001c.7300.0044", ["00:1c:73:00:00", "zz:zz:zz:zz:zz:zz"], True),
    "validate_metric": ("10", {"minimum": 1, "maximum": 100, "label": "Cost"}, 10, ["0", "101", "ten"], False),
    "validate_mtu": ("1500", {}, 1500, ["575", "9217", "jumbo"], False),
    "validate_optional_integer": ("5", {"minimum": 1, "maximum": 10, "label": "Priority"}, 5, ["0", "11", "five"], False),
    "validate_platform": ("arista_ceos", {}, "arista_ceos", ["junos", ""], False),
    "validate_port_spec": ("80", {}, "80", ["70000", "http", "-1"], False),
    "validate_prefix": ("192.0.2.0/24", {}, "192.0.2.0/24", ["192.0.2.1/24", "192.0.2.0/33"], True),
    "validate_router_id": ("1.1.1.1", {}, "1.1.1.1", ["256.1.1.1", "2001:db8::1"], True),
    "validate_secret_ref": ("runtime://device-credentials/x", {}, "runtime://device-credentials/x", ["bad\x00ref", "x" * 300], True),
    "validate_target_type": ("NEW_DEVICE", {}, "NEW_DEVICE", ["OTHER", ""], False),
    "validate_vlan_id": ("10", {}, 10, ["0", "4095", "ten"], False),
    "validate_vlan_set": ("10,20-22", {}, [10, 20, 21, 22], ["10,5000", "20-10", "x"], False),
}


def _validators():
    return sorted(n for n, f in vars(fv).items() if n.startswith("validate_") and inspect.isfunction(f))


class FieldValidatorCaseTests(SimpleTestCase):
    maxDiff = None

    def _positive(self, name):
        sample, kwargs, normalized, _negatives, _types = TABLE[name]
        ok, value, message = getattr(fv, name)(sample, **kwargs)
        self.assertEqual((ok, value), (True, normalized))
        self.assertIsInstance(message, str)

    def _negative(self, name):
        _sample, kwargs, _normalized, negatives, text_only = TABLE[name]
        validator = getattr(fv, name)
        inputs = [(f"boundary / malformed {v!r:.30}", v) for v in negatives]
        if text_only:
            inputs += [(f"wrong type {label}", value) for label, value in WRONG_TYPES]
        else:
            inputs += [(f"wrong type {label}", value) for label, value in WRONG_TYPES if label in ("float", "object")]
        for label, value in inputs:
            with self.subTest(case=f"invalid {label}"):
                ok, returned, message = validator(value, **kwargs)
                self.assertIs(ok, False)
                self.assertEqual(returned, value)          # the raw value is returned, never "fixed" into something valid
                self.assertTrue(message)


def _add() -> None:
    for name in _validators():
        def positive(self, name=name):
            self._positive(name)

        def negative(self, name=name):
            self._negative(name)

        positive = case(f"FIELD_{name.upper()}_ACCEPTS_VALID", target=f"{FV}::{name}", polarity=POSITIVE,
                        condition=f"valid sample {TABLE[name][0]!r}", expected=f"(True, {TABLE[name][2]!r})")(positive)
        negative = case(f"FIELD_{name.upper()}_REFUSES_INVALID", target=f"{FV}::{name}", polarity=NEGATIVE,
                        condition="boundary / malformed values" + (" and non-text JSON types" if TABLE[name][4] else " and unusable types"),
                        expected="(False, raw value, message); never an exception")(negative)
        setattr(FieldValidatorCaseTests, f"test_{name}_accepts_valid_sample", positive)
        setattr(FieldValidatorCaseTests, f"test_{name}_refuses_invalid_input", negative)


_add()


class ValidatorInventoryTests(SimpleTestCase):
    def test_every_validator_has_a_table_row(self):
        self.assertEqual(sorted(TABLE), _validators())


class DescriptionInjectionRegressionTests(SimpleTestCase):
    @case("F1_DESCRIPTION_LINE_BREAK_NEVER_RENDERED", target="web/core/services/candidate_renderer.py::descriptor_text", polarity=NEGATIVE,
          condition="an interface description containing a line break followed by a configuration statement (stored before the fix)",
          expected="the renderer withholds the value with a refusal marker; no injected configuration line",
          requirement="Lab 7 finding F1: CLI injection through description fields")
    def test_a_multi_line_value_is_withheld_by_the_renderer(self):
        for platform in ("arista_ceos", "ubuntu_frr"):
            sample = probe_cases.sample(platform, features.by_key()["interface.LOOPBACK"])
            interface = next(iter(sample.sections["interfaces"].values()))
            interface["description"] = "uplink\nusername injected privilege 15 nopassword"
            rows = platform_drivers.get_driver(platform).render_candidate(
                field_values={"device.hostname": "R9", "device.description": "line\nip routing vrf X"},
                interfaces=list(sample.sections["interfaces"].values()), routing={}, phase12={})
            lines = [t for r in rows if (t := candidate_renderer.descriptor_text(r)) is not None]
            with self.subTest(platform=platform):
                self.assertFalse([line for line in lines if "injected" in line or "vrf X" in line])
                self.assertTrue(any(line.startswith(platform_drivers.UNSUPPORTED_OBJECT_MARKER) and "line break" in line for line in lines))
                self.assertTrue(all("\n" not in line for line in lines))

    @case("F1_DESCRIPTION_LINE_BREAK_REFUSED_AT_TIER1", target=f"{FV}::validate_interface_description", polarity=NEGATIVE,
          condition="a description with CR / LF / NUL / other control characters", expected="INVALID at Tier-1 (never accepted)",
          requirement="Lab 7 finding F1")
    def test_control_characters_are_refused(self):
        for value in ("a\nb", "a\rb", "a\x00b", "a\x1bb", "a\x7fb"):
            with self.subTest(case=f"invalid {value!r}"):
                self.assertFalse(fv.validate_interface_description(value)[0])
                self.assertFalse(fv.validate_description(value)[0])
        self.assertEqual(fv.validate_interface_description("to S1 -- core uplink")[:2], (True, "to S1 -- core uplink"))


class CommitEndpointTypeRegressionTests(TestCase):
    @case("F4_NON_TEXT_JSON_VALUE_IS_INVALID_NOT_500", target="web/core/views.py::device_builder_field_commit", polarity=NEGATIVE,
          condition="a crafted JSON commit body whose value is a number / list for a text field (hostname)",
          expected="HTTP 200 with validationState INVALID; the accepted value is unchanged (before the fix: AttributeError, HTTP 500)",
          requirement="Lab 7 finding F4: wrong-type input at an exposed boundary")
    def test_a_non_text_value_becomes_an_invalid_field_state(self):
        from core.services import change_service, field_commit_service, intent_service

        change = change_service.create_change(title="Lab 7 type robustness")
        intent, _ = intent_service.create_or_get_device_intent(change=change, device_name="R9", platform="arista_ceos")
        revision = intent_service.create_candidate_revision(device_intent=intent)
        field_commit_service.seed_device_identity_field_states(intent=intent, revision=revision)
        url = reverse("core:device_builder_field_commit", args=[change.change_id, intent.pk])
        for value in (5, [1, 2], {"x": 1}, True):
            with self.subTest(case=f"invalid value {value!r}"):
                response = self.client.post(url, json.dumps({"path": "device.hostname", "value": value, "revisionId": revision.pk}),
                                            content_type="application/json")
                self.assertEqual(response.status_code, 200)
                body = response.json()
                self.assertEqual((body["ok"], body["validationState"]), (False, "INVALID"))
                self.assertNotEqual(body["acceptedValue"], value)
