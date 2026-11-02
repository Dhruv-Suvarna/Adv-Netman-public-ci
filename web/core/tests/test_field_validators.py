"""Tier-1 field validators (syntax only): one table, one row per behavior.

Replaces the per-validator, per-phase test methods (Phase 9 identity validators
and Phase 10 scalar validators).  Each row is ``(label, validator, args,
kwargs, accepted?, normalized value)`` -- a failing row names itself.
"""

from __future__ import annotations

from django.test import SimpleTestCase

from core import models
from core.services import field_validators as v

ANY = object()  # accepted, but the normalized value is not asserted


def rows():
    table = [
        # -- identity ---------------------------------------------------------------------------
        ("hostname", v.validate_hostname, ("R1",), {}, True, "R1"),
        ("hostname is trimmed", v.validate_hostname, ("  R1  ",), {}, True, "R1"),
        ("hostname empty", v.validate_hostname, ("",), {}, False, ANY),
        ("hostname invalid characters", v.validate_hostname, ("%%%bad%%%",), {}, False, ANY),
        ("hostname leading hyphen", v.validate_hostname, ("-r1",), {}, False, ANY),
        ("hostname 65 chars", v.validate_hostname, ("r" * 65,), {}, False, ANY),
        ("description empty", v.validate_description, ("",), {}, True, ""),
        ("description 501 chars", v.validate_description, ("x" * 501,), {}, False, ANY),
        ("description html is stored verbatim (escaped at render)", v.validate_description, ("<script>alert(1)</script>",), {},
         True, "<script>alert(1)</script>"),
        ("platform unknown", v.validate_platform, ("junos",), {}, False, ANY),
        ("target type unknown", v.validate_target_type, ("SOMETHING_ELSE",), {}, False, ANY),
        ("image reference empty", v.validate_image_reference, ("",), {}, True, ""),
        ("image reference safe", v.validate_image_reference, ("ceos:4.36.2F",), {}, True, "ceos:4.36.2F"),
        ("image reference shell metacharacters", v.validate_image_reference, ("ceos;rm -rf /",), {}, False, ANY),
        ("image reference 256 chars", v.validate_image_reference, ("a" * 256,), {}, False, ANY),
        # -- interface scalars --------------------------------------------------------------------
        ("interface name is trimmed", v.validate_interface_name, (" Ethernet1.100 ",), {}, True, "Ethernet1.100"),
        ("interface name invalid", v.validate_interface_name, ("1 bad",), {}, False, ANY),
        ("interface description 500", v.validate_interface_description, ("x" * 500,), {}, True, ANY),
        ("interface description 501", v.validate_interface_description, ("x" * 501,), {}, False, ANY),
        ("mtu 576", v.validate_mtu, (576,), {}, True, ANY),
        ("mtu 9216", v.validate_mtu, (9216,), {}, True, ANY),
        ("mtu 575", v.validate_mtu, (575,), {}, False, ANY),
        ("mtu 9217", v.validate_mtu, (9217,), {}, False, ANY),
        ("vlan 1", v.validate_vlan_id, ("1",), {}, True, 1),
        ("vlan 4094", v.validate_vlan_id, ("4094",), {}, True, 4094),
        ("vlan 0", v.validate_vlan_id, (0,), {}, False, ANY),
        ("vlan 4095", v.validate_vlan_id, (4095,), {}, False, ANY),
        ("vlan not a number", v.validate_vlan_id, ("x",), {}, False, ANY),
        ("vlan bool is not an int", v.validate_vlan_id, (True,), {}, False, ANY),
        ("vlan set dedupes and merges overlaps", v.validate_vlan_set, ("10,10,11-13,12-14",), {}, True, [10, 11, 12, 13, 14]),
        ("vlan set reversed range", v.validate_vlan_set, ("30-20",), {}, False, ANY),
        ("vlan set out-of-range member", v.validate_vlan_set, ("1,4095",), {}, False, ANY),
        # -- addresses ----------------------------------------------------------------------------
        ("cidr v4 keeps host bits", v.validate_cidr, ("192.0.2.1/31",), {"family": 4}, True, "192.0.2.1/31"),
        ("cidr v6 keeps host bits, compressed", v.validate_cidr, ("2001:0db8::1/64",), {"family": 6}, True, "2001:db8::1/64"),
        ("cidr invalid octet", v.validate_cidr, ("192.0.2.999/24",), {"family": 4}, False, ANY),
        ("cidr family mismatch", v.validate_cidr, ("2001:db8::1/64",), {"family": 4}, False, ANY),
        ("prefix at network address", v.validate_prefix, ("192.0.2.0/24",), {"family": 4}, True, ANY),
        ("prefix with host bits", v.validate_prefix, ("192.0.2.1/24",), {"family": 4}, False, ANY),
        ("wan host rejects a prefix", v.validate_ip_host, ("192.0.2.1/31",), {"family": 4, "label": "Peer"}, False, ANY),
        ("wan host rejects wrong family", v.validate_ip_host, ("2001:db8::1",), {"family": 4, "label": "Peer"}, False, ANY),
    ]
    table += [(f"platform {p}", v.validate_platform, (p,), {}, True, p) for p in models.Platform.values]
    table += [(f"target type {t}", v.validate_target_type, (t,), {}, True, t) for t in ("EXISTING_DEVICE", "NEW_DEVICE")]
    return table


class FieldValidatorMatrixTests(SimpleTestCase):
    def test_validator_matrix(self):
        for label, validator, args, kwargs, accepted, expected in rows():
            with self.subTest(case=label):
                ok, value, message = validator(*args, **kwargs)
                self.assertEqual(ok, accepted)
                if accepted and expected is not ANY:
                    self.assertEqual(value, expected)
                if not accepted:
                    self.assertTrue(message, "a rejection must explain itself")

    def test_result_shape_and_display_helpers(self):
        self.assertEqual(v.validate_hostname("R1"), (True, "R1", ""))  # success carries no message
        self.assertEqual(v.vlan_set_display(v.validate_vlan_set("10,10,11-13,12-14")[1]), "10-14")
