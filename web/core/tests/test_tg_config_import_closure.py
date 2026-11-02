"""Lab 7 closure -- the read-only running-config acquisition path and the IOS XE parser, each called directly.

Every read goes through the real capture transport with a fake session factory (``core.tests.helpers.health``): no
device, network or credential is touched and nothing is written anywhere.  POSITIVE: a reachable cEOS yields one
sanitized running-config section and a stable digest.  NEGATIVE: an unknown device, an unreachable device and an
unsupported platform each return no capture and a fixed code; unsupported IOS XE stanzas are preserved, never parsed.
"""

from __future__ import annotations

from unittest import mock

from django.test import SimpleTestCase, TestCase

from core.services.config_import import parser_iosxe
from core.services.config_import import service as svc
from core.services.bundles import canonical
from core.tests import test_config_import as ci

DIGEST = "2b03a300d0a4bca79ac25040fa90a045d071707b7748b15d5b719a04436a3e8b"


class FetchRunningConfigTests(TestCase):
    def test_fetch_running_config_outcome_of_a_reachable_ceos(self):
        fetched, code, message = svc.fetch_running_config_outcome("R1", session_factory=ci.fake_factory())
        self.assertEqual((code, message, fetched["entry"]["platform"]), ("", "", "ceos"))
        self.assertEqual([(s["name"], s["command_key"]) for s in fetched["sections"]], [("running-config", "running_config")])
        self.assertIn("hostname R1-IMPORTED", fetched["sections"][0]["sanitized"])

    def test_fetch_running_config_outcome_refuses_unknown_unreachable_or_unsupported_devices(self):
        self.assertEqual(svc.fetch_running_config_outcome("R99"), (None, "DEVICE_NOT_FOUND", "'R99' is not a managed inventory device."))
        down = ci.fake_factory(fail={"R1": ConnectionError("simulated unreachable")})
        self.assertEqual(svc.fetch_running_config_outcome("R1", session_factory=down), (None, "CONNECTION_FAILED", "Could not read R1: CONNECTION_FAILED"))
        with mock.patch.object(svc.capture, "managed_scope", return_value={"X1": {"name": "X1", "platform": "vyos"}}):
            self.assertEqual(svc.fetch_running_config_outcome("X1"), (None, "UNSUPPORTED_PLATFORM", "No read-only capture transport is defined for platform 'vyos'."))

    def test_fetch_sanitized_running_config_returns_the_capture(self):
        fetched, message = svc.fetch_sanitized_running_config("R1", session_factory=ci.fake_factory())
        self.assertEqual((message, svc.running_config_digest(fetched["sections"])), ("", DIGEST))

    def test_fetch_sanitized_running_config_of_an_unknown_device_is_none(self):
        self.assertEqual(svc.fetch_sanitized_running_config("R99"), (None, "'R99' is not a managed inventory device."))


class DigestAndParserTests(SimpleTestCase):
    def test_running_config_digest_hashes_the_joined_sanitized_text(self):
        self.assertEqual(svc.running_config_digest([{"sanitized": "a"}, {"sanitized": "b"}]), canonical.text_hash("a\nb"))

    def test_running_config_digest_of_a_tampered_or_empty_capture_differs(self):
        self.assertNotEqual(svc.running_config_digest([{"sanitized": "a"}, {"sanitized": "c"}]), canonical.text_hash("a\nb"))
        self.assertEqual(svc.running_config_digest([]), canonical.text_hash(""))

    def test_parse_never_models_unsupported_stanzas_or_unknown_interface_lines(self):
        parsed = parser_iosxe.parse("hostname X\ninterface GigabitEthernet9\n bogus thing\n!\nrouter eigrp 5\n network 10.0.0.0\n!\n")
        self.assertEqual((parsed.hostname, parsed.static_routes), ("X", []))
        self.assertEqual(parsed.interfaces[0].preserved_lines, [" bogus thing"])
        self.assertEqual([(b.classification, b.lines) for b in parsed.unmanaged_blocks], [("RECOGNIZED_UNSUPPORTED", ["router eigrp 5", " network 10.0.0.0"])])
        empty = parser_iosxe.parse("")
        self.assertEqual((empty.hostname, empty.interfaces, empty.static_routes, empty.unmanaged_blocks), ("", [], [], []))
