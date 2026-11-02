"""Lab 7 -- negative cases for every health parser of untrusted device output (health/live.py ``parse_*``).

Device output is untrusted input.  The contract proven here, parser by parser (generated from the module, so a new
``parse_*`` function cannot be added without a case):

* JSON parsers: malformed / wrong-shaped output raises (``LiveError PARSE_ERROR`` or a parse exception), and the
  device-read wrapper turns it into an UNAVAILABLE fact group with the fixed code ``PARSE_ERROR`` -- never a crash,
  never a partial fact, never the raw text.
* text parsers: output they do not recognise yields NO facts (no phantom ACL / NAT / route / VARP fact).

The positive cases (real-format samples) live in test_health_sources / test_isis_ceos / test_srlinux_executor /
test_iosxe_executor / test_frr_routing_executor.
"""

from __future__ import annotations

import inspect
from datetime import datetime, timezone

from django.test import SimpleTestCase

from core.services.health import live
from core.services.test_governance.cases import NEGATIVE, POSITIVE, case

LIVE = "web/core/services/health/live.py"
MALFORMED = (("garbage", "Traceback (most recent call last):"), ("wrong shape list", "[1, 2]"), ("wrong shape scalar", "42"))
TEXT_PARSERS = {"parse_eos_config", "parse_eos_varp", "parse_frr_rip", "parse_iosxe_interfaces", "parse_iosxe_routes", "parse_nft",
                "parse_nft_acl"}
NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _parsers():
    return sorted(name for name, fn in vars(live).items() if name.startswith("parse_") and inspect.isfunction(fn) and fn.__module__ == live.__name__)


def _empty(value) -> bool:
    if isinstance(value, dict):
        return all(_empty(v) for v in value.values())
    if isinstance(value, (list, tuple)):
        return all(_empty(v) for v in value) if isinstance(value, tuple) else not value
    return value in (None, "", 0)


class HealthParserNegativeTests(SimpleTestCase):
    def _negative(self, name: str):
        parser = getattr(live, name)
        arity = len(inspect.signature(parser).parameters)
        for label, text in MALFORMED:
            with self.subTest(case=f"malformed {label}"):
                if name in TEXT_PARSERS:
                    self.assertTrue(_empty(parser(*([text] * arity))), f"{name} produced facts from unrecognised output")
                    continue
                with self.assertRaises((live.LiveError, ValueError, KeyError, TypeError, AttributeError)):
                    parser(*([text] * arity))
                group = live._group(lambda text=text: parser(*([text] * arity)), now=NOW)  # pylint: disable=protected-access
                self.assertFalse(group.available)
                self.assertEqual(group.error, "PARSE_ERROR")
                self.assertNotIn(text, repr(group))                                   # the raw output is never carried

    @case("HEALTH_PING_OUTPUT_WITHOUT_STATISTICS_REFUSED", target=f"{LIVE}::parse_ping_output", polarity=NEGATIVE,
          condition="ping output with no statistics line (timeout banner, error text)", expected="LiveError PARSE_ERROR; no fabricated loss figure")
    def test_ping_output_without_statistics_is_refused(self):
        for text in ("", "ping: unknown host", "PING 192.0.2.1 56(84) bytes of data."):
            with self.subTest(case=f"invalid {text!r}"):
                with self.assertRaises(live.LiveError) as ctx:
                    live.parse_ping_output(text)
                self.assertEqual(ctx.exception.code, "PARSE_ERROR")

    @case("HEALTH_PING_OUTPUT_PARSED", target=f"{LIVE}::parse_ping_output", polarity=POSITIVE,
          condition="iputils / cEOS ping statistics", expected="exact transmitted / received / loss / rtt figures")
    def test_ping_output_is_parsed_exactly(self):
        text = "3 packets transmitted, 2 received, 33.3333% packet loss, time 2003ms\nrtt min/avg/max/mdev = 0.041/0.052/0.063/0.009 ms\n"
        self.assertEqual(live.parse_ping_output(text), {"transmitted": 3, "received": 2, "loss_percent": 33.3333,
                                                        "rtt_min_ms": 0.041, "rtt_avg_ms": 0.052, "rtt_max_ms": 0.063})


def _add() -> None:
    for name in _parsers():
        def test(self, name=name):
            self._negative(name)

        kind = "unrecognised text" if name in TEXT_PARSERS else "malformed / wrong-shaped JSON"
        test = case(f"HEALTH_{name.upper()}_MALFORMED_FAILS_CLOSED", target=f"{LIVE}::{name}", polarity=NEGATIVE,
                    condition=f"{kind} from the device (garbage, list, scalar)",
                    expected="no facts" if name in TEXT_PARSERS else "raises; the device read records an UNAVAILABLE PARSE_ERROR group, never a crash")(test)
        setattr(HealthParserNegativeTests, f"test_{name}_refuses_malformed_output", test)


_add()


class ParserInventoryTests(SimpleTestCase):
    def test_every_parser_has_a_generated_negative_case(self):
        self.assertGreaterEqual(len(_parsers()), 19)
        for name in _parsers():
            with self.subTest(parser=name):
                self.assertTrue(hasattr(HealthParserNegativeTests, f"test_{name}_refuses_malformed_output"))
