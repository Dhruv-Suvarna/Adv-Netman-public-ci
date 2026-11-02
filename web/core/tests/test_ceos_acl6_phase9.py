"""V2 Phase 9 -- cEOS IPv6 ACLs and exact ACL import (ports by EOS name), each function called directly.

POSITIVE: IPv6 standard / extended lists and ``ipv6 access-group`` render in the grammar cEOS 4.36.2F accepted, EOS port
names import back to their numbers, and the capability probe records every stage from a fake isolated lab.  NEGATIVE: an
unknown port name, another port operator or trailing token is never guessed (the line stays unmodelled), IPv6 logging is
refused (EOS ignores it), a missing or altered entry fails the import check, and a probe whose compensation does not
restore the capture records FAIL.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase

from core.services import platform_drivers as D
from core.services.capabilities import batch_live as B
from core.services.config_import import ceos_port_names, parser_ceos
from core.services.execution.executors.base import ApplyOutcome, Assessment, CompensationOutcome

EOS_V6 = """ipv6 access-list CAP_ACL
   10 deny icmpv6 host 2001:db8:44::66 any
   15 deny tcp any range 1024 2048 host 2001:db8:44::1 eq www
   20 permit ipv6 any any
!
interface Ethernet1
   ipv6 access-group CAP_ACL in
"""


def _acl(family="IPV6", acl_type="EXTENDED"):
    acl = {"id": "acl_1", "name": "CAP_ACL", "family": family, "acl_type": acl_type}
    acl["entries"] = B.acl_entries(acl, {"id": "x", "source_port": "", "destination_port": ""})
    return acl


class CeosPortNameTests(SimpleTestCase):
    def test_port_number_returns_the_number_of_a_displayed_name_or_number(self):
        self.assertEqual([ceos_port_names.port_number(p, t) for p, t in (("tcp", "www"), ("TCP", "ssh"), ("udp", "bootps"),
                                                                          ("udp", "syslog"), ("tcp", "8080"))], [80, 22, 67, 514, 8080])

    def test_port_number_is_none_for_an_unknown_name_wrong_protocol_or_invalid_number(self):
        self.assertEqual([ceos_port_names.port_number(p, t) for p, t in (("tcp", "syslog"), ("udp", "www"), ("icmp", "www"),
                                                                          ("tcp", "70000"), ("tcp", ""), ("tcp", "nonexistent"))],
                         [None, None, None, None, None, None])


class CeosAclRenderTests(SimpleTestCase):
    def test_ceos_acl_protocol_returns_the_keyword_of_each_family(self):
        self.assertEqual([D.ceos_acl_protocol("IPV6", p) for p in ("IP", "IPV6", "ICMP", "ICMPV6", "TCP", None)],
                         ["ipv6", "ipv6", "icmpv6", "icmpv6", "tcp", "ipv6"])
        self.assertEqual([D.ceos_acl_protocol("IPV4", p) for p in ("IP", "ICMP", "UDP")], ["ip", "icmp", "udp"])

    def test_ceos_acl_protocol_of_an_unknown_family_falls_back_to_ipv4_keywords_not_ipv6(self):
        self.assertEqual(D.ceos_acl_protocol("", "ICMPV6"), "icmp")

    def test_render_ceos_acl_renders_ipv6_standard_and_extended_lists(self):
        standard = [r["text"] for r in D._render_ceos_acl(_acl(acl_type="STANDARD"))]   # pylint: disable=protected-access
        self.assertEqual(standard, ["ipv6 access-list standard CAP_ACL", "   10 deny host 2001:db8:44::66", "   20 permit any"])
        extended = [r["text"] for r in D._render_ceos_acl(_acl())]   # pylint: disable=protected-access
        self.assertEqual(extended, ["ipv6 access-list CAP_ACL", "   10 deny icmpv6 host 2001:db8:44::66 any",
                                    "   15 deny tcp any range 1024 2048 host 2001:db8:44::1 eq 80", "   20 permit ipv6 any any"])

    def test_render_ceos_acl_refuses_ipv6_logging_with_an_unsupported_marker(self):
        acl = _acl()
        acl["entries"]["ace_0000000000000015"]["logging"] = True
        texts = [r["text"] for r in D._render_ceos_acl(acl)]   # pylint: disable=protected-access
        self.assertFalse(any(t.endswith(" log") for t in texts))
        self.assertTrue(any(t.startswith(D.UNSUPPORTED_OBJECT_MARKER) and "logging on IPv6 ACL CAP_ACL entry 15" in t for t in texts))

    def test_acl_interface_contributions_render_an_ipv6_access_group(self):
        interface = {"_scope": {"acl_attachments": [{"family": "IPV6", "acl_name": "CAP_ACL", "direction": "IN"},
                                                    {"family": "IPV4", "acl_name": "V4", "direction": "OUT"}]}}
        self.assertEqual([r["text"] for r in D._acl_interface_contributions(interface)],   # pylint: disable=protected-access
                         ["   ipv6 access-group CAP_ACL in", "   ip access-group V4 out"])

    def test_acl_interface_contributions_skip_an_unknown_family_or_unsupported_platform(self):
        interface = {"_scope": {"acl_attachments": [{"family": "MPLS", "acl_name": "X"}, {"family": "IPV6", "acl_name": "Y"}]}}
        self.assertEqual(D._acl_interface_contributions(interface, platform="cisco_c8000v_iosxe"), [])   # pylint: disable=protected-access
        self.assertEqual(len(D._acl_interface_contributions(interface)), 1)   # pylint: disable=protected-access

    def test_ipv6_acl_features_are_supported_and_selectable_on_ceos(self):
        for feature in ("ACL_IPV6_STANDARD", "ACL_IPV6_EXTENDED", "ACL_ATTACH_IPV6"):
            self.assertTrue(D.is_service_policy_feature_selectable("arista_ceos", feature), feature)


class CeosAclImportTests(SimpleTestCase):
    def test_parse_imports_named_ports_of_an_ipv6_list(self):
        (acl,) = parser_ceos.parse(EOS_V6).acls
        entry = next(e for e in acl.entries if e["sequence"] == 15)
        self.assertEqual((acl.family, acl.acl_type, acl.preserved_lines), ("IPV6", "EXTENDED", []))
        self.assertEqual((entry["protocol"], entry["source_port"], entry["destination_port"], entry["destination_value"], entry["logging"]),
                         ("TCP", "1024-2048", "80", "2001:db8:44::1", False))

    def test_parse_never_guesses_an_unknown_port_name_or_operator(self):
        text = ("ip access-list X\n   10 permit tcp any eq unknownsvc any\n   20 permit tcp any gt 1000 any\n"
                "   30 permit udp any any eq bootps count\n   40 permit udp any any eq bootps log\n")
        (acl,) = parser_ceos.parse(text).acls
        self.assertEqual([e["sequence"] for e in acl.entries], [40])
        self.assertEqual(len(acl.preserved_lines), 3)
        self.assertEqual((acl.entries[0]["destination_port"], acl.entries[0]["logging"]), ("67", True))

    def test_standard_acl_preserves_trailing_tokens_and_logging_changes(self):
        intended = _acl(acl_type="STANDARD")
        valid = "ipv6 access-list standard CAP_ACL\n   10 deny host 2001:db8:44::66\n   20 permit any\n"
        self.assertTrue(B.acl_imported(parser_ceos.parse(valid), intended))
        trailing = valid.replace("20 permit any", "20 permit any count")
        parsed = parser_ceos.parse(trailing)
        self.assertEqual(len(parsed.acls[0].preserved_lines), 1)
        self.assertFalse(B.acl_imported(parsed, intended))
        logged = valid.replace("20 permit any", "20 permit any log")
        self.assertFalse(B.acl_imported(parser_ceos.parse(logged), intended))


class CeosAclHarnessTests(SimpleTestCase):
    def test_acl_entries_builds_a_protocol_and_port_entry_for_an_extended_list(self):
        entries = _acl()["entries"]
        self.assertEqual([(e["sequence"], e["action"], e["protocol"]) for e in entries.values()],
                         [(10, "DENY", "ICMPV6"), (15, "DENY", "TCP"), (20, "PERMIT", "IPV6")])
        v4 = _acl("IPV4")["entries"]["ace_0000000000000015"]
        self.assertEqual((v4["source_port"], v4["destination_port"], v4["logging"]), ("1024-2048", "80", True))

    def test_acl_entries_of_a_standard_list_has_no_protocol_or_port_entry(self):
        entries = _acl("IPV4", "STANDARD")["entries"]
        self.assertEqual([(e["sequence"], e["protocol"], e["source_value"]) for e in entries.values()],
                         [(10, "IP", "198.18.0.66"), (20, "IP", "")])

    def test_acl_imported_matches_the_live_list_exactly(self):
        self.assertTrue(B.acl_imported(parser_ceos.parse(EOS_V6), _acl()))

    def test_acl_imported_fails_for_a_missing_entry_another_port_or_a_preserved_line(self):
        for label, text in (("missing entry", EOS_V6.replace("   20 permit ipv6 any any\n", "")),
                            ("wrong port", EOS_V6.replace("eq www", "eq ssh")),
                            ("unmodelled line", EOS_V6.replace("eq www", "gt 79"))):
            with self.subTest(f"{label} fails"):
                self.assertFalse(B.acl_imported(parser_ceos.parse(text), _acl()))
        self.assertFalse(B.acl_imported(parser_ceos.parse(""), _acl()))


class _Executor:
    def __init__(self, text, restore=True):
        self.text, self.digests, self.restore = text, iter(["prep", "prep"] + (["prep", "prep"] if restore else ["other", "other"])), restore

    def _config_state_digest(self):
        return next(self.digests, "prep" if self.restore else "other")

    def _config_text(self):
        return self.text

    def assess(self, spec):
        return Assessment("APPLY", True, "")

    def apply(self, spec, preflight):
        return ApplyOutcome(True, lines_sent=len(spec.lines))

    def compensate(self, spec, preflight):
        return CompensationOutcome("COMPENSATED")


class _Lab:
    def __init__(self, executor, active=True):
        self.executor, self.prepared_digest, self.device, self.active = executor, "prep", {"name": "ceos", "container": "c"}, active
        self.applied = False
        self.reader = lambda device: B.live.read_device(device)

    def ping(self, node, target, *, source=""):
        return not (self.active and self.executor.restore is not None and self._filtering and source == B.ACL_DENIED["IPV6"])

    _filtering = False


class CeosProbeCellTests(SimpleTestCase):
    def _probe(self, executor, observed_config):
        lab = _Lab(executor)
        original_apply = executor.apply

        def apply(spec, preflight):
            lab._filtering = True   # pylint: disable=protected-access
            return original_apply(spec, preflight)

        def compensate(spec, preflight):
            lab._filtering = False   # pylint: disable=protected-access
            return CompensationOutcome("COMPENSATED")

        executor.apply, executor.compensate = apply, compensate
        observed = SimpleNamespace(live_reachable=True, facts=lambda name: observed_config if name == "config" else None)
        cell = SimpleNamespace(probes={}, runtime_version="")
        with mock.patch.object(B.live, "read_device", return_value=observed), mock.patch.object(B, "_run"):
            B.probe_cell(lab, cell, "service_policy.ACL_IPV6_EXTENDED")
        return cell

    CONFIG = {"acl_definitions": ["CAP_ACL"], "acl_attachments": [{"interface": "Ethernet1", "acl": "CAP_ACL", "direction": "IN"}]}

    def test_probe_cell_records_pass_for_every_stage_of_an_exact_ipv6_acl(self):
        cell = self._probe(_Executor(EOS_V6), self.CONFIG)
        self.assertEqual({name: p["outcome"] for name, p in cell.probes.items()},
                         dict.fromkeys(("live_write", "live_read", "live_post_write_validation", "parser_import",
                                        "runtime_validation", "compensation"), "PASS"))
        self.assertIn("ipv6 access-group CAP_ACL in", cell.probes["live_write"]["detail"])
        self.assertEqual(cell.runtime_version, B.RUNTIME)

    def test_probe_cell_records_a_failed_import_when_the_live_entries_differ(self):
        cell = self._probe(_Executor(EOS_V6.replace("eq www", "eq ssh")), self.CONFIG)
        self.assertEqual((cell.probes["parser_import"]["outcome"], cell.probes["parser_import"]["reason"]), ("FAIL", "PARSER_ABSENT"))

    def test_probe_cell_raises_when_the_prepared_lab_drifted(self):
        executor = _Executor(EOS_V6)
        executor.digests = iter(["drifted"])
        with self.assertRaisesRegex(RuntimeError, "drifted"):
            B.probe_cell(_Lab(executor), SimpleNamespace(probes={}, runtime_version=""), "service_policy.ACL_IPV6_STANDARD")
