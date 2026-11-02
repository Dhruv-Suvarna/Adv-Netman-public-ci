"""Ubuntu/FRR ACLs as nftables (V2 Phase 9): the shared grammar, renderer, strict executor, import, postcheck, live runner."""

from __future__ import annotations

import importlib.util
import itertools
import json
import re
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase

from core.services import nft_acl
from core.services import platform_drivers as drivers
from core.services.capabilities.features import by_key
from core.services.capabilities.probe_cases import sample
from core.services.config_import import parser_frr
from core.services.execution.executors import linux
from core.services.execution.executors.base import APPLY, REFUSE, ConfigletSpec
from core.services.health import evaluators, live, requirements as reqs
from core.services.health.codes import CheckStatus as S, Phase
from core.tests.helpers.health import device_evidence, evidence_set

TABLE = nft_acl.TABLE
DOCKER = 'table ip nat {\n\tchain DOCKER_OUTPUT {\n\t\tip daddr 127.0.0.11 udp dport 53 counter packets 4 bytes 603 xt target "DNAT"\n\t}\n}\n'
# ``nft list ruleset`` of nftables 1.0.9 with /etc/protocols present (captured from an Ubuntu 24.04 container)
LISTED = """table inet DEVICE_BUILDER_ACL {
\tchain acl4_CAP_ACL {
\t\tip saddr 198.18.0.66 drop comment "seq 10"
\t\tip saddr 198.18.0.66 meta l4proto icmp drop comment "seq 11"
\t\tip daddr 198.18.0.1 tcp sport 1024-2048 tcp dport 80 log drop comment "seq 15"
\t\tip saddr 198.18.9.0/24 ip daddr 198.18.0.0/30 meta l4proto udp accept comment "seq 16"
\t\taccept comment "seq 20"
\t\tdrop comment "implicit-deny EXTENDED"
\t}

\tchain acl6_Cap.v6-x {
\t\tip6 saddr 2001:db8:44::66 drop comment "seq 10"
\t\tip6 saddr 2001:db8:44::66 meta l4proto ipv6-icmp drop comment "seq 11"
\t\taccept comment "seq 20"
\t\ticmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } accept comment "implicit-nd"
\t\tdrop comment "implicit-deny EXTENDED"
\t}

\tchain filter_in {
\t\ttype filter hook prerouting priority filter; policy accept;
\t\tiifname "eth1" meta nfproto ipv4 jump acl4_CAP_ACL
\t\tiifname "eth1" meta nfproto ipv6 jump acl6_Cap.v6-x
\t}
}
"""
V4_CHAIN = LISTED.split("\n\n")[0].splitlines()[1:]          # "chain acl4_CAP_ACL {" .. "}"
HOOK_IN = ("chain filter_in {", "type filter hook prerouting priority filter; policy accept;")


def entry(sequence, action="PERMIT", **fields):
    return {"id": f"ace_{sequence}", "sequence": sequence, "action": action, **fields}


def acl(name="EDGE", family="IPV4", acl_type="EXTENDED", *entries, acl_id="acl_1"):
    rows = entries or (entry(10, "DENY", source_type="HOST", source_value="198.18.0.66"),)
    return {"id": acl_id, "name": name, "family": family, "acl_type": acl_type, "entries": {e["id"]: e for e in rows}}


def attachment(acl_id="acl_1", interface_id="if_1", direction="IN", attach_id="att_1"):
    return {"id": attach_id, "acl_id": acl_id, "interface_id": interface_id, "direction": direction}


def render_security(acls, attachments=(), interfaces=None):
    security = {"acls": {a["id"]: a for a in acls}, "attachments": {a["id"]: a for a in attachments}}
    rows = drivers._render_ubuntu_security("ubuntu_frr", "Ubuntu/FRR", security,
                                           interfaces or {"if_1": {"name": "eth3"}, "if_2": {"name": "eth2"}})
    return [row["text"] for row in rows if row.get("text")]


def spec(object_type, lines, cfg="c1"):
    return ConfigletSpec(cfg, 1, "frr", "ubuntu_frr", object_type, "CREATE_DEFINE", tuple(lines), {})


def batch():
    from core.services.capabilities import batch_frr_acl
    return batch_frr_acl


class FakeNft:
    """A small nft: the NMAS table as ordered chains, listed as nftables 1.0.9 (with netbase) prints it.  Each
    transaction applies to a copy and commits only if every command succeeds, as nft does."""

    NAMES = {"1": "icmp", "6": "tcp", "17": "udp", "58": "ipv6-icmp"}

    def __init__(self, chains=None, foreign=""):
        self.chains, self.foreign, self.sent = chains, foreign, []

    def listing(self):
        if self.chains is None:
            return DOCKER + self.foreign
        blocks = []
        for name, rules in self.chains.items():
            body = "".join("\t\t" + re.sub(r"meta l4proto (\d+)", lambda m: f"meta l4proto {self.NAMES[m.group(1)]}", rule) + "\n"
                           for rule in rules)
            blocks.append(f"\tchain {name} {{\n{body}\t}}\n")
        return DOCKER + f"table inet {TABLE} {{\n" + "\n".join(blocks) + "}\n"

    def _one(self, chains, line):
        words = line.split(" ", 5)
        if line == f"create table inet {TABLE}":
            return {} if chains is None else None
        if line == f"delete table inet {TABLE}":
            return None if chains is None else "deleted"
        if chains is None or words[2:4] != ["inet", TABLE]:
            return None
        name = words[4].split(" ")[0]
        if words[:2] == ["create", "chain"] and name not in chains:
            chains[name] = [line.split("{", 1)[1].strip().removesuffix("}").strip()] if "{" in line else []
        elif words[:2] == ["add", "rule"] and name in chains:
            target = words[5].split(" jump ")[1] if " jump " in words[5] else None
            if target is not None and target not in chains:
                return None
            chains[name].append(words[5])
        elif words[:2] == ["flush", "chain"] and name in chains:
            chains[name] = [rule for rule in chains[name][:1] if rule.startswith("type ")]
        elif words[:2] == ["delete", "chain"] and name in chains:
            if any(rule.endswith(f" jump {name}") for rules in chains.values() for rule in rules):
                return None                                  # EBUSY: still referenced
            del chains[name]
        else:
            return None
        return chains

    def run(self, _container, argv, _timeout):
        self.sent.append(argv)
        chains = None if self.chains is None else {name: list(rules) for name, rules in self.chains.items()}
        for line in argv[1].splitlines():
            chains = self._one(chains, line)
            if chains is None:
                return 1
            if chains == "deleted":
                chains = None
        self.chains = chains
        return 0

    def executor(self):
        return linux.LinuxExecutor({"name": "frr", "container": "x"}, runner=self.run,
                                   reader=lambda _d: SimpleNamespace(live_reachable=True),
                                   nft_reader=lambda _c, _t: self.listing())


def seeded_nft(interface="eth2"):
    legacy = nft_acl.acl_rules({"name": "LEGACY", "family": "IPV4", "acl_type": "STANDARD", "entries": {"e": {
        "id": "e", "sequence": 10, "action": "DENY", "source_type": "PREFIX", "source_value": "198.51.100.0/24"}}})
    return FakeNft({"acl4_LEGACY": legacy, "filter_in": [HOOK_IN[1], f'iifname "{interface}" meta nfproto ipv4 jump acl4_LEGACY']})


# --- grammar ---------------------------------------------------------------------------------------------------------
class NftAclGrammarTests(SimpleTestCase):
    def test_listed_table_with_protocol_names_parses_to_the_rendered_model(self):
        model = nft_acl.table_from_ruleset(DOCKER + LISTED)
        self.assertEqual(set(model["acls"]), {"acl4_CAP_ACL", "acl6_Cap.v6-x"})
        self.assertEqual(model["hooks"], {"IN": [("eth1", "IPV4", "acl4_CAP_ACL"), ("eth1", "IPV6", "acl6_Cap.v6-x")], "OUT": []})
        v4 = model["acls"]["acl4_CAP_ACL"]
        self.assertEqual((v4["name"], v4["family"], v4["acl_type"], len(v4["entries"])), ("CAP_ACL", "IPV4", "EXTENDED", 5))
        self.assertEqual(v4["rules"][1], 'ip saddr 198.18.0.66 meta l4proto 1 drop comment "seq 11"')
        self.assertEqual(v4["entries"][2], {"sequence": 15, "action": "DENY", "protocol": "TCP", "source_type": "ANY",
                                            "source_value": "", "destination_type": "HOST", "destination_value": "198.18.0.1",
                                            "source_port": "1024-2048", "destination_port": "80", "logging": True})
        numeric = re.sub(r"l4proto (icmp|udp|ipv6-icmp)", lambda m: "l4proto " + {"icmp": "1", "udp": "17", "ipv6-icmp": "58"}[m.group(1)],
                         LISTED)
        self.assertEqual(nft_acl.table_from_ruleset(numeric), model)

    def test_every_entry_shape_renders_and_parses_back_exactly(self):
        cases = [
            ("IPV4", "STANDARD", entry(10, "DENY", source_type="HOST", source_value="198.18.0.66")),
            ("IPV4", "STANDARD", entry(20, source_type="PREFIX", source_value="198.18.9.7/24")),
            ("IPV4", "EXTENDED", entry(30, protocol="UDP", destination_type="PREFIX", destination_value="10.0.0.0/8",
                                       destination_port="53")),
            ("IPV4", "EXTENDED", entry(40, "DENY", protocol="ICMP", logging=True)),
            ("IPV6", "EXTENDED", entry(50, protocol="ICMPV6", source_type="PREFIX", source_value="2001:db8::/32")),
            ("IPV6", "EXTENDED", entry(60, protocol="TCP", source_port="1000-2000", destination_port="443")),
            ("IPV6", "STANDARD", entry(70, source_type="PREFIX", source_value="2001:db8::5/128")),
        ]
        for family, acl_type, row in cases:
            with self.subTest(rule=row["sequence"]):
                rule = nft_acl.entry_rule(family, acl_type, row)
                parsed = nft_acl.parse_rule(family, acl_type, rule)
                self.assertIsNotNone(parsed, rule)
                self.assertEqual(nft_acl.entry_rule(family, acl_type, parsed), rule)
        self.assertEqual(nft_acl.entry_rule("IPV4", "STANDARD", cases[1][2]), 'ip saddr 198.18.9.0/24 accept comment "seq 20"')
        self.assertEqual(nft_acl.entry_rule("IPV6", "STANDARD", cases[6][2]), 'ip6 saddr 2001:db8::5 accept comment "seq 70"')

    def test_entries_without_an_exact_nft_form_are_refused(self):
        cases = {
            "action": entry(10, "REMARK"), "sequence": {"action": "PERMIT"},
            "family of host": entry(10, source_type="HOST", source_value="2001:db8::1"),
            "family of prefix": entry(10, source_type="PREFIX", source_value="2001:db8::/32"),
            "garbage address": entry(10, source_type="HOST", source_value="198.18.0.300"),
            "port without tcp/udp": entry(10, protocol="ICMP", destination_port="80"),
            "port on any protocol": entry(10, destination_port="80"),
            "descending range": entry(10, protocol="TCP", destination_port="90-80"),
            "port zero": entry(10, protocol="TCP", destination_port="0"),
            "port overflow": entry(10, protocol="TCP", destination_port="70000"),
            "protocol": entry(10, protocol="GRE"),
        }
        for label, row in cases.items():
            with self.subTest(case=label):
                with self.assertRaises(nft_acl.AclRenderError):
                    nft_acl.entry_rule("IPV4", "EXTENDED", row)

    def test_listed_rules_not_in_the_rendered_spelling_are_refused(self):
        cases = {
            "host as /32": 'ip saddr 198.18.0.66/32 drop comment "seq 10"',
            "host bits in prefix": 'ip saddr 198.18.9.7/24 drop comment "seq 10"',
            "counter": 'ip saddr 198.18.0.66 counter drop comment "seq 10"',
            "unknown protocol": 'meta l4proto 47 drop comment "seq 10"',
            "ports reversed": 'tcp dport 80 tcp sport 1024 drop comment "seq 10"',
            "family keyword": 'ip6 saddr 198.18.0.66 drop comment "seq 10"',
            "no comment": "ip saddr 198.18.0.66 drop",
            "jump": 'jump other comment "seq 10"',
        }
        for label, rule in cases.items():
            with self.subTest(case=label):
                self.assertIsNone(nft_acl.parse_rule("IPV4", "EXTENDED", rule))
        self.assertIsNone(nft_acl.parse_rule("IPV4", "STANDARD", 'meta l4proto 6 drop comment "seq 10"'))

    def test_any_departure_from_the_table_shape_refuses_the_whole_table(self):
        lines = LISTED.splitlines()
        v6_start = lines.index("\tchain acl6_Cap.v6-x {")
        bad = {
            "no implicit deny": [line for line in lines if "implicit-deny EXTENDED" not in line],
            "v6 list without nd rule": [line for line in lines if "implicit-nd" not in line],
            "entries out of order": lines[:2] + [lines[3], lines[2]] + lines[4:],
            "duplicate sequence": lines[:3] + [lines[2]] + lines[3:],
            "jump to other family": [line.replace("ipv6 jump acl6", "ipv6 jump acl4") for line in lines],
            "two lists one interface": [line.replace("jump acl6_Cap.v6-x", "jump acl6_Cap.v6-x") for line in lines[:-2]]
                                       + ['\t\tiifname "eth1" meta nfproto ipv6 jump acl6_Cap.v6-x'] + lines[-2:],
            "oifname in filter_in": [line.replace("iifname", "oifname") for line in lines],
            "undefined chain": lines[:v6_start - 1] + lines[v6_start + 7:],
            "interface injection": [line.replace('"eth1"', '"eth1; flush ruleset"') for line in lines],
            "unknown chain": [line.replace("chain acl6_Cap.v6-x", "chain input") for line in lines],
            "hook statement": lines[:-3] + ["\t\tcounter accept"] + lines[-3:],
            "hook priority": [line.replace("priority filter", "priority raw") for line in lines],
            "unclosed table": lines[:-1],
            "other family": [line.replace("table inet", "table ip") for line in lines],
        }
        for label, variant in bad.items():
            with self.subTest(case=label):
                self.assertIsNone(nft_acl.parse_table(variant), label)

    def test_snippet_mode_reads_a_configlet_with_dangling_jumps(self):
        lines = (nft_acl.TABLE_HEADER, "    chain filter_out {", "        type filter hook postrouting priority filter; policy accept;",
                 '        oifname "eth3" meta nfproto ipv6 jump acl6_X', "    }")
        self.assertIsNone(nft_acl.parse_table(lines))
        self.assertEqual(nft_acl.parse_table(lines, snippet=True)["hooks"]["OUT"], [("eth3", "IPV6", "acl6_X")])
        self.assertEqual(nft_acl.parse_table(("! comment", *V4_CHAIN), snippet=True)["acls"]["acl4_CAP_ACL"]["acl_type"], "EXTENDED")

    def test_ruleset_without_the_table_or_with_a_foreign_table_is_told_apart(self):
        self.assertIsNone(nft_acl.table_from_ruleset(DOCKER))
        self.assertIs(nft_acl.table_from_ruleset(DOCKER + f"table inet {TABLE} {{\n\tchain input {{\n\t}}\n}}\n"), False)

    def test_acl_rules_sorts_entries_and_ends_with_nd_and_deny(self):
        rules = nft_acl.acl_rules(acl("V6", "IPV6", "STANDARD", entry(20), entry(10, "DENY", source_type="HOST",
                                                                                     source_value="2001:db8:44::66")))
        self.assertEqual(rules, ['ip6 saddr 2001:db8:44::66 drop comment "seq 10"', 'accept comment "seq 20"', nft_acl.ND_RULE,
                                 'drop comment "implicit-deny STANDARD"'])

    def test_standard_list_ignores_destination_and_protocol_fields(self):
        row = entry(10, "DENY", source_type="HOST", source_value="198.18.0.66", protocol="TCP", destination_port="80")
        self.assertEqual(nft_acl.entry_rule("IPV4", "STANDARD", row), 'ip saddr 198.18.0.66 drop comment "seq 10"')


class NftAclDirectCaseTests(SimpleTestCase):
    """Single-polarity direct cases for each public boundary (test governance links a symbol only to a direct caller)."""

    def test_chain_name_builds_the_family_prefixed_chain(self):
        self.assertEqual((nft_acl.chain_name("IPV4", "A"), nft_acl.chain_name("IPV6", "B")), ("acl4_A", "acl6_B"))

    def test_chain_name_refuses_an_unknown_family(self):
        with self.assertRaises(KeyError):
            nft_acl.chain_name("IPV5", "A")

    def test_implicit_deny_returns_the_rule_carrying_the_list_type(self):
        self.assertEqual(nft_acl.implicit_deny("STANDARD"), 'drop comment "implicit-deny STANDARD"')

    def test_implicit_deny_of_an_unknown_type_is_refused_on_read(self):
        self.assertIsNone(nft_acl.parse_table(("chain acl4_X {", nft_acl.implicit_deny("OTHER"), "}"), snippet=True))

    def test_hook_header_returns_the_base_chain_lines(self):
        self.assertEqual(nft_acl.hook_header("OUT"), ("chain filter_out {",
                                                      "type filter hook postrouting priority filter; policy accept;"))

    def test_hook_header_refuses_an_unknown_direction(self):
        with self.assertRaises(KeyError):
            nft_acl.hook_header("BOTH")

    def test_jump_rule_guards_the_family_on_the_jump(self):
        self.assertEqual(nft_acl.jump_rule("IN", "eth1", "IPV6", "acl6_X"), 'iifname "eth1" meta nfproto ipv6 jump acl6_X')

    def test_jump_rule_refuses_an_unknown_direction(self):
        with self.assertRaises(KeyError):
            nft_acl.jump_rule("BOTH", "eth1", "IPV4", "acl4_X")

    def test_entry_rule_renders_a_logged_port_entry(self):
        self.assertEqual(nft_acl.entry_rule("IPV4", "EXTENDED", entry(15, "DENY", protocol="TCP", source_port="1024-2048",
                                                                      destination_port="80", logging=True)),
                         'tcp sport 1024-2048 tcp dport 80 log drop comment "seq 15"')

    def test_entry_rule_refuses_a_port_without_tcp_or_udp(self):
        with self.assertRaisesRegex(nft_acl.AclRenderError, "TCP or UDP"):
            nft_acl.entry_rule("IPV4", "EXTENDED", entry(10, protocol="ICMP", source_port="80"))

    def test_acl_rules_returns_entries_then_the_implicit_deny(self):
        self.assertEqual(nft_acl.acl_rules(acl("A", "IPV4", "STANDARD", entry(10))), ['accept comment "seq 10"',
                                                                                     'drop comment "implicit-deny STANDARD"'])

    def test_acl_rules_refuses_a_duplicate_sequence(self):
        with self.assertRaisesRegex(nft_acl.AclRenderError, "share a sequence"):
            nft_acl.acl_rules(acl("A", "IPV4", "STANDARD", entry(10), {**entry(10), "id": "other"}))

    def test_acl_rules_refuses_a_bad_name_or_type(self):
        with self.assertRaises(nft_acl.AclRenderError):
            nft_acl.acl_rules(acl("1-bad name"))
        with self.assertRaises(nft_acl.AclRenderError):
            nft_acl.acl_rules(acl("A", "IPV4", "REFLEXIVE"))

    def test_refusal_is_empty_for_a_renderable_list(self):
        self.assertEqual(nft_acl.refusal(acl()), "")

    def test_refusal_names_why_a_list_cannot_render(self):
        self.assertIn("is not an IPV4 address", nft_acl.refusal(acl("A", "IPV4", "STANDARD", entry(10, source_type="HOST",
                                                                                                 source_value="::1"))))

    def test_normalize_rule_folds_protocol_names_and_whitespace(self):
        self.assertEqual(nft_acl.normalize_rule('  meta l4proto ipv6-icmp\t drop comment "seq 1" '),
                         'meta l4proto 58 drop comment "seq 1"')

    def test_normalize_rule_never_folds_an_unknown_protocol_name(self):
        self.assertEqual(nft_acl.normalize_rule('meta l4proto gre drop comment "seq 1"'), 'meta l4proto gre drop comment "seq 1"')

    def test_parse_rule_returns_the_entry_of_a_listed_rule(self):
        self.assertEqual(nft_acl.parse_rule("IPV6", "EXTENDED", 'ip6 saddr 2001:db8::/32 meta l4proto ipv6-icmp accept comment "seq 5"'),
                         {"sequence": 5, "action": "PERMIT", "protocol": "ICMPV6", "source_type": "PREFIX",
                          "source_value": "2001:db8::/32", "destination_type": "ANY", "destination_value": "", "source_port": "",
                          "destination_port": "", "logging": False})

    def test_parse_rule_refuses_a_counter_statement(self):
        self.assertIsNone(nft_acl.parse_rule("IPV4", "STANDARD", 'counter accept comment "seq 5"'))

    def test_parse_table_reads_the_listed_table(self):
        self.assertEqual(len(nft_acl.parse_table(LISTED.splitlines())["acls"]), 2)

    def test_parse_table_refuses_a_missing_header(self):
        self.assertIsNone(nft_acl.parse_table(LISTED.splitlines()[1:]))

    def test_table_from_ruleset_returns_the_model_after_unrelated_tables(self):
        self.assertEqual(nft_acl.table_from_ruleset(DOCKER + LISTED)["hook_chains"], ["filter_in"])

    def test_table_from_ruleset_is_none_when_the_table_is_absent(self):
        self.assertIsNone(nft_acl.table_from_ruleset(""))

    def test_create_chain_commands_creates_then_adds_each_rule(self):
        self.assertEqual(nft_acl.create_chain_commands("acl4_A", ["accept", "drop"]),
                         f"create chain inet {TABLE} acl4_A\nadd rule inet {TABLE} acl4_A accept\nadd rule inet {TABLE} acl4_A drop\n")

    def test_create_chain_commands_with_no_rules_adds_nothing_but_the_chain(self):
        self.assertEqual(nft_acl.create_chain_commands("acl4_A", []), f"create chain inet {TABLE} acl4_A\n")

    def test_replace_chain_commands_flushes_then_adds(self):
        self.assertEqual(nft_acl.replace_chain_commands("acl4_A", ["drop"]),
                         f"flush chain inet {TABLE} acl4_A\nadd rule inet {TABLE} acl4_A drop\n")

    def test_replace_chain_commands_with_empty_rules_only_flushes(self):
        self.assertEqual(nft_acl.replace_chain_commands("acl4_A", []), f"flush chain inet {TABLE} acl4_A\n")

    def test_create_hook_commands_creates_the_base_chain(self):
        self.assertEqual(nft_acl.create_hook_commands("IN"),
                         f"create chain inet {TABLE} filter_in {{ type filter hook prerouting priority filter; policy accept; }}\n")

    def test_create_hook_commands_refuses_an_unknown_direction(self):
        with self.assertRaises(KeyError):
            nft_acl.create_hook_commands("BOTH")

    def test_jump_commands_adds_one_rule_per_jump(self):
        self.assertEqual(nft_acl.jump_commands("OUT", [("eth3", "IPV4", "acl4_A")]),
                         f'add rule inet {TABLE} filter_out oifname "eth3" meta nfproto ipv4 jump acl4_A\n')

    def test_jump_commands_with_no_jumps_is_empty(self):
        self.assertEqual(nft_acl.jump_commands("OUT", []), "")


# --- renderer --------------------------------------------------------------------------------------------------------
class UbuntuAclRendererTests(SimpleTestCase):
    CODES = ("ACL_IPV4_STANDARD", "ACL_IPV4_EXTENDED", "ACL_IPV6_STANDARD", "ACL_IPV6_EXTENDED", "ACL_ATTACH_IPV4", "ACL_ATTACH_IPV6")

    def test_every_acl_cell_is_supported_on_ubuntu_frr(self):
        for code in self.CODES:
            with self.subTest(code=code):
                self.assertEqual(drivers._service_policy_capability_or_not_implemented("ubuntu_frr", code).status,
                                 drivers.CapabilityStatus.SUPPORTED)

    def test_definitions_and_both_directions_render_as_one_table(self):
        v6 = acl("V6", "IPV6", "STANDARD", entry(10), acl_id="acl_2")
        lines = render_security([acl(), v6], [attachment(), attachment("acl_2", "if_1", "OUT", "att_2")])
        self.assertEqual(lines, [
            nft_acl.TABLE_HEADER, "    chain acl4_EDGE {", '        ip saddr 198.18.0.66 drop comment "seq 10"',
            '        drop comment "implicit-deny EXTENDED"', "    }", "    chain acl6_V6 {", '        accept comment "seq 10"',
            f"        {nft_acl.ND_RULE}", '        drop comment "implicit-deny STANDARD"', "    }", "    chain filter_in {",
            "        type filter hook prerouting priority filter; policy accept;",
            '        iifname "eth3" meta nfproto ipv4 jump acl4_EDGE', "    }", "    chain filter_out {",
            "        type filter hook postrouting priority filter; policy accept;",
            '        oifname "eth3" meta nfproto ipv6 jump acl6_V6', "    }", "}",
            "! Traffic-impact validation has not run; project validation pending."])
        model = nft_acl.parse_table(lines)
        self.assertEqual(model["hooks"], {"IN": [("eth3", "IPV4", "acl4_EDGE")], "OUT": [("eth3", "IPV6", "acl6_V6")]})

    def test_unrenderable_lists_and_attachments_are_refused_with_a_marker(self):
        broken = acl("BAD", "IPV4", "EXTENDED", entry(10, protocol="ICMP", destination_port="80"), acl_id="acl_bad")
        twin = acl("EDGE", acl_id="acl_twin")
        lines = render_security([acl(), broken, twin], [
            attachment(), attachment("acl_bad", attach_id="att_bad"), attachment(interface_id="if_9", attach_id="att_noif"),
            attachment(direction="SIDEWAYS", attach_id="att_dir"), attachment(interface_id="if_1", attach_id="att_twice")])
        markers = [line for line in lines if line.startswith(drivers.UNSUPPORTED_OBJECT_MARKER)]
        for needle in ("ACL BAD (a port match needs protocol TCP or UDP)", "ACL EDGE (another ACL of this family already has that name)",
                       "att_bad (its ACL is not rendered)", "att_noif (a known direction and an interface name are required)",
                       "att_dir (a known direction", "att_twice (another IPV4 ACL is already attached in on eth3)"):
            with self.subTest(marker=needle):
                self.assertTrue(any(needle in line for line in markers), markers)
        self.assertTrue(all("NOT_IMPLEMENTED" in line for line in markers), markers)
        self.assertEqual(sum("jump acl4_EDGE" in line for line in lines), 1)
        self.assertNotIn("    chain acl4_BAD {", lines)

    def test_no_security_intent_renders_the_not_configured_comment(self):
        self.assertEqual(render_security([]), ["! Security/ACL: not configured in current candidate"])

    def test_canonical_samples_render_the_table_and_plan_executable_configlets(self):
        from core.services.capabilities.offline_verify import _descriptors
        for code in self.CODES:
            key = f"service_policy.{code}"
            with self.subTest(code=code):
                rendered = _descriptors("ubuntu_frr", sample("ubuntu_frr", by_key()[key]).sections)
                self.assertIn(nft_acl.TABLE_HEADER, rendered)
                specs, requirements, _sections = batch().plan(key)
                self.assertEqual([s.object_type for s in specs], ["acl", "acl_attachment"])
                self.assertTrue(all(linux.acl_request(s) for s in specs))
                self.assertEqual({r.kind for r in requirements}, {"ACL_DEFINED", "ACL_ATTACHMENT_INTENDED"})


# --- executor --------------------------------------------------------------------------------------------------------
class AclExecutorTests(SimpleTestCase):
    """The registered LinuxExecutor against a fake nft that applies transactions atomically, as nft does."""

    def planned(self, key="service_policy.ACL_IPV4_EXTENDED", direction="IN"):
        specs, _requirements, _sections = batch().plan(key, direction)
        return specs

    def run_engine_order(self, fake, specs):
        executor = fake.executor()
        preflight = [executor.assess(s) for s in specs]
        self.assertEqual([(p.action, p.restorable) for p in preflight], [(APPLY, True)] * len(specs))
        for s, p in zip(specs, preflight):
            self.assertTrue(executor.apply(s, p).ok, fake.sent)
        self.assertEqual([executor.assess(s).action for s in specs], ["SKIP_SATISFIED"] * len(specs))
        statuses = [executor.compensate(s, p).status for s, p in reversed(list(zip(specs, preflight)))]
        return executor, statuses

    def test_pristine_node_creates_the_table_and_compensation_deletes_it(self):
        fake = FakeNft()
        specs = self.planned()
        _executor, statuses = self.run_engine_order(fake, specs)
        self.assertTrue(fake.sent[0][1].startswith(f"create table inet {TABLE}\ncreate chain inet {TABLE} acl4_CAP_ACL\n"))
        self.assertTrue(fake.sent[1][1].startswith(f"create chain inet {TABLE} filter_in {{"))
        self.assertEqual(statuses, ["COMPENSATED", "COMPENSATED"])
        self.assertEqual(fake.sent[-2:], [["nft", f"delete chain inet {TABLE} filter_in\n"], ["nft", f"delete table inet {TABLE}\n"]])
        self.assertEqual(fake.listing(), DOCKER)

    def test_existing_nmas_table_is_extended_and_restored_exactly(self):
        fake = seeded_nft()
        before = fake.listing()
        _executor, statuses = self.run_engine_order(fake, self.planned("service_policy.ACL_ATTACH_IPV4"))
        self.assertEqual(fake.sent[1], ["nft", nft_acl.jump_commands("IN", [("eth3", "IPV4", "acl4_CAP_ACL")])])
        self.assertEqual(statuses, ["COMPENSATED", "COMPENSATED"])
        self.assertTrue(fake.sent[-2][1].startswith(f"flush chain inet {TABLE} filter_in\n"))
        self.assertEqual(fake.listing(), before)

    def test_out_attachment_on_a_seeded_table_creates_and_deletes_only_its_hook_chain(self):
        fake = seeded_nft()
        before = fake.listing()
        _executor, statuses = self.run_engine_order(fake, self.planned("service_policy.ACL_ATTACH_IPV6", "OUT"))
        self.assertEqual(statuses, ["COMPENSATED", "COMPENSATED"])
        self.assertEqual(fake.sent[-2], ["nft", f"delete chain inet {TABLE} filter_out\n"])
        self.assertEqual(fake.listing(), before)

    def test_redefined_list_is_replaced_then_restored_to_its_captured_rules(self):
        old = nft_acl.acl_rules(acl("CAP_ACL", "IPV4", "EXTENDED", entry(5)))
        fake = FakeNft({"acl4_CAP_ACL": list(old)})
        definition = self.planned()[0]
        executor = fake.executor()
        preflight = executor.assess(definition)
        self.assertEqual((preflight.action, preflight.restorable, preflight.previous_state["replaces"]), (APPLY, True, True))
        self.assertTrue(executor.apply(definition, preflight).ok)
        self.assertTrue(fake.sent[0][1].startswith(f"flush chain inet {TABLE} acl4_CAP_ACL\n"))
        self.assertEqual(executor.compensate(definition, preflight).status, "COMPENSATED")
        self.assertEqual(fake.chains["acl4_CAP_ACL"], old)

    def test_conflicting_attachment_or_foreign_table_is_never_written(self):
        attach = self.planned()[1]
        foreign = FakeNft(foreign=f"table inet {TABLE} {{\n\tchain input {{\n\t\ttype filter hook input priority 0; policy drop;\n\t}}\n}}\n")
        for label, fake in (("conflict", seeded_nft("eth3")), ("foreign", foreign)):
            with self.subTest(case=label):
                executor = fake.executor()
                found = executor.assess(attach)
                self.assertEqual((found.action, found.restorable, found.reason), (APPLY, False, "COMPENSATION_NOT_PROVABLE"))
                self.assertEqual(executor.apply(attach, found).error_code, "UNSUPPORTED")
                self.assertEqual(fake.sent, [])

    def test_apply_refuses_foreign_content_that_appeared_after_preflight(self):
        fake = FakeNft()
        definition = self.planned()[0]
        executor = fake.executor()
        preflight = executor.assess(definition)
        fake.foreign = f"table inet {TABLE} {{\n\tchain input {{\n\t}}\n}}\n"
        outcome = executor.apply(definition, preflight)
        self.assertEqual((outcome.ok, outcome.error_code), (False, "COMMAND_REJECTED"))
        self.assertEqual(fake.sent, [])

    def test_nft_rejects_a_jump_to_a_missing_list_and_nothing_is_written(self):
        fake = FakeNft()
        attach = self.planned()[1]
        executor = fake.executor()
        outcome = executor.apply(attach, executor.assess(attach))
        self.assertEqual((outcome.ok, outcome.error_code), (False, "COMMAND_REJECTED"))
        self.assertIsNone(fake.chains)

    def test_compensation_refuses_to_delete_a_table_that_gained_other_chains(self):
        fake = FakeNft()
        definition = self.planned()[0]
        executor = fake.executor()
        preflight = executor.assess(definition)
        self.assertTrue(executor.apply(definition, preflight).ok)
        fake.chains["acl4_OTHER"] = [nft_acl.implicit_deny("STANDARD")]
        outcome = executor.compensate(definition, preflight)
        self.assertEqual((outcome.status, outcome.error_code), ("COMPENSATION_FAILED", "STATE_NOT_RESTORED"))
        self.assertIn("acl4_CAP_ACL", fake.chains)

    def test_malformed_or_mixed_acl_configlets_are_refused(self):
        definition, attach = self.planned()
        executor = FakeNft().executor()
        for label, bad in (("mixed", spec("acl_attachment", definition.lines)), ("both", spec("acl", (*definition.lines, *attach.lines[1:]))),
                           ("garbage", spec("acl", ("table inet DEVICE_BUILDER_ACL {", "    flush ruleset")))):
            with self.subTest(case=label):
                self.assertEqual(executor.assess(bad).action, REFUSE)

    def test_acl_request_reads_a_definition_or_an_attachment(self):
        definition, attach = self.planned()
        self.assertEqual(linux.acl_request(definition)["chain"], "acl4_CAP_ACL")
        self.assertEqual(linux.acl_request(attach), {"direction": "IN", "jump": ("eth3", "IPV4", "acl4_CAP_ACL")})

    def test_acl_request_refuses_a_definition_without_a_list(self):
        self.assertIsNone(linux.acl_request(spec("acl", (nft_acl.TABLE_HEADER, *nft_acl.hook_header("IN"), "}"))))


# --- import / postcheck ----------------------------------------------------------------------------------------------
class AclImportAndPostcheckTests(SimpleTestCase):
    ADDR = json.dumps([{"ifname": "eth1", "flags": ["UP"], "mtu": 1500, "addr_info": []}])

    def test_parser_imports_each_list_and_its_attachment(self):
        parsed = parser_frr.parse("", addr_json=self.ADDR, nft_text=DOCKER + LISTED)
        self.assertEqual({(a.name, a.family, a.acl_type, len(a.entries)) for a in parsed.acls},
                         {("CAP_ACL", "IPV4", "EXTENDED", 5), ("Cap.v6-x", "IPV6", "EXTENDED", 3)})
        (eth1,) = [i for i in parsed.interfaces if i.name == "eth1"]
        self.assertEqual(eth1.acl_attachments, [{"family": "IPV4", "name": "CAP_ACL", "direction": "IN"},
                                                {"family": "IPV6", "name": "Cap.v6-x", "direction": "IN"}])

    def test_parser_imports_nothing_from_a_foreign_table(self):
        parsed = parser_frr.parse("", addr_json=self.ADDR, nft_text=LISTED.replace("priority filter", "priority raw"))
        self.assertEqual(parsed.acls, [])

    def test_parse_nft_acl_reports_definitions_and_attachments(self):
        self.assertEqual(live.parse_nft_acl(DOCKER + LISTED), {
            "acl_definitions": ["CAP_ACL", "Cap.v6-x"],
            "acl_attachments": [{"interface": "eth1", "acl": "CAP_ACL", "direction": "IN"},
                                {"interface": "eth1", "acl": "Cap.v6-x", "direction": "IN"}]})

    def test_parse_nft_acl_is_empty_when_the_table_is_absent_or_foreign(self):
        self.assertEqual(live.parse_nft_acl(DOCKER), {"acl_definitions": [], "acl_attachments": []})
        self.assertEqual(live.parse_nft_acl(None), {"acl_definitions": [], "acl_attachments": []})

    def evaluate(self, kind, expected, config):
        requirement = reqs.Requirement(cfg_id="CFG-1", device="R1", kind=kind, label="R1 acl", object_type="t", object_id="o",
                                       expected=expected, check_types=reqs.expand(kind, expected))
        evidence = evidence_set(device_evidence("R1", platform="linux", config=config))
        return evaluators.evaluate_requirements([requirement], Phase.POSTCHECK, evidence).results[0]

    def test_postcheck_passes_on_the_read_back_table_and_fails_on_another_direction(self):
        config = live.parse_nft_acl(LISTED)
        self.assertEqual(self.evaluate("ACL_DEFINED", {"name": "Cap.v6-x", "family": "IPV6"}, config).status, S.PASS)
        attached = {"acl_name": "CAP_ACL", "interface": "eth1", "direction": "IN"}
        self.assertEqual(self.evaluate("ACL_ATTACHMENT_INTENDED", attached, config).status, S.PASS)
        failed = self.evaluate("ACL_ATTACHMENT_INTENDED", {**attached, "direction": "OUT"}, config)
        self.assertEqual((failed.status, failed.check_code), (S.FAIL, "ACL_ATTACHMENT_MISSING"))
        self.assertEqual(self.evaluate("ACL_DEFINED", {"name": "OTHER", "family": "IPV4"}, config).status, S.FAIL)

    def test_dhcp_relay_is_unknown_on_a_config_read_without_relay_facts(self):
        result = self.evaluate("DHCP_RELAY_INTENDED", {"interface": "eth1", "destination": "198.18.0.9"}, live.parse_nft_acl(LISTED))
        self.assertEqual(result.status, S.UNKNOWN)

    def test_linux_health_reads_the_acl_table_as_its_config_group(self):
        self.assertIn("config", live.HEALTH_CAPABILITIES["linux"]["groups"])
        self.assertEqual(live._LINUX_GROUPS["config"](lambda name: LISTED if name == "nft" else "")["acl_definitions"],
                         ["CAP_ACL", "Cap.v6-x"])


# --- live runner (offline) -------------------------------------------------------------------------------------------
class AclProbePlanTests(SimpleTestCase):
    """Direct cases for the live runner's planning helpers, with no container touched."""

    def test_family_reads_ipv6_from_the_cell_key(self):
        self.assertEqual(batch().family("service_policy.ACL_IPV6_STANDARD"), "IPV6")
        self.assertEqual(batch().family("service_policy.ACL_ATTACH_IPV6"), "IPV6")

    def test_family_is_not_ipv6_without_an_ipv6_marker(self):
        self.assertEqual(batch().family("service_policy.ACL_ATTACH_IPV4"), "IPV4")

    def test_intent_attaches_the_lab_list_on_the_lab_port(self):
        sections = batch().intent("service_policy.ACL_IPV6_EXTENDED", "OUT")
        (row,) = sections["security"]["acls"].values()
        self.assertEqual([e["sequence"] for e in row["entries"].values()], [10, 15, 20])
        self.assertEqual(next(iter(sections["interfaces"].values()))["name"], batch().PORT)
        (attached,) = sections["security"]["attachments"].values()
        self.assertEqual((attached["acl_id"], attached["direction"]), (row["id"], "OUT"))

    def test_intent_refuses_an_unknown_cell(self):
        with self.assertRaises(KeyError):
            batch().intent("service_policy.ACL_IPV9_STANDARD")

    def test_planner_context_carries_the_sample_security_intent(self):
        sections = batch().intent("service_policy.ACL_IPV4_STANDARD")
        ctx = batch().planner_context(sections)
        self.assertEqual((ctx.platform, ctx.name, ctx.phase12["security"]), ("ubuntu_frr", "frr", sections["security"]))

    def test_planner_context_refuses_intent_without_interfaces(self):
        with self.assertRaises(KeyError):
            batch().planner_context({"security": {}})

    def test_plan_builds_the_definition_and_attachment_configlets(self):
        specs, requirements, _sections = batch().plan("service_policy.ACL_IPV4_STANDARD")
        self.assertEqual([(s.object_type, s.expected) for s in specs],
                         [("acl", {"name": "CAP_ACL", "family": "IPV4"}),
                          ("acl_attachment", {"acl_name": "CAP_ACL", "interface": "eth3", "direction": "IN"})])
        self.assertEqual(len(requirements), 2)

    def test_plan_refuses_an_unknown_cell(self):
        with self.assertRaises(KeyError):
            batch().plan("service_policy.ACL_NONE")

    def test_seed_creates_a_legacy_list_the_preservation_check_recognises(self):
        fake = FakeNft()
        self.assertEqual(fake.run("x", ["nft", batch().seed("IPV6")], 1), 0)
        self.assertTrue(batch().preserved("IPV6", fake.listing()))

    def test_seed_refuses_an_unknown_family(self):
        with self.assertRaises(KeyError):
            batch().seed("IPV5")

    def test_preserved_is_false_when_the_legacy_list_is_missing_or_changed(self):
        self.assertFalse(batch().preserved("IPV4", DOCKER))
        fake = FakeNft()
        fake.run("x", ["nft", batch().seed("IPV4").replace("198.51.100.0/24", "198.51.101.0/24")], 1)
        self.assertFalse(batch().preserved("IPV4", fake.listing()))

    def test_conflicting_spec_returns_an_attachment_on_the_seeded_interface(self):
        self.assertEqual(linux.acl_request(batch().conflicting("IPV6")),
                         {"direction": "IN", "jump": (batch().SEED_PORT, "IPV6", "acl6_CAP_ACL")})

    def test_conflicting_refuses_an_unknown_family(self):
        with self.assertRaises(KeyError):
            batch().conflicting("IPV5")

    def applied(self, key, direction, *, attach=True):
        specs, _requirements, sections = batch().plan(key, direction)
        definition, attachment_spec = (linux.acl_request(s) for s in specs)
        fake = FakeNft()
        command = f"create table inet {TABLE}\n" + nft_acl.create_chain_commands(definition["chain"], definition["rules"])
        if attach:
            command += nft_acl.create_hook_commands(direction) + nft_acl.jump_commands(direction, [attachment_spec["jump"]])
        self.assertEqual(fake.run("x", ["nft", command], 1), 0)
        return sections, fake.listing()

    def test_imported_recovers_the_list_and_its_attachment(self):
        sections, ruleset = self.applied("service_policy.ACL_IPV6_EXTENDED", "OUT")
        self.assertTrue(batch().imported(sections, ruleset, "OUT"))

    def test_imported_is_false_without_the_attachment_or_in_the_wrong_direction(self):
        sections, ruleset = self.applied("service_policy.ACL_IPV4_EXTENDED", "IN", attach=False)
        self.assertFalse(batch().imported(sections, ruleset, "IN"))
        sections, ruleset = self.applied("service_policy.ACL_IPV4_EXTENDED", "IN")
        self.assertFalse(batch().imported(sections, ruleset, "OUT"))


class AclLabTests(SimpleTestCase):
    """The lab wrapper's prerequisites, flows and restoration, with every container command replaced."""

    def lab(self, direction="IN", fam="IPV4"):
        b = batch()
        lab = b.AclLab.__new__(b.AclLab)
        lab.fc, lab.pc, lab.pids, lab.family, lab.direction = "frr", "peer", {"frr": "11", "peer": "22"}, fam, direction
        lab.sender, lab.receiver = ("peer", "frr") if direction == "IN" else ("frr", "peer")
        lab.prepared, lab.installed, lab.baseline, lab.packages, lab.apt_lists = True, False, {"frr": "k", "peer": "k"}, "pkgs", "x"
        lab.ruleset = linux.nft_digest("same")
        return lab

    @staticmethod
    def inspect(label):
        b = batch()
        return SimpleNamespace(returncode=0, stdout=json.dumps([{"Config": {"Labels": {"containerlab": label}},
                                                                  "NetworkSettings": {"Networks": {b.NETWORK: {}}},
                                                                  "State": {"Pid": 42}}]))

    def construct(self, label, must=None):
        b = batch()
        return mock.patch.multiple(
            b, _target=mock.Mock(return_value=({"container": "frr"}, None, None)),
            _run=mock.Mock(return_value=self.inspect(label)), _call=mock.Mock(return_value=SimpleNamespace(returncode=0, stdout="k"))), \
            mock.patch.object(b.FrrPair, "kernel", return_value="k"), \
            mock.patch.object(b.FrrPair, "must", must or mock.Mock(return_value="ruleset"))

    def test_lab_init_creates_link_and_probe_addresses_on_the_sending_side(self):
        b = batch()
        must = mock.Mock(return_value="ruleset")
        patches = self.construct(b.LAB, must)
        with patches[0], patches[1], patches[2]:
            lab = b.AclLab("IPV4", "OUT")
        self.assertEqual((lab.sender, lab.receiver, lab.installed, lab.pids), ("frr", f"clab-{b.LAB}-peer", False,
                                                                              {"frr": "42", f"clab-{b.LAB}-peer": "42"}))
        self.assertIn(mock.call("frr", "ip", "addr", "add", f"{b.DENIED['IPV4']}/32", "dev", b.PORT), must.call_args_list)
        self.assertEqual(lab.ruleset, linux.nft_digest("ruleset"))

    def test_lab_init_refuses_a_container_outside_the_isolated_lab(self):
        b = batch()
        patches = self.construct("production")
        with patches[0], patches[1], patches[2]:
            with self.assertRaisesRegex(RuntimeError, "outside the isolated lab"):
                b.AclLab("IPV4", "IN")

    def test_lab_init_failure_restores_the_lab_and_raises(self):
        b = batch()
        patches = self.construct(b.LAB, mock.Mock(side_effect=RuntimeError("address refused")))
        with patches[0], patches[1], patches[2], mock.patch.object(b.AclLab, "close") as close:
            with self.assertRaisesRegex(RuntimeError, "address refused"):
                b.AclLab("IPV6", "IN")
        close.assert_called_once()

    def test_ping_passes_on_zero_loss_from_the_sender_namespace(self):
        b = batch()
        with mock.patch.object(b, "_run", return_value=SimpleNamespace(returncode=0, stdout="2 received, 0% packet loss")) as run:
            self.assertTrue(self.lab().ping("198.18.0.2", "198.18.0.1"))
        self.assertEqual(run.call_args.args[0][:6], ["sudo", "-n", "nsenter", "-t", "22", "-n"])

    def test_ping_fails_on_packet_loss(self):
        b = batch()
        with mock.patch.object(b, "_run", return_value=SimpleNamespace(returncode=1, stdout="0 received, 100% packet loss")):
            self.assertFalse(self.lab().ping("198.18.0.66", "198.18.0.1"))

    def tcp(self, answer, flows):
        b = batch()
        server = mock.Mock()
        server.poll.return_value = None
        with mock.patch.object(b.subprocess, "Popen", return_value=server) as popen, \
                mock.patch.object(b, "_run", return_value=SimpleNamespace(stdout=answer)), mock.patch.object(b.time, "sleep"):
            result = self.lab().tcp(flows)
        self.assertIn("11", popen.call_args.args[0])
        server.terminate.assert_called_once()
        return result

    def test_tcp_returns_each_connected_flow(self):
        self.assertEqual(self.tcp("OPEN\n", [("198.18.0.2", (30000, 39999)), ("198.18.0.66", (1024, 2048))]), [True, True])

    def test_tcp_reports_none_when_the_connect_is_dropped(self):
        self.assertEqual(self.tcp("NONE\n", [("198.18.0.2", (1024, 2048))]), [False])

    def test_observe_runs_pings_and_tcp_flows_in_and_pings_only_out(self):
        b = batch()
        with mock.patch.object(b.AclLab, "ping", return_value=True), \
                mock.patch.object(b.AclLab, "tcp", return_value=[True, False, True]) as tcp:
            seen = self.lab("IN").observe(True)
            self.assertEqual(seen["tcp permitted, other source port"], False)
            self.assertEqual(len(seen), 5)
            self.assertEqual(self.lab("OUT").observe(True), {"ping permitted": True, "ping denied": True})
        tcp.assert_called_once()

    def test_expected_without_filtering_returns_every_flow_answered(self):
        self.assertEqual(set(self.lab("IN").expected(True, False).values()), {True})

    def test_expected_with_filtering_denies_only_the_listed_flows(self):
        extended, standard = self.lab("IN").expected(True, True), self.lab("IN").expected(False, True)
        self.assertEqual([k for k, v in extended.items() if not v], ["ping denied", "tcp permitted, source port in denied range"])
        self.assertEqual([k for k, v in standard.items() if not v], ["ping denied", "tcp denied source"])
        self.assertEqual(self.lab("OUT").expected(True, True), {"ping permitted": True, "ping denied": False})

    def test_settled_returns_once_the_flows_match(self):
        b = batch()
        lab = self.lab("OUT")
        with mock.patch.object(b.AclLab, "observe", return_value=lab.expected(False, True)):
            ok, seen, _took = lab.settled(False, True)
        self.assertTrue(ok)
        self.assertEqual(seen["ping denied"], False)

    def test_settled_fails_when_the_flows_never_match_within_the_limit(self):
        b = batch()
        clock = itertools.chain([0.0, 0.0], itertools.repeat(100.0))
        with mock.patch.object(b.AclLab, "observe", return_value={}), mock.patch.object(b.time, "sleep"), \
                mock.patch.object(b.time, "monotonic", side_effect=lambda: next(clock)):
            self.assertEqual(self.lab("OUT").settled(False, True, limit=6), (False, {}, 100))

    def test_close_restores_the_baseline(self):
        b = batch()
        with mock.patch.object(b, "_call", return_value=SimpleNamespace(returncode=0, stdout="same")) as call, \
                mock.patch.object(b.FrrPair, "kernel", return_value="k"):
            lab = self.lab()
            lab.packages = "same"
            self.assertTrue(lab.close())
            self.assertTrue(lab.close())             # idempotent once closed
        self.assertIn(mock.call("frr", "ip", "route", "del", f"{b.DENIED['IPV4']}/32", "dev", b.PORT), call.call_args_list)

    def test_close_raises_when_the_kernel_state_was_not_restored(self):
        b = batch()
        with mock.patch.object(b, "_call", return_value=SimpleNamespace(returncode=0, stdout="same")), \
                mock.patch.object(b.FrrPair, "kernel", return_value="changed"):
            lab = self.lab()
            lab.packages = "same"
            with self.assertRaisesRegex(RuntimeError, "did not return to its captured baseline"):
                lab.close()


class AclProbeVerdictTests(SimpleTestCase):
    SEEDED = "existing NMAS ACL table (another list attached elsewhere)"
    PASSING = {"applied": True, "read_ok": True, "post_ok": True, "imported": True, "verified": True, "control": True,
               "compensated": True, "config_restored": True, "after": True, "restored": True, "preserved": True,
               "actions": [], "statuses": [], "detail": "", "failure": "", "negative": ""}

    def scenarios(self, **seeded):
        return {"pristine node": dict(self.PASSING),
                self.SEEDED: {**self.PASSING, "negative": "APPLY/False/COMPENSATION_NOT_PROVABLE", **seeded}}

    def test_scenarios_for_an_attachment_cell_returns_three_scenarios(self):
        b = batch()
        with mock.patch.object(b, "_scenario", return_value={}) as scenario:
            found = b.scenarios_for("service_policy.ACL_ATTACH_IPV4")
        self.assertEqual(list(found), ["pristine node", self.SEEDED, "pristine node, attached OUT"])
        self.assertEqual(scenario.call_args_list[-1], mock.call("service_policy.ACL_ATTACH_IPV4", seeded=False, direction="OUT"))

    def test_scenarios_for_a_definition_cell_never_runs_the_out_attachment(self):
        b = batch()
        with mock.patch.object(b, "_scenario", return_value={}) as scenario:
            self.assertEqual(len(b.scenarios_for("service_policy.ACL_IPV4_STANDARD")), 2)
        self.assertEqual(scenario.call_count, 2)

    def test_probe_records_a_passing_live_verdict_from_mocked_scenarios(self):
        b = batch()
        cell = SimpleNamespace(probes={}, runtime_version="")
        with mock.patch.object(b, "scenarios_for", return_value=self.scenarios()):
            b.probe_frr_acl(cell, "service_policy.ACL_IPV6_STANDARD")
        self.assertEqual({row["outcome"] for row in cell.probes.values()}, {"PASS"})
        self.assertEqual(len(cell.probes), 6)
        self.assertIn("acl6_CAP_ACL", cell.probes["live_write"]["detail"])
        self.assertEqual(cell.runtime_version, b.RUNTIME)

    def test_probe_fails_runtime_validation_when_the_conflict_was_not_refused(self):
        b = batch()
        cell = SimpleNamespace(probes={}, runtime_version="")
        with mock.patch.object(b, "scenarios_for", return_value=self.scenarios(negative="APPLY/True/-")):
            b.probe_frr_acl(cell, "service_policy.ACL_IPV4_STANDARD")
        self.assertEqual(cell.probes["runtime_validation"]["outcome"], "FAIL")
        self.assertEqual(cell.probes["live_write"]["outcome"], "PASS")

    def test_probe_fails_compensation_when_the_seeded_list_was_not_preserved(self):
        b = batch()
        cell = SimpleNamespace(probes={}, runtime_version="")
        with mock.patch.object(b, "scenarios_for", return_value=self.scenarios(preserved=False)):
            b.probe_frr_acl(cell, "service_policy.ACL_IPV4_EXTENDED")
        self.assertEqual(cell.probes["compensation"]["outcome"], "FAIL")


class AclHarnessTests(SimpleTestCase):
    """The isolated harness entry point, driven with its lab, database and Git replaced."""

    @staticmethod
    def load():
        path = Path(__file__).resolve().parents[3] / "labs/phase9-frr-acl-isolated/run.py"
        module_spec = importlib.util.spec_from_file_location("nmas_phase9_frr_acl_run", path)
        module = importlib.util.module_from_spec(module_spec)
        module_spec.loader.exec_module(module)
        return module

    def run_main(self, root, outcome, features):
        module = self.load()
        cell = SimpleNamespace(probes={"renderer": {"outcome": outcome}}, complete=outcome == "PASS",
                               status="SUPPORTED" if outcome == "PASS" else "UNSUPPORTED", as_dict=lambda: {"status": "SUPPORTED"})
        with mock.patch.dict(module.settings.DATABASES["default"], {}, clear=False), \
                mock.patch.object(module, "ROOT", root), mock.patch.object(module.sys, "argv", ["run.py", *features]), \
                mock.patch.object(module.subprocess, "check_output", return_value="revision\n"), \
                mock.patch.object(module, "call_command"), \
                mock.patch.object(module, "verify_cell", return_value=cell), \
                mock.patch.object(module, "probe_frr_acl", return_value={"pristine node": {"restored": True}}) as probe, \
                mock.patch("builtins.print") as printed:
            module.main()
        return module, probe, printed

    def fake_root(self, directory):
        root = Path(directory)
        for name in self.load().SOURCES:
            (root / name).parent.mkdir(parents=True, exist_ok=True)
            (root / name).write_text("safe fixture\n")
        return root

    def test_harness_main_positive_writes_one_record_per_selected_cell(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.fake_root(directory)
            module, probe, _printed = self.run_main(root, "PASS", ["service_policy.ACL_ATTACH_IPV6"])
            evidence = json.loads((root / module.EVIDENCE / "service_policy-ACL_ATTACH_IPV6.json").read_text())
        probe.assert_called_once()
        self.assertEqual(evidence["schema"], "nmas.v2.phase9.frr-acl-live/1")
        self.assertTrue(evidence["ephemeral_database"])
        self.assertEqual(evidence["repository_head"], "revision")
        self.assertEqual(set(evidence["uncommitted_source_sha256"]), set(module.SOURCES))

    def test_harness_main_skips_the_lab_after_an_offline_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.fake_root(directory)
            module, probe, printed = self.run_main(root, "FAIL", [])
            self.assertFalse((root / module.EVIDENCE).exists())
        probe.assert_not_called()
        self.assertEqual(printed.call_count, len(module.CELLS))
