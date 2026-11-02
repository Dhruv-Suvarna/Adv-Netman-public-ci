"""Ubuntu/FRR static NAT44 (V2 Phase 9): renderer, strict nftables execution shape, semantic import and postcheck."""

from __future__ import annotations

import importlib.util
import json
import tempfile
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase

from core.services import platform_drivers as drivers
from core.services.capabilities.features import by_key
from core.services.capabilities.offline_verify import ordered_added
from core.services.capabilities.probe_cases import sample
from core.services.config_import import parser_frr
from core.services.execution.executors import linux
from core.services.execution.executors.base import APPLY, REFUSE, ConfigletSpec
from core.services.health import evaluators, live, requirements as reqs
from core.services.health.codes import CheckStatus as S, Phase
from core.tests.helpers.health import device_evidence, evidence_set

TABLE = "DEVICE_BUILDER_NAT44_STATIC"
BLOCK = ("# Static NAT44 1:1 (nftables; candidate only)", f"table ip {TABLE} {{", "    chain prerouting {",
         "        type nat hook prerouting priority dstnat; policy accept;",
         '        iifname "eth2" ip daddr 203.0.113.44 dnat to 198.18.0.2', "    }", "    chain postrouting {",
         "        type nat hook postrouting priority srcnat; policy accept;",
         '        oifname "eth2" ip saddr 198.18.0.2 snat to 203.0.113.44', "    }", "}")
DOCKER = 'table ip nat {\n\tchain DOCKER_OUTPUT {\n\t\tip daddr 127.0.0.11 udp dport 53 counter packets %d bytes 603 xt target "DNAT"\n\t}\n}\n'


def listed(*mappings) -> str:
    """A static table exactly as ``nft list ruleset`` (1.0.9) prints it."""
    pre = "".join(f'\t\tiifname "{o}" ip daddr {g} dnat to {i}\n' for o, i, g in mappings)
    post = "".join(f'\t\toifname "{o}" ip saddr {i} snat to {g}\n' for o, i, g in mappings)
    return (f"table ip {TABLE} {{\n\tchain prerouting {{\n\t\ttype nat hook prerouting priority dstnat; policy accept;\n{pre}\t}}\n\n"
            f"\tchain postrouting {{\n\t\ttype nat hook postrouting priority srcnat; policy accept;\n{post}\t}}\n}}\n")


def spec(cfg, lines):
    return ConfigletSpec(cfg, 1, "frr", "ubuntu_frr", "nat_rule", "CREATE_DEFINE", tuple(lines), {})


def rule(**overrides):
    return {"id": "nat_1", "sequence": 1, "family": "NAT44", "mode": "STATIC", "original_source": "198.18.0.2",
            "translated_source": "203.0.113.44", "protocol": "IP", "original_port": "", "translated_port": "",
            "outside_interface_id": "if_2", **overrides}


def render(*rules):
    rows = drivers._render_nat("ubuntu_frr", "Ubuntu/FRR", {"pools": {}, "rules": {r["id"]: r for r in rules}},
                               {"if_2": {"name": "eth2"}}, ubuntu=True)
    return [row["text"] for row in rows if row.get("text")]


class StaticNat44RendererTests(SimpleTestCase):
    def test_capability_is_supported_only_on_ubuntu_frr(self):
        self.assertEqual(drivers._service_policy_capability_or_not_implemented("ubuntu_frr", "NAT_NAT44_STATIC").status,
                         drivers.CapabilityStatus.SUPPORTED)
        self.assertNotEqual(drivers._service_policy_capability_or_not_implemented("arista_ceos", "NAT_NAT44_STATIC").status,
                            drivers.CapabilityStatus.SUPPORTED)

    def test_host_mapping_renders_both_directions_in_one_dedicated_table(self):
        self.assertEqual(render(rule()), list(BLOCK))

    def test_canonical_sample_renders_the_exact_block(self):
        case = sample("ubuntu_frr", by_key()["service_policy.NAT_NAT44_STATIC"])
        from core.services.capabilities.offline_verify import _descriptors
        rendered = _descriptors("ubuntu_frr", case.sections)
        start = rendered.index(f"table ip {TABLE} {{")
        self.assertEqual(rendered[start - 1:rendered.index("}", start) + 1], list(BLOCK))

    def test_unproven_variants_are_refused_with_a_marker_not_approximated(self):
        cases = {
            "prefix": rule(original_source="198.18.0.0/30"), "ipv6": rule(translated_source="2001:db8::44"),
            "port": rule(original_port="80"), "protocol": rule(protocol="TCP"), "no translated": rule(translated_source=""),
            "no outside": rule(outside_interface_id="if_9"),
        }
        for label, row in cases.items():
            with self.subTest(case=label):
                lines = render(row)
                self.assertFalse(any(line.startswith("table ip ") for line in lines), lines)
                self.assertTrue(any(line.startswith(drivers.UNSUPPORTED_OBJECT_MARKER) and "NAT44 STATIC rule nat_1" in line
                                    for line in lines), lines)

    def test_an_address_used_twice_refuses_the_later_mapping(self):
        lines = render(rule(), rule(id="nat_2", sequence=2, original_source="198.18.0.6"))
        self.assertEqual(sum("snat to 203.0.113.44" in line for line in lines), 1)
        self.assertTrue(any("nat_2" in line and "already used" in line for line in lines))

    def test_static_and_pat_rules_render_as_separate_tables(self):
        pat = {"id": "nat_p", "sequence": 2, "family": "NAT44", "mode": "PAT", "original_source": "198.18.9.0/24",
               "outside_interface_id": "if_2"}
        lines = render(rule(), pat)
        self.assertIn("table ip DEVICE_BUILDER_PAT {", lines)
        self.assertIn(f"table ip {TABLE} {{", lines)
        self.assertIsNotNone(linux.parse_nat_table(lines[lines.index(f"table ip {TABLE} {{"):]))


class StaticNat44ShapeTests(SimpleTestCase):
    def test_rendered_and_listed_forms_parse_to_the_same_mapping(self):
        rendered = linux.parse_nat_table(BLOCK)
        self.assertEqual(rendered, {"table": TABLE, "kind": "static", "rules": [("eth2", "198.18.0.2", "203.0.113.44")]})
        self.assertEqual(linux.nat_table_rules(DOCKER % 1 + listed(("eth2", "198.18.0.2", "203.0.113.44")), TABLE, "static"),
                         rendered["rules"])
        self.assertEqual(linux.parse_nat_table(linux.static_nat_statement(rendered).splitlines()), rendered)

    def test_a_static_table_is_not_a_masquerade_table_and_vice_versa(self):
        text = listed(("eth2", "198.18.0.2", "203.0.113.44"))
        self.assertIs(linux.nat_table_rules(text, TABLE), False)
        pat = f"table ip {TABLE} {{\n\tchain postrouting {{\n\t\ttype nat hook postrouting priority srcnat; policy accept;\n" \
              '\t\toifname "eth2" ip saddr 198.18.0.0/30 masquerade\n\t}\n}\n'
        self.assertIs(linux.nat_table_rules(pat, TABLE, "static"), False)

    def test_anything_but_the_exact_paired_shape_is_refused(self):
        dnat, snat = BLOCK[4], BLOCK[8]
        bad = {
            "unpaired directions": BLOCK[:4] + (dnat.replace("203.0.113.44", "203.0.113.45"),) + BLOCK[5:],
            "missing dnat": BLOCK[:4] + BLOCK[5:],
            "chains swapped": (BLOCK[1], *BLOCK[6:10], *BLOCK[2:6], "}"),
            "prefix": tuple(line.replace("198.18.0.2", "198.18.0.0/30") for line in BLOCK),
            "injection": tuple(line.replace('"eth2"', '"eth2; flush ruleset"') for line in BLOCK),
            "extra statement": BLOCK[:5] + ("        counter drop",) + BLOCK[5:],
            "inet family": (BLOCK[0], f"table inet {TABLE} {{", *BLOCK[2:]),
            "address reused": BLOCK[:5] + (dnat.replace("203.0.113.44", "203.0.113.45"),) + BLOCK[5:9]
                              + (snat.replace("203.0.113.44", "203.0.113.45"),) + BLOCK[9:],
            "out-of-range octet": tuple(line.replace("198.18.0.2", "198.18.0.299") for line in BLOCK),
        }
        for label, lines in bad.items():
            with self.subTest(case=label):
                self.assertIsNone(linux.parse_nat_table(lines), lines)

    def test_conflict_is_any_reuse_of_an_owned_address(self):
        owned = [("eth2", "198.18.9.2", "203.0.113.99")]
        self.assertFalse(linux.static_nat_conflict(owned, owned))
        self.assertFalse(linux.static_nat_conflict([("eth2", "198.18.0.2", "203.0.113.44")], owned))
        self.assertTrue(linux.static_nat_conflict([("eth2", "198.18.9.2", "203.0.113.44")], owned))
        self.assertTrue(linux.static_nat_conflict([("eth2", "198.18.0.2", "203.0.113.99")], owned))

    def test_rule_commands_write_both_directions_of_each_mapping(self):
        self.assertEqual(linux.static_nat_rule_commands("T", [("eth2", "198.18.0.2", "203.0.113.44")]),
                         'add rule ip T prerouting iifname "eth2" ip daddr 203.0.113.44 dnat to 198.18.0.2\n'
                         'add rule ip T postrouting oifname "eth2" ip saddr 198.18.0.2 snat to 203.0.113.44\n')


class StaticNat44ExecutorTests(SimpleTestCase):
    """A fake nft that understands exactly the four command forms the executor sends."""

    def device(self, ruleset):
        box = {"ruleset": ruleset, "sent": []}

        def run(_container, argv, _timeout):
            box["sent"].append(argv)
            current = linux.nat_table_rules(box["ruleset"], TABLE, "static") or []
            other = box["ruleset"].split(f"table ip {TABLE}")[0]
            if argv[1:3] == ["delete", "table"]:
                box["ruleset"] = other
                return 0
            if argv[1].startswith(f"table ip {TABLE}"):
                mappings = linux.parse_nat_table(argv[1].splitlines())["rules"]
            else:
                commands = argv[1].splitlines()
                mappings = [] if commands[0].startswith("flush chain") else list(current)
                for line in commands:
                    if " postrouting " in line and line.startswith("add rule"):
                        tokens = line.split()
                        mappings.append((tokens[6].strip('"'), tokens[9], tokens[12]))
            box["ruleset"] = other + listed(*mappings)
            return 0

        executor = linux.LinuxExecutor({"name": "frr", "container": "x"}, runner=run,
                                       reader=lambda _d: SimpleNamespace(live_reachable=True),
                                       nft_reader=lambda _c, _t: box["ruleset"])
        return executor, box

    def test_new_table_is_created_atomically_and_deleted_with_unrelated_rules_intact(self):
        executor, box = self.device(DOCKER % 8)
        nat = spec("nat", BLOCK)
        preflight = executor.assess(nat)
        self.assertEqual((preflight.action, preflight.restorable, preflight.previous_state["nat_kind"]), (APPLY, True, "static"))
        self.assertTrue(executor.apply(nat, preflight).ok)
        (argv,) = box["sent"]
        self.assertEqual(len(argv), 2, "the whole table is one nft transaction")
        self.assertIn("dnat to 198.18.0.2", argv[1])
        self.assertIn("snat to 203.0.113.44", argv[1])
        self.assertEqual(executor.assess(nat).action, "SKIP_SATISFIED")
        box["ruleset"] = box["ruleset"].replace("packets 8", "packets 31")
        self.assertEqual(executor.compensate(nat, preflight).status, "COMPENSATED")
        self.assertEqual(box["sent"][-1], ["nft", "delete", "table", "ip", TABLE])
        self.assertEqual(box["ruleset"], DOCKER % 31)

    def test_append_to_an_existing_nmas_table_then_restore_it_exactly(self):
        seeded = DOCKER % 1 + listed(("eth2", "198.18.9.2", "203.0.113.99"))
        executor, box = self.device(seeded)
        nat = spec("nat", BLOCK)
        preflight = executor.assess(nat)
        self.assertEqual((preflight.action, preflight.restorable, preflight.previous_state["existing_rules"]), (APPLY, True, 1))
        self.assertTrue(executor.apply(nat, preflight).ok)
        self.assertEqual(box["sent"], [["nft", linux.static_nat_rule_commands(TABLE, [("eth2", "198.18.0.2", "203.0.113.44")])]])
        self.assertEqual(len(linux.nat_table_rules(box["ruleset"], TABLE, "static")), 2)
        self.assertEqual(executor.compensate(nat, preflight).status, "COMPENSATED")
        self.assertTrue(box["sent"][-1][1].startswith(f"flush chain ip {TABLE} prerouting\nflush chain ip {TABLE} postrouting\n"))
        self.assertEqual(box["ruleset"], seeded)

    def test_conflicting_or_foreign_content_has_no_provable_inverse_and_is_never_written(self):
        conflicting = DOCKER % 1 + listed(("eth2", "198.18.0.2", "203.0.113.99"))
        foreign = DOCKER % 1 + f"table ip {TABLE} {{\n\tchain prerouting {{\n\t\tip daddr 203.0.113.44 drop\n\t}}\n}}\n"
        for label, ruleset in (("conflict", conflicting), ("foreign", foreign)):
            with self.subTest(case=label):
                executor, box = self.device(ruleset)
                found = executor.assess(spec("nat", BLOCK))
                self.assertEqual((found.action, found.restorable, found.reason), (APPLY, False, "COMPENSATION_NOT_PROVABLE"))
                self.assertFalse(executor.apply(spec("nat", BLOCK), found).ok)
                self.assertEqual(box["sent"], [])

    def test_apply_refuses_content_that_appeared_after_preflight(self):
        executor, box = self.device(DOCKER % 1)
        preflight = executor.assess(spec("nat", BLOCK))
        box["ruleset"] += listed(("eth2", "198.18.0.2", "203.0.113.99"))
        outcome = executor.apply(spec("nat", BLOCK), preflight)
        self.assertEqual((outcome.ok, outcome.error_code), (False, "COMMAND_REJECTED"))
        self.assertEqual(box["sent"], [])

    def test_malformed_static_configlet_is_refused(self):
        executor, _box = self.device(DOCKER % 1)
        self.assertEqual(executor.assess(spec("nat", BLOCK[:4] + BLOCK[5:])).action, REFUSE)


class StaticNat44ImportAndPostcheckTests(SimpleTestCase):
    def test_parser_imports_the_mapping_with_its_translated_address(self):
        text = DOCKER % 1 + listed(("eth2", "198.18.0.2", "203.0.113.44"))
        (parsed,) = parser_frr.parse("", nft_text=text).nat_rules
        self.assertEqual((parsed.mode, parsed.original_source, parsed.translated_source, parsed.outside_interface),
                         ("STATIC", "198.18.0.2", "203.0.113.44", "eth2"))

    def test_parser_ignores_a_table_that_is_not_the_exact_shape(self):
        text = listed(("eth2", "198.18.0.2", "203.0.113.44")).replace("dnat to 198.18.0.2", "dnat to 198.18.0.3")
        self.assertEqual(parser_frr.parse("", nft_text=text).nat_rules, [])

    def test_parse_nft_adds_static_facts_only_when_a_static_table_is_listed(self):
        self.assertNotIn("static", live.parse_nft(DOCKER % 1))
        facts = live.parse_nft(DOCKER % 1 + listed(("eth2", "198.18.0.2", "203.0.113.44")))
        self.assertEqual(facts["static"], [{"table": TABLE, "oif": "eth2", "inside": "198.18.0.2", "global": "203.0.113.44"}])

    def evaluate(self, expected, nat):
        requirement = reqs.Requirement(cfg_id="CFG-1", device="R1", kind="NAT_RULE_INTENDED", label="R1 nat", object_type="t",
                                       object_id="o", expected=expected, check_types=reqs.expand("NAT_RULE_INTENDED", expected))
        evidence = evidence_set(device_evidence("R1", nat=nat))
        return evaluators.evaluate_requirements([requirement], Phase.POSTCHECK, evidence).results[0]

    def test_static_postcheck_requires_the_exact_pair(self):
        nat = live.parse_nft(listed(("eth2", "198.18.0.2", "203.0.113.44")))
        base = {"outside_interface": "eth2", "mode": "STATIC", "original_source": "198.18.0.2/32", "translated_source": "203.0.113.44"}
        passed = self.evaluate(base, nat)
        self.assertEqual((passed.status, passed.check_code), (S.PASS, "NAT_RULE_EXPECTED_PRESENT"))
        for label, change in (("other global", {"translated_source": "203.0.113.45"}), ("other inside", {"original_source": "198.18.0.6"}),
                              ("other interface", {"outside_interface": "eth9"})):
            with self.subTest(case=label):
                failed = self.evaluate({**base, **change}, nat)
                self.assertEqual((failed.status, failed.check_code), (S.FAIL, "NAT_RULE_MISSING"))
        masquerade_only = {"tables": [TABLE], "rules": [{"table": TABLE, "oif": "eth2", "action": "snat"}]}
        self.assertEqual(self.evaluate(base, masquerade_only).status, S.FAIL)

    def test_configlet_facts_carry_the_translated_address_for_static_only(self):
        from core.services.planning import configlet_factory
        ctx = SimpleNamespace(phase12={"nat": {"rules": {"nat_1": rule()}}}, ifaces=lambda ids: {},
                              added=lambda _before, _after: list(BLOCK), iface=lambda _id: {"name": "eth2"},
                              name="R1", platform="ubuntu_frr", intent={})
        node = {"id": "n1", "object_id": "nat_1", "type": "nat_rule"}
        (static,) = configlet_factory._nat_rule(ctx, node)
        self.assertEqual(static.facts["translated_source"], "203.0.113.44")
        ctx.phase12["nat"]["rules"]["nat_1"] = rule(mode="PAT", original_source="198.18.0.0/30")
        (pat,) = configlet_factory._nat_rule(ctx, node)
        self.assertNotIn("translated_source", pat.facts)

    def test_working_intent_keeps_the_translated_address(self):
        from core.services.config_templates.working_intent import intent_from_sections
        sections = {"interfaces": {"if_2": {"id": "if_2", "name": "eth2"}}, "nat": {"rules": {"nat_1": rule()}}}
        (row,) = intent_from_sections(sections, hostname="R1")["nat_rules"]
        self.assertEqual((row["mode"], row["translated_source"], row["outside_interface"]), ("STATIC", "203.0.113.44", "eth2"))


class OrderedAddedTests(SimpleTestCase):
    def test_repeated_lines_keep_their_rendered_order(self):
        self.assertEqual(ordered_added(list(BLOCK), []), list(BLOCK))
        self.assertEqual(ordered_added(["a", "}", "b", "}"], ["}"]), ["a", "b", "}"])

    def test_lines_present_in_the_baseline_are_removed(self):
        self.assertEqual(ordered_added(["x", "y"], ["x", "y"]), [])


class StaticNat44ProbeVerdictTests(SimpleTestCase):
    """Direct offline cases for the live runner; the live proof itself is the isolated evidence record."""

    PASSING = {"applied": True, "read_ok": True, "post_ok": True, "verified": True, "compensated": True,
               "config_restored": True, "restored": True, "actions": [], "statuses": [], "detail": "", "failure": "",
               "control": (), "after": (), "negative": "APPLY/False/COMPENSATION_NOT_PROVABLE"}

    def batch(self):
        from core.services.capabilities import batch_frr_nat
        return batch_frr_nat

    def test_probe_records_a_passing_live_verdict_from_mocked_scenarios(self):
        cell = SimpleNamespace(probes={}, runtime_version="")
        with mock.patch.object(self.batch(), "_static_scenario", return_value=dict(self.PASSING)) as scenario:
            scenarios = self.batch().probe_nat_static(cell)
        self.assertEqual(scenario.call_count, 2)
        self.assertEqual(set(scenarios), {"new table", "existing NMAS table (mapping appended)"})
        self.assertEqual({row["outcome"] for row in cell.probes.values()}, {"PASS"})
        self.assertEqual(len(cell.probes), 5)

    def test_probe_fails_runtime_validation_when_the_conflict_negative_was_not_refused(self):
        cell = SimpleNamespace(probes={}, runtime_version="")
        with mock.patch.object(self.batch(), "_static_scenario", return_value={**self.PASSING, "negative": "APPLY/True/-"}):
            self.batch().probe_nat_static(cell)
        self.assertEqual(cell.probes["runtime_validation"]["outcome"], "FAIL")
        self.assertEqual(cell.probes["live_write"]["outcome"], "PASS")

    def test_probe_fails_compensation_when_the_lab_was_not_restored(self):
        cell = SimpleNamespace(probes={}, runtime_version="")
        with mock.patch.object(self.batch(), "_static_scenario", return_value={**self.PASSING, "restored": False}):
            self.batch().probe_nat_static(cell)
        self.assertEqual(cell.probes["compensation"]["outcome"], "FAIL")

    def test_seed_is_an_exact_nmas_static_table_of_the_other_source(self):
        seed = linux.parse_nat_table(self.batch()._seed_static().splitlines())
        self.assertEqual(seed["rules"], [(self.batch().OUT, *self.batch().SEED_STATIC)])


class StaticNat44HarnessTests(SimpleTestCase):
    """The isolated harness entry point, driven with its lab, database and Git replaced."""

    @staticmethod
    def load():
        path = Path(__file__).resolve().parents[3] / "labs/phase9-frr-nat44-static-isolated/run.py"
        module_spec = importlib.util.spec_from_file_location("nmas_phase9_frr_nat44_static_run", path)
        module = importlib.util.module_from_spec(module_spec)
        module_spec.loader.exec_module(module)
        return module

    def run_main(self, root, outcome):
        module = self.load()
        cell = SimpleNamespace(probes={"renderer": {"outcome": outcome}}, complete=outcome == "PASS",
                               status="SUPPORTED" if outcome == "PASS" else "UNSUPPORTED", as_dict=lambda: {"status": "SUPPORTED"})
        with mock.patch.dict(module.settings.DATABASES["default"], {}, clear=False), \
                mock.patch.object(module, "ROOT", root), \
                mock.patch.object(module.subprocess, "check_output", return_value="revision\n"), \
                mock.patch.object(module, "call_command"), \
                mock.patch.object(module, "verify_cell", return_value=cell), \
                mock.patch.object(module, "probe_nat_static", return_value={"new table": {"restored": True}}) as probe, \
                mock.patch("builtins.print"):
            module.main()
        return module, probe

    def fake_root(self, directory):
        root = Path(directory)
        for name in self.load().SOURCES:
            (root / name).parent.mkdir(parents=True, exist_ok=True)
            (root / name).write_text("safe fixture\n")
        return root

    def test_harness_main_positive_writes_ephemeral_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.fake_root(directory)
            module, probe = self.run_main(root, "PASS")
            evidence = json.loads((root / module.EVIDENCE).read_text())
        probe.assert_called_once()
        self.assertTrue(evidence["ephemeral_database"])
        self.assertEqual(evidence["repository_head"], "revision")
        self.assertEqual(set(evidence["uncommitted_source_sha256"]), set(module.SOURCES))

    def test_harness_main_refuses_an_offline_failure_before_the_lab(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.fake_root(directory)
            with self.assertRaisesRegex(RuntimeError, "offline failure"):
                self.run_main(root, "FAIL")
            self.assertFalse((root / self.load().EVIDENCE).exists())


class StaticNat44SampleTests(SimpleTestCase):
    def test_canonical_sample_maps_a_host_the_probe_can_reach(self):
        case = sample("ubuntu_frr", by_key()["service_policy.NAT_NAT44_STATIC"])
        (row,) = deepcopy(case.sections)["nat"]["rules"].values()
        self.assertEqual((row["mode"], row["original_source"], row["translated_source"]), ("STATIC", "198.18.0.2", "203.0.113.44"))


class StaticNat44DirectCaseTests(SimpleTestCase):
    """Single-polarity direct cases for each new boundary (test governance links a symbol only to a direct caller)."""

    MAPPING = [("eth2", "198.18.0.2", "203.0.113.44")]

    def test_parse_static_nat_table_reads_the_paired_mapping(self):
        self.assertEqual(linux.parse_static_nat_table(BLOCK)["rules"], self.MAPPING)

    def test_parse_static_nat_table_refuses_unpaired_rules(self):
        self.assertIsNone(linux.parse_static_nat_table(BLOCK[:4] + (BLOCK[4].replace(".44", ".45"),) + BLOCK[5:]))

    def test_static_nat_statement_creates_both_chains(self):
        text = linux.static_nat_statement({"table": TABLE, "rules": self.MAPPING})
        self.assertIn("chain prerouting", text)
        self.assertIn("chain postrouting", text)

    def test_static_nat_statement_refuses_a_malformed_mapping(self):
        with self.assertRaises((KeyError, ValueError)):
            linux.static_nat_statement({"table": TABLE, "rules": [("eth2", "198.18.0.2")]})

    def test_static_nat_rule_commands_adds_both_directions(self):
        self.assertEqual(linux.static_nat_rule_commands(TABLE, self.MAPPING).count("add rule"), 2)

    def test_static_nat_rule_commands_refuses_a_malformed_mapping(self):
        with self.assertRaises(ValueError):
            linux.static_nat_rule_commands(TABLE, [("eth2",)])

    def test_static_nat_conflict_accepts_disjoint_or_identical_mappings(self):
        owned = [("eth2", "198.18.9.2", "203.0.113.99")]
        self.assertFalse(linux.static_nat_conflict(self.MAPPING, owned))
        self.assertFalse(linux.static_nat_conflict(owned, owned))

    def test_static_nat_conflict_detects_a_reused_global_address(self):
        self.assertTrue(linux.static_nat_conflict([("eth2", "198.18.0.6", "203.0.113.44")], self.MAPPING))


class StaticNatLabTests(SimpleTestCase):
    """The lab wrapper's own prerequisite (the global-range blackhole) and its inbound flow, with no container touched."""

    def batch(self):
        from core.services.capabilities import batch_frr_nat
        return batch_frr_nat

    def lab(self):
        batch = self.batch()
        lab = batch.StaticNatLab.__new__(batch.StaticNatLab)
        lab.fc, lab.pc, lab.pids, lab.prepared = "frr", "peer", {"frr": "11", "peer": "22"}, True
        return lab

    def test_static_lab_init_adds_the_blackhole_after_the_base_lab(self):
        batch = self.batch()
        with mock.patch.object(batch.NatLab, "__init__", lambda lab: setattr(lab, "fc", "frr")), \
                mock.patch.object(batch.FrrPair, "must") as must:
            batch.StaticNatLab()
        must.assert_called_once_with("frr", "ip", "route", "add", "blackhole", batch.GLOBAL_NET)

    def test_static_lab_init_failure_closes_the_base_lab_and_raises(self):
        batch = self.batch()
        with mock.patch.object(batch.NatLab, "__init__", lambda lab: setattr(lab, "fc", "frr")), \
                mock.patch.object(batch.FrrPair, "must", side_effect=RuntimeError("route refused")), \
                mock.patch.object(batch.NatLab, "close") as close:
            with self.assertRaisesRegex(RuntimeError, "route refused"):
                batch.StaticNatLab()
        close.assert_called_once()

    def test_static_lab_inbound_returns_what_both_ends_saw(self):
        batch = self.batch()
        server = mock.Mock()
        server.communicate.return_value = ("198.18.1.2\n", "")
        with mock.patch.object(batch.subprocess, "Popen", return_value=server) as popen, \
                mock.patch.object(batch, "_run", return_value=SimpleNamespace(stdout="REPLY 203.0.113.44\n")) as run:
            self.assertEqual(self.lab().inbound("203.0.113.44"), ("198.18.1.2", "REPLY 203.0.113.44"))
        self.assertIn("-t", popen.call_args.args[0])
        self.assertIn("203.0.113.44", run.call_args.args[0])

    def test_static_lab_inbound_reports_none_when_nothing_answers(self):
        batch = self.batch()
        server = mock.Mock()
        server.communicate.return_value = ("NONE\n", "")
        with mock.patch.object(batch.subprocess, "Popen", return_value=server), \
                mock.patch.object(batch, "_run", return_value=SimpleNamespace(stdout="NONE\n")):
            self.assertEqual(self.lab().inbound(batch.UNUSED_GLOBAL), ("NONE", "NONE"))

    def test_static_lab_close_removes_the_blackhole_then_restores_the_base_lab(self):
        batch = self.batch()
        lab = self.lab()
        with mock.patch.object(batch, "_call") as call, mock.patch.object(batch.NatLab, "close", return_value=True) as close:
            self.assertTrue(lab.close())
        call.assert_called_once_with("frr", "ip", "route", "del", "blackhole", batch.GLOBAL_NET)
        close.assert_called_once()
