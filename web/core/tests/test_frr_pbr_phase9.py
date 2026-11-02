"""Ubuntu/FRR policy-based routing as pbrd (V2 Phase 9): grammar, renderer, executor, import, postcheck, live runner."""

from __future__ import annotations

import importlib.util
import itertools
import json
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase

from core.services import frr_pbr
from core.services import platform_drivers as drivers
from core.services.capabilities.features import by_key
from core.services.capabilities.probe_cases import sample
from core.services.config_import import parser_frr, service as import_service
from core.services.config_import.schema import ParsedConfig, ParsedInterface, ParsedPbr
from core.services.execution.executors import frr_routing, linux
from core.services.execution.executors.base import APPLY, ConfigletSpec
from core.services.health import evaluators, live, requirements as reqs
from core.services.health.codes import CheckStatus as S, Phase
from core.tests.helpers.health import device_evidence, evidence_set
from core.tests.test_frr_routing_executor import FakeFrr

POLICY = ("pbr-map CAP_PBR seq 10", "   match src-ip 198.51.100.0/24", "   match dst-ip 192.0.2.0/24", "   set nexthop 198.18.7.2")
ATTACH = ("interface eth3", "   pbr-policy CAP_PBR")
# FRR 8.4.4 ``show running-config`` (one-space leaves) and ``show pbr ... json`` as captured from the isolated container
RUNNING = ("frr version 8.4.4\n!\ninterface eth3\n pbr-policy CAP_PBR\nexit\n!\ninterface eth2\n pbr-policy LEGACY\nexit\n!\n"
           "pbr-map CAP_PBR seq 10\n match src-ip 198.51.100.0/24\n match dst-ip 192.0.2.0/24\n set nexthop 198.18.7.2\nexit\n!\n"
           "pbr-map CAP_PBR seq 20\n match dst-ip 192.0.2.0/24\n set nexthop 198.18.7.2\nexit\n!\n"
           "pbr-map LEGACY seq 10\n match src-ip 203.0.113.0/24\n set nexthop 198.18.7.2\n set table 10\nexit\n!\nend\n")
MAP_JSON = json.dumps([{"name": "CAP_PBR", "valid": True, "policies": [
    {"sequenceNumber": 10, "installed": True, "matchSrc": "198.51.100.0/24", "matchDst": "192.0.2.0/24",
     "nexthopGroup": {"tableId": 10000, "name": "CAP_PBR10"}},
    {"sequenceNumber": 20, "installed": False, "matchDst": "2001:DB8:192::/64", "nexthopGroup": {"tableId": 10001}}]}])
NEXTHOP_JSON = json.dumps([{"id": 10000, "nexthops": [{"nexthop": "198.18.7.2", "valid": True}]},
                           {"id": 10001, "nexthops": [{"nexthop": "2001:DB8:77::2", "valid": False}]}])
INTERFACE_JSON = json.dumps([{"name": "eth3", "policy": "CAP_PBR", "valid": True}, {"name": "eth2", "policy": "LEGACY", "valid": False}])
ADDR = json.dumps([{"ifname": name, "flags": ["UP"], "mtu": 1500, "addr_info": []} for name in ("eth2", "eth3")])


def row(sequence=10, **fields):
    return {"id": f"seq_{sequence}", "sequence": sequence, "source_prefix": "198.51.100.0/24", "destination_prefix": "",
            "protocol": "IP", "next_hop": "198.18.7.2", "output_interface_id": "", **fields}


def policy(name="EDGE", family="IPV4", *rows, policy_id="pbr_1"):
    rows = rows or (row(),)
    return {"id": policy_id, "name": name, "family": family, "sequences": {r["id"]: r for r in rows}}


def attachment(policy_id="pbr_1", interface_id="if_1", direction="IN", attach_id="att_1"):
    return {"id": attach_id, "policy_id": policy_id, "interface_id": interface_id, "direction": direction}


def render(policies, attachments=(), interfaces=None):
    pbr = {"pbr": {"policies": {p["id"]: p for p in policies}, "attachments": {a["id"]: a for a in attachments}}}
    rows = drivers._render_ubuntu_policy("ubuntu_frr", "Ubuntu/FRR", pbr,
                                         interfaces or {"if_1": {"name": "eth3"}, "if_2": {"name": "eth2"}})
    return [r.get("text") or r["template"].format(value=r.get("value")) for r in rows]


def spec(object_type, lines, cfg="c1"):
    return ConfigletSpec(cfg, 1, "frr", "ubuntu_frr", object_type, "CREATE_DEFINE", tuple(lines), {})


def batch():
    from core.services.capabilities import batch_frr_pbr
    return batch_frr_pbr


# --- grammar ---------------------------------------------------------------------------------------------------------
class FrrPbrGrammarTests(SimpleTestCase):
    def test_sequence_lines_renders_matches_then_the_next_hop(self):
        self.assertEqual(frr_pbr.sequence_lines("IPV4", row(destination_prefix="192.0.2.9/24")),
                         ["   match src-ip 198.51.100.0/24", "   match dst-ip 192.0.2.0/24", "   set nexthop 198.18.7.2"])
        self.assertEqual(frr_pbr.sequence_lines("IPV6", row(source_prefix="", destination_prefix="2001:DB8:192::/64",
                                                            next_hop="2001:DB8:77::2", protocol="")),
                         ["   match dst-ip 2001:db8:192::/64", "   set nexthop 2001:db8:77::2"])

    def test_sequence_lines_refuses_shapes_without_an_exact_pbrd_form(self):
        for fields, reason in (({"sequence": 0}, "1-700"), ({"sequence": 701}, "1-700"), ({"sequence": "x"}, "1-700"),
                               ({"protocol": "TCP"}, "ip-protocol"), ({"output_interface_id": "if_1"}, "next-hop interface"),
                               ({"source_prefix": ""}, "source or destination"), ({"source_prefix": "bad"}, "not an IPV4 prefix"),
                               ({"source_prefix": "2001:db8::/64"}, "not an IPV4 prefix"), ({"next_hop": "2001:db8::1"}, "not an IPV4"),
                               ({"next_hop": ""}, "not an IPV4")):
            with self.subTest(fields=fields), self.assertRaisesRegex(frr_pbr.PbrRenderError, reason):
                frr_pbr.sequence_lines("IPV4", row(**fields))

    def test_sequences_returns_rows_in_sequence_order(self):
        rows = frr_pbr.sequences(policy("EDGE", "IPV4", row(20, next_hop="198.18.7.3"), row(10)))
        self.assertEqual([n for n, _leaves in rows], [10, 20])
        self.assertEqual(rows[1][1][-1], "   set nexthop 198.18.7.3")
        self.assertEqual(frr_pbr.sequences({"name": "EMPTY", "family": "IPV6", "sequences": {}}), [])

    def test_sequences_refuses_a_duplicate_number_bad_name_or_unknown_family(self):
        for bad, reason in ((policy("EDGE", "IPV4", row(10), {**row(10), "id": "twin"}), "share a number"),
                            (policy("has space"), "pbr-map name"), (policy("EDGE", "IPX"), "unknown PBR family")):
            with self.subTest(reason=reason), self.assertRaisesRegex(frr_pbr.PbrRenderError, reason):
                frr_pbr.sequences(bad)

    def test_refusal_is_empty_for_a_renderable_policy(self):
        self.assertEqual(frr_pbr.refusal(policy()), "")

    def test_refusal_names_why_a_policy_cannot_render(self):
        self.assertEqual(frr_pbr.refusal(policy("EDGE", "IPV4", row(protocol="UDP"))), "an ip-protocol match is not proven on this runtime")

    def test_attachment_lines_returns_the_interface_block(self):
        self.assertEqual(frr_pbr.attachment_lines("eth3", "CAP_PBR"), list(ATTACH))

    def test_attachment_lines_refuses_an_invalid_interface_or_policy_name(self):
        for interface, name in (("", "CAP_PBR"), ("eth3 x", "CAP_PBR"), ("a" * 16, "CAP_PBR"), ("eth3", "")):
            with self.subTest(interface=interface, name=name), self.assertRaises(frr_pbr.PbrRenderError):
                frr_pbr.attachment_lines(interface, name)

    def test_parse_block_returns_the_entry_of_a_rendered_block(self):
        name, entry = frr_pbr.parse_block(["pbr-map CAP_PBR seq 10", " match src-ip 198.51.100.0/24",
                                           " match dst-ip 192.0.2.0/24", " set nexthop 198.18.7.2", "exit"])
        self.assertEqual((name, entry["family"], entry["sequence"], entry["destination_prefix"], entry["next_hop"]),
                         ("CAP_PBR", "IPV4", 10, "192.0.2.0/24", "198.18.7.2"))
        self.assertEqual(frr_pbr.parse_block(["pbr-map V6 seq 5", " match dst-ip 2001:db8:192::/64",
                                              " set nexthop 2001:db8:77::2"])[1]["family"], "IPV6")

    def test_parse_block_refuses_any_shape_nmas_does_not_render(self):
        for block in ([], ["interface eth3"], ["pbr-map X seq 10", " match ip-protocol tcp", " set nexthop 198.18.7.2"],
                      ["pbr-map X seq 10", " match src-ip 198.51.100.0/24", " match src-ip 198.51.101.0/24", " set nexthop 1.1.1.1"],
                      ["pbr-map X seq 10", " set nexthop 198.18.7.2"],                       # no match
                      ["pbr-map X seq 10", " match src-ip 198.51.100.1/24", " set nexthop 198.18.7.2"],  # host bits
                      ["pbr-map X seq 10", " match src-ip 2001:db8::/64", " set nexthop 198.18.7.2"],    # mixed family
                      ["pbr-map X seq 10", " set nexthop 198.18.7.2", " match src-ip 198.51.100.0/24"]):  # other order
            with self.subTest(block=block):
                self.assertIsNone(frr_pbr.parse_block(block))


# --- renderer --------------------------------------------------------------------------------------------------------
class UbuntuPbrRendererTests(SimpleTestCase):
    CODES = ("PBR_IPV4", "PBR_IPV6", "PBR_ATTACH_IPV4", "PBR_ATTACH_IPV6")

    def test_every_pbr_cell_is_supported_on_ubuntu_frr(self):
        for code in self.CODES:
            with self.subTest(code=code):
                self.assertEqual(drivers._service_policy_capability_or_not_implemented("ubuntu_frr", code).status,
                                 drivers.CapabilityStatus.SUPPORTED)

    def test_policies_and_attachments_render_as_pbrd_configuration(self):
        v6 = policy("V6", "IPV6", row(5, source_prefix="", destination_prefix="2001:db8:192::/64", next_hop="2001:db8:77::2"),
                    policy_id="pbr_2")
        lines = render([policy("EDGE", "IPV4", row(20), row(10, destination_prefix="192.0.2.0/24")), v6],
                       [attachment(), attachment("pbr_2", "if_2", attach_id="att_2")])
        self.assertEqual(lines, [
            "pbr-map EDGE seq 10", "   match src-ip 198.51.100.0/24", "   match dst-ip 192.0.2.0/24", "   set nexthop 198.18.7.2", "!",
            "pbr-map EDGE seq 20", "   match src-ip 198.51.100.0/24", "   set nexthop 198.18.7.2", "!",
            "pbr-map V6 seq 5", "   match dst-ip 2001:db8:192::/64", "   set nexthop 2001:db8:77::2", "!",
            "interface eth3", "   pbr-policy EDGE", "!", "interface eth2", "   pbr-policy V6", "!",
            "! PBR next-hop reachability and loop-risk validation are Phase 13 concerns."])

    def test_unrenderable_policies_and_attachments_are_refused_with_a_marker(self):
        lines = render([policy(), policy("BAD", "IPV4", row(protocol="TCP"), policy_id="pbr_bad"), policy(policy_id="pbr_twin")],
                       [attachment(), attachment("pbr_bad", attach_id="att_bad"), attachment(interface_id="if_9", attach_id="att_noif"),
                        attachment(direction="OUT", attach_id="att_out"), attachment(interface_id="if_1", attach_id="att_twice")])
        markers = [line for line in lines if line.startswith(drivers.UNSUPPORTED_OBJECT_MARKER)]
        for needle in ("PBR policy BAD (an ip-protocol match is not proven", "PBR policy EDGE (another PBR policy already has that name)",
                       "att_bad (its PBR policy is not rendered)", "att_noif (direction IN and an interface name are required)",
                       "att_out (direction IN", "att_twice (another PBR policy is already attached on eth3)"):
            with self.subTest(marker=needle):
                self.assertTrue(any(needle in line for line in markers), markers)
        self.assertTrue(all("NOT_IMPLEMENTED" in line for line in markers), markers)
        self.assertEqual(lines.count("   pbr-policy EDGE"), 1)
        self.assertNotIn("pbr-map BAD seq 10", lines)

    def test_no_pbr_intent_renders_the_not_configured_comment(self):
        self.assertEqual(render([]), ["! Policy/PBR: not configured in current candidate"])

    def test_ubuntu_pbr_plan_returns_rendered_attached_and_refused(self):
        pbr = {"policies": {"pbr_1": policy(), "pbr_bad": policy("BAD", "IPV4", row(sequence=0), policy_id="pbr_bad")},
               "attachments": {"att_1": attachment()}}
        rendered, attached, refused = drivers._ubuntu_pbr_plan("ubuntu_frr", pbr, {"if_1": {"name": "eth3"}})
        self.assertEqual([(p["name"], [n for n, _l in rows]) for p, rows in rendered], [("EDGE", [10])])
        self.assertEqual(attached, [("eth3", "EDGE")])
        self.assertEqual(refused, {"pbr_bad": "a sequence number must be 1-700"})

    def test_ubuntu_pbr_plan_refuses_an_attachment_of_an_unrendered_policy(self):
        pbr = {"policies": {"pbr_1": policy(name="bad name")}, "attachments": {"att_1": attachment()}}
        _rendered, attached, refused = drivers._ubuntu_pbr_plan("ubuntu_frr", pbr, {"if_1": {"name": "eth3"}})
        self.assertEqual((attached, refused["att_1"]), ([], "its PBR policy is not rendered"))

    def test_other_platforms_keep_their_own_policy_renderer(self):
        with mock.patch.object(drivers, "_render_ubuntu_policy") as ubuntu:
            drivers.get_driver("arista_ceos").render_candidate(field_values={"device.hostname": "R"}, interfaces=[], routing={},
                                                               phase12={"policy": {"pbr": {"policies": {"pbr_1": policy()}}}})
        ubuntu.assert_not_called()

    def test_canonical_samples_render_pbrd_and_plan_executable_configlets(self):
        from core.services.capabilities.offline_verify import _descriptors
        for code in self.CODES:
            key = f"service_policy.{code}"
            with self.subTest(code=code):
                rendered = _descriptors("ubuntu_frr", sample("ubuntu_frr", by_key()[key]).sections)
                self.assertTrue(any(str(line).startswith("pbr-map ") for line in rendered), rendered)
                specs, requirements, _sections = batch().plan(key)
                self.assertEqual([s.object_type for s in specs], ["pbr_policy", "pbr_attachment"])
                self.assertTrue(all(frr_routing.parse(s.lines) for s in specs))
                self.assertEqual({r.kind for r in requirements}, {"PBR_POLICY_DEFINED", "PBR_ATTACHMENT_INTENDED"})


# --- executor --------------------------------------------------------------------------------------------------------
class PbrExecutorTests(SimpleTestCase):
    def test_executor_grammar_accepts_the_rendered_pbr_blocks_and_their_daemon(self):
        blocks = frr_routing.parse([*POLICY, *ATTACH]) or []
        self.assertEqual([b.kind for b in blocks], ["pbr", "interface"])
        self.assertEqual(frr_routing.required_daemons(blocks), {"zebra", "pbrd"})
        self.assertEqual(frr_routing.required_daemons(frr_routing.parse(ATTACH)), {"zebra", "pbrd"})
        self.assertEqual(frr_routing.required_daemons(frr_routing.parse(("interface eth3", "   no pbr-policy X"))), {"zebra", "pbrd"})

    def test_executor_grammar_refuses_unbounded_pbr_commands(self):
        for bad in ("   match ip-protocol tcp", "   set table 10000", "   set vrf blue", "   match mark 7"):
            with self.subTest(bad=bad):
                self.assertIsNone(frr_routing.parse([POLICY[0], bad]))
        self.assertIsNone(frr_routing.parse(["pbr-map X seq 701", "   set nexthop 198.18.7.2"]))
        self.assertIsNone(frr_routing.parse(["pbr-map X seq 0", "   set nexthop 198.18.7.2"]))

    def test_inverse_removes_a_new_sequence_and_a_new_attachment(self):
        self.assertEqual(linux.frr_routing_inverse(POLICY, ""), ["no pbr-map CAP_PBR seq 10"])
        self.assertEqual(linux.frr_routing_inverse(ATTACH, ""), ["interface eth3", "   no pbr-policy CAP_PBR"])

    def test_inverse_refuses_replacing_another_next_hop_or_attached_policy(self):
        changed = "pbr-map CAP_PBR seq 10\n match src-ip 198.51.100.0/24\n set nexthop 198.18.7.9\nexit\n"
        self.assertIsNone(linux.frr_routing_inverse(POLICY, changed))
        self.assertIsNone(linux.frr_routing_inverse(ATTACH, "interface eth3\n pbr-policy LEGACY\nexit\n"))

    def test_engine_order_writes_then_compensates_leaving_the_other_policy(self):
        device = FakeFrr("interface eth2\n pbr-policy LEGACY\nexit\n")
        executor = device.executor()
        specs = [spec("pbr_policy", POLICY, "p"), spec("pbr_attachment", ATTACH, "a")]
        preflights = [executor.assess(s) for s in specs]
        self.assertEqual([(p.action, p.restorable) for p in preflights], [(APPLY, True)] * 2)
        self.assertTrue(all(executor.apply(s, p).ok for s, p in zip(specs, preflights)))
        self.assertIn(" pbr-policy CAP_PBR", device.text)
        self.assertEqual([executor.compensate(s, p).status for s, p in reversed(list(zip(specs, preflights)))], ["COMPENSATED"] * 2)
        self.assertEqual(device.sent[-2:], [["interface eth3", "no pbr-policy CAP_PBR"], ["no pbr-map CAP_PBR seq 10"]])
        self.assertIn(" pbr-policy LEGACY", device.text)
        self.assertNotIn("CAP_PBR", device.text)

    def test_conflicting_attachment_is_never_written(self):
        device = FakeFrr("interface eth3\n pbr-policy LEGACY\nexit\n")
        found = device.executor().assess(spec("pbr_attachment", ATTACH))
        self.assertEqual((found.action, found.restorable, found.reason), (APPLY, False, "COMPENSATION_NOT_PROVABLE"))
        self.assertEqual(device.sent, [])

    def test_missing_pbrd_is_refused_before_any_write(self):
        device = FakeFrr(daemons={"zebra"})
        found = device.executor().assess(spec("pbr_policy", POLICY))
        self.assertEqual(found.action, "REFUSE")
        self.assertEqual(device.sent, [])


# --- import ----------------------------------------------------------------------------------------------------------
class PbrImportTests(SimpleTestCase):
    def test_parser_imports_each_policy_and_its_attachment(self):
        parsed = parser_frr.parse(RUNNING, addr_json=ADDR)
        self.assertEqual([(p.name, p.family, [s["sequence"] for s in p.sequences]) for p in parsed.pbr_policies],
                         [("CAP_PBR", "IPV4", [10, 20])])
        self.assertEqual(parsed.pbr_policies[0].sequences[1], {"sequence": 20, "source_prefix": "", "destination_prefix": "192.0.2.0/24",
                                                               "next_hop": "198.18.7.2"})
        eth3 = next(i for i in parsed.interfaces if i.name == "eth3")
        self.assertEqual(eth3.pbr_attachments, [{"name": "CAP_PBR", "direction": "IN"}])

    def test_parser_preserves_an_unmanaged_map_and_its_attachment(self):
        parsed = parser_frr.parse(RUNNING, addr_json=ADDR)
        self.assertTrue(any(b.label == "Unmanaged FRR configuration (pbr-map)" and b.lines[0] == "pbr-map LEGACY seq 10"
                            for b in parsed.unmanaged_blocks))
        eth2 = next(i for i in parsed.interfaces if i.name == "eth2")
        self.assertEqual((eth2.pbr_attachments, eth2.preserved_lines[-1]), ([], " pbr-policy LEGACY"))

    def test_parser_refuses_a_map_mixing_families(self):
        text = ("pbr-map MIX seq 10\n match src-ip 198.51.100.0/24\n set nexthop 198.18.7.2\nexit\n"
                "pbr-map MIX seq 20\n match dst-ip 2001:db8:192::/64\n set nexthop 2001:db8:77::2\nexit\n")
        parsed = parser_frr.parse(text)
        self.assertEqual(parsed.pbr_policies, [])
        self.assertEqual(sum(b.label == "Unmanaged FRR configuration (pbr-map)" for b in parsed.unmanaged_blocks), 2)

    def test_apply_pbr_policies_creates_policies_and_commits_each_sequence_field(self):
        parsed = ParsedConfig(pbr_policies=[ParsedPbr("CAP_PBR", "IPV4", [{"sequence": 10, "source_prefix": "198.51.100.0/24",
                                                                          "destination_prefix": "", "next_hop": "198.18.7.2"}])])
        managed, counts = {}, {}
        with mock.patch.object(import_service.service_policy_intent_service, "add_pbr_policy", return_value={"id": "pbr_9"}) as add, \
                mock.patch.object(import_service.service_policy_intent_service, "add_pbr_sequence",
                                  return_value={"id": "seq_9", "sequence": 10}), \
                mock.patch.object(import_service, "_commit") as commit:
            ids = import_service._apply_pbr_policies(change=None, intent=None, revision="r", parsed=parsed, managed_ids=managed,
                                                     counts=counts)
        self.assertEqual((ids, managed, counts), ({"CAP_PBR": "pbr_9"}, {"pbr_policies": ["pbr_9"]}, {"pbr_policies": 1}))
        add.assert_called_once_with(revision="r", name="CAP_PBR", family="IPV4")
        self.assertEqual([c.kwargs["path"].rsplit(".", 1)[1] for c in commit.call_args_list], ["source_prefix", "next_hop"])

    def test_apply_pbr_policies_with_no_parsed_policy_changes_nothing(self):
        managed, counts = {}, {}
        with mock.patch.object(import_service.service_policy_intent_service, "add_pbr_policy") as add:
            self.assertEqual(import_service._apply_pbr_policies(change=None, intent=None, revision="r", parsed=ParsedConfig(),
                                                                managed_ids=managed, counts=counts), {})
        add.assert_not_called()
        self.assertEqual((managed, counts), ({}, {}))

    def test_offline_parsed_contains_reads_the_cap_policy_and_attachment(self):
        from core.services.capabilities.offline_verify import _parsed_contains
        parsed = ParsedConfig(pbr_policies=[ParsedPbr("CAP_PBR", "IPV6", [{"sequence": 10}])],
                              interfaces=[ParsedInterface(name="eth3", pbr_attachments=[{"name": "CAP_PBR", "direction": "IN"}])])
        self.assertTrue(_parsed_contains(parsed, by_key()["service_policy.PBR_IPV6"], None))
        self.assertTrue(_parsed_contains(parsed, by_key()["service_policy.PBR_ATTACH_IPV6"], None))

    def test_offline_parsed_contains_is_false_for_another_family_or_without_attachment(self):
        from core.services.capabilities.offline_verify import _parsed_contains
        parsed = ParsedConfig(pbr_policies=[ParsedPbr("CAP_PBR", "IPV6", [{"sequence": 10}])])
        self.assertFalse(_parsed_contains(parsed, by_key()["service_policy.PBR_IPV4"], None))
        self.assertFalse(_parsed_contains(parsed, by_key()["service_policy.PBR_ATTACH_IPV6"], None))


# --- read-back and postcheck -----------------------------------------------------------------------------------------
class PbrPostcheckTests(SimpleTestCase):
    def test_parse_frr_pbr_returns_policies_with_their_next_hops_and_attachments(self):
        state = live.parse_frr_pbr(MAP_JSON, NEXTHOP_JSON, INTERFACE_JSON)
        self.assertEqual(state["policies"]["CAP_PBR"]["sequences"], [
            {"sequence": 10, "installed": True, "source_prefix": "198.51.100.0/24", "destination_prefix": "192.0.2.0/24",
             "next_hops": ["198.18.7.2"]},
            {"sequence": 20, "installed": False, "source_prefix": "", "destination_prefix": "2001:db8:192::/64",
             "next_hops": ["2001:db8:77::2"]}])
        self.assertEqual(state["attachments"], [{"interface": "eth2", "policy": "LEGACY", "valid": False},
                                                {"interface": "eth3", "policy": "CAP_PBR", "valid": True}])
        self.assertEqual(live.parse_frr_pbr("", "", ""), {"policies": {}, "attachments": []})

    def test_parse_frr_pbr_raises_on_an_unexpected_shape(self):
        with self.assertRaises(ValueError):
            live.parse_frr_pbr("{}", "[]", "[]")
        with self.assertRaises(ValueError):
            live.parse_frr_pbr("not json", "[]", "[]")

    def test_linux_health_reads_pbr_as_its_own_group(self):
        self.assertIn("pbr", live.HEALTH_CAPABILITIES["linux"]["groups"])
        outputs = {"pbr_map": MAP_JSON, "pbr_nexthops": NEXTHOP_JSON, "pbr_interface": INTERFACE_JSON}
        self.assertEqual(list(live._LINUX_GROUPS["pbr"](outputs.get)["policies"]), ["CAP_PBR"])
        self.assertEqual(live.LINUX_COMMANDS["pbr_map"], ("vtysh", "-c", "show pbr map json"))

    def test_requirement_kinds_expand_to_the_pbr_checks(self):
        self.assertEqual(reqs.expand("PBR_POLICY_DEFINED", {}), ("PBR_POLICY_PRESENT",))
        self.assertEqual(reqs.expand("PBR_ATTACHMENT_INTENDED", {}), ("PBR_ATTACHMENT_PRESENT",))
        self.assertNotIn("PBR_POLICY_DEFINED", reqs.KNOWN_NOT_IMPLEMENTED)

    def evaluate(self, kind, expected, pbr, phase=Phase.POSTCHECK, **evidence):
        requirement = reqs.Requirement(cfg_id="CFG-1", device="R1", kind=kind, label="R1 pbr", object_type="t", object_id="o",
                                       expected=expected, check_types=reqs.expand(kind, expected))
        found = evidence_set(device_evidence("R1", platform="linux", pbr=pbr, **evidence))
        return evaluators.evaluate_requirements([requirement], phase, found).results[0]

    def test_postcheck_passes_on_installed_sequences_and_a_valid_attachment(self):
        state = live.parse_frr_pbr(MAP_JSON, NEXTHOP_JSON, INTERFACE_JSON)
        wanted = {"name": "CAP_PBR", "family": "IPV4", "sequences": [
            {"sequence": 10, "source_prefix": "198.51.100.0/24", "destination_prefix": "192.0.2.0/24", "next_hop": "198.18.7.2"}]}
        self.assertEqual(self.evaluate("PBR_POLICY_DEFINED", wanted, state).status, S.PASS)
        attached = {"policy_name": "CAP_PBR", "interface": "eth3", "direction": "IN"}
        self.assertEqual(self.evaluate("PBR_ATTACHMENT_INTENDED", attached, state).status, S.PASS)

    def test_postcheck_fails_on_an_uninstalled_sequence_or_invalid_or_missing_attachment(self):
        state = live.parse_frr_pbr(MAP_JSON, NEXTHOP_JSON, INTERFACE_JSON)
        uninstalled = {"name": "CAP_PBR", "sequences": [{"sequence": 20, "destination_prefix": "2001:db8:192::/64",
                                                         "next_hop": "2001:db8:77::2"}]}
        failed = self.evaluate("PBR_POLICY_DEFINED", uninstalled, state)
        self.assertEqual((failed.status, failed.check_code), (S.FAIL, "PBR_POLICY_MISSING"))
        self.assertEqual(self.evaluate("PBR_POLICY_DEFINED", {"name": "OTHER", "sequences": [{"sequence": 1}]}, state).status, S.FAIL)
        for attached in ({"policy_name": "LEGACY", "interface": "eth2"}, {"policy_name": "CAP_PBR", "interface": "eth9"},
                         {"policy_name": "CAP_PBR", "interface": "eth3", "direction": "OUT"}):
            with self.subTest(attached=attached):
                result = self.evaluate("PBR_ATTACHMENT_INTENDED", attached, state)
                self.assertEqual((result.status, result.check_code), (S.FAIL, "PBR_ATTACHMENT_MISSING"))

    def test_postcheck_is_unknown_without_a_pbr_read(self):
        result = self.evaluate("PBR_POLICY_DEFINED", {"name": "CAP_PBR", "sequences": [{"sequence": 10}]}, None)
        self.assertEqual(result.status, S.UNKNOWN)

    def test_pbr_sequence_returns_the_comparable_tuple(self):
        self.assertEqual(evaluators._pbr_sequence({"sequence": "10", "source_prefix": "198.51.100.1/24", "next_hop": "198.18.7.2"}),
                         (10, "198.51.100.0/24", "", "198.18.7.2"))

    def test_precheck_attachment_returns_the_interface_prerequisite(self):
        with mock.patch.object(evaluators, "_interface_prerequisite", return_value="checked") as prerequisite:
            self.assertEqual(evaluators._pre_pbr_attachment(SimpleNamespace(expected={"interface": "eth3"}), "ctx"), "checked")
        self.assertEqual(prerequisite.call_args.args[2], ["eth3"])


# --- planner facts ---------------------------------------------------------------------------------------------------
class PbrPlannerFactsTests(SimpleTestCase):
    def test_plan_carries_the_policy_and_attachment_facts(self):
        specs, requirements, _sections = batch().plan("service_policy.PBR_IPV6")
        self.assertEqual(specs[0].expected, {"name": "CAP_PBR", "family": "IPV6", "sequences": [
            {"sequence": 10, "source_prefix": "2001:db8:114::/64", "destination_prefix": "2001:db8:192::/64",
             "next_hop": "2001:db8:77::2"}]})
        self.assertEqual(specs[1].expected, {"policy_name": "CAP_PBR", "interface": "eth3", "direction": "IN"})
        self.assertEqual([r.check_types for r in requirements], [("PBR_POLICY_PRESENT",), ("PBR_ATTACHMENT_PRESENT",)])


# --- live runner (offline) -------------------------------------------------------------------------------------------
class PbrProbePlanTests(SimpleTestCase):
    def test_family_reads_ipv6_from_the_cell_key(self):
        self.assertEqual(batch().family("service_policy.PBR_ATTACH_IPV6"), "IPV6")

    def test_family_is_not_ipv6_without_an_ipv6_marker(self):
        self.assertEqual(batch().family("service_policy.PBR_IPV4"), "IPV4")

    def test_intent_returns_one_sequence_attached_on_the_lab_port(self):
        b = batch()
        sections = b.intent("service_policy.PBR_IPV4")
        (pol,) = sections["policy"]["pbr"]["policies"].values()
        (seq,) = pol["sequences"].values()
        self.assertEqual((seq["source_prefix"], seq["destination_prefix"], seq["next_hop"]),
                         (b.PEER_NET["IPV4"], b.DESTINATION["IPV4"], b.NEXT_HOP["IPV4"]))
        (att,) = sections["policy"]["pbr"]["attachments"].values()
        self.assertEqual((att["policy_id"], att["direction"]), (pol["id"], "IN"))
        self.assertEqual(next(iter(sections["interfaces"].values()))["name"], b.PORT)

    def test_intent_refuses_an_unknown_cell(self):
        with self.assertRaises(KeyError):
            batch().intent("service_policy.PBR_IPX")

    def test_planner_context_carries_the_sample_policy_intent(self):
        b = batch()
        ctx = b.planner_context(b.intent("service_policy.PBR_IPV6"))
        self.assertEqual((ctx.platform, ctx.interfaces[0]["name"]), ("ubuntu_frr", b.PORT))
        self.assertIn("pbr", ctx.phase12["policy"])

    def test_planner_context_refuses_intent_without_interfaces(self):
        with self.assertRaises(KeyError):
            batch().planner_context({"policy": {}})

    def test_plan_builds_the_policy_and_attachment_configlets(self):
        specs, _requirements, _sections = batch().plan("service_policy.PBR_ATTACH_IPV4")
        self.assertEqual(specs[0].lines, POLICY)
        self.assertEqual(specs[1].lines, ATTACH)

    def test_plan_refuses_an_unknown_cell(self):
        with self.assertRaises(KeyError):
            batch().plan("service_policy.PBR_UNKNOWN")

    def test_conflicting_spec_returns_an_attachment_on_the_seeded_interface(self):
        b = batch()
        self.assertEqual(b.conflicting().lines, ("interface eth2", "   pbr-policy CAP_PBR"))
        self.assertEqual(b.conflicting().expected["interface"], b.SEED_PORT)

    LEGACY_STATE = {"policies": {"LEGACY": {"valid": True, "sequences": [{"installed": True}]}},
                    "attachments": [{"interface": "eth2", "policy": "LEGACY", "valid": True}]}
    LEGACY_TEXT = "pbr-map LEGACY seq 10\n match src-ip 203.0.113.0/24\n set nexthop 198.18.7.2\nexit\n"

    def test_preserved_accepts_the_seeded_policy_still_installed_and_attached(self):
        self.assertTrue(batch().preserved(self.LEGACY_TEXT, self.LEGACY_STATE))

    def test_preserved_is_false_when_the_seed_changed_or_is_not_applied(self):
        b = batch()
        self.assertFalse(b.preserved(self.LEGACY_TEXT.replace("198.18.7.2", "198.18.7.3"), self.LEGACY_STATE))
        self.assertFalse(b.preserved(self.LEGACY_TEXT, {**self.LEGACY_STATE, "attachments": []}))
        self.assertFalse(b.preserved(self.LEGACY_TEXT, {"policies": {"LEGACY": {"valid": True, "sequences": [{"installed": False}]}},
                                                        "attachments": self.LEGACY_STATE["attachments"]}))
        self.assertFalse(b.preserved("", {}))

    def test_imported_recovers_the_policy_and_its_attachment(self):
        b = batch()
        running = "pbr-map CAP_PBR seq 10\n match src-ip 198.51.100.0/24\n match dst-ip 192.0.2.0/24\n set nexthop 198.18.7.2\nexit\n" \
                  "interface eth3\n pbr-policy CAP_PBR\nexit\n"
        self.assertTrue(b.imported(b.intent("service_policy.PBR_IPV4"), running))

    def test_imported_is_false_without_the_attachment_or_with_another_next_hop(self):
        b = batch()
        sections = b.intent("service_policy.PBR_IPV4")
        policy_text = "pbr-map CAP_PBR seq 10\n match src-ip 198.51.100.0/24\n match dst-ip 192.0.2.0/24\n set nexthop 198.18.7.2\nexit\n"
        self.assertFalse(b.imported(sections, policy_text))
        self.assertFalse(b.imported(sections, policy_text.replace("7.2", "7.3") + "interface eth3\n pbr-policy CAP_PBR\nexit\n"))
        self.assertFalse(b.imported(sections, ""))


class PbrLabTests(SimpleTestCase):
    """The lab wrapper's prerequisites, flows and restoration, with every container command replaced."""

    def lab(self, fam="IPV4"):
        b = batch()
        lab = b.PbrLab.__new__(b.PbrLab)
        lab.family, lab.fc, lab.pc, lab.peer_pid, lab.prepared = fam, "frr", "peer", "22", True
        lab.rules, lab.forwarding = "rules", "0"
        lab.pair = mock.Mock(**{"close.return_value": True})
        return lab

    def test_lab_init_creates_the_egress_dummy_routes_and_forwarding(self):
        b = batch()
        must = mock.Mock(return_value="")
        with mock.patch.multiple(b, FrrPair=mock.Mock(return_value=mock.Mock(dut={}, fc="frr", pc="peer"), must=must),
                                 _run=mock.Mock(return_value=SimpleNamespace(stdout=json.dumps([{"State": {"Pid": 42}}]))),
                                 _call=mock.Mock(return_value=SimpleNamespace(returncode=0, stdout="0"))):
            lab = b.PbrLab("IPV6")
        self.assertEqual((lab.peer_pid, lab.forwarding), ("42", "0"))
        self.assertIn(mock.call("frr", "ip", "link", "add", b.EGRESS, "type", "dummy"), must.call_args_list)
        self.assertIn(mock.call("frr", "ip", "-6", "route", "add", "blackhole", b.DESTINATION["IPV6"]), must.call_args_list)
        self.assertIn(mock.call("peer", "ip", "-4", "route", "add", b.DESTINATION["IPV4"], "via", b.DUT_HOP["IPV4"]), must.call_args_list)
        self.assertEqual(must.call_args_list[-1], mock.call("frr", "sysctl", "-qw", f"net.ipv6.conf.{b.PORT}.force_forwarding=1"))

    def test_lab_init_failure_restores_the_lab_and_raises(self):
        b = batch()
        with mock.patch.multiple(b, FrrPair=mock.Mock(return_value=mock.Mock(dut={}, fc="frr", pc="peer"),
                                                      must=mock.Mock(side_effect=RuntimeError("dummy refused"))),
                                 _run=mock.Mock(return_value=SimpleNamespace(stdout=json.dumps([{"State": {"Pid": 42}}]))),
                                 _call=mock.Mock(return_value=SimpleNamespace(returncode=0, stdout="0"))), \
                mock.patch.object(b.PbrLab, "close") as close:
            with self.assertRaisesRegex(RuntimeError, "dummy refused"):
                b.PbrLab("IPV4")
        close.assert_called_once()

    def test_policy_rules_returns_both_families(self):
        b = batch()
        with mock.patch.object(b, "_call", side_effect=[SimpleNamespace(stdout="v4"), SimpleNamespace(stdout="v6")]):
            self.assertEqual(self.lab().policy_rules(), "v4\nv6")

    def test_pbr_routes_returns_zebra_pbr_routes_of_every_table(self):
        b = batch()
        with mock.patch.object(b, "_call", return_value=SimpleNamespace(stdout="default via 198.18.7.2 table 10000 proto pbr\n")) as call:
            self.assertIn("proto pbr", self.lab().pbr_routes())
        self.assertEqual(call.call_args.args[1:], ("ip", "-6", "route", "show", "table", "all", "proto", "pbr"))

    def test_steered_returns_the_egress_tx_counter(self):
        b = batch()
        with mock.patch.object(b, "_call", return_value=SimpleNamespace(stdout="17\n")) as call:
            self.assertEqual(self.lab().steered(), 17)
        self.assertIn(f"/sys/class/net/{b.EGRESS}/statistics/tx_packets", call.call_args.args)

    def test_ping_sends_from_the_source_inside_the_peer_namespace(self):
        b = batch()
        with mock.patch.object(b, "_run") as run:
            self.lab("IPV6").ping("2001:db8:114::1")
        argv = run.call_args.args[0]
        self.assertEqual(argv[:6], ["sudo", "-n", "nsenter", "-t", "22", "-n"])
        self.assertEqual(argv[-3:], ["-I", "2001:db8:114::1", b.TARGET["IPV6"]])

    def test_ping_without_a_reply_does_not_raise(self):
        b = batch()
        with mock.patch.object(b, "_run", return_value=SimpleNamespace(returncode=1, stdout="100% packet loss")) as run:
            self.assertIsNone(self.lab().ping("198.18.0.2"))
        run.assert_called_once()

    def test_observe_returns_the_counter_delta_per_source(self):
        b = batch()
        with mock.patch.object(b.PbrLab, "ping"), mock.patch.object(b.PbrLab, "steered", side_effect=[10, 16, 16, 16]):
            self.assertEqual(self.lab().observe(), {"matching source": 6, "other source": 0})

    def test_expected_returns_steering_only_for_the_matching_source(self):
        b = batch()
        self.assertEqual(b.PbrLab.expected(True), {"matching source": b.PINGS, "other source": 0})

    def test_expected_while_not_steering_is_zero_for_every_source(self):
        self.assertEqual(batch().PbrLab.expected(False), {"matching source": 0, "other source": 0})

    def test_settled_returns_once_the_flows_match(self):
        b = batch()
        with mock.patch.object(b.PbrLab, "observe", return_value=b.PbrLab.expected(True)):
            ok, seen, _took = self.lab().settled(True)
        self.assertTrue(ok)
        self.assertEqual(seen["matching source"], b.PINGS)

    def test_settled_fails_when_the_flows_never_match_within_the_limit(self):
        b = batch()
        clock = itertools.chain([0.0, 0.0], itertools.repeat(100.0))
        with mock.patch.object(b.PbrLab, "observe", return_value={}), mock.patch.object(b.time, "sleep"), \
                mock.patch.object(b.time, "monotonic", side_effect=lambda: next(clock)):
            self.assertEqual(self.lab().settled(False, limit=6), (False, {}, 100))

    def test_close_restores_the_baseline(self):
        b = batch()
        lab = self.lab()
        with mock.patch.object(b, "_call", return_value=SimpleNamespace(returncode=0, stdout="0")) as call, \
                mock.patch.object(b.PbrLab, "policy_rules", return_value="rules"), mock.patch.object(b.PbrLab, "pbr_routes", return_value=""):
            self.assertTrue(lab.close())
            self.assertTrue(lab.close())             # idempotent once closed
        self.assertIn(mock.call("frr", "ip", "link", "delete", b.EGRESS), call.call_args_list)
        lab.pair.close.assert_called_once()

    def test_close_raises_when_pbr_routes_or_rules_were_left_behind(self):
        b = batch()
        for rules, routes in (("changed", ""), ("rules", "default via 198.18.7.2 proto pbr")):
            with self.subTest(rules=rules, routes=routes), \
                    mock.patch.object(b, "_call", return_value=SimpleNamespace(returncode=0, stdout="0")), \
                    mock.patch.object(b.PbrLab, "policy_rules", return_value=rules), \
                    mock.patch.object(b.PbrLab, "pbr_routes", return_value=routes):
                with self.assertRaisesRegex(RuntimeError, "did not return to its captured baseline"):
                    self.lab().close()

    def test_pbr_state_returns_the_parsed_live_read(self):
        b = batch()
        outputs = iter([MAP_JSON, NEXTHOP_JSON, INTERFACE_JSON])
        with mock.patch.object(b, "_call", side_effect=lambda *_a: SimpleNamespace(stdout=next(outputs))):
            self.assertEqual(list(b._pbr_state("frr")["policies"]), ["CAP_PBR"])


class PbrProbeVerdictTests(SimpleTestCase):
    SEEDED = "existing policy attached elsewhere"
    PASSING = {"applied": True, "read_ok": True, "post_ok": True, "imported": True, "verified": True, "control": True,
               "compensated": True, "config_restored": True, "after": True, "restored": True, "preserved": True,
               "actions": [], "statuses": [], "detail": "", "failure": "", "negative": ""}

    def scenarios(self, **seeded):
        return {"pristine node": dict(self.PASSING),
                self.SEEDED: {**self.PASSING, "negative": "APPLY/False/COMPENSATION_NOT_PROVABLE", **seeded}}

    def test_scenarios_for_returns_the_pristine_and_seeded_scenarios(self):
        b = batch()
        with mock.patch.object(b, "_scenario", return_value={}) as scenario:
            self.assertEqual(list(b.scenarios_for("service_policy.PBR_IPV4")), ["pristine node", self.SEEDED])
        self.assertEqual(scenario.call_args_list, [mock.call("service_policy.PBR_IPV4", seeded=False),
                                                   mock.call("service_policy.PBR_IPV4", seeded=True)])

    def test_scenarios_for_raises_when_the_lab_is_not_restored(self):
        b = batch()
        with mock.patch.object(b, "_scenario", side_effect=RuntimeError("did not return to its captured baseline")):
            with self.assertRaisesRegex(RuntimeError, "captured baseline"):
                b.scenarios_for("service_policy.PBR_IPV6")

    def test_probe_records_a_passing_live_verdict_from_mocked_scenarios(self):
        b = batch()
        cell = SimpleNamespace(probes={}, runtime_version="")
        with mock.patch.object(b, "scenarios_for", return_value=self.scenarios()):
            b.probe_frr_pbr(cell, "service_policy.PBR_IPV6")
        self.assertEqual({r["outcome"] for r in cell.probes.values()}, {"PASS"})
        self.assertEqual(len(cell.probes), 6)
        self.assertIn("pbr-map CAP_PBR seq 10", cell.probes["live_write"]["detail"])
        self.assertEqual(cell.runtime_version, b.RUNTIME)

    def test_probe_fails_runtime_validation_when_the_conflict_was_not_refused(self):
        b = batch()
        cell = SimpleNamespace(probes={}, runtime_version="")
        with mock.patch.object(b, "scenarios_for", return_value=self.scenarios(negative="APPLY/True/-")):
            b.probe_frr_pbr(cell, "service_policy.PBR_IPV4")
        self.assertEqual(cell.probes["runtime_validation"]["outcome"], "FAIL")
        self.assertEqual(cell.probes["live_write"]["outcome"], "PASS")

    def test_probe_fails_compensation_when_the_seeded_policy_was_not_preserved(self):
        b = batch()
        cell = SimpleNamespace(probes={}, runtime_version="")
        with mock.patch.object(b, "scenarios_for", return_value=self.scenarios(preserved=False)):
            b.probe_frr_pbr(cell, "service_policy.PBR_ATTACH_IPV4")
        self.assertEqual(cell.probes["compensation"]["outcome"], "FAIL")

    def test_scenario_records_a_lab_failure_and_still_closes_the_lab(self):
        b = batch()
        lab = mock.Mock(fc="frr", dut={"container": "frr"}, **{"settled.return_value": (False, {"matching source": 3}, 30),
                                                                  "close.return_value": True})
        with mock.patch.object(b, "PbrLab", return_value=lab), mock.patch.object(b, "LinuxExecutor") as executor, \
                mock.patch.object(b, "read_frr_config", return_value=""), mock.patch.object(b, "_call") as call:
            result = b._scenario("service_policy.PBR_IPV4", seeded=True)
        self.assertIn("Control flows are not as expected", result["failure"])
        self.assertTrue(result["restored"])
        executor.return_value.close.assert_called_once()
        self.assertIn("no pbr-map LEGACY", call.call_args.args)


class PbrHarnessTests(SimpleTestCase):
    """The isolated harness entry point, driven with its lab, database and Git replaced."""

    @staticmethod
    def load():
        path = Path(__file__).resolve().parents[3] / "labs/phase9-frr-pbr-isolated/run.py"
        module_spec = importlib.util.spec_from_file_location("nmas_phase9_frr_pbr_run", path)
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
                mock.patch.object(module, "probe_frr_pbr", return_value={"pristine node": {"restored": True}}) as probe, \
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
            module, probe, _printed = self.run_main(root, "PASS", ["service_policy.PBR_ATTACH_IPV6"])
            evidence = json.loads((root / module.EVIDENCE / "service_policy-PBR_ATTACH_IPV6.json").read_text())
        probe.assert_called_once()
        self.assertEqual(evidence["schema"], "nmas.v2.phase9.frr-pbr-live/1")
        self.assertTrue(evidence["ephemeral_database"])
        self.assertEqual(set(evidence["uncommitted_source_sha256"]), set(module.SOURCES))

    def test_harness_main_skips_the_lab_after_an_offline_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.fake_root(directory)
            module, probe, printed = self.run_main(root, "FAIL", [])
            self.assertFalse((root / module.EVIDENCE).exists())
        probe.assert_not_called()
        self.assertEqual(printed.call_count, len(module.CELLS))
