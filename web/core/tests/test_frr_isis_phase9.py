"""FRR IS-IS implementation boundaries: renderer, strict execution grammar and semantic import."""

from __future__ import annotations

import json
from copy import deepcopy
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase

from core.services import platform_drivers as drivers
from core.services.capabilities.features import by_key
from core.services.capabilities.probe_cases import sample
from core.services.config_import import parser_frr
from core.services.execution.executors import frr_routing, linux
from core.services.health import live

NET = "49.0001.0000.0000.0044.00"
PROCESS = ("router isis NMAS44", f"   net {NET}", "   is-type level-2-only", "   metric-style wide")
LINK = ("interface eth1", "   ip router isis NMAS44", "   ipv6 router isis NMAS44",
        "   isis network point-to-point", "   isis circuit-type level-2-only", "   isis metric 20")


class FrrIsisTests(SimpleTestCase):
    def test_renderer_generates_the_named_process_and_both_interface_families(self):
        case = sample("ubuntu_frr", by_key()["routing.ISIS"])
        sections = deepcopy(case.sections)
        instance = next(iter(sections["routing"]["isis"].values()))
        instance.update(net=NET, address_family_ipv4=True, address_family_ipv6=True)
        interface = next(iter(sections["interfaces"].values()))
        instance["interfaces"] = {"bind": {"id": "bind", "interface_id": interface["id"], "passive": False, "metric": 20}}
        with mock.patch.object(drivers, "is_routing_protocol_selectable", return_value=True):
            rendered = drivers.get_driver("ubuntu_frr").render_candidate(
                field_values={"device.hostname": "CAPDUT"}, interfaces=list(sections["interfaces"].values()),
                routing=sections["routing"], phase12={})
        text = [r.get("text") or r["template"].format(value=r["value"]) for r in rendered]
        for line in (*PROCESS, *LINK[1:]):
            self.assertIn(line, text)
        self.assertEqual(text.count("interface eth1"), 1)

    def test_executor_grammar_accepts_only_the_bounded_isis_commands(self):
        blocks = frr_routing.parse([*PROCESS, *LINK])
        self.assertEqual([b.kind for b in blocks], ["isis", "interface"])
        self.assertEqual(frr_routing.required_daemons(blocks), {"zebra", "isisd"})
        for bad in (" redistribute connected", " password clear secret", " isis metric 20\n router bgp 1"):
            self.assertIsNone(frr_routing.parse([*PROCESS, bad]))

    def test_inverse_restores_a_new_process_and_refuses_replacing_an_existing_net(self):
        before = "frr version 8.4.4\nend\n"
        self.assertEqual(linux.frr_routing_inverse(PROCESS, before), ["no router isis NMAS44"])
        existing = f"router isis NMAS44\n net 49.0001.0000.0000.0099.00\nexit\n"
        self.assertIsNone(linux.frr_routing_inverse(PROCESS, existing))

    def test_parser_recovers_isis_and_preserves_foreign_processes(self):
        text = ("interface eth1\n ip router isis NMAS44\n ipv6 router isis NMAS44\n isis metric 20\nexit\n"
                f"router isis NMAS44\n net {NET}\n is-type level-2-only\nexit\n"
                "router isis FOREIGN\n net 49.0001.0000.0000.0099.00\nexit\n")
        parsed = parser_frr.parse(text)
        row = next(r for r in parsed.routing_instances if r.family == "isis")
        self.assertEqual((row.fields["net"], row.fields["level"], row.fields["address_family_ipv4"],
                          row.fields["address_family_ipv6"]), (NET, "LEVEL_2", True, True))
        self.assertEqual(row.bindings[0]["metric"], 20)
        self.assertTrue(any("FOREIGN" in line for block in parsed.unmanaged_blocks for line in block.lines))

    def test_live_neighbor_parser_uses_frr_json_and_refuses_malformed_data(self):
        text = '{"areas":[{"area":"NMAS44","circuits":[{"adj":"peer","interface":"eth3","level":2,"state":"Up"}]}]}'
        self.assertEqual(live.parse_frr_isis(text)[0]["state"], "UP")
        self.assertEqual(live.parse_frr_isis(""), [])
        with self.assertRaises(live.LiveError):
            live.parse_frr_isis("not-json")


class FrrIsisHarnessTests(SimpleTestCase):
    """The isolated FRR IS-IS harness entry point, driven with its lab, database and Git replaced."""

    SOURCES = ("web/core/services/capabilities/batch_frr_isis.py", "web/core/services/platform_drivers.py",
               "web/core/services/execution/executors/frr_routing.py", "web/core/services/execution/executors/linux.py",
               "web/core/services/config_import/parser_frr.py", "web/core/services/candidate_composition.py",
               "web/core/services/health/live.py", "web/core/services/capabilities/offline_verify.py",
               "templates/features/ubuntu_frr/routing_isis.j2")

    @staticmethod
    def load():
        import importlib.util
        from pathlib import Path
        path = Path(__file__).resolve().parents[3] / "labs/phase9-frr-isis-isolated/run.py"
        spec = importlib.util.spec_from_file_location("nmas_phase9_frr_isis_run", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def run_main(self, root, outcome):
        from types import SimpleNamespace
        module = self.load()
        cell = SimpleNamespace(probes={"renderer": {"outcome": outcome}}, complete=outcome == "PASS",
                               status="SUPPORTED" if outcome == "PASS" else "NOT_IMPLEMENTED",
                               as_dict=lambda: {"status": "SUPPORTED"})
        with mock.patch.dict(module.settings.DATABASES["default"], {}, clear=False), \
                mock.patch.object(module, "ROOT", root), \
                mock.patch.object(module.subprocess, "check_output", return_value="revision\n"), \
                mock.patch.object(module, "call_command"), \
                mock.patch.object(module, "verify_cell", return_value=cell), \
                mock.patch.object(module, "probe_frr_isis", return_value={"pristine": {"restored": True}}) as probe, \
                mock.patch("builtins.print"):
            module.main()
        return probe

    def fake_root(self, directory):
        from pathlib import Path
        root = Path(directory)
        for name in self.SOURCES:
            (root / name).parent.mkdir(parents=True, exist_ok=True)
            (root / name).write_text("safe fixture\n")
        return root

    def test_frr_isis_harness_main_positive_writes_ephemeral_evidence(self):
        import json
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            root = self.fake_root(directory)
            probe = self.run_main(root, "PASS")
            evidence = json.loads((root / "docs/evidence/v2-phase9-closure/frr-isis/assessment.json").read_text())
        probe.assert_called_once()
        self.assertTrue(evidence["ephemeral_database"])
        self.assertEqual(evidence["repository_head"], "revision")
        self.assertEqual(set(evidence["uncommitted_source_sha256"]), set(self.SOURCES))

    def test_frr_isis_harness_main_refuses_an_offline_failure_before_the_lab(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            root = self.fake_root(directory)
            with self.assertRaisesRegex(RuntimeError, "offline failure"):
                self.run_main(root, "FAIL")
            self.assertFalse((root / "docs/evidence/v2-phase9-closure/frr-isis/assessment.json").exists())


class FrrIsisReleaseGovernanceTests(SimpleTestCase):
    """Direct offline cases for the FRR IS-IS live runner; the live proof itself is the isolated evidence record."""

    PASSING = {"applied": True, "read_ok": True, "post_ok": True, "verified": True, "runtime_ok": True, "control": True,
               "compensated": True, "config_restored": True, "after": True, "restored": True, "preserved": True}

    def _isis_frr_batch(self):
        from core.services.capabilities import batch_frr_isis
        return batch_frr_isis

    def rendered_text(self) -> str:
        specs, _requirements, _sections = self._isis_frr_batch().plan()
        return "\n".join(line for spec in reversed(specs) for line in (*spec.lines, "exit", "!")) + "\n"

    def test_plan_returns_the_bounded_process_binding_and_postchecks(self):
        batch = self._isis_frr_batch()
        specs, requirements, sections = batch.plan()
        self.assertEqual([spec.object_type for spec in specs], ["routing_isis", "routing_binding"])
        self.assertIn(f"net {batch.NET}", [line.strip() for line in specs[0].lines])
        self.assertIn("ip router isis NMAS44", [line.strip() for line in specs[1].lines])
        self.assertEqual(len(requirements), 3)
        self.assertIn("isis", sections["routing"])

    def test_plan_refuses_a_candidate_without_the_link_binding(self):
        batch = self._isis_frr_batch()
        with mock.patch.object(batch, "_block", side_effect=lambda _rendered, header: [header]):
            with self.assertRaisesRegex(RuntimeError, "lacks the NMAS process or link binding"):
                batch.plan()

    def test_imported_accepts_the_exact_rendered_read_back(self):
        self.assertTrue(self._isis_frr_batch().imported(self.rendered_text()))

    def test_imported_rejects_a_missing_or_drifted_read_back(self):
        batch = self._isis_frr_batch()
        self.assertFalse(batch.imported(""))
        self.assertFalse(batch.imported(self.rendered_text().replace("isis metric 20", "isis metric 10")))

    def test_probe_records_a_passing_live_verdict_from_mocked_scenarios(self):
        batch = self._isis_frr_batch()
        cell = SimpleNamespace(probes={}, runtime_version="")
        with mock.patch.object(batch, "_scenario", return_value=dict(self.PASSING)):
            scenarios = batch.probe_frr_isis(cell)
        self.assertEqual(set(scenarios), {"pristine", "configured"})
        self.assertEqual({row["outcome"] for row in cell.probes.values()}, {"PASS"})
        self.assertEqual(len(cell.probes), 5)

    def test_probe_refuses_a_failed_live_verdict_without_a_device(self):
        batch = self._isis_frr_batch()
        cell = SimpleNamespace(probes={}, runtime_version="")
        with mock.patch.object(batch, "_scenario", return_value={**self.PASSING, "verified": False, "restored": False}):
            batch.probe_frr_isis(cell)
        self.assertEqual(cell.probes["runtime_validation"]["outcome"], "FAIL")
        self.assertEqual(cell.probes["compensation"]["outcome"], "FAIL")
        self.assertEqual(cell.probes["live_write"]["outcome"], "PASS")

    def test_parse_frr_isis_reads_one_adjacency_per_circuit(self):
        text = json.dumps({"areas": [{"area": "NMAS44", "circuits": [
            {"adj": "peer", "interface": "eth3", "level": 2, "state": "Up"}]}]})
        self.assertEqual(live.parse_frr_isis(text), [{"instance": "NMAS44", "system_id": "peer", "hostname": "peer",
                                                      "interface": "eth3", "level": "2", "state": "UP"}])
