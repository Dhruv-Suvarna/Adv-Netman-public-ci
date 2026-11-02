"""Configuration Changes / Remove Configuration through the REAL lifecycle, on fakes only.

snapshot (fake read-only session) -> Change -> Phase-13 validation -> Phase-14 plan -> Phase-15 precheck -> Phase-17 execution
with the production ``CeosExecutor`` talking to an in-memory EOS simulator.  No test contacts a device, NetBox or the network.
"""
from __future__ import annotations

import re

from django.test import TestCase

from core import models
from core.services import change_plan_service as cps, execution_service as es, health_service as hs, workbench_service as wb
from core.services.config_workbench import contribution, snapshots
from core.services.config_workbench.structure import config_paths
from core.services.execution.executors.ceos import CeosExecutor
from core.tests.helpers import health as h
from core.tests.helpers.validation import make_sources
from core.tests.helpers.workbench import use_scope
from core.tests.test_config_workbench import SWITCH

DEVICE = "S1"


class FakeEos:
    """Just enough EOS for removal: flattened ``no ...`` commands edit an in-memory running config."""

    def __init__(self, text: str):
        self.text = text
        self.sent: list[list[str]] = []

    # netmiko surface used by CeosExecutor
    def send_command(self, command, **kwargs):
        assert command == "show running-config"
        return self.text

    def config_mode(self, **kwargs):
        return ""

    def check_config_mode(self):
        return False

    def exit_config_mode(self):
        return ""

    def disconnect(self):
        pass

    def send_config_set(self, commands, **kwargs):
        self.sent.append(list(commands))
        lines = self.text.splitlines()
        context: list[str] = []
        for command in commands:
            if command in ("exit", "end"):
                if context:
                    context.pop()
                continue
            if not command.startswith("no "):
                if not context and not command.startswith(" "):
                    if command in lines:
                        context = [command]
                    else:   # re-adding a top-level stanza (compensation)
                        lines.append(command)
                        context = [command]
                else:
                    header = context[-1]
                    index = lines.index(header)
                    lines.insert(index + 1, "   " + command.strip())
                continue
            statement = command[3:]
            if not context:
                if statement in lines:
                    start = lines.index(statement)
                    end = start + 1
                    while end < len(lines) and lines[end].startswith(" "):
                        end += 1
                    del lines[start:end]
                continue
            header = context[-1]
            start = lines.index(header)
            end = start + 1
            while end < len(lines) and lines[end].startswith(" "):
                end += 1
            peer = re.fullmatch(r"neighbor (\S+)", statement)
            keep = []
            for line in lines[start + 1:end]:
                gone = line.strip() == statement or (peer and line.strip().startswith(f"neighbor {peer.group(1)} "))
                if not gone:
                    keep.append(line)
            lines[start + 1:end] = keep
        self.text = "\n".join(lines) + "\n"
        return ""


def fetch_factory(text):
    return h.session_factory({DEVICE: h.eos_outputs(config=text)})


class RemovalLifecycleTests(TestCase):
    def setUp(self):
        use_scope(self)
        self.sources = make_sources()
        self.snapshot, error = snapshots.capture_snapshot(DEVICE, actor="tester", session_factory=fetch_factory(SWITCH))
        self.assertEqual(error, "")

    def removal_change(self, object_ids, proposals=()):
        selection = wb.removal_selection(models.RemovalMode.SEMANTIC, object_ids=object_ids, accepted_proposals=proposals)
        return wb.create_removal_change(snapshot=self.snapshot, mode=models.RemovalMode.SEMANTIC, selection=selection, actor="tester")

    def plan(self, change):
        from core.services import change_validation_service as cvs

        run = cvs.validate_change(change, actor="tester", sources=self.sources)
        self.assertIn(run.status, ("PASS", "PASS_WITH_WARNINGS"), [f["code"] for f in (run.report or {}).get("findings", [])])
        plan, _ = cps.build_change_plan(change, actor="tester", sources=self.sources)
        return plan

    def test_snapshot_is_sanitized_line_numbered_and_uses_the_import_digest(self):
        rows = snapshots.numbered(self.snapshot, highlight=[3])
        self.assertEqual(rows[2], {"number": 3, "text": "vlan 10", "highlight": True})
        self.assertEqual(len(self.snapshot.digest), 64)
        with self.assertRaises(ValueError):
            self.snapshot.save()   # immutable evidence

    def test_blocked_selection_is_refused_and_nothing_is_saved(self):
        with self.assertRaises(wb.RemovalRefused):
            self.removal_change(["vlan:10"])
        self.assertFalse(models.ConfigRemoval.objects.exists())

    def test_svi_plus_accepted_vlan_plans_first_class_removal_configlets_in_safe_order(self):
        change = self.removal_change(["interface:Vlan40"], proposals=["vlan:40"])
        plan = self.plan(change)
        rows = list(plan.configlets.order_by("sequence"))
        self.assertEqual([(c.operation_type, c.origin, c.rendered_config) for c in rows], [
            ("REMOVE_DELETE", "REMOVAL", "no interface Vlan40"), ("REMOVE_DELETE", "REMOVAL", "no vlan 40")])
        self.assertEqual(rows[1].dependencies.get().depends_on, rows[0])
        self.assertEqual(rows[0].metadata["removal"]["restore_lines"], ["interface Vlan40", "   ip address 192.168.40.2/24"])
        requirement = rows[0].verification_spec["requirements"][0]
        self.assertEqual((requirement["requirement"], requirement["expected"]["absent_paths"]), ("CONFIG_REMOVED", ["interface Vlan40"]))

    def test_validator_rederives_from_snapshot_text_not_the_stored_page_copy(self):
        change = self.removal_change(["interface:Vlan40"])
        models.ConfigRemoval.objects.filter(change=change).update(selection={"object_ids": ["vlan:10"], "accepted_proposals": []})
        from core.services import change_validation_service as cvs

        run = cvs.validate_change(change, actor="tester", sources=self.sources)
        self.assertEqual(run.status, "BLOCKED")
        self.assertIn("REMOVAL_BLOCKED", [f["code"] for f in run.report["findings"]])

    def execute(self, change, eos, *, mode=models.ExecutionMode.COMPLETE):
        change.execution_mode = mode
        change.save(update_fields=["execution_mode"])
        precheck = hs.run_change_precheck(change, actor="tester", sources=self.sources, snapshot=h.snapshot(),
                                          session_factory=fetch_factory(eos.text), persist=True)
        self.assertIn(precheck.result, ("PASS", "PASS_WITH_WARNINGS"), [(r.check_code, r.status) for r in precheck.results])
        managed = {"name": DEVICE, "platform": "ceos"}

        def factory(device):
            return CeosExecutor(device, connection_factory=lambda d: eos, reader=lambda d: h.device_evidence(DEVICE))

        def evidence(plan, cfg_ids):
            return h.evidence_set(h.device_evidence(DEVICE, config_paths=sorted(config_paths(eos.text))))

        return es.execute_change(change, actor="tester", confirm_mode=mode, sources=self.sources, executor_factory=factory,
                                 evidence_provider=evidence, notifier=lambda **k: None, sleep=lambda s: None,
                                 acknowledgements={name: True for name, _ in es.UAT_ACK_FIELDS}, clock=iter(range(0, 10000, 5)).__next__,
                                 through_cfg_id="" if mode == models.ExecutionMode.COMPLETE else "CFG-002"), managed

    def test_complete_execution_removes_verifies_by_read_back_and_records_history(self):
        change = self.removal_change(["interface:Vlan40"], proposals=["vlan:40"])
        self.plan(change)
        eos = FakeEos(SWITCH)
        result, _ = self.execute(change, eos)
        self.assertEqual(result.outcome, models.ExecutionOutcome.SUCCEEDED, result.run.report.get("blockers") or result.run.report.get("postcheck"))
        self.assertNotIn("interface Vlan40", eos.text)
        self.assertNotIn("vlan 40\n", eos.text)
        self.assertIn("vlan 10", eos.text)                                # nothing outside the removal changed
        self.assertEqual(result.run.report["postcheck"]["result"], "PASS")
        self.assertEqual(eos.sent, [["no interface Vlan40"], ["no vlan 40"]])
        live = result.run.network_config_validation_runs.get()
        self.assertEqual((live.operation_type, live.status, live.created_by), ("POST_REMOVAL", "PASS", "tester"))
        self.assertEqual(live.device, DEVICE)

    def test_stale_snapshot_blocks_execution_before_any_mutation(self):
        change = self.removal_change(["interface:Vlan40"])
        self.plan(change)
        eos = FakeEos(SWITCH.replace("   name LAB_ONLY", "   name CHANGED_BY_SOMEONE_ELSE"))
        result, _ = self.execute(change, eos)
        self.assertEqual(result.outcome, models.ExecutionOutcome.BLOCKED)
        self.assertIn("SNAPSHOT_STALE", [b["code"] for b in result.run.report["blockers"]])
        self.assertEqual(eos.sent, [])

    def test_failed_postcheck_in_complete_mode_restores_the_captured_lines(self):
        change = self.removal_change(["bgp_neighbor:65001/10.0.0.3"])
        self.plan(change)
        eos = FakeEos(SWITCH)
        change.execution_mode = models.ExecutionMode.COMPLETE
        change.save(update_fields=["execution_mode"])
        hs.run_change_precheck(change, actor="tester", sources=self.sources, snapshot=h.snapshot(), session_factory=fetch_factory(eos.text), persist=True)

        def factory(device):
            return CeosExecutor(device, connection_factory=lambda d: eos, reader=lambda d: h.device_evidence(DEVICE))

        def lying_evidence(plan, cfg_ids):   # the postcheck still sees the neighbor -> Complete must compensate
            return h.evidence_set(h.device_evidence(DEVICE, config_paths=sorted(config_paths(SWITCH))))

        result = es.execute_change(change, actor="tester", confirm_mode="COMPLETE", sources=self.sources, executor_factory=factory,
                                   evidence_provider=lying_evidence, notifier=lambda **k: None, sleep=lambda s: None,
                                   clock=iter(range(0, 10000, 50)).__next__)
        self.assertEqual(result.outcome, models.ExecutionOutcome.POSTCHECK_FAILED_ROLLED_BACK)
        self.assertIn("neighbor 10.0.0.3 remote-as 65003", eos.text)       # restored by read-back-verified compensation

    def test_fixture_only_platform_cannot_reach_a_plan(self):
        frr = models.RunningConfigSnapshot.objects.create(device_name="R3", platform="ubuntu_frr", digest="0" * 64,
                                                          text="router bgp 65003\n neighbor 10.0.34.4 remote-as 65004\nexit\n", line_count=3,
                                                          source="fixture", captured_at=self.snapshot.captured_at)
        selection = wb.removal_selection(models.RemovalMode.SEMANTIC, object_ids=["bgp_neighbor:65003/10.0.34.4"])
        change = wb.create_removal_change(snapshot=frr, mode=models.RemovalMode.SEMANTIC, selection=selection)
        from core.services import change_validation_service as cvs

        run = cvs.validate_change(change, actor="tester", sources=self.sources)
        self.assertEqual(run.status, "BLOCKED")
        self.assertIn("REMOVAL_NOT_EXECUTABLE", [f["code"] for f in run.report["findings"]])


ROUTER = """hostname R1
interface Ethernet1
   description uplink
   no switchport
   ip address 192.0.2.1/31
interface Ethernet2
   no switchport
   ip address 198.51.100.1/24
router ospf 10
   router-id 1.1.1.1
end
"""


class ContributionTests(TestCase):
    def setUp(self):
        use_scope(self)
        self.sources = make_sources()
        self.factory = h.session_factory({"R1": h.eos_outputs(config=ROUTER)})
        self.snapshot, error = snapshots.capture_snapshot("R1", actor="tester", session_factory=self.factory)
        self.assertEqual(error, "")

    def build(self, operations):
        return contribution.create_contribution_change(snapshot=self.snapshot, operations=operations, actor="tester", session_factory=self.factory)

    def test_plan_contains_only_the_requested_contribution(self):
        change = self.build([
            {"op": "static_route", "destination": "10.9.0.0/24", "next_hop": "192.0.2.0"},
            {"op": "interface_address", "interface": "Ethernet2", "cidr": "203.0.113.1/24", "role": "SECONDARY"},
        ])
        from core.services import change_validation_service as cvs

        run = cvs.validate_change(change, actor="tester", sources=self.sources)
        self.assertIn(run.status, ("PASS", "PASS_WITH_WARNINGS"), [(f["code"], f["message"]) for f in run.report["findings"] if f["severity"] == "ERROR"])
        plan, _ = cps.build_change_plan(change, actor="tester", sources=self.sources)
        rendered = [c.rendered_config for c in plan.configlets.order_by("sequence")]
        self.assertEqual(sorted(rendered), sorted(["ip route 10.9.0.0/24 192.0.2.0", "interface Ethernet2\n   ip address 203.0.113.1/24 secondary"]))
        everything = "\n".join(rendered)
        for untouched in ("description uplink", "router ospf 10", "192.0.2.1/31", "198.51.100.1/24", "no switchport"):
            self.assertNotIn(untouched, everything)
        self.assertIn("CONTRIBUTION_CONTEXT_EXCLUDED", [w["code"] for w in plan.warnings])

    def test_import_digest_must_match_the_snapshot_or_nothing_is_kept(self):
        self.factory = h.session_factory({"R1": h.eos_outputs(config=ROUTER.replace("uplink", "changed"))})
        with self.assertRaises(contribution.ContributionError):
            self.build([{"op": "static_route", "destination": "10.9.0.0/24", "next_hop": "192.0.2.0"}])
        self.assertFalse(models.Change.objects.filter(metadata__workflow="CONFIGURATION_CHANGES").exists())

    def test_invalid_or_protected_operations_are_refused_before_anything_is_created(self):
        for op in ({"op": "interface_address", "interface": "Ethernet9", "cidr": "10.0.0.1/24"},
                   {"op": "static_route", "destination": "not-a-prefix", "next_hop": "192.0.2.0"},
                   {"op": "bgp_neighbor", "peer_address": "10.0.0.2", "remote_asn": "65002"}):
            with self.assertRaises(contribution.ContributionError):
                self.build([op])
        self.assertEqual(models.Change.objects.count(), 0)

    def test_direct_cli_is_normalized_onto_structured_operations(self):
        parsed = contribution.parse_direct_cli(
            "ip route 10.9.0.0/24 192.0.2.0\ninterface Ethernet2\n   ip address 203.0.113.1/24 secondary\n"
            "no ip route 10.8.0.0/24 192.0.2.0\nusername x secret TEST_ONLY_ROTATION_SECRET_NEVER_REAL\nspanning-tree mode mstp\n",
            "arista_ceos", ROUTER)
        self.assertEqual([op["op"] for op in parsed["operations"]], ["static_route", "interface_address"])
        reasons = {r["reason"] for r in parsed["rejected"]}
        self.assertEqual(reasons, {"REMOVAL_BELONGS_IN_REMOVE_CONFIGURATION", "SECRET_MATERIAL_REFUSED", "UNRECOGNISED_STATEMENT"})
        self.assertNotIn("TEST_ONLY_ROTATION_SECRET_NEVER_REAL", str(parsed))

    def test_widget_catalogue_is_capability_honest(self):
        rows = {r["key"]: r for r in contribution.operation_catalogue("arista_ceos")}
        self.assertEqual(rows["static_route"]["mode"], "COMPLETE_OR_PARTIAL")
        # V2 Phase 4 proved exact running-configuration restoration for cEOS BGP on the isolated lab
        # (executors.ceos.CONFIG_BLOCK_TYPES), so the capability model now offers Complete mode for it.
        self.assertEqual(rows["bgp_neighbor"]["mode"], "COMPLETE_OR_PARTIAL")
        frr = {r["key"]: r for r in contribution.operation_catalogue("ubuntu_frr")}
        self.assertTrue(frr["static_route"]["executable"])
        self.assertEqual(frr["static_route"]["mode"], "COMPLETE_OR_PARTIAL")
        # a platform with an executor but no proven apply path for the object type is never offered as executable
        srl = {r["key"]: r for r in contribution.operation_catalogue("nokia_srlinux")}
        self.assertEqual((srl["static_route"]["mode"], srl["bgp_neighbor"]["mode"]), ("COMPLETE_OR_PARTIAL", "NOT_EXECUTABLE"))
        self.assertFalse(srl["bgp_neighbor"]["executable"])
        self.assertFalse({r["key"]: r for r in contribution.operation_catalogue("cisco_iosxr")}["static_route"]["executable"])

    def test_widget_catalogue_mode_follows_the_capability_model_and_never_exceeds_it(self):
        from core.services.execution import capability as execution_capability

        def cap(apply, compensation):
            return execution_capability.ExecutionCapability(apply, compensation, "t", "e", "n")

        for apply, compensation, mode in (("SUPPORTED", "SUPPORTED", "COMPLETE_OR_PARTIAL"), ("SUPPORTED", "NOT_IMPLEMENTED", "PARTIAL_UAT_ONLY"),
                                          ("NOT_IMPLEMENTED", "NOT_IMPLEMENTED", "NOT_EXECUTABLE"), ("NOT_IMPLEMENTED", "SUPPORTED", "NOT_EXECUTABLE")):
            with self.subTest(apply=apply, compensation=compensation), \
                    mock.patch.object(execution_capability, "capability_for", return_value=cap(apply, compensation)):
                row = {r["key"]: r for r in contribution.operation_catalogue("arista_ceos")}["bgp_neighbor"]
                self.assertEqual((row["mode"], row["executable"]), (mode, apply == "SUPPORTED"))


# ---------------------------------------------------------------------------------------------------------------------
# Pages: identical split layout, honest routing, read-only GETs, explicit POSTs only
# ---------------------------------------------------------------------------------------------------------------------
from unittest import mock  # noqa: E402

from django.urls import reverse  # noqa: E402

SECRET_SWITCH = SWITCH.replace("hostname S1\n", "hostname S1\nusername admin privilege 15 secret sha512 TEST_ONLY_ROTATION_SECRET_NEVER_REAL\n")


class CountingFactory:
    def __init__(self, text):
        self.inner = fetch_factory(text)
        self.calls = 0

    def __call__(self, device):
        self.calls += 1
        return self.inner(device)


class WorkbenchPageTests(TestCase):
    def setUp(self):
        use_scope(self)
        self.factory = CountingFactory(SECRET_SWITCH)
        patcher = mock.patch.object(snapshots, "SESSION_FACTORY", self.factory)
        patcher.start()
        self.addCleanup(patcher.stop)
        sources = mock.patch("core.services.change_validation_service.build_source_snapshot", lambda change=None: make_sources())
        sources.start()
        self.addCleanup(sources.stop)

    def capture(self, workflow="REMOVE_CONFIGURATION"):
        response = self.client.post(reverse("core:workbench_snapshot"), {"device": DEVICE, "workflow": workflow})
        self.assertEqual(response.status_code, 302)
        return models.RunningConfigSnapshot.objects.latest("created_at")

    def test_automation_cards_route_to_the_new_workflows_not_device_builder_or_a_shell(self):
        html = self.client.get(reverse("core:automation_landing")).content.decode()
        self.assertIn(f'href="{reverse("core:workbench_changes")}"', html)
        self.assertIn(f'href="{reverse("core:workbench_remove")}"', html)
        from django.urls import resolve

        self.assertIs(resolve(reverse("core:workbench_remove")).func.__name__ == "workbench_remove", True)   # no longer the shell
        self.assertIn(f'href="{reverse("core:automation_section", args=["rollback-recovery"])}"', html)   # rollback stays separate
        self.assertIn("Open Remove Configuration", html)
        from core.services import automation_service

        self.assertNotEqual(automation_service.IMPLEMENTED_SECTIONS["configuration-changes"], "core:device_builder_changes")

    def test_both_pages_share_the_same_two_pane_layout_and_running_config_component(self):
        snapshot = self.capture()
        for name in ("core:workbench_changes", "core:workbench_remove"):
            html = self.client.get(reverse(name), {"device": DEVICE, "snapshot": str(snapshot.snapshot_id)}).content.decode()
            self.assertIn('data-workbench-pane="left"', html, name)
            self.assertIn('data-workbench-pane="right"', html, name)
            self.assertLess(html.index('data-workbench-pane="left"'), html.index('data-workbench-pane="right"'))
            self.assertEqual(html.count('data-component="running-config"'), 1)
            self.assertIn('aria-readonly="true"', html)
            number = snapshot.text.splitlines().index("vlan 10") + 1
            self.assertIn(f'<span class="rc-no" aria-hidden="true">{number}</span><code>vlan 10</code>', html)
            self.assertIn('data-component="workbench-bar"', html)

    def test_page_loads_never_contact_a_device_and_running_config_is_redacted(self):
        snapshot = self.capture()
        calls = self.factory.calls
        for name in ("core:workbench_changes", "core:workbench_remove"):
            html = self.client.get(reverse(name), {"device": DEVICE, "snapshot": str(snapshot.snapshot_id)}).content.decode()
            self.assertNotIn("TEST_ONLY_ROTATION_SECRET_NEVER_REAL", html)
            self.assertIn("&lt;REDACTED&gt;", html)
        self.assertEqual(self.factory.calls, calls)

    def test_browser_supplied_device_or_foreign_snapshot_is_refused(self):
        self.assertEqual(self.client.post(reverse("core:workbench_snapshot"), {"device": "10.0.0.1", "workflow": "REMOVE_CONFIGURATION"}).status_code, 400)
        snapshot = self.capture()
        html = self.client.get(reverse("core:workbench_remove"), {"device": "R1", "snapshot": str(snapshot.snapshot_id)}).content.decode()
        self.assertNotIn("vlan 10</code>", html)       # an S1 snapshot is never shown for R1
        self.assertEqual(self.client.get(reverse("core:workbench_snapshot")).status_code, 405)

    def test_direct_cli_preview_normalizes_rejects_removals_and_writes_nothing(self):
        snapshot = self.capture("CONFIGURATION_CHANGES")
        response = self.client.post(reverse("core:workbench_changes_preview"), {
            "device": DEVICE, "snapshot": str(snapshot.snapshot_id), "mode": "cli",
            "fragment": "ip route 10.77.0.0/16 192.168.110.0\nno vlan 10\n"})
        html = response.content.decode()
        self.assertIn("<code>static_route</code>", html)
        self.assertIn("REMOVAL_BELONGS_IN_REMOVE_CONFIGURATION", html)
        self.assertNotIn("Save Draft", html)            # rejected input must be fixed first
        self.assertFalse(models.Change.objects.exists())

    def test_smart_removal_analysis_proposes_the_vlan_and_save_builds_a_validated_plan(self):
        snapshot = self.capture()
        params = {"device": DEVICE, "snapshot": str(snapshot.snapshot_id), "mode": "smart", "obj": "interface:Vlan40"}
        html = self.client.get(reverse("core:workbench_remove"), params).content.decode()
        self.assertIn('data-status="READY"', html)
        self.assertIn('name="proposal" value="vlan:40"', html)
        self.assertIn("rc-line rc-line--hl", html)
        with_vlan = self.client.get(reverse("core:workbench_remove"), {**params, "proposal": "vlan:40"}).content.decode()
        self.assertIn("no vlan 40", with_vlan)
        selection = json.dumps({"object_ids": ["interface:Vlan40"], "accepted_proposals": ["vlan:40"]})
        response = self.client.post(reverse("core:workbench_remove_save"), {"device": DEVICE, "snapshot": str(snapshot.snapshot_id),
                                                                              "mode": "SEMANTIC", "selection": selection})
        self.assertEqual(response.status_code, 302)
        change = models.Change.objects.get(metadata__workflow="REMOVE_CONFIGURATION")
        page = self.client.get(response["Location"]).content.decode()
        self.assertIn('data-component="patch-preview"', page)
        self.assertIn("no interface Vlan40", page)
        self.assertIn(reverse("core:change_execute", args=[change.change_id]), page)
        self.assertEqual(models.ChangeExecutionRun.objects.count(), 0)   # nothing executed

    def test_line_range_cutting_a_stanza_is_blocked_and_cannot_be_saved(self):
        snapshot = self.capture()
        start = next(n for n, line in enumerate(SECRET_SWITCH.splitlines(), 1) if line == "router bgp 65001")
        html = self.client.get(reverse("core:workbench_remove"), {"device": DEVICE, "snapshot": str(snapshot.snapshot_id), "mode": "line",
                                                                    "from_line": start, "to_line": start + 1}).content.decode()
        self.assertIn('data-status="BLOCKED"', html)
        self.assertIn("PARTIAL_CONTEXT_SELECTED", html)
        self.assertNotIn("Save removal draft", html)
        selection = json.dumps({"from_line": start, "to_line": start + 1})
        response = self.client.post(reverse("core:workbench_remove_save"), {"device": DEVICE, "snapshot": str(snapshot.snapshot_id),
                                                                              "mode": "LINE_RANGE", "selection": selection})
        self.assertIn("error=", response["Location"])
        self.assertFalse(models.ConfigRemoval.objects.exists())


import json  # noqa: E402
