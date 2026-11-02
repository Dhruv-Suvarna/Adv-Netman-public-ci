"""V2 Phase 4 -- management VRF: intent, per-platform rendering, validation, planning, cEOS execution inverse and the honest
capability classification.  NMAS database only; no device and no network."""

from __future__ import annotations

import json
from pathlib import Path
from unittest import mock

from django.test import SimpleTestCase, TestCase

from core import models
from core.services import candidate_renderer, change_plan_service as cps, platform_drivers
from core.services.execution import capability
from core.services.execution.executors import ceos
from core.services.management import capability_evidence, vrf
from core.services.health import evaluators as health_evaluators, live as health_live, requirements as health_requirements
from core.services.health.codes import CheckStatus, Phase
from core.tests.helpers import health as health_fixture
from core.tests.helpers.validation import Dev, make_sources, new_change, validate

P = models.Platform


def _candidate(platform=P.ARISTA_CEOS, name="R1", *, address="10.99.0.1/30", services=("SSH",), route=True, bind=True):
    change = new_change("management VRF fixture")
    dev = Dev(change, name, platform=platform)
    port = dev.iface("Ethernet5" if platform != P.UBUNTU_FRR else "eth5")
    if address:
        dev.address(port, address)
    revision = dev.refresh()
    mvrf = vrf.add_vrf(revision, name="MGMT", description="out-of-band")
    binding = vrf.add_binding(revision, vrf_id=mvrf["id"], interface_id=port["id"]) if bind else None
    route_obj = vrf.add_route(revision, vrf_id=mvrf["id"], destination="0.0.0.0/0", next_hop="10.99.0.2") if route else None
    service_objs = [vrf.add_service(revision, vrf_id=mvrf["id"], service=kind) for kind in services]
    return dev, {"vrf": mvrf, "binding": binding, "route": route_obj, "services": service_objs, "port": port}


def _render_via_driver(dev) -> list[str]:
    state = candidate_renderer.hydrate_state(dev.intent, dev.refresh(), use_draft=False)
    driver = platform_drivers.get_driver(dev.intent.platform)
    descriptors = driver.render_candidate(field_values=state["field_values"], interfaces=state["interfaces"],
                                          routing=state["routing"], phase12=state["phase12"])
    return [text for d in descriptors if (text := candidate_renderer.descriptor_text(d)) is not None]


class IntentTests(TestCase):
    def test_add_vrf_binding_route_service_round_trip(self):
        dev, objs = _candidate()
        management = vrf.section(dev.refresh())
        self.assertEqual(list(management["vrfs"]), [objs["vrf"]["id"]])
        self.assertEqual(management["bindings"][objs["binding"]["id"]]["interface_id"], objs["port"]["id"])
        self.assertTrue(vrf.present(management))

    def test_add_vrf_reserved_name_refused(self):
        dev = Dev(new_change(), "R1")
        for name in ("default", "1bad", "x" * 40, "has space"):
            with self.assertRaises(vrf.ManagementIntentError) as caught:
                vrf.add_vrf(dev.refresh(), name=name)
            self.assertEqual(caught.exception.code, "MGMT_VRF_INVALID")

    def test_add_vrf_duplicate_and_limit_refused(self):
        dev = Dev(new_change(), "R1")
        vrf.add_vrf(dev.refresh(), name="MGMT")
        with self.assertRaises(vrf.ManagementIntentError):
            vrf.add_vrf(dev.refresh(), name="mgmt")
        vrf.add_vrf(dev.refresh(), name="MGMT2")
        with self.assertRaises(vrf.ManagementIntentError) as caught:
            vrf.add_vrf(dev.refresh(), name="MGMT3")
        self.assertEqual(caught.exception.code, "MGMT_LIMIT")

    def test_add_binding_layer2_interface_refused(self):
        dev = Dev(new_change(), "R1")
        access = dev.iface("Ethernet7", kind="ACCESS")
        mvrf = vrf.add_vrf(dev.refresh(), name="MGMT")
        with self.assertRaises(vrf.ManagementIntentError) as caught:
            vrf.add_binding(dev.refresh(), vrf_id=mvrf["id"], interface_id=access["id"])
        self.assertEqual(caught.exception.code, "MGMT_BINDING_INVALID")
        with self.assertRaises(vrf.ManagementIntentError) as caught:
            vrf.add_binding(dev.refresh(), vrf_id=mvrf["id"], interface_id="iface_not_mine")
        self.assertEqual(caught.exception.code, "MGMT_INTERFACE_REFERENCE_INVALID")

    def test_add_route_and_service_invalid_refused(self):
        dev = Dev(new_change(), "R1")
        mvrf = vrf.add_vrf(dev.refresh(), name="MGMT")
        with self.assertRaises(vrf.ManagementIntentError):
            vrf.add_route(dev.refresh(), vrf_id=mvrf["id"], destination="not-a-prefix", next_hop="10.0.0.1")
        with self.assertRaises(vrf.ManagementIntentError):
            vrf.add_service(dev.refresh(), vrf_id=mvrf["id"], service="TELNET")
        with self.assertRaises(vrf.ManagementIntentError):
            vrf.add_service(dev.refresh(), vrf_id=mvrf["id"], service="SYSLOG")     # host required
        with self.assertRaises(vrf.ManagementIntentError):
            vrf.add_route(dev.refresh(), vrf_id="mvrf_missing", destination="0.0.0.0/0", next_hop="10.0.0.1")

    def test_remove_vrf_in_use_refused_then_empty_section_removed(self):
        dev, objs = _candidate(services=(), route=False)
        with self.assertRaises(vrf.ManagementIntentError):
            vrf.remove(dev.refresh(), collection="vrfs", object_id=objs["vrf"]["id"])
        vrf.remove(dev.refresh(), collection="bindings", object_id=objs["binding"]["id"])
        vrf.remove(dev.refresh(), collection="vrfs", object_id=objs["vrf"]["id"])
        self.assertNotIn("management", dev.refresh().sections)

    def test_mutation_not_draft_refused(self):
        from core.services import interface_intent_service

        change = new_change()
        dev = Dev(change, "R1")
        models.Change.objects.filter(pk=change.pk).update(lifecycle_state=models.ChangeLifecycleState.VALIDATED)
        with self.assertRaises(interface_intent_service.DraftOnlyError):
            vrf.add_vrf(dev.refresh(), name="MGMT")
        self.assertNotIn("management", dev.refresh().sections)


class RenderTests(TestCase):
    def test_render_without_management_is_byte_identical(self):
        dev = Dev(new_change(), "R1")
        port = dev.iface("Ethernet5")
        dev.address(port, "10.99.0.1/30")
        before = _render_via_driver(dev)
        mvrf = vrf.add_vrf(dev.refresh(), name="MGMT")
        vrf.remove(dev.refresh(), collection="vrfs", object_id=mvrf["id"])
        self.assertEqual(_render_via_driver(dev), before)
        self.assertNotIn("management", candidate_renderer.hydrate_state(dev.intent, dev.refresh(), use_draft=False)["phase12"])

    def test_render_eos_orders_definition_binding_before_address(self):
        dev, _objs = _candidate()
        text = "\n".join(_render_via_driver(dev))
        self.assertIn("vrf instance MGMT", text)
        self.assertIn("ip routing vrf MGMT", text)
        self.assertIn("ip route vrf MGMT 0.0.0.0/0 10.99.0.2", text)
        self.assertIn("management ssh\n   vrf MGMT\n      no shutdown", text)
        self.assertLess(text.index("vrf instance MGMT"), text.index("interface Ethernet5"))
        block = text[text.index("interface Ethernet5"):]
        self.assertLess(block.index("   vrf MGMT"), block.index("ip address 10.99.0.1/30"))

    def test_render_eos_netconf_unsupported_marker(self):
        dev, _objs = _candidate(services=("SSH", "NETCONF"))
        self.assertTrue(any(line.startswith(vrf.UNSUPPORTED) and "NETCONF" in line for line in _render_via_driver(dev)))

    def test_render_iosxe_iosxr_srlinux_ubuntu(self):
        expect = {
            P.CISCO_C8000V_IOSXE: ("vrf definition MGMT", " vrf forwarding MGMT"),
            P.CISCO_IOSXR: ("vrf MGMT", "router static"),
            P.NOKIA_SRLINUX: ("network-instance MGMT", "ip-vrf"),
            P.UBUNTU_FRR: ("type vrf", "master MGMT"),
        }
        for platform, needles in expect.items():
            with self.subTest(platform=platform):
                dev, _objs = _candidate(platform=platform, services=())
                text = "\n".join(_render_via_driver(dev))
                for needle in needles:
                    self.assertIn(needle, text)

    def test_render_unknown_platform_unsupported_marker(self):
        lines = vrf.render("juniper_junos", "definitions", {"vrfs": {"a": {"id": "a", "name": "MGMT"}}}, {})
        self.assertTrue(lines and lines[0]["text"].startswith(vrf.UNSUPPORTED))
        self.assertEqual(vrf.render("arista_ceos", "definitions", None, {}), [])

    def test_sonic_config_db_mgmt_vrf_only_no_bindings(self):
        unsupported: list = []
        doc = vrf.sonic_config_db({"vrfs": {"a": {"id": "a", "name": "mgmt"}}, "bindings": {}, "routes": {}, "services": {}}, unsupported)
        self.assertEqual(doc["MGMT_VRF_CONFIG"]["vrf_global"]["mgmtVrfEnabled"], "true")
        self.assertFalse(unsupported)
        refused: list = []
        vrf.sonic_config_db({"vrfs": {"a": {"id": "a", "name": "MGMT2"}}, "bindings": {"b": {"id": "b"}}, "routes": {}, "services": {}}, refused)
        self.assertTrue(refused)


class ProblemTests(TestCase):
    def test_problems_unbound_and_no_access_service(self):
        management = {"vrfs": {"a": {"id": "a", "name": "MGMT"}}, "bindings": {}, "routes": {}, "services": {}}
        codes = {p["code"] for p in vrf.problems("arista_ceos", management, [])}
        self.assertIn("MGMT_VRF_UNBOUND", codes)
        self.assertIn("MGMT_VRF_NO_ACCESS_SERVICE", codes)

    def test_problems_binding_no_address_and_next_hop_unreachable(self):
        iface = {"id": "i1", "name": "Ethernet5", "kind": "ROUTED_PHYSICAL", "addresses": {}}
        management = {"vrfs": {"a": {"id": "a", "name": "MGMT"}}, "bindings": {"b": {"id": "b", "vrf_id": "a", "interface_id": "i1"}},
                      "routes": {"r": {"id": "r", "vrf_id": "a", "family": "IPV4", "destination": "0.0.0.0/0", "next_hop": "10.1.1.1"}},
                      "services": {"s": {"id": "s", "vrf_id": "a", "service": "SSH", "host": "", "source_interface_id": ""}}}
        codes = {p["code"] for p in vrf.problems("arista_ceos", management, [iface])}
        self.assertIn("MGMT_BINDING_NO_ADDRESS", codes)
        self.assertIn("MGMT_ROUTE_NEXT_HOP_UNREACHABLE", codes)

    def test_problems_clean_intent_empty(self):
        iface = {"id": "i1", "name": "Ethernet5", "kind": "ROUTED_PHYSICAL", "addresses": {"x": {"id": "x", "cidr": "10.1.1.2/30"}}}
        management = {"vrfs": {"a": {"id": "a", "name": "MGMT"}}, "bindings": {"b": {"id": "b", "vrf_id": "a", "interface_id": "i1"}},
                      "routes": {"r": {"id": "r", "vrf_id": "a", "family": "IPV4", "destination": "0.0.0.0/0", "next_hop": "10.1.1.1"}},
                      "services": {"s": {"id": "s", "vrf_id": "a", "service": "SSH", "host": "", "source_interface_id": ""}}}
        self.assertEqual(vrf.problems("arista_ceos", management, [iface]), [])


class ValidationAndPlanTests(TestCase):
    def test_validate_management_vrf_eos_passes_and_graph_has_nodes(self):
        dev, _objs = _candidate()
        run = validate(dev.change, make_sources())
        codes = [f["code"] for f in run.report["findings"] if f["code"].startswith("MGMT_")]
        self.assertEqual(codes, [])
        types = {n["type"] for n in run.dependency_graph["nodes"] if n["device"] == "R1"}
        self.assertTrue({"mgmt_vrf", "mgmt_vrf_binding", "mgmt_vrf_route", "mgmt_vrf_service"} <= types)

    def test_validate_unbound_vrf_blocks(self):
        dev, _objs = _candidate(bind=False)
        run = validate(dev.change, make_sources())
        self.assertIn("MGMT_VRF_UNBOUND", [f["code"] for f in run.report["findings"]])
        self.assertEqual(run.status, models.ValidationRunStatus.BLOCKED)

    def test_validate_netconf_on_eos_unsupported_blocks(self):
        dev, _objs = _candidate(services=("SSH", "NETCONF"))
        run = validate(dev.change, make_sources())
        self.assertIn("MGMT_VRF_FEATURE_UNSUPPORTED", [f["code"] for f in run.report["findings"]])

    def test_validate_non_eos_execution_warning(self):
        dev, _objs = _candidate(platform=P.UBUNTU_FRR)
        run = validate(dev.change, make_sources())
        self.assertIn("MGMT_VRF_EXECUTION_NOT_IMPLEMENTED", [f["code"] for f in run.report["findings"]])

    def test_plan_management_configlets_ordered_and_binding_reapplies_address(self):
        dev, _objs = _candidate()
        run = validate(dev.change, make_sources())
        self.assertIn(run.status, (models.ValidationRunStatus.PASS, models.ValidationRunStatus.PASS_WITH_WARNINGS), run.report["findings"])
        plan, _created = cps.build_change_plan(dev.change, actor="tester")
        doc = cps.serialize_plan(plan)
        rows = [c for c in doc["configlets"] if c["source"]["object_type"].startswith("mgmt_")]
        order = [c["source"]["object_type"] for c in rows]
        self.assertEqual(order, ["mgmt_vrf", "mgmt_vrf_binding", "mgmt_vrf_route", "mgmt_vrf_service"])
        route = next(c for c in plan.configlets.all() if (c.desired_state_ref or {}).get("source", {}).get("object_type") == "mgmt_vrf_route")
        self.assertEqual(route.verification_spec["requirements"][0]["requirement"], "MGMT_VRF_ROUTE_PRESENT")
        binding = next(c for c in rows if c["source"]["object_type"] == "mgmt_vrf_binding")
        lines = binding["rendered_config"].splitlines()
        self.assertEqual(lines[0], "interface Ethernet5")
        self.assertIn("   vrf MGMT", lines)
        self.assertIn("   ip address 10.99.0.1/30", lines)
        self.assertLess(lines.index("   vrf MGMT"), lines.index("   ip address 10.99.0.1/30"))


RUNNING = """hostname R1
!
vrf instance OTHER
!
interface Ethernet5
   no switchport
   ip address 10.99.0.1/30
!
management ssh
   idle-timeout 0
!
end
"""


class ExecutorInverseTests(TestCase):
    def test_structural_commands_returns_exit_after_nested_sections(self):
        self.assertEqual(ceos.structural_commands(["management ssh", "   vrf MGMT", "      no shutdown"]),
                         ["management ssh", "vrf MGMT", "no shutdown", "exit", "exit"])
        self.assertEqual(ceos.structural_commands(["configure", "ip routing vrf MGMT", "end"]), ["ip routing vrf MGMT"])

    def test_management_inverse_new_definition(self):
        self.assertEqual(ceos.management_inverse(["vrf instance MGMT", "ip routing vrf MGMT"], RUNNING),
                         ["no ip routing vrf MGMT", "no vrf instance MGMT"])

    def test_management_inverse_nested_child_under_existing_header(self):
        self.assertEqual(ceos.management_inverse(["management ssh", "   vrf MGMT", "      no shutdown"], RUNNING),
                         ["management ssh", "   no vrf MGMT"])

    def test_management_inverse_already_present_empty(self):
        self.assertEqual(ceos.management_inverse(["vrf instance OTHER"], RUNNING), [])

    def test_management_inverse_not_provable_none(self):
        self.assertIsNone(ceos.management_inverse(["no vrf instance OTHER"], RUNNING))
        running = RUNNING.replace("vrf instance OTHER\n", "vrf instance OTHER\n   description old\n")
        self.assertIsNone(ceos.management_inverse(["vrf instance OTHER", "   description new"], running))
        logging = RUNNING + "logging vrf MGMT source-interface Ethernet1\n"
        self.assertIsNone(ceos.management_inverse(["logging vrf MGMT source-interface Ethernet5"], logging))

    def test_binding_snapshot_inverse_restores_addresses(self):
        inverse = ceos.interface_snapshot_inverse(["interface Ethernet5", "   vrf MGMT", "   ip address 10.99.0.1/30"], RUNNING)
        self.assertEqual(inverse[0], "interface Ethernet5")
        self.assertIn("   ip address 10.99.0.1/30", inverse)
        self.assertTrue(any(line.strip() in ("no vrf MGMT", "default vrf MGMT") for line in inverse))


class CapabilityTests(TestCase):
    def test_capability_for_management_not_implemented_without_live_evidence(self):
        with mock.patch.dict(capability_evidence.LIVE, {}, clear=True):
            for object_type in capability.MANAGEMENT_TYPES:
                cap = capability.capability_for("arista_ceos", object_type, "SSH")
                self.assertEqual(cap.apply, "NOT_IMPLEMENTED", object_type)
                self.assertFalse(capability.management_gate("arista_ceos", object_type, "SSH"))
                self.assertEqual(capability.capability_for("nokia_srlinux", object_type).apply, "NOT_IMPLEMENTED")

    def test_capability_for_management_supported_only_with_recorded_evidence(self):
        with mock.patch.dict(capability_evidence.LIVE, {"arista_ceos:execute:mgmt_vrf": "docs/evidence/test"}, clear=True):
            self.assertTrue(capability.management_gate("arista_ceos", "mgmt_vrf"))
            self.assertEqual(capability.capability_for("arista_ceos", "mgmt_vrf").apply, "SUPPORTED")

    def test_management_gate_for_services_without_the_named_live_service_is_refused(self):
        # the recorded cEOS evidence covers SSH / eAPI / gNMI in the VRF; SYSLOG / NTP / SNMP were not exercised live
        for service in ("SSH", "EAPI", "GNMI"):
            self.assertEqual(capability.capability_for("arista_ceos", "mgmt_vrf_service", service).apply, "SUPPORTED", service)
        for service in ("SYSLOG", "NTP", "SNMP", ""):
            self.assertFalse(capability.management_gate("arista_ceos", "mgmt_vrf_service", service), service)
            self.assertEqual(capability.capability_for("arista_ceos", "mgmt_vrf_service", service).apply, "NOT_IMPLEMENTED", service)
        self.assertEqual(capability.capability_for("nokia_srlinux", "mgmt_vrf_service", "SSH").apply, "NOT_IMPLEMENTED")

    def test_recorded_live_evidence_names_committed_passing_files(self):
        root = Path(__file__).resolve().parents[3]
        self.assertTrue(capability_evidence.LIVE)
        for key, relative in capability_evidence.LIVE.items():
            with self.subTest(key):
                self.assertTrue(key.startswith("arista_ceos:"), key)          # only cEOS has live evidence
                document = json.loads((root / relative).read_text())
                text = json.dumps(document)
                self.assertNotIn("PRIVATE KEY", text)
                if relative.endswith("vrf-execution.json"):
                    self.assertEqual(document["before_digest"], document["after_compensation_digest"])
                    self.assertEqual({row["status"] for row in document["compensation"]}, {"COMPENSATED"})
                elif relative.endswith("failover.json"):
                    self.assertEqual(document["result"], "PASS")
                else:
                    self.assertEqual(document["status"]["state"], "COMPLETE")

    def test_capability_matrix_honest_classification(self):
        with mock.patch.dict(capability_evidence.LIVE, {}, clear=True):
            matrix = vrf.capability_matrix()
        self.assertEqual(matrix["juniper_junos"]["VRF_DEFINE"]["render"], "OUT_OF_SCOPE")
        for platform, rows in matrix.items():
            for feature, row in rows.items():
                self.assertEqual(row["live_verified"], "NOT_VERIFIED", (platform, feature))  # no live evidence recorded
                self.assertNotEqual(row["execute"], "SUPPORTED", (platform, feature))       # gated on live evidence
        live = vrf.capability_matrix()["arista_ceos"]
        self.assertEqual({f for f, row in live.items() if row["execute"] == "SUPPORTED"},
                         {"VRF_DEFINE", "INTERFACE_BINDING", "STATIC_ROUTE", "SSH", "EAPI", "GNMI"})
        self.assertEqual([live[f]["live_verified"] for f in ("SYSLOG", "NTP", "SNMP")], ["NOT_VERIFIED"] * 3)
        self.assertEqual(matrix["arista_ceos"]["NETCONF"]["render"], "UNSUPPORTED")
        self.assertEqual(matrix["sonic"]["INTERFACE_BINDING"]["render"], "UNSUPPORTED")


IMPORT_CONFIG = """hostname R1
!
vrf instance MGMT
   description oob
!
vrf instance DATA
!
ip routing
ip routing vrf MGMT
ip routing vrf DATA
!
interface Ethernet5
   no switchport
   vrf MGMT
   ip address 10.99.0.1/30
!
interface Ethernet6
   no switchport
   vrf DATA
   ip address 10.98.0.1/30
!
ip route vrf MGMT 0.0.0.0/0 10.99.0.2
ip route vrf DATA 0.0.0.0/0 10.98.0.2
!
management ssh
   idle-timeout 30
   vrf MGMT
      no shutdown
!
end
"""


class ImportTests(TestCase):
    def test_parse_ceos_management_vrf_lifted_data_vrf_untouched(self):
        from core.services.config_import import parser_ceos

        parsed = parser_ceos.parse(IMPORT_CONFIG)
        self.assertEqual([v["name"] for v in parsed.management["vrfs"]], ["MGMT"])
        self.assertEqual(parsed.management["bindings"][0]["interface"], "Ethernet5")
        self.assertEqual(parsed.management["routes"][0]["destination"], "0.0.0.0/0")
        self.assertEqual([s["service"] for s in parsed.management["services"]], ["SSH"])
        unmanaged = "\n".join(line for block in parsed.unmanaged_blocks for line in block.lines)
        self.assertIn("vrf instance DATA", unmanaged)
        self.assertIn("ip route vrf DATA 0.0.0.0/0 10.98.0.2", unmanaged)
        self.assertIn("idle-timeout 30", unmanaged)               # the rest of the block is preserved
        self.assertNotIn("vrf instance MGMT", unmanaged)
        self.assertNotIn("ip route vrf MGMT", unmanaged)
        data_port = next(i for i in parsed.interfaces if i.name == "Ethernet6")
        self.assertIn("   vrf DATA", data_port.preserved_lines)

    def test_parse_ceos_no_management_service_no_management_records(self):
        from core.services.config_import import parser_ceos

        text = IMPORT_CONFIG.replace("management ssh\n   idle-timeout 30\n   vrf MGMT\n      no shutdown\n", "")
        parsed = parser_ceos.parse(text)
        self.assertEqual(parsed.management, {})
        self.assertIn("vrf instance MGMT", "\n".join(line for block in parsed.unmanaged_blocks for line in block.lines))

    def test_parse_ceos_vrf_without_ip_routing_not_lifted(self):
        from core.services.config_import import parser_ceos

        parsed = parser_ceos.parse(IMPORT_CONFIG.replace("ip routing vrf MGMT\n", ""))
        self.assertEqual(parsed.management, {})

    def test_import_apply_management_vrf_and_reimport_replaces(self):
        from core.services.config_import import parser_ceos, service

        change = new_change()
        dev = Dev(change, "R1")
        for _round in range(2):
            revision = dev.refresh()
            service._remove_prior_import_objects(revision)
            parsed = parser_ceos.parse(IMPORT_CONFIG)
            _count, counts, owned = service.apply_parsed_config(change=change, intent=dev.intent, revision=revision, parsed=parsed)
            sections = dict(revision.sections)
            sections["_import"] = {"managed_object_ids": owned}
            revision.sections = sections
            revision.save(update_fields=["sections"])
        management = vrf.section(dev.refresh())
        self.assertEqual(len(management["vrfs"]), 1)
        self.assertEqual(len(management["bindings"]), 1)
        self.assertEqual(counts["mgmt_services"], 1)
        text = "\n".join(_render_via_driver(dev))
        self.assertIn("ip route vrf MGMT 0.0.0.0/0 10.99.0.2", text)
        self.assertIn("management ssh\n   vrf MGMT\n      no shutdown", text)

    def test_import_apply_without_management_counts_unchanged(self):
        from core.services.config_import import parser_ceos, service

        change = new_change()
        dev = Dev(change, "R1")
        parsed = parser_ceos.parse("hostname R1\ninterface Ethernet1\n   no switchport\n   ip address 192.0.2.1/31\nend\n")
        _count, counts, owned = service.apply_parsed_config(change=change, intent=dev.intent, revision=dev.refresh(), parsed=parsed)
        self.assertFalse(any(key.startswith("mgmt_") for key in (*counts, *owned)))
        self.assertNotIn("management", dev.refresh().sections)


class _EosConfig:
    """A minimal in-memory EOS running configuration driven by a Netmiko-shaped session: indentation-nested blocks, mode
    entry for block headers, ``exit``, ``no <line>`` / ``default <line>`` removal at the current level."""

    HEADERS = ("interface ", "vrf instance ", "management ", "vrf ", "transport grpc ")

    def __init__(self, text: str):
        self.root = self._parse(text)
        self.sent = []

    @staticmethod
    def _parse(text):
        root, stack = [], [(-1, None)]
        for raw in text.splitlines():
            if not raw.strip() or raw.strip() in ("!", "end"):
                continue
            indent = len(raw) - len(raw.lstrip())
            node = [raw.strip(), []]
            while stack[-1][0] >= indent:
                stack.pop()
            (stack[-1][1][1] if stack[-1][1] else root).append(node)
            stack.append((indent, node))
        return root

    def text(self):
        def render(nodes, depth):
            for line, children in nodes:
                yield "   " * depth + line
                yield from render(children, depth + 1)
                if depth == 0:
                    yield "!"
        return "\n".join(render(self.root, 0)) + "\nend\n"

    # -- the Netmiko surface the executor uses ---------------------------------------------------------------------------
    def send_command(self, command, **kwargs):
        assert command == "show running-config", command
        return self.text()

    def config_mode(self, **kwargs):
        pass

    def check_config_mode(self):
        return False

    def exit_config_mode(self):
        pass

    def disconnect(self):
        pass

    def send_config_set(self, commands, **kwargs):
        self.sent.append(list(commands))
        stack = [("", self.root)]                       # (mode header, children)
        for command in commands:
            mode, level = stack[-1]
            if command == "exit":
                stack.pop()
                continue
            if command.startswith(("no ", "default ")):
                target = command.split(" ", 1)[1]
                level[:] = [n for n in level if n[0] != target and not n[0].startswith(target + " ")]
                continue
            node = next((n for n in level if n[0] == command), None)
            if node is None:
                node = [command, []]
                level.append(node)
            if command.startswith(self.HEADERS) and not mode.startswith("interface "):   # "vrf X" under an interface is a leaf
                stack.append((command, node[1]))
        return ""


class MultiConfigletCompensationTests(TestCase):
    """The engine assesses EVERY Configlet before applying any; a management plan with several Configlets on one device is
    then compensated in reverse order while the earlier ones are still applied (the defect the isolated live run found)."""

    def test_compensation_of_a_whole_management_plan_returns_the_exact_prior_state(self):
        dev, _objs = _candidate(services=("SSH", "EAPI", "GNMI"))
        run = validate(dev.change, make_sources())
        self.assertIn(run.status, (models.ValidationRunStatus.PASS, models.ValidationRunStatus.PASS_WITH_WARNINGS))
        plan, _created = cps.build_change_plan(dev.change, actor="tester")
        from core.services.execution.executors.base import ConfigletSpec
        from core.tests.helpers import health as h

        specs = [ConfigletSpec.from_configlet(c) for c in plan.configlets.order_by("sequence")
                 if (c.desired_state_ref or {}).get("source", {}).get("object_type", "").startswith("mgmt_")]
        device = _EosConfig(RUNNING)
        before = device.text()
        executor = ceos.CeosExecutor({"name": "R1", "platform": "ceos"}, connection_factory=lambda d: device,
                                     reader=lambda d: h.device_evidence("R1", interfaces={}, addresses={}, routes=[], live_ok=True))
        executor.connect()
        assessments = [executor.assess(spec) for spec in specs]
        self.assertEqual({(a.action, a.restorable) for a in assessments}, {("APPLY", True)})
        for spec, assessment in zip(specs, assessments):
            self.assertTrue(executor.apply(spec, assessment).ok, spec.object_type)
        self.assertIn("vrf instance MGMT", device.text())
        for spec, assessment in reversed(list(zip(specs, assessments))):
            outcome = executor.compensate(spec, assessment)
            self.assertEqual(outcome.status, "COMPENSATED", (spec.object_type, outcome.error_code))
        self.assertEqual(device.text(), before)


class ManagementVrfHealthTests(SimpleTestCase):
    CONFIG = """vrf instance MGMT
!
interface Ethernet5
   no switchport
   vrf MGMT
   ip address 10.99.0.1/30
!
ip route vrf MGMT 0.0.0.0/0 10.99.0.2
!
management ssh
   vrf MGMT
      no shutdown
!
"""

    @staticmethod
    def requirement(kind, expected):
        return health_requirements.Requirement(cfg_id="CFG-MGMT", device="R1", kind=kind, expected=expected,
                                               check_types=health_requirements.expand(kind, expected))

    @staticmethod
    def evaluate(requirement, phase, text=None):
        groups = {} if text is None else {"config_paths": health_live.config_path_signatures(text),
                                         "management_services": health_live.parse_management_config(text).services}
        evidence = health_fixture.evidence_set(health_fixture.device_evidence("R1", **groups))
        return health_evaluators.evaluate_requirements([requirement], phase, evidence)

    def test_live_running_config_proves_each_management_vrf_requirement(self):
        rows = (
            ("MGMT_VRF_PRESENT", {"vrf": "MGMT"}),
            ("MGMT_VRF_BOUND", {"vrf": "MGMT", "interface": "Ethernet5", "addresses": ["10.99.0.1/30"]}),
            ("MGMT_VRF_ROUTE_PRESENT", {"vrf": "MGMT", "prefix": "0.0.0.0/0", "next_hop": "10.99.0.2", "family": "IPV4"}),
            ("MGMT_SERVICE_IN_VRF", {"vrf": "MGMT", "service": "SSH", "host": ""}),
        )
        for kind, expected in rows:
            with self.subTest(kind=kind):
                requirement = self.requirement(kind, expected)
                post = self.evaluate(requirement, Phase.POSTCHECK, self.CONFIG)
                self.assertEqual([(r.status, r.check_code) for r in post.results], [(CheckStatus.PASS, "MGMT_CONFIG_PRESENT")])
                self.assertEqual(post.result, "PASS")
                pre = self.evaluate(requirement, Phase.PRECHECK, "")
                self.assertEqual(pre.results[0].status, CheckStatus.NOT_APPLICABLE)

    def test_missing_or_unavailable_management_config_never_passes(self):
        requirement = self.requirement("MGMT_VRF_ROUTE_PRESENT", {"vrf": "MGMT", "prefix": "0.0.0.0/0",
                                                                     "next_hop": "10.99.0.2", "family": "IPV4"})
        wrong_vrf = "ip route 0.0.0.0/0 10.99.0.2\n"
        failed = self.evaluate(requirement, Phase.POSTCHECK, wrong_vrf)
        self.assertEqual([(r.status, r.check_code) for r in failed.results], [(CheckStatus.FAIL, "MGMT_CONFIG_MISSING")])
        unknown = self.evaluate(requirement, Phase.POSTCHECK)
        self.assertEqual([(r.status, r.check_code) for r in unknown.results], [(CheckStatus.UNKNOWN, "POSTCHECK_DATA_UNAVAILABLE")])

    def test_ipv6_management_route_is_verified_in_its_vrf(self):
        requirement = self.requirement("MGMT_VRF_ROUTE_PRESENT", {"vrf": "MGMT", "prefix": "2001:db8:99::/64",
                                                                     "next_hop": "2001:db8:1::2", "family": 6})
        config = "ipv6 route vrf MGMT 2001:db8:99::/64 2001:db8:1::2\n"
        self.assertEqual(self.evaluate(requirement, Phase.POSTCHECK, config).results[0].status, CheckStatus.PASS)

    def test_unverified_service_does_not_claim_health_pass(self):
        requirement = self.requirement("MGMT_SERVICE_IN_VRF", {"vrf": "MGMT", "service": "NETCONF", "host": ""})
        outcome = self.evaluate(requirement, Phase.POSTCHECK, self.CONFIG)
        self.assertEqual([(r.status, r.check_code) for r in outcome.results], [(CheckStatus.UNKNOWN, "REQUIREMENT_NOT_IMPLEMENTED")])

    def test_gnmi_shutdown_cannot_satisfy_management_service(self):
        requirement = self.requirement("MGMT_SERVICE_IN_VRF", {"vrf": "MGMT", "service": "GNMI", "host": ""})
        enabled = "management api gnmi\n   transport grpc MGMT\n      vrf MGMT\n"
        disabled = enabled + "      shutdown\n"
        self.assertEqual(self.evaluate(requirement, Phase.POSTCHECK, enabled).results[0].status, CheckStatus.PASS)
        self.assertEqual(self.evaluate(requirement, Phase.POSTCHECK, disabled).results[0].status, CheckStatus.FAIL)

    def test_service_health_evaluation_never_opens_a_session_or_executes_a_change(self):
        requirement = self.requirement("MGMT_SERVICE_IN_VRF", {"vrf": "MGMT", "service": "SSH", "host": ""})
        with mock.patch.object(health_live, "default_session_factory") as sessions, \
                mock.patch("core.services.execution.engine.execute_change") as execution:
            enabled = self.evaluate(requirement, Phase.POSTCHECK, self.CONFIG)
            disabled = self.evaluate(requirement, Phase.POSTCHECK, self.CONFIG.replace("no shutdown", "shutdown"))
            self.assertEqual(enabled.results[0].status, CheckStatus.PASS)
            self.assertEqual(disabled.results[0].status, CheckStatus.FAIL)
            sessions.assert_not_called()
            execution.assert_not_called()
            self.assertNotIn("no shutdown", str(enabled.results[0]))
