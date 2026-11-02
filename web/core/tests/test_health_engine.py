"""Health engine logic that needs no database and no I/O: vocabulary, thresholds, freshness, aggregation, blocking
policy, the requirement mapping, evaluator semantics (PRECHECK vs POSTCHECK) and evidence precedence.

Table-driven: every case has a label so a failure names the row.  HTTP behavior is in ``test_health_views``; source
adapters (fleet / deep / live) in ``test_health_sources``; plan-level precheck / postcheck in ``test_change_precheck``;
import / read-only contracts in ``test_contracts``.
"""

from __future__ import annotations

import re
from pathlib import Path

from django.conf import settings
from django.test import SimpleTestCase

from core.services import health_service as hs
from core.services.planning import priorities
from core.services.health import codes, evaluators, requirements as reqs, results, thresholds
from core.services.health.codes import CheckStatus as S, Freshness, Phase, Role
from core.services.health.evidence import merge_precedence
from core.tests.helpers.health import device_evidence, evidence_set


def R(code, status, *, role=Role.TARGET, device="R1"):
    return results.CheckResult(code, status, device, "m", "LIVE", role=role)


def req(kind, expected, *, device="R1", cfg="CFG-001"):
    return reqs.Requirement(cfg_id=cfg, device=device, kind=kind, label=f"{device} {kind}", object_type="t", object_id="o",
                            expected=expected, check_types=reqs.expand(kind, expected))


class ThresholdAndFreshnessTests(SimpleTestCase):
    def test_thresholds_reuse_the_existing_monitoring_definitions(self):
        found = thresholds.load_thresholds()
        root = Path(settings.REPO_ROOT)
        cpu = re.findall(r"^(warning_pct|critical_pct):\s*(\d+)", (root / "monitoring/config/cpu_threshold_policy.yml").read_text(), re.M)
        topo = dict(re.findall(r"^(healthy_seconds|stale_seconds):\s*(\d+)", (root / "monitoring/config/topology.yml").read_text(), re.M))
        self.assertEqual({k: found["cpu"][k.split("_")[0]] for k, _ in cpu}, {k: float(v) for k, v in cpu})
        self.assertEqual((found["freshness"]["healthy"], found["freshness"]["stale"]), (float(topo["healthy_seconds"]), float(topo["stale_seconds"])))
        # memory mirrors the Grafana "Memory utilization" panel thresholds: one threshold system, drift fails here
        grafana = (root / "monitoring/scripts/build_grafana_dashboards.py").read_text()
        panel = re.search(r'"Memory utilization".*?threshold_steps=\(\("green", None\), \("orange", (\d+)\), \("red", (\d+)\)\)', grafana, re.S)
        self.assertEqual((found["memory"]["warning"], found["memory"]["critical"]), (float(panel.group(1)), float(panel.group(2))))
        # the running topology service's own values win when it reports them
        self.assertEqual(thresholds.load_thresholds({"healthy_max": 10, "stale_max": 20})["freshness"], {"healthy": 10.0, "stale": 20.0})

    def test_freshness_boundaries(self):
        freshness = {"healthy": 60.0, "stale": 120.0}
        rows = [(0, Freshness.FRESH), (60, Freshness.FRESH), (60.01, Freshness.STALE), (120, Freshness.STALE),
                (120.01, Freshness.EXPIRED), (10_000, Freshness.EXPIRED), (None, Freshness.UNKNOWN), (-5, Freshness.FRESH)]
        for age, expected in rows:
            with self.subTest(age=age):
                self.assertEqual(thresholds.classify_age(age, freshness), expected)

    def test_metric_levels_and_missing_metric_is_never_zero(self):
        band = {"warning": 70.0, "critical": 90.0}
        rows = [(0, "NORMAL"), (69.9, "NORMAL"), (70, "WARNING"), (89.9, "WARNING"), (90, "CRITICAL"), (100, "CRITICAL"), (None, None)]
        for value, level in rows:
            with self.subTest(value=value):
                self.assertEqual(thresholds.classify_level(value, band), level)


class VocabularyAndAggregationTests(SimpleTestCase):
    def test_result_carries_structured_evidence_bounded_and_redacted(self):
        result = results.CheckResult("ROUTE_MISSING", S.FAIL, "R1", "x" * 1000, "LIVE", observed={"password": "hunter2", "routes": list(range(100))},
                                     expected={"prefix": "10.0.0.0/8"}, observed_at="2026-09-21T12:00:00Z", freshness=Freshness.FRESH,
                                     role=Role.TARGET, phase=Phase.POSTCHECK, requirement="STATIC_ROUTE_PRESENT", cfg_id="CFG-002")
        row = result.to_dict()
        for key in ("check_code", "status", "category", "device", "message", "source", "observed", "expected", "timestamp", "freshness", "blocking", "remediation"):
            self.assertIn(key, row)
        self.assertEqual((row["category"], row["blocking"], row["remediation"]), ("ROUTING", True, codes.CODES["ROUTE_MISSING"].remediation))
        self.assertLessEqual(len(row["message"]), results.MAX_STRING)
        self.assertNotIn("password", row["observed"], "a secret-shaped KEY is replaced, not merely its value")
        self.assertEqual(row["observed"]["redacted_field_1"], "[REDACTED]")
        self.assertNotIn("hunter2", str(row))
        self.assertLessEqual(len(row["observed"]["routes"]), results.MAX_LIST)
        with self.assertRaises(ValueError):
            results.CheckResult("NOT_A_CODE", S.PASS, "R1", "m", "LIVE")
        with self.assertRaises(ValueError):
            results.CheckResult("ROUTE_MISSING", "MAYBE", "R1", "m", "LIVE")

    def test_health_aggregation_matrix(self):
        core_pass, core_unknown = ("DEVICE_TELEMETRY_FRESH", S.PASS), ("DEVICE_TELEMETRY_UNAVAILABLE", S.UNKNOWN)
        rows = [
            ("all pass", [core_pass, ("CPU_HIGH", S.PASS)], codes.Health.HEALTHY),
            ("a warning degrades", [core_pass, ("CPU_HIGH", S.WARN)], codes.Health.DEGRADED),
            ("a failure wins over a warning", [core_pass, ("CPU_HIGH", S.WARN), ("MEMORY_HIGH", S.FAIL)], codes.Health.UNHEALTHY),
            ("non-core unknown does not downgrade", [core_pass, ("MEMORY_HIGH", S.UNKNOWN)], codes.Health.HEALTHY),
            ("core unknown with nothing else is unknown", [core_unknown, ("CPU_HIGH", S.UNKNOWN)], codes.Health.UNKNOWN),
            ("unknown never becomes failure", [core_unknown], codes.Health.UNKNOWN),
            ("a failure still wins over unknown", [core_unknown, ("CPU_HIGH", S.FAIL)], codes.Health.UNHEALTHY),
            ("only not-applicable", [("ADDRESS_EXPECTED_PRESENT", S.NOT_APPLICABLE)], codes.Health.UNKNOWN),
            ("nothing at all", [], codes.Health.UNKNOWN),
        ]
        for label, pairs, expected in rows:
            with self.subTest(case=label):
                self.assertEqual(results.aggregate_health([R(c, s) for c, s in pairs]), expected)

    def test_blocking_policy_matrix(self):
        # (code, status, role) -> blocks?   FAIL blocks only a blocking code; UNKNOWN only an unknown-blocking code;
        # WARN / PEER / FLEET never block.
        rows = [
            ("DEVICE_UNREACHABLE", S.FAIL, Role.TARGET, True), ("DEVICE_UNREACHABLE", S.UNKNOWN, Role.TARGET, True),
            ("DEVICE_UNREACHABLE", S.FAIL, Role.PEER, False), ("DEVICE_UNREACHABLE", S.UNKNOWN, Role.FLEET, False),
            ("DEVICE_TELEMETRY_STALE", S.FAIL, Role.TARGET, True), ("DEVICE_TELEMETRY_STALE", S.WARN, Role.TARGET, False),
            ("DEVICE_TELEMETRY_UNAVAILABLE", S.UNKNOWN, Role.TARGET, True),
            ("CPU_HIGH", S.FAIL, Role.TARGET, True), ("CPU_HIGH", S.WARN, Role.TARGET, False), ("CPU_HIGH", S.UNKNOWN, Role.TARGET, False),
            ("LINK_HEALTH_DEGRADED", S.FAIL, Role.TARGET, False),
            ("PLAN_STALE", S.FAIL, Role.PLAN, True), ("PLAN_MISSING", S.UNKNOWN, Role.PLAN, True),
            ("ADDRESS_MISSING", S.PASS, Role.TARGET, False), ("ADDRESS_MISSING", S.NOT_APPLICABLE, Role.TARGET, False),
            ("REQUIREMENT_NOT_IMPLEMENTED", S.UNKNOWN, Role.TARGET, False),
        ]
        for code, status, role, blocks in rows:
            with self.subTest(code=code, status=status, role=role):
                self.assertEqual(results.effective_blocking(code, status, role), blocks)

    def test_precheck_and_postcheck_result_matrix(self):
        pre = [
            ("no problem", [("CPU_HIGH", S.PASS)], "PASS"),
            ("a warning", [("CPU_HIGH", S.WARN)], "PASS_WITH_WARNINGS"),
            ("blocking failure", [("DEVICE_UNREACHABLE", S.FAIL)], "BLOCKED"),
            ("blocking unknown", [("DEVICE_UNREACHABLE", S.UNKNOWN)], "INCOMPLETE"),
            ("blocked beats incomplete", [("DEVICE_UNREACHABLE", S.UNKNOWN), ("CPU_HIGH", S.FAIL)], "BLOCKED"),
            ("non-blocking failure only warns", [("LINK_HEALTH_DEGRADED", S.FAIL)], "PASS_WITH_WARNINGS"),
            ("not applicable is ignored", [("ADDRESS_MISSING", S.NOT_APPLICABLE)], "PASS"),
        ]
        for label, pairs, expected in pre:
            with self.subTest(precheck=label):
                self.assertEqual(results.precheck_result([R(c, s) for c, s in pairs]), expected)
        post = [
            ("all verified", [("ADDRESS_EXPECTED_PRESENT", S.PASS)], "PASS"),
            ("a warning", [("ADDRESS_EXPECTED_PRESENT", S.PASS), ("INTERFACE_OPER_DOWN", S.WARN)], "PASS_WITH_WARNINGS"),
            ("a deviation fails", [("ADDRESS_EXPECTED_PRESENT", S.PASS), ("ROUTE_MISSING", S.FAIL)], "FAIL"),
            ("missing evidence is incomplete, never pass", [("ADDRESS_EXPECTED_PRESENT", S.PASS), ("POSTCHECK_DATA_UNAVAILABLE", S.UNKNOWN)], "INCOMPLETE"),
            ("failure wins over incomplete", [("POSTCHECK_DATA_UNAVAILABLE", S.UNKNOWN), ("ROUTE_MISSING", S.FAIL)], "FAIL"),
            ("nothing verified is incomplete", [("ADDRESS_MISSING", S.NOT_APPLICABLE)], "INCOMPLETE"),
            ("nothing at all is incomplete", [], "INCOMPLETE"),
        ]
        for label, pairs, expected in post:
            with self.subTest(postcheck=label):
                self.assertEqual(results.postcheck_result([R(c, s) for c, s in pairs]), expected)


class RequirementMappingTests(SimpleTestCase):
    def test_every_phase14_requirement_kind_is_mapped_or_declared_not_implemented(self):
        planned = {cls.requirement for cls in priorities.CATALOGUE.values()}
        handled = set(reqs.REQUIREMENT_MAP) | reqs.KNOWN_NOT_IMPLEMENTED
        self.assertEqual(planned - handled, set(), "a plannable requirement kind has neither an evaluator nor an honest NOT_IMPLEMENTED")
        for kind, rows in reqs.REQUIREMENT_MAP.items():
            for _, check in rows:
                with self.subTest(kind=kind, check=check):
                    self.assertIn(check, evaluators.EVALUATORS)
                    self.assertIn(check, reqs.CHECK_TYPES)
        self.assertEqual(set(evaluators.EVALUATORS), set(reqs.CHECK_TYPES))

    def test_expansion_table(self):
        rows = [
            ("INTERFACE_PRESENT", {}, ("INTERFACE_PRESENT", "INTERFACE_ADMIN_STATE", "INTERFACE_OPER_STATE")),
            ("ROUTE_INTENDED", {}, ("STATIC_ROUTE_PRESENT",)),
            ("ROUTING_INTERFACE_ENABLED", {"protocol": "ospf"}, ("OSPF_NEIGHBOR_EXPECTED", "ROUTING_BINDING_CONFIG")),
            ("ROUTING_INTERFACE_ENABLED", {"protocol": "rip"}, ("ROUTING_BINDING_CONFIG",)),
            ("BGP_AF_ACTIVATION_INTENDED", {}, ("BGP_NEIGHBOR_EXPECTED", "BGP_NEIGHBOR_CONFIG")),
            ("NAT_POOL_INTENDED", {}, (reqs.NOT_IMPLEMENTED,)),
            ("PBR_ATTACHMENT_INTENDED", {}, (reqs.NOT_IMPLEMENTED,)),
            ("SOMETHING_NEW", {}, (reqs.UNKNOWN_TYPE,)),
        ]
        for kind, expected, check_types in rows:
            with self.subTest(kind=kind, expected=expected):
                self.assertEqual(reqs.expand(kind, expected), check_types)


# The world for the evaluator matrices: R1 with Ethernet1 up + addressed + routed, and every service present.
def world(**overrides):
    groups = dict(
        interfaces={"Ethernet1": {"admin": "UP", "oper": "UP"}}, addresses={"Ethernet1": ["192.0.2.0/31"]},
        virtual_addresses={"Vlan10": ["192.168.10.1"]},
        routes=[{"prefix": "10.9.0.0/24", "type": "static", "next_hops": ["192.0.2.1"], "interfaces": ["Ethernet1"]}],
        ospf=[{"family": "OSPFV2", "neighbor_id": "10.0.0.2", "interface": "Ethernet1", "state": "FULL"}],
        bgp=[{"peer": "192.0.2.1", "remote_as": "65002", "state": "ESTABLISHED", "family": 4}],
        config={"acl_definitions": ["EDGE-IN"], "acl_attachments": [{"interface": "Vlan10", "acl": "EDGE-IN", "direction": "IN"}],
                "dhcp_relays": [{"interface": "Vlan10", "destination": "192.168.200.100"}]},
        routing_config=[
            {"protocol": "ospf", "version": "OSPFV2", "process_id": 44, "local_asn": None,
             "router_id": "10.0.0.1", "enabled": True, "networks": [],
             "bindings": [{"interface_name": "Ethernet1", "area": "0", "passive": False}],
             "neighbors": [], "redistributions": []},
            {"protocol": "bgp", "version": "", "process_id": None, "local_asn": 65001,
             "router_id": "10.0.0.1", "enabled": True, "networks": [], "bindings": [],
             "neighbors": [{"peer_address": "192.0.2.1", "remote_asn": 65002,
                            "activate_ipv4": True, "activate_ipv6": False}], "redistributions": []},
        ],
        nat={"tables": ["T"], "rules": [{"table": "T", "oif": "eth2", "action": "masquerade"}]},
    )
    groups.update(overrides)
    return evidence_set(device_evidence("R1", **groups))


class EvaluatorTests(SimpleTestCase):
    def evaluate(self, requirement, phase, evidence=None, **kwargs):
        evaluation = evaluators.evaluate_requirements([requirement], phase, evidence or world(), **kwargs)
        return evaluation

    def test_postcheck_matrix_requirement_passes_and_failures(self):
        E = {"interface": "Ethernet1"}
        rows = [  # label, requirement, evidence overrides, expected (status, code) of the FIRST check
            ("interface present", req("INTERFACE_PRESENT", E), {}, S.PASS, "INTERFACE_EXPECTED_PRESENT"),
            ("interface missing", req("INTERFACE_PRESENT", {"interface": "Ethernet9"}), {}, S.FAIL, "INTERFACE_MISSING"),
            ("address present", req("ADDRESS_PRESENT", {**E, "address": "192.0.2.0/31"}), {}, S.PASS, "ADDRESS_EXPECTED_PRESENT"),
            ("address on the wrong interface", req("ADDRESS_PRESENT", {"interface": "Ethernet2", "address": "192.0.2.0/31"}), {}, S.FAIL, "ADDRESS_MISSING"),
            ("ipv6 address normalised", req("ADDRESS_PRESENT", {**E, "address": "2001:0DB8:0:0:0:0:0:1/64"}), {"addresses": {"Ethernet1": ["2001:db8::1/64"]}}, S.PASS, "ADDRESS_EXPECTED_PRESENT"),
            ("static route present", req("ROUTE_INTENDED", {"prefix": "10.9.0.0/24", "next_hop": "192.0.2.1"}), {}, S.PASS, "ROUTE_EXPECTED_PRESENT"),
            ("static route wrong next hop", req("ROUTE_INTENDED", {"prefix": "10.9.0.0/24", "next_hop": "192.0.2.9"}), {}, S.FAIL, "ROUTE_MISSING"),
            ("static route absent", req("ROUTE_INTENDED", {"prefix": "10.8.0.0/24", "next_hop": "192.0.2.1"}), {}, S.FAIL, "ROUTE_MISSING"),
            ("ospf full", req("ROUTING_INTERFACE_ENABLED", {"protocol": "ospf", "interface": "Ethernet1", "version": "OSPFV2"}), {}, S.PASS, "OSPF_EXPECTED_FULL"),
            ("ospf not full", req("ROUTING_INTERFACE_ENABLED", {"protocol": "ospf", "interface": "Ethernet1", "version": "OSPFV2"}),
             {"ospf": [{"family": "OSPFV2", "neighbor_id": "10.0.0.2", "interface": "Ethernet1", "state": "EX_START"}]}, S.FAIL, "OSPF_ADJACENCY_DOWN"),
            ("ospf no neighbor", req("ROUTING_INTERFACE_ENABLED", {"protocol": "ospf", "interface": "Ethernet1", "version": "OSPFV2"}), {"ospf": []}, S.FAIL, "OSPF_ADJACENCY_DOWN"),
            ("ospf passive interface", req("ROUTING_INTERFACE_ENABLED", {"protocol": "ospf", "interface": "Ethernet1", "passive": True}), {"ospf": []}, S.NOT_APPLICABLE, "OSPF_EXPECTED_FULL"),
            ("bgp established", req("BGP_PEER_INTENDED", {"peer": "192.0.2.1"}), {}, S.PASS, "BGP_EXPECTED_ESTABLISHED"),
            ("bgp idle", req("BGP_PEER_INTENDED", {"peer": "192.0.2.1"}),
             {"bgp": [{"peer": "192.0.2.1", "remote_as": "65002", "state": "IDLE", "family": 4}]}, S.FAIL, "BGP_SESSION_DOWN"),
            ("bgp peer absent", req("BGP_PEER_INTENDED", {"peer": "192.0.2.77"}), {}, S.FAIL, "BGP_SESSION_DOWN"),
            ("bgp shutdown neighbor", req("BGP_PEER_INTENDED", {"peer": "192.0.2.77", "shutdown": True}), {}, S.NOT_APPLICABLE, "BGP_EXPECTED_ESTABLISHED"),
            ("fhrp vip", req("FHRP_GROUP_INTENDED", {"interface": "Vlan10", "virtual_addresses": ["192.168.10.1"]}), {}, S.PASS, "FHRP_VIP_EXPECTED_PRESENT"),
            ("fhrp vip missing", req("FHRP_GROUP_INTENDED", {"interface": "Vlan10", "virtual_addresses": ["192.168.10.2"]}), {}, S.FAIL, "FHRP_VIP_MISSING"),
            ("dhcp relay", req("DHCP_RELAY_INTENDED", {"interface": "Vlan10", "destination": "192.168.200.100"}), {}, S.PASS, "DHCP_RELAY_EXPECTED_PRESENT"),
            ("dhcp relay missing", req("DHCP_RELAY_INTENDED", {"interface": "Vlan10", "destination": "192.168.200.9"}), {}, S.FAIL, "DHCP_RELAY_MISSING"),
            ("acl defined", req("ACL_DEFINED", {"name": "EDGE-IN"}), {}, S.PASS, "ACL_DEFINITION_EXPECTED_PRESENT"),
            ("acl attachment", req("ACL_ATTACHMENT_INTENDED", {"interface": "Vlan10", "acl_name": "EDGE-IN", "direction": "IN"}), {}, S.PASS, "ACL_ATTACHMENT_EXPECTED_PRESENT"),
            ("acl wrong direction", req("ACL_ATTACHMENT_INTENDED", {"interface": "Vlan10", "acl_name": "EDGE-IN", "direction": "OUT"}), {}, S.FAIL, "ACL_ATTACHMENT_MISSING"),
            ("nat rule", req("NAT_RULE_INTENDED", {"outside_interface": "eth2"}), {}, S.PASS, "NAT_RULE_EXPECTED_PRESENT"),
            ("nat rule missing", req("NAT_RULE_INTENDED", {"outside_interface": "eth9"}), {}, S.FAIL, "NAT_RULE_MISSING"),
        ]
        for label, requirement, overrides, status, code in rows:
            with self.subTest(case=label):
                first = self.evaluate(requirement, Phase.POSTCHECK, world(**overrides)).results[0]
                self.assertEqual((first.status, first.check_code), (status, code))

    def test_interface_admin_and_oper_state_semantics(self):
        down = world(interfaces={"Ethernet1": {"admin": "DOWN", "oper": "DOWN"}})
        oper_only = world(interfaces={"Ethernet1": {"admin": "UP", "oper": "DOWN"}})
        rows = [
            ("enabled and up", world(), {"interface": "Ethernet1", "admin_enabled": True}, [S.PASS, S.PASS, S.PASS]),
            ("admin down when enabled is a failure", down, {"interface": "Ethernet1", "admin_enabled": True}, [S.PASS, S.FAIL, S.WARN]),
            ("oper down is only a warning (depends on the far end)", oper_only, {"interface": "Ethernet1", "admin_enabled": True}, [S.PASS, S.PASS, S.WARN]),
            ("intentionally shut", down, {"interface": "Ethernet1", "admin_enabled": False}, [S.PASS, S.PASS, S.NOT_APPLICABLE]),
        ]
        for label, evidence, expected, statuses in rows:
            with self.subTest(case=label):
                evaluation = self.evaluate(req("INTERFACE_PRESENT", expected), Phase.POSTCHECK, evidence)
                self.assertEqual([r.status for r in evaluation.results], statuses)

    def test_precheck_never_requires_future_state_but_postcheck_does(self):
        empty = world(interfaces={}, addresses={}, routes=[], ospf=[], bgp=[], config={"acl_definitions": [], "acl_attachments": [], "dhcp_relays": []})
        future = [
            req("INTERFACE_PRESENT", {"interface": "Ethernet7", "admin_enabled": True}),
            req("ADDRESS_PRESENT", {"interface": "Ethernet7", "address": "192.0.2.4/31"}),
            req("BGP_PEER_INTENDED", {"peer": "192.0.2.5"}),
            req("ACL_DEFINED", {"name": "NEW-ACL"}),
        ]
        for requirement in future:
            with self.subTest(kind=requirement.kind):
                pre = self.evaluate(requirement, Phase.PRECHECK, empty)
                self.assertEqual(pre.result, "PASS")
                self.assertTrue(all(r.status == S.NOT_APPLICABLE and not r.blocking for r in pre.results))
                post = self.evaluate(requirement, Phase.POSTCHECK, empty)
                self.assertEqual(post.result, "FAIL", "the same absence IS a failure after deployment")
        # ... and an already-satisfied future state is an informational PASS (idempotent), not a failure
        already = self.evaluate(future[1], Phase.PRECHECK, world(addresses={"Ethernet7": ["192.0.2.4/31"]}))
        self.assertEqual([r.status for r in already.results], [S.PASS])
        self.assertIn("idempotent", already.results[0].message)

    def test_prerequisites_are_checked_before_deployment_unless_the_plan_creates_them(self):
        route = req("ROUTE_INTENDED", {"prefix": "10.9.0.0/24", "exit_interface": "Ethernet7"})
        rows = [
            ("prerequisite interface missing", [route], world(), S.FAIL, "INTERFACE_MISSING", True),
            ("prerequisite interface oper down", [route], world(interfaces={"Ethernet7": {"admin": "UP", "oper": "DOWN"}}), S.FAIL, "INTERFACE_OPER_DOWN", True),
            ("prerequisite interface admin down", [route], world(interfaces={"Ethernet7": {"admin": "DOWN", "oper": "DOWN"}}), S.WARN, "INTERFACE_ADMIN_DOWN", False),
            ("prerequisite interface up", [route], world(interfaces={"Ethernet7": {"admin": "UP", "oper": "UP"}}), S.PASS, "INTERFACE_EXPECTED_UP", False),
            ("created earlier in this plan", [req("INTERFACE_PRESENT", {"interface": "Ethernet7", "admin_enabled": True}, cfg="CFG-001"), route], world(),
             S.NOT_APPLICABLE, "INTERFACE_EXPECTED_PRESENT", False),
            ("no exit interface, next hop only", [req("ROUTE_INTENDED", {"prefix": "10.9.0.0/24", "next_hop": "192.0.2.1"})], world(), S.NOT_APPLICABLE, "INTERFACE_EXPECTED_UP", False),
            ("partial telemetry cannot prove absence", [route], evidence_set(device_evidence("R1", source="TELEMETRY", complete=False,
                                                                                              interfaces={"Ethernet1": {"admin": "UP", "oper": "UP"}})),
             S.UNKNOWN, "PRECHECK_DATA_UNAVAILABLE", True),
        ]
        for label, requirements, evidence, status, code, blocks in rows:
            with self.subTest(case=label):
                evaluation = evaluators.evaluate_requirements(requirements, Phase.PRECHECK, evidence, roles={"R1": Role.TARGET})
                last = [r for r in evaluation.results if r.requirement == "STATIC_ROUTE_PRESENT"][-1]
                self.assertEqual((last.status, last.check_code, last.blocking), (status, code, blocks))

    def test_unimplemented_unknown_and_incomplete_requirements_never_pass(self):
        rows = [
            ("known gap: NAT pool", req("NAT_POOL_INTENDED", {}), "REQUIREMENT_NOT_IMPLEMENTED"),
            ("unknown requirement type", req("TELEPORT_INTENDED", {"x": 1}), "REQUIREMENT_UNKNOWN_TYPE"),
            ("older plan without expected facts", req("ADDRESS_PRESENT", None), "REQUIREMENT_DESCRIPTOR_INCOMPLETE"),
            ("descriptor missing a needed fact", req("ADDRESS_PRESENT", {"interface": "Ethernet1"}), "REQUIREMENT_DESCRIPTOR_INCOMPLETE"),
        ]
        for label, requirement, code in rows:
            with self.subTest(case=label):
                post = self.evaluate(requirement, Phase.POSTCHECK)
                self.assertEqual([(r.status, r.check_code) for r in post.results], [(S.UNKNOWN, code)])
                self.assertEqual(post.result, "INCOMPLETE")
                self.assertTrue(post.summary["unverified"])
        # in a precheck a requirement with nothing to check beforehand is simply not applicable
        pre = self.evaluate(req("BGP_NETWORK_INTENDED", {"prefix": "203.0.113.0/24", "family": "IPV4"}), Phase.PRECHECK)
        self.assertEqual([r.status for r in pre.results], [S.NOT_APPLICABLE])

    def test_routing_config_checks_process_binding_neighbor_and_network(self):
        good = world(routing_config=[
            {"protocol": "ospf", "version": "OSPFV2", "process_id": 44, "local_asn": None,
             "router_id": "10.0.0.1", "enabled": True,
             "networks": [{"prefix": "192.0.2.0/31", "area": "0"}],
             "bindings": [{"interface_name": "Ethernet1", "area": "0", "passive": False}],
             "neighbors": [], "redistributions": []},
            {"protocol": "bgp", "version": "", "process_id": None, "local_asn": 65001,
             "router_id": "10.0.0.1", "enabled": True,
             "networks": [{"family": "IPV4", "cidr": "203.0.113.0/24"}], "bindings": [],
             "neighbors": [{"peer_address": "192.0.2.1", "remote_asn": 65002,
                            "activate_ipv4": True, "activate_ipv6": False}], "redistributions": []},
        ])
        cases = [
            ("ROUTING_PROCESS_INTENDED", {"protocol": "ospf", "version": "OSPFV2", "process_id": 44,
                                          "router_id": "10.0.0.1", "networks": [{"prefix": "192.0.2.0/31", "area": "0"}]}),
            ("ROUTING_INTERFACE_ENABLED", {"protocol": "ospf", "version": "OSPFV2", "interface": "Ethernet1", "area": "0"}),
            ("BGP_PEER_INTENDED", {"peer": "192.0.2.1", "family": "IPV4", "local_asn": 65001, "remote_asn": 65002}),
            ("BGP_NETWORK_INTENDED", {"prefix": "203.0.113.0/24", "family": "IPV4"}),
        ]
        for kind, facts in cases:
            with self.subTest(kind=kind):
                self.assertEqual(self.evaluate(req(kind, facts), Phase.POSTCHECK, good).result, "PASS")
        bad = req("BGP_PEER_INTENDED", {"peer": "192.0.2.1", "family": "IPV4", "remote_asn": 65009})
        self.assertEqual(self.evaluate(bad, Phase.POSTCHECK, good).result, "FAIL")
        self.assertEqual(self.evaluate(req("BGP_NETWORK_INTENDED", {"prefix": "203.0.114.0/24", "family": "IPV4"}),
                                       Phase.POSTCHECK, good).result, "FAIL")

    def test_an_ospf_network_statement_enables_an_interface_only_when_it_covers_its_address_and_area(self):
        from core.services.health import routing_config

        config = ("interface Ethernet1\n   ip address 10.0.1.1/24\ninterface Ethernet2\n   ip address 172.16.0.1/24\n"
                  "interface Ethernet3\n   ip address 10.0.3.1/24\n   ip ospf area 0.0.0.7\n"
                  "router ospf 10\n   network 10.0.0.0/8 area 0\n   network 10.0.1.0/24 area 0.0.0.5\n")
        row = next(r for r in routing_config.eos(config) if r["protocol"] == "ospf")
        self.assertEqual(row["network_bindings"], [{"interface_name": "Ethernet1", "area": "5"}], "most specific statement; Ethernet2 uncovered; Ethernet3 bound itself")
        self.assertEqual([b["interface_name"] for b in row["bindings"]], ["Ethernet3"])
        frr = next(r for r in routing_config.frr("interface eth1\n ip address 10.0.1.1/24\n!\nrouter ospf\n network 10.0.0.0/8 area 0\nexit\n", "[]")
                   if r["protocol"] == "ospf")
        self.assertEqual(frr["network_bindings"], [{"interface_name": "eth1", "area": "0"}])

        observed = world(routing_config=[row])
        cases = [
            ({"interface": "Ethernet1"}, "PASS"),                       # an observed adjacency: enabled by the covering statement
            ({"interface": "Ethernet1", "area": "5"}, "PASS"),
            ({"interface": "Ethernet1", "area": "0"}, "FAIL"),          # the wrong area is still a mismatch
            ({"interface": "Ethernet1", "passive": True}, "FAIL"),      # the statement form cannot confirm a passive expectation
            ({"interface": "Ethernet2"}, "FAIL"),                       # no binding and no covering statement
            ({"interface": "Ethernet1", "version": "OSPFV3"}, "FAIL"),  # a different process family
        ]
        for facts, result in cases:
            with self.subTest(facts=facts):
                requirement = req("ROUTING_INTERFACE_ENABLED", {"protocol": "ospf", "version": "OSPFV2", **facts})
                found = {(r.check_code, r.status) for r in self.evaluate(requirement, Phase.POSTCHECK, observed).results}
                wanted = ("ROUTING_CONFIG_PRESENT", S.PASS) if result == "PASS" else ("ROUTING_CONFIG_MISMATCH", S.FAIL)
                self.assertIn(wanted, found)
                self.assertEqual({code for code, _ in found} & {"ROUTING_CONFIG_PRESENT", "ROUTING_CONFIG_MISMATCH"}, {wanted[0]})

    def test_missing_and_expired_evidence_is_unknown_never_pass(self):
        address = req("ADDRESS_PRESENT", {"interface": "Ethernet1", "address": "192.0.2.0/31"})
        rows = [
            ("device evidence never collected", evidence_set()),
            ("group unavailable", evidence_set(device_evidence("R1", addresses=None))),
            ("group expired", evidence_set(device_evidence("R1", age=600.0, addresses={"Ethernet1": ["192.0.2.0/31"]}))),
        ]
        for label, evidence in rows:
            with self.subTest(case=label):
                post = self.evaluate(address, Phase.POSTCHECK, evidence)
                self.assertEqual([(r.status, r.check_code) for r in post.results], [(S.UNKNOWN, "POSTCHECK_DATA_UNAVAILABLE")])
                self.assertEqual(post.result, "INCOMPLETE")
                pre = self.evaluate(req("ROUTE_INTENDED", {"prefix": "10.9.0.0/24", "exit_interface": "Ethernet1"}), Phase.PRECHECK, evidence)
                self.assertEqual((pre.results[0].status, pre.results[0].check_code, pre.results[0].blocking), (S.UNKNOWN, "PRECHECK_DATA_UNAVAILABLE", True))

    def test_ospf_one_sided_link_expects_no_adjacency(self):
        binding = req("ROUTING_INTERFACE_ENABLED", {"protocol": "ospf", "interface": "Ethernet1", "version": "OSPFV2"})
        empty = world(ospf=[])
        without = self.evaluate(binding, Phase.POSTCHECK, empty)
        with_flag = self.evaluate(binding, Phase.POSTCHECK, empty, one_sided_ospf={("R1", "Ethernet1")})
        self.assertEqual((without.results[0].status, with_flag.results[0].status), (S.FAIL, S.NOT_APPLICABLE))

    def test_evaluation_is_deterministic_and_pure(self):
        requirements = [req("ADDRESS_PRESENT", {"interface": "Ethernet1", "address": "192.0.2.0/31"}, cfg="CFG-002"),
                        req("ROUTE_INTENDED", {"prefix": "10.8.0.0/24"}, cfg="CFG-003")]
        first = evaluators.evaluate_requirements(requirements, Phase.POSTCHECK, world())
        second = evaluators.evaluate_requirements(list(requirements), Phase.POSTCHECK, world())
        strip = lambda ev: [{k: v for k, v in r.to_dict().items() if k != "timestamp"} for r in ev.results]  # noqa: E731
        self.assertEqual(strip(first), strip(second))
        self.assertEqual((first.result, first.counts), (second.result, second.counts))
        with self.assertRaises(ValueError):
            evaluators.evaluate_requirements(requirements, "DURING", world())


class EvidencePrecedenceTests(SimpleTestCase):
    def test_live_takes_precedence_over_older_telemetry_per_group_and_conflicts_are_recorded(self):
        live = device_evidence("R1", interfaces={"Ethernet1": {"admin": "UP", "oper": "DOWN"}, "Ethernet2": {"admin": "UP", "oper": "UP"}})
        telemetry = device_evidence("R1", source="TELEMETRY", age=90.0, complete=False, interfaces={"Ethernet1": {"admin": "UP", "oper": "UP"}},
                                    telemetry={"cpu_percent": 12.0})
        merged = merge_precedence(live, telemetry)
        self.assertEqual(merged.group("interfaces").source, "LIVE")
        self.assertEqual(merged.facts("interfaces")["Ethernet1"]["oper"], "DOWN")
        self.assertEqual(merged.group("telemetry").source, "TELEMETRY", "a group live did not provide still comes from telemetry, source-labelled")
        self.assertEqual(merged.conflicts, [{"group": "interfaces", "key": "Ethernet1", "live": "DOWN", "telemetry": "UP", "used": "LIVE"}])
        # the telemetry group is never blended into a live one
        self.assertNotIn("Ethernet2", telemetry.facts("interfaces"))
        # and when live evidence is unavailable, telemetry is used but stays partial and labelled
        fallback = merge_precedence(device_evidence("R1", interfaces=None), telemetry)
        self.assertEqual((fallback.group("interfaces").source, fallback.group("interfaces").complete), ("TELEMETRY", False))
        self.assertTrue(hs.CODES["EVIDENCE_CONFLICT"].description)


class DocumentationTests(SimpleTestCase):
    def test_every_stable_code_and_required_topic_is_documented(self):
        root = Path(settings.REPO_ROOT)
        doc = (root / "docs/HEALTH_PRECHECK_POSTCHECK.md").read_text()
        self.assertEqual([c for c in codes.CODES if f"`{c}`" not in doc], [], "an undocumented stable check code")
        for kind in reqs.REQUIREMENT_MAP:
            with self.subTest(kind=kind):
                self.assertIn(f"`{kind}`", doc)
        for topic in ("Fleet Quick", "Deep Health", "Precheck", "Postcheck", "Evidence precedence", "UNKNOWN semantics", "Blocking policy",
                      "Known limitations", "No deployment", "No rollback", "Credential handling", "Read-only device guarantees",
                      "Affected-device scope", "Phase-16 / Phase-17 handoff", "Descriptor extension"):
            with self.subTest(topic=topic):
                self.assertIn(topic, doc)
        state = (root / "docs/CURRENT_STATE.md").read_text()
        self.assertIn("**Phase 15 update", state)
        self.assertIn("**Phase 14 update", state, "historical notes are kept, not rewritten")
