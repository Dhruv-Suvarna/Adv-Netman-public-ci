"""Direct tests for the smaller Troubleshooter source adapters: DNS, physical, QoS, L2, ACL, STP, monitoring, the
contracts bridge, the capability matrix and the exact-target policy provider (troubleshooting/adapters/*).

Every adapter issues only bounded reads of an explicit scope, labels non-gateway evidence as never live, and treats
missing, foreign or malformed history as no history rather than inventing a sample.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

from django.test import SimpleTestCase, TestCase

from core.services.health import inventory as health_inventory
from core.services.troubleshooting import collectors as col
from core.services.troubleshooting.adapters import acl, capabilities, contracts_bridge as cb, dns, l2, monitoring as mon
from core.services.troubleshooting.adapters import nmas_providers, physical as phy, qos, stp
from core.tests.test_tg_ts_engine_units import open_case
from core.tests.test_troubleshooting_engine import ACTOR

NOW = datetime(2026, 11, 27, 6, 0, tzinfo=timezone.utc)
DNS_TARGET = {"client": "h1", "name": "www.lab", "zone": "lab", "resolvers": ["10.0.0.53"], "authoritative": ["ns1"]}


# ============================================================================================================ DNS
class DnsTests(SimpleTestCase):
    def test_allowed_servers_of_a_target_without_servers_is_empty(self):
        with self.subTest("a target without servers has none"):
            self.assertEqual(dns.allowed_servers({}), [])
        self.assertEqual(dns.allowed_servers(DNS_TARGET, dns.DnsContext(extra_servers=("9.9.9.9",))), ["10.0.0.53", "ns1", "9.9.9.9"])

    def test_describe_source_of_an_unrecorded_gateway_is_never_live(self):
        out = dns.describe_source(gateway={"live": "yes"})
        self.assertEqual((out["label"], out["live"]), (dns.SIMULATED, False))

    def test_requests_for_an_unknown_device_is_empty(self):
        self.assertEqual(dns.requests_for_device(DNS_TARGET, "h9", ["dns.query", "dns.xfr"]), [])

    def test_served_keys_returns_each_requested_dns_key(self):
        reqs = dns.requests_for_device(DNS_TARGET, "h1", ["dns.resolver_config", "dns.query"])
        self.assertEqual(dns.served_keys(reqs), {"dns.resolver_config", "dns.query"})

    def test_served_keys_of_no_request_is_empty(self):
        self.assertEqual(dns.served_keys([]), set())

    def test_ttl_recovery_returns_each_recheck_state(self):
        self.assertEqual(dns.ttl_recovery({"ttl": 60}, NOW, NOW + timedelta(seconds=10))["state"], "WAITING_TTL")
        self.assertEqual(dns.ttl_recovery({"ttl": 60}, NOW, NOW + timedelta(seconds=90))["state"], "RECHECK_DUE")
        self.assertEqual(dns.ttl_recovery({"ttl": True}, NOW, NOW)["state"], "NO_TTL")


# ======================================================================================================= physical
LINKS = phy.PhysicalContext(links=({"a": "R1", "a_if": "Ethernet1", "b": "R2", "b_if": "Ethernet3"},))
PHY_TARGET = {"device": "R1", "interface": "Ethernet1"}


class PhysicalTests(SimpleTestCase):
    def test_peer_returns_the_far_end_of_an_intent_link(self):
        self.assertEqual((LINKS.peer("R1", "Ethernet1"), LINKS.peer("R2", "Ethernet3"), LINKS.peer("R1", "Ethernet9")),
                         (("R2", "Ethernet3"), ("R1", "Ethernet1"), (None, None)))

    def test_wanted_here_returns_true_for_physical_or_rate_keys(self):
        self.assertTrue(phy.wanted_here(["interface.fec"]))
        self.assertTrue(phy.wanted_here(["interface.rate.in_bps"]))

    def test_wanted_here_without_a_physical_key_is_false(self):
        self.assertFalse(phy.wanted_here(["routing.neighbor"]))

    def test_requests_for_a_device_off_the_link_or_without_context_is_empty(self):
        self.assertEqual(phy.requests_for_device(PHY_TARGET, "R3", ["interface.fec"], LINKS), [])
        self.assertEqual(phy.requests_for_device(PHY_TARGET, "R2", ["interface.fec"], None), [])
        self.assertEqual(phy.requests_for_device(PHY_TARGET, "R2", ["interface.fec"], LINKS)[0]["interfaces"], ["Ethernet3"])

    def test_gap_reason_names_each_unknown_cause(self):
        self.assertEqual(phy.gap_reason(False, False), phy.PHY_GAP_REASON)
        self.assertTrue(phy.gap_reason(True, False).startswith("SCOPE_MISMATCH"))
        self.assertTrue(phy.gap_reason(True, True).startswith("UNKNOWN"))


# ============================================================================================================ QoS
class QosTests(SimpleTestCase):
    def test_qos_request_returns_the_stated_production_tuple(self):
        self.assertEqual(qos.qos_request({"vrf": "blue", "protocol": "tcp", "port": 443, "dscp": None}),
                         {"vrf": "blue", "directions": ["in", "out"], "flow": {"protocol": "tcp", "port": 443}})

    def test_qos_request_without_a_flow_is_unscoped_default(self):
        self.assertEqual(qos.qos_request(None), {"vrf": "default", "directions": ["in", "out"], "flow": {}})

    def test_classify_refuses_to_decide_unknown_or_unsupported_criteria(self):
        flow = {"protocol": "tcp", "port": 443, "dst_ip": "10.2.2.9"}
        for label, cls, expected in (("unsupported syntax", {"name": "c", "unsupported": "nbar"}, None),
                                     ("incomplete criteria", {"name": "c", "match_complete": False, "match": {"any": True}}, None),
                                     ("a DSCP class for an unstated DSCP", {"name": "c", "match_complete": True, "match": {"dscp": [46]}}, None),
                                     ("an unparsable network", {"name": "c", "match_complete": True, "match": {"dst": ["bad"]}}, None),
                                     ("another port", {"name": "c", "match_complete": True, "match": {"ports": [80]}}, False)):
            with self.subTest(f"{label} is not a match"):
                self.assertIs(qos.classify(cls, flow)[0], expected)


# =================================================================================================== contract bridge
MISSING = {"source_type": "CLI", "device": "R1", "recorded_at": "2026-11-27T06:00:00Z", "reason": "TIMEOUT"}


class ContractsBridgeTests(SimpleTestCase):
    def test_target_string_returns_sorted_key_values(self):
        self.assertEqual(cb.target_string({"interface": "Ethernet1", "device": "R1"}), "device=R1,interface=Ethernet1")

    def test_target_string_omits_empty_or_none_values(self):
        self.assertEqual(cb.target_string({"device": "R1", "vrf": "", "peer": None}), "device=R1")

    def test_to_contract_missing_returns_a_missing_data_record(self):
        out = cb.to_contract_missing({**MISSING, "evidence_id": "EV-1"})
        self.assertEqual((out["key"], out["quality"], out["is_missing_data"], out["evidence_id"]), ("missing.cli", "MISSING", True, "EV-1"))

    def test_to_contract_missing_without_evidence_has_an_empty_reference(self):
        self.assertEqual(cb.to_contract_missing(MISSING)["evidence_id"], "")


class CapabilityAndProviderTests(TestCase):
    def test_capability_matrix_returns_every_platform_and_source(self):
        matrix = capabilities.capability_matrix(lambda platform, source: f"{platform}:{source}")
        self.assertEqual(set(matrix), set(capabilities.KNOWN_PLATFORMS))
        self.assertEqual(set(next(iter(matrix.values()))), set(col.SourceType.ALL))

    def test_target_policy_builds_from_the_tracked_inventory(self):
        policy = nmas_providers.target_policy()
        self.assertEqual(policy.topology_id, str(health_inventory.load_inventory()["lab_name"]).strip())


# ======================================================================================================== L2 / ACL / STP
class L2AclStpTests(TestCase):
    def setUp(self):
        self.case = open_case(key="tg-src-adapters")

    def test_describe_source_and_is_supported_return_the_ceos_contract(self):
        for module in (acl, l2):
            with self.subTest(module=module.__name__):
                self.assertEqual(module.describe_source(gateway={"live": True})["label"], module.LIVE)
                self.assertTrue(module.is_supported("ceos", "4.36.2F"))
        self.assertTrue(stp.is_supported("ceos", "4.36.2F"))

    def test_stp_describe_source_of_a_simulated_run_is_never_live(self):
        self.assertEqual(stp.describe_source(recorded=True)["label"], stp.RECORDED)
        self.assertFalse(stp.describe_source()["live"])

    def test_for_vlans_returns_string_vlan_aliases(self):
        self.assertEqual(stp.StpContext.for_vlans([10, "20"]).vlans, ("10", "20"))

    def test_for_vlans_of_none_is_empty(self):
        self.assertEqual(stp.StpContext.for_vlans([]).vlans, ())

    def test_acl_history_record_persists_a_sample_a_new_instance_reloads(self):
        entry = {"at": NOW, "rules": {10: {"hits": 5, "text": "permit ip any any"}}}
        acl.PersistentAclHistory(ACTOR, self.case.case_id).record("r1", "EDGE", entry)
        reloaded = acl.PersistentAclHistory(ACTOR, self.case.case_id).previous("r1", "EDGE")
        self.assertEqual((reloaded["at"], reloaded["rules"]), (NOW, entry["rules"]))

    def test_acl_history_record_of_an_unknown_case_is_never_persisted(self):
        history = acl.PersistentAclHistory(ACTOR, "TS-CASE-UNKNOWN")
        history.record("r1", "EDGE", {"at": NOW, "rules": {}})
        self.assertTrue(history.problems)
        self.assertIsNone(acl.PersistentAclHistory(ACTOR, "TS-CASE-UNKNOWN").previous("r1", "EDGE"))

    def mac_entry(self):
        return {"macs": {"aa:bb:cc:00:00:01": "Ethernet1"}, "at": NOW, "coverage_start": NOW - timedelta(minutes=5), "events": []}

    def test_mac_history_record_persists_a_sample_a_new_instance_reloads(self):
        l2.PersistentMacHistory(ACTOR, self.case.case_id).record("r1", "10", self.mac_entry())
        reloaded = l2.persistent_l2_context(ACTOR, self.case.case_id).history.previous("r1", "10")
        self.assertEqual(reloaded["macs"], self.mac_entry()["macs"])

    def test_mac_history_record_of_an_unknown_case_is_never_persisted(self):
        history = l2.PersistentMacHistory(ACTOR, "TS-CASE-UNKNOWN")
        history.record("r1", "10", self.mac_entry())
        self.assertTrue(history.problems)

    def test_persistent_l2_context_of_an_unknown_case_has_no_history(self):
        context = l2.persistent_l2_context(ACTOR, "TS-CASE-UNKNOWN")
        self.assertIsInstance(context.history, l2.PersistentMacHistory)
        self.assertIsNone(context.history.previous("r1", "10"))


# ===================================================================================================== monitoring
class MonitoringTests(SimpleTestCase):
    def test_catalog_loaders_refuse_a_missing_file(self):
        for label, loader in (("the gNMI catalog", mon.load_gnmi_stream_catalog), ("the SNMP OID map", mon.load_snmp_oids)):
            with self.subTest(f"a missing {label} raises"), self.assertRaises(FileNotFoundError):
                loader(Path("/nonexistent/nmas-monitoring.yml"))

    def test_load_snmp_oids_returns_the_repository_map(self):
        self.assertIsInstance(mon.load_snmp_oids(), dict)

    def test_gnmi_allowed_prefixes_never_include_a_wildcard_key(self):
        with self.subTest("a wildcard key is never part of a prefix"):
            prefixes = mon.gnmi_allowed_prefixes({"paths": ["/interfaces/interface[name=*]/state", "/system/state/"]})
            self.assertEqual(prefixes, ("/interfaces/interface", "/system/state"))

    def test_verify_oid_consistency_reports_a_mismatched_column(self):
        name = next(iter(col.IF_TABLE_COLUMNS))
        self.assertEqual(len(mon.verify_oid_consistency({name: "1.3.6.1.9.9.9"})), 1)

    def test_parse_flux_csv_drops_comments_and_empty_values(self):
        text = "#datatype,string\n,result,_time,_value\n,_result,2026-11-27T06:00:00Z,\n,_result,2026-11-27T06:00:01Z,link down\n"
        self.assertEqual(mon.parse_flux_csv(text), [("link down", "2026-11-27T06:00:01Z")])

    def test_topology_collect_of_an_unavailable_service_is_a_missing_record(self):
        collector = mon.TopologyTelemetryCollector(clock=lambda: 0.0, sleep=lambda s: None, now=lambda: NOW)
        target = col.Target(device="R1", platform="ceos", capabilities={col.SourceType.TOPOLOGY_TELEMETRY: "SUPPORTED"})
        bundle = collector.collect(target, SimpleNamespace(available=False))
        self.assertEqual((bundle["observations"], bundle["missing"][0]["reason"]), ([], "TRANSPORT_ERROR"))
