"""Multi-fault diagnosis and safe non-remediation (milestone NMAS_V2_MULTI_FAULT_DIAGNOSIS_AND_SAFE_NON_REMEDIATION).

Deterministic classification of administrative vs operational vs flapping vs degradation vs routing vs reachability faults,
the deterministic remediation decision, intake correlation/dedup for the new categories, governance negatives (an ineffective
or unauthorized operation can never reach the Change Engine), the Codex-outage path, and the bounded link-fault harness.
"""

from __future__ import annotations

import copy
import json
import tempfile
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

from django.test import SimpleTestCase, TestCase

from core import models
from core.services.troubleshooting import fault_injection as fi
from core.services.troubleshooting import faults as F
from core.services.troubleshooting import governance as gov
from core.services.troubleshooting import intake, recovery
from core.services.troubleshooting import repository as repo

T0 = datetime(2026, 11, 17, 19, 0, 0, tzinfo=timezone.utc)
INTENT = {"R2": {"Ethernet1": "up", "Ethernet2": "up"}, "S4": {"Ethernet3": "up"}}
PEERS = {("R2", "Ethernet1"): ("S4", "Ethernet3"), ("S4", "Ethernet3"): ("R2", "Ethernet1")}
POLICY = {"id": "ARP-R2-E1-002", "device": "R2", "interface": "Ethernet1", "kind": "interface_enable"}


def sample(dev, iface, at, *, status="connected", proto="up", changes=None, counters=None, last_change=None):
    return F.InterfaceSample(device=dev, interface=iface, at=at, admin="down" if status == "disabled" else "up",
                             oper="up" if status == "connected" and proto == "up" else "down", link_status=status, protocol=proto,
                             link_status_changes=changes, last_change=last_change, counters=counters or {}, bandwidth_bps=10**9)


def hist(*samples):
    h = F.LinkHistory()
    for s in samples:
        h.update(s)
    return h


# ------------------------------------------------------------------------------------------------------------ classification
class ObservationNormalizationTests(SimpleTestCase):
    DOC = {"interfaces": {
        "Ethernet1": {"interfaceStatus": "notconnect", "lineProtocolStatus": "down", "bandwidth": 1000000000, "duplex": "duplexFull",
                      "lastStatusChangeTimestamp": 1794939484.0,
                      "interfaceCounters": {"linkStatusChanges": 26, "totalInErrors": 0, "totalOutErrors": 0, "inDiscards": 0,
                                            "outDiscards": 0, "inTotalPkts": 10, "outTotalPkts": 9},
                      "interfaceStatistics": {"inBitsRate": 0.0, "outBitsRate": 0.0}},
        "Ethernet2": {"interfaceStatus": "disabled", "lineProtocolStatus": "down"},
        "Management0": {"interfaceStatus": "connected", "lineProtocolStatus": "up"}}}

    def test_admin_and_operational_state_are_separate_fields(self):
        rows = {s.interface: s for s in F.interface_samples("R2", self.DOC, T0)}
        self.assertNotIn("Management0", rows)
        self.assertEqual((rows["Ethernet1"].admin, rows["Ethernet1"].oper, rows["Ethernet1"].link_status), ("up", "down", "notconnect"))
        self.assertEqual((rows["Ethernet2"].admin, rows["Ethernet2"].oper), ("down", "down"))
        self.assertEqual(rows["Ethernet1"].link_status_changes, 26)
        self.assertEqual(rows["Ethernet1"].counters["inTotalPkts"], 10)
        self.assertIsNotNone(rows["Ethernet1"].last_change)


class InterfaceClassificationTests(SimpleTestCase):
    def classify(self, s, h=None, intent="up", now=None):
        return F.classify_interface(s, intent, h, now=now or s.at, confirm_seconds=30)

    def test_admin_down_against_intent_is_admin_state_mismatch_with_confirmed_cause(self):
        s = sample("R2", "Ethernet1", T0, status="disabled", proto="down")
        c = self.classify(s, hist(s))
        self.assertEqual((c.category, c.cause_status), (F.ADMIN_STATE_MISMATCH, F.CAUSE_CONFIRMED))

    def test_oper_down_admin_up_is_operational_link_down_after_debounce_with_undetermined_cause(self):
        a = sample("R2", "Ethernet1", T0, status="notconnect", proto="down")
        b = sample("R2", "Ethernet1", T0 + timedelta(seconds=31), status="notconnect", proto="down")
        self.assertEqual(self.classify(a, hist(a)).category, F.INDETERMINATE)          # inside the debounce window
        c = self.classify(b, hist(a, b))
        self.assertEqual(c.category, F.OPERATIONAL_LINK_DOWN)
        self.assertEqual((c.cause_status, c.cause), (F.CAUSE_UNDETERMINED, ""))         # no cause asserted without evidence
        self.assertIn("transceiver/optic failure", c.possible_causes)
        self.assertEqual(c.evidence["observed"]["admin"], "up")

    def test_repeated_transitions_are_link_flapping_from_poll_edges(self):
        rows = [sample("R2", "Ethernet1", T0 + timedelta(seconds=10 * i), status="connected" if i % 2 else "notconnect",
                       proto="up" if i % 2 else "down") for i in range(6)]
        c = self.classify(rows[-1], hist(*rows))
        self.assertEqual(c.category, F.LINK_FLAPPING)
        self.assertGreaterEqual(c.evidence["transitions"]["transitions"], 4)
        self.assertTrue(all("at" in e for e in c.evidence["transitions"]["poll_edges"]))

    def test_sub_poll_flaps_are_counted_from_the_device_counter(self):
        a = sample("R2", "Ethernet1", T0, changes=24)
        b = sample("R2", "Ethernet1", T0 + timedelta(seconds=10), changes=32)             # 8 transitions between two polls, both up
        c = self.classify(b, hist(a, b))
        self.assertEqual(c.category, F.LINK_FLAPPING)
        self.assertEqual(c.evidence["transitions"]["device_counter_transitions"], 8)
        self.assertEqual(c.evidence["transitions"]["severity"], "HIGH")

    def test_a_single_outage_and_lifetime_counters_are_not_flapping(self):
        a = sample("R2", "Ethernet1", T0, changes=24)
        b = sample("R2", "Ethernet1", T0 + timedelta(seconds=10), changes=26)
        self.assertEqual(self.classify(b, hist(a, b)).category, F.NO_FAULT)

    def test_admin_driven_toggles_are_not_reported_as_flapping(self):
        rows = [sample("R2", "Ethernet1", T0 + timedelta(seconds=10 * i), status="connected" if i % 2 else "disabled",
                       proto="up" if i % 2 else "down") for i in range(6)]
        self.assertNotEqual(self.classify(rows[-1], hist(*rows)).category, F.LINK_FLAPPING)

    def test_error_deltas_in_consecutive_intervals_are_degradation_but_resets_and_lifetime_totals_are_not(self):
        base = {"totalInErrors": 5000, "totalOutErrors": 0, "inDiscards": 0, "outDiscards": 0, "inTotalPkts": 10000, "outTotalPkts": 10000}
        rows = [sample("R2", "Ethernet1", T0 + timedelta(seconds=10 * i),
                       counters={**base, "totalInErrors": 5000 + 50 * i, "inTotalPkts": 10000 + 1000 * i}) for i in range(3)]
        self.assertEqual(self.classify(rows[-1], hist(*rows)).category, F.INTERFACE_DEGRADATION)
        flat = [sample("R2", "Ethernet1", T0 + timedelta(seconds=10 * i), counters=base) for i in range(3)]   # 5000 lifetime, no delta
        self.assertEqual(self.classify(flat[-1], hist(*flat)).category, F.NO_FAULT)
        reset = [rows[0], rows[1], sample("R2", "Ethernet1", T0 + timedelta(seconds=30), counters={**base, "totalInErrors": 3})]
        h = hist(*reset)
        self.assertTrue(h.last_delta.reset)
        self.assertEqual(self.classify(reset[-1], h).category, F.NO_FAULT)

    def test_intent_down_and_unknown_intent(self):
        s = sample("R2", "Ethernet2", T0, status="disabled", proto="down")
        self.assertEqual(self.classify(s, hist(s), intent="down").category, F.NO_FAULT)
        self.assertEqual(self.classify(s, hist(s), intent=None).category, F.INDETERMINATE)

    def test_errdisabled_is_operational_not_administrative(self):
        a = sample("R2", "Ethernet1", T0, status="errdisabled", proto="down")
        b = sample("R2", "Ethernet1", T0 + timedelta(seconds=40), status="errdisabled", proto="down")
        c = self.classify(b, hist(a, b))
        self.assertEqual(c.category, F.OPERATIONAL_LINK_DOWN)
        self.assertIn("error-disable", c.possible_causes[0])


class LinkCorrelationTests(SimpleTestCase):
    def ends(self, r2_status, s4_status, seconds=31):
        out = []
        for dev, iface, status in (("R2", "Ethernet1", r2_status), ("S4", "Ethernet3", s4_status)):
            a = sample(dev, iface, T0, status=status, proto="down")
            b = sample(dev, iface, T0 + timedelta(seconds=seconds), status=status, proto="down")
            out.append(F.classify_interface(b, "up", hist(a, b), now=b.at))
        return F.classify_link(out)

    def test_far_end_admin_shutdown_explains_the_local_oper_down(self):
        c = self.ends("disabled", "notconnect")
        self.assertEqual((c.category, c.scope["device"]), (F.ADMIN_STATE_MISMATCH, "R2"))
        self.assertTrue(any("explained by the administrative shutdown" in s for s in c.secondary))

    def test_both_ends_admin_up_and_down_is_one_operational_fault_with_no_asserted_cause(self):
        c = self.ends("notconnect", "notconnect")
        self.assertEqual(c.category, F.OPERATIONAL_LINK_DOWN)
        self.assertTrue(c.evidence["both_ends_admin_up"])
        self.assertEqual(c.cause, "")
        self.assertEqual(len(c.scope["link"]), 2)


class RoutingAndReachabilityTests(SimpleTestCase):
    def test_expected_adjacency_loss_and_secondary_correlation(self):
        exp = [F.AdjacencySample("R2", "ospf", "192.168.255.3", "Vlan103", "full", T0),
               F.AdjacencySample("R2", "ospf", "192.168.255.8", "Ethernet4", "full", T0)]
        obs = [F.AdjacencySample("R2", "ospf", "192.168.255.8", "Ethernet4", "full", T0)]
        out = F.classify_adjacency(exp, obs, now=T0, expectation_source="test", link_incidents={"R2": "LINK:R2:Ethernet1|S4:Ethernet3"})
        self.assertEqual([c.category for c in out], [F.ROUTING_ADJACENCY_FAILURE])
        self.assertEqual(out[0].evidence["possibly_secondary_to"], "LINK:R2:Ethernet1|S4:Ethernet3")
        self.assertIn("absent", out[0].summary)
        self.assertEqual(F.classify_adjacency(exp, exp, now=T0, expectation_source="test"), [])

    def test_ospf_and_bgp_documents_normalize(self):
        ospf = {"vrfs": {"default": {"instList": {"10": {"ospfNeighborEntries": [
            {"routerId": "192.168.255.4", "interfaceName": "Vlan104", "adjacencyState": "full"}]}}}}}
        bgp = {"vrfs": {"default": {"peers": {"172.20.5.0": {"peerState": "Active"}}}}}
        rows = F.adjacency_samples("R5", ospf, bgp, T0)
        self.assertEqual([(r.protocol, r.healthy) for r in rows], [("ospf", True), ("bgp", False)])

    def test_missing_route_wrong_next_hop_and_unreadable_rib(self):
        self.assertEqual(F.classify_route("R2", "10.0.0.0/24", ["192.168.100.5"], [], now=T0).category, F.ROUTE_OR_REACHABILITY_FAILURE)
        self.assertIn("expected", F.classify_route("R2", "10.0.0.0/24", ["192.168.100.5"], ["10.254.82.2"], now=T0).summary)
        self.assertEqual(F.classify_route("R2", "10.0.0.0/24", ["192.168.100.5"], None, now=T0).category, F.INDETERMINATE)
        self.assertEqual(F.classify_route("R2", "10.0.0.0/24", ["192.168.100.5"], ["192.168.100.5"], now=T0).category, F.NO_FAULT)

    def test_reachability_needs_consecutive_loss_and_correlates_a_missing_route(self):
        flow = {"source": "H1", "destination": "192.168.20.101", "af": "ipv4"}
        lossy = [{"at": "t1", "loss_pct": 100.0, "measured": True}, {"at": "t2", "loss_pct": 100.0, "measured": True}]
        route = F.classify_route("S1", "192.168.20.0/24", ["x"], [], now=T0)
        c = F.classify_reachability(flow, lossy, baseline_loss_pct=0.0, routes=[route], now=T0)
        self.assertEqual((c.category, c.cause_status), (F.ROUTE_OR_REACHABILITY_FAILURE, F.CAUSE_CONFIRMED))
        c = F.classify_reachability(flow, lossy, baseline_loss_pct=0.0, now=T0)
        self.assertEqual(c.cause_status, F.CAUSE_UNDETERMINED)
        one = F.classify_reachability(flow, lossy[:1], baseline_loss_pct=0.0, now=T0)
        self.assertEqual(one.category, F.INDETERMINATE)
        healthy = [{"loss_pct": 0.0, "measured": True}] * 3
        self.assertEqual(F.classify_reachability(flow, healthy, baseline_loss_pct=0.0, now=T0).category, F.NO_FAULT)


# ----------------------------------------------------------------------------------------------------------------- decision
class DecisionTests(SimpleTestCase):
    def cl(self, category, **kw):
        return F.Classification(category, {"device": "R2", "interface": "Ethernet1"}, kw.pop("confirmed", True), F.CAUSE_UNDETERMINED,
                                "x", evidence=kw.pop("evidence", {"observed": {"admin": "up"}}), **kw)

    def test_admin_mismatch_is_auto_only_with_an_exact_standing_policy(self):
        c = self.cl(F.ADMIN_STATE_MISMATCH)
        d = F.decide(c, policy_lookup=lambda op: POLICY if (op["device"], op["interface"]) == ("R2", "Ethernet1") else None)
        self.assertEqual((d["outcome"], d["policy_id"], d["operation"]["kind"]), (F.AUTO_REMEDIATE, "ARP-R2-E1-002", "interface_enable"))
        d = F.decide(replace(c, scope={"device": "S4", "interface": "Ethernet3"}), policy_lookup=lambda op: None)
        self.assertEqual(d["outcome"], F.PROPOSE_FOR_APPROVAL)                       # appropriate but not authorized
        self.assertTrue(d["denied"][0].startswith("NO_STANDING_POLICY"))

    def test_non_administrative_faults_are_escalated_never_enabled(self):
        for cat in (F.OPERATIONAL_LINK_DOWN, F.LINK_FLAPPING, F.INTERFACE_DEGRADATION, F.ROUTING_ADJACENCY_FAILURE,
                    F.ROUTE_OR_REACHABILITY_FAILURE):
            with self.subTest(cat=cat):
                d = F.decide(self.cl(cat), policy_lookup=lambda op: POLICY)   # even a matching policy is irrelevant here
                self.assertEqual((d["outcome"], d["operation"]), (F.DIAGNOSE_AND_ESCALATE, None))
                self.assertTrue(d["requires_human"])
                self.assertTrue(any(r.startswith("STANDING_POLICIES_COVER_ONLY") for r in d["denied"]))
        d = F.decide(self.cl(F.OPERATIONAL_LINK_DOWN))
        self.assertTrue(d["denied"][0].startswith("INTERFACE_ENABLE_INEFFECTIVE"))

    def test_insufficient_and_healthy(self):
        self.assertEqual(F.decide(self.cl(F.INDETERMINATE, confirmed=False))["outcome"], F.INSUFFICIENT_EVIDENCE)
        self.assertEqual(F.decide(self.cl(F.NO_FAULT, confirmed=False))["outcome"], F.NO_ACTION_REQUIRED)


# ------------------------------------------------------------------------------------------------------------------- intake
class World:
    def __init__(self):
        self.t = T0
        self.state = {"R2": {"Ethernet1": ["connected", "up", 24], "Ethernet2": ["connected", "up", 2]},
                      "S4": {"Ethernet3": ["connected", "up", 24]}}
        self.config = {"R2": {"Ethernet1": "up"}, "S4": {"Ethernet3": "up"}}
        self.adj = {"R2": [("ospf", "192.168.255.3", "Vlan103", "full"), ("ospf", "192.168.255.4", "Vlan104", "full")]}
        # live R2 route-summary shape (normalised, 2026-11-17 capture)
        self.routes = {"R2": {"ipv4": {"bgp": 0, "connected": 8, "isis": 0, "ospf": 7, "ospf_external": 1, "rip": 9, "static": 1},
                              "ipv6": {"bgp": 0, "connected": 7, "isis": 5, "ospf3": 4, "ospf3_external": 0, "static": 2}}}

    def read_routes(self, device, cfg):
        fam = self.routes.get(device)
        return None if fam is None else {af: (None if c is None else dict(c)) for af, c in fam.items()}

    def read(self, device, cfg):
        return [sample(device, i, self.t, status=v[0], proto=v[1], changes=v[2]) for i, v in self.state[device].items()]

    def read_adj(self, device, cfg):
        return [F.AdjacencySample(device, p, n, i, st, self.t) for p, n, i, st in self.adj.get(device, [])]

    def set(self, dev, iface, status, proto, bump=0):
        row = self.state[dev][iface]
        row[0], row[1], row[2] = status, proto, row[2] + bump

    def carrier_loss(self):
        self.set("R2", "Ethernet1", "notconnect", "down", 1)
        self.set("S4", "Ethernet3", "notconnect", "down", 1)

    def heal(self):
        self.set("R2", "Ethernet1", "connected", "up", 1)
        self.set("S4", "Ethernet3", "connected", "up", 1)


class MultiFaultIntakeTests(TestCase):
    def setUp(self):
        self.world = World()
        self.mail, self.dispatched, self.flows_measured = [], [], []
        self.maintenance = ""

        def open_handoff(actor, case, **kw):
            self.handoff_kw = kw
            return SimpleNamespace(record_id="AIH-0123456789ab")

        self.deps = intake.IntakeDeps(run_case=lambda actor, cid, deps: None, open_handoff=open_handoff,
                                      dispatch=lambda hid: self.dispatched.append(hid) or True, notify=lambda s, b: self.mail.append((s, b)),
                                      policy_lookup=lambda op: POLICY if (op["device"], op["interface"]) == ("R2", "Ethernet1") else None,
                                      maintenance=lambda devs: self.maintenance,
                                      flows=lambda: [{"name": "H1-H2-v4"}, {"name": "H1-H2-v6"}],
                                      measure=lambda flows: self.flows_measured.append(1) or {f["name"]: {"loss_pct": 0.0} for f in flows},
                                      dispatch_active=lambda hid: self.unit_running)
        self.unit_running = True
        self.engine = self.make()

    def make(self, **kw):
        cfg = intake.IntakeConfig(devices=("R2", "S4"), confirm_seconds=30, cooldown_seconds=900, max_cases_per_hour=4,
                                  routing_devices=kw.pop("routing", ()), routing_every=1)
        return intake.Intake(cfg=cfg, reader=self.world.read, intent=INTENT.get, deps=self.deps, _peers=PEERS,
                             adjacency_reader=self.world.read_adj, route_reader=self.world.read_routes,
                             config_admin=lambda d, i, c: self.world.config[d][i], **kw)

    def poll(self, seconds):
        self.world.t = T0 + timedelta(seconds=seconds)
        return self.engine.poll(self.world.t)

    def audits(self, case, action):
        return list(models.TsAuditEvent.objects.filter(case=case, action=action).order_by("seq"))

    def test_operational_down_with_admin_up_opens_one_escalated_case_with_deterministic_evidence(self):
        self.poll(0)
        self.world.carrier_loss()
        self.assertEqual(self.poll(10), [])
        out = [r for r in self.poll(45) if "case" in r]
        self.assertEqual(len(out), 1, out)
        self.assertEqual((out[0]["category"], out[0]["decision"]), (F.OPERATIONAL_LINK_DOWN, F.DIAGNOSE_AND_ESCALATE))
        case = models.TsCase.objects.get(case_id=out[0]["case"])
        self.assertEqual(case.affected_scope["devices"], ["R2", "S4"])                    # both readable ends; no admin side
        self.assertEqual(case.service_intent["fault_category"], F.OPERATIONAL_LINK_DOWN)
        decision = self.audits(case, "REMEDIATION_DECISION")
        self.assertEqual([d.result for d in decision], [F.DIAGNOSE_AND_ESCALATE])
        self.assertIn("INTERFACE_ENABLE_INEFFECTIVE", decision[0].rationale)
        obs = models.TsObservation.objects.filter(case=case, key=f"{F.EVIDENCE_KEY}@Ethernet1", target="R2").get()
        self.assertEqual((obs.value["admin"], obs.value["oper"]), ("up", "down"))
        self.assertTrue(any("DIAGNOSE_AND_ESCALATE" in s for s, _ in self.mail))
        self.assertIn("OPERATIONAL_LINK_DOWN", self.handoff_kw["uncertainty"])
        self.assertNotIn("interface_enable", self.handoff_kw["uncertainty"])
        self.assertFalse(models.TsRemediationPlan.objects.exists())
        self.assertEqual(self.poll(60)[0]["skipped"], "OPEN_CASE_EXISTS")

    def test_flapping_is_one_incident_and_later_transitions_never_reopen_or_duplicate(self):
        self.poll(0)
        t = 0
        for _ in range(3):
            t += 10
            self.world.carrier_loss()
            self.poll(t)
            t += 10
            self.world.heal()
            res = self.poll(t)
        cases = models.TsCase.objects.all()
        self.assertEqual(cases.count(), 1, res)
        case = cases.get()
        self.assertEqual(case.service_intent["fault_category"], F.LINK_FLAPPING)
        self.assertEqual(self.audits(case, "REMEDIATION_DECISION")[0].result, F.DIAGNOSE_AND_ESCALATE)
        for _ in range(3):                                           # flapping continues, then the link stays down
            t += 10
            self.world.carrier_loss()
            self.poll(t)
        t += 60
        out = self.poll(t)
        self.assertEqual(models.TsCase.objects.count(), 1, out)
        self.assertEqual(len(self.dispatched), 1)

    def test_campaign_011_shape_is_unchanged_admin_side_scope_and_auto_decision(self):
        self.poll(0)
        self.world.set("R2", "Ethernet1", "disabled", "down", 1)
        self.world.set("S4", "Ethernet3", "notconnect", "down", 1)
        self.world.config["R2"]["Ethernet1"] = "down"
        self.poll(10)
        out = [r for r in self.poll(45) if "case" in r]
        case = models.TsCase.objects.get(case_id=out[0]["case"])
        self.assertEqual((case.trigger_ref, case.affected_scope["devices"]), ("LINK:R2:Ethernet1|S4:Ethernet3", ["R2"]))
        self.assertEqual(out[0]["decision"], F.AUTO_REMEDIATE)
        self.assertFalse(any("AUTO_REMEDIATE" in s for s, _ in self.mail))     # no escalation mail for a policy-covered fix

    def test_status_disabled_without_configured_shutdown_is_not_an_admin_fault(self):
        self.poll(0)
        self.world.set("R2", "Ethernet1", "disabled", "down", 1)             # status column says disabled ...
        self.world.set("S4", "Ethernet3", "notconnect", "down", 1)
        self.poll(10)                                                       # ... but the running config has no shutdown
        out = [r for r in self.poll(45) if "case" in r]
        self.assertEqual(out[0]["category"], F.OPERATIONAL_LINK_DOWN)

    def test_maintenance_suppresses_with_an_auditable_reason_notified_once(self):
        self.maintenance = "R2: maintenance MW-1 active"
        self.poll(0)
        self.world.carrier_loss()
        self.poll(10)
        out = self.poll(45)
        self.assertTrue(out[0]["skipped"].startswith("MAINTENANCE_ACTIVE"), out)
        self.poll(55)
        self.assertEqual(sum("MAINTENANCE_ACTIVE" in s for s, _ in self.mail), 1)
        self.assertFalse(models.TsCase.objects.exists())

    def test_adjacency_loss_during_a_link_incident_is_secondary_not_a_new_case(self):
        self.engine = self.make(routing=("R2",))
        self.poll(0)
        self.world.carrier_loss()
        self.world.adj["R2"] = []
        self.poll(10)
        self.poll(45)                                          # link case opens; adjacency loss confirmed in the same window
        out = self.poll(55)
        self.assertEqual(models.TsCase.objects.count(), 1, out)
        case = models.TsCase.objects.get()
        self.assertTrue(self.audits(case, "SECONDARY_SYMPTOM"), out)

    def test_standalone_adjacency_loss_opens_a_routing_case(self):
        self.engine = self.make(routing=("R2",))
        self.poll(0)
        self.world.adj["R2"] = self.world.adj["R2"][:1]
        self.poll(10)
        out = [r for r in self.poll(45) if "case" in r]
        self.assertEqual(out[0]["category"], F.ROUTING_ADJACENCY_FAILURE)
        self.assertEqual(out[0]["fingerprint"], "ADJ:R2:ospf:192.168.255.4")
        self.assertEqual(out[0]["decision"], F.DIAGNOSE_AND_ESCALATE)

    def test_a_dispatch_that_exited_without_progress_is_retried_and_audited(self):
        """22:35Z 2026-11-17: the unit started, then exited GLOBAL_LEASE_BUSY; intake recorded started=True and never retried."""
        from core.services.troubleshooting import ai

        self.deps.open_handoff = ai.open_handoff                     # a real OPEN handoff row (the engine shares this deps object)
        self.poll(0)
        self.world.carrier_loss()
        self.poll(10)
        case_id = [r for r in self.poll(45) if "case" in r][0]["case"]
        self.assertEqual(len(self.dispatched), 1)
        self.unit_running = True
        self.poll(200)
        self.assertEqual(len(self.dispatched), 1)                  # still running: never a second dispatcher
        self.unit_running = False                                  # the unit exited (lease busy) without touching the handoff
        later = int((datetime.now(timezone.utc) - T0).total_seconds()) + 400   # the dispatch audit carries wall-clock time
        out = [r for r in self.poll(later) if "dispatch_retry" in r]
        self.assertEqual((len(out), len(self.dispatched)), (1, 2))
        retry = models.TsAuditEvent.objects.get(case__case_id=case_id, action="INTAKE_DISPATCH_RETRY")
        self.assertIn("without progress", retry.rationale)

    def test_standalone_route_source_collapse_opens_one_routing_case_and_never_a_write(self):
        self.engine = self.make(routing=("R2",))
        self.poll(0)                                            # learns the baseline
        self.world.routes["R2"]["ipv4"]["rip"] = 0              # RIP routes vanish; adjacencies and links stay healthy
        self.assertEqual([r for r in self.poll(10) if "case" in r], [])          # debounce
        out = [r for r in self.poll(45) if "case" in r]
        self.assertEqual(len(out), 1, out)
        self.assertEqual((out[0]["fingerprint"], out[0]["category"], out[0]["decision"]),
                         ("RSRC:R2:ipv4:rip", F.ROUTE_OR_REACHABILITY_FAILURE, F.DIAGNOSE_AND_ESCALATE))
        self.assertEqual(self.poll(60)[0]["skipped"], "OPEN_CASE_EXISTS")
        self.assertFalse(models.TsRemediationPlan.objects.exists())

    def test_route_source_collapse_during_a_link_incident_is_secondary(self):
        self.engine = self.make(routing=("R2",))
        self.poll(0)
        self.world.carrier_loss()
        self.world.routes["R2"]["ipv4"]["ospf"] = 2             # OSPF lost most routes with the uplink
        self.world.routes["R2"]["ipv6"]["ospf3"] = 1
        self.poll(10)
        self.poll(45)
        out = self.poll(55)
        self.assertEqual(models.TsCase.objects.count(), 1, out)
        lines = [a.decision for a in self.audits(models.TsCase.objects.get(), "SECONDARY_SYMPTOM")]
        self.assertTrue(any("ospf routes 7 -> 2" in x for x in lines), lines)
        self.assertTrue(any("ospf3 routes 4 -> 1" in x for x in lines), lines)

    def test_route_sources_that_recover_before_confirmation_open_nothing_and_unreadable_decides_nothing(self):
        self.engine = self.make(routing=("R2",))
        self.poll(0)
        self.world.routes["R2"]["ipv4"]["rip"] = 1
        self.poll(10)
        self.world.routes["R2"]["ipv4"]["rip"] = 9
        self.poll(20)
        self.world.routes["R2"] = {"ipv4": None, "ipv6": None}
        self.assertEqual([r for r in self.poll(60) if "case" in r], [])
        self.assertFalse(models.TsCase.objects.exists())

    def test_externally_cleared_escalated_case_is_verified_and_closed_unresolved_never_resolved(self):
        self.poll(0)
        self.world.carrier_loss()
        self.poll(10)
        case_id = [r for r in self.poll(45) if "case" in r][0]["case"]
        self.world.heal()
        self.poll(60)
        self.assertEqual(models.TsCase.objects.get(case_id=case_id).state, "OPEN")       # not yet stable
        self.poll(130)
        out = self.poll(170)
        case = models.TsCase.objects.get(case_id=case_id)
        self.assertEqual(case.state, "UNRESOLVED", out)
        self.assertTrue(case.disposition["cleared_externally"])
        self.assertFalse(case.disposition["nmas_performed_repair"])
        self.assertTrue(case.disposition["protected_flows_baseline_ok"])
        self.assertTrue(self.audits(case, "FAULT_CLEARED_VERIFIED"))

    def test_policy_covered_admin_case_is_never_closed_by_the_intake(self):
        self.poll(0)
        self.world.set("R2", "Ethernet1", "disabled", "down", 1)
        self.world.config["R2"]["Ethernet1"] = "down"
        self.poll(10)
        case_id = [r for r in self.poll(45) if "case" in r][0]["case"]
        self.world.set("R2", "Ethernet1", "connected", "up", 1)
        for t in (60, 150, 200):
            self.poll(t)
        self.assertEqual(models.TsCase.objects.get(case_id=case_id).state, "OPEN")       # recovery owns it


class CodexOutageTests(TestCase):
    """Deterministic monitoring survives an AI-path outage: case, evidence, classification and decision persist; no model
    conclusion is invented; nothing executes; dispatch is retried and recovers when the path returns."""

    def test_outage_preserves_deterministic_case_and_dispatch_recovers(self):
        from core.services.troubleshooting import ai

        world, mail, attempts = World(), [], []
        available = {"up": False}

        def dispatch(hid):
            attempts.append(hid)
            return available["up"]

        deps = intake.IntakeDeps(run_case=lambda actor, cid, d: None, open_handoff=ai.open_handoff, dispatch=dispatch,
                                 notify=lambda s, b: mail.append(s), policy_lookup=lambda op: None, maintenance=lambda d: "",
                                 flows=lambda: [], measure=lambda f: {}, dispatch_active=lambda hid: True)
        cfg = intake.IntakeConfig(devices=("R2", "S4"), confirm_seconds=30)
        engine = intake.Intake(cfg=cfg, reader=world.read, intent=INTENT.get, deps=deps, _peers=PEERS, config_admin=lambda d, i, c: "up")
        now = datetime.now(timezone.utc)
        world.t = now
        engine.poll(now)
        world.carrier_loss()
        engine.poll(now + timedelta(seconds=10))
        out = [r for r in engine.poll(now + timedelta(seconds=45)) if "case" in r]
        self.assertFalse(out[0]["dispatch_started"])
        case = models.TsCase.objects.get(case_id=out[0]["case"])
        self.assertEqual(case.service_intent["fault_category"], F.OPERATIONAL_LINK_DOWN)
        self.assertEqual(self.result(case, "INTAKE_DISPATCH"), ["NOT_STARTED"])
        self.assertEqual(self.result(case, "REMEDIATION_DECISION"), [F.DIAGNOSE_AND_ESCALATE])
        self.assertTrue(models.TsObservation.objects.filter(case=case, key__startswith=F.EVIDENCE_KEY).exists())
        self.assertFalse(models.TsRemediationPlan.objects.filter(case=case).exists())           # nothing proposed or executed
        self.assertFalse(models.TsHypothesis.objects.filter(case=case, basis="AI_INFERRED").exists())   # no invented conclusion
        self.assertTrue(any("could not start Codex dispatch" in s for s in mail))
        handoff = models.TsAIHandoff.objects.get(case=case)
        self.assertEqual(handoff.status, "OPEN")                                                 # preserved for continuation
        engine.poll(now + timedelta(seconds=100))                                                # inside the retry interval
        self.assertEqual(len(attempts), 1)
        engine.poll(now + timedelta(seconds=45 + intake.DISPATCH_RETRY_SECONDS + 1))
        self.assertEqual(self.result(case, "INTAKE_DISPATCH_RETRY"), ["NOT_STARTED"])
        available["up"] = True
        engine.poll(now + timedelta(seconds=45 + 2 * intake.DISPATCH_RETRY_SECONDS + 2))
        self.assertEqual(self.result(case, "INTAKE_DISPATCH_RETRY"), ["NOT_STARTED", "OK"])
        engine.poll(now + timedelta(seconds=45 + 4 * intake.DISPATCH_RETRY_SECONDS))
        self.assertEqual(len(attempts), 3)                                                       # stops once started
        self.assertEqual(repo.verify_audit_chain(case), [])

    @staticmethod
    def result(case, action):
        return list(models.TsAuditEvent.objects.filter(case=case, action=action).order_by("seq").values_list("result", flat=True))


# ---------------------------------------------------------------------------------------------------------- governance
class GovernanceNegativeTests(TestCase):
    NOW = datetime(2026, 11, 17, 6, 0, tzinfo=timezone.utc)
    OP = {"kind": "interface_enable", "device": "R2", "interface": "Ethernet1", "intended_state": "admin_up"}
    POL = gov.RecoveryPolicy(id="ARP-R2-E1-002", owner_authorization="OWNER", device="R2", interface="Ethernet1",
                             kind="interface_enable", intended_state="admin_up", expires_at=NOW + timedelta(days=1),
                             max_executions=10, cooldown_seconds=600, enabled=True)
    CTX = gov.RecoveryContext(now=NOW, executions=(), authoritative_intent="admin_up", observed_admin_state="down",
                              observed_at=NOW - timedelta(seconds=20), maintenance_active=False, conflicting_change=False,
                              management_path_healthy=True, protected_flows_healthy=True, rollback_ready=True, observed_oper_state="down")

    def decide(self, policy=None, op=None, **ctx):
        return gov.evaluate_recovery_policy(self.POL if policy is None else policy, op or self.OP, replace(self.CTX, **ctx), risk="HIGH")

    def test_campaign_011_facts_still_authorize(self):
        self.assertTrue(self.decide()["authorized"])

    def test_enable_cannot_run_when_admin_already_up_and_oper_down(self):
        d = self.decide(observed_admin_state="up", observed_oper_state="down")
        self.assertEqual((d["authorized"], d["noop"]), (False, False))           # a refusal, NOT an idempotent success
        self.assertIn("INEFFECTIVE_OPERATION_ADMIN_UP_OPER_DOWN", d["reasons"])
        self.assertTrue(self.decide(observed_admin_state="up", observed_oper_state="up")["noop"])

    def test_contradictory_evidence_blocks(self):
        self.assertIn("CONTRADICTORY_EVIDENCE", self.decide(observed_admin_state="down", observed_oper_state="up")["reasons"])

    def test_policy_cannot_authorize_bounce_shutdown_or_routing_changes(self):
        for kind in ("interface_bounce", "interface_shutdown", "routing_metric_change", "neighbor_reset", "process_restart"):
            with self.subTest(kind=kind):
                op = {"kind": kind, "device": "R2", "interface": "Ethernet1"}
                self.assertIn("POLICY_SCOPE_MISMATCH", self.decide(op=op)["reasons"])
                rogue = replace(self.POL, kind=kind)                       # even a policy that names it is refused
                self.assertIn("POLICY_OPERATION_NOT_RECOVERABLE", self.decide(policy=rogue, op=op)["reasons"])

    def test_wrong_target_expired_exhausted_maintenance_and_management(self):
        self.assertIn("POLICY_SCOPE_MISMATCH", self.decide(op={**self.OP, "device": "S4", "interface": "Ethernet3"})["reasons"])
        self.assertIn("POLICY_EXPIRED", self.decide(policy=replace(self.POL, expires_at=self.NOW))["reasons"])
        self.assertIn("EXECUTION_LIMIT_EXHAUSTED", self.decide(executions=(self.NOW - timedelta(days=1),) * 10)["reasons"])
        self.assertIn("MAINTENANCE_ACTIVE", self.decide(maintenance_active=True)["reasons"])
        self.assertIn("MANAGEMENT_PATH_NOT_HEALTHY", self.decide(management_path_healthy=False)["reasons"])
        self.assertIn("POLICY_NOT_ACTIVE", self.decide(policy=replace(self.POL, enabled=False))["reasons"])

    def _case(self, admin: str):
        actor = repo.Actor("nmas-intake", "system", tenant="default", devices=frozenset({"R2", "S4"}))
        now = datetime.now(timezone.utc)
        case = repo.open_case(actor, trigger_source="monitoring", trigger_ref=f"TEST:{admin}", title="t", symptom="t",
                              affected_scope={"devices": ["R2", "S4"]}, target_states={"R2": "UNKNOWN", "S4": "UNKNOWN"}, runbook="RB02",
                              service_intent={"service": "test"},
                              idempotency_key=f"t-{admin}", now=now)
        ev = repo.store_evidence(actor, case, source_type="device_state", device="R2", command_or_api="show interfaces | json",
                                 collected_at=now, raw=f"admin={admin}")
        repo.record_observation(actor, case, key=f"{F.EVIDENCE_KEY}@Ethernet1", target="R2", observed_at=now,
                                value={"admin": admin, "oper": "down"}, evidence=ev)
        return case, ev

    def _propose(self, case, ev, ops):
        from core.tests.test_troubleshooting_governance import make_ports
        agent = repo.Actor("codex", "agent", tenant="default", devices=frozenset({"R2", "S4"}))
        return gov.propose(agent, case, operations=ops, causal_evidence_ids=[ev.evidence_id], rollback_plan={"steps": ["restore"]},
                           addressed_fault="R2 Ethernet1 down", ports=make_ports())

    def test_model_proposed_enable_on_an_admin_up_interface_is_rejected_visibly(self):
        case, ev = self._case("up")
        with self.assertRaises(gov.GovernanceRefused) as ctx:
            self._propose(case, ev, [self.OP])
        self.assertEqual(ctx.exception.code, "INEFFECTIVE_OPERATION")
        self.assertFalse(models.TsRemediationPlan.objects.filter(case=case).exists())
        self.assertTrue(models.TsAuditEvent.objects.filter(case=case, action="PROPOSAL_REJECTED").exists())

    def test_enable_on_an_admin_down_interface_is_still_accepted(self):
        case, ev = self._case("down")
        self.assertEqual(self._propose(case, ev, [self.OP]).status, "RISK_ASSESSED")

    def test_unsafe_model_proposal_cannot_bypass_the_change_engine(self):
        case, ev = self._case("up")
        plan = self._propose(case, ev, [{"kind": "interface_bounce", "device": "R2", "interface": "Ethernet1"}])
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump({"schema": "x", "policies": [{**POLICY, "enabled": True, "expires_at": "2099-01-01T00:00:00Z",
                                                    "intended_state": "admin_up"}]}, fh)
        with self.settings(NMAS_TS_RECOVERY_POLICY_FILE=fh.name):
            self.assertNotIn(plan.record_id, recovery.pending_plans())
            with self.assertRaises(recovery.RecoveryRefused) as ctx:
                recovery.recover(plan.record_id)
            self.assertEqual(ctx.exception.code, "NO_POLICY")
            self.assertIn(plan.record_id, recovery.undecided_plans())
            sent = []
            d = recovery.record_plan_decision(plan.record_id, send=lambda s, b: sent.append(s))
            self.assertEqual(d["outcome"], "PROPOSE_FOR_APPROVAL")
            self.assertTrue(any(r.startswith("NOT_PREAUTHORIZABLE: interface_bounce") for r in d["denied"]))
            self.assertNotIn(plan.record_id, recovery.undecided_plans())          # recorded exactly once
        plan.refresh_from_db()
        self.assertEqual(plan.status, "RISK_ASSESSED")
        self.assertFalse(models.TsActionExecution.objects.filter(plan=plan).exists())
        self.assertFalse(models.Change.objects.exists())
        self.assertEqual(len(sent), 1)
        Path(fh.name).unlink()


# --------------------------------------------------------------------------------------------------------------- harness
def flap_policy():
    path = Path(__file__).parents[3] / "deploy" / "sandbox" / "fault-campaign.fixture.json"
    value = json.loads(path.read_text(encoding="utf-8"))
    value["allowed_faults"][0].update(fault_type="link_flap", maximum_seconds=200, flap={"cycles": 4, "down_seconds": 8, "up_seconds": 12})
    return value


class LinkFaultHarnessTests(SimpleTestCase):
    NOW = datetime(2026, 11, 15, 21, 0, tzinfo=timezone.utc)

    def test_flap_spec_is_bounded_and_must_end_before_the_deadline(self):
        fi.validate_policy(flap_policy(), now=self.NOW)
        for mutate, code in ((lambda f: f["flap"].update(cycles=50), "INVALID_FLAP_SPEC"),
                             (lambda f: f["flap"].pop("cycles"), "INVALID_FLAP_SPEC"),
                             (lambda f: f.pop("flap"), "INVALID_FAULT_ENTRY"),
                             (lambda f: f.update(maximum_seconds=60), "FLAP_EXCEEDS_DEADLINE"),
                             (lambda f: f["flap"].update(command="ip link"), "FORBIDDEN_POLICY_FIELD")):
            value = flap_policy()
            mutate(value["allowed_faults"][0])
            with self.subTest(code=code), self.assertRaisesRegex(fi.FaultRefused, code):
                fi.validate_policy(value, now=self.NOW)
        other = flap_policy()
        other["allowed_faults"][0].update(fault_type="carrier_loss")
        with self.assertRaisesRegex(fi.FaultRefused, "INVALID_FAULT_ENTRY"):         # flap spec only on link_flap
            fi.validate_policy(other, now=self.NOW)

    class FakeNode:
        """Records argv; emulates one cEOS interface config and its kernel veth end."""

        def __init__(self, fail_on_down=0):
            self.calls, self.kernel_up, self.downs, self.fail_on_down = [], True, 0, fail_on_down

        def __call__(self, argv, timeout=20):
            self.calls.append(argv)
            if argv[3:5] == ["ip", "-j"]:
                flags = ["UP", "LOWER_UP"] if self.kernel_up else []
                return 0, json.dumps([{"flags": flags}])
            if argv[3:6] == ["ip", "link", "set"]:
                if argv[-1] == "down":
                    self.downs += 1
                    if self.fail_on_down and self.downs >= self.fail_on_down:
                        raise RuntimeError("boom")
                self.kernel_up = argv[-1] == "up"
                return 0, ""
            if argv[3] == "Cli":
                return 0, "interface Ethernet3\n   switchport mode trunk\n"
            return 0, "5 packets transmitted, 5 received, 0% packet loss"

    def driver(self, node):
        return fi.ContainerlabCeosDriver("srlceos01", {}, run=node, management_probe=lambda: True)

    def fault(self, kind="carrier_loss", **kw):
        return {"device": "S4", "platform": "arista_ceos", "object_name": "Ethernet3", "fault_type": kind,
                "flap": {"cycles": 3, "down_seconds": 0, "up_seconds": 0}, **kw}

    def test_carrier_loss_touches_only_the_kernel_link_and_rollback_restores_it(self):
        node = self.FakeNode()
        d = self.driver(node)
        base = d.capture_baseline(self.fault())
        receipt = d.inject(self.fault(), "op1")
        self.assertTrue(receipt["verified_link_down"] and receipt["config_unchanged_admin_up"])
        writes = [c for c in node.calls if c[3:6] == ["ip", "link", "set"]]
        self.assertEqual(writes, [["/usr/bin/docker", "exec", "clab-srlceos01-S4", "ip", "link", "set", "dev", "eth3", "down"]])
        self.assertFalse(any("configure" in " ".join(c) for c in node.calls))            # no device configuration write
        self.assertFalse(d.matches_baseline(self.fault(), base))
        self.assertTrue(d.rollback(self.fault(), base, "op2")["restored"])

    def test_flap_is_bounded_and_always_leaves_the_link_up_even_on_error(self):
        from unittest import mock
        node = self.FakeNode()
        d = self.driver(node)
        with mock.patch("time.sleep"):
            r = d.inject(self.fault("link_flap"), "op")
        self.assertEqual((r["cycles_completed"], r["final_link_up"]), (3, True))
        self.assertEqual([t["state"] for t in r["transitions"]], ["down", "up"] * 3)
        node = self.FakeNode(fail_on_down=2)
        d = self.driver(node)
        with mock.patch("time.sleep"), self.assertRaises(RuntimeError):
            d.inject(self.fault("link_flap"), "op")
        self.assertTrue(node.kernel_up)                                                  # finally: link restored

    def test_flap_stops_early_on_protected_flow_degradation(self):
        from unittest import mock
        node = self.FakeNode()
        d = self.driver(node)
        d._flow_stop = lambda: True                                                      # pylint: disable=protected-access
        with mock.patch("time.sleep"):
            r = d.inject(self.fault("link_flap"), "op")
        self.assertEqual((r["cycles_completed"], r["stopped"]), (1, "protected-flow stop condition"))
        self.assertTrue(node.kernel_up)

    def test_controller_marks_link_faults_active_before_touching_the_link(self):
        with tempfile.TemporaryDirectory() as tmp:
            pol = flap_policy()
            store = fi.StateStore(tmp, pol["campaign"]["id"])
            seen = {}

            class Probe(fi.FixtureDriver):
                def inject(self, fault, operation_id):
                    seen["status"] = store.load()["status"]
                    return super().inject(fault, operation_id)

            ctl = fi.CampaignController(pol, pol["allowed_faults"][0]["id"], store, Probe(), now=lambda: self.NOW)
            confirm = fi.policy_digest(pol)[:16]
            ctl.prepare(authorization_id=pol["campaign"]["authorization_id"], confirm=confirm)
            out = ctl.inject(authorization_id=pol["campaign"]["authorization_id"], confirm=confirm)
            self.assertEqual((seen["status"], out["status"]), ("ACTIVE", "ACTIVE"))
            events = [e["event"] for e in store.load()["events"]]
            self.assertEqual(events[:3], ["ARMED", "INJECTING", "INJECTED"])
            self.assertEqual(ctl.rollback(reason="test")["status"], "RESTORED")


# ------------------------------------------------------------------------------------- operational-down acceptance matrix (§4)
class OperationalDownAcceptanceMatrixTests(SimpleTestCase):
    """The four states the live campaign must tell apart, and the remediation consequence of each."""

    def classify(self, rows):
        h = hist(*rows)
        return F.classify_interface(rows[-1], "up", h, now=rows[-1].at, confirm_seconds=30)

    def test_matrix(self):
        t = [T0 + timedelta(seconds=s) for s in (0, 31)]
        admin_down = self.classify([sample("S2", "Ethernet4", x, status="disabled", proto="down") for x in t])
        oper_down = self.classify([sample("S2", "Ethernet4", x, status="notconnect", proto="down") for x in t])
        healthy = self.classify([sample("S2", "Ethernet4", x) for x in t])
        flapping = self.classify([sample("S2", "Ethernet4", T0 + timedelta(seconds=10 * i), status="connected" if i % 2 else "notconnect",
                                         proto="up" if i % 2 else "down") for i in range(6)])
        self.assertEqual([c.category for c in (admin_down, oper_down, healthy, flapping)],
                         [F.ADMIN_STATE_MISMATCH, F.OPERATIONAL_LINK_DOWN, F.NO_FAULT, F.LINK_FLAPPING])
        enable_everywhere = lambda op: {"id": "ANY"}                                   # noqa: E731 - even an all-matching policy
        self.assertEqual(F.decide(admin_down, policy_lookup=enable_everywhere)["operation"]["kind"], "interface_enable")
        for c in (oper_down, flapping):
            d = F.decide(c, policy_lookup=enable_everywhere)
            self.assertEqual((d["outcome"], d["operation"]), (F.DIAGNOSE_AND_ESCALATE, None))
        self.assertEqual(F.decide(healthy)["outcome"], F.NO_ACTION_REQUIRED)

    def test_a_brief_outage_is_never_reported_as_sustained_operational_down(self):
        rows = [sample("S2", "Ethernet4", T0, status="notconnect", proto="down"),
                sample("S2", "Ethernet4", T0 + timedelta(seconds=10), status="connected")]
        self.assertNotEqual(self.classify(rows).category, F.OPERATIONAL_LINK_DOWN)
        self.assertEqual(self.classify(rows[:1]).category, F.INDETERMINATE)                  # inside the 30 s confirmation


# ---------------------------------------------------------------------------------------------------- peer_carrier_loss
def peer_policy(**fault):
    value = flap_policy()
    f = value["allowed_faults"][0]
    for key in ("flap", "management_path_ref", "identity_verified", "lifecycle_eligible", "write_eligible"):
        f.pop(key)
    f.update({"device": "S2", "platform": "arista_ceos", "object_name": "Ethernet4", "fault_type": "peer_carrier_loss", "maximum_seconds": 240,
              "peer": {"node": "H4", "interface": "eth1"}, "observation_only": True, **fault})
    return value


class PeerCarrierLossTests(SimpleTestCase):
    NOW = datetime(2026, 11, 15, 21, 0, tzinfo=timezone.utc)

    def test_policy_is_observation_only_and_peer_allowlisted(self):
        fi.validate_policy(peer_policy(), now=self.NOW)
        bad = {"PEER_NOT_ALLOWED": [{"peer": {"node": "H1", "interface": "eth1"}}, {"peer": {"node": "R4", "interface": "eth1"}},
                                    {"peer": {"node": "H4", "interface": "eth0"}}],
               "PEER_FAULT_MUST_BE_OBSERVATION_ONLY": [{"observation_only": False}],
               "INVALID_PEER_SPEC": [{"peer": {"node": "H4"}}]}
        for code, variants in bad.items():
            for kw in variants:
                with self.subTest(kw=kw), self.assertRaisesRegex(fi.FaultRefused, code):
                    fi.validate_policy(peer_policy(**kw), now=self.NOW)
        claims = peer_policy()
        claims["allowed_faults"][0]["write_eligible"] = True                     # no write-eligibility claim for a peer fault
        with self.assertRaisesRegex(fi.FaultRefused, "INVALID_FAULT_ENTRY"):
            fi.validate_policy(claims, now=self.NOW)

    def test_peer_must_be_the_tracked_topology_peer(self):
        self.assertEqual(fi.topology_peer("srlceos01", "S2", "eth4"), ("H4", "eth1"))
        self.assertEqual(fi.topology_peer("srlceos01", "R2", "eth1"), ("S4", "eth3"))
        drv = fi.ContainerlabCeosDriver("srlceos01", {}, run=lambda argv, timeout=20: (0, ""), management_probe=lambda: True)
        with self.assertRaisesRegex(fi.FaultRefused, "PEER_NOT_TOPOLOGY_LINK"):
            drv._peer_target(peer_policy(peer={"node": "H3", "interface": "eth1"})["allowed_faults"][0])  # pylint: disable=protected-access

    class Lab:
        """S2 (cEOS, config + Et4 status) and H4 (Linux end host) behind a fake docker exec."""

        def __init__(self, reassert=False, dynamic=False):
            self.calls, self.h4_up, self.keep, self.reassert, self.rs_pending = [], True, "0", reassert, False
            self.dynamic = dynamic

        def __call__(self, argv, timeout=20):
            self.calls.append(argv)
            c, rest = argv[2], argv[3:]
            if c.endswith("-S2"):
                if rest[:3] == ["ip", "-j", "link"]:
                    return 0, json.dumps([{"flags": ["UP", "LOWER_UP"] if self.carrier() else ["UP"]}])
                if rest[0] == "Cli" and rest[-1].startswith("show running-config"):
                    return 0, "interface Ethernet4\n   description H4_VLAN30\n   switchport access vlan 30\n"
                if rest[0] == "Cli":
                    up = self.carrier()
                    return 0, json.dumps({"interfaces": {"Ethernet4": {"interfaceStatus": "connected" if up else "notconnect",
                                                                       "lineProtocolStatus": "up" if up else "down",
                                                                       "interfaceCounters": {"linkStatusChanges": 4}}}})
            if c.endswith("-H4"):
                if rest[:3] == ["ip", "-j", "addr"]:
                    row = {"family": "inet6", "local": "2001:db8:30::18e5", "prefixlen": 128, "scope": "global",
                           "valid_life_time": 4294967295, "preferred_life_time": 4294967295}
                    if self.dynamic:                              # a DHCPv6 lease as dhclient-script installs it
                        row.update(dynamic=True, valid_life_time=28800, preferred_life_time=7200)
                    return 0, json.dumps([{"flags": ["UP", "LOWER_UP"] if self.h4_up else [], "addr_info": [row]}])
                if rest[:2] == ["ip", "-j"]:
                    routes = [] if rest[2] == "-4" or not self.h4_up else [{"dst": "default", "gateway": "fe80::99", "protocol": "ra",
                                                                             "metric": 1024}]
                    if self.rs_pending:                                   # first read after link-up: RA not yet received
                        self.rs_pending, routes = False, []
                    return 0, json.dumps(routes)
                if rest[:2] == ["sysctl", "-n"]:
                    return 0, self.keep + "\n"
                if rest[:2] == ["sysctl", "-w"]:
                    self.keep = rest[2].rsplit("=", 1)[1]
                    return 0, ""
                if rest[:3] == ["ip", "link", "set"]:
                    self.h4_up = rest[-1] == "up"
                    self.rs_pending = self.h4_up
                    return 0, ""
            return 1, ""

        def carrier(self):
            return self.h4_up or self.reassert

    def run_fault(self, lab):
        from unittest import mock
        drv = fi.ContainerlabCeosDriver("srlceos01", {}, run=lab, management_probe=lambda: True)
        fault = peer_policy()["allowed_faults"][0]
        with mock.patch("time.sleep"):
            base = drv.capture_baseline(fault)
            receipt = drv.inject(fault, "op1")
            matched_during = drv.matches_baseline(fault, base)
            rollback = drv.rollback(fault, base, "op2")
        return base, receipt, matched_during, rollback

    def test_held_fault_is_admin_up_oper_down_and_rollback_restores_the_host_exactly(self):
        lab = self.Lab()
        base, receipt, during, rollback = self.run_fault(lab)
        self.assertEqual((base["peer"]["keep_addr_on_down"], base["device_status"]["interfaceStatus"]), ("0", "connected"))
        self.assertTrue(receipt["held"] and receipt["config_unchanged_admin_up"])
        self.assertEqual({(c["interfaceStatus"], c["lineProtocolStatus"]) for c in receipt["hold_checks"]}, {("notconnect", "down")})
        self.assertFalse(during)
        self.assertTrue(rollback["restored"])
        self.assertEqual((lab.h4_up, lab.keep), (True, "0"))                                   # sysctl restored to its baseline
        writes = [c for c in lab.calls if c[3:5] in (["ip", "link"], ["sysctl", "-w"])]
        self.assertTrue(all(c[2] == "clab-srlceos01-H4" for c in writes))                     # only the end host is touched
        self.assertFalse(any("configure" in " ".join(c) for c in lab.calls))                  # S2 is read, never configured

    def test_dynamic_peer_address_refuses_before_anything_is_touched(self):
        """Campaign 017 regression: H4's DHCPv6 /128 (finite lifetime) was flushed on link down despite keep_addr_on_down=1
        and the rollback could not verify the baseline.  The harness must refuse at baseline time, with no write."""
        lab = self.Lab(dynamic=True)
        drv = fi.ContainerlabCeosDriver("srlceos01", {}, run=lab, management_probe=lambda: True)
        with self.assertRaisesRegex(fi.FaultRefused, "PEER_ADDRESS_NOT_PRESERVABLE"):
            drv.capture_baseline(peer_policy()["allowed_faults"][0])
        self.assertFalse([c for c in lab.calls if c[3:5] in (["ip", "link"], ["sysctl", "-w"])])

    def test_a_reasserted_link_is_reported_as_not_held(self):
        _base, receipt, _during, _rollback = self.run_fault(self.Lab(reassert=True))
        self.assertFalse(receipt["held"])

    def test_controller_rolls_back_immediately_when_the_fault_does_not_hold(self):
        with tempfile.TemporaryDirectory() as tmp:
            pol = peer_policy()
            store = fi.StateStore(tmp, pol["campaign"]["id"])

            class NotHeld(fi.FixtureDriver):
                def inject(self, fault, operation_id):
                    super().inject(fault, operation_id)
                    return {"operation_id": operation_id, "accepted": True, "held": False, "hold_checks": []}

            ctl = fi.CampaignController(pol, pol["allowed_faults"][0]["id"], store, NotHeld(), now=lambda: self.NOW)
            confirm = fi.policy_digest(pol)[:16]
            ctl.prepare(authorization_id=pol["campaign"]["authorization_id"], confirm=confirm)
            out = ctl.inject(authorization_id=pol["campaign"]["authorization_id"], confirm=confirm)
            self.assertEqual(out["status"], "RESTORED")
            self.assertTrue(any("INJECTION_NOT_HELD" in str(e.get("reason")) for e in store.load()["events"]))


class StandaloneOperationalDownIntakeTests(TestCase):
    """The live-campaign shape: S2 Ethernet4 (end-host peer, not an intake device) goes admin UP / oper DOWN."""

    def test_one_iface_case_escalated_and_never_enable(self):
        world = World()
        world.state = {"S2": {"Ethernet4": ["connected", "up", 4]}}
        world.config = {"S2": {"Ethernet4": "up"}}
        handoffs, mail = [], []
        deps = intake.IntakeDeps(run_case=lambda a, c, d: None, open_handoff=lambda actor, case, **kw: handoffs.append(kw) or
                                 SimpleNamespace(record_id="AIH-00000000000a"), dispatch=lambda hid: True,
                                 notify=lambda s, b: mail.append(s), policy_lookup=lambda op: {"id": "ANY"},   # even a matching policy
                                 maintenance=lambda d: "", flows=lambda: [], measure=lambda f: {})
        engine = intake.Intake(cfg=intake.IntakeConfig(devices=("S2",), confirm_seconds=30), reader=world.read,
                               intent={"S2": {"Ethernet4": "up"}}.get, deps=deps, _peers={},
                               config_admin=lambda d, i, c: world.config[d][i])
        world.t = T0
        engine.poll(T0)
        world.set("S2", "Ethernet4", "notconnect", "down", 1)
        for s in (10, 20):
            world.t = T0 + timedelta(seconds=s)
            self.assertFalse([r for r in engine.poll(world.t) if "case" in r])       # debounce: not yet sustained
        world.t = T0 + timedelta(seconds=45)
        out = [r for r in engine.poll(world.t) if "case" in r]
        self.assertEqual(len(out), 1)
        self.assertEqual((out[0]["fingerprint"], out[0]["category"], out[0]["decision"]),
                         ("IFACE:S2:Ethernet4", F.OPERATIONAL_LINK_DOWN, F.DIAGNOSE_AND_ESCALATE))
        case = models.TsCase.objects.get(case_id=out[0]["case"])
        self.assertEqual(case.affected_scope["devices"], ["S2"])
        d = models.TsAuditEvent.objects.get(case=case, action="REMEDIATION_DECISION")
        self.assertIn("INTERFACE_ENABLE_INEFFECTIVE", d.rationale)
        self.assertNotIn("interface_enable", handoffs[0]["uncertainty"])
        world.t = T0 + timedelta(seconds=60)
        self.assertEqual([r.get("skipped") for r in engine.poll(world.t)], ["OPEN_CASE_EXISTS"])
