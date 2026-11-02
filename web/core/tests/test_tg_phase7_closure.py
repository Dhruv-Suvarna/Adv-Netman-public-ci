"""Test-governance closure for V2 Phase 7 (``core.services.decommission`` and the lifecycle / transaction edges it added): every
function called directly, with an accepting and a refusing case where it has both.

The workflows themselves are proven end to end in ``test_decommission_service`` over the REAL cEOS executor."""

from __future__ import annotations

import json
from datetime import timedelta
from types import SimpleNamespace

from django.test import SimpleTestCase, TestCase, override_settings
from django.utils import timezone

from core import models
from core.services.decommission import dependencies, eos, observe, readiness, service as svc
from core.services.devices import lifecycle
from core.services.isolation import transaction as governed
from core.services.maintenance_mode import model
from core.tests.helpers import decommission as H
from core.tests.helpers import lifecycle as L

D, R, S = models.DecommissionState, models.RestorationState, models.DeviceLifecycleState
OPERATOR, APPROVER = L.OPERATOR, L.APPROVER


# ------------------------------------------------------------------------------------------------------------- eos
class EosClosureTests(SimpleTestCase):
    def test_eos_parsers_build_blocks_paths_and_ops(self):
        text = H.router_config()
        sections = eos.blocks(text)
        self.assertEqual(sections["router ospf 1"][0], "router ospf 1")
        self.assertEqual(eos.paths(["router ospf 1", "   router-id 1.1.1.1"]), ["router ospf 1", "router ospf 1 > router-id 1.1.1.1"])
        self.assertEqual(eos.op("k", "ADD", ["a"], ["no a"], ["a"], "d")["inverse"], ["no a"])
        self.assertEqual(eos.routing_processes(text), ["router ospf 1", "ipv6 router ospf 1"])
        self.assertEqual(eos.ospf_processes(text), {"IPV4": "router ospf 1", "IPV6": "ipv6 router ospf 1"})
        self.assertEqual(eos.interface_address(["interface E1", "   ip address 10.0.0.1/31"]), ["10.0.0.1"])
        self.assertEqual(eos.management_interfaces(text, [H.MGMT]), ["Ethernet5"])
        self.assertEqual(eos.production_interfaces(text, ["Ethernet5"]), ["Ethernet1", "Ethernet2"])
        self.assertEqual((eos.PlanError("X", "d" * 400).code, len(eos.PlanError("X", "d" * 400).detail)), ("X", 300))

    def test_eos_parsers_return_empty_for_empty_text(self):
        self.assertEqual(eos.blocks(""), {})
        self.assertEqual(eos.paths([]), [])
        self.assertEqual(eos.routing_processes(""), [])
        self.assertEqual(eos.ospf_processes("hostname x\n"), {})
        self.assertEqual(eos.interface_address(["interface E1", "   description x"]), [])
        self.assertEqual(eos.management_interfaces(H.router_config(), ["192.0.2.1"]), [])
        shut = H.router_config().replace("   description to E1", "   description to E1\n   shutdown")
        self.assertNotIn("Ethernet1", eos.production_interfaces(shut, ["Ethernet5"]))
        self.assertEqual(eos.PlanError("NOTHING").detail, "")
        self.assertEqual(eos.op("k", "REMOVE", [], [], [], "")["lines"], [])

    def test_render_decommission_with_transition_orders_cost_out_first(self):
        plan = eos.render_decommission(H.router_config(), management_addresses=[H.MGMT], transition=True)
        self.assertEqual([o["key"] for o in plan["transition"]], ["cost-out-ipv4", "cost-out-ipv6"])
        removal = {o["key"]: o for o in plan["removal"]}
        self.assertIn("shutdown-Ethernet1", removal)
        self.assertIn("   max-metric router-lsa", removal["remove-router-ospf-1"]["inverse"])
        self.assertNotIn("shutdown-Ethernet5", removal)

    def test_render_decommission_refuses_unknown_management_missing_mechanism_and_nothing_left(self):
        for kwargs, code in ((dict(text=H.router_config(), management_addresses=["192.0.2.9"], transition=False), "MANAGEMENT_INTERFACE_UNKNOWN"),
                             (dict(text=H.router_config(ospf=False, ospf6=False), management_addresses=[H.MGMT], transition=True),
                              "TRANSITION_MECHANISM_UNAVAILABLE"),
                             (dict(text="interface Ethernet5\n   ip address 10.254.70.2/24\n", management_addresses=[H.MGMT], transition=False),
                              "NOTHING_TO_DECOMMISSION"),
                             (dict(text=H.router_config(extra="router ospf 1\n   max-metric router-lsa"), management_addresses=[H.MGMT],
                                   transition=True), "TRANSITION_ALREADY_PRESENT")):
            with self.subTest(code=code), self.assertRaises(eos.PlanError) as caught:
                eos.render_decommission(kwargs["text"], management_addresses=kwargs["management_addresses"], transition=kwargs["transition"])
            self.assertEqual(caught.exception.code, code)

    def test_render_restore_reverses_the_removal(self):
        before = H.router_config()
        after = before.replace("router ospf 1\n   router-id 10.254.255.2\n   network 10.254.81.0/31 area 0.0.0.0\n!\n", "") \
            .replace("   description to E1", "   description to E1\n   shutdown")
        plan = eos.render_restore(before, after, management_addresses=[H.MGMT])
        keys = [o["key"] for o in plan["operations"]]
        self.assertEqual(keys, ["restore-router-ospf-1", "no-shutdown-Ethernet1"])

    def test_render_restore_refuses_conflict_and_nothing_to_restore(self):
        with self.assertRaises(eos.PlanError) as caught:
            eos.render_restore(H.router_config(), H.router_config(), management_addresses=[H.MGMT])
        self.assertEqual(caught.exception.code, "NOTHING_TO_RESTORE")
        changed = H.router_config().replace("network 10.254.81.0/31", "network 10.9.9.0/31")
        with self.assertRaises(eos.PlanError) as caught:
            eos.render_restore(H.router_config(), changed, management_addresses=[H.MGMT])
        self.assertEqual(caught.exception.code, "RESTORE_CONFLICT")


# ------------------------------------------------------------------------------------------------------------- readiness
class ReadinessClosureTests(SimpleTestCase):
    NOW = timezone.now()

    def test_readiness_redundant_transition_and_quiescent_verdicts(self):
        active = readiness.evaluate(H.observation(), operator="o", reason="r", now=self.NOW)
        self.assertEqual(active["verdict"], readiness.REDUNDANT_TRANSITION)
        quiet = readiness.evaluate(H.observation(active=False), operator="o", reason="r", now=self.NOW)
        self.assertEqual(quiet["verdict"], readiness.QUIESCENT)
        self.assertEqual(len(readiness.mechanisms(H.observation())), 4)
        self.assertEqual(readiness.traffic_moved(H.observation(on_device=False)), [])
        self.assertEqual(readiness.loss_findings({"f": {"sent": 5, "received": 5}}), [])
        self.assertEqual(H.observation().summary()["device"], "T1")

    def test_readiness_blocked_without_alternate_unknown_traffic_or_blind_spot(self):
        blocked = readiness.evaluate(H.observation(alternate=False), operator="o", reason="r", now=self.NOW)
        self.assertEqual(blocked["verdict"], readiness.BLOCKED)
        self.assertTrue(all(b["instruction"] for b in blocked["blockers"]))
        blind = readiness.evaluate(H.observation(active=False, blind=["E1 unreadable"]), operator="o", reason="r", now=self.NOW)
        self.assertEqual(blind["verdict"], readiness.BLOCKED)
        unknown = readiness.Observation(device="T1", flows=[], ospf={})
        self.assertEqual(readiness.evaluate(unknown, operator="o", reason="r", now=self.NOW)["verdict"], readiness.BLOCKED)
        self.assertEqual(readiness.mechanisms(readiness.Observation(device="T1")), {})
        not_ready = readiness.mechanisms(H.observation(full=()))
        self.assertTrue(all(m.state == model.NOT_READY for m in not_ready.values()))
        self.assertEqual(len(readiness.traffic_moved(H.observation())), 4)
        self.assertEqual(readiness.Observation(device="X").summary()["flows"], [])

    def test_loss_findings_refuses_loss_and_missing_measurement(self):
        self.assertEqual(readiness.loss_findings({})[0]["check"], "traffic")
        self.assertIn("lost", readiness.loss_findings({"f": {"sent": 10, "received": 9}})[0]["detail"])
        self.assertIn("no packets", readiness.loss_findings({"f": {"sent": None, "received": None}})[0]["detail"])


# ------------------------------------------------------------------------------------------------------------- observe
SNMP = "Ip: Forwarding OutRequests InDelivers\nIp: 1 {out} {inn}\n"
SNMP6 = ("Ip6OutRequests {o6}\nIp6OutMcastPkts 1\nIp6InDelivers {i6}\nIp6InMcastPkts 1\nIcmp6OutNeighborSolicits 1\n"
         "Icmp6OutNeighborAdvertisements 0\nIcmp6InNeighborSolicits 0\nIcmp6InNeighborAdvertisements 1\n")
IDS = {"E1": "1.1.1.1", "T1": "2.2.2.2", "T2": "3.3.3.3", "E2": "4.4.4.4"}


def fabric(*, ecmp=False, t2_full=True, broken=()):
    """E1 - T1 - E2 with T2 as the alternate; E1 routes HB's LAN via T1 (Ethernet2), T1 via Ethernet2 to E2, E2 connected."""
    def router(name):
        def read(command):
            if name in broken:
                raise OSError("unreadable")
            if command in ("show ip ospf | json", "show ipv6 ospf | json"):
                return H.ospf_id(IDS[name])
            if command == "show running-config":
                return H.router_config()
            if command.startswith(("show ip ospf neighbor", "show ipv6 ospf neighbor")):
                key = "ospfNeighborEntries" if command.startswith("show ip ") else "ospf3NeighborEntries"
                state = "full" if t2_full else "init"
                rows = {"E1": [(IDS["T1"], "Ethernet2", "full"), (IDS["T2"], "Ethernet3", state)],
                        "T1": [(IDS["E1"], "Ethernet1", "full"), (IDS["E2"], "Ethernet2", "full")],
                        "T2": [(IDS["E1"], "Ethernet1", state), (IDS["E2"], "Ethernet2", state)],
                        "E2": [(IDS["T1"], "Ethernet2", "full"), (IDS["T2"], "Ethernet3", state)]}[name]
                return H.neighbors(*rows, key=key)
            if command.startswith(("show ip route", "show ipv6 route")):
                to_hb = "10.254.85.10" in command or "2001:db8::20" in command
                if name == ("E2" if to_hb else "E1"):
                    return H.route(connected=True)
                outgoing = "Ethernet1" if name == "T1" and not to_hb else "Ethernet2"
                return H.route(interface=outgoing, vias=2 if ecmp and name in ("E1", "E2") else 1)
            return ""
        return read
    return {name: router(name) for name in IDS}


def counter(out, inn):
    return lambda: observe.proc_counters(SNMP.format(out=out, inn=inn), SNMP6.format(o6=out + 2, i6=inn + 2))


class Hosts:
    def __init__(self):
        self.n = 0

    def reader(self, name):
        def read():
            self.n += 1
            return observe.proc_counters(SNMP.format(out=self.n * 10, inn=self.n * 10), SNMP6.format(o6=self.n * 10 + 2, i6=self.n * 10 + 2))
        return read


def live(**kwargs):
    hosts = Hosts()
    specs = observe.flow_specs(workload="HA-HB", sender="HA", receiver="HB", sender_gateway="E1", receiver_gateway="E2",
                               addresses={"HA": {"IPV4": "10.254.80.10", "IPV6": "2001:db8::10"}, "HB": {"IPV4": "10.254.85.10", "IPV6": "2001:db8::20"}})
    return observe.LiveObserver(routers=fabric(**kwargs), hosts={"HA": hosts.reader("HA"), "HB": hosts.reader("HB")}, flows=specs,
                                window_seconds=0, sleep=lambda s: None)


class ObserveClosureTests(SimpleTestCase):
    def test_proc_counters_parses_unicast_counters(self):
        found = observe.proc_counters(SNMP.format(out=7, inn=9), SNMP6.format(o6=10, i6=10))
        self.assertEqual(found["IPV4"], {"out": 7, "in": 9})
        self.assertEqual(found["IPV6"], {"out": 8, "in": 8})

    def test_proc_counters_unreadable_text_gives_empty(self):
        self.assertEqual(observe.proc_counters("", ""), {})
        self.assertEqual(observe._json("not json"), {})  # pylint: disable=protected-access
        self.assertEqual(observe._default_vrf({}), {})  # pylint: disable=protected-access
        self.assertIsNone(observe._delta({}, {}, "HA", "IPV4", "out"))  # pylint: disable=protected-access

    def test_observer_helpers_parse_documents(self):
        self.assertEqual(observe._json('{"a": 1}'), {"a": 1})  # pylint: disable=protected-access
        self.assertEqual(observe._default_vrf({"vrfs": {"default": {"x": 1}}}), {"x": 1})  # pylint: disable=protected-access
        self.assertEqual(observe._delta({"HA": {"IPV4": {"out": 1}}}, {"HA": {"IPV4": {"out": 4}}}, "HA", "IPV4", "out"), 3)  # pylint: disable=protected-access
        self.assertEqual(len(observe.flow_specs(workload="w", sender="A", receiver="B", sender_gateway="G1", receiver_gateway="G2",
                                                addresses={"A": {"IPV4": "10.0.0.1", "IPV6": "::1"}, "B": {"IPV4": "10.0.0.2", "IPV6": "::2"}})), 4)

    def test_live_observer_derives_path_alternate_and_activity(self):
        obs = live()
        ids = obs.router_ids()
        self.assertEqual(ids["2.2.2.2"], "T1")
        tables = obs.neighbors("IPV4")
        self.assertEqual(len(tables["E1"]), 2)
        graph = obs.adjacency_graph("IPV4", tables, ids)
        self.assertTrue(graph.has_edge("E1", "T2"))
        self.assertEqual(obs.path({"src_gateway": "E1", "family": "IPV4", "destination": "10.254.85.10"}, tables, ids), ["E1", "T1", "E2"])
        self.assertEqual(obs._read("T1", "show ip ospf | json"), H.ospf_id("2.2.2.2"))  # pylint: disable=protected-access
        self.assertIn("HA", obs.counters())
        result = obs.observe("T1")
        self.assertTrue(all(f.on_device for f in result.flows))
        self.assertTrue(all(f.activity == model.ACTIVE for f in result.flows))
        self.assertTrue(all(result.alternates.values()))
        self.assertEqual(result.ospf["IPV4"], "router ospf 1")

    def test_live_observer_refuses_unknown_path_and_unhealthy_alternate(self):
        obs = live(ecmp=True)
        ids = obs.router_ids()
        self.assertIsNone(obs.path({"src_gateway": "E1", "family": "IPV4", "destination": "10.254.85.10"}, obs.neighbors("IPV4"), ids))
        self.assertTrue(all(f.on_device is None for f in obs.observe("T1").flows))
        gateway = live().observe("E2")
        self.assertFalse(any(gateway.alternates.values()))
        no_alt = live(t2_full=False).observe("T1")
        self.assertFalse(any(no_alt.alternates.values()))
        broken = live(broken=("T2",))
        self.assertIsNone(broken._read("T2", "show ip ospf | json"))  # pylint: disable=protected-access
        self.assertIsNone(broken._read("ZZ", "show x"))  # pylint: disable=protected-access
        self.assertIsNone(broken.neighbors("IPV4")["T2"])
        self.assertTrue(broken.observe("T1").blind_spots)
        failing = observe.LiveObserver(routers={}, hosts={"HA": lambda: (_ for _ in ()).throw(OSError())}, flows=[], sleep=lambda s: None)
        self.assertEqual(failing.counters(), {"HA": {}})
        self.assertEqual(failing.router_ids(), {})
        self.assertEqual(list(failing.adjacency_graph("IPV4", {}, {}).edges()), [])


# ------------------------------------------------------------------------------------------------------------- dependencies
class DependencyClosureTests(TestCase):
    def setUp(self):
        self.upstream = L.adopt("S1").device

    def test_dependents_found_through_attachment_and_management_path(self):
        downstream = L.register().device
        L.attach(downstream, upstream="S1")
        rows = dependencies.downstream("S1")
        self.assertEqual([r["name"] for r in rows], ["NEW1"])
        self.assertTrue(rows[0]["stranded"])
        self.assertEqual(dependencies._upstreams(downstream), {"S1"})  # pylint: disable=protected-access
        self.assertEqual(dependencies._live(models.ManagedDevice.objects.all()).count(), 2)  # pylint: disable=protected-access
        found = dependencies.analyze(self.upstream)
        self.assertIn("DOWNSTREAM_DEPENDENT", [b["code"] for b in found["blockers"]])
        self.assertEqual(dependencies.management_dependents("S1"), [])

    def test_dependents_none_for_a_leaf_device(self):
        self.assertEqual(dependencies.downstream("S1"), [])
        self.assertEqual(dependencies.management_dependents("S1"), [])
        self.assertEqual(dependencies.analyze(self.upstream)["blockers"], [])
        self.assertEqual(dependencies._upstreams(self.upstream), set())  # pylint: disable=protected-access
        self.assertEqual(dependencies._live(models.ManagedDevice.objects.none()).count(), 0)  # pylint: disable=protected-access


# ------------------------------------------------------------------------------------------------------------- service
class ServiceHelperClosureTests(TestCase):
    def setUp(self):
        self.device = L.adopt("R1", role="router").device
        self.fake = H.session()

    def test_service_settings_lookups_and_identity(self):
        self.assertEqual(svc.approval_ttl_seconds(), 3600.0)
        self.assertEqual(svc.readiness_max_age_seconds(), 1800.0)
        self.assertEqual(svc.device_dict(self.device), {"name": "R1", "platform": "ceos"})
        self.assertEqual(svc.Result(True, "X", blockers=[{"code": "A"}]).codes, ["A"])
        record = svc.request(self.device, actor=OPERATOR, reason="r").record
        self.assertEqual(svc.get_record(record.record_id), record)
        self.assertEqual(svc.ops_of(record), [])
        executor = H.executor_factory(self.fake)(svc.device_dict(self.device))
        executor.connect()
        self.assertTrue(svc.host_key(executor).startswith("SHA256:"))
        snap = svc.snapshot(self.device, executor, purpose=models.DeviceConfigSnapshot.Purpose.DECOMMISSION_BASELINE, actor=OPERATOR)
        self.assertEqual(snap.state_digest, executor.config_state_digest())
        self.assertIn("router ospf 1", svc.governed_read(executor))
        self.assertTrue(svc._cas(record, record.version, reason="r"))  # pylint: disable=protected-access

    @override_settings(NMAS_DECOMMISSION_APPROVAL_TTL_SECONDS=5, NMAS_DECOMMISSION_READINESS_MAX_AGE_SECONDS=7,
                       NMAS_DECOMMISSION_RUNTIME="")
    def test_service_lookups_refuse_unknown_ids_and_unconfigured_runtime(self):
        self.assertEqual((svc.approval_ttl_seconds(), svc.readiness_max_age_seconds()), (5.0, 7.0))
        self.assertIsNone(svc.configured_runtime())
        self.assertIsNone(svc.get_record("DCM-x"))
        self.assertIsNone(svc.get_restoration("nope"))
        self.assertEqual(svc.Result(False, "X").codes, [])
        self.assertEqual(svc.device_dict(SimpleNamespace(name="R3", platform="ubuntu_frr"))["platform"], "ubuntu_frr")
        record = svc.request(self.device, actor=OPERATOR, reason="r").record
        self.assertFalse(svc._cas(record, record.version + 5, reason="x"))  # pylint: disable=protected-access
        self.fake.outputs["show management ssh hostkey ed25519 public"] = "garbage"
        executor = H.executor_factory(self.fake)(svc.device_dict(self.device))
        executor.connect()
        self.assertEqual(svc.host_key(executor), "")

    @override_settings(NMAS_DECOMMISSION_RUNTIME="core.tests.test_tg_phase7_closure.fixture_runtime")
    def test_configured_runtime_loads_the_factory(self):
        self.assertIsInstance(svc.configured_runtime(), svc.Runtime)

    def test_recording_helpers_write_events_audit_and_facts(self):
        record = svc.request(self.device, actor=OPERATOR, reason="r").record
        svc._event(self.device, "DECOMMISSION_TEST", models.DeviceLifecycleEventOutcome.RECORDED, actor=OPERATOR, evidence={})  # pylint: disable=protected-access
        svc._audit(record, models.AuditEventType.DECOMMISSION_CHANGED, OPERATOR, "s", {})  # pylint: disable=protected-access
        svc._fact(self.device, "DECOMMISSION_REQUESTED", actor=OPERATOR, detail={"record": record.record_id})  # pylint: disable=protected-access
        self.assertTrue(models.AuditEvent.objects.filter(event_type="DECOMMISSION_CHANGED").exists())
        refused = svc._refuse("X", record, ["REASON_REQUIRED"], actor=OPERATOR)  # pylint: disable=protected-access
        self.assertEqual(refused.codes, ["REASON_REQUIRED"])
        self.assertFalse(svc._refuse_device(self.device, "X", ["REASON_REQUIRED"], actor=OPERATOR).ok)  # pylint: disable=protected-access

    def test_recording_helpers_refuse_secret_fact_and_unknown_refusal_without_record(self):
        from core.services.commissioning.outbox import OutboxError

        with self.assertRaises(OutboxError):
            svc._fact(self.device, "DECOMMISSION_REQUESTED", actor=OPERATOR, detail={"password": "hunter2"})  # pylint: disable=protected-access
        self.assertEqual(svc._refuse("X", None, ["REASON_REQUIRED"], actor=OPERATOR).record, None)  # pylint: disable=protected-access
        with self.assertRaises(ValueError):
            svc._event(self.device, "X", "REFUSED", actor=OPERATOR, evidence={}, actor_kind="ROBOT")  # pylint: disable=protected-access
        record = svc.request(self.device, actor=OPERATOR, reason="r").record
        svc._audit(record, models.AuditEventType.DECOMMISSION_CHANGED, "o" * 400, "refused " + "s" * 400, {})  # pylint: disable=protected-access
        event = models.AuditEvent.objects.get(object_id=record.record_id, summary__startswith="refused")
        self.assertEqual((len(event.summary), len(event.actor)), (255, 150))
        with self.assertRaises(Exception):
            svc._refuse_device(SimpleNamespace(pk=999999), "X", ["REASON_REQUIRED"], actor=OPERATOR)  # pylint: disable=protected-access

    def test_governed_read_fails_on_unreadable_session(self):
        from core.services.execution.executors.base import ExecutorError

        class Broken:
            def show(self, command):
                raise ExecutorError("PREVIOUS_STATE_UNAVAILABLE")

            def config_state_digest(self):
                raise ExecutorError("PREVIOUS_STATE_UNAVAILABLE")
        with self.assertRaises(ExecutorError):
            svc.governed_read(Broken())
        with self.assertRaises(ExecutorError):
            svc.snapshot(self.device, Broken(), purpose=models.DeviceConfigSnapshot.Purpose.DECOMMISSION_BASELINE, actor=OPERATOR)
        self.assertEqual(svc.host_key(Broken()), "")
        self.assertEqual(svc.ops_of(SimpleNamespace(plan=None)), [])


def fixture_runtime():
    return H.runtime(H.session(), H.FakeObserver(H.observation()))


class ServiceWorkflowClosureTests(TestCase):
    """Each workflow function: one accepting and one refusing direct call."""

    def setUp(self):
        self.device = L.adopt("R1", role="router").device
        self.fake = H.session()

    def runtime(self, *observations, probe=None):
        return H.runtime(self.fake, H.FakeObserver(*(observations or (H.observation(active=False),))), probe=probe)

    def evaluated(self, runtime):
        record = svc.request(self.device, actor=OPERATOR, reason="retire").record
        svc.evaluate(record, actor=OPERATOR, runtime=runtime)
        record.refresh_from_db()
        return record

    def approved(self, runtime):
        record = self.evaluated(runtime)
        svc.approve(record, actor=APPROVER, confirmation=record.plan_hash)
        record.refresh_from_db()
        return record

    def test_request_records_the_intent(self):
        result = svc.request(self.device, actor=OPERATOR, reason="  retire   T1 ")
        self.assertTrue(result.ok)
        self.assertEqual(result.record.reason, "retire T1")
        self.assertTrue(models.LifecycleOutboxEvent.objects.filter(device=self.device, payload__fact="DECOMMISSION_REQUESTED").exists())

    def test_request_refuses_missing_reason_duplicate_and_ineligible_device(self):
        self.assertEqual(svc.request(self.device, actor=OPERATOR, reason=" ").codes, ["REASON_REQUIRED"])
        svc.request(self.device, actor=OPERATOR, reason="r")
        self.assertEqual(svc.request(self.device, actor=OPERATOR, reason="r").codes, ["DECOMMISSION_OPEN_EXISTS"])
        new = L.register().device
        self.assertEqual(svc.request(new, actor=OPERATOR, reason="r").codes, ["DECOMMISSION_NOT_ELIGIBLE"])
        self.assertEqual(svc.request(None, actor=OPERATOR, reason="r").codes, ["DECOMMISSION_NOT_ELIGIBLE"])

    def test_evaluate_builds_the_governed_plan(self):
        record = self.evaluated(self.runtime())
        self.assertEqual(record.state, D.READY)
        self.assertEqual(record.change.metadata["transition"]["kind"], svc.KIND)
        self.assertTrue(record.plan_hash)

    def test_evaluate_refuses_missing_runtime_platform_unsupported_and_wrong_state(self):
        record = svc.request(self.device, actor=OPERATOR, reason="r").record
        self.assertIn("DECOMMISSION_RUNTIME_UNAVAILABLE", svc.evaluate(record, actor=OPERATOR, runtime=None).codes)
        self.assertIn("DECOMMISSION_NOT_FOUND", svc.evaluate(None, actor=OPERATOR, runtime=None).codes)
        frr = L.adopt("R3", role="router").device
        other = svc.request(frr, actor=OPERATOR, reason="r").record
        self.assertIn("DECOMMISSION_PLATFORM_NOT_IMPLEMENTED", svc.evaluate(other, actor=OPERATOR, runtime=self.runtime()).codes)
        svc.cancel(record, actor=OPERATOR)
        record.refresh_from_db()
        self.assertIn("DECOMMISSION_STATE_INVALID", svc.evaluate(record, actor=OPERATOR, runtime=self.runtime()).codes)

    def test_evaluate_live_records_baseline_and_plan(self):
        record = svc.request(self.device, actor=OPERATOR, reason="r").record
        fields = {"readiness_mode": models.DecommissionReadiness.UNKNOWN}
        self.assertEqual(svc._evaluate_live(record, self.device, fields, actor=OPERATOR, runtime=self.runtime()), [])  # pylint: disable=protected-access
        self.assertTrue(fields["plan_hash"])

    def test_evaluate_live_refuses_unreadable_device_blocked_traffic_and_plan_refusal(self):
        record = svc.request(self.device, actor=OPERATOR, reason="r").record

        class Broken:
            def __init__(self, _device):
                pass

            def connect(self):
                raise OSError("down")

            def close(self):
                raise OSError("down")
        broken = H.runtime(self.fake, H.FakeObserver(H.observation()), factory=Broken)
        found = svc._evaluate_live(record, self.device, {}, actor=OPERATOR, runtime=broken)  # pylint: disable=protected-access
        self.assertEqual(found[0]["code"], "DECOMMISSION_EVIDENCE_UNAVAILABLE")
        blocked = svc._evaluate_live(record, self.device, {}, actor=OPERATOR, runtime=self.runtime(H.observation(alternate=False)))  # pylint: disable=protected-access
        self.assertEqual(blocked[0]["code"], "DECOMMISSION_TRAFFIC_BLOCKED")
        self.fake = H.session(H.router_config(mgmt="10.9.9.9"))
        refused = svc._evaluate_live(record, self.device, {}, actor=OPERATOR, runtime=self.runtime())  # pylint: disable=protected-access
        self.assertEqual(refused[0]["code"], "DECOMMISSION_PLAN_REFUSED")

    def test_evaluate_blocks_on_a_stranded_downstream_dependent(self):
        downstream = L.register().device
        L.attach(downstream, upstream="R1")
        result = svc.evaluate(svc.request(self.device, actor=OPERATOR, reason="r").record, actor=OPERATOR, runtime=self.runtime())
        self.assertIn("DECOMMISSION_DEPENDENCY_BLOCKED", result.codes)

    def test_approve_binds_the_plan(self):
        record = self.evaluated(self.runtime())
        self.assertTrue(svc.approve(record, actor=APPROVER, confirmation=record.plan_hash).ok)
        record.refresh_from_db()
        self.assertEqual(record.state, D.APPROVED)
        self.assertGreater(record.approval_expires_at, timezone.now())

    def test_approve_refuses_self_approval_mismatch_stale_and_missing(self):
        record = self.evaluated(self.runtime())
        self.assertIn("DECOMMISSION_SELF_APPROVAL", svc.approve(record, actor=OPERATOR, confirmation=record.plan_hash).codes)
        self.assertIn("DECOMMISSION_CONFIRMATION_MISMATCH", svc.approve(record, actor=APPROVER, confirmation="x").codes)
        models.DecommissionRecord.objects.filter(pk=record.pk).update(updated_at=timezone.now() - timedelta(hours=2))
        record.refresh_from_db()
        self.assertIn("DECOMMISSION_READINESS_STALE", svc.approve(record, actor=APPROVER, confirmation=record.plan_hash).codes)
        self.assertIn("DECOMMISSION_NOT_FOUND", svc.approve(None, actor=APPROVER, confirmation="").codes)

    def test_cancel_closes_an_open_record(self):
        record = svc.request(self.device, actor=OPERATOR, reason="r").record
        self.assertTrue(svc.cancel(record, actor=OPERATOR, reason="changed plans").ok)
        record.refresh_from_db()
        self.assertEqual(record.state, D.CANCELLED)

    def test_cancel_refuses_closed_and_missing_records(self):
        record = svc.request(self.device, actor=OPERATOR, reason="r").record
        svc.cancel(record, actor=OPERATOR)
        record.refresh_from_db()
        self.assertIn("DECOMMISSION_STATE_INVALID", svc.cancel(record, actor=OPERATOR).codes)
        self.assertIn("DECOMMISSION_NOT_FOUND", svc.cancel(None, actor=OPERATOR).codes)

    def test_execute_decommissions_and_finish_retires(self):
        runtime = self.runtime()
        record = self.approved(runtime)
        result = svc.execute(record, actor=APPROVER, confirmation=record.plan_hash, runtime=runtime)
        self.assertTrue(result.ok)
        self.assertEqual(result.record.result_snapshot.purpose, models.DeviceConfigSnapshot.Purpose.DECOMMISSION_RESULT)

    def test_execute_refuses_unapproved_mismatch_missing_runtime(self):
        record = self.evaluated(self.runtime())
        found = svc.execute(record, actor=APPROVER, confirmation="x", runtime=None).codes
        self.assertIn("DECOMMISSION_STATE_INVALID", found)
        self.assertIn("DECOMMISSION_CONFIRMATION_MISMATCH", found)
        self.assertIn("DECOMMISSION_RUNTIME_UNAVAILABLE", found)
        self.assertIn("DECOMMISSION_NOT_FOUND", svc.execute(None, actor=APPROVER, confirmation="", runtime=None).codes)

    def test_await_moved_returns_once_traffic_left(self):
        measured = {"moves": []}
        svc._await_moved(None, self.device, self.runtime(H.observation(on_device=False)), measured)  # pylint: disable=protected-access
        self.assertEqual(measured["moves"][-1]["still_on_device"], [])

    def test_await_moved_raises_when_traffic_never_left(self):
        with self.assertRaises(svc.TrafficNotMoved):
            svc._await_moved(None, self.device, self.runtime(H.observation()), {"moves": []})  # pylint: disable=protected-access

    def test_finish_records_uncertain_on_an_interrupted_run(self):
        record = self.approved(self.runtime())
        run = SimpleNamespace(run_id="r1")
        result = SimpleNamespace(run=run, outcome=governed.Outcome.INTERRUPTED, blockers=[], report={}, succeeded=False)
        svc._lifecycle(self.device, S.DECOMMISSION_PENDING, actor=APPROVER, record=record)  # pylint: disable=protected-access
        done = svc._finish(record, self.device, result, {"moves": [], "probe": None, "probe_started": None}, {}, actor=APPROVER)  # pylint: disable=protected-access
        self.assertFalse(done.ok)
        self.assertEqual(done.record.state, D.UNCERTAIN)
        self.assertEqual(done.codes, ["DECOMMISSION_UNCERTAIN"])

    def test_lifecycle_refused_without_an_approved_record(self):
        record = self.evaluated(self.runtime())
        with self.assertRaises(governed.TransactionError):
            svc._lifecycle(self.device, S.DECOMMISSION_PENDING, actor=APPROVER, record=record)  # pylint: disable=protected-access

    def test_retire_only_device_is_retired_without_device_writes(self):
        device = L.register(name="NEW9", serial="SN-NEW9", mac="00:1c:73:00:00:09").device
        models.ManagedDevice.objects.compare_and_swap(device.pk, device.version, lifecycle_state=S.FAILED)
        device.refresh_from_db()
        record = svc.request(device, actor=OPERATOR, reason="never commissioned").record
        self.assertTrue(svc.evaluate(record, actor=OPERATOR, runtime=None).ok)
        record.refresh_from_db()
        self.assertTrue(svc.approve(record, actor=APPROVER, confirmation=record.record_id).ok)
        record.refresh_from_db()
        self.assertTrue(svc._retire(record, device, actor=APPROVER).ok)  # pylint: disable=protected-access
        device.refresh_from_db()
        self.assertEqual(device.lifecycle_state, S.DECOMMISSIONED)

    def test_retire_refused_for_an_unapproved_record(self):
        device = L.register(name="NEW8", serial="SN-NEW8", mac="00:1c:73:00:00:08").device
        models.ManagedDevice.objects.compare_and_swap(device.pk, device.version, lifecycle_state=S.FAILED)
        device.refresh_from_db()
        record = svc.request(device, actor=OPERATOR, reason="r").record
        self.assertFalse(svc._retire(record, device, actor=APPROVER).ok)  # pylint: disable=protected-access

    def test_reconcile_on_baseline_rolls_back_to_service(self):
        runtime = self.runtime()
        record = self.approved(runtime)
        svc._lifecycle(self.device, S.DECOMMISSION_PENDING, actor=APPROVER, record=record)  # pylint: disable=protected-access
        models.DecommissionRecord.objects.filter(pk=record.pk).update(state=D.UNCERTAIN)
        record.refresh_from_db()
        result = svc.reconcile(record, actor=APPROVER, runtime=runtime)
        self.assertTrue(result.ok)
        self.assertEqual(result.record.state, D.ROLLED_BACK)
        self.device.refresh_from_db()
        self.assertEqual(self.device.lifecycle_state, S.IN_SERVICE)

    def test_reconcile_not_on_baseline_stays_uncertain_and_refuses_wrong_state(self):
        runtime = self.runtime()
        record = self.approved(runtime)
        self.assertIn("DECOMMISSION_STATE_INVALID", svc.reconcile(record, actor=APPROVER, runtime=runtime).codes)
        models.DecommissionRecord.objects.filter(pk=record.pk).update(state=D.UNCERTAIN)
        record.refresh_from_db()
        self.assertIn("DECOMMISSION_RUNTIME_UNAVAILABLE", svc.reconcile(record, actor=APPROVER, runtime=None).codes)
        self.fake.config.apply(["hostname CHANGED"])
        result = svc.reconcile(record, actor=APPROVER, runtime=runtime)
        self.assertFalse(result.ok)
        self.assertEqual(result.record.state, D.UNCERTAIN)
        self.assertIn("DECOMMISSION_NOT_FOUND", svc.reconcile(None, actor=APPROVER, runtime=runtime).codes)


class RestorationClosureTests(TestCase):
    def setUp(self):
        self.device = L.adopt("R1", role="router").device
        self.fake = H.session()
        self.runtime = H.runtime(self.fake, H.FakeObserver(H.observation(active=False)))
        record = svc.request(self.device, actor=OPERATOR, reason="r").record
        svc.evaluate(record, actor=OPERATOR, runtime=self.runtime)
        record.refresh_from_db()
        svc.approve(record, actor=APPROVER, confirmation=record.plan_hash)
        record.refresh_from_db()
        svc.execute(record, actor=APPROVER, confirmation=record.plan_hash, runtime=self.runtime)
        record.refresh_from_db()
        self.record = record

    def planned(self):
        row = svc.request_restore(self.record, actor=OPERATOR).record
        svc.check_restore(row, actor=OPERATOR, runtime=self.runtime)
        row.refresh_from_db()
        return row

    def test_request_restore_opens_a_restoration(self):
        result = svc.request_restore(self.record, actor=OPERATOR)
        self.assertTrue(result.ok)
        self.assertEqual(svc.get_restoration(result.record.record_id), result.record)

    def test_request_restore_refuses_duplicate_missing_and_open_decommission(self):
        svc.request_restore(self.record, actor=OPERATOR)
        self.assertEqual(svc.request_restore(self.record, actor=OPERATOR).codes, ["RESTORATION_OPEN_EXISTS"])
        self.assertEqual(svc.request_restore(None, actor=OPERATOR).codes, ["DECOMMISSION_NOT_FOUND"])
        other = svc.request(L.adopt("R2", role="router").device, actor=OPERATOR, reason="r").record
        self.assertEqual(svc.request_restore(other, actor=OPERATOR).codes, ["RESTORATION_STATE_INVALID"])

    def test_check_restore_plans_the_restoration(self):
        row = self.planned()
        self.assertEqual(row.state, R.PLANNED)
        self.assertEqual(row.change.metadata["transition"]["kind"], svc.RESTORE_KIND)

    def test_check_restore_refuses_tampered_snapshot_never_admitted_and_missing_runtime(self):
        row = svc.request_restore(self.record, actor=OPERATOR).record
        self.assertIn("DECOMMISSION_RUNTIME_UNAVAILABLE", svc.check_restore(row, actor=OPERATOR, runtime=None).codes)
        self.assertIn("RESTORATION_NOT_FOUND", svc.check_restore(None, actor=OPERATOR, runtime=None).codes)
        original = row.snapshot.text
        models.DeviceConfigSnapshot.objects.filter(pk=row.snapshot_id).update(text="tampered")
        row.refresh_from_db()
        self.assertIn("RESTORATION_SNAPSHOT_INVALID", svc.check_restore(row, actor=OPERATOR, runtime=self.runtime).codes)
        models.DeviceConfigSnapshot.objects.filter(pk=row.snapshot_id).update(text=original)
        self.device.refresh_from_db()
        models.ManagedDevice.objects.compare_and_swap(self.device.pk, self.device.version,
                                                      admission_state=models.ProductionAdmissionState.NOT_ADMITTED)
        row.refresh_from_db()
        self.assertIn("RESTORATION_REENROLLMENT_REQUIRED", svc.check_restore(row, actor=OPERATOR, runtime=self.runtime).codes)
        row.refresh_from_db()
        self.assertEqual(row.state, R.REENROLLMENT_REQUIRED)

    def test_restoration_refuse_records_the_blockers(self):
        row = svc.request_restore(self.record, actor=OPERATOR).record
        result = svc._restoration_refuse("X", row, [{"code": "RESTORATION_CONFLICT"}], actor=OPERATOR, state=R.BLOCKED)  # pylint: disable=protected-access
        row.refresh_from_db()
        self.assertEqual((result.ok, row.state), (False, R.BLOCKED))

    def test_restoration_refuse_never_changes_a_closed_record(self):
        row = svc.request_restore(self.record, actor=OPERATOR).record
        svc.cancel_restore(row, actor=OPERATOR)
        row.refresh_from_db()
        svc._restoration_refuse("X", row, [{"code": "RESTORATION_CONFLICT"}], actor=OPERATOR, state=R.BLOCKED)  # pylint: disable=protected-access
        row.refresh_from_db()
        self.assertEqual(row.state, R.CANCELLED)

    def test_approve_restore_binds_the_plan(self):
        row = self.planned()
        self.assertTrue(svc.approve_restore(row, actor=APPROVER, confirmation=row.plan_hash).ok)

    def test_approve_restore_refuses_self_approval_mismatch_and_missing(self):
        row = self.planned()
        codes_ = svc.approve_restore(row, actor=OPERATOR, confirmation="x").codes
        self.assertIn("RESTORATION_SELF_APPROVAL", codes_)
        self.assertIn("DECOMMISSION_CONFIRMATION_MISMATCH", codes_)
        self.assertIn("RESTORATION_NOT_FOUND", svc.approve_restore(None, actor=APPROVER, confirmation="").codes)

    def test_execute_restore_restores_exactly(self):
        row = self.planned()
        svc.approve_restore(row, actor=APPROVER, confirmation=row.plan_hash)
        row.refresh_from_db()
        self.assertTrue(svc.execute_restore(row, actor=APPROVER, confirmation=row.plan_hash, runtime=self.runtime).ok)

    def test_execute_restore_refuses_unapproved_mismatch_and_missing_runtime(self):
        row = self.planned()
        codes_ = svc.execute_restore(row, actor=APPROVER, confirmation="x", runtime=None).codes
        self.assertEqual(set(codes_), {"RESTORATION_STATE_INVALID", "DECOMMISSION_CONFIRMATION_MISMATCH", "DECOMMISSION_RUNTIME_UNAVAILABLE"})
        self.assertIn("RESTORATION_NOT_FOUND", svc.execute_restore(None, actor=APPROVER, confirmation="", runtime=None).codes)

    def test_cancel_restore_closes_it(self):
        row = svc.request_restore(self.record, actor=OPERATOR).record
        self.assertTrue(svc.cancel_restore(row, actor=OPERATOR).ok)

    def test_cancel_restore_refuses_closed_and_missing(self):
        row = svc.request_restore(self.record, actor=OPERATOR).record
        svc.cancel_restore(row, actor=OPERATOR)
        row.refresh_from_db()
        self.assertFalse(svc.cancel_restore(row, actor=OPERATOR).ok)
        self.assertIn("RESTORATION_NOT_FOUND", svc.cancel_restore(None, actor=OPERATOR).codes)

    def test_register_restored_creates_the_successor(self):
        row = self.planned()
        models.RestorationRecord.objects.filter(pk=row.pk).update(state=R.RESTORING)
        self.device.refresh_from_db()
        successor = lifecycle.register_restored(self.device, actor=APPROVER, restoration=row.record_id, evidence={"digest": "d", "x": 1})
        self.assertEqual((successor.origin, successor.predecessor_id), (models.DeviceOrigin.RESTORED, self.device.pk))

    def test_register_restored_refuses_without_an_executing_restoration(self):
        self.device.refresh_from_db()
        with self.assertRaises(ValueError):
            lifecycle.register_restored(self.device, actor=APPROVER, restoration="RST-999999", evidence={})
        live = L.adopt("R2", role="router").device
        with self.assertRaises(ValueError):
            lifecycle.register_restored(live, actor=APPROVER, restoration="RST-1", evidence={})


class LifecycleEdgeClosureTests(TestCase):
    def setUp(self):
        self.device = L.adopt("R1", role="router").device

    def test_decommission_prerequisites_accept_an_approved_record(self):
        record = svc.request(self.device, actor=OPERATOR, reason="r").record
        models.DecommissionRecord.objects.filter(pk=record.pk).update(state=D.APPROVED, approved_by=APPROVER)
        self.assertEqual(lifecycle._decommission_prerequisites(self.device, "DECOMMISSION_REQUEST", {"decommission": record.record_id}), {})  # pylint: disable=protected-access
        models.DecommissionRecord.objects.filter(pk=record.pk).update(state=D.DECOMMISSIONED)
        self.assertIn("retired_at", lifecycle._decommission_prerequisites(self.device, "DECOMMISSION", {"decommission": record.record_id}))  # pylint: disable=protected-access

    def test_decommission_prerequisites_refuse_without_record_or_approver(self):
        record = svc.request(self.device, actor=OPERATOR, reason="r").record
        for evidence, action in (({}, "DECOMMISSION_REQUEST"), ({"decommission": record.record_id}, "DECOMMISSION_REQUEST"),
                                 ({"decommission": record.record_id}, "DECOMMISSION")):
            with self.subTest(action=action), self.assertRaises(lifecycle._Refused):  # pylint: disable=protected-access
                lifecycle._decommission_prerequisites(self.device, action, evidence)  # pylint: disable=protected-access
        result = lifecycle.transition(self.device, S.DECOMMISSION_PENDING, actor=APPROVER, evidence={})
        self.assertIn("DECOMMISSION_STATE_INVALID", result.codes)

    def test_decommission_cancel_refused_for_a_never_admitted_device(self):
        device = L.register().device
        record = models.DecommissionRecord.objects.create(device=device, reason="r", requested_by=OPERATOR, state=D.ROLLED_BACK)
        with self.assertRaises(lifecycle._Refused):  # pylint: disable=protected-access
            lifecycle._decommission_prerequisites(device, "DECOMMISSION_CANCEL", {"decommission": record.record_id})  # pylint: disable=protected-access


class UnresolvedRunsClosureTests(TestCase):
    def test_unresolved_runs_lists_an_interrupted_decommission(self):
        device = L.adopt("R1", role="router").device
        fake = H.session()
        runtime = H.runtime(fake, H.FakeObserver(H.observation(active=False)))
        record = svc.request(device, actor=OPERATOR, reason="r").record
        svc.evaluate(record, actor=OPERATOR, runtime=runtime)
        record.refresh_from_db()
        svc.approve(record, actor=APPROVER, confirmation=record.plan_hash)
        record.refresh_from_db()
        self.assertTrue(svc.execute(record, actor=APPROVER, confirmation=record.plan_hash, runtime=runtime).ok)
        self.assertEqual(governed.unresolved_runs("R1"), [])
        models.ChangeExecutionRun.objects.filter(change=record.change).update(outcome=governed.Outcome.INTERRUPTED)
        self.assertEqual(governed.unresolved_runs("R1"), [record.change.change_id])

    def test_unresolved_runs_empty_for_an_unknown_device(self):
        self.assertEqual(governed.unresolved_runs("NOPE"), [])
        self.assertIn("DEVICE_DECOMMISSION", governed.GOVERNED_KINDS)
        self.assertEqual(json.loads("[]"), [])
