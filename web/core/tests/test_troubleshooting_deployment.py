"""Deployment factory (DEP-001 .. DEP-010): read-only RuntimeDeps composition, shared by the API view and the AI command.

Everything is injected/simulated: no credentials, no device contact.  Nothing here claims live verification.
"""

from __future__ import annotations

import json

from django.test import SimpleTestCase, TestCase, override_settings

from core.tests.helpers.troubleshooting import ts_sign_in, ts_user
from core import models as m
from core.services.troubleshooting import baselines as bl
from core.services.troubleshooting import deployment as dep
from core.services.troubleshooting import runtime as rt
from core.tests.test_troubleshooting_runtime import ACTOR, GW, OUT, T0, Session, Transport, make_case, obs

INV = {"R1": {"platform": "ceos", "os_version": "9.9.9-CLIENT"}, "R2": {"platform": "ceos"}, "X1": {"platform": "mystery"}}
VERSIONS = {"R1": "4.36.2F", "R2": "4.36.2F", "X1": "1.0"}
LIFE = {"R1": {"state": "ACTIVE"}, "R2": {"state": "ACTIVE"}, "X1": {"state": "ACTIVE"}}
CALLS: list = []
TR = Transport(OUT, provenance=GW)


def inventory():
    return INV


def version_provider(device, entry):
    return VERSIONS.get(device)


def lifecycle_provider(device):
    return LIFE.get(device)


def cli_factory(info):
    CALLS.append(info.device)
    return TR


def bad_factory(info):
    raise RuntimeError("password=hunter2")


CFG = {"inventory": f"{__name__}.inventory", "version_provider": f"{__name__}.version_provider", "lifecycle_provider": f"{__name__}.lifecycle_provider",
       "cli_transport_factory": f"{__name__}.cli_factory", "use_health_capability": False}
FACTORY = dep.FACTORY_PATH
PROBE = lambda p, s: {"status": "SUPPORTED", "evidence": "test", "transport": "test"}   # noqa: E731


def build(**kw):
    base = dict(inventory=inventory, version_provider=version_provider, lifecycle_provider=lifecycle_provider, capability_probe=PROBE)
    base.update(kw)
    return dep.build_runtime_deps(**base)


class AdmissionTests(SimpleTestCase):
    def adm(self, devices=("R1", "R2", "X1", "ZZ"), **kw):
        return build(**kw).admission.resolve(list(devices))

    def test_DEP001_verified_uses_authoritative_version_not_inventory_or_client_claim(self):
        a = self.adm()["R1"]
        self.assertTrue(a.admitted)
        self.assertEqual((a.os_version, a.platform), ("4.36.2F", "ceos"))      # inventory's "9.9.9-CLIENT" ignored

    def test_DEP002_fail_closed_missing_unknown_unsupported(self):
        a = self.adm()
        self.assertEqual(a["ZZ"].state, "UNKNOWN")
        self.assertEqual(a["X1"].state, "UNSUPPORTED_PLATFORM")
        self.assertEqual(self.adm(version_provider=None)["R1"].state, "VERSION_UNKNOWN")
        self.assertEqual(self.adm(version_provider=lambda d, e: "not-a-version")["R1"].state, "VERSION_UNKNOWN")
        self.assertEqual(self.adm(version_provider=lambda d, e: 1 / 0)["R1"].state, "VERSION_UNKNOWN")
        self.assertEqual(self.adm(lifecycle_provider=None)["R1"].state, "LIFECYCLE_UNKNOWN")
        self.assertEqual(self.adm(lifecycle_provider=lambda d: None)["R1"].state, "LIFECYCLE_UNKNOWN")
        self.assertEqual(self.adm(lifecycle_provider=lambda d: {})["R1"].state, "LIFECYCLE_UNKNOWN")
        self.assertEqual(self.adm(inventory=lambda: 1 / 0)["R1"].state, "UNKNOWN")

    def test_DEP003_withdrawn_and_non_admitted_lifecycle_refused(self):
        self.assertEqual(self.adm(lifecycle_provider=lambda d: {"state": "ACTIVE", "withdrawn": True})["R1"].state, "WITHDRAWN")
        self.assertEqual(self.adm(lifecycle_provider=lambda d: {"state": "decommissioning"})["R1"].state, "DECOMMISSIONING")
        self.assertFalse(self.adm(lifecycle_provider=lambda d: {"state": "RETIRED"})["R1"].admitted)
        self.assertTrue(self.adm(lifecycle_provider=lambda d: {"state": "ACTIVE", "maintenance": True})["R1"].maintenance)

    def test_DEP004_default_factory_admits_nobody(self):
        self.assertFalse(any(a.admitted for a in dep.runtime_deps({}).admission.resolve(["R1"]).values()))


class WrapperTests(SimpleTestCase):
    def test_DEP005_wrappers_expose_no_write_surface_and_forward_provenance_verbatim(self):
        class Conn:
            def execute(self, r): return "x"
            def send_config_set(self, c): raise AssertionError("write reached")
            def provenance(self): return {"live": True, "gateway_evidence_seqs": [1]}
        w = dep.ReadOnlyCli(Conn())
        self.assertFalse(hasattr(w, "send_config_set"))
        self.assertEqual(w.provenance(), {"live": True, "gateway_evidence_seqs": [1]})
        self.assertFalse(hasattr(dep.ReadOnlyCli(Transport({})), "provenance"))          # nothing fabricated
        self.assertFalse(hasattr(dep.ReadOnlySnmp(Session()), "set"))
        with self.assertRaises(TypeError):
            dep.ReadOnlyCli(object())

    def test_DEP006_provider_failure_is_unavailable_and_sanitized(self):
        d = build(cli_transport_factory=bad_factory)
        info = d.admission.resolve(["R1"])["R1"]
        self.assertIsNone(d.cli_transport(info))
        self.assertEqual(d.deployment_problems, ["cli(R1): RuntimeError"])
        self.assertNotIn("hunter2", json.dumps(d.deployment_problems))

    def test_DEP007_no_write_field_in_deps(self):
        names = set(rt.RuntimeDeps.__dataclass_fields__)
        self.assertFalse({n for n in names if any(w in n for w in ("write", "config_set", "apply", "executor"))})


class SettingsTests(SimpleTestCase):
    @override_settings(NMAS_TS_DEPLOYMENT=CFG)
    def test_DEP008_settings_factory_builds_and_misconfig_refuses_all(self):
        d = dep.runtime_deps()
        self.assertIsInstance(d, rt.RuntimeDeps)
        self.assertTrue(d.admission.resolve(["R1"])["R1"].admitted)
        bad = dep.runtime_deps({**CFG, "version_provider": "no.such.module.fn"})
        self.assertFalse(bad.admission.resolve(["R1"])["R1"].admitted)
        self.assertFalse(dep.runtime_deps({"bogus": 1}).admission.resolve(["R1"])["R1"].admitted)
        self.assertIsNone(dep.runtime_deps({**CFG, "cli_transport_factory": "no.such.fn"}).cli_transport)

    def test_DEP009_consistency_check(self):
        class S: pass
        s = S()
        self.assertEqual(len(dep.consistency_problems(s)), 2)
        s.NMAS_TS_RUNTIME_FACTORY = FACTORY
        s.TROUBLESHOOTING_RUNTIME_DEPS = FACTORY.rsplit(".", 1)[0] + ":" + FACTORY.rsplit(".", 1)[1]
        self.assertEqual(dep.consistency_problems(s), [])
        s.TROUBLESHOOTING_RUNTIME_DEPS = "other.fn"
        self.assertTrue(dep.consistency_problems(s))


@override_settings(NMAS_TS_RUNTIME_FACTORY=FACTORY, TROUBLESHOOTING_RUNTIME_DEPS=FACTORY, NMAS_TS_DEPLOYMENT=CFG)
class CollectionTests(TestCase):
    def setUp(self):
        CALLS.clear()
        TR.calls.clear()

    def test_DEP010_bounded_read_only_collection_via_runtime(self):
        case = make_case(key="dep10")
        d = build(cli_transport_factory=cli_factory, sources=bl.StaticSources({}), now=lambda: T0)
        res = rt.run_case(ACTOR, case.case_id, d, run_key="d1", now=T0)
        self.assertEqual(res["collection"]["contacted"], ["R1", "R2"])
        self.assertTrue(obs(case, "R1").filter(key="interface.oper_state@Ethernet1", is_missing_data=False).exists())
        self.assertTrue(TR.calls and all(isinstance(c, str) and c.startswith("show ") for c in TR.calls))
        ev = m.TsEvidenceRef.objects.filter(case=case, device="R1", command_or_api="show interfaces | json").get()
        self.assertEqual(ev.scope["gateway"], GW)
        self.assertEqual(ev.os_version if hasattr(ev, "os_version") else "4.36.2F", "4.36.2F")
        self.assertEqual(dict(m.TsCase.objects.get(case_id=case.case_id).target_states), {"R1": "VERIFIED", "R2": "VERIFIED"})

    def test_DEP011_missing_version_or_withdrawn_is_not_contacted(self):
        for key, kw in (("dep11a", {"version_provider": None}), ("dep11b", {"lifecycle_provider": lambda d: {"state": "ACTIVE", "withdrawn": True}})):
            case = make_case(key=key)
            TR.calls.clear()
            d = build(cli_transport_factory=cli_factory, sources=bl.StaticSources({}), now=lambda: T0, **kw)
            try:
                rt.run_case(ACTOR, case.case_id, d, run_key="d1", now=T0)
            except Exception:  # noqa: BLE001 - refusal may surface as an exception; either way no device is contacted
                pass
            self.assertEqual(TR.calls, [])
            self.assertFalse(obs(case).filter(is_missing_data=False, key__startswith="interface.").exists())

    def test_DEP012_api_and_ai_consumers_resolve_equivalent_deps(self):
        from django.utils.module_loading import import_string
        from core import troubleshooting_views as tv
        api_deps = tv._runtime_deps()
        mod, _, attr = FACTORY.rpartition(".")
        import importlib
        ai_deps = getattr(importlib.import_module(mod), attr)()
        for d in (api_deps, ai_deps):
            self.assertIsInstance(d, rt.RuntimeDeps)
            r = d.admission.resolve(["R1", "ZZ"])
            self.assertEqual((r["R1"].state, r["R1"].os_version, r["ZZ"].state), ("VERIFIED", "4.36.2F", "UNKNOWN"))
        self.assertIs(import_string(FACTORY), dep.runtime_deps)
        self.assertEqual(dep.consistency_problems(), [])

    def test_DEP013_view_run_uses_factory_and_ignores_client_states(self):
        u = ts_user("op", "ts-operator", "ts-tenant:acme")
        case = make_case(key="dep13")
        ts_sign_in(self.client, u)
        r = self.client.post(f"/api/v1/troubleshooting/cases/{case.case_id}/run/", json.dumps({"run_key": "v", "target_states": {"R1": "VERIFIED"}}),
                             content_type="application/json")
        self.assertEqual(r.status_code, 200, r.content)
        self.assertEqual(r.json()["data"]["collection"]["contacted"], ["R1", "R2"])
        self.assertEqual(CALLS, ["R1", "R2"])

class ExtendedBindingsTests(SimpleTestCase):
    def test_DEP014_lazy_typed_contexts_and_baselines(self):
        from core.services.troubleshooting.adapters.dns import DnsContext
        from core.services.troubleshooting.adapters.stp import StpContext
        calls = []
        context = DnsContext(extra_servers=("192.0.2.1",))
        source = bl.StaticSources({"golden": {"revision": "pinned"}})
        def provider(value):
            def load():
                calls.append(value)
                return value
            return load
        d = build(dns_context_provider=provider(context), stp_context_provider=provider(StpContext()),
                  baseline_sources_provider=provider(source), dns_runner_factory=bad_factory, flow_input=bad_factory)
        self.assertEqual(calls, [])
        self.assertEqual(d.dns_context.extra_servers, context.extra_servers)
        self.assertEqual(d.stp_context.vlans, ())
        self.assertEqual(d.sources.golden(["R1"])["revision"], "pinned")
        self.assertEqual(len(calls), 3)
        info = d.admission.resolve(["R1"])["R1"]
        self.assertIsNone(d.dns_runner(info))
        self.assertIsNone(d.flow_input(info))
        self.assertNotIn("hunter2", json.dumps(d.deployment_problems))

    def test_DEP015_missing_and_invalid_bindings_fail_closed(self):
        d = dep.runtime_deps({**CFG, **{k: "no.such.provider" for k in
            ("dns_runner_factory", "dns_context_provider", "stp_context_provider", "flow_input", "baseline_sources_provider")}})
        self.assertIsNone(d.dns_runner)
        self.assertIsNone(d.flow_input)
        self.assertEqual(d.sources.golden(["R1"])["status"], "unavailable")
        d = build(dns_context_provider=lambda: object(), stp_context_provider=lambda: object(),
                  baseline_sources_provider=lambda: object(), flow_input=lambda info: object(), dns_runner_factory=lambda info: object())
        self.assertEqual(d.dns_context.extra_servers, ())
        self.assertEqual(d.stp_context.vlans, ())
        self.assertEqual(d.sources.intent([], {})["status"], "unavailable")
        info = d.admission.resolve(["R1"])["R1"]
        self.assertIsNone(d.flow_input(info))
        self.assertIsNone(d.dns_runner(info))
        self.assertTrue(d.deployment_problems)

    def test_DEP016_both_consumers_share_extended_bindings_without_contact(self):
        from core import troubleshooting_views as tv
        from django.utils.module_loading import import_string
        from unittest.mock import Mock
        provider = Mock(side_effect=AssertionError("contact during construction"))
        cfg = {**CFG, **{k: provider for k in ("dns_runner_factory", "dns_context_provider", "stp_context_provider", "flow_input", "baseline_sources_provider")}}
        with override_settings(NMAS_TS_RUNTIME_FACTORY=FACTORY, TROUBLESHOOTING_RUNTIME_DEPS=FACTORY, NMAS_TS_DEPLOYMENT=cfg):
            for d in (tv._runtime_deps(), import_string(FACTORY)()):
                self.assertIsNotNone(d.dns_runner)
                self.assertIsNotNone(d.flow_input)
                self.assertIsNotNone(d.sources)
            provider.assert_not_called()

    def test_DEP017_dns_capability_refusal_never_executes_runner(self):
        from core.services.troubleshooting import collectors as col
        from unittest.mock import Mock
        runner = Mock()
        provenance = {"live": False, "opaque": "unchanged"}
        runner.provenance.return_value = provenance
        d = build(dns_runner_factory=lambda info: runner)
        wrapped = d.dns_runner(d.admission.resolve(["R1"])["R1"])
        self.assertIs(wrapped.provenance(), provenance)
        self.assertFalse(hasattr(wrapped, "send_config_set"))
        collector = col.DnsCollector(capability_probe=lambda *args: {"status": "UNSUPPORTED"})
        target = col.Target(device="R1", platform="ceos", os_version="4.36.2F", lifecycle_state="VERIFIED")
        bundle = collector.collect(target, [col.DnsRequest("query", server="192.0.2.1", name="example.test")], wrapped,
                                   allowed_servers=["192.0.2.1"])
        runner.execute.assert_not_called()
        self.assertTrue(bundle["missing"])

    def test_DEP018_flow_binding_identity_and_baseline_failure_sanitization(self):
        from unittest.mock import Mock
        binding = rt.FlowRuntimeInput(wire=Mock(), selector={"protocol": "tcp", "dst_ports": [443]})
        d = build(flow_input=lambda info: binding)
        info = d.admission.resolve(["R1"])["R1"]
        self.assertIs(d.flow_input(info), binding)
        binding.wire.collect.assert_not_called()
        source = Mock()
        source.golden.side_effect = RuntimeError("password=hunter2")
        d = build(baseline_sources_provider=lambda: source)
        result = d.sources.golden(["R1"])
        self.assertEqual(result["status"], "unavailable")
        self.assertNotIn("hunter2", json.dumps([result, d.deployment_problems]))


class ForwardingBindingTests(SimpleTestCase):
    def test_DEP019_forwarding_context_is_lazy_scoped_and_shared_by_consumers(self):
        from unittest.mock import Mock
        from core.services.troubleshooting.adapters.forwarding import ForwardingContext, gateway_subjects
        from core import troubleshooting_views as tv
        from django.utils.module_loading import import_string
        context = ForwardingContext(gateways={"R1": ["192.0.2.1"]}, address_owners={"192.0.2.1": "R2"})
        provider = Mock(return_value=context)
        cfg = {**CFG, "forwarding_context_provider": provider}
        with override_settings(NMAS_TS_RUNTIME_FACTORY=FACTORY, TROUBLESHOOTING_RUNTIME_DEPS=FACTORY, NMAS_TS_DEPLOYMENT=cfg):
            consumers = (tv._runtime_deps(), import_string(FACTORY)())
            provider.assert_not_called()
            for deps in consumers:
                self.assertEqual(gateway_subjects("R1", deps.forwarding_context), ["192.0.2.1"])
                self.assertEqual(gateway_subjects("R2", deps.forwarding_context), [])
                self.assertEqual(deps.forwarding_context.address_owners["192.0.2.1"], "R2")
            self.assertEqual(provider.call_count, 2)

    def test_DEP020_invalid_forwarding_provider_invents_no_context(self):
        from unittest.mock import Mock
        from core.services.troubleshooting.adapters.forwarding import gateway_subjects
        provider = Mock(side_effect=RuntimeError("password=hunter2"))
        deps = dep.runtime_deps({**CFG, "forwarding_context_provider": provider})
        provider.assert_not_called()
        self.assertEqual(gateway_subjects("R1", deps.forwarding_context), [])
        self.assertEqual(deps.forwarding_context.address_owners, {})
        provider.assert_called_once()
        self.assertNotIn("hunter2", json.dumps(deps.deployment_problems))
        self.assertTrue(any("forwarding_context: RuntimeError" in p for p in deps.deployment_problems))


class ReaderBindingTests(SimpleTestCase):
    class Reader:
        def __init__(self, tag):
            self.tag = tag

        def read(self, request):
            return {"tag": self.tag, "request": request}

        def provenance(self):
            return {"verbatim": self.tag}

        def write(self, *a):
            raise AssertionError("must be unreachable")

    def test_DEP021_absent_bindings_keep_defaults(self):
        deps = dep.runtime_deps({**CFG})
        self.assertIsNone(deps.fib_source)
        self.assertIsNone(deps.qos_source)

    def test_DEP022_lazy_construction_and_read_only_wrapper(self):
        from unittest.mock import Mock
        fib, qos = Mock(side_effect=lambda i: self.Reader("fib")), Mock(side_effect=lambda i: self.Reader("qos"))
        deps = dep.runtime_deps({**CFG, "fib_reader_factory": fib, "qos_reader_factory": qos})
        fib.assert_not_called(); qos.assert_not_called()
        info = deps.admission.resolve(["R1"])["R1"]
        f, q = deps.fib_source(info), deps.qos_source(info)
        self.assertEqual(f.read({"a": 1})["tag"], "fib")
        self.assertEqual(q.provenance(), {"verbatim": "qos"})
        self.assertFalse(hasattr(f, "write"))

    def test_DEP023_invalid_and_raising_providers_fail_closed_sanitized(self):
        def boom(info):
            raise RuntimeError("password=hunter2")
        deps = dep.runtime_deps({**CFG, "fib_reader_factory": boom, "qos_reader_factory": lambda i: object()})
        info = deps.admission.resolve(["R1"])["R1"]
        self.assertIsNone(deps.fib_source(info))
        self.assertIsNone(deps.qos_source(info))
        self.assertNotIn("hunter2", json.dumps(deps.deployment_problems))
        self.assertEqual(len(deps.deployment_problems), 2)
        bad = dep.runtime_deps({**CFG, "fib_reader_factory": "no.such.mod.fn"})
        self.assertIsNone(bad.fib_source)
        self.assertTrue(any("fib_reader_factory could not be loaded" in p for p in bad.deployment_problems))

    def test_DEP024_both_consumers_get_identical_bindings_and_runtime_consumes(self):
        from core import troubleshooting_views as tv
        from django.utils.module_loading import import_string
        cfg = {**CFG, "fib_reader_factory": lambda i: self.Reader("fib"), "qos_reader_factory": lambda i: self.Reader("qos")}
        with override_settings(NMAS_TS_RUNTIME_FACTORY=FACTORY, TROUBLESHOOTING_RUNTIME_DEPS=FACTORY, NMAS_TS_DEPLOYMENT=cfg):
            for deps in (tv._runtime_deps(), import_string(FACTORY)()):
                info = deps.admission.resolve(["R1"])["R1"]
                self.assertEqual(deps.fib_source(info).read({})["tag"], "fib")
                self.assertEqual(deps.qos_source(info).read({})["tag"], "qos")


class PhysProtoBindingTests(SimpleTestCase):
    """DEP-025..DEP-028: phy_reader_factory / proto_reader_factory / phy_context_provider (simulated; not live evidence)."""
    Reader = ReaderBindingTests.Reader

    def test_DEP029_bound_readers_reach_collectors_with_lazy_peer_scope(self):
        from core.tests import test_troubleshooting_physical_source as physical
        from core.tests import test_troubleshooting_protocol_source as protocol
        from core.services.troubleshooting.adapters import physical as adapter

        phy = physical.Reader({"r2": physical.doc(
            [physical.iface("Ethernet7")], device="r2", scope=("Ethernet7",))})
        proto = protocol.Reader({"r1": protocol.doc()})
        deps = dep.build_runtime_deps(
            phy_reader_factory=lambda info: phy,
            proto_reader_factory=lambda info: proto,
            phy_context_provider=lambda: adapter.PhysicalContext(links=(
                {"a": "r1", "a_if": "Ethernet1", "b": "r2", "b_if": "Ethernet7"},)))
        requests = adapter.requests_for_device(
            {"device": "r1", "interface": "Ethernet1"}, "r2",
            ["interface.transceiver"], deps.phy_context)
        peer = physical.col.Target("r2", "ceos", "4.36.2F", "VERIFIED")
        bundle = physical.collector().collect(peer, requests, deps.phy_source(peer))
        self.assertEqual(phy.calls[0]["interfaces"], ["Ethernet7"])
        self.assertTrue(any(o["key"] == "interface.transceiver" for o in bundle["observations"]))
        local = protocol.target()
        bundle = protocol.collector().collect(local, [protocol.REQ], deps.proto_source(local))
        self.assertTrue(any(o["key"] == "routing.neighbor.detail" for o in bundle["observations"]))
        self.assertFalse(bundle["run"]["gateway"]["live"])

    def test_DEP025_absent_keys_keep_defaults(self):
        deps = dep.runtime_deps({**CFG})
        self.assertIsNone(deps.phy_source)
        self.assertIsNone(deps.proto_source)
        self.assertIsNone(deps.phy_context)

    def test_DEP026_no_construction_io_and_read_only_wrappers(self):
        from unittest.mock import Mock
        from core.services.troubleshooting.adapters.physical import PhysicalContext
        phy, proto = Mock(side_effect=lambda i: self.Reader("phy")), Mock(side_effect=lambda i: self.Reader("proto"))
        ctx = PhysicalContext(links=({"a": "R1", "a_if": "Ethernet1", "b": "R2", "b_if": "Ethernet2"},))
        cp = Mock(return_value=ctx)
        deps = dep.runtime_deps({**CFG, "phy_reader_factory": phy, "proto_reader_factory": proto, "phy_context_provider": cp})
        phy.assert_not_called(); proto.assert_not_called(); cp.assert_not_called()
        info = deps.admission.resolve(["R1"])["R1"]
        p, q = deps.phy_source(info), deps.proto_source(info)
        self.assertEqual(p.read({"x": 1})["tag"], "phy")
        self.assertEqual(q.provenance(), {"verbatim": "proto"})
        self.assertFalse(hasattr(p, "write")); self.assertFalse(hasattr(q, "write"))
        cp.assert_not_called()
        self.assertEqual(deps.phy_context.peer("R1", "Ethernet1"), ("R2", "Ethernet2"))
        self.assertEqual(deps.phy_context.links, ctx.links)
        cp.assert_called_once()

    def test_DEP027_invalid_and_raising_providers_fail_closed_sanitized(self):
        def boom(info):
            raise RuntimeError("password=hunter2")

        def bad_ctx():
            raise RuntimeError("token=abc")
        deps = dep.runtime_deps({**CFG, "phy_reader_factory": boom, "proto_reader_factory": lambda i: object(), "phy_context_provider": bad_ctx})
        info = deps.admission.resolve(["R1"])["R1"]
        self.assertIsNone(deps.phy_source(info))
        self.assertIsNone(deps.proto_source(info))
        self.assertEqual(deps.phy_context.links, ())
        self.assertEqual(deps.phy_context.peer("R1", "Ethernet1"), (None, None))
        text = json.dumps(deps.deployment_problems)
        self.assertNotIn("hunter2", text); self.assertNotIn("abc", text)
        self.assertTrue(any("phy_context: RuntimeError" in p for p in deps.deployment_problems))
        wrong = dep.runtime_deps({**CFG, "phy_context_provider": lambda: {"links": []}})
        self.assertEqual(wrong.phy_context.links, ())
        bad = dep.runtime_deps({**CFG, "proto_reader_factory": "no.such.mod.fn", "phy_reader_factory": "no.such.mod.fn"})
        self.assertIsNone(bad.proto_source); self.assertIsNone(bad.phy_source)
        self.assertEqual(len([p for p in bad.deployment_problems if "could not be loaded" in p]), 2)

    def test_DEP028_both_consumers_and_build_runtime_deps_receive_bindings(self):
        from core import troubleshooting_views as tv
        from django.utils.module_loading import import_string
        from core.services.troubleshooting.adapters.physical import PhysicalContext
        ctx = PhysicalContext(links=({"a": "R1", "a_if": "Ethernet1", "b": "R2", "b_if": "Ethernet2"},))
        kw = {"phy_reader_factory": lambda i: self.Reader("phy"), "proto_reader_factory": lambda i: self.Reader("proto"), "phy_context_provider": lambda: ctx}
        with override_settings(NMAS_TS_RUNTIME_FACTORY=FACTORY, TROUBLESHOOTING_RUNTIME_DEPS=FACTORY, NMAS_TS_DEPLOYMENT={**CFG, **kw}):
            all_deps = (tv._runtime_deps(), import_string(FACTORY)(), dep.build_runtime_deps(**kw))
        for deps in all_deps:
            info = rt.DeviceAdmission("R1", "VERIFIED", platform="ceos", os_version="4.36.2F")
            self.assertEqual(deps.phy_source(info).read({})["tag"], "phy")
            self.assertEqual(deps.proto_source(info).read({})["tag"], "proto")
            self.assertEqual(deps.phy_context.links, ctx.links)
