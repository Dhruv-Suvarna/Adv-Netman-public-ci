"""Direct tests for the bounded read-only collectors (troubleshooting/collectors.py).

The properties are the module's contract: collection is read-only (every write operation is refused before a transport is
touched), admission and capability are checked first and fail closed, budgets and backpressure are enforced and counted,
and every request is validated against the case scope before anything is sent.
"""

from __future__ import annotations

from datetime import timedelta

from django.test import SimpleTestCase

from core.services.troubleshooting import collectors as c, normalization as nz
from core.tests.test_troubleshooting_collectors import T0, Clock, collector, ceos
from core.tests.test_troubleshooting_fib_source import Reader as FibReader
from core.tests.test_troubleshooting_qos_source import Reader as QosReader, good_r1, qos_doc

def SUPPORTED(_platform, _source):  # pylint: disable=invalid-name  # used like the constant capability answer it stands for
    return {"status": "SUPPORTED"}


def target(**kw):
    return c.Target(**{"device": "R1", "platform": "ceos", "os_version": "4.36.2F", **kw})


class TelemetryPlanTests(SimpleTestCase):
    def test_plan_telemetry_returns_stream_when_gnmi_exists(self):
        self.assertEqual(c.plan_telemetry(gnmi=True, snmp=True)["selected"], [c.SourceType.GNMI_STREAM])

    def test_plan_telemetry_refuses_unknown_or_unavailable_choices(self):
        with self.subTest("an unknown preference is refused"):
            plan = c.plan_telemetry(gnmi=True, snmp=True, prefer="sometimes")
            self.assertEqual((plan["selected"], plan["error"]), ([], "INVALID_PREFERENCE"))
        with self.subTest("streaming without gnmi is unavailable, not substituted"):
            plan = c.plan_telemetry(gnmi=False, snmp=False, prefer="stream")
            self.assertEqual((plan["selected"], plan["unavailable"]), ([], [c.SourceType.GNMI_STREAM]))


class BudgetTests(SimpleTestCase):
    def test_budget_as_dict_and_tracker_accounting(self):
        budget = c.Budget(max_commands=3, min_interval_s=1.0, max_seconds=100)
        self.assertEqual(budget.as_dict()["max_commands"], 3)
        clock = Clock()
        tracker = c.BudgetTracker(budget, clock=clock, sleep=clock.sleep)
        tracker.before_request()
        tracker.before_request()                     # rate bound: waits min_interval_s
        tracker.add_bytes(10)
        tracker.add_records(2)
        clock.t += 0.5
        self.assertEqual(tracker.elapsed(), clock.t)
        self.assertEqual(tracker.used(), {"commands": 2, "seconds": 1.5, "bytes": 10, "records": 2, "retries": 0, "throttled_s": 1.0})

    def test_budget_tracker_refuses_each_exceeded_limit(self):
        clock = Clock()
        with self.subTest("a zero command budget is refused"):
            with self.assertRaises(c.BudgetExceeded) as caught:
                c.BudgetTracker(c.Budget(max_commands=0), clock=clock, sleep=clock.sleep).before_request()
            self.assertEqual(caught.exception.which, "COMMANDS")
        tracker = c.BudgetTracker(c.Budget(max_bytes=5, max_records=1), clock=clock, sleep=clock.sleep)
        with self.subTest("bytes beyond the budget are refused"):
            with self.assertRaises(c.BudgetExceeded) as caught:
                tracker.add_bytes(6)
            self.assertEqual(caught.exception.which, "BYTES")
        with self.subTest("records beyond the budget are refused"):
            with self.assertRaises(c.BudgetExceeded) as caught:
                tracker.add_records(2)
            self.assertEqual(caught.exception.which, "RECORDS")
        with self.subTest("a tracker with no requests has used none"):
            self.assertEqual(c.BudgetTracker(c.Budget(), clock=clock, sleep=clock.sleep).used()["commands"], 0)

    def test_bounded_buffer_accepts_until_capacity(self):
        buffer = c.BoundedBuffer(2)
        self.assertEqual([buffer.offer(1), buffer.offer(2), buffer.offer(3)], [True, True, False])
        self.assertEqual((buffer.items, buffer.dropped), ([1, 2], 1))


class AdmissionAndCatalogueTests(SimpleTestCase):
    def test_target_canonical_platform_and_admission(self):
        t = target(platform="arista_eos", capabilities={c.SourceType.CLI: "SUPPORTED"})
        self.assertEqual(t.canonical_platform, c.canonical_platform("arista_eos"))
        self.assertTrue(c.check_admission(ceos(), c.SourceType.CLI).ok)
        self.assertEqual(c.check_admission(ceos(maintenance=True), c.SourceType.CLI).flags, ("MAINTENANCE_MODE",))

    def test_check_admission_refuses_before_any_transport(self):
        cases = (
            ("a write operation", dict(t=ceos(), operation="write"), c.Missing.UNSUPPORTED_OPERATION),
            ("an unknown source type", dict(t=ceos(), source="TELEPATHY"), c.Missing.UNSUPPORTED_OPERATION),
            ("a withdrawn device", dict(t=ceos(withdrawn=True)), c.Missing.NOT_ADMITTED),
            ("an unverified device", dict(t=ceos(verified=False)), c.Missing.NOT_ADMITTED),
            ("an unauthorized source", dict(t=ceos(), authorized=()), c.Missing.NOT_ADMITTED),
            ("an unknown capability", dict(t=target()), c.Missing.UNSUPPORTED_PLATFORM),
        )
        for label, kw, code in cases:
            with self.subTest(f"{label} is refused"):
                adm = c.check_admission(kw["t"], kw.get("source", c.SourceType.CLI), operation=kw.get("operation", "read"),
                                        authorized_sources=kw.get("authorized"))
                self.assertEqual((adm.ok, adm.code), (False, code))

    def test_commands_for_unknown_platform_or_domain_is_empty(self):
        with self.subTest("an unknown platform has no commands"):
            self.assertEqual(c.commands_for("no-such-os"), [])
        with self.subTest("config commands are not listed unless asked"):
            self.assertFalse(any(spec.kind == "config" for spec in c.commands_for("ceos", "4.36.2F")))

    def test_extract_version_returns_the_platform_version(self):
        self.assertEqual(c.extract_version("Arista vEOS\nSoftware image version: 4.36.2F\n"), "4.36.2F")
        self.assertEqual(c.extract_version("FRRouting 8.4.4 (r1)"), "8.4.4")

    def test_extract_version_of_unversioned_text_is_empty(self):
        for text in ("", None, "no version here"):
            with self.subTest(f"{text!r} carries no version"):
                self.assertEqual(c.extract_version(text), "")


class RunAndBundleTests(SimpleTestCase):
    def run_for(self, t=None):
        clock = Clock()
        tracker = c.BudgetTracker(c.Budget(), clock=clock, sleep=clock.sleep)
        return c._Run("cli", c.SourceType.CLI, t or ceos(), tracker=tracker, clock_now=lambda: T0, transport="t", adapter="a",
                      admission=c.Admission(True, flags=("MAINTENANCE_MODE",)))

    def test_raw_store_run_and_bundle_build_complete_results(self):
        store = c.InMemoryRawStore()
        self.assertEqual(store.put("abc", "redacted"), "mem:abc")
        run = self.run_for()
        self.assertEqual((run.next_seq(), run.next_seq(), run.flags), (1, 2, ["MAINTENANCE_MODE"]))
        run.requested = 1
        run.evidence.append(c.build_evidence(seq=1, source_type="CLI", transport="t", adapter="a", device="R1", platform="ceos", os_version="",
                                             command_or_api="show version", raw="x", started_at=T0, finished_at=T0, status="OK", store=store))
        bundle = run.bundle(extra={"note": "n"})
        self.assertEqual((bundle["run"]["status"], bundle["run"]["note"], bundle["coverage"]["collected"]), ("COMPLETE", "n", 1))
        merged = c.merge_bundles([bundle, bundle])
        self.assertEqual((len(merged["runs"]), merged["coverage"]["collected"]), (2, 2))

    def test_empty_or_refused_runs_are_not_complete(self):
        with self.subTest("a run with no evidence is failed"):
            self.assertEqual(self.run_for().bundle()["run"]["status"], "FAILED")
        with self.subTest("a run without admission is refused"):
            run = self.run_for()
            run.refused = c.Admission(False, c.Missing.NOT_ADMITTED, "no")
            self.assertEqual(run.bundle()["run"]["admission"], {"ok": False, "code": c.Missing.NOT_ADMITTED, "detail": "no"})
        with self.subTest("a store put with no text keeps an empty entry"):
            store = c.InMemoryRawStore()
            store.put("h", "")
            self.assertEqual(store.items, {"h": ""})
        with self.subTest("merging no bundles yields none"):
            self.assertEqual(c.merge_bundles([])["runs"], [])
        with self.subTest("a fresh run has no sequence and no flags without admission"):
            clock = Clock()
            bare = c._Run("cli", c.SourceType.CLI, ceos(), tracker=c.BudgetTracker(c.Budget(), clock=clock, sleep=clock.sleep), clock_now=lambda: T0,
                          transport="t", adapter="a")
            self.assertEqual((bare.seq, bare.flags), (0, []))

    def test_every_write_operation_is_refused_without_a_transport(self):
        gnmi, _ = collector(c.GnmiCollector, capability_probe=SUPPORTED)
        netconf, _ = collector(c.NetconfCollector, capability_probe=SUPPORTED)
        base, _ = collector(c.CliCollector, capability_probe=SUPPORTED)
        for label, bundle in (("gnmi set", gnmi.set(ceos())), ("netconf edit-config", netconf.edit_config(ceos())),
                              ("a named write", base.refuse_operation(ceos(), "configure terminal"))):
            with self.subTest(f"{label} is refused"):
                self.assertEqual((bundle["run"]["status"], bundle["missing"][0]["reason"]), ("REFUSED", c.Missing.UNSUPPORTED_OPERATION))

    def test_write_entry_points_return_a_bundle_naming_the_operation(self):
        base, _ = collector(c.CliCollector, capability_probe=SUPPORTED)
        gnmi, _ = collector(c.GnmiCollector, capability_probe=SUPPORTED)
        netconf, _ = collector(c.NetconfCollector, capability_probe=SUPPORTED)
        self.assertEqual(gnmi.set(ceos())["run"]["command_or_api"], ["REFUSED:gNMI Set"])
        self.assertEqual(netconf.edit_config(ceos())["run"]["command_or_api"], ["REFUSED:NETCONF edit-config"])
        self.assertEqual(base.refuse_operation(ceos(), "reload", "custom")["run"]["command_or_api"], ["REFUSED:reload"])


class RequestValidationTests(SimpleTestCase):
    POLICY = c.ProbePolicy(authorization_id="AUTH-1", admitted_sources=("h1",), destinations=("h2",), ports=(443, 33434),
                           flow={"src": "h1", "dst": "h2", "protocol": "tcp", "port": 443}, pmtu_authorized=True, pmtu_protocols=("icmp", "udp"),
                           pmtu_families=("ipv4",))

    def tcp(self, **kw):
        return c.ProbeRequest(**{"op": "tcp_connect", "src": "h1", "dst": "h2", "dst_address": "10.2.2.20", "protocol": "tcp", "port": 443, "count": 3, **kw})

    def pmtu(self, **kw):
        return c.ProbeRequest(**{"op": "pmtu_probe", "src": "h1", "dst": "h2", "dst_address": "10.2.2.20", "protocol": "icmp", "count": 2,
                                 "sizes": (1000, 1472), "family": "ipv4", "rate_pps": 2, "max_seconds": 10.0, **kw})

    def test_dns_request_as_dict_and_command(self):
        req = c.DnsRequest("query", server="10.0.0.53", name="app.lab", qtype="A")
        self.assertEqual(req.as_dict()["name"], "app.lab")
        self.assertEqual(req.command(), "dns:query name=app.lab type=A server=10.0.0.53 proto=udp")

    def test_dns_request_validate_refuses_out_of_scope_requests(self):
        cases = (("an unknown operation", c.DnsRequest("axfr", server="10.0.0.53", zone="lab"), None),
                 ("a zone transfer type", c.DnsRequest("query", server="10.0.0.53", name="app.lab", qtype="AXFR"), None),
                 ("an unauthorized server", c.DnsRequest("query", server="10.9.9.9", name="app.lab", qtype="A"), ["10.0.0.53"]),
                 ("a bad transport", c.DnsRequest("query", server="10.0.0.53", name="app.lab", qtype="A", transport="quic"), None))
        for label, req, allowed in cases:
            with self.subTest(f"{label} is refused"):
                normalised, errors = req.validate(allowed)
                self.assertIsNone(normalised)
                self.assertTrue(errors)

    def test_probe_request_shape_cost_and_wire(self):
        tcp, pm = self.tcp(), self.pmtu()
        self.assertEqual((tcp.cost(), tcp.packets()), (3, 0))
        self.assertEqual((pm.packets(), pm.cost(), pm.max_packet_bytes()), (4, 4, (1028 + 1500) * 2))
        self.assertIn("probe:tcp_connect src=h1 dst=h2(10.2.2.20) port=443", tcp.command())
        self.assertIn("sizes=1000,1472", pm.command())
        self.assertEqual(tcp.validate(self.POLICY, T0, "h1"), [])
        self.assertEqual(pm.validate(self.POLICY, T0, "h1"), [])
        self.assertEqual(tcp.wire(self.POLICY, 5.0)["port"], 443)
        self.assertEqual(pm.wire(self.POLICY, 5.0)["max_packets"], 4)

    def test_probe_request_validate_refuses_out_of_scope_probes(self):
        cases = (("an unknown operation", self.tcp(op="flood")), ("a foreign source", self.tcp(src="h9")),
                 ("an off-flow port", self.tcp(port=22)), ("a multicast destination", self.tcp(dst_address="224.0.0.1")),
                 ("an excessive count", self.tcp(count=50)), ("a size probe without DF", self.pmtu(df=False)),
                 ("a tcp size probe", self.pmtu(protocol="tcp")), ("duplicate sizes", self.pmtu(sizes=(1000, 1000))))
        for label, req in cases:
            with self.subTest(f"{label} is refused"):
                self.assertTrue(req.validate(self.POLICY, T0, "h1"))

    def test_probe_wire_of_a_non_tcp_trace_carries_no_port(self):
        trace = c.ProbeRequest("path_trace", src="h1", dst="h2", dst_address="10.2.2.20", method="icmp", max_hops=5)
        with self.subTest("an icmp trace carries no port"):
            self.assertIsNone(trace.wire(self.POLICY, 5.0)["port"])


class CollectorDirectTests(SimpleTestCase):
    NOTIF = {"timestamp": int(T0.timestamp() * 1e9), "prefix": "/interfaces/interface[name=Ethernet1]", "update": [{"path": "state/oper-status", "val": "UP"}]}

    def test_gnmi_validate_paths_and_get(self):
        self.assertEqual(c.GnmiCollector.validate_paths(["/interfaces/interface"]), [])
        gnmi, _ = collector(c.GnmiCollector, capability_probe=SUPPORTED)
        bundle = gnmi.get(ceos(), ["/interfaces/interface"], lambda paths: [self.NOTIF])
        self.assertEqual((bundle["run"]["status"], bundle["observations"][0]["key"]), ("COMPLETE", "interface.oper_state"))

    def test_gnmi_refuses_paths_outside_the_allowlist(self):
        gnmi, _ = collector(c.GnmiCollector, capability_probe=SUPPORTED)
        with self.subTest("a system path is outside the allowlist"):
            self.assertEqual(c.GnmiCollector.validate_paths(["/system/aaa"]), ["/system/aaa"])
        with self.subTest("a get outside the allowlist is refused"):
            bundle = gnmi.get(ceos(), ["/system/aaa"], lambda paths: [self.NOTIF])
            self.assertEqual(bundle["missing"][0]["reason"], c.Missing.COMMAND_NOT_ALLOWED)

    def test_snmp_poll_refuses_columns_outside_if_mib(self):
        snmp, _ = collector(c.SnmpCollector, capability_probe=SUPPORTED)
        bundle = snmp.poll(ceos(), session=None, columns=["sysContact"])
        self.assertEqual((bundle["run"]["status"], bundle["missing"][0]["reason"]), ("REFUSED", c.Missing.COMMAND_NOT_ALLOWED))

    def test_syslog_collect_refuses_an_unadmitted_device(self):
        syslog, _ = collector(c.SyslogCollector, capability_probe=SUPPORTED)
        bundle = syslog.collect(ceos(lifecycle_state="DECOMMISSIONED"), [("<189>Nov  9 12:00:05 R1 Ebra: x", T0)])
        self.assertEqual((bundle["run"]["status"], bundle["observations"]), ("REFUSED", []))

    def test_capture_authorization_problem_accepts_a_scoped_authorization(self):
        auth = {"authorized_by": "op", "ticket": "CHG-1", "expires_at": (T0 + timedelta(minutes=5)).isoformat(), "device": "R1", "interface": "Eth1"}
        self.assertEqual(c.CaptureMetadataCollector.authorization_problem(auth, {"interface": "Ethernet1"}, "R1", T0), "")

    def test_capture_authorization_problem_refuses_missing_expired_or_foreign_scope(self):
        auth = {"authorized_by": "op", "ticket": "CHG-1", "expires_at": (T0 + timedelta(minutes=5)).isoformat(), "device": "R1", "interface": "Eth1"}
        cases = (("no authorization", None, "NO_AUTHORIZATION"), ("no ticket", {**auth, "ticket": ""}, "AUTHORIZATION_MISSING_TICKET"),
                 ("an expired authorization", {**auth, "expires_at": (T0 - timedelta(seconds=1)).isoformat()}, "AUTHORIZATION_EXPIRED"),
                 ("another interface", {**auth, "interface": "Eth2"}, "AUTHORIZATION_SCOPE_MISMATCH"))
        for label, a, code in cases:
            with self.subTest(f"{label} is refused"):
                self.assertEqual(c.CaptureMetadataCollector.authorization_problem(a, {"interface": "Ethernet1"}, "R1", T0), code)

    def test_netconf_interfaces_xml_converts_to_openconfig(self):
        xml = ("<data xmlns='urn:ietf:params:xml:ns:netconf:base:1.0'><interfaces xmlns='http://openconfig.net/yang/interfaces'><interface>"
               "<name>Ethernet1</name><state><oper-status>UP</oper-status><counters><in-errors>3</in-errors></counters></state>"
               "</interface></interfaces></data>")
        rows = c.netconf_interfaces_xml_to_openconfig(xml)["openconfig-interfaces:interfaces"]["interface"]
        self.assertEqual(rows, [{"name": "Ethernet1", "state": {"oper-status": "UP", "counters": {"in-errors": 3}}}])

    def test_netconf_xml_with_entities_is_refused(self):
        with self.assertRaises(ValueError):
            c.netconf_interfaces_xml_to_openconfig("<!DOCTYPE x [<!ENTITY e SYSTEM 'file:///etc/passwd'>]><data>&e;</data>")

    def test_provider_collector_refuses_bad_types_and_failing_providers(self):
        with self.subTest("a non-provider source type is refused"):
            with self.assertRaises(ValueError):
                c.ProviderCollector(c.SourceType.CLI)
        provider = c.ProviderCollector(c.SourceType.CONFIG_SNAPSHOT, now=lambda: T0, capability_probe=SUPPORTED)

        def unavailable():
            raise OSError("down")
        with self.subTest("an unavailable provider is a missing record"):
            bundle = provider.collect(ceos(), unavailable)
            self.assertEqual((bundle["observations"], bundle["missing"][0]["reason"]), ([], c.Missing.TRANSPORT_ERROR))
        with self.subTest("an empty provider is a missing record"):
            self.assertEqual(provider.collect(ceos(), dict)["missing"][0]["reason"], c.Missing.EMPTY)

    def test_fib_collect_refuses_a_failing_source(self):
        fib = c.FibCollector(capability_probe=SUPPORTED, now=lambda: T0, clock=lambda: 0.0, sleep=lambda s: None)
        bundle = fib.collect(target(device="r1"), [{"vrf": "default", "family": "ipv4", "prefixes": ["10.2.2.0/24"]}],
                             FibReader({"r1": c.PermissionDenied()}))
        self.assertEqual((bundle["observations"], bundle["missing"][0]["reason"]), ([], nz.Missing.PERMISSION_DENIED))

    def test_qos_collect_returns_observations_for_a_complete_document(self):
        qos = c.QosCollector(capability_probe=SUPPORTED, now=lambda: T0, clock=lambda: 0.0, sleep=lambda s: None)
        bundle = qos.collect(target(device="r1"), [{"vrf": "default"}], QosReader({"r1": qos_doc("r1", [good_r1()])}))
        self.assertEqual(bundle["run"]["privileges"], "read-only")
        self.assertTrue(bundle["observations"])
        self.assertTrue(bundle["evidence"])

    def test_qos_collect_refuses_failing_or_unadmitted_sources(self):
        qos = c.QosCollector(capability_probe=SUPPORTED, now=lambda: T0, clock=lambda: 0.0, sleep=lambda s: None)
        with self.subTest("a timed-out source is a missing record"):
            bundle = qos.collect(target(device="r1"), [{}], QosReader({"r1": TimeoutError()}))
            self.assertEqual(bundle["missing"][0]["reason"], nz.Missing.TRANSPORT_ERROR)
        with self.subTest("a decommissioned device is refused before reading"):
            reader = QosReader({"r1": qos_doc("r1", [good_r1()])})
            bundle = qos.collect(target(device="r1", lifecycle_state="DECOMMISSIONED"), [{}], reader)
            self.assertEqual((bundle["run"]["status"], reader.calls), ("REFUSED", []))
