"""V2 Phase 5B -- traffic / test workbench, website side, over the REAL traffic runner with a scripted container runtime.

Nothing is spawned and no container is touched.  The runner itself (policy, runtime argv, IPC, failures) is ``test_traffic_runner``.
"""

from __future__ import annotations

import ast
from datetime import timedelta
from pathlib import Path
from unittest import mock

from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from core import models
from core.services import traffic_service as ts
from core.services.health import inventory
from core.services.traffic import client, endpoints, limits, parsers, service
from core.tests.helpers import traffic as t

S = models.TrafficRunStatus
TRAFFIC_DIR = Path(service.__file__).parent


def go(world=None, **overrides):
    with t.wired(world) as w:
        run, errors = ts.request_run(t.request(**overrides), operator="tester")
    return run, errors, w


class EndpointCatalogueTests(TestCase):
    def test_catalogue_is_the_tracked_endpoints_and_nothing_else(self):
        catalogue = endpoints.catalogue()
        self.assertEqual(sorted(catalogue), ["H1", "H2", "H3", "H4", "WebServer"])
        self.assertEqual(catalogue["H4"].families, ("IPV6",))                     # H4 is IPv6-only by lab design
        self.assertEqual(catalogue["H1"].container, "clab-srlceos01-H1")
        for managed in ("R1", "R5", "S1", "mgmt_swt"):
            self.assertIsNone(endpoints.get(managed))

    def test_endpoints_stay_unmanaged(self):
        run, errors, _ = go()
        self.assertEqual((run.status, errors), (S.PASSED, []))
        self.assertEqual(models.ProvisionedDevice.objects.count(), 0)
        self.assertEqual(set(inventory.managed_devices()) & {"H1", "H2", "H3", "H4", "WebServer"}, set())

    def test_non_endpoints_and_same_endpoint_are_refused_without_spawning(self):
        for overrides, code in (({"source": "R1"}, "SOURCE_NOT_AN_ENDPOINT"), ({"destination": "8.8.8.8"}, "DESTINATION_NOT_AN_ENDPOINT"),
                                ({"destination": "H1"}, "SAME_ENDPOINT"), ({"destination": "clab-srlceos01-R1"}, "DESTINATION_NOT_AN_ENDPOINT")):
            run, errors, world = go(**overrides)
            self.assertIsNone(run)
            self.assertEqual([e["code"] for e in errors], [code])
            self.assertEqual(world.calls, [])
        self.assertEqual(models.TrafficRun.objects.count(), 0)

    def test_ipv4_with_the_ipv6_only_endpoint_is_not_applicable_not_a_failed_test(self):
        for overrides in ({"source": "H4"}, {"destination": "H4"}):
            run, errors, world = go(**overrides)
            self.assertIsNone(run)
            self.assertEqual(errors[0]["code"], "FAMILY_NOT_SUPPORTED_BY_ENDPOINT")
            self.assertEqual(world.calls, [])
        run, _errors, _ = go(source="H1", destination="H4", address_family="IPV6")
        self.assertEqual((run.status, run.destination_address), (S.PASSED, "2001:db8:30::18e5"))

    def test_addresses_are_discovered_never_typed(self):
        run, _errors, world = go(destination_address="10.0.0.1", address="10.0.0.1", target="10.0.0.1")   # ignored fields
        self.assertEqual((run.source_address, run.destination_address), ("192.168.10.102", "192.168.20.101"))
        ping = next(args for _pid, tool, args in world.calls if tool == "ping")
        self.assertEqual(ping[-1], "192.168.20.101")
        self.assertNotIn("10.0.0.1", repr(world.calls) + repr(run.requested))

    def test_management_and_link_local_addresses_are_never_test_paths(self):
        from core.services.traffic.runner.engine import parse_addresses
        text = '[{"ifname":"eth0","addr_info":[{"local":"172.20.20.2","scope":"global"}]},{"ifname":"eth1","addr_info":[{"local":"fe80::1","scope":"link"},{"local":"2001:db8::2","scope":"global"}]}]'
        self.assertEqual(parse_addresses(text), {"IPV4": [], "IPV6": ["2001:db8::2"]})
        self.assertEqual(parse_addresses("not json"), {"IPV4": [], "IPV6": []})


class WebsiteBoundaryTests(SimpleTestCase):
    def test_contract_the_website_starts_no_process_for_a_traffic_test(self):
        """The website's traffic code never spawns: its only ``subprocess`` use is the read-only Git HEAD lookup, its only ``socket`` use
        is the runner client, and it never names the container runtime.  (The runner's own single spawn point: ``test_traffic_runner``.)"""
        users, socket_users = {}, []
        for path in sorted(TRAFFIC_DIR.glob("*.py")):
            tree, text = ast.parse(path.read_text()), path.read_text()
            imports = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names} | {
                (n.module or "").split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
            for forbidden in ("os", "netmiko", "paramiko", "pty", "shlex", "docker", "multiprocessing", "ctypes"):
                self.assertNotIn(forbidden, imports, f"{path.name} imports {forbidden}")
            if "socket" in imports:
                socket_users.append(path.name)
            calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                     and getattr(n.func.value, "id", "") == "subprocess"]
            if calls or "subprocess" in imports:
                users[path.name] = calls
            for forbidden in ("shell=True", "os.system", "Popen", "nsenter", "sudo", "docker"):
                self.assertFalse(forbidden in text, f"{path.name}: {forbidden}")
            self.assertFalse({"runtime", "engine"} & {a.name for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) for a in n.names},
                             f"{path.name} reaches into the runner's execution modules")
        self.assertEqual(sorted(users), ["service.py"])
        self.assertEqual([c.args[0].elts[0].value for c in users["service.py"]], ["git"])           # provenance only
        self.assertEqual(socket_users, ["client.py"])
        for module in ("views.py", "services/traffic_service.py", "management/commands/traffic_reconcile.py",
                       "management/commands/traffic_runner_config.py"):
            text = (TRAFFIC_DIR.parents[1] / module).read_text()
            self.assertNotIn("subprocess", text.split("# V2 Phase 5B")[-1] if module == "views.py" else text)

    def test_the_browser_fields_are_a_closed_list_without_commands(self):
        for field in service._FIELDS:
            for forbidden in ("command", "cmd", "argv", "flag", "pid", "namespace", "container", "image", "address", "shell", "raw"):
                self.assertNotIn(forbidden, field.replace("address_family", ""))

    def test_the_request_document_is_ids_enumerations_and_bounded_integers_only(self):
        run = models.TrafficRun(operator="t", source="H1", destination="H2", address_family="IPV4", family="ICMP", protocol="ICMP",
                                parameters={"count": 3, "size": 56})
        document = client.document(run)
        self.assertEqual(set(document), {"v", "run_id", "source_endpoint_id", "destination_endpoint_id", "address_family", "test_type",
                                         "protocol", "parameters"})
        self.assertEqual((document["source_endpoint_id"], document["destination_endpoint_id"], document["run_id"]), ("H1", "H2", str(run.run_id)))
        self.assertNotIn("clab-", repr(document))                                    # an id, never a container name

    def test_a_reply_for_another_run_or_of_the_wrong_shape_is_never_recorded(self):
        run = models.TrafficRun(operator="t", source="H1", destination="H2", address_family="IPV4", family="ICMP", protocol="ICMP")
        good = {"v": 1, "ok": True, "run_id": str(run.run_id)}
        self.assertIs(client.check(good, run), good)
        for bad in ({**good, "run_id": "00000000-0000-4000-8000-000000000000"}, {**good, "v": 2}, {**good, "ok": "yes"}, [good], None,
                    {"v": 1, "ok": False, "run_id": str(run.run_id)}, {"v": 1, "ok": True, "run_id": ""},
                    {"v": 1, "ok": True, "run_id": "", "refused": True}):
            with self.assertRaises(client.ClientError, msg=bad) as raised:
                client.check(bad, run)
            self.assertEqual(raised.exception.code, "RUNNER_PROTOCOL_ERROR")

    def test_both_validation_layers_enforce_the_same_numbers(self):
        from core.services.traffic.runner import policy
        self.assertEqual(policy.BOUNDS, {
            "ICMP": {"count": limits.PING_COUNT, "size": limits.PING_SIZE}, "TRACEROUTE": {"max_hops": limits.TRACEROUTE_MAX_HOPS},
            "TCP_CONNECT": {"port": limits.PORT, "timeout": limits.PROBE_TIMEOUT},
            "UDP_PROBE": {"port": limits.PORT, "timeout": limits.PROBE_TIMEOUT, "count": limits.UDP_PROBE_COUNT, "size": limits.UDP_PROBE_SIZE},
            "IPERF3": {"port": limits.IPERF_PORTS, "duration": limits.IPERF_DURATION, "bandwidth_kbps": limits.IPERF_BANDWIDTH_KBPS,
                       "parallel": limits.IPERF_PARALLEL}})
        self.assertEqual((policy.IPERF_UDP_LENGTH, policy.MAX_ACTIVE_RUNS), (limits.IPERF_UDP_LENGTH, limits.MAX_ACTIVE_RUNS))
        self.assertEqual({k: tuple(v) for k, v in policy.PROTOCOL.items()}, {str(k): tuple(v) for k, v in limits.PROTOCOL.items()})
        self.assertEqual((policy.PING_PER_PACKET_WAIT, policy.TRACEROUTE_WAIT, policy.IPERF_SERVER_READY_SECONDS, policy.IPERF_GRACE_SECONDS),
                         (limits.PING_PER_PACKET_WAIT, limits.TRACEROUTE_WAIT, limits.IPERF_SERVER_READY_SECONDS, limits.IPERF_GRACE_SECONDS))
        self.assertEqual(set(policy.ADDRESS_FAMILIES), set(models.TrafficAddressFamily.values))
        self.assertEqual(set(policy.BOUNDS), set(models.TrafficTestFamily.values))


class BoundsTests(TestCase):
    def test_every_bound_refuses_out_of_range_and_non_numeric_values(self):
        cases = (
            ({"family": "ICMP", "count": "11"}, "count"), ({"family": "ICMP", "count": "0"}, "count"), ({"family": "ICMP", "size": "9000"}, "size"),
            ({"family": "ICMP", "count": "3 -f"}, "count"), ({"family": "ICMP", "count": "-1"}, "count"), ({"family": "ICMP", "count": "1e3"}, "count"),
            ({"family": "TRACEROUTE", "max_hops": "64"}, "max_hops"),
            ({"family": "TCP_CONNECT"}, "port"), ({"family": "TCP_CONNECT", "port": "70000"}, "port"), ({"family": "TCP_CONNECT", "port": "80", "timeout": "60"}, "timeout"),
            ({"family": "UDP_PROBE", "port": "53", "count": "100"}, "count"), ({"family": "UDP_PROBE", "port": "53", "size": "65000"}, "size"),
            ({"family": "IPERF3", "duration": "3600"}, "duration"), ({"family": "IPERF3", "bandwidth_kbps": "1000000"}, "bandwidth_kbps"),
            ({"family": "IPERF3", "bandwidth_kbps": "0"}, "bandwidth_kbps"), ({"family": "IPERF3", "parallel": "32"}, "parallel"),
            ({"family": "IPERF3", "port": "22"}, "port"), ({"family": "IPERF3", "protocol": "UDP", "length": "65507"}, "length"),
        )
        for overrides, field in cases:
            run, errors, world = go(**overrides)
            self.assertIsNone(run, overrides)
            self.assertEqual([(e["code"], e.get("field")) for e in errors], [("PARAMETER_OUT_OF_BOUNDS", field)], overrides)
            self.assertEqual(world.calls, [], overrides)
        self.assertEqual(models.TrafficRun.objects.count(), 0)

    def test_limits_are_conservative_and_the_bitrate_is_never_unlimited(self):
        self.assertLessEqual(limits.IPERF_DURATION[1], 10)
        self.assertLessEqual(limits.IPERF_BANDWIDTH_KBPS[1], 10_000)
        self.assertGreater(limits.IPERF_BANDWIDTH_KBPS[0], 0)
        self.assertLessEqual(limits.IPERF_PARALLEL[1], 2)
        self.assertEqual(limits.MAX_ACTIVE_RUNS, 1)
        run, _errors, world = go(family="IPERF3")                                  # no bitrate given: the default cap applies
        client = next(args for _pid, tool, args in world.calls if tool == "iperf3")
        self.assertEqual(client[client.index("-b") + 1], "1000K")
        self.assertEqual(run.parameters["bandwidth_kbps"], 1000)

    def test_unknown_family_protocol_and_reference_are_refused(self):
        self.assertEqual(go(family="FLOOD")[1][0]["code"], "FAMILY_UNKNOWN")
        self.assertEqual(go(address_family="IPX")[1][0]["code"], "ADDRESS_FAMILY_UNKNOWN")
        self.assertEqual(go(family="ICMP", protocol="TCP")[1][0]["code"], "PROTOCOL_NOT_APPLICABLE")
        self.assertEqual(go(family="TCP_CONNECT", port="80", protocol="UDP")[1][0]["code"], "PROTOCOL_NOT_APPLICABLE")
        self.assertEqual(go(change_id="CHG-19990101-0001")[1][0]["code"], "REFERENCE_UNKNOWN")
        self.assertEqual(go(prov_id="PROV-1; drop")[1][0]["code"], "REFERENCE_UNKNOWN")

    def test_run_timeout_is_bounded_for_every_family(self):
        worst = {"ICMP": {"count": 10}, "TRACEROUTE": {"max_hops": 20}, "TCP_CONNECT": {"timeout": 5}, "UDP_PROBE": {"timeout": 5, "count": 5},
                 "IPERF3": {"duration": 10}}
        for family, parameters in worst.items():
            self.assertLessEqual(limits.run_timeout_seconds(family, parameters), 60, family)


class ParserTests(SimpleTestCase):
    def test_ping(self):
        metrics = parsers.ping(t.PING_OK)
        self.assertEqual((metrics["transmitted"], metrics["received"], metrics["loss_percent"]), (3, 3, 0.0))
        self.assertEqual((metrics["rtt_min_ms"], metrics["rtt_avg_ms"], metrics["rtt_max_ms"], metrics["rtt_mdev_ms"]), (2.454, 5.143, 10.257, 3.617))
        self.assertIsNone(parsers.ping(t.PING_DEAD)["rtt_avg_ms"])
        with self.assertRaises(parsers.ParseError):
            parsers.ping("ping: connect: Network is unreachable")

    def test_traceroute_ipv4_ipv6_and_silent_hops(self):
        v4 = parsers.traceroute(t.TRACE_OK, "192.168.20.101")
        self.assertEqual(v4["hops"], [{"hop": 1, "address": None, "rtt_ms": None}, {"hop": 2, "address": "192.168.20.101", "rtt_ms": 10.002}])
        self.assertEqual((v4["reached"], v4["silent_hops"], v4["hop_count"]), (True, 1, 2))
        v6 = parsers.traceroute(t.TRACE_V6, "2001:db8:20::2001")
        self.assertEqual(([h["address"] for h in v6["hops"]], v6["reached"]), (["2001:db8:10::1", "2001:db8:20::2001"], True))
        self.assertFalse(parsers.traceroute(t.TRACE_SHORT, "192.168.20.101")["reached"])
        with self.assertRaises(parsers.ParseError):
            parsers.traceroute("traceroute: unknown host", "x")

    def test_iperf3_tcp_and_udp_json(self):
        tcp = parsers.iperf3(t.iperf_tcp(1_000_000.0), udp=False)
        self.assertEqual((tcp["bits_per_second"], tcp["retransmits"], tcp["bytes"]), (1_000_000.0, 2, 393216))
        udp = parsers.iperf3(t.iperf_udp(lost=3, packets=300), udp=True)
        self.assertEqual((udp["jitter_ms"], udp["lost_packets"], udp["packets"], udp["loss_percent"]), (0.412, 3, 300, 1.0))
        for text in ("", "not json", '{"error": "unable to connect to server: Connection refused"}', '{"end": {}}', "[]"):
            with self.assertRaises(parsers.ParseError):
                parsers.iperf3(text, udp=False)

    def test_probe(self):
        self.assertEqual(parsers.probe('noise\n{"result": "refused", "elapsed_ms": 0.4}\n')["result"], "refused")
        with self.assertRaises(parsers.ParseError):
            parsers.probe("Traceback (most recent call last):")


class RunTests(TestCase):
    def test_icmp_ipv4_and_ipv6(self):
        v4, _e, world = go()
        self.assertEqual((v4.status, v4.protocol, v4.metrics["received"], v4.failure_reason), (S.PASSED, "ICMP", 3, ""))
        self.assertIn("-4", world.calls[-1][2])
        v6, _e, world = go(address_family="IPV6")
        self.assertEqual((v6.status, v6.destination_address), (S.PASSED, "2001:db8:20::2001"))
        self.assertIn("-6", world.calls[-1][2])
        self.assertEqual(world.tools(), ["ping"])                                   # a ping is a ping: no throughput tool was involved

    def test_icmp_loss_and_unreachable_are_failures_with_metrics(self):
        world = t.World(); world.outputs["ping"] = t.PING_LOSS
        run, _e, _ = go(world)
        self.assertEqual((run.status, run.failure_reason, run.metrics["received"]), (S.FAILED, "PACKET_LOSS", 1))
        world = t.World(); world.outputs["ping"] = t.PING_DEAD
        run, _e, _ = go(world)
        self.assertEqual((run.status, run.failure_reason, run.metrics["loss_percent"]), (S.FAILED, "DESTINATION_UNREACHABLE", 100.0))

    def test_traceroute(self):
        run, _e, world = go(family="TRACEROUTE")
        self.assertEqual((run.status, run.metrics["hop_count"], run.metrics["reached"]), (S.PASSED, 2, True))
        args = world.calls[-1][2]
        self.assertEqual((args[args.index("-m") + 1], args[args.index("-q") + 1], "-n" in args), ("15", "1", True))
        world = t.World(); world.outputs["traceroute"] = t.TRACE_SHORT
        run, _e, _ = go(world, family="TRACEROUTE", max_hops="2")
        self.assertEqual((run.status, run.failure_reason), (S.FAILED, "PATH_INCOMPLETE"))

    def test_tcp_connectivity_connected_refused_and_timeout(self):
        run, _e, world = go(family="TCP_CONNECT", port="80")
        self.assertEqual((run.status, run.protocol, run.metrics["result"]), (S.PASSED, "TCP", "connected"))
        self.assertEqual(world.calls[-1][2], ["192.168.20.101", "80", "3"])
        for result, reason in (("refused", "CONNECTION_REFUSED"), ("timeout", "CONNECTION_TIMEOUT"), ("unreachable", "DESTINATION_UNREACHABLE")):
            world = t.World(); world.outputs["tcp_connect"] = '{"result": "%s", "elapsed_ms": 1.0}' % result
            run, _e, _ = go(world, family="TCP_CONNECT", port="81")
            self.assertEqual((run.status, run.failure_reason), (S.FAILED, reason))

    def test_udp_probe_states_what_udp_can_and_cannot_tell(self):
        world = t.World(); world.outputs["udp_probe"] = '{"result": "open_or_filtered", "sent": 3, "replies": 0, "elapsed_ms": 6000.1}'
        run, _e, world = go(world, family="UDP_PROBE", port="5353")
        self.assertEqual((run.status, run.protocol, run.metrics["result"], run.metrics["sent"]), (S.PASSED, "UDP", "open_or_filtered", 3))
        self.assertEqual(world.calls[-1][2], ["192.168.20.101", "5353", "2", "3", "64"])
        world = t.World(); world.outputs["udp_probe"] = '{"result": "refused", "sent": 1, "replies": 0, "elapsed_ms": 1.0}'
        run, _e, _ = go(world, family="UDP_PROBE", port="5353")
        self.assertEqual((run.status, run.failure_reason), (S.FAILED, "CONNECTION_REFUSED"))

    def test_iperf3_tcp_throughput_and_server_lifecycle(self):
        run, _e, world = go(family="IPERF3", duration="3", bandwidth_kbps="2000", parallel="2")
        self.assertEqual((run.status, run.protocol), (S.PASSED, "TCP"))
        self.assertEqual((run.metrics["bits_per_second"], run.metrics["requested_bits_per_second"]), (1047038.25, 4_000_000))
        server = next(args for pid, tool, args in world.calls if tool == "server:iperf3")
        client = next(args for pid, tool, args in world.calls if tool == "iperf3")
        self.assertEqual(next(node for node, tool, _ in world.calls if tool == "server:iperf3"), "H2")                         # DESTINATION namespace
        self.assertEqual(next(node for node, tool, _ in world.calls if tool == "iperf3"), "H1")                                # SOURCE namespace
        self.assertEqual(server[:6], ["-s", "-1", "-4", "-B", "192.168.20.101", "-p"])                                        # one-off, bound
        self.assertEqual((client[client.index("-t") + 1], client[client.index("-b") + 1], client[client.index("-P") + 1], "-J" in client, "-u" in client),
                         ("3", "2000K", "2", True, False))
        self.assertEqual(run.metrics["server"], {"started": True, "ready": True, "exit_code": 0, "terminated": False, "stopped": True})
        self.assertEqual(world.containers, {})
        self.assertEqual([n.rsplit("-", 1)[1] for n in world.removed].count("server"), 2)       # the lifecycle's own removal + the run cleanup

    def test_iperf3_udp_throughput_loss_and_jitter_over_ipv6(self):
        world = t.World(); world.outputs["iperf3"] = t.iperf_udp(lost=3, packets=300)
        run, _e, world = go(world, family="IPERF3", protocol="UDP", address_family="IPV6", length="1000")
        self.assertEqual((run.status, run.protocol, run.address_family), (S.PASSED, "UDP", "IPV6"))
        self.assertEqual((run.metrics["jitter_ms"], run.metrics["lost_packets"], run.metrics["loss_percent"]), (0.412, 3, 1.0))
        client = next(args for _pid, tool, args in world.calls if tool == "iperf3")
        self.assertEqual(("-u" in client, client[client.index("-l") + 1], "-6" in client, client[1]), (True, "1000", True, "2001:db8:20::2001"))

    def test_failed_server_startup_runs_no_client_and_leaves_no_server(self):
        world = t.World(); world.server_listens = False
        run, _e, world = go(world, family="IPERF3")
        self.assertEqual((run.status, run.failure_reason), (S.FAILED, "SERVER_START_FAILED"))
        self.assertNotIn("iperf3", world.tools())                                    # the client never ran
        self.assertEqual((run.metrics["server"]["ready"], run.metrics["server"]["stopped"], world.containers), (False, True, {}))

    def test_a_port_someone_else_listens_on_is_never_shared_or_killed(self):
        world = t.World(); world.port_busy = True
        run, _e, world = go(world, family="IPERF3")
        self.assertEqual((run.status, run.failure_reason), (S.FAILED, "SERVER_START_FAILED"))
        self.assertNotIn("iperf3", world.tools())                                    # the client never ran against the foreign listener
        self.assertEqual({n[:45] for n in world.removed}, {f"nmas-traffic-{run.run_id.hex}"})   # only THIS run's containers were touched
        self.assertEqual(world.containers, {})

    def test_client_timeout_terminates_this_runs_server_only(self):
        world = t.World(); world.timeouts.add("iperf3"); world.server_exits = False
        run, _e, world = go(world, family="IPERF3")
        self.assertEqual((run.status, run.failure_reason), (S.TIMED_OUT, "TIMEOUT"))
        self.assertEqual((run.metrics["server"]["terminated"], run.metrics["server"]["stopped"]), (True, True))
        self.assertEqual(world.containers, {})                                       # the killed client's container and the server are gone

    def test_client_error_is_a_failure_and_the_server_is_cleaned_up(self):
        world = t.World(); world.outputs["iperf3"] = '{"error": "unable to connect to server: Connection refused"}'; world.server_exits = False
        run, _e, world = go(world, family="IPERF3")
        self.assertEqual((run.status, run.failure_reason), (S.FAILED, "CLIENT_FAILED"))
        self.assertIn("Connection refused", run.metrics["client_error"])
        self.assertEqual((run.metrics["server"]["terminated"], world.containers), (True, {}))

    def test_a_server_that_cannot_be_confirmed_stopped_fails_the_run(self):
        world = t.World()
        world.unremovable.add("-server")
        run, _e, _ = go(world, family="IPERF3")
        self.assertEqual((run.status, run.failure_reason), (S.FAILED, "SERVER_NOT_STOPPED"))
        self.assertEqual(run.metrics.get("bits_per_second"), None)                    # a measurement with a leaked listener is not a pass

    def test_tool_timeout_and_missing_endpoint(self):
        world = t.World(); world.timeouts.add("ping")
        run, _e, _ = go(world)
        self.assertEqual((run.status, run.failure_reason), (S.TIMED_OUT, "TIMEOUT"))
        world = t.World(); world.missing.add("clab-srlceos01-H2")
        run, _e, _ = go(world)
        self.assertEqual((run.status, run.failure_reason, run.destination_address), (S.FAILED, "ENDPOINT_NOT_FOUND", ""))

    def test_an_internal_defect_is_a_recorded_failure_never_a_stuck_run(self):
        world = t.World(); world.run_tool = mock.Mock(side_effect=RuntimeError("boom"))
        run, _e, _ = go(world)
        self.assertEqual((run.status, run.failure_reason), (S.FAILED, "INTERNAL_ERROR"))
        self.assertIsNone(ts.active_run())


class EvidenceTests(TestCase):
    def test_run_records_structured_evidence_and_provenance(self):
        run, _e, _ = go(count="5", size="100")
        self.assertEqual((run.operator, run.requested["count"], run.parameters), ("tester", "5", {"count": 5, "size": 100}))
        name = f"nmas-traffic-{run.run_id.hex}"
        self.assertEqual(run.operation, {
            "tool": "ping", "namespace": "H1", "arguments": ["-4", "-n", "-c", "5", "-s", "100", "-W", "2", "192.168.20.101"],
            "runtime": {"runner": "traffic-runner-1", "image": t.IMAGE,
                        "cleanup": {"containers": [f"{name}-asrc", f"{name}-adst", f"{name}-tool"], "left_behind": [], "verified": True}}})
        self.assertIn("ping statistics", run.raw_output)
        self.assertTrue(run.started_at <= run.finished_at)
        self.assertEqual((run.engine_version, len(run.repository_head) in (0, 40)), (limits.ENGINE_VERSION, True))
        self.assertNotIn("sudo", repr(run.operation))                                # the record is structured, not a shell line
        self.assertNotIn("docker", repr(run.operation))
        events = list(models.AuditEvent.objects.filter(object_type="TrafficRun").values_list("event_type", flat=True))
        self.assertEqual(sorted(events), ["TRAFFIC_RUN_FINISHED", "TRAFFIC_RUN_STARTED"])

    def test_raw_output_is_bounded(self):
        world = t.World(); world.outputs["ping"] = t.PING_OK + "x" * 100_000
        run, _e, _ = go(world)
        self.assertEqual(len(run.raw_output), limits.RAW_OUTPUT_LIMIT)

    def test_finished_run_is_immutable_and_undeletable(self):
        run, _e, _ = go()
        run.metrics = {"bits_per_second": 10**12}
        with self.assertRaises(ValueError):
            run.save()
        with self.assertRaises(ValueError):
            run.delete()
        fresh = models.TrafficRun.objects.get(pk=run.pk)
        self.assertEqual(fresh.metrics["received"], 3)

    def test_identity_is_immutable_even_while_active(self):
        run = models.TrafficRun.objects.create(operator="t", source="H1", destination="H2", address_family="IPV4", family="ICMP", protocol="ICMP")
        run.destination = "H3"
        with self.assertRaises(ValueError):
            run.save()

    def test_related_change_provisioning_and_soak_are_references(self):
        from core.tests.helpers import provisioning as p
        from core.services import provisioning_service as ps
        lab = p.Lab()
        lab.through("sync")
        ps.start_probation(lab.run, actor="approver")
        run, errors, _ = go(change_id=lab.run.change.change_id, prov_id=lab.run.prov_id, soak_id=lab.run.soak_run.soak_id)
        self.assertEqual(errors, [])
        self.assertEqual((run.change_id, run.provisioning_run_id, run.soak_run_id), (lab.run.change_id, lab.run.pk, lab.run.soak_run_id))

    def test_refused_request_is_audited_without_a_run(self):
        go(family="IPERF3", duration="9999")
        self.assertEqual(models.TrafficRun.objects.count(), 0)
        event = models.AuditEvent.objects.get(event_type=models.AuditEventType.TRAFFIC_RUN_REFUSED)
        self.assertEqual(event.metadata["codes"], ["PARAMETER_OUT_OF_BOUNDS"])


class ConcurrencyAndReconciliationTests(TestCase):
    def _active(self, **overrides):
        values = dict(operator="t", source="H1", destination="H2", address_family="IPV4", family="ICMP", protocol="ICMP",
                      status=S.RUNNING, started_at=timezone.now(), deadline_at=timezone.now() + timedelta(seconds=60))
        values.update(overrides)
        return models.TrafficRun.objects.create(**values)

    def test_only_one_test_may_be_active(self):
        self._active()
        run, errors, world = go()
        self.assertIsNone(run)
        self.assertEqual(errors[0]["code"], "TEST_ALREADY_RUNNING")
        self.assertEqual(world.calls, [])
        self.assertEqual(models.TrafficRun.objects.count(), 1)

    def test_the_database_enforces_the_bound(self):
        from django.db import IntegrityError, transaction
        self._active()
        with self.assertRaises(IntegrityError), transaction.atomic():
            self._active(source="H3")

    def test_abandoned_run_is_reconciled_as_interrupted_never_passed(self):
        stale = self._active(deadline_at=timezone.now() - timedelta(seconds=1))
        self.assertEqual([r.pk for r in ts.reconcile()], [stale.pk])
        stale.refresh_from_db()
        self.assertEqual((stale.status, stale.failure_reason, stale.metrics), (S.INTERRUPTED, "PROCESS_LOST", {}))
        self.assertIsNotNone(stale.finished_at)
        self.assertTrue(models.AuditEvent.objects.filter(event_type=models.AuditEventType.TRAFFIC_RUN_RECONCILED).exists())

    def test_a_live_run_is_not_reconciled_and_a_new_request_reconciles_first(self):
        live = self._active()
        self.assertEqual(ts.reconcile(), [])
        models.TrafficRun.objects.filter(pk=live.pk).update(deadline_at=timezone.now() - timedelta(seconds=5))
        run, errors, _ = go()                                                        # the stale row no longer blocks the lab
        self.assertEqual((run.status, errors), (S.PASSED, []))
        live.refresh_from_db()
        self.assertEqual(live.status, S.INTERRUPTED)

    def test_reconcile_command(self):
        from io import StringIO
        from django.core.management import call_command
        self._active(deadline_at=timezone.now() - timedelta(seconds=1))
        out = StringIO()
        call_command("traffic_reconcile", stdout=out)
        self.assertIn("reconciled 1 abandoned run(s)", out.getvalue())
