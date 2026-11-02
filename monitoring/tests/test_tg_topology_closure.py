"""Lab 7 closure -- the dynamic topology: active-snapshot reconciliation, provisioning hand-off, the read-only Influx
evidence reader, the graph builder and the localhost topology server, each called directly.

Hermetic: ``subprocess.run`` (containerlab inspect / sudo hand-off) is patched and records its argv, the runtime
metadata and ``monitoring.env`` live in a temporary directory, the Influx HTTP session is a fake, and the server
handler writes to an in-memory buffer (no socket is opened).  POSITIVE: the exact reconciled snapshot, provisioning
argv and redacted output, parsed CSV rows, normalized evidence, a validated graph payload and the served JSON.
NEGATIVE: missing / invalid / mismatched metadata, failed inspect, non-running nodes, unprotected or incomplete
runtime env and a failed hand-off are refused; the token never appears in an error; an unsupported demo mode or path
is refused; an incomplete server environment exits before listening.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import requests

from modules import topology
from modules import topology_graph as tg
from modules.nmas import NmasError

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "modules"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import topology_server as server  # noqa: E402  (path set above, as test_topology_layout does)

import test_topology as base  # noqa: E402  sibling fixture module (discover -s monitoring/tests)

TOKEN = "fake-Influx-Token-7"
LAB = "tglab"


def metadata(nodes=None, links=None, name=LAB):
    nodes = nodes if nodes is not None else {"R1": {"kind": "arista_ceos", "image": "ceos:t"}, "H1": {"kind": "linux", "image": "u:t"},
                                             "mgmt_swt": {"kind": "linux", "image": "u:t"}}
    links = links if links is not None else [
        {"endpoints": {"a": {"node": "R1", "interface": "eth1"}, "z": {"node": "H1", "interface": "eth1"}}},
        {"endpoints": {"a": {"node": "mgmt_swt", "interface": "eth3"}, "z": {"node": "R1", "interface": "eth9"}}},
        {"endpoints": {"a": {"node": "host", "interface": "veth0"}, "z": {"node": "H1", "interface": "eth2"}}},
    ]
    return {"name": name, "nodes": nodes, "links": links}


def inspect_rows(names=("R1", "H1", "mgmt_swt"), state="running"):
    rows = [{"name": f"clab-{LAB}-{n}", "state": state, "ipv4_address": f"172.20.0.{i}/24", "ipv6_address": f"3fff::{i}/64"}
            for i, n in enumerate(names, start=2)]
    return json.dumps({LAB: rows})


class Spawn:
    def __init__(self, stdout="", returncode=0, stderr=""):
        self.stdout, self.returncode, self.stderr, self.calls = stdout, returncode, stderr, []

    def __call__(self, argv, **kwargs):
        self.calls.append((list(argv), kwargs))
        return subprocess.CompletedProcess(argv, self.returncode, stdout=self.stdout, stderr=self.stderr)


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.source = Path(self.tmp.name) / "topology-data.json"
        self.config = {"lab_name": LAB, "runtime_metadata": str(self.source)}

    def snapshot(self, data=None, spawn=None, raw=None):
        if raw is not None or data is not None:
            self.source.write_text(raw if raw is not None else json.dumps(data))
        spawn = spawn or Spawn(inspect_rows())
        with mock.patch.object(topology.subprocess, "run", spawn):
            return topology.active_topology_snapshot(self.config), spawn

    def test_active_topology_snapshot_returns_the_reconciled_nodes_and_edges(self):
        found, spawn = self.snapshot(metadata())
        self.assertEqual(spawn.calls[0][0], ["containerlab", "inspect", "--name", LAB, "--format", "json"])
        nodes = {n["id"]: n for n in found["nodes"]}
        self.assertEqual(nodes["R1"], {"id": "R1", "kind": "arista_ceos", "image": "ceos:t", "platform": "ceos", "runtime_state": "running",
                                       "management_ipv4": "172.20.0.2", "management_ipv6": "3fff::2", "monitoring_address": "192.168.200.1",
                                       "monitoring_address_v6": "2001:db8:200::1", "monitoring_interface": "Vlan200", "monitored": True,
                                       "monitoring_implementation": "native cEOS gNMI"})
        self.assertEqual((nodes["H1"]["platform"], nodes["H1"]["monitored"], nodes["H1"]["monitoring_implementation"]), ("linux-endpoint", False, "none"))
        self.assertEqual([(e["id"], e["plane"], [p["monitor_interface"] for p in e["endpoints"]]) for e in found["edges"]],
                         [("H1:eth1--R1:eth1", "data", ["eth1", "Ethernet1"]), ("R1:eth9--mgmt_swt:eth3", "management", ["Ethernet9", "eth3"])])
        self.assertEqual((found["lab_name"], found["excluded_host_links"], len(found["source_sha256"])), (LAB, 1, 64))

    def test_active_topology_snapshot_refuses_missing_invalid_or_mismatched_metadata(self):
        duplicate = metadata(links=[{"endpoints": {"a": {"node": "R1", "interface": "eth1"}, "z": {"node": "H1", "interface": "eth1"}}}] * 2)
        cases = (
            ("missing", None, None, None, "Active Containerlab metadata is missing"),
            ("invalid json", None, "{not json", None, "topology-data.json is invalid"),
            ("wrong lab", metadata(name="other"), None, None, "does not match the configured lab"),
            ("inspect error", metadata(), None, Spawn("", 1, "permission denied"), "Read-only Containerlab inspect failed: permission denied"),
            ("inspect schema", metadata(), None, Spawn("{}"), "unexpected schema"),
            ("node mismatch", metadata(), None, Spawn(inspect_rows(("R1", "H1"))), "inspect nodes differ"),
            ("not running", metadata(), None, Spawn(inspect_rows(state="exited")), "non-running nodes: H1, R1, mgmt_swt"),
            ("bad endpoints", metadata(links=[{"endpoints": {"a": {"node": "R1"}}}]), None, None, "unexpected endpoint schema"),
            ("duplicate edge", duplicate, None, None, "duplicate graph edge identities"),
        )
        for label, data, raw, spawn, message in cases:
            with self.subTest(case=f"refused {label}"):
                if self.source.exists():
                    self.source.unlink()
                with self.assertRaisesRegex(NmasError, message):
                    self.snapshot(data, spawn, raw)


class ProvisionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.runtime = Path(self.tmp.name)
        patcher = mock.patch.object(topology, "RUNTIME", self.runtime)
        patcher.start()
        self.addCleanup(patcher.stop)

    def env(self, text=f"INFLUXDB_ORG=o\nINFLUXDB_BUCKET=b\nINFLUXDB_TOKEN={TOKEN}\n", mode=0o600):
        path = self.runtime / "monitoring.env"
        path.write_text(text)
        path.chmod(mode)

    def provision(self, spawn):
        out = io.StringIO()
        with mock.patch.object(topology.subprocess, "run", spawn), contextlib.redirect_stdout(out):
            return topology.provision_topology({"nodes": [], "edges": []}, {"port": 8099}), out.getvalue()

    def test_provision_topology_hands_the_payload_to_sudo_and_returns_redacted_output(self):
        self.env()
        spawn = Spawn(f"NetworkX topology converged; token {TOKEN}\n")
        result, printed = self.provision(spawn)
        argv, kwargs = spawn.calls[0]
        self.assertEqual(argv[:4], ["sudo", "-n", "python3", "-c"])
        self.assertEqual(argv[4], (topology.MONITORING / "scripts/provision_topology.py").read_text())
        payload = json.loads(kwargs["input"])
        self.assertEqual((payload["influx_org"], payload["influx_bucket"], payload["config"], payload["topology"]), ("o", "b", {"port": 8099}, {"nodes": [], "edges": []}))
        self.assertEqual((result, printed), ("NetworkX topology converged; token [REDACTED]", "NetworkX topology converged; token [REDACTED]\n"))

    def test_provision_topology_refuses_unprotected_incomplete_env_or_failed_handoff(self):
        for label, text, mode, spawn, message in (
            ("unprotected env", f"INFLUXDB_ORG=o\nINFLUXDB_BUCKET=b\nINFLUXDB_TOKEN={TOKEN}\n", 0o644, None, "requires protected"),
            ("incomplete env", "INFLUXDB_ORG=o\n", 0o600, None, "environment is incomplete"),
            ("failed handoff", f"INFLUXDB_ORG=o\nINFLUXDB_BUCKET=b\nINFLUXDB_TOKEN={TOKEN}\n", 0o600, Spawn("", 1, f"denied {TOKEN}"), "provisioning failed: denied \\[REDACTED\\]"),
        ):
            with self.subTest(case=f"refused {label}"):
                self.env(text, mode)
                spawn = spawn or Spawn("ok")
                with self.assertRaisesRegex(NmasError, message) as caught:
                    self.provision(spawn)
                self.assertNotIn(TOKEN, str(caught.exception))
                self.assertEqual(len(spawn.calls), 1 if label == "failed handoff" else 0)
        (self.runtime / "monitoring.env").unlink()
        with self.assertRaisesRegex(NmasError, "requires protected"):
            self.provision(Spawn("ok"))

    def test_ensure_topology_infrastructure_snapshots_provisions_then_verifies(self):
        with mock.patch.object(topology, "load_config", return_value={"lab_name": LAB}), \
                mock.patch.object(topology, "active_topology_snapshot", return_value={"nodes": []}) as snap, \
                mock.patch.object(topology, "provision_topology", return_value="converged") as prov, \
                mock.patch.object(topology, "stage") as stage:
            self.assertEqual(topology.ensure_topology_infrastructure(verbose=True), "converged")
        snap.assert_called_once_with({"lab_name": LAB})
        prov.assert_called_once_with({"nodes": []}, {"lab_name": LAB})
        stage.assert_called_once_with("Dynamic topology verification",
                                      [str(topology.VENV / "bin/python"), str(topology.MONITORING / "tests/verify_topology.py")], True)

    def test_ensure_topology_infrastructure_never_provisions_after_a_failed_snapshot(self):
        with mock.patch.object(topology, "load_config", return_value={"lab_name": LAB}), \
                mock.patch.object(topology, "active_topology_snapshot", side_effect=NmasError("inspect nodes differ")), \
                mock.patch.object(topology, "provision_topology") as prov, mock.patch.object(topology, "stage") as stage, \
                self.assertRaisesRegex(NmasError, "inspect nodes differ"):
            topology.ensure_topology_infrastructure()
        self.assertEqual((prov.call_count, stage.call_count), (0, 0))


CSV = (
    "#datatype,string,long,dateTime:RFC3339,string,string,double\r\n"
    ",result,table,_time,device,_field,_value\r\n"
    ",_result,0,2026-09-07T19:59:50Z,R1,cpu_total_pct,20\r\n"
    ",_result,0,2026-09-07T19:59:55Z,R1,mem_used_bytes,40.5\r\n"
    "\r\n"
    ",result,table,_time,device,_field,_value\r\n"
    ",,,,,,\r\n"
)


class FakeResponse:
    def __init__(self, text="", status=200):
        self.text, self.status = text, status

    def raise_for_status(self):
        if self.status >= 400:
            raise requests.HTTPError(f"{self.status} Unauthorized")


class InfluxEvidenceTests(unittest.TestCase):
    def influx(self, response=None):
        found = tg.InfluxEvidence(org="nmas", bucket="network-monitoring", token=TOKEN, url="http://127.0.0.1:8086/")
        found.session = mock.Mock(post=mock.Mock(return_value=response or FakeResponse(CSV)))
        return found

    def test_influx_evidence_init_builds_an_authorized_session(self):
        found = tg.InfluxEvidence(org="nmas", bucket="b", token=TOKEN, url="http://127.0.0.1:8086/")
        self.assertEqual((found.url, found.org, found.bucket, found.session.headers["Authorization"]), ("http://127.0.0.1:8086", "nmas", "b", f"Token {TOKEN}"))

    def test_influx_evidence_init_never_trusts_proxy_environment(self):
        with mock.patch.dict(os.environ, {"HTTP_PROXY": "http://proxy.invalid:3128"}):
            found = tg.InfluxEvidence(org="nmas", bucket="b", token=TOKEN)
        self.assertEqual((found.session.trust_env, found.url), (False, "http://127.0.0.1:8086"))

    def test_query_returns_clean_rows_from_annotated_csv(self):
        found = self.influx()
        rows = found.query("from(bucket: \"b\")")
        self.assertEqual(rows, [{"result": "_result", "table": "0", "_time": "2026-09-07T19:59:50Z", "device": "R1", "_field": "cpu_total_pct", "_value": "20"},
                                {"result": "_result", "table": "0", "_time": "2026-09-07T19:59:55Z", "device": "R1", "_field": "mem_used_bytes", "_value": "40.5"}])
        _args, kwargs = found.session.post.call_args
        self.assertEqual((found.session.post.call_args[0][0], kwargs["params"], kwargs["data"], kwargs["timeout"]),
                         ("http://127.0.0.1:8086/api/v2/query", {"org": "nmas"}, "from(bucket: \"b\")", 15))

    def test_query_refuses_an_http_error_and_rows_without_header_or_values(self):
        with self.assertRaisesRegex(requests.HTTPError, "401 Unauthorized"):
            self.influx(FakeResponse("", 401)).query("x")
        self.assertEqual(self.influx(FakeResponse(",_result,0,2026-09-07T19:59:50Z,R1\r\n,,,,\r\n")).query("x"), [])

    def test_collect_returns_normalized_evidence_from_six_queries(self):
        found = self.influx()
        stamp = "2026-09-07T19:59:50Z"
        answers = [[{"_time": stamp, "device": "R1", "platform": "ceos", "_field": "cpu_total_pct", "_value": "20"}],
                   [{"_time": stamp, "device": "R1", "interface": "Ethernet1", "_field": "oper_status", "_value": "UP"}],
                   [], [{"_time": stamp, "device": "R1", "severity": "crit"}],
                   [{"_time": stamp, "device": "R1", "event_type": "linkDown", "ifindex": "1"}],
                   [{"device": "R1", "ifindex": "1", "interface": "Ethernet1"}]]
        with mock.patch.object(found, "query", side_effect=answers) as query:
            evidence = found.collect(900)
        self.assertEqual(query.call_count, 6)
        self.assertIn("range(start: -900s)", query.call_args_list[3][0][0])
        self.assertEqual((evidence["devices"]["R1"]["fields"], evidence["devices"]["R1"]["platform"]), ({"cpu_total_pct": 20}, "ceos"))
        self.assertEqual(evidence["interfaces"][("R1", "Ethernet1")]["fields"], {"oper_status": "UP"})
        self.assertEqual([e["event_type"] for e in evidence["link_events"][("R1", "Ethernet1")]], ["linkDown"])

    def test_collect_never_interpolates_an_unquoted_bucket(self):
        found = self.influx()
        found.bucket = 'b") |> drop(columns: ["x'
        with mock.patch.object(found, "query", return_value=[]) as query:
            self.assertEqual(found.collect("60"), tg.empty_evidence())
        self.assertTrue(all(call[0][0].startswith('from(bucket: "b\\") |> drop(columns: [\\"x")') for call in query.call_args_list))


NOW = base.NOW


class GraphPrimitiveTests(unittest.TestCase):
    def test_utc_now_returns_an_aware_utc_time(self):
        now = tg.utc_now()
        self.assertEqual((now.tzinfo, tg.isoformat(datetime(2026, 9, 7, 20, 0, tzinfo=timezone.utc))), (timezone.utc, "2026-09-07T20:00:00Z"))

    def test_isoformat_of_no_time_is_none(self):
        self.assertEqual((tg.isoformat(None), tg.parse_time(None), tg.parse_time("not-a-time")), (None, None, None))

    def test_normalize_evidence_returns_latest_fields_and_sorted_events(self):
        t1, t2 = "2026-09-07T19:59:00Z", "2026-09-07T19:59:30Z"
        found = tg.normalize_evidence(
            [{"_time": t1, "device": "R1", "_field": "cpu_total_pct", "_value": "20"}, {"_time": t2, "device": "R1", "_field": "mem_used_bytes", "_value": "4.5"}],
            [{"_time": t1, "device": "R1", "interface": "Ethernet1", "_field": "oper_status", "_value": "UP"}],
            [{"_time": t2, "device": "R1", "interface": "Ethernet1", "_field": "in_errors", "_value": "3"}],
            [{"_time": t2, "device": "R1", "severity": "crit"}, {"_time": t1, "device": "R1", "severity": "err"}],
            [{"_time": t2, "device": "R1", "event_type": "linkUp", "ifindex": "1"}, {"_time": t1, "device": "R1", "event_type": "linkDown", "ifindex": "1"}],
            [{"device": "R1", "ifindex": "1", "interface": "Ethernet1"}],
        )
        self.assertEqual((found["devices"]["R1"]["fields"], tg.isoformat(found["devices"]["R1"]["last_update"])),
                         ({"cpu_total_pct": 20, "mem_used_bytes": 4.5}, t2))
        iface = found["interfaces"][("R1", "Ethernet1")]
        self.assertEqual((iface["fields"], tg.isoformat(iface["state_last_update"]), tg.isoformat(iface["counter_last_update"])),
                         ({"oper_status": "UP", "in_errors": 3}, t1, t2))
        self.assertEqual([e["severity"] for e in found["syslog"]["R1"]], ["err", "crit"])
        self.assertEqual([e["event_type"] for e in found["link_events"][("R1", "Ethernet1")]], ["linkDown", "linkUp"])

    def test_normalize_evidence_drops_rows_without_device_time_or_mapping(self):
        found = tg.normalize_evidence(
            [{"_time": "bad", "device": "R1"}, {"_time": "2026-09-07T19:59:00Z"}],
            [{"_time": "2026-09-07T19:59:00Z", "device": "R1"}],
            [], [{"device": "R1"}],
            [{"_time": "2026-09-07T19:59:00Z", "device": "R1", "event_type": "linkDown", "ifindex": "9"},
             {"_time": "2026-09-07T19:59:00Z", "device": "R1", "event_type": "coldStart", "ifindex": "1"}],
            [{"device": "R1", "ifindex": "1", "interface": ""}],
        )
        self.assertEqual((found["devices"], found["interfaces"], found["syslog"], found["link_events"]), ({}, {}, {}, {}))
        self.assertEqual(len(found["traps"]["R1"]), 2)

    def test_classify_edge_without_fresh_evidence_or_after_link_down_is_never_up(self):
        stale = [{"node": "R1", "evidence_fresh": False}, {"node": "R3", "evidence_fresh": False}]
        self.assertEqual(tg.classify_edge(stale, [], {"R1", "R3"}), ("UNKNOWN", "No fresh monitored endpoint evidence is available", "none"))
        fresh = [{"node": "R1", "evidence_fresh": True, "last_update": "2026-09-07T19:59:00Z", "oper_status": "UP", "admin_status": "UP"}]
        event = {"timestamp": datetime(2026, 9, 7, 19, 59, 30, tzinfo=timezone.utc), "event_type": "linkDown"}
        self.assertEqual(tg.classify_edge(fresh, [event], {"R1"}), ("DOWN", "A linkDown notification is newer than interface telemetry", "snmp_trap"))
        self.assertEqual(tg.classify_edge([{**fresh[0], "admin_status": "DOWN"}], [], {"R1"})[0], "DEGRADED")


class FakeInflux:
    token = TOKEN

    def __init__(self, evidence=None, error=None):
        self.evidence, self.error, self.windows = evidence, error, []

    def collect(self, window):
        self.windows.append(window)
        if self.error is not None:
            raise self.error
        return self.evidence


class BuilderTests(unittest.TestCase):
    def build(self, influx, builder_class=tg.TopologyBuilder):
        with mock.patch.object(tg, "utc_now", return_value=NOW):
            return builder_class(base.SNAPSHOT, {**base.CONFIG, "grafana_url": "http://g"}, influx).build()

    def test_build_returns_a_validated_payload_with_backend_ok(self):
        influx = FakeInflux(base.evidence())
        payload = self.build(influx)
        nodes = {n["id"]: n["health"] for n in payload["graph"]["nodes"]}
        self.assertEqual((payload["backend"]["status"], payload["grafana_url"], influx.windows, nodes),
                         ("OK", "http://g", [900], {"R1": "HEALTHY", "R3": "STALE", "H1": "UNKNOWN"}))

    def test_build_with_an_unreachable_backend_is_unknown_and_never_leaks_the_token(self):
        payload = self.build(FakeInflux(error=requests.ConnectionError(f"refused for Token {TOKEN}")))
        self.assertEqual(payload["backend"], {"status": "ERROR", "source": "InfluxDB existing network-monitoring bucket", "error": "refused for Token [REDACTED]"})
        self.assertEqual({n["health"] for n in payload["graph"]["nodes"]}, {"UNKNOWN"})
        self.assertNotIn(TOKEN, json.dumps(payload))


class FakeBuilder:
    def __init__(self, payload=None):
        self.calls, self.payload = [], payload

    def build(self, demo=None):
        self.calls.append(demo)
        return self.payload or {"demo": demo, "n": len(self.calls)}


class SnapshotCacheTests(unittest.TestCase):
    def test_snapshot_cache_get_returns_the_cached_value_per_mode(self):
        builder = FakeBuilder()
        cache = server.SnapshotCache(builder, max_age=60)
        first = cache.get()
        self.assertIs(cache.get(), first)
        self.assertEqual((cache.get(server.DEMO_MODE), builder.calls, cache.max_age), ({"demo": server.DEMO_MODE, "n": 2}, [None, server.DEMO_MODE], 60))

    def test_snapshot_cache_get_never_reuses_an_expired_value(self):
        builder = FakeBuilder()
        cache = server.SnapshotCache(builder, max_age=0)
        self.assertEqual((cache.get(), cache.get(), builder.calls), ({"demo": None, "n": 1}, {"demo": None, "n": 2}, [None, None]))
        self.assertEqual(sorted(cache.values), ["real"])


def handler(path, cache):
    found = server.Handler.__new__(server.Handler)
    found.path, found.server, found.wfile = path, SimpleNamespace(cache=cache), io.BytesIO()
    found.request_version, found.requestline, found.command, found.client_address = "HTTP/1.1", f"GET {path} HTTP/1.1", "GET", ("127.0.0.1", 1)
    found.do_GET()
    head, _, body = found.wfile.getvalue().partition(b"\r\n\r\n")
    return int(head.split(b" ")[1]), head.decode(), body


GOOD = {"backend": {"status": "OK"}, "generated_at": "2026-09-07T20:00:00Z", "graph": {"nodes": [{"id": "R1"}], "edges": []}}


class HandlerTests(unittest.TestCase):
    def test_do_get_serves_the_page_topology_and_health(self):
        cache = server.SnapshotCache(FakeBuilder(GOOD), max_age=60)
        status, head, body = handler("/", cache)
        self.assertEqual((status, body), (200, server.INDEX_HTML.encode()))
        self.assertIn("X-Frame-Options: DENY", head)
        status, head, body = handler("/api/topology?demo=" + server.DEMO_MODE, cache)
        self.assertEqual((status, json.loads(body)), (200, GOOD))
        status, _head, body = handler("/healthz", cache)
        self.assertEqual((status, json.loads(body)), (200, {"status": "ok", "backend": "OK", "generated_at": "2026-09-07T20:00:00Z", "nodes": 1, "edges": 0}))

    def test_do_get_refuses_unsupported_demo_unknown_path_and_degraded_backend(self):
        builder = FakeBuilder({**GOOD, "backend": {"status": "ERROR"}})
        cache = server.SnapshotCache(builder, max_age=60)
        for path, status, document in (("/api/topology?demo=wipe", 400, {"error": "unsupported demo mode"}), ("/admin", 404, {"error": "not found"}),
                                       ("/healthz", 503, {"status": "degraded", "backend": "ERROR", "generated_at": "2026-09-07T20:00:00Z", "nodes": 1, "edges": 0})):
            with self.subTest(case=f"refused {path}"):
                found, _head, body = handler(path, cache)
                self.assertEqual((found, json.loads(body)), (status, document))
        self.assertEqual(builder.calls, [None])

    def test_log_message_returns_none_and_writes_nothing(self):
        found = server.Handler.__new__(server.Handler)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertIsNone(found.log_message("%s", "GET / 200"))
        self.assertEqual(err.getvalue(), "")


class ServerMainTests(unittest.TestCase):
    def test_main_builds_the_first_snapshot_then_serves_on_the_configured_address(self):
        with tempfile.TemporaryDirectory() as tmp:
            etc = Path(tmp)
            (etc / "config.json").write_text(json.dumps({**base.CONFIG, "bind_address": "127.0.0.1", "port": 8099, "backend_cache_seconds": 15}))
            (etc / "topology.json").write_text(json.dumps(base.SNAPSHOT))
            served = []

            class FakeServer:
                def __init__(self, address, handler_class):
                    self.address, self.handler_class = address, handler_class

                def serve_forever(self):
                    served.append((self.address, self.handler_class, self.cache.max_age, sorted(self.cache.values)))

            env = {"INFLUXDB_ORG": "o", "INFLUXDB_BUCKET": "b", "INFLUXDB_TOKEN": TOKEN}
            with mock.patch.object(server, "ETC", etc), mock.patch.dict(os.environ, env), \
                    mock.patch.object(server, "ThreadingHTTPServer", FakeServer), \
                    mock.patch.object(server, "InfluxEvidence", return_value=FakeInflux(error=OSError("no influx"))) as influx:
                server.main()
        influx.assert_called_once_with(org="o", bucket="b", token=TOKEN)
        self.assertEqual(served, [(("127.0.0.1", 8099), server.Handler, 15, ["real"])])

    def test_main_without_the_influx_environment_exits_before_listening(self):
        with tempfile.TemporaryDirectory() as tmp:
            etc = Path(tmp)
            (etc / "config.json").write_text("{}")
            (etc / "topology.json").write_text("{}")
            with mock.patch.object(server, "ETC", etc), mock.patch.dict(os.environ, {"INFLUXDB_TOKEN": ""}), \
                    mock.patch.object(server, "ThreadingHTTPServer") as listener, self.assertRaisesRegex(SystemExit, "environment is incomplete"):
                server.main()
        listener.assert_not_called()


if __name__ == "__main__":
    unittest.main()
