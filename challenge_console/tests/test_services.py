"""NMAS / telemetry: component state from real checks, web-down handling, freshness classes and recovery."""

from __future__ import annotations

import json
from datetime import timedelta

from challenge_console import models as m
from challenge_console.adapters import services, telemetry
from challenge_console.adapters.http import HttpResult
from challenge_console.adapters.process import CommandResult
from challenge_console.collectors import ServiceTelemetryCollector

from .helpers import ConsoleTestCase, FakeGetter, FakeRunner, ok_json

UNITS = ("nmas-web.service", "nmas-traffic-runner.socket", "nmas-probation-soak-tick.timer", "nmas-topology.service",
         "nmas-gnmi-collector.service", "nmas-syslog-ingest.service", "snmptrapd.service")


def systemd(active="active", sub="running", load="loaded"):
    return CommandResult(0, stdout=f"LoadState={load}\nActiveState={active}\nSubState={sub}\n")


def topology(now, ages: dict, *, backend="OK", thresholds=True):
    nodes = [{"id": name, "monitored": True, "health": "HEALTHY", "cpu_percent": 40, "memory_percent": 31.5,
              "last_telemetry_timestamp": None if age is None else m.iso(now - timedelta(seconds=age))} for name, age in ages.items()]
    nodes.append({"id": "H1", "monitored": False, "last_telemetry_timestamp": None})
    document = {"generated_at": m.iso(now), "backend": {"status": backend}, "graph": {"nodes": nodes}}
    if thresholds:
        document["health_thresholds_seconds"] = {"healthy_max": 60, "stale_max": 120}
    return document


class ServiceTestCase(ConsoleTestCase):
    def setUp(self):
        super().setUp()
        self.now = m.utcnow()
        self.runner = FakeRunner()
        for unit in UNITS:
            self.runner.outputs[("systemctl", "show", unit)] = systemd()
        self.runner.outputs[("systemctl", "show", "nmas-probation-soak-tick.service")] = CommandResult(
            0, stdout="Result=success\nExecMainStatus=0\nExecMainExitTimestamp=Tue 2026-10-06 05:08:05 MDT\n")
        self.runner.outputs[("docker", "inspect", "-f")] = CommandResult(0, stdout="running|healthy\n")
        socket_path = self.tmp / "runner.sock"
        import socket
        server = socket.socket(socket.AF_UNIX)
        server.bind(str(socket_path))
        self.addCleanup(server.close)
        self.config = self.config.with_overrides(traffic_runner_socket=socket_path)
        self.getter = FakeGetter({
            self.config.nmas_web_health_url: HttpResult(200, body=b"ok", elapsed_ms=2.0),
            "http://netbox.test/api/status/": ok_json({"netbox-version": "4"}),
            "http://netbox.test/login/": HttpResult(200, body=b"<html>", elapsed_ms=2.0),
            self.config.influxdb_health_url: ok_json({"status": "pass"}),
            self.config.grafana_health_url: ok_json({"database": "ok"}),
            self.config.privacyidea_url: HttpResult(200, body=b"<html>", elapsed_ms=2.0),
            self.config.topology_health_url: ok_json({"status": "ok"}),
            self.config.topology_api_url: lambda url, headers: ok_json(topology(m.utcnow(), {"R1": 10, "R3": 10, "R5": 10})),
        })

    def observe(self, **kwargs):
        return {o.component: o for o in services.observe_all(self.config, runner=self.runner, getter=self.getter, **kwargs)}

    def collector(self):
        collector = ServiceTelemetryCollector(self.config, self.store, self.bus, runner=self.runner, getter=self.getter,
                                              netbox_target=lambda: ("http://netbox.test", {"Authorization": "Token t0ken-value"}))
        collector.setup()
        return collector


class ComponentTests(ServiceTestCase):
    def test_every_component_is_observed_and_up(self):
        found = self.observe()
        self.assertEqual(set(found), {"nmas-web", "netbox", "influxdb", "grafana", "freeradius", "privacyidea", "traffic-runner", "soak-timer",
                                      "topology", "gnmi-collector", "syslog-ingest", "snmptrapd"})
        self.assertEqual({o.state for o in found.values()}, {m.UP})
        self.assertTrue(all(o.ts.tzinfo for o in found.values()))
        self.assertEqual([c.name for c in found["nmas-web"].checks], ["systemd", "http"])            # not systemd alone
        self.assertEqual(found["nmas-web"].latency_ms, 2.0)

    def test_nmas_web_down_is_reported_and_nothing_else_is_affected(self):
        del self.getter.routes[self.config.nmas_web_health_url]                                     # connection refused
        self.runner.outputs[("systemctl", "show", "nmas-web.service")] = systemd("inactive", "dead")
        found = self.observe()
        self.assertEqual(found["nmas-web"].state, m.DOWN)
        self.assertIn("CONNECTION_REFUSED", found["nmas-web"].detail)
        self.assertEqual({o.state for name, o in found.items() if name != "nmas-web"}, {m.UP})

    def test_systemd_active_is_not_enough_when_the_health_endpoint_fails(self):
        self.getter.routes[self.config.nmas_web_health_url] = HttpResult(None, error="TIMEOUT")
        self.assertEqual(self.observe()["nmas-web"].state, m.DOWN)                                   # unit active, application not answering
        self.getter.routes[self.config.influxdb_health_url] = ok_json({"status": "fail"})
        self.assertEqual(self.observe()["influxdb"].state, m.DOWN)
        self.getter.routes[self.config.grafana_health_url] = HttpResult(503, elapsed_ms=1.0)
        self.assertEqual(self.observe()["grafana"].state, m.DOWN)

    def test_degraded_and_unknown_are_distinguished_from_down(self):
        self.runner.outputs[("systemctl", "show", "nmas-web.service")] = systemd("failed", "failed")
        self.assertEqual(self.observe()["nmas-web"].state, m.DEGRADED)                               # answering, but the unit is not active
        self.runner.outputs[("docker", "inspect", "-f")] = CommandResult(None, error="RUNTIME_UNAVAILABLE")
        self.assertEqual(self.observe()["freeradius"].state, m.UNKNOWN)                              # cannot tell: never guessed UP or DOWN
        self.runner.outputs[("docker", "inspect", "-f")] = CommandResult(0, stdout="running|unhealthy\n")
        self.assertEqual(self.observe()["freeradius"].state, m.DOWN)
        self.runner.outputs[("systemctl", "show", "nmas-probation-soak-tick.service")] = CommandResult(
            0, stdout="Result=exit-code\nExecMainStatus=1\nExecMainExitTimestamp=x\n")
        self.assertEqual(self.observe()["soak-timer"].state, m.DEGRADED)                             # timer live, last tick failed
        self.runner.outputs[("systemctl", "show", "nmas-probation-soak-tick.timer")] = systemd("inactive", "dead")
        self.assertEqual(self.observe()["soak-timer"].state, m.DOWN)

    def test_netbox_token_is_sent_only_as_a_header_and_never_reported(self):
        headers = {"Authorization": "Token t0ken-value"}
        found = self.observe(netbox_url="http://netbox.test", netbox_headers=headers)
        self.assertEqual(found["netbox"].state, m.UP)
        self.assertIn(("http://netbox.test/api/status/", headers), self.getter.requests)
        self.assertNotIn("t0ken-value", json.dumps([o.to_dict() for o in found.values()]))
        self.assertTrue(all(h == {} for url, h in self.getter.requests if "netbox.test" not in url))  # the token goes nowhere else


class CollectorTests(ServiceTestCase):
    def test_console_keeps_working_with_nmas_web_down(self):
        del self.getter.routes[self.config.nmas_web_health_url]
        collector = self.collector()
        collector.collect()
        states = {entry["observation"].component: entry["observation"].state for entry in self.store.services()}
        self.assertEqual(states["nmas-web"], m.DOWN)
        self.assertEqual(self.store.telemetry()["available"], True)                                  # telemetry is independent of the website
        web = [e for e in self.kinds("service.sample") if e.target == "nmas-web"][0]
        self.assertEqual((web.outcome, web.data["state"]), (m.FAIL, m.DOWN))
        self.assertNotIn("t0ken-value", json.dumps([e.to_record() for e in self.events]))

    def test_down_then_up_is_a_transition_with_last_seen_up(self):
        collector = self.collector()
        collector.collect()
        url = self.config.nmas_web_health_url
        good = self.getter.routes.pop(url)
        collector.collect()
        self.getter.routes[url] = good
        collector.collect()
        transitions = [(e.data["from"], e.data["to"]) for e in self.kinds("service.transition") if e.target == "nmas-web"]
        self.assertEqual(transitions, [(m.UP, m.DOWN), (m.DOWN, m.UP)])
        entry = next(e for e in self.store.services() if e["observation"].component == "nmas-web")
        self.assertEqual(entry["last_up"], entry["observation"].ts)
        self.assertEqual(len([e for e in self.kinds("service.sample") if e.target == "nmas-web"]), 3)  # every observation logged

    def freshness(self):
        return {row.device: row for row in self.store.telemetry()["rows"]}

    def test_fresh_stale_expired_missing_and_recovery(self):
        ages = {"R1": 10, "R3": 90, "R5": 500}
        self.getter.routes[self.config.topology_api_url] = lambda url, headers: ok_json(topology(m.utcnow(), ages))
        collector = self.collector()
        collector.collect()
        rows = self.freshness()
        self.assertEqual((rows["R1"].freshness, rows["R3"].freshness, rows["R5"].freshness), ("FRESH", "STALE", "EXPIRED"))
        self.assertEqual((rows["R1"].managed, rows["R5"].managed), (True, False))                    # R5 is monitored but unmanaged
        self.assertAlmostEqual(rows["R3"].age_seconds, 90, delta=2)
        self.assertNotIn("H1", rows)                                                                # an unmonitored endpoint is not a telemetry row
        ages["R3"] = None
        collector.collect()
        self.assertEqual(self.freshness()["R3"].freshness, "UNKNOWN")                                # missing: no timestamp, no invented age
        self.assertIsNone(self.freshness()["R3"].age_seconds)
        ages["R3"] = 5
        collector.collect()
        self.assertEqual(self.freshness()["R3"].freshness, "FRESH")
        self.assertEqual([(e.target, e.data["from"], e.data["to"]) for e in self.kinds("telemetry.transition")],
                         [("R3", "STALE", "UNKNOWN"), ("R3", "UNKNOWN", "FRESH")])
        sample = self.kinds("telemetry.sample")[0]
        self.assertEqual(sample.outcome, m.FAIL)                                                     # a managed device was not FRESH
        self.assertEqual(sample.data["devices"]["R3"]["freshness"], "STALE")

    def test_a_managed_device_absent_from_the_payload_is_unknown(self):
        self.getter.routes[self.config.topology_api_url] = lambda url, headers: ok_json(topology(m.utcnow(), {"R1": 5}))
        collector = self.collector()
        collector.collect()
        self.assertEqual(self.freshness()["R3"].freshness, "UNKNOWN")

    def test_telemetry_source_failure_is_logged_every_cycle_then_recovers(self):
        good = self.getter.routes[self.config.topology_api_url]
        collector = self.collector()
        collector.collect()
        self.getter.routes[self.config.topology_api_url] = HttpResult(None, error="TIMEOUT")
        collector.collect()
        collector.collect()
        telemetry_state = self.store.telemetry()
        self.assertEqual((telemetry_state["available"], telemetry_state["reason"]), (False, "TIMEOUT"))
        self.assertIsNotNone(telemetry_state["last_ok"])
        self.assertEqual([e.data["code"] for e in self.kinds("telemetry.error")], ["TIMEOUT", "TIMEOUT"])
        self.assertEqual(len(self.store.services()), 12)                                             # components still observed
        self.getter.routes[self.config.topology_api_url] = good
        collector.collect()
        self.assertTrue(self.store.telemetry()["available"])
        self.assertEqual(len(self.kinds("telemetry.recovered")), 1)

    def test_freshness_boundaries_are_the_project_ones(self):
        thresholds = telemetry.load_thresholds(self.config.topology_policy_path)
        self.assertEqual(thresholds, {"healthy": 60.0, "stale": 120.0})
        cases = {0: "FRESH", 60: "FRESH", 60.1: "STALE", 120: "STALE", 120.1: "EXPIRED", -5: "FRESH", None: "UNKNOWN"}
        self.assertEqual({age: telemetry.classify_age(age, thresholds) for age in cases}, cases)
        self.assertEqual(telemetry.load_thresholds(self.config.topology_policy_path, {"healthy_max": 30, "stale_max": 45}),
                         {"healthy": 30.0, "stale": 45.0})                                           # the running service's values win

    def test_thresholds_match_the_tracked_project_policy_file(self):
        from challenge_console.config import ConsoleConfig
        import yaml
        real = ConsoleConfig()
        policy = yaml.safe_load(real.topology_policy_path.read_text())
        self.assertEqual(telemetry.load_thresholds(real.topology_policy_path),
                         {"healthy": float(policy["healthy_seconds"]), "stale": float(policy["stale_seconds"])})
