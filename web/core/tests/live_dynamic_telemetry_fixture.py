"""V2 Phase 8 LIVE harness -- dynamic, management-path-aware telemetry on the disposable Phase 4 fixture.

    lifecycle / path facts -> MonitoringTarget -> exported target file -> collector (path-bound SSH, pinned key, path credential)
    -> InfluxDB -> the provisioned Grafana lifecycle dashboard

NOT part of any automated suite (the module name does not match ``test*.py``; skipped unless ``NMAS_MGMT_LIVE_FIXTURE=1``).
Run it INSIDE the fixture's NMAS namespace after the Phase 4 management-VRF test left ``vrf instance MGMT`` on DUT1:

    labs/mgmt-multihoming-isolated/fixture.sh up && labs/mgmt-multihoming-isolated/tsdb.sh up
    labs/mgmt-multihoming-isolated/run-harness.sh <evidence> LiveManagementFixture.test_1_management_vrf_apply_verify_compensate_reapply
    NMAS_MGMT_LIVE_MODULE=core.tests.live_dynamic_telemetry_fixture NMAS_P8_TSDB_RUNTIME=labs/mgmt-multihoming-isolated/runtime/tsdb \\
        labs/mgmt-multihoming-isolated/run-harness.sh <evidence> LiveDynamicTelemetry

REAL: DUT1 / MSW1 / SW1 cEOS and their links, the selector's failover / failback, the monitoring consumer, the exported
file, the collector and the health engine's ``EosSession`` over ``ssh_transport`` (the socket's bound interface / source /
peer are read back from the live socket), InfluxDB 2.7.11 and Grafana 11.5.2 (both disposable, on the NMAS namespace's
loopback only).  SUBSTITUTED: the NMAS database is the Django test database; the inventory and credential store are the
Phase 4 fixture's.  The host-key negative changes the PIN (the device keeps its real key): exactly the condition of a
re-imaged or impostor device answering on the path.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import time
import unittest
import urllib.parse
import urllib.request
from base64 import b64encode
from pathlib import Path

from django.test import override_settings

from core import models
from core.services.health import live
from core.services.infrastructure import collector, dispatcher, grafana, monitoring
from core.services.management import paths, resolve, selector
from core.tests import live_management_fixture as LMF
from core.tests.helpers import lifecycle as L

TSDB = Path(os.environ["NMAS_P8_TSDB_RUNTIME"]) if os.environ.get("NMAS_P8_TSDB_RUNTIME") else None
INFLUX, GRAFANA, ORG, BUCKET = "http://127.0.0.1:8086", "http://127.0.0.1:3000", "nmas-p8", "network-monitoring"
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _http(url, *, data=None, headers=None, method=None):
    request = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    with OPENER.open(request, timeout=20) as response:
        return response.status, response.read().decode()


def influx_query(flux: str, token: str) -> list[dict]:
    """Flux over the InfluxDB HTTP API -> CSV rows as dicts (annotations dropped)."""
    status, body = _http(f"{INFLUX}/api/v2/query?{urllib.parse.urlencode({'org': ORG})}", data=flux.encode(), method="POST",
                         headers={"Authorization": f"Token {token}", "Content-Type": "application/vnd.flux", "Accept": "application/csv"})
    assert status == 200, status
    rows, header = [], None
    for line in body.splitlines():
        if not line.strip() or line.startswith("#"):
            header = None if not line.strip() else header
            continue
        cells = line.split(",")
        if header is None:
            header = cells
            continue
        rows.append(dict(zip(header, cells)))
    return rows


@unittest.skipUnless(LMF.LIVE, "live fixture harness: set NMAS_MGMT_LIVE_FIXTURE=1 and run inside the fixture's NMAS namespace")
@override_settings(NMAS_MGMT_MIN_PROBE_INTERVAL_SECONDS=0, NMAS_MGMT_FAILBACK_HOLD_DOWN_SECONDS=30)
class LiveDynamicTelemetry(LMF.LiveManagementFixture):
    # the Phase 4 tests stay in their own module; only the Phase 8 proof runs here
    test_1_management_vrf_apply_verify_compensate_reapply = None
    test_2_probes_failover_failback_and_switch_failure = None

    def setUp(self):
        super().setUp()
        self.work = Path(tempfile.mkdtemp(prefix="nmas-p8-"))
        self.addCleanup(shutil.rmtree, self.work, True)
        self.file = self.work / "nmas-dynamic-targets.json"
        self.bindings = []
        self.token = (TSDB / "token").read_text().strip() if TSDB and (TSDB / "token").exists() else ""
        self.push = {"url": INFLUX, "org": ORG, "bucket": BUCKET, "token": self.token} if self.token else None

    def session_factory(self, device):
        """The health engine's EosSession (the collector's default), with the live socket's binding recorded."""
        session = live.EosSession(device)
        sock = session._conn.remote_conn_pre.get_transport().sock  # pylint: disable=protected-access
        import socket

        self.bindings.append({"interface": sock.getsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, 64).rstrip(b"\0").decode(),
                              "source": sock.getsockname()[0], "peer": sock.getpeername()[0]})
        return session

    def cycle(self, record, label, *, export=True, targets=None, dispatch=True):
        if dispatch:
            dispatcher.dispatch("monitoring", limit=500)
        if export:
            monitoring.write_runtime_targets(self.file)
        before = len(self.bindings)
        report = collector.run(targets_path=targets or self.file, push=self.push, session_factory=self.session_factory)
        lifecycle_push = grafana.push(grafana.lifecycle_points(), url=INFLUX, org=ORG, bucket=BUCKET, token=self.token) if self.push else None
        target = models.MonitoringTarget.objects.select_related("management_path").get(device__name="DUT1", device__lifecycle_state="IN_SERVICE")
        row = {"step": label, "at": time.strftime("%H:%M:%S"), "file": str(targets or self.file).replace(str(self.work), "<work>"),
               "target": {"state": target.state, "generation": target.generation, "address": target.address,
                          "management_path": target.management_path.path_id if target.management_path_id else ""},
               "report": report, "bindings": self.bindings[before:], "lifecycle_push": lifecycle_push}
        record["collections"].append(row)
        return row

    def test_dynamic_telemetry_follows_the_management_path(self):
        record = {"collections": [], "evaluations": [], "links": [], "tsdb": bool(self.push)}
        self.addCleanup(lambda: LMF.evidence("dynamic-telemetry.json", record))
        self.assertIn("vrf instance MGMT", LMF.show(LMF.DUT_SVI, "dut", "show running-config section vrf"))
        dut, p, _nmas = self._registry(record)
        record["paths"] = {k: {"id": v.path_id, "type": v.path_type, "endpoint": v.endpoint_address,
                               "nmas_interface": v.nmas_attachment.host_interface} for k, v in p.items()}

        def link(action, name):
            LMF.fixture(action, name)
            record["links"].append({"at": time.strftime("%H:%M:%S"), "action": action, "link": name})

        # 1. initial: OOB (class 1) over NMAS eth1
        result, _endpoint = self._evaluate(dut, record, "initial")
        self.assertEqual(result.active_path, p["oob"].path_id)
        row = self.cycle(record, "oob")
        self.assertEqual(row["report"]["counts"], {"COLLECTED": 1}, row["report"])
        self.assertEqual((row["target"]["management_path"], row["target"]["address"]), (p["oob"].path_id, LMF.DUT_SVI))
        self.assertEqual(row["bindings"], [{"interface": "eth1", "source": "10.254.40.10", "peer": LMF.DUT_SVI}])
        first_generation = row["target"]["generation"]
        stale = self.work / "stale-targets.json"
        shutil.copyfile(self.file, stale)

        # 2. OOB fails -> via SW1 (class 2); the stale file is refused before any connection, the fresh export is collected
        link("fail", "oob")
        result, _endpoint = self._until(dut, record, "oob down", lambda r, e: r.active_path == p["via-sw1"].path_id)
        row = self.cycle(record, "stale file after failover", export=False, targets=stale)
        self.assertEqual([(o["status"], o["code"]) for o in row["report"]["outcomes"]], [("REFUSED", "STALE_TARGET")])
        self.assertEqual(row["bindings"], [])
        row = self.cycle(record, "via-sw1")
        self.assertEqual(row["report"]["counts"], {"COLLECTED": 1}, row["report"])
        self.assertEqual(row["target"]["management_path"], p["via-sw1"].path_id)
        self.assertEqual(row["target"]["generation"], first_generation + 1)
        self.assertEqual(row["bindings"], [{"interface": "eth1", "source": "10.254.40.10", "peer": LMF.DUT_SVI}])

        # 3. SW1 path fails too -> routed VRF (class 3) over NMAS's second attachment eth2
        link("fail", "via-sw1")
        result, _endpoint = self._until(dut, record, "via-sw1 down", lambda r, e: r.active_path == p["vrf"].path_id)
        row = self.cycle(record, "vrf")
        self.assertEqual(row["report"]["counts"], {"COLLECTED": 1}, row["report"])
        self.assertEqual((row["target"]["management_path"], row["target"]["address"]), (p["vrf"].path_id, LMF.DUT_VRF))
        self.assertEqual(row["bindings"], [{"interface": "eth2", "source": "10.254.42.2", "peer": LMF.DUT_VRF}])

        # 4. restore -> hold-down -> failback to OOB
        for name in ("via-sw1", "oob"):
            link("restore", name)
        result, _endpoint = self._until(dut, record, "restored", lambda r, e: r.decision in ("HOLD_DOWN", "FAILBACK"), attempts=15)
        if result.decision == "HOLD_DOWN":
            state = selector.state_for(dut)
            from django.utils import timezone

            time.sleep(max(0.0, (state.failback_not_before - timezone.now()).total_seconds()) + 1)
            result, _endpoint = self._until(dut, record, "after hold-down", lambda r, e: r.decision == "FAILBACK", attempts=5)
        self.assertEqual(result.active_path, p["oob"].path_id)
        row = self.cycle(record, "failback")
        self.assertEqual(row["report"]["counts"], {"COLLECTED": 1}, row["report"])
        self.assertEqual(row["target"]["management_path"], p["oob"].path_id)
        self.assertEqual(row["bindings"], [{"interface": "eth1", "source": "10.254.40.10", "peer": LMF.DUT_SVI}])
        record["generations"] = [c["target"]["generation"] for c in record["collections"]]

        # 5. host key: the pinned key no longer matches what the device presents -> no session, reachable=0 CONNECTION_FAILED
        oob = models.ManagementPath.objects.get(pk=p["oob"].pk)
        real_key = oob.expected_host_key
        models.ManagementPath.objects.filter(pk=oob.pk).update(expected_host_key="SHA256:" + "Z" * 43)
        try:
            row = self.cycle(record, "host key mismatch", export=False)
            self.assertEqual([(o["status"], o["code"]) for o in row["report"]["outcomes"]], [("FAILED", "CONNECTION_FAILED")])
            self.assertEqual(row["bindings"], [])
        finally:
            models.ManagementPath.objects.filter(pk=oob.pk).update(expected_host_key=real_key)
        row = self.cycle(record, "host key restored", export=False)
        self.assertEqual(row["report"]["counts"], {"COLLECTED": 1})

        # 6. revocation: the active path revoked -> the unchanged file is refused without a connection; all revoked -> no target
        self.assertTrue(paths.revoke_path(oob, actor=L.APPROVER, reason="live: collector revocation", acknowledge_active=True).ok)
        row = self.cycle(record, "active path revoked (collector before the consumer)", export=False, dispatch=False)
        self.assertEqual([(o["status"], o["code"]) for o in row["report"]["outcomes"]], [("REFUSED", "MGMT_NO_USABLE_PATH")])
        self.assertEqual(row["bindings"], [])
        for remaining in models.ManagementPath.objects.filter(device=dut, approval_state=models.ManagementApproval.APPROVED):
            self.assertTrue(paths.revoke_path(remaining, actor=L.APPROVER, reason="live: revoke all", acknowledge_active=True).ok)
        self._evaluate(dut, record, "all revoked")
        self.assertEqual(resolve.endpoint("DUT1").source, resolve.BLOCKED)
        dispatcher.dispatch("monitoring", limit=500)
        monitoring.write_runtime_targets(self.file)
        record["export_after_revocation"] = json.loads(self.file.read_text())["targets"]
        self.assertEqual(record["export_after_revocation"], [])
        record["target_after_revocation"] = models.MonitoringTarget.objects.get(device=dut).state

        # 7. the TSDB and the provisioned dashboard actually carry it
        if self.push:
            time.sleep(2)
            record["influx_reachable_by_path"] = influx_query(
                f'from(bucket: "{BUCKET}") |> range(start: -2h) |> filter(fn: (r) => r._measurement == "nmas_dynamic_device" '
                'and r._field == "reachable") |> group(columns: ["management_path", "error"]) |> count()', self.token)
            record["influx_interface_series"] = len(influx_query(
                f'from(bucket: "{BUCKET}") |> range(start: -2h) |> filter(fn: (r) => r._measurement == "nmas_dynamic_interface" '
                'and r._field == "in_octets") |> group(columns: ["interface"]) |> last()', self.token))
            seen = {(r.get("management_path"), r.get("error", "")) for r in record["influx_reachable_by_path"]}
            for label in ("oob", "via-sw1", "vrf"):
                self.assertTrue(any(path == p[label].path_id for path, _error in seen), (label, seen))
            self.assertGreater(record["influx_interface_series"], 0)
            record["grafana"] = self.grafana(p)

    def grafana(self, p) -> dict:
        auth = "Basic " + b64encode(f"p8admin:{(TSDB / 'admin').read_text().strip()}".encode()).decode()
        for _ in range(30):
            try:
                status, body = _http(f"{GRAFANA}/api/dashboards/uid/nmas-device-lifecycle", headers={"Authorization": auth})
                break
            except OSError:
                time.sleep(2)
        dashboard = json.loads(body)
        loaded = grafana.load_lifecycle_dashboard()          # the repository file Grafana provisioned, under its contract
        panel = next(x for x in dashboard["dashboard"]["panels"] if x["title"] == "Dynamic collection by management path")
        query = panel["targets"][0]["query"].replace("${device:regex}", ".*")
        status, answer = _http(f"{GRAFANA}/api/ds/query", method="POST", headers={"Authorization": auth, "Content-Type": "application/json"},
                               data=json.dumps({"from": "now-2h", "to": "now", "queries": [
                                   {"refId": "A", "datasource": {"uid": grafana.DATASOURCE_UID}, "query": query, "intervalMs": 10000,
                                    "maxDataPoints": 500}]}).encode())
        frames = json.loads(answer)["results"]["A"].get("frames", [])
        series = sorted({(f["schema"]["fields"][-1].get("labels") or {}).get("management_path", "") for f in frames})
        self.assertEqual(status, 200)
        self.assertTrue(dashboard["meta"].get("provisioned"))
        self.assertEqual({x["title"] for x in dashboard["dashboard"]["panels"]}, {x["title"] for x in loaded["panels"]})
        self.assertTrue({p["oob"].path_id, p["via-sw1"].path_id, p["vrf"].path_id} <= set(series), series)
        return {"dashboard_status": status, "provisioned": dashboard["meta"].get("provisioned"), "editable": dashboard["dashboard"].get("editable"),
                "panels": sorted(x["title"] for x in dashboard["dashboard"]["panels"]), "panel_query_series_by_path": series,
                "frames": len(frames)}
