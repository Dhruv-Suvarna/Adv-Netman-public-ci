"""Test-governance closure for the Phase 9 option-82 live runner (``labs/phase9-option82-isolated/run_live.py``) and the provisioned
lifecycle dashboard (``monitoring/grafana/provisioning/dashboards/json/device-lifecycle.json``).

The runner's helpers are called directly with ``run`` (the only process boundary) replaced by a scripted fake -- no container,
no network -- except ``run`` itself, which executes the local Python interpreter.  ``main`` is driven end to end against the
same fake with its evidence file and runtime directory in a temporary directory: it proves the evidence plumbing, NOT the
live result (that is ``docs/evidence/v2-phase7-9/phase9/option82-ceos-live.json``)."""

from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest import mock

from django.test import SimpleTestCase

from core.services.infrastructure import grafana
from core.services.test_governance.cases import NEGATIVE, POSITIVE, case
from core.services.test_governance.constants import REPO_ROOT

RUNNER = REPO_ROOT / "labs/phase9-option82-isolated/run_live.py"
DASHBOARD = "monitoring/grafana/provisioning/dashboards/json/device-lifecycle.json"
_spec = importlib.util.spec_from_file_location("nmas_p9_run_live", RUNNER)
M = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(M)          # importing runs nothing: the live run is main()

RELAY_CONFIG = ("hostname P9RELAY\n!\ninterface Ethernet1\n   no switchport\n   ip address 10.254.90.1/24\n"
                "   ip helper-address 10.254.91.2\n!\nend\n")
PCAP = ("12:00:00 IP 10.254.90.1.67 > 10.254.91.2.67: BOOTP/DHCP, Request\n"
        "      Agent-Information Option 82, length 20\n        Circuit-ID SubOption 1, length 9: Ethernet1\n"
        "      Unrelated line\n")


def scripted(rc=0):
    """A fake ``run``: the answers the fixture's containers would give, with every call recorded."""
    calls = []

    def fake(*argv, timeout=60):
        calls.append((argv, timeout))
        joined = " ".join(argv)
        if "show running-config" in joined:
            return rc, RELAY_CONFIG
        if "show version" in joined:
            return rc, "Arista cEOSLab\nSoftware image version: 4.36.2F\n"
        if "udhcpc" in joined:
            return rc, "udhcpc: started\nudhcpc: lease of 10.254.90.10 obtained\nnoise\n"
        if "tcpdump" in argv and "-r" in argv:
            return rc, PCAP
        return rc, ""
    fake.calls = calls
    return fake


class RunnerProcessClosureTests(SimpleTestCase):
    def test_run_returns_exit_status_and_combined_output(self):
        rc, out = M.run(sys.executable, "-c", "import sys; print('out'); print('err', file=sys.stderr)")
        self.assertEqual(rc, 0)
        self.assertIn("out", out)
        self.assertIn("err", out)

    def test_run_failed_command_returns_nonzero_status(self):
        self.assertEqual(M.run(sys.executable, "-c", "import sys; sys.exit(3)")[0], 3)
        with self.assertRaises(subprocess.TimeoutExpired):
            M.run(sys.executable, "-c", "import time; time.sleep(5)", timeout=0.2)

    def test_cli_returns_relay_output(self):
        fake = scripted()
        with mock.patch.object(M, "run", fake):
            self.assertEqual(M.cli("show running-config"), RELAY_CONFIG)
        self.assertEqual(fake.calls[0][0], ("docker", "exec", M.RELAY, "Cli", "-p", "15", "-c", "show running-config"))

    def test_cli_failed_command_yields_error_text(self):
        with mock.patch.object(M, "run", return_value=(1, "% Invalid input")):
            self.assertEqual(M.cli("show nothing"), "% Invalid input")

    def test_apply_returns_rc_output_and_lines(self):
        fake = scripted()
        lines = ["interface Ethernet1", "   ip dhcp relay information option circuit-id Ethernet1"]
        with mock.patch.object(M, "run", fake):
            result = M.apply(lines)
        self.assertEqual((result["rc"], result["lines"]), (0, lines))
        self.assertIn("--abort-on-error", fake.calls[0][0])
        self.assertEqual(fake.calls[0][0][-1], M.o82.change_payload(lines))

    def test_apply_failed_change_reports_nonzero_rc(self):
        with mock.patch.object(M, "run", return_value=(1, "x" * 1000 + "% Error")):
            result = M.apply(["bogus"])
        self.assertEqual(result["rc"], 1)
        self.assertEqual(len(result["output"]), 400)
        self.assertTrue(result["output"].endswith("% Error"))


class RunnerCaptureClosureTests(SimpleTestCase):
    def test_capture_start_removes_old_file_and_starts_tcpdump(self):
        fake = scripted()
        with mock.patch.object(M, "run", fake), mock.patch.object(M, "time") as clock:
            self.assertIsNone(M.capture_start("before"))
        argvs = [call[0] for call in fake.calls]
        self.assertEqual(argvs[0], ("docker", "exec", M.SVC, "rm", "-f", "/srv/dhcp/before.pcap"))
        self.assertEqual(argvs[1][:4], ("docker", "exec", "-d", M.SVC))
        self.assertIn("/srv/dhcp/before.pcap", argvs[1])
        clock.sleep.assert_called_once()

    def test_capture_start_failed_docker_does_not_raise(self):
        with mock.patch.object(M, "run", return_value=(125, "Error: No such container")), mock.patch.object(M, "time"):
            self.assertIsNone(M.capture_start("before"))

    def test_capture_stop_returns_the_decoded_capture(self):
        fake = scripted()
        with mock.patch.object(M, "run", fake), mock.patch.object(M, "time"):
            self.assertEqual(M.capture_stop("before"), PCAP)
        self.assertEqual(fake.calls[0][0], ("docker", "exec", M.SVC, "pkill", "-x", "tcpdump"))

    def test_capture_stop_missing_capture_file_yields_error_output(self):
        with mock.patch.object(M, "run", return_value=(1, "tcpdump: before.pcap: No such file")), mock.patch.object(M, "time"):
            self.assertIn("No such file", M.capture_stop("before"))

    def test_client_lease_obtained_keeps_udhcpc_lines(self):
        fake = scripted()
        with mock.patch.object(M, "run", fake):
            result = M.client("-x", "0x52:01")
        self.assertTrue(result["lease_obtained"])
        self.assertEqual(result["output"], ["udhcpc: started", "udhcpc: lease of 10.254.90.10 obtained"])
        self.assertEqual(fake.calls[1][0][-2:], ("-x", "0x52:01"))
        self.assertEqual(fake.calls[1][1], 40)

    def test_client_without_lease_reports_failure(self):
        with mock.patch.object(M, "run", scripted(rc=1)):
            result = M.client()
        self.assertEqual((result["rc"], result["lease_obtained"]), (1, False))

    def test_summarize_keeps_the_dhcp_relay_lines(self):
        kept = M.summarize(PCAP)
        self.assertEqual(kept[1], "Agent-Information Option 82, length 20")
        self.assertNotIn("Unrelated line", kept)
        self.assertEqual(len(M.summarize("Circuit-ID x\n" * 100)), 40)

    def test_summarize_empty_capture_yields_no_lines(self):
        self.assertEqual(M.summarize(""), [])
        self.assertEqual(M.summarize("no relay information here\n"), [])


class RunnerMainClosureTests(SimpleTestCase):
    def test_main_writes_the_evidence_file(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        (tmp / "runtime" / "dhcp").mkdir(parents=True)
        out = tmp / "evidence.json"
        fake = scripted()
        with mock.patch.object(M, "run", fake), mock.patch.object(M, "time"), mock.patch.object(M, "OUT", out), \
                mock.patch.object(M, "RUNTIME", tmp / "runtime"), mock.patch("builtins.print"):
            M.main()
        evidence = json.loads(out.read_text())
        self.assertEqual(evidence["schema"], "nmas.v2.phase9.option82.live/1")
        for key in ("pre", "rendered", "isc", "negative_before_apply", "apply", "post", "positive", "compensation", "restored",
                    "negative_after_compensation", "finished_at"):
            self.assertIn(key, evidence)
        self.assertTrue((tmp / "runtime" / "dhcp" / "dhcpd.conf").exists())
        self.assertTrue(all(argv[0] == "docker" and argv[2] in (M.RELAY, M.SVC, M.CLIENT, "-d") for argv, _ in fake.calls))


class LifecycleDashboardClosureTests(SimpleTestCase):
    @case(f"CFG:{DASHBOARD}:LOAD:{POSITIVE}", target=DASHBOARD, polarity=POSITIVE, condition="the provisioned lifecycle dashboard",
          expected="grafana.load_lifecycle_dashboard accepts it: stable uid / title, not editable, the six panels, the device "
                   "variable, every query on the provisioned datasource reading an NMAS lifecycle measurement")
    def test_lifecycle_dashboard_loads_with_its_contract(self):
        value = grafana.load_lifecycle_dashboard(REPO_ROOT / DASHBOARD)
        self.assertEqual(value["uid"], "nmas-device-lifecycle")
        self.assertEqual({p["title"] for p in value["panels"]}, grafana.LIFECYCLE_CONTRACT["panels"])

    @case(f"CFG:{DASHBOARD}:MALFORMED:{NEGATIVE}", target=DASHBOARD, polarity=NEGATIVE,
          condition="a malformed / incomplete copy of the provisioned dashboard",
          expected="grafana.load_lifecycle_dashboard refuses it with a fixed code")
    def test_lifecycle_dashboard_malformed_copy_is_refused(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        good = json.loads((REPO_ROOT / DASHBOARD).read_text())
        broken = {
            "DASHBOARD_UNREADABLE": "{not json",
            "DASHBOARD_IDENTITY": json.dumps({**good, "uid": "other"}),
            "DASHBOARD_EDITABLE": json.dumps({**good, "editable": True}),
            "DASHBOARD_PANELS": json.dumps({**good, "panels": good["panels"][:-1]}),
            "DASHBOARD_VARIABLES": json.dumps({**good, "templating": {"list": []}}),
            "DASHBOARD_QUERY": json.dumps({**good, "panels": [{**p, "targets": [{**t, "datasource": {"uid": "other"}}
                                                                                 for t in p.get("targets", [])]}
                                                              for p in good["panels"]]}),
        }
        for code, text in broken.items():
            with self.subTest(code=code):
                target = tmp / f"{code}.json"
                target.write_text(text)
                with self.assertRaises(grafana.DashboardError) as ctx:
                    grafana.load_lifecycle_dashboard(target)
                self.assertEqual(str(ctx.exception), code)
        with self.assertRaises(grafana.DashboardError):
            grafana.load_lifecycle_dashboard(tmp / "absent.json")
