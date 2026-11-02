"""Lab 7 closure -- the Labs 1-3 device-write scripts (master.py, hostserv.py, address_report.py), each function called directly.

These scripts push configuration to devices, so every boundary is replaced: netmiko's connection by ``FakeEos`` and
``docker`` / ``subprocess.run`` by recorders. The only real files read are the tracked ``inventory.yml`` and nothing outside a temporary
directory is written (``RUN_LOG``, ``logs/`` and the CSV report are redirected).  NO DEVICE IS CONTACTED AND NOTHING IS SPAWNED.

POSITIVE: the exact command sequence, pushed configuration, verdict and report.  NEGATIVE: a rejected configuration, a non-zero
container-console failure, missing neighbours / NAT / DHCP / HTTP, and an uninspectable container are reported or raised --
the run stops before the next write, and no shared password path exists.
"""

from __future__ import annotations

import csv
import io
import json
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase

from core.services.test_governance.constants import REPO_ROOT

if str(REPO_ROOT) not in sys.path:
    sys.path.append(str(REPO_ROOT))

import address_report  # noqa: E402
import hostserv  # noqa: E402
import master  # noqa: E402
from modules.eos_render import eos_commands  # noqa: E402

class FakeEos:
    """netmiko connection stand-in."""

    def __init__(self, outputs=None, config_output="configured"):
        self.outputs, self.config_output = outputs or {}, config_output
        self.pushed, self.timing, self.disconnected, self.enabled, self._config = None, [], False, False, True

    def check_enable_mode(self):
        return False

    def enable(self):
        self.enabled = True

    def config_mode(self, **kwargs):
        pass

    def send_config_set(self, commands, **kwargs):
        self.pushed = list(commands)
        return self.config_output

    def check_config_mode(self):
        inside, self._config = self._config, False
        return inside

    def exit_config_mode(self):
        pass

    def send_command_timing(self, command):
        self.timing.append(command)
        return "Copy completed successfully."

    def send_command(self, command, **kwargs):
        return self.outputs.get(command, "")

    def disconnect(self):
        self.disconnected = True


class ScriptCase(SimpleTestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="nmas-lab7-scripts-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp, ignore_errors=True))
        for target, name, value in ((master, "RUN_LOG", self.tmp / "Run_Logs.log"), (master, "BASE", self.tmp),
                                    (address_report, "CSV_FILE", self.tmp / "address_report.csv"),
                                    (master.time, "sleep", lambda s: None), (hostserv.time, "sleep", lambda s: None)):
            patcher = mock.patch.object(target, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        # a safety net: any real process start from these scripts is a test failure, never a host command
        for module in (master, address_report):
            patcher = mock.patch.object(module.subprocess, "run", side_effect=AssertionError("process start attempted"))
            patcher.start()
            self.addCleanup(patcher.stop)
        master.RUN_LOG.write_text("")
        self.out = io.StringIO()
        patcher = mock.patch("sys.stdout", self.out)
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_log(self):
        return master.RUN_LOG.read_text()


# --- master.py --------------------------------------------------------------------------------------------------------------------
class MasterPushTests(ScriptCase):
    CFG = "hostname R1\ninterface Ethernet1\n   no switchport\n"

    def push(self, conn):
        with mock.patch.object(master, "_build_eos_config", return_value=self.CFG), mock.patch.object(master, "eos_conn", return_value=conn) as opened:
            master.push_eos("R1", "172.20.20.2", {"network_devices": {}})
        return opened

    def test_push_eos_sends_the_rendered_commands_and_writes_memory(self):
        conn = FakeEos()
        opened = self.push(conn)
        self.assertEqual(opened.call_args.args[:2], ("R1", "172.20.20.2"))
        self.assertEqual((conn.pushed, conn.timing, conn.enabled, conn.disconnected), (eos_commands(self.CFG), ["write memory"], True, True))
        self.assertIn("CONFIG R1", self.run_log())

    def test_push_eos_rejected_configuration_raises_and_never_writes_memory(self):
        conn = FakeEos(config_output="% Invalid input at '^' marker")
        with self.assertRaisesRegex(RuntimeError, "R1: config rejected"):
            self.push(conn)
        self.assertEqual((conn.timing, conn.disconnected), ([], True))

    def test_linux_exec_uses_the_fixed_container_console_and_feeds_stdin(self):
        result = SimpleNamespace(returncode=0, stdout="done\n", stderr="")
        with mock.patch.object(master, "docker", return_value=result) as docker:
            self.assertEqual(master.linux_exec("lab", "R3", "cat > /tmp/x", stdin_data="line"), "done\n")
        docker.assert_called_once_with(
            ["exec", "-i", "clab-lab-R3", "bash", "-lc", "cat > /tmp/x"], input_data="line",
        )

    def test_linux_exec_propagates_a_console_failure(self):
        with mock.patch.object(master, "docker", side_effect=RuntimeError("container console failed")), \
                self.assertRaisesRegex(RuntimeError, "container console failed"):
            master.linux_exec("lab", "R3", "false")

    def test_push_linux_router_uploads_checks_then_runs_the_script(self):
        with mock.patch.object(master, "render", return_value="#!/bin/bash\nvtysh -b\n"), mock.patch.object(master, "linux_exec", return_value="") as remote:
            master.push_linux_router("R3", "172.20.20.4", master.load_inventory())
        self.assertEqual([c.args[2] for c in remote.call_args_list], ["cat > /tmp/R3.cfg", "bash -n /tmp/R3.cfg", "bash /tmp/R3.cfg"])
        self.assertEqual(remote.call_args_list[0].kwargs["stdin_data"], "#!/bin/bash\nvtysh -b\n")

    def test_push_linux_router_syntax_failure_raises_and_never_executes(self):
        def remote(lab, node, command, **kwargs):
            if command.startswith("bash -n"):
                raise RuntimeError("console failed RC=2 syntax error")
            return ""

        with mock.patch.object(master, "render", return_value="if then\n"), mock.patch.object(master, "linux_exec", side_effect=remote) as fake:
            with self.assertRaises(RuntimeError):
                master.push_linux_router("R3", "172.20.20.4", master.load_inventory())
        self.assertNotIn("bash /tmp/R3.cfg", [c.args[2] for c in fake.call_args_list])

    def test_log_without_text_writes_no_body(self):
        master.log("EMPTY SECTION")
        self.assertRegex(self.run_log(), r"\n\[[0-9T:-]+\] EMPTY SECTION\n\n$")


class MasterVerifyTests(ScriptCase):
    HEALTHY = {"show ip ospf neighbor": "Neighbor ID  Instance\n10.0.0.2  1  FULL", "show ipv6 ospf neighbor": "10.0.0.2 FULL",
               "show nexthop-group": "NexthopGroup ipip1 ... programmed"}

    def verify(self, outputs):
        conn = FakeEos(outputs)
        with mock.patch.object(master, "eos_conn", return_value=conn):
            return master.verify_eos("R1", "172.20.20.2", {"network_devices": {}}), conn

    def test_verify_eos_passes_with_neighbours_and_programmed_nexthops(self):
        verdict, conn = self.verify(self.HEALTHY)
        self.assertEqual((verdict, conn.disconnected), (True, True))
        self.assertIn("VERIFY RESULT R1", self.run_log())

    def test_verify_eos_fails_without_ospf_neighbours_or_with_a_dropped_nexthop(self):
        verdict, _conn = self.verify({**self.HEALTHY, "show ip ospf neighbor": "Neighbor ID  Instance\n", "show nexthop-group": "ipip1 (drop)"})
        self.assertFalse(verdict)
        self.assertIn("FAILED: OSPFv2 has no neighbors; IPIP nexthop-group unresolved", self.run_log())

    def test_verify_linux_router_passes_with_the_nat_table(self):
        with mock.patch.object(master, "linux_exec", return_value="--- NAT ---\ntable ip EDGE_PAT {\n}"):
            self.assertTrue(master.verify_linux_router("R3", {"lab_name": "lab"}))

    def test_verify_linux_router_fails_without_nat_or_when_ssh_errors(self):
        with mock.patch.object(master, "linux_exec", return_value="--- NAT ---\n"):
            self.assertFalse(master.verify_linux_router("R3", {"lab_name": "lab"}))
        with mock.patch.object(master, "linux_exec", side_effect=RuntimeError("console failed")):
            self.assertFalse(master.verify_linux_router("R3", {"lab_name": "lab"}))
        self.assertIn("NAT/PAT table missing", self.run_log())


class MasterMainTests(ScriptCase):
    def test_main_pushes_in_dependency_order_then_verifies_every_node(self):
        inv = master.load_inventory()
        names = ("setup_nmas", "push_eos", "push_linux_router", "bootstrap_linux_ssh", "configure_webserver", "configure_host", "verify_eos",
                 "verify_linux_router", "verify_linux", "ensure_nmas_infrastructure", "ensure_snmp_infrastructure", "ensure_syslog_infrastructure",
                 "ensure_telemetry_infrastructure", "ensure_grafana_infrastructure", "ensure_topology_infrastructure")
        fakes = {}
        with mock.patch.object(master, "load_inventory", return_value=inv), \
                mock.patch.object(master, "discover_ip", side_effect=lambda lab, node: f"ip-{node}"), \
                mock.patch.object(master.subprocess, "run") as report:
            for name in names:
                patcher = mock.patch.object(master, name)
                fakes[name] = patcher.start()
                self.addCleanup(patcher.stop)
            master.main()
        pushed = [c.args[0] for c in (fakes["push_eos"].call_args_list + fakes["push_linux_router"].call_args_list)]
        self.assertEqual(sorted(pushed), sorted(["mgmt_swt", "S3", "S4", "S1", "S2", "R1", "R2", "R3", "R4", "R5"]))
        self.assertEqual([c.args[0] for c in fakes["push_eos"].call_args_list], ["mgmt_swt", "S3", "S4", "S1", "S2", "R1", "R2", "R5"])
        self.assertEqual([c.args[0] for c in fakes["push_linux_router"].call_args_list], ["R3", "R4"])
        fakes["setup_nmas"].assert_called_once_with(inv)
        fakes["configure_webserver"].assert_called_once()
        self.assertEqual([c.args[1] for c in fakes["verify_linux"].call_args_list], ["H1", "H2", "H3", "H4"])
        self.assertEqual(report.call_args.args[0][1], str(master.BASE / "address_report.py"))


# --- hostserv.py ------------------------------------------------------------------------------------------------------------------
class HostServTests(ScriptCase):
    def test_console_exec_uses_the_fixed_container_name(self):
        docker = mock.Mock(return_value=SimpleNamespace(stdout="Hello world\n"))
        self.assertEqual(hostserv.console_exec("lab", "H1", docker, "curl x"), "Hello world\n")
        docker.assert_called_once_with(["exec", "clab-lab-H1", "bash", "-lc", "curl x"])

    def test_console_exec_propagates_console_failure(self):
        docker = mock.Mock(side_effect=RuntimeError("console unavailable"))
        with self.assertRaisesRegex(RuntimeError, "console unavailable"):
            hostserv.console_exec("lab", "H1", docker, "true")
        self.assertEqual(docker.call_count, 1)

    def test_bootstrap_linux_ssh_disables_password_and_root_login(self):
        docker, log = mock.Mock(return_value=SimpleNamespace(stdout="host_private_keys=3\n", stderr="")), mock.Mock()
        hostserv.bootstrap_linux_ssh("srlceos01", "H1", docker, log)
        (setup,) = docker.call_args_list
        self.assertEqual(setup.args[0][:2], ["exec", "clab-srlceos01-H1"])
        script = setup.args[0][-1]
        self.assertIn("PermitRootLogin no", script)
        self.assertIn("PasswordAuthentication no", script)
        self.assertIn("passwd -l root", script)
        self.assertNotIn("chpasswd", script)

    def test_bootstrap_linux_ssh_failure_stops_after_one_console_call(self):
        docker = mock.Mock(side_effect=RuntimeError("No such container"))
        with self.assertRaises(RuntimeError):
            hostserv.bootstrap_linux_ssh("srlceos01", "H9", docker, mock.Mock())
        self.assertEqual(docker.call_count, 1)

    def test_configure_webserver_runs_the_setup_and_logs_it(self):
        log = mock.Mock()
        with mock.patch.object(hostserv, "console_exec", return_value="apache2 OK") as remote:
            hostserv.configure_webserver("lab", "WebServer", mock.Mock(), log)
        self.assertEqual(remote.call_args.args[:2], ("lab", "WebServer"))
        log.assert_called_once_with("WebServer configuration", "apache2 OK")

    def test_configure_webserver_failure_raises(self):
        with mock.patch.object(hostserv, "console_exec", side_effect=RuntimeError("command failed (1)")), self.assertRaises(RuntimeError):
            hostserv.configure_webserver("lab", "WebServer", mock.Mock())

    def test_configure_host_acquires_both_families(self):
        with mock.patch.object(hostserv, "console_exec", return_value="eth1 UP 192.168.10.102/24 2001:db8:10::2001/64") as remote:
            self.assertTrue(hostserv.configure_host("lab", "H1", mock.Mock()))
        self.assertEqual(len(remote.call_args_list), 4)  # reset, dhclient -4, dhclient -6, report

    def test_configure_host_without_a_dhcpv6_lease_fails(self):
        log = mock.Mock()
        with mock.patch.object(hostserv, "console_exec", return_value="eth1 UP 192.168.10.102/24"):
            self.assertFalse(hostserv.configure_host("lab", "H1", mock.Mock(), log=log))
        self.assertIn("address acquisition FAILED (DHCPv6)", self.out.getvalue())

    def test_verify_linux_passes_when_both_curls_return_hello_world(self):
        log = mock.Mock()
        with mock.patch.object(hostserv, "console_exec", side_effect=["eth1 UP", "Hello world", "Hello world"]) as remote:
            self.assertTrue(hostserv.verify_linux("lab", "H1", mock.Mock(), log))
        self.assertEqual([c.args[3].split()[1] for c in remote.call_args_list[1:]], ["-4", "-6"])

    def test_verify_linux_fails_on_an_empty_or_failed_response(self):
        log = mock.Mock()
        with mock.patch.object(hostserv, "console_exec", side_effect=["eth1 UP", "", RuntimeError("timeout")]):
            self.assertFalse(hostserv.verify_linux("lab", "H1", mock.Mock(), log))
        self.assertIn("curl4: FAIL - empty response", log.call_args.args[1])
        self.assertIn("curl6: FAIL - timeout", log.call_args.args[1])


# --- address_report.py ------------------------------------------------------------------------------------------------------------
class AddressReportTests(ScriptCase):
    INSPECT = [{"NetworkSettings": {"Networks": {"other": {"IPAddress": "10.1.1.5"}, "clab": {"IPAddress": "172.20.20.3"}}}}]

    def test_docker_inspect_returns_the_document_falling_back_to_sudo(self):
        results = [SimpleNamespace(returncode=1, stdout="", stderr="permission denied"), SimpleNamespace(returncode=0, stdout=json.dumps(self.INSPECT))]
        with mock.patch.object(address_report.subprocess, "run", side_effect=results) as run:
            self.assertEqual(address_report.docker_inspect("clab-srlceos01-R3"), self.INSPECT[0])
        self.assertEqual(run.call_args.args[0][:2], ["sudo", "docker"])

    def test_docker_inspect_of_a_missing_container_raises(self):
        with mock.patch.object(address_report.subprocess, "run", return_value=SimpleNamespace(returncode=1, stdout="", stderr="No such object")), \
                self.assertRaisesRegex(RuntimeError, "Cannot inspect clab-srlceos01-R9"):
            address_report.docker_inspect("clab-srlceos01-R9")

    def test_management_ip_returns_the_management_address(self):
        with mock.patch.object(address_report, "docker_inspect", return_value=self.INSPECT[0]):
            self.assertEqual(address_report.management_ip("srlceos01", "R3"), "172.20.20.3")

    def test_management_ip_without_any_address_raises(self):
        with mock.patch.object(address_report, "docker_inspect", return_value={"NetworkSettings": {"Networks": {"clab": {"IPAddress": ""}}}}), \
                self.assertRaisesRegex(RuntimeError, "No Containerlab management IP for R3"):
            address_report.management_ip("srlceos01", "R3")

    def test_docker_exec_returns_output_and_falls_back_to_sudo(self):
        results = [SimpleNamespace(returncode=1, stdout="", stderr="denied"),
                   SimpleNamespace(returncode=0, stdout="ok\n", stderr="")]
        with mock.patch.object(address_report.subprocess, "run", side_effect=results) as run:
            self.assertEqual(address_report.docker_exec("clab-lab-H1", ["true"]), "ok\n")
        self.assertEqual(run.call_args.args[0][:3], ["sudo", "docker", "exec"])

    def test_docker_exec_fails_after_both_fixed_argv_attempts(self):
        result = SimpleNamespace(returncode=1, stdout="", stderr="denied")
        with mock.patch.object(address_report.subprocess, "run", return_value=result) as run, \
                self.assertRaisesRegex(RuntimeError, "Container console command failed"):
            address_report.docker_exec("clab-lab-H1", ["true"])
        self.assertEqual(run.call_count, 2)

    def test_linux_addresses_parses_interfaces_and_families(self):
        out = "2: eth1@if9    inet 192.168.10.102/24 brd x\n2: eth1@if9    inet6 2001:db8:10::2001/64 scope global\n"
        with mock.patch.object(address_report, "docker_exec", return_value=out):
            self.assertEqual(address_report.linux_addresses("lab", "H1"), [("eth1", "IPv4", "192.168.10.102/24"), ("eth1", "IPv6", "2001:db8:10::2001/64")])

    def test_linux_addresses_of_malformed_output_is_empty(self):
        with mock.patch.object(address_report, "docker_exec", return_value="garbage\n\nnot an address line\n"):
            self.assertEqual(address_report.linux_addresses("lab", "H1"), [])

    def test_linux_leases_parses_v4_v6_and_dhclient_logs(self):
        out = ("lease {\n  fixed-address 192.168.10.102;\n  expire 3 2026/10/20 10:00:00;\n}\n"
               "iaaddr 2001:db8:10::2001 {\n  max-life 7200;\n}\n"
               "bound to 192.168.10.103 -- renewal in 300 seconds.\nConfirm Address 2001:db8:10::2002\n")
        with mock.patch.object(address_report, "docker_exec", return_value=out):
            self.assertEqual(address_report.linux_leases("lab", "H1"), {"192.168.10.102": "DHCPv4 expire 2026/10/20 10:00:00", "2001:db8:10::2001": "DHCPv6 max-life 7200s",
                                                                 "192.168.10.103": "DHCPv4 renewal 300s", "2001:db8:10::2002": "DHCPv6"})

    def test_linux_leases_without_any_lease_is_empty(self):
        with mock.patch.object(address_report, "docker_exec", return_value="lease {\n  option routers 1.1.1.1;\n}\n"):
            self.assertEqual(address_report.linux_leases("lab", "H1"), {})

    def test_eos_addresses_console_failure_raises(self):
        with mock.patch.object(address_report, "docker_exec", side_effect=RuntimeError("console unavailable")), \
                self.assertRaisesRegex(RuntimeError, "console unavailable"):
            address_report.eos_addresses("lab", "R1")

    def test_print_table_aligns_the_rows(self):
        address_report.print_table([["R1", "Ethernet1", "IPv4", "10.0.0.1/31", ""]])
        lines = self.out.getvalue().splitlines()
        self.assertEqual(lines[0].split(), ["Device", "Interface", "Family", "Address", "DHCP", "Lease"])
        self.assertEqual(lines[2].split(), ["R1", "Ethernet1", "IPv4", "10.0.0.1/31"])

    def test_print_table_of_no_rows_prints_only_the_header(self):
        address_report.print_table([])
        self.assertEqual(len(self.out.getvalue().splitlines()), 2)

    def test_main_writes_the_sorted_csv_report(self):
        with mock.patch.object(address_report, "management_ip", side_effect=lambda lab, node: f"ip-{node}"), \
                mock.patch.object(address_report, "linux_leases", return_value={"192.168.10.102": "DHCPv4"}), \
                mock.patch.object(address_report, "linux_addresses", return_value=[("eth1", "IPv4", "192.168.10.102/24")]), \
                mock.patch.object(address_report, "eos_addresses", return_value=[("Ethernet1", "IPv4", "10.0.0.1/31")]) as eos:
            address_report.main()
        with address_report.CSV_FILE.open() as handle:
            rows = list(csv.reader(handle))
        self.assertEqual(rows[0], ["device", "interface", "family", "address", "dhcp_lease"])
        self.assertIn(["H1", "eth1", "IPv4", "192.168.10.102/24", "DHCPv4"], rows)
        self.assertEqual(sorted(c.args[1] for c in eos.call_args_list), ["R1", "R2", "R5", "S1", "S2", "S3", "S4", "mgmt_swt"])
        self.assertEqual(rows[1:], sorted(rows[1:]))
