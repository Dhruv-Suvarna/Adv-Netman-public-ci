"""Lab 7 closure -- ``modules/snmp.py`` (SNMP IaC, one-shot polling, receiver provisioning and verification), each
function called directly.

Hermetic: ``RUNTIME`` / ``BASE`` point into a temporary directory (a synthetic inventory, never the lab's), every
``subprocess.run`` / ``docker`` / ``cli`` / ``command`` / ``poll`` call is a recording fake, InfluxDB is an in-memory
session, the CPU-alert evaluator is patched (it would write state), and the absolute ``/etc/snmp`` paths are remapped
into the temporary root.  No device, container, receiver or InfluxDB is contacted; secrets are fake values.
POSITIVE: exact argv, parsed SNMP values, rendered/converged configuration, line-protocol records and verification
output.  NEGATIVE: insecure / missing / malformed credentials, failed commands (with secrets redacted), unsupported
policy or platform, stopped containers, EOS rejections, empty polls, sysName / CPU / interface-table mismatches,
missing trap files and absent stored events are all refused.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

from modules import snmp
from modules.nmas import NmasError

AUTH, PRIV = "a" * 32, "b" * 32
POLICY = {"username": "nmas-monitor", "auth": "SHA-256", "privacy": "AES", "receiver": "192.168.200.100", "interval_seconds": 60}
CEOS = {"platform": "ceos", "address": "192.168.200.1", "source_interface": "Vlan200", "device": "R1", "container": "clab-lab-R1", **POLICY}
LINUX = {"platform": "linux", "address": "192.168.200.3", "source_interface": "Vlan200", "device": "R3", "container": "clab-lab-R3", **POLICY}


def completed(argv, stdout="", returncode=0, stderr=""):
    return subprocess.CompletedProcess(argv, returncode, stdout=stdout, stderr=stderr)


class FakeResponse:
    def __init__(self, text=""):
        self.text = text

    def raise_for_status(self):
        return None


class FakeSession:
    def __init__(self, query_text):
        self.query_text, self.posts = query_text, []

    def post(self, url, **kwargs):
        self.posts.append((url, kwargs))
        return FakeResponse(self.query_text if url.endswith("/query") else "")


ENV = {"INFLUXDB_ORG": "nmas", "INFLUXDB_BUCKET": "network-monitoring", "INFLUXDB_TOKEN": "fake-Influx-Token-3"}


class SnmpBase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.runtime = self.root / "runtime"
        patcher = mock.patch.object(snmp, "RUNTIME", self.runtime)
        patcher.start()
        self.addCleanup(patcher.stop)

    def secrets(self, value=None, mode=0o600):
        snmp.protected_json(self.runtime / "snmp-secrets.json", value or {"auth_password": AUTH, "privacy_password": PRIV})
        (self.runtime / "snmp-secrets.json").chmod(mode)


class SecretsTests(SnmpBase):
    def test_protected_json_returns_after_writing_an_owner_only_file(self):
        path = self.runtime / "nested" / "x.json"
        self.assertIsNone(snmp.protected_json(path, {"k": 1}))
        self.assertEqual((json.loads(path.read_text()), oct(path.stat().st_mode & 0o777)), ({"k": 1}, "0o600"))

    def test_protected_json_never_keeps_group_or_world_bits_of_an_existing_file(self):
        path = self.runtime / "x.json"
        self.runtime.mkdir()
        path.write_text("old")
        path.chmod(0o644)
        snmp.protected_json(path, [1])
        self.assertEqual((path.read_text(), path.stat().st_mode & 0o077), ("[\n  1\n]", 0))

    def test_credentials_create_returns_generated_hex_secrets(self):
        found = snmp.credentials(create=True)
        self.assertEqual((sorted(found), [len(v) for v in found.values()]), (["auth_password", "privacy_password"], [48, 48]))
        self.assertEqual(snmp.credentials(), found)

    def test_credentials_refuse_missing_insecure_or_malformed_secrets(self):
        with self.subTest(case="refused missing"), self.assertRaisesRegex(NmasError, "missing or insecure"):
            snmp.credentials()
        for label, value, mode, message in (("insecure", None, 0o644, "missing or insecure"),
                                            ("malformed", {"auth_password": "short", "privacy_password": PRIV}, 0o600, "Invalid SNMP runtime credentials")):
            with self.subTest(case=f"refused {label}"):
                self.secrets(value, mode)
                with self.assertRaisesRegex(NmasError, message):
                    snmp.credentials()


class CommandTests(SnmpBase):
    def test_command_returns_stdout(self):
        with mock.patch.object(snmp.subprocess, "run", return_value=completed(["x"], "ok\n")) as run:
            self.assertEqual(snmp.command(["snmpget", "-v3"], data="in", timeout=5), "ok\n")
        run.assert_called_once_with(["snmpget", "-v3"], input="in", capture_output=True, text=True, timeout=5)

    def test_command_failure_is_refused_with_secrets_redacted(self):
        self.secrets()
        with mock.patch.object(snmp.subprocess, "run", return_value=completed(["x"], "", 1, f"auth {AUTH} priv {PRIV} denied")), \
                self.assertRaises(NmasError) as caught:
            snmp.command(["snmpget"])
        self.assertEqual(str(caught.exception), "SNMP command failed (snmpget): auth [REDACTED] priv [REDACTED] denied")

    def test_docker_returns_output_through_docker_or_the_sudo_fallback(self):
        for info_rc, prefix in ((0, ["docker"]), (1, ["sudo", "-n", "docker"])):
            with self.subTest(case=f"docker info exit {info_rc} returns output"), \
                    mock.patch.object(snmp.subprocess, "run", return_value=completed(["docker", "info"], returncode=info_rc)), \
                    mock.patch.object(snmp, "command", return_value="out") as command:
                self.assertEqual(snmp.docker("ps", data="d", timeout=9), "out")
            command.assert_called_once_with([*prefix, "ps"], "d", 9)

    def test_docker_failure_is_refused(self):
        def run(argv, **_kwargs):
            return completed(argv, returncode=0 if argv == ["docker", "info"] else 1, stderr="no such container")

        with mock.patch.object(snmp.subprocess, "run", side_effect=run), self.assertRaisesRegex(NmasError, r"SNMP command failed \(docker\): no such container"):
            snmp.docker("inspect", "clab-lab-R9")

    def test_tag_escapes_line_protocol_separators(self):
        self.assertEqual(snmp.tag("a b,c=d\\e"), "a\\ b\\,c\\=d\\\\e")

    def test_tag_of_an_empty_or_non_string_value_is_its_text(self):
        self.assertEqual((snmp.tag(""), snmp.tag(7), snmp.tag(None)), ("", "7", "None"))

    def test_influx_returns_an_authorized_session_without_proxy_trust(self):
        self.runtime.mkdir()
        (self.runtime / "monitoring.env").write_text("".join(f"{k}={v}\n" for k, v in ENV.items()) + "noise\n")
        session, env = snmp.influx()
        self.assertEqual((env, session.trust_env, session.headers["Authorization"]), (ENV, False, "Token fake-Influx-Token-3"))


class DevicesTests(SnmpBase):
    def inventory(self, policy=None, devices=None):
        self.root.joinpath("inventory.yml").write_text(yaml.safe_dump({"lab_name": "lab", "snmp": policy or POLICY, "network_devices": devices or {
            "R1": {"monitoring": {"platform": "ceos", "address": "192.168.200.1", "source_interface": "Vlan200"}},
            "R5": {"monitoring": {"platform": "ceos", "address": "auto", "source_interface": "Management0"}}}}))

    def devices(self, running=True):
        def docker(*args, **_kwargs):
            networks = {"clab": {"IPAddress": "172.20.20.15"}, "other": {"IPAddress": "10.9.9.9"}}
            return json.dumps([{"State": {"Running": running}, "NetworkSettings": {"Networks": networks}}])

        with mock.patch.object(snmp, "BASE", self.root), mock.patch.object(snmp, "docker", side_effect=docker) as called:
            return snmp.devices(), called

    def test_devices_returns_each_running_monitored_device_with_policy(self):
        self.inventory()
        found, called = self.devices()
        self.assertEqual([(d["device"], d["container"], d["address"], d["auth"]) for d in found],
                         [("R1", "clab-lab-R1", "192.168.200.1", "SHA-256"), ("R5", "clab-lab-R5", "172.20.20.15", "SHA-256")])
        self.assertEqual([c.args for c in called.call_args_list], [("inspect", "clab-lab-R1"), ("inspect", "clab-lab-R5")])

    def test_devices_refuses_unsupported_policy_missing_metadata_platform_or_stopped_containers(self):
        for label, policy, devices, running, message in (
                ("policy", {**POLICY, "auth": "MD5"}, None, True, "Only verified SHA-256/AES"),
                ("metadata", None, {"R1": {}}, True, "R1: monitoring metadata missing"),
                ("platform", None, {"R1": {"monitoring": {"platform": "junos", "address": "1.1.1.1"}}}, True, "R1: unsupported platform"),
                ("stopped", None, None, False, "R1: container is not running")):
            with self.subTest(case=f"refused {label}"):
                self.inventory(policy, devices)
                with self.assertRaisesRegex(NmasError, message):
                    self.devices(running)


class CliPollTests(SnmpBase):
    def test_cli_returns_the_eos_output(self):
        with mock.patch.object(snmp, "docker", return_value="Local SNMP EngineID: 0a0b\n") as docker:
            self.assertEqual(snmp.cli(CEOS, "show snmp engineID"), "Local SNMP EngineID: 0a0b\n")
        docker.assert_called_once_with("exec", "-i", "clab-lab-R1", "Cli", "-p", "15", "--abort-on-error", data="show snmp engineID\n")

    def test_cli_refuses_an_eos_rejection_with_secrets_redacted(self):
        self.secrets()
        with mock.patch.object(snmp, "docker", return_value=f"% Invalid input near {AUTH}"), self.assertRaises(NmasError) as caught:
            snmp.cli(CEOS, "snmp-server user x")
        self.assertEqual(str(caught.exception), "R1: EOS rejected SNMP configuration: % Invalid input near [REDACTED]")

    def poll(self, stdout, returncode=0, **kwargs):
        seen = {}

        def run(argv, env, **_kwargs):
            seen["argv"], seen["conf"] = argv, Path(env["SNMPCONFPATH"], "snmp.conf").read_text()
            seen["dir"] = env["SNMPCONFPATH"]
            return completed(argv, stdout, returncode, "Timeout: No Response")

        with mock.patch.object(snmp.subprocess, "run", side_effect=run):
            try:
                return snmp.poll(CEOS, "1.3.6.1.2.1.2.2.1.8", **kwargs), seen
            finally:
                self.assertFalse(Path(seen["dir"]).exists())

    def test_poll_returns_typed_values_from_a_walk(self):
        self.secrets()
        found, seen = self.poll('.1.3.6.1.2.1.2.2.1.8.1 = INTEGER: 1\n.1.3.6.1.2.1.31.1.1.1.1.1 = STRING: "Ethernet1"\n'
                                ".1.3.6.1.2.1.1.3.0 = 12345\n.1.3.6.1.2.1.2.2.1.8.9 = No Such Instance\n", walk=True)
        self.assertEqual(found, {"1.3.6.1.2.1.2.2.1.8.1": 1, "1.3.6.1.2.1.31.1.1.1.1.1": "Ethernet1", "1.3.6.1.2.1.1.3.0": 12345})
        self.assertEqual(seen["argv"], ["snmpwalk", "-On", "-Oe", "-Ot", "-t", "2", "-r", "1", "192.168.200.1", "1.3.6.1.2.1.2.2.1.8"])
        self.assertIn(f"defAuthPassphrase {AUTH}\n", seen["conf"])
        self.assertIn("defSecurityLevel authPriv\n", seen["conf"])
        self.assertTrue(seen["conf"].endswith("clientaddr 192.168.200.100\n"))

    def test_poll_refuses_a_failed_request_or_no_usable_values(self):
        self.secrets()
        with self.subTest(case="refused failed request"), self.assertRaisesRegex(NmasError, "R1: SNMP noAuthNoPriv request failed: Timeout: No Response"):
            self.poll("", returncode=1, security="noAuthNoPriv")
        with self.subTest(case="refused empty"), self.assertRaisesRegex(NmasError, "R1: requested OID has no usable values: 1.3.6.1.2.1.2.2.1.8"):
            self.poll("No more variables left in this MIB View\n")


class ConfigureTests(SnmpBase):
    def test_configure_device_converges_ceos_then_reports_unchanged(self):
        self.secrets()
        out = io.StringIO()
        with mock.patch.object(snmp, "cli", return_value="snmp-server running\n") as cli, mock.patch.object(snmp, "poll", return_value={"x": "R1"}) as poll, \
                contextlib.redirect_stdout(out):
            self.assertIsNone(snmp.configure_device(CEOS))
            self.assertIsNone(snmp.configure_device(CEOS))
        commands = [c.args[1] for c in cli.call_args_list]
        self.assertTrue(commands[1].startswith("configure terminal\nip access-list standard NMAS_SNMP\n   10 permit host 192.168.200.100\n"))
        self.assertIn(f"auth sha256 {AUTH} priv aes {PRIV}", commands[1])
        self.assertEqual((commands[2], len(commands)), ("write memory", 5))
        poll.assert_called_once_with(CEOS, snmp.OIDS["sysName"])
        self.assertEqual(out.getvalue(), "R1: SNMP converged\nR1: SNMP unchanged\n")
        self.assertEqual(oct((self.runtime / "R1-snmp-state.json").stat().st_mode & 0o777), "0o600")

    def test_configure_device_hands_linux_the_rendered_context(self):
        self.secrets()
        out = io.StringIO()
        with mock.patch.object(snmp, "docker", return_value="R3 converged\n") as docker, contextlib.redirect_stdout(out):
            snmp.configure_device(LINUX)
        args, kwargs = docker.call_args
        context = json.loads(kwargs["data"])
        self.assertEqual((args[:4], args[4], kwargs["timeout"], out.getvalue()),
                         (("exec", "-i", "clab-lab-R3", "python3"), "-c", 600, "R3: R3 converged\n"))
        self.assertEqual((context["events"]["notification_engine"], "watcher" in context["events"], "config" in context["events"]),
                         ("0x80001f8804" + "nmas-R3-events".encode().hex(), False, False))
        self.assertTrue(context["config"].startswith("# Repository-owned monitoring only; no FRR/forwarding settings.\nagentAddress udp:192.168.200.3:161\nsysName R3\n"))
        self.assertEqual(context["watcher"], (snmp.MONITORING / "scripts/linux_link_notifications.py").read_text())

    def test_configure_device_never_writes_state_after_an_eos_rejection(self):
        self.secrets()
        with mock.patch.object(snmp, "cli", side_effect=["running", NmasError("R1: EOS rejected SNMP configuration")]), \
                self.assertRaisesRegex(NmasError, "EOS rejected"):
            snmp.configure_device(CEOS)
        self.assertFalse((self.runtime / "R1-snmp-state.json").exists())


class ReceiverTests(SnmpBase):
    def receiver(self, cli_text="Local SNMP EngineID: 0A0B0C\n", command_error=None):
        self.secrets()
        out = io.StringIO()
        with mock.patch.object(snmp, "cli", return_value=cli_text), \
                mock.patch.object(snmp, "poll", return_value={"1.3.6.1.6.3.10.2.1.1.0": "80 00 1F 88"}), \
                mock.patch.object(snmp, "influx", return_value=(None, ENV)), \
                mock.patch.object(snmp, "command", side_effect=["installed", command_error or "receiver converged\n"]) as command, \
                contextlib.redirect_stdout(out):
            snmp.ensure_receiver([CEOS, LINUX])
        return command, out.getvalue()

    def test_ensure_receiver_provisions_every_engine_and_records_them(self):
        command, printed = self.receiver()
        install, provision = command.call_args_list
        self.assertEqual(install.args[0], ["bash", str(snmp.MONITORING / "scripts/install_nmas_receivers.sh")])
        payload = json.loads(provision.args[1])
        self.assertEqual(payload["users"], [{"device": "R1", "engine": "0A0B0C"}, {"device": "R3", "engine": "80001f88"},
                                            {"device": "R3-events", "engine": "80001f8804" + "nmas-R3-events".encode().hex()}])
        self.assertEqual((payload["device_map"], payload["influx_token"], printed), ({"192.168.200.1": "R1", "192.168.200.3": "R3"}, "fake-Influx-Token-3", "receiver converged\n"))
        self.assertEqual(json.loads((self.runtime / "snmp-engines.json").read_text()), payload["users"])

    def test_ensure_receiver_never_records_engines_after_a_failed_provisioning(self):
        with self.assertRaisesRegex(NmasError, "receiver failed"):
            self.receiver(command_error=NmasError("receiver failed"))
        self.assertFalse((self.runtime / "snmp-engines.json").exists())


def walks(cpu=(12, 14), names=("Ethernet1", "Ethernet2"), sysname="R1", admin=(1, 1), oper=(1, 2)):
    o = snmp.OIDS
    table = {"sysName": {o["sysName"]: sysname}, "sysUpTime": {o["sysUpTime"]: 100},
             "ifIndex": {f"{o['ifIndex']}.{i}": i for i in (1, 2)}, "ifDescr": {f"{o['ifDescr']}.{i}": n for i, n in zip((1, 2), names)},
             "ifName": {f"{o['ifName']}.{i}": n for i, n in zip((1, 2), names)},
             "ifAdminStatus": {f"{o['ifAdminStatus']}.{i}": v for i, v in zip((1, 2), admin)},
             "ifOperStatus": {f"{o['ifOperStatus']}.{i}": v for i, v in zip((1, 2), oper)},
             "cpu": {f"{o['cpu']['ceos']}.{i}": v for i, v in enumerate(cpu, start=1)}}
    by_oid = {o[k] if k != "cpu" else o["cpu"]["ceos"]: v for k, v in table.items()}
    return lambda item, oid, walk=False, security="authPriv": by_oid[oid]


class CollectTests(SnmpBase):
    def collect(self, poll, query_text="R1,cpu,13"):
        session = FakeSession(query_text)
        with mock.patch.object(snmp, "poll", side_effect=poll), mock.patch.object(snmp, "influx", return_value=(session, ENV)), \
                mock.patch.object(snmp, "evaluate_cpu_threshold", return_value=None) as evaluate, mock.patch.object(snmp.time, "time_ns", return_value=1000):
            return snmp.collect(CEOS), session, evaluate

    def test_collect_returns_written_records_and_the_cpu_mean(self):
        found, session, evaluate = self.collect(walks())
        lines = session.posts[0][1]["data"].splitlines()
        self.assertEqual((found["records_written"], found["cpu_mean"], found["timestamp_ns"], len(lines)), (7, 13.0, 1000, 7))
        self.assertIn("snmp_poll,device=R1,hostname=R1,management_ip=192.168.200.1,platform=ceos,source_protocol=snmp,metric=ifOperStatus,ifindex=2,interface=Ethernet2 value=2i 1000", lines)
        self.assertIn("snmp_poll,device=R1,hostname=R1,management_ip=192.168.200.1,platform=ceos,source_protocol=snmp,metric=cpu,cpu_index=1 value=12i 1000", lines)
        evaluate.assert_called_once_with("R1", "ceos", 13.0, timestamp_ns=1000)

    def test_collect_refuses_mismatched_or_invalid_data_without_writing(self):
        for label, poll, message in (("sysName", walks(sysname="R9"), "sysName does not match inventory"),
                                     ("cpu", walks(cpu=(101,)), "invalid CPU values"),
                                     ("admin", walks(admin=(1, 9)), "Invalid interface admin state"),
                                     ("oper", walks(oper=(1, 0)), "Invalid interface operational state")):
            with self.subTest(case=f"refused {label}"), self.assertRaisesRegex(NmasError, message):
                self.collect(poll)
        with self.subTest(case="refused missing stored sample"), self.assertRaisesRegex(NmasError, "did not return the new CPU sample"):
            self.collect(walks(), query_text="")


class VerifyTests(SnmpBase):
    def test_verify_snmp_returns_results_when_unauthenticated_reads_fail(self):
        out = io.StringIO()
        with mock.patch.object(snmp, "collect", return_value={"device": "R1"}), mock.patch.object(snmp, "poll", side_effect=NmasError("noAuth refused")), \
                contextlib.redirect_stdout(out):
            self.assertEqual(snmp.verify_snmp([CEOS]), [{"device": "R1"}])
        self.assertIn("R1         PASS  PASS PASS    PASS   PASS PASS     PASS", out.getvalue())
        self.assertEqual(json.loads((self.runtime / "snmp-verification.json").read_text()), [{"device": "R1"}])

    def test_verify_snmp_refuses_an_unauthenticated_read_or_a_failed_collect(self):
        for label, collect, poll in (("noAuth read accepted", {"device": "R1"}, {"x": 1}), ("collect failed", NmasError("boom"), None)):
            with self.subTest(case=f"refused {label}"), contextlib.redirect_stdout(io.StringIO()), \
                    mock.patch.object(snmp, "collect", **({"side_effect": collect} if isinstance(collect, Exception) else {"return_value": collect})), \
                    mock.patch.object(snmp, "poll", return_value=poll), self.assertRaisesRegex(NmasError, "SNMP verification failed: R1"):
                snmp.verify_snmp([CEOS])

    def trap_files(self, env_mode=0o600, traphandle=True, ingest_mode=0o755):
        etc = self.root / "etc" / "snmp"
        etc.mkdir(parents=True, exist_ok=True)
        for name, mode in (("nmas-trap-ingest.py", ingest_mode), ("nmas-trap-oids.json", 0o644), ("nmas-trap-devices.json", 0o644), ("nmas-trap-ingest.env", env_mode)):
            (etc / name).write_text("x")
            (etc / name).chmod(mode)
        (etc / "snmptrapd.conf").write_text("traphandle default /usr/bin/python3 /etc/snmp/nmas-trap-ingest.py\n" if traphandle else "")
        root = self.root
        return mock.patch.object(snmp, "Path", side_effect=lambda p: root / str(p).lstrip("/"))

    def test_verify_trap_ingestion_passes_structure_and_a_stored_test_notification(self):
        out = io.StringIO()
        session = FakeSession("R1 ceosTestNotification")
        with self.trap_files(), mock.patch.object(snmp, "cli") as cli, mock.patch.object(snmp.time, "sleep"), \
                mock.patch.object(snmp, "influx", return_value=(session, ENV)), contextlib.redirect_stdout(out):
            self.assertIsNone(snmp.verify_trap_ingestion([LINUX, CEOS]))
        cli.assert_called_once_with(CEOS, "test snmp notification")
        self.assertEqual(out.getvalue(), "Trap ingestion: PASS (verified via R1 test notification -> InfluxDB)\n")
        out = io.StringIO()
        with self.trap_files(), contextlib.redirect_stdout(out):
            snmp.verify_trap_ingestion([LINUX])
        self.assertEqual(out.getvalue(), "Trap ingestion: structural checks PASS (no cEOS device available for a live test)\n")

    def test_verify_trap_ingestion_refuses_missing_insecure_or_unstored_traps(self):
        for label, kwargs, message in (("insecure env", {"env_mode": 0o644}, "credentials file missing or insecure"),
                                       ("permissions", {"ingest_mode": 0o777}, "unexpected permissions: /etc/snmp/nmas-trap-ingest.py"),
                                       ("traphandle", {"traphandle": False}, "missing the trap ingestion traphandle")):
            with self.subTest(case=f"refused {label}"), self.trap_files(**kwargs), self.assertRaisesRegex(NmasError, message):
                snmp.verify_trap_ingestion([LINUX])
        with self.subTest(case="refused unstored event"), self.trap_files(), mock.patch.object(snmp, "cli"), mock.patch.object(snmp.time, "sleep"), \
                mock.patch.object(snmp, "influx", return_value=(FakeSession(""), ENV)), self.assertRaisesRegex(NmasError, "no fresh snmp_trap event stored for R1"):
            snmp.verify_trap_ingestion([CEOS])
        with self.subTest(case="refused missing file"), mock.patch.object(snmp, "Path", side_effect=lambda p: self.root / "nowhere" / str(p).lstrip("/")), \
                self.assertRaisesRegex(NmasError, "Trap ingestion file missing: /etc/snmp/nmas-trap-ingest.py"):
            snmp.verify_trap_ingestion([LINUX])

    def test_verify_cpu_threshold_alerting_returns_alert_and_recovery_events(self):
        events = [{"transition": "alert", "timestamp_ns": 1}, {"transition": "recovery", "timestamp_ns": 2}]
        with mock.patch.object(snmp, "poll", return_value={"a": 10, "b": 30}), mock.patch.object(snmp, "evaluate_cpu_threshold", side_effect=events) as evaluate, \
                mock.patch.object(snmp, "cpu_alert_confirm_stored", return_value=True), contextlib.redirect_stdout(io.StringIO()):
            found = snmp.verify_cpu_threshold_alerting([CEOS])
        self.assertEqual((found["real_cpu"], found["alert_event"], found["recovery_event"]), (20.0, events[0], events[1]))
        alert_policy, recovery_policy = (c.kwargs["policy"] for c in evaluate.call_args_list)
        self.assertEqual((alert_policy["warning_pct"], recovery_policy["warning_pct"], {c.kwargs["verification"] for c in evaluate.call_args_list}), (19.0, 30.0, {True}))

    def test_verify_cpu_threshold_alerting_refuses_missing_or_unstored_events(self):
        for label, events, stored, message in (("no alert", [None], [True], "expected a deterministic ALERT"),
                                               ("alert unstored", [{"transition": "alert", "timestamp_ns": 1}], [False], "ALERT event not found"),
                                               ("no recovery", [{"transition": "alert", "timestamp_ns": 1}, {"transition": "alert", "timestamp_ns": 2}], [True], "expected a deterministic RECOVERY"),
                                               ("recovery unstored", [{"transition": "alert", "timestamp_ns": 1}, {"transition": "recovery", "timestamp_ns": 2}], [True, False], "RECOVERY event not found")):
            with self.subTest(case=f"refused {label}"), mock.patch.object(snmp, "poll", return_value={"a": 50}), \
                    mock.patch.object(snmp, "evaluate_cpu_threshold", side_effect=events), mock.patch.object(snmp, "cpu_alert_confirm_stored", side_effect=stored), \
                    self.assertRaisesRegex(NmasError, message):
                snmp.verify_cpu_threshold_alerting([CEOS])

    def test_ensure_snmp_infrastructure_runs_every_stage_in_order(self):
        calls = []
        names = ("verify_nmas", "devices", "credentials", "configure_device", "ensure_receiver", "verify_snmp", "verify_trap_ingestion", "verify_cpu_threshold_alerting")
        patches = [mock.patch.object(snmp, n, side_effect=lambda *a, n=n, **k: calls.append(n) or ([CEOS, LINUX] if n == "devices" else None)) for n in names]
        with contextlib.ExitStack() as stack:
            for p in patches:
                stack.enter_context(p)
            self.assertIsNone(snmp.ensure_snmp_infrastructure(verbose=True))
        self.assertEqual(calls, ["verify_nmas", "devices", "credentials", "configure_device", "configure_device", "ensure_receiver", "verify_snmp",
                                 "verify_trap_ingestion", "verify_cpu_threshold_alerting", "verify_nmas"])

    def test_ensure_snmp_infrastructure_never_configures_after_a_failed_nmas_check(self):
        with mock.patch.object(snmp, "verify_nmas", side_effect=NmasError("NMAS unhealthy")), mock.patch.object(snmp, "devices") as devices, \
                mock.patch.object(snmp, "configure_device") as configure, self.assertRaisesRegex(NmasError, "NMAS unhealthy"):
            snmp.ensure_snmp_infrastructure()
        self.assertEqual((devices.call_count, configure.call_count), (0, 0))


if __name__ == "__main__":
    unittest.main()
