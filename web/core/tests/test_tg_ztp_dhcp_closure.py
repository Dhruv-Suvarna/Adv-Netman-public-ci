"""Lab 7 closure -- the V2 Phase 3 DHCP provider contract (base helpers, ISC, Kea, the provider registry), called directly.

``test_ztp_dhcp`` proves the providers through ``policy.validate_policy`` / ``apply_policy`` / ``rollback_policy``; this module
calls each provider operation and helper itself.  POSITIVE -- exact serializations, atomic writes, bounded command results,
validated / applied / rolled-back / read-back states.  NEGATIVE -- unknown providers, malformed leases and out-of-subnet or
unrenderable reservations are refused, a failing validator or a missing validator never validates, a missing directory or
binary fails closed, and Kea's unimplemented operations refuse with DHCP_PROVIDER_UNSUPPORTED.

Every write goes to a temporary isolated provider root (``ZtpTestMixin``); validate / status commands are fake runners.
"""
from __future__ import annotations

import csv
import io
import json
import os
from types import SimpleNamespace

from django.test import SimpleTestCase, override_settings

from core.services.test_governance.cases import POSITIVE, case
from core.services.ztp import dhcp
from core.services.ztp.dhcp import base as dhcp_base
from core.services.ztp.dhcp.isc import IscDhcpProvider
from core.services.ztp.dhcp.kea import KeaDhcp4Provider
from core.tests.helpers import ztp as Z
from core.tests.test_ztp_dhcp import POLICY, RES, SupervisorRunner

BASE = "web/core/services/ztp/dhcp/base.py"


def kea_memfile(*rows) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["address", "hwaddr", "client_id", "valid_lifetime", "expire", "subnet_id", "fqdn_fwd", "fqdn_rev", "hostname", "state",
                     "user_context"])
    for row in rows:
        writer.writerow(row)
    return buffer.getvalue()


class BaseHelperTests(Z.ZtpTestMixin, SimpleTestCase):
    def test_bootstrap_policy_as_dict_lists_every_reservation(self):
        data = POLICY.as_dict()
        self.assertEqual((data["network"], data["subnet"], data["lease_seconds"]), ("ztp-test", "10.254.30.0/24", 600))
        self.assertEqual(data["reservations"][0]["circuit_id"], "Ethernet7")
        self.assertEqual(json.loads(json.dumps(data))["reservations"][0]["options"], [list(RES.options[0])])   # plain JSON values only

    def test_dhcp_provider_exception_carries_its_code_and_detail(self):
        error = dhcp.ProviderError("DHCP_PROVIDER_ERROR", "validator failed")
        self.assertEqual((error.code, error.detail, str(error)), ("DHCP_PROVIDER_ERROR", "validator failed", "DHCP_PROVIDER_ERROR"))

    def test_provider_error_detail_beyond_the_bound_is_truncated(self):
        self.assertEqual(len(dhcp.ProviderError("X", "d" * 5000).detail), 2000)

    def test_check_value_returns_a_safe_value_unchanged(self):
        self.assertEqual(dhcp_base.check_value("Arista;cEOSLab"), "Arista;cEOSLab")
        self.assertEqual(dhcp_base.check_value("http://10.254.31.2:8080/ztp/v1/ART-a/startup-config"),
                         "http://10.254.31.2:8080/ztp/v1/ART-a/startup-config")

    def test_provider_roots_are_the_configured_directories(self):
        self.assertEqual(dhcp_base.provider_roots(), [self.root.resolve()])
        with override_settings(NMAS_ZTP_PROVIDER_ROOTS=[str(self.root), "", "  "]):
            self.assertEqual(dhcp_base.provider_roots(), [self.root.resolve()])

    def test_safe_root_returns_a_directory_under_the_provider_roots(self):
        self.assertEqual(dhcp_base.safe_root(str(self.root / "dhcp")), self.root / "dhcp")
        self.assertEqual(dhcp_base.safe_root(str(self.root / "dhcp" / "not-created-yet")), self.root / "dhcp" / "not-created-yet")

    def test_atomic_write_replaces_the_file_with_mode_0644(self):
        target = self.root / "dhcp" / "dhcpd.conf"
        dhcp_base.atomic_write(target, "first\n")
        dhcp_base.atomic_write(target, "second\n")
        self.assertEqual(target.read_text(), "second\n")
        self.assertEqual(os.stat(target).st_mode & 0o777, 0o644)
        self.assertEqual(sorted(p.name for p in target.parent.iterdir()), ["dhcpd.conf"])     # no temporary file is left behind

    def test_atomic_write_into_a_missing_directory_raises_and_writes_nothing(self):
        with self.assertRaises(FileNotFoundError):
            dhcp_base.atomic_write(self.root / "absent" / "dhcpd.conf", "x")
        self.assertFalse((self.root / "absent").exists())

    def test_run_command_returns_the_exit_code_and_output(self):
        self.assertEqual(dhcp_base.run_command(["sh", "-c", "echo out; echo err >&2; exit 3"]), (3, "out\nerr\n"))

    def test_run_command_never_uses_a_shell_and_fails_closed(self):
        self.assertEqual(dhcp_base.run_command(["echo", "$(id)"]), (0, "$(id)\n"))     # an argv, never a shell
        self.assertEqual(dhcp_base.run_command(["/nonexistent/nmas-validator"]), (127, "FileNotFoundError"))
        self.assertEqual(dhcp_base.run_command(["sleep", "5"], timeout=0.2), (127, "TimeoutExpired"))

    @case("ZTP_DHCP_CONTRACT_ROLLBACK_DEFAULT_REFUSES", target=BASE + "::DhcpProvider.rollback", polarity=POSITIVE,
          condition="recovery is requested from a provider that does not implement it (Kea: configuration generation only)",
          expected="the contract default refuses with DHCP_PROVIDER_UNSUPPORTED and writes nothing in the provider root",
          requirement="V2 Phase 3: only an operational provider may claim recovery")
    def test_contract_default_rollback_is_the_documented_unsupported_result(self):
        provider = KeaDhcp4Provider(str(self.root / "dhcp"))
        with self.assertRaises(dhcp.ProviderError) as caught:
            provider.rollback()
        self.assertEqual(caught.exception.code, "DHCP_PROVIDER_UNSUPPORTED")
        self.assertEqual(list((self.root / "dhcp").iterdir()), [])

    @case("ZTP_DHCP_CONTRACT_READ_BACK_DEFAULT_REFUSES", target=BASE + "::DhcpProvider.read_back", polarity=POSITIVE,
          condition="the running state is read back from a provider that does not implement read-back (Kea)",
          expected="the contract default refuses with DHCP_PROVIDER_UNSUPPORTED (never an invented 'running' state)",
          requirement="V2 Phase 3: APPLIED requires a provider that can read the applied state back")
    def test_contract_default_read_back_is_the_documented_unsupported_result(self):
        with self.assertRaises(dhcp.ProviderError) as caught:
            KeaDhcp4Provider(str(self.root / "dhcp")).read_back()
        self.assertEqual(caught.exception.code, "DHCP_PROVIDER_UNSUPPORTED")


class RegistryTests(Z.ZtpTestMixin, SimpleTestCase):
    def test_for_network_builds_the_provider_with_the_configured_commands(self):
        provider = dhcp.for_network(SimpleNamespace(provider="ISC_DHCP", config_root=str(self.root / "dhcp")))
        self.assertIsInstance(provider, IscDhcpProvider)
        self.assertEqual((provider.validate_command, provider.status_command), (Z.VALIDATE, Z.STATUS))

    def test_for_network_of_an_unknown_provider_is_refused(self):
        with self.assertRaises(dhcp.ProviderError) as caught:
            dhcp.for_network(SimpleNamespace(provider="WINDOWS_DHCP", config_root=str(self.root / "dhcp")))
        self.assertEqual(caught.exception.code, "DHCP_PROVIDER_UNSUPPORTED")


class IscProviderTests(Z.ZtpTestMixin, SimpleTestCase):
    def provider(self, *, settle=2.0, **kwargs) -> IscDhcpProvider:
        """``settle``: the read-back window -- the fake supervisor consumes the restart marker on the first status poll, so a
        positive read-back is seen on the second poll (one second later), as with the fixture's real supervisor."""
        kwargs.setdefault("runner", SupervisorRunner(self.root / "dhcp"))
        provider = IscDhcpProvider(str(self.root / "dhcp"), validate_command=Z.VALIDATE, status_command=Z.STATUS, **kwargs)
        provider.settle_seconds = settle
        return provider

    def test_isc_validate_runs_the_provider_parser_on_the_candidate(self):
        runner = SupervisorRunner(self.root / "dhcp")
        result = self.provider(runner=runner).validate("authoritative;\n")
        self.assertEqual((result["ok"], result["returncode"]), (True, 0))
        self.assertEqual(runner.calls, [["dhcpd", "-t", "-cf", str(self.root / "dhcp" / "dhcpd.conf.candidate")]])

    def test_isc_validate_with_a_failing_or_missing_validator_is_refused(self):
        self.assertFalse(self.provider(runner=SupervisorRunner(self.root / "dhcp", rc=1)).validate("bad;\n")["ok"])
        unconfigured = IscDhcpProvider(str(self.root / "dhcp"))
        self.assertFalse(unconfigured.validate("authoritative;\n")["ok"])

    def test_isc_apply_writes_reads_back_and_reports_applied(self):
        provider = self.provider()
        result = provider.apply(POLICY)
        self.assertEqual((result.ok, result.state, result.code), (True, "APPLIED", ""))
        self.assertEqual(result.read_back["classes"], ["nmas-ZTP-000001"])
        self.assertEqual(dhcp_base.sha256_text((self.root / "dhcp" / "dhcpd.conf").read_text()), result.config_sha256)

    def test_isc_rollback_restores_the_previous_configuration(self):
        provider = self.provider()
        first = provider.apply(POLICY)
        provider.apply(dhcp.BootstrapPolicy("ztp-test", "10.254.30.0/24", "10.254.30.1", "10.254.31.0/30"))
        result = provider.rollback()
        self.assertEqual((result.ok, result.state), (True, "ROLLED_BACK"))
        self.assertEqual(result.config_sha256, first.config_sha256)
        self.assertEqual((self.root / "dhcp" / "dhcpd.conf").read_text(), first.config_text)

    def test_isc_read_back_reports_the_deployed_file_and_service(self):
        provider = self.provider()
        provider.apply(POLICY)
        found = provider.read_back()
        self.assertEqual((found["present"], found["classes"], found["service"]["running"]), (True, ["nmas-ZTP-000001"], True))

    def test_isc_read_back_without_a_deployed_file_or_status_is_never_running(self):
        self.assertEqual(self.provider().read_back(), {"present": False})
        (self.root / "dhcp" / "dhcpd.conf").write_text("authoritative;\n")
        self.assertIsNone(IscDhcpProvider(str(self.root / "dhcp")).read_back()["service"]["running"])

    def test_isc_lease_parsing_of_garbage_or_unrelayed_blocks_yields_no_relay(self):
        self.assertEqual(IscDhcpProvider("/unused").parse_leases("not a lease file"), [])
        self.assertEqual(IscDhcpProvider("/unused").parse_leases(None), [])
        rows = IscDhcpProvider("/unused").parse_leases(Z.lease(relay="0.0.0.0"))
        self.assertEqual((rows[0]["relay_address"], rows[0]["circuit_id"]), ("", "Ethernet7"))


class KeaProviderTests(Z.ZtpTestMixin, SimpleTestCase):
    def test_kea_render_of_out_of_subnet_or_unrenderable_reservations_is_refused(self):
        outside = dhcp.Reservation("ZTP-000001", "NEW1", "10.9.9.9", "10.254.30.1", "Ethernet7")
        unknown = dhcp.Reservation("ZTP-000001", "NEW1", "10.254.30.10", "10.254.30.1", "Ethernet7", "", (("domain-name", "x"),))
        injected = dhcp.Reservation("ZTP-000001", "NEW1", "10.254.30.10", "10.254.30.1", "Ethernet7'; drop", "")
        for label, res in (("outside", outside), ("unknown option", unknown), ("injected circuit", injected)):
            with self.subTest(label), self.assertRaises(dhcp.ProviderError):
                KeaDhcp4Provider("/unused").render(dhcp.BootstrapPolicy("ztp-test", "10.254.30.0/24", "10.254.30.1", "10.254.31.0/30", (res,)))

    def test_kea_validate_runs_kea_on_the_candidate(self):
        runner = Z.FakeRunner(0, "Syntax check OK")
        provider = KeaDhcp4Provider(str(self.root / "dhcp"), validate_command=["kea-dhcp4", "-t", "{path}"], runner=runner)
        result = provider.validate(provider.render(POLICY))
        self.assertTrue(result["ok"])
        self.assertEqual(runner.calls, [["kea-dhcp4", "-t", str(self.root / "dhcp" / "kea-dhcp4.conf.candidate")]])

    def test_kea_validate_without_a_validator_or_with_a_failing_one_is_refused(self):
        self.assertFalse(KeaDhcp4Provider(str(self.root / "dhcp")).validate("{}")["ok"])
        failing = KeaDhcp4Provider(str(self.root / "dhcp"), validate_command=["kea-dhcp4", "-t", "{path}"], runner=Z.FakeRunner(1, "error"))
        self.assertFalse(failing.validate("{}")["ok"])

    def test_kea_memfile_rows_with_invalid_numbers_or_context_are_skipped_or_carry_no_circuit(self):
        text = kea_memfile(["10.254.30.11", "aa:bb:cc:dd:ee:ff", "", "not-a-number", "2000000000", "1", "0", "0", "", "0", ""],
                           ["10.254.30.12", "AA:BB:CC:DD:EE:01", "", "600", "2000000000", "1", "0", "0", "", "2", "{broken json"])
        rows = KeaDhcp4Provider("/unused").parse_leases(text)
        self.assertEqual([r["address"] for r in rows], ["10.254.30.12"])
        self.assertEqual((rows[0]["client_mac"], rows[0]["circuit_id"], rows[0]["binding_state"]), ("aa:bb:cc:dd:ee:01", "", "expired-reclaimed"))
        self.assertEqual(KeaDhcp4Provider("/unused").parse_leases(""), [])

    def test_kea_reservation_options_are_translated(self):
        config = json.loads(KeaDhcp4Provider("/unused").render(POLICY))
        self.assertEqual(config["Dhcp4"]["client-classes"][0]["option-data"], [{"name": "boot-file-name", "data": RES.options[0][1]}])
