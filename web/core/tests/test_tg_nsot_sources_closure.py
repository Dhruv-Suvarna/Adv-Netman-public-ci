"""Lab 7 closure -- the remaining NSOT source readers: the AUTO-address prefix lookup, the allowlisted Git file reader
and the explicit live running-config fetch, each called directly.

NetBox, Netmiko and the trusted-target resolver are replaced, so nothing connects to NetBox or a device; the Git
reader reads a real repository template read-only.  POSITIVE: family-filtered sorted prefixes, the exact allowlisted
file text (truncated at the cap), and a redacted running configuration fetched with one read-only command.
NEGATIVE: a non-AUTO address, an unavailable or malformed NetBox answer, a non-allowlisted or escaping path, an
unknown or non-cEOS target, rejected credentials, a timeout and any other error are each refused with a fixed message
that leaks no connection detail -- and no configuration command is ever sent.
"""

from __future__ import annotations

from unittest import mock

from django.test import SimpleTestCase
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

from core.services import device_builder_ipam_service as ipam
from core.services import interface_intent_service, nsot_git, nsot_live
from modules import netbox_ipam

SECRET_HOST = "192.0.2.77 password fake-Live-value-91"


class PrefixLookupTests(SimpleTestCase):
    def lookup(self, family="IPV4", source="AUTO", prefixes=("10.0.0.0/8", "2001:db8::/32", "10.0.0.0/24", "192.0.2.0/24")):
        with mock.patch.object(interface_intent_service, "get_address", return_value={"source": source, "family": family}), \
                mock.patch.object(netbox_ipam, "list_all_prefix_cidrs", return_value=list(prefixes)) as listing:
            return ipam.list_prefixes_for_address(revision=object(), interface_id="if-1", address_id="a-1"), listing

    def test_list_prefixes_for_address_returns_sorted_prefixes_of_the_address_family(self):
        self.assertEqual(self.lookup()[0], ["10.0.0.0/8", "10.0.0.0/24", "192.0.2.0/24"])
        self.assertEqual(self.lookup(family="IPV6")[0], ["2001:db8::/32"])

    def test_list_prefixes_for_address_refuses_manual_addresses_and_unavailable_or_malformed_netbox_data(self):
        with self.assertRaisesRegex(interface_intent_service.CollectionMutationError, "only for an AUTO address object"):
            self.lookup(source="MANUAL")
        for name, effect in (("netbox error", netbox_ipam.NetboxError(SECRET_HOST)), ("host bits", None)):
            with self.subTest(case=f"refused {name}"), mock.patch.object(interface_intent_service, "get_address", return_value={"source": "AUTO", "family": "IPV4"}), \
                    mock.patch.object(netbox_ipam, "list_all_prefix_cidrs", side_effect=effect, return_value=["10.0.0.1/24"]), \
                    self.assertRaises(ipam.IpamLookupError) as raised:
                ipam.list_prefixes_for_address(revision=object(), interface_id="if-1", address_id="a-1")
            self.assertEqual(str(raised.exception), "NetBox prefix data is currently unavailable.")


class CataloguedFileTests(SimpleTestCase):
    PATH = "templates/R1.cfg.j2"

    def read(self, path, allowlist=(PATH,), cap=None):
        catalogue = {"status": "available", "data": [{"path": p} for p in allowlist]}
        with mock.patch.object(nsot_git, "list_catalogued_files", return_value=catalogue), \
                mock.patch.object(nsot_git, "MAX_FILE_BYTES", cap or nsot_git.MAX_FILE_BYTES):
            return nsot_git.read_catalogued_file(path)

    def test_read_catalogued_file_returns_the_exact_allowlisted_text(self):
        expected = (nsot_git.REPO_ROOT / self.PATH).read_bytes().decode()
        found = self.read(self.PATH)
        self.assertEqual((found["status"], found["source"], found["path"], found["content"], found["truncated"]),
                         ("available", "GIT", self.PATH, expected, False))
        capped = self.read(self.PATH, cap=16)
        self.assertEqual((capped["content"], capped["truncated"]), (expected[:16], True))

    def test_read_catalogued_file_refuses_unlisted_escaping_or_missing_paths(self):
        refused = {"status": "unavailable", "message": "File is not in the allowlisted catalogue.", "source": "GIT"}
        for name, path, allowlist in (("unlisted", "manage.py", (self.PATH,)), ("escaping", "../../etc/hostname", ("../../etc/hostname",)),
                                      ("missing", "templates/NOPE.cfg.j2", ("templates/NOPE.cfg.j2",))):
            with self.subTest(case=f"refused {name}"):
                self.assertEqual(self.read(path, allowlist), refused)


class FakeConnection:
    def __init__(self, config, enabled=False):
        self.config, self.enabled, self.calls = config, enabled, []

    def check_enable_mode(self):
        return self.enabled

    def enable(self):
        self.calls.append("enable")

    def send_command(self, command, read_timeout=None):
        self.calls.append(command)
        return self.config

    def disconnect(self):
        self.calls.append("disconnect")

    def __getattr__(self, item):
        raise AssertionError(f"unexpected device call {item}")


CANDIDATES = ({"username": "old", "password": "fake-Old-value-1", "ssh_auth": {}},
              {"username": "nmas-automation", "password": "fake-New-value-2", "ssh_auth": {}})
TARGET = {"address": "192.0.2.10", "platform": "ceos", "username": "old", "password": "fake-Old-value-1", "ssh_auth": {},  # get_live_target's shape
          "auth_candidates": CANDIDATES}


class LiveFetchTests(SimpleTestCase):
    def fetch(self, target=TARGET, connect=None):
        with mock.patch.object(nsot_live, "get_live_target", return_value=target), \
                mock.patch("netmiko.ConnectHandler", side_effect=connect) as handler:
            return nsot_live.fetch_running_config("R1"), handler

    def test_fetch_running_config_returns_the_redacted_configuration_after_a_rejected_candidate(self):
        connection = FakeConnection("hostname R1\nusername admin secret sha512 $6$fakeHASHvalue\n")
        found, handler = self.fetch(connect=[NetmikoAuthenticationException("old"), connection])
        self.assertEqual((found["status"], found["source"], found["command"]), ("available", "LIVE", "show running-config"))
        self.assertEqual(found["data"], nsot_live.redact_config(connection.config))
        self.assertNotIn("fakeHASHvalue", found["data"])
        self.assertEqual(connection.calls, ["enable", "show running-config", "disconnect"])
        self.assertEqual([c.kwargs["username"] for c in handler.call_args_list], ["old", "nmas-automation"])
        self.assertEqual({c.kwargs["device_type"] for c in handler.call_args_list}, {"arista_eos"})

    def test_fetch_running_config_refuses_unknown_and_non_ceos_targets_without_connecting(self):
        for name, target, expected in (("unknown", None, {"status": "unavailable", "source": "LIVE", "data": None,
                                                         "message": "'R1' has no known read-only management address."}),
                                       ("linux", {**TARGET, "platform": "linux"}, {"status": "not_supported", "source": "LIVE", "data": None,
                                                                                  "message": "Live read-only retrieval currently supports cEOS devices only."})):
            with self.subTest(case=f"refused {name}"):
                found, handler = self.fetch(target=target)
                self.assertEqual(found, expected)
                handler.assert_not_called()

    def test_fetch_running_config_failures_name_no_host_or_password(self):
        for name, effect, message in (("auth", [NetmikoAuthenticationException(SECRET_HOST)] * 2, "LIVE UNAVAILABLE: authentication failed."),
                                      ("timeout", NetmikoTimeoutException(SECRET_HOST), "LIVE UNAVAILABLE: device did not respond within the timeout."),
                                      ("other", OSError(SECRET_HOST), "LIVE UNAVAILABLE: OSError.")):
            with self.subTest(case=f"refused {name}"):
                found, _handler = self.fetch(connect=effect)
                self.assertEqual(found, {"status": "unavailable", "source": "LIVE", "message": message, "data": None})
