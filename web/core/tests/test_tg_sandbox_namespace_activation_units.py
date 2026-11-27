"""Direct tests for the fail-closed worker-namespace controller (deploy/sandbox/namespace_activation.py).

The controller's real integration suite (deploy/sandbox/test_namespace_activation.py) needs root and disposable kernel
namespaces, so it runs on the sandbox host only.  Here every host interaction goes through ``FakeHost``, an in-process
stand-in for ``ip`` / ``nft`` / ``sysctl`` that keeps namespace, veth, address, route and table state.  The
controller's own journalling, ownership checks and cleanup run unmodified against it.  Configurations come from the
suite's ``config_text`` (test mode); nothing touches a real namespace, link, route or firewall.
"""

from __future__ import annotations

import importlib.util
import io
import json
import os
import re
import subprocess
import tempfile
from contextlib import ExitStack, redirect_stdout
from pathlib import Path
from unittest import mock

from django.test import SimpleTestCase

SANDBOX = Path(__file__).resolve().parents[3] / "deploy" / "sandbox"


def _load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, SANDBOX / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


na = _load("namespace_activation", "namespace_activation.py")
suite = _load("namespace_activation_suite", "test_namespace_activation.py")
REAL_PATH = Path
REAL_OPEN = os.open
HOST_NS = suite.HOST_NS


def completed(argv, stdout="", rc=0):
    return subprocess.CompletedProcess(argv, rc, stdout, "")


class FakeHost:
    """A host network namespace plus one worker namespace, driven only through the controller's argv."""

    def __init__(self, config, run_dir: Path):
        self.cfg, self.run = config, run_dir
        self.namespaces = {HOST_NS}
        self.lo_alias: dict[str, str] = {}
        self.host_alias, self.host_end, self.veth = "", None, False
        self.addresses = {"ns": set(), "host": set()}
        self.routes = {4: [], 6: []}
        self.ns_table, self.host_policy = False, None
        self.calls: list[list[str]] = []
        self.fail_on = ""
        self.sysctl_host = "1"
        self.egress = [f"{family['nat']}/24" if family and family["nat"] != "masquerade" else None
                       for family in (config["ipv4"], config["ipv6"])]
        self.egress = [a.replace("/24", "/64") if a and ":" in a else a for a in self.egress if a] or ["10.224.76.50/22"]

    # -- documents --------------------------------------------------------------------------------------------------
    def sets(self):
        cfg = self.cfg
        if cfg["kind"] == "diagnostic":
            out = []
            for version in (4, 6):
                elems = [{"concat": [a, p]} for a, p in cfg["targets"] if (":" in a) == (version == 6)]
                out.append({"set": {"name": f"targets{version}", "elem": elems}})
            return out
        return [{"set": {"name": "https4", "elem": [{"concat": [a, p]} for a, p in cfg["https_targets"]]}},
                {"set": {"name": "dns4", "elem": list(cfg["dns_servers"])}}]

    def ns_ruleset(self):
        if not self.ns_table:
            return {"nftables": []}
        chains = [{"chain": {"name": n, "policy": "drop"}} for n in ("input", "forward", "output")]
        return {"nftables": [{"table": {"family": "inet", "name": self.cfg["table"]}}, *chains, *self.sets()]}

    def host_table_doc(self):
        comment = re.search(r'comment "([^"]+)"', self.host_policy).group(1)
        chains = [{"chain": {"name": n, "hook": n}} for n in ("input", "output", "forward", "postrouting")]
        return {"nftables": [{"table": {"family": "inet", "name": self.cfg["host_table"], "comment": comment}}, *chains, *self.sets()]}

    @staticmethod
    def addr_doc(name, addresses):
        return {"ifname": name, "addr_info": [{"local": a.split("/")[0], "prefixlen": int(a.split("/")[1])} for a in sorted(addresses)]}

    # -- the command boundary ---------------------------------------------------------------------------------------
    def __call__(self, argv, *, capture=False, check=True, stdin=None):
        argv = list(argv)
        self.calls.append(argv)
        if self.fail_on and self.fail_on in " ".join(argv):
            if check:
                raise subprocess.CalledProcessError(2, argv, "", "injected")
            return completed(argv, rc=2)
        result = self.dispatch(argv, stdin)
        if result is None:
            return completed(argv)
        if result.returncode and check:
            raise subprocess.CalledProcessError(result.returncode, argv)
        return result

    def dispatch(self, argv, stdin):  # pylint: disable=too-many-return-statements,too-many-branches  # one branch per emulated command
        cfg = self.cfg
        if argv[:3] == ["/usr/sbin/ip", "netns", "list"]:
            return completed(argv, "".join(f"{n} (id: 1)\n" for n in sorted(self.namespaces)))
        if argv[:3] == ["/usr/sbin/ip", "netns", "add"]:
            self.namespaces.add(argv[3])
            (self.run / argv[3]).write_text("")
            return None
        if argv[:3] == ["/usr/sbin/ip", "netns", "delete"]:
            self.namespaces.discard(argv[3])
            (self.run / argv[3]).unlink()
            self.veth, self.host_end, self.ns_table = False, None, False      # deleting a namespace removes its veth pair,
            self.addresses = {"ns": set(), "host": set()}                    # addresses, routes and nft ruleset
            self.routes = {4: [], 6: []}
            return None
        if argv[:3] == ["/usr/sbin/ip", "netns", "exec"]:
            return self.inside("host" if argv[3] == HOST_NS else "ns", argv[4:], stdin)
        if argv[0] != "/usr/sbin/ip":
            return completed(argv)                      # nft -c syntax checks
        where, flags, rest, tokens = None, set(), [], argv[1:]
        while tokens:
            token = tokens.pop(0)
            if token == "-n":
                where = tokens.pop(0)
            elif token in ("-j", "-d", "-4", "-6"):
                flags.add(token)
            else:
                rest = [token, *tokens]
                break
        side = "host" if where == HOST_NS else "ns"
        version = 6 if "-6" in flags else 4
        if rest[:2] == ["link", "show"]:
            if side == "ns" and rest[2:] == ["dev", "lo"]:
                if where not in self.namespaces:
                    return completed(argv, rc=1)
                return completed(argv, json.dumps([{"ifname": "lo", "ifalias": self.lo_alias.get(where)}]))
            if side == "host":
                return completed(argv, json.dumps([self.host_end])) if self.host_end else completed(argv, rc=1)
            links = [{"ifname": "lo", "flags": ["UP"]}]
            if self.veth:
                links.append({"ifname": cfg["interface"], "flags": ["UP"], "linkinfo": {"info_kind": "veth"}})
            return completed(argv, json.dumps(links))
        if rest[:4] == ["link", "set", "lo", "alias"]:
            self.lo_alias[where] = rest[4]
        elif rest[:2] == ["link", "add"]:
            self.veth = True
        elif rest[:3] == ["link", "set", "dev"] and rest[4:5] == ["alias"]:
            self.host_alias = rest[5]
        elif rest[:3] == ["link", "set", "dev"] and rest[4:5] == ["netns"]:
            self.host_end = {"ifname": cfg["host_interface"], "ifalias": self.host_alias, "linkinfo": {"info_kind": "veth"}, "ifindex": 7}
        elif rest[:2] == ["link", "delete"]:
            self.host_end, self.veth = None, False
        elif rest[:2] == ["address", "add"]:
            self.addresses[side].add(rest[2])
        elif rest[:2] == ["address", "show"]:
            if rest[2:3] == ["dev"] and rest[3] == cfg["egress"]:
                return completed(argv, json.dumps([self.addr_doc(cfg["egress"], self.egress)]))
            if rest[2:3] == ["dev"]:
                return completed(argv, json.dumps([self.addr_doc(rest[3], self.addresses[side])]))
            return completed(argv, json.dumps([self.addr_doc(cfg["egress"], self.egress)]))
        elif rest[:2] == ["route", "add"]:
            self.routes[version].append({"dst": rest[2], "gateway": rest[4], "dev": rest[6]})
        elif rest[:2] == ["route", "show"]:
            return completed(argv, json.dumps([] if "table" in rest else self.routes[version]))
        return None

    def inside(self, side, argv, stdin):
        if argv[:2] == ["/usr/sbin/sysctl", "-n"]:
            return completed(argv, (self.sysctl_host if side == "host" else "0") + "\n")
        if argv[0] != "/usr/sbin/nft":
            return None
        if argv[1:] == ["-f", self.cfg["nft_policy"]]:
            self.ns_table = True
        elif argv[1:] == ["-f", "-"]:
            self.host_policy = stdin
        elif argv[1:3] == ["-j", "list"] and argv[3] == "ruleset":
            return completed(argv, json.dumps(self.ns_ruleset()))
        elif argv[1:3] == ["-j", "list"] and argv[3] == "table":
            return completed(argv, json.dumps(self.host_table_doc())) if self.host_policy else completed(argv, rc=1)
        elif argv[1:3] == ["-j", "list"] and argv[3] == "chains":
            return completed(argv, json.dumps({"nftables": []}))
        elif argv[1:2] == ["delete"]:
            self.host_policy = None
        return None


def trusted_regular(path, *, mode, label):        # the root-ownership half of secure_* is proven against real root files below
    del mode, label
    return Path(path).lstat()


def trusted_read(path, *, mode, label):
    del mode, label
    return Path(path).lstat(), Path(path).read_bytes()


class Harness(SimpleTestCase):
    """A disposable test root with the suite's two reviewed configurations and a fake host behind ``command``."""

    kind = "diagnostic"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = REAL_PATH(self.tmp.name)
        self.diag_env, self.research_env = suite.make_files(self.root)
        self.netns_etc = self.root / "etc-netns"
        (self.root / "state").mkdir(mode=0o700)
        self.run_dir = self.root / "run-netns"
        self.run_dir.mkdir()
        self.env = self.diag_env if self.kind == "diagnostic" else self.research_env
        self.config = na.normalized_config(self.env, self.kind, test_mode=True)
        self.state_path = self.root / "state" / f"{self.kind}.json"
        self.host = FakeHost(self.config, self.run_dir)
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(mock.patch.object(na, "command", self.host))
        stack.enter_context(mock.patch.object(na, "Path", self.path))

    def path(self, *parts):
        p = REAL_PATH(*parts)
        return self.run_dir if str(p) == "/run/netns" else p

    def variant(self, name, **changes):
        return suite.variant(self.root, self.env, name, **changes)

    def activated(self):
        return na.activate(self.config, self.state_path, self.netns_etc, fail_after=None)

    def state(self):
        return json.loads(self.state_path.read_text())


# ======================================================================================================== pure helpers
class PrimitiveTests(SimpleTestCase):
    def test_sha256_returns_the_hex_digest(self):
        self.assertEqual(na.sha256(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

    def test_sha256_of_different_bytes_differs(self):
        self.assertNotEqual(na.sha256(b"abc"), na.sha256(b"abd"))

    def test_sha256_refuses_text_that_is_not_bytes(self):
        with self.assertRaises(TypeError):
            na.sha256("abc")

    def test_atomic_json_creates_a_private_state_file(self):
        with tempfile.TemporaryDirectory() as d:
            path = REAL_PATH(d) / "state" / "x.json"
            na.atomic_json(path, {"a": 1})
            self.assertEqual((json.loads(path.read_text()), oct(path.stat().st_mode & 0o777)), ({"a": 1}, "0o600"))
            na.atomic_json(path, {"a": 2})
            self.assertEqual(json.loads(path.read_text()), {"a": 2})

    def test_atomic_json_refuses_an_unsafe_directory_or_target(self):
        with tempfile.TemporaryDirectory() as d:
            loose = REAL_PATH(d) / "loose"
            loose.mkdir(mode=0o755)
            loose.chmod(0o755)
            with self.subTest("a group-readable state directory is refused"), self.assertRaises(na.Refused):
                na.atomic_json(loose / "x.json", {})
            private = REAL_PATH(d) / "private"
            private.mkdir(mode=0o700)
            (private / "x.json").symlink_to("/etc/passwd")
            with self.subTest("a symlinked target is refused"), self.assertRaises(na.Refused):
                na.atomic_json(private / "x.json", {})

    def test_required_and_approval_return_attributable_values(self):
        self.assertEqual(na.required({"K": " v "}, "K"), "v")
        self.assertEqual(na.approval({"K": "CHG-NMAS-0001"}, "K"), "CHG-NMAS-0001")

    def test_required_and_approval_refuse_missing_or_unattributable_values(self):
        for label, call in (("a missing key", lambda: na.required({}, "K")), ("a blank key", lambda: na.required({"K": "  "}, "K")),
                            ("a short approval", lambda: na.approval({"K": "ok"}, "K")),
                            ("a spaced approval", lambda: na.approval({"K": "CHG NMAS 0001"}, "K"))):
            with self.subTest(f"{label} is refused"), self.assertRaises(na.Refused):
                call()

    def test_command_returns_the_completed_process(self):
        self.assertEqual(na.command(["true"]).returncode, 0)
        self.assertEqual(na.command(["printf", "x"], capture=True).stdout, "x")

    def test_command_raises_for_a_failing_checked_command(self):
        with self.assertRaises(subprocess.CalledProcessError):
            na.command(["false"])
        self.assertEqual(na.command(["false"], check=False).returncode, 1)

    def test_run_json_parses_command_output(self):
        self.assertEqual(na.run_json(["printf", "[1, 2]"]), [1, 2])
        self.assertEqual(na.run_json(["true"]), [])

    def test_run_json_raises_for_invalid_output(self):
        with self.assertRaises(json.JSONDecodeError):
            na.run_json(["printf", "not json"])

    def test_namespace_wrappers_build_the_exact_argv(self):
        cfg = {"host_namespace": "nmas-test-host", "namespace": "nmas-test-diag"}
        self.assertEqual(na.host_ip(cfg, "link", "show"), ["/usr/sbin/ip", "-n", "nmas-test-host", "link", "show"])
        self.assertEqual(na.host_exec(cfg, ["nft"]), ["/usr/sbin/ip", "netns", "exec", "nmas-test-host", "nft"])
        self.assertEqual(na.ns_exec(cfg, ["sysctl"]), ["/usr/sbin/ip", "netns", "exec", "nmas-test-diag", "sysctl"])

    def test_production_host_commands_never_enter_a_namespace(self):
        cfg = {"host_namespace": None, "namespace": "nmas-ts-diagnostic"}
        with self.subTest("host ip never names a namespace"):
            self.assertEqual(na.host_ip(cfg, "link"), ["/usr/sbin/ip", "link"])
        with self.subTest("host exec never wraps the command"):
            self.assertEqual(na.host_exec(cfg, ["nft"]), ["nft"])
        with self.subTest("namespace exec never runs outside the worker namespace"):
            self.assertEqual(na.ns_exec(cfg, ["nft"])[:4], ["/usr/sbin/ip", "netns", "exec", "nmas-ts-diagnostic"])

    def test_parse_extra_deny_returns_sorted_unique_networks(self):
        self.assertEqual(na.parse_extra_deny("93.184.217.0/24 10.0.0.0/8 93.184.217.0/24"), ["10.0.0.0/8", "93.184.217.0/24"])

    def test_parse_extra_deny_refuses_a_host_address_or_garbage(self):
        for item in ("93.184.217.9/24", "not-a-network"):
            with self.subTest(f"{item} is refused"), self.assertRaises(na.Refused):
                na.parse_extra_deny(item)

    def test_marker_and_nft_set_build_owned_text(self):
        cfg = {"activation_id": "TEST-ACTIVATION-0001", "config_digest": "a" * 64}
        self.assertEqual(na.marker(cfg), "nmas-owner:TEST-ACTIVATION-0001:" + "a" * 16)
        self.assertEqual(na.marker(cfg, "b" * 32), na.marker(cfg) + ":" + "b" * 32)
        self.assertEqual(na.nft_set("dns4", "ipv4_addr", ["1.1.1.1"], interval=True),
                         "  set dns4 { type ipv4_addr; flags interval; elements = { 1.1.1.1 } }\n")

    def test_marker_of_another_generation_or_an_empty_set_never_matches(self):
        cfg = {"activation_id": "TEST-ACTIVATION-0001", "config_digest": "a" * 64}
        with self.subTest("another generation never shares the marker"):
            self.assertNotEqual(na.marker(cfg, "b" * 32), na.marker(cfg, "c" * 32))
        with self.subTest("an empty set never carries an elements clause"):
            self.assertNotIn("elements", na.nft_set("dns4", "ipv4_addr", []))

    def test_nft_document_readers_return_comment_and_elements(self):
        objects = [{"table": {"comment": "nmas-owner:x"}}, {"set": {"name": "targets4", "elem": [{"concat": ["198.51.100.1", 22]}]}},
                   {"set": {"name": "dns4", "elem": ["93.184.216.53"]}}]
        self.assertEqual(na.table_comment(objects), "nmas-owner:x")
        self.assertEqual(na.set_elements(objects, "targets4"), {("198.51.100.1", 22)})
        self.assertEqual(na.address_set_elements(objects, "dns4"), {"93.184.216.53"})

    def test_nft_document_readers_without_the_object_are_empty(self):
        with self.subTest("no table has no comment"):
            self.assertIsNone(na.table_comment([{"chain": {}}]))
        with self.subTest("an absent set has no elements"):
            self.assertEqual(na.set_elements([], "targets4"), set())
        with self.subTest("an absent address set has no elements"):
            self.assertEqual(na.address_set_elements([{"set": {"name": "other"}}], "dns4"), set())

    def test_link_addresses_returns_prefixed_addresses(self):
        doc = json.dumps([{"addr_info": [{"local": "169.254.86.2", "prefixlen": 30}]}])
        self.assertEqual(na.link_addresses(["printf", doc]), {"169.254.86.2/30"})

    def test_link_addresses_of_an_unaddressed_link_is_empty(self):
        self.assertEqual(na.link_addresses(["printf", "[{}]"]), set())

    def test_failpoint_passes_other_steps(self):
        self.assertIsNone(na.failpoint("link", None))
        self.assertIsNone(na.failpoint("link", "netns"))

    def test_failpoint_raises_at_its_injected_step(self):
        with self.assertRaises(na.Refused):
            na.failpoint("link", "link")

    def test_ensure_test_paths_returns_production_paths_without_a_test_root(self):
        self.assertEqual(na.ensure_test_paths(None), (na.PRODUCTION_STATE, na.PRODUCTION_NETNS_ETC))

    def test_ensure_test_paths_refuses_an_unprivileged_or_foreign_test_root(self):
        with self.assertRaises(na.Refused):
            na.ensure_test_paths(REAL_PATH("/var/tmp/elsewhere"))


class RootOwnedFileTests(SimpleTestCase):
    """secure_* demand root ownership and an exact mode; real root-owned system files are the positive fixtures."""

    def test_secure_regular_and_read_accept_a_root_owned_file(self):
        info = na.secure_regular(REAL_PATH("/etc/passwd"), mode=0o644, label="passwd")
        opened, data = na.read_secure_regular(REAL_PATH("/etc/passwd"), mode=0o644, label="passwd")
        self.assertEqual((opened.st_ino, data[:5]), (info.st_ino, b"root:"))

    def test_secure_regular_and_read_refuse_wrong_mode_owner_or_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            mine = REAL_PATH(d) / "mine"
            mine.write_text("x")
            link = REAL_PATH(d) / "link"
            link.symlink_to("/etc/passwd")
            for label, path, mode in (("a wrong mode", REAL_PATH("/etc/passwd"), 0o600), ("a user-owned file", mine, 0o644),
                                      ("a symlink", link, 0o644), ("a missing file", REAL_PATH(d) / "nope", 0o644)):
                with self.subTest(f"{label} is refused"):
                    with self.assertRaises(na.Refused):
                        na.secure_regular(path, mode=mode, label=label)
                    with self.assertRaises(na.Refused):
                        na.read_secure_regular(path, mode=mode, label=label)

    def test_secure_directory_and_resolver_root_accept_a_root_owned_directory(self):
        self.assertEqual(na.secure_directory(REAL_PATH("/usr"), mode=0o755, label="usr").st_uid, 0)
        self.assertTrue(na.resolver_root_safe(REAL_PATH("/usr")))

    def test_secure_directory_and_resolver_root_refuse_user_owned_or_missing_directories(self):
        with tempfile.TemporaryDirectory() as d:
            for label, path in (("a user-owned directory", REAL_PATH(d)), ("a missing directory", REAL_PATH(d) / "nope")):
                with self.subTest(f"{label} is refused"):
                    self.assertFalse(na.resolver_root_safe(path))
                    with self.assertRaises(na.Refused):
                        na.secure_directory(path, mode=0o755, label=label)

    def test_verify_resolver_root_receipt_returns_a_fixture_marker_outside_production(self):
        self.assertEqual(na.verify_resolver_root_receipt(REAL_PATH("/tmp/nmas-namespace-test-x/etc-netns"), "CHG-1"), {"test_fixture": True})

    def test_verify_resolver_root_receipt_refuses_an_unverifiable_production_root(self):
        with self.assertRaises(na.Refused):
            na.verify_resolver_root_receipt(na.PRODUCTION_NETNS_ETC, "CHG-NOT-THE-APPROVED-CHANGE")


# =================================================================================================== configuration
class ConfigurationTests(Harness):
    def test_parse_config_returns_reviewed_keys(self):
        values = na.parse_config(self.env, test_mode=True)
        self.assertEqual((values["NAMESPACE"], values["IPV4_MODE"]), ("diagnostic", "enabled"))

    def test_parse_config_refuses_unknown_duplicate_or_writable_configuration(self):
        unknown = self.variant("unknown.env", SHELL="/bin/sh")
        duplicate = self.root / "duplicate.env"
        suite.write(duplicate, self.env.read_text() + "NAMESPACE=diagnostic\n")
        writable = self.variant("writable.env")
        writable.chmod(0o666)
        for label, path in (("an unknown key", unknown), ("a duplicate key", duplicate), ("a world-writable file", writable),
                            ("a missing file", self.root / "nope.env")):
            with self.subTest(f"{label} is refused"), self.assertRaises(na.Refused):
                na.parse_config(path, test_mode=True)
        with self.subTest("production mode refuses a non-root configuration"), self.assertRaises(na.Refused):
            na.parse_config(self.env, test_mode=False)

    def test_validate_family_returns_the_point_to_point_link(self):
        family = na.validate_family(na.parse_config(self.env, test_mode=True), 4, "diagnostic")
        self.assertEqual((family["source"], family["gateway"], family["nat"]), ("169.254.86.2/30", "169.254.86.1", "198.51.100.100"))
        self.assertIsNone(na.validate_family({"IPV6_MODE": "disabled"}, 6, "research"))

    def test_validate_family_refuses_routable_wide_or_masqueraded_diagnostic_links(self):
        base = na.parse_config(self.env, test_mode=True)
        cases = (("an undeclared mode", {"IPV4_MODE": "auto"}), ("a routable link", {"IPV4_LINK_CIDR": "8.8.8.2/30", "IPV4_GATEWAY": "8.8.8.1"}),
                 ("a wide link", {"IPV4_LINK_CIDR": "169.254.86.2/24"}), ("a gateway outside the link", {"IPV4_GATEWAY": "169.254.99.1"}),
                 ("a masqueraded diagnostic source", {"IPV4_NAT": "masquerade"}), ("a disabled family with values", {"IPV4_MODE": "disabled"}),
                 ("a nat source inside the link", {"IPV4_NAT": "169.254.86.1"}))
        for label, over in cases:
            with self.subTest(f"{label} is refused"), self.assertRaises(na.Refused):
                na.validate_family({**base, **over}, 4, "diagnostic")

    def test_parse_targets_returns_sorted_exact_targets(self):
        families = {4: self.config["ipv4"], 6: self.config["ipv6"]}
        self.assertEqual(na.parse_targets("tcp:[fd00:51::1]:2222 tcp:198.51.100.1:2222", families),
                         [["198.51.100.1", 2222], ["fd00:51::1", 2222]])

    def test_parse_targets_refuses_wildcards_link_collisions_or_disabled_families(self):
        families = {4: self.config["ipv4"], 6: None}
        for item in ("udp:198.51.100.1:22", "tcp:0.0.0.0:22", "tcp:198.51.100.1:0", "tcp:169.254.86.1:22", "tcp:[fd00:51::1]:22",
                     "tcp:198.51.100.100:22", ""):
            with self.subTest(f"{item or 'no target'} is refused"), self.assertRaises(na.Refused):
                na.parse_targets(item, families)

    def test_normalized_config_returns_digested_test_configuration(self):
        cfg = na.normalized_config(self.env, "diagnostic", test_mode=True)
        self.assertEqual((cfg["namespace"], cfg["host_namespace"], cfg["interface"]), (suite.DIAG_NS, HOST_NS, "nmas-test0"))
        self.assertEqual(len(cfg["config_digest"]), 64)
        self.assertEqual(sorted(cfg["legacy_config_digests"]), sorted(na.LEGACY_SCHEMAS))

    def test_normalized_config_refuses_mismatched_kind_policy_or_dns(self):
        cases = (("another kind", self.env, "research"), ("a tampered policy digest", self.variant("digest.env", NFT_POLICY_SHA256="0" * 64), "diagnostic"),
                 ("an unapproved authorization", self.variant("auth.env", AUTHORIZATION_APPROVED="no"), "diagnostic"),
                 ("diagnostic dns", self.variant("dns.env", DNS_MODE="enabled", DNS_SERVERS="93.184.216.53", DNS_TRANSPORTS="udp,tcp"), "diagnostic"),
                 ("a research key", self.variant("research-key.env", HTTPS_TARGETS="tcp:93.184.216.34:443"), "diagnostic"),
                 ("the owned veth as egress", self.variant("egress.env", EGRESS_INTERFACE="nmas-test0"), "diagnostic"))
        for label, path, kind in cases:
            with self.subTest(f"{label} is refused"), self.assertRaises(na.Refused):
                na.normalized_config(path, kind, test_mode=True)


# ======================================================================================================== state & receipts
class StateTests(Harness):
    def test_new_state_read_state_and_persist_roundtrip(self):
        state = na.new_state(self.config, "policy", generation="a" * 32, status="activating")
        na.persist(self.state_path, state)
        na.persist(self.state_path, state)
        self.assertEqual((na.read_state(self.state_path)["sequence"], na.read_state(self.state_path)["generation"]), (2, "a" * 32))
        self.assertIsNone(na.read_state(self.root / "state" / "absent.json"))

    def test_new_state_read_state_and_persist_refuse_untrusted_state(self):
        with self.subTest("an invalid generation is refused"), self.assertRaises(na.Refused):
            na.new_state(self.config, "policy", generation="short", status="activating")
        foreign = self.root / "state" / "foreign.json"
        foreign.write_text(json.dumps({"schema": "someone-else/1"}))
        foreign.chmod(0o600)
        with self.subTest("a foreign schema is refused"), self.assertRaises(na.Refused):
            na.read_state(foreign)
        foreign.chmod(0o644)
        with self.subTest("a readable state file is refused"), self.assertRaises(na.Refused):
            na.read_state(foreign)
        loose = self.root / "loose"
        loose.mkdir(mode=0o755)
        loose.chmod(0o755)
        with self.subTest("persisting into an open directory is refused"), self.assertRaises(na.Refused):
            na.persist(loose / "x.json", {"sequence": 0})

    def test_assert_state_owner_accepts_its_own_or_legacy_receipt(self):
        state = na.new_state(self.config, "p", generation="a" * 32, status="deactivate")
        self.assertIsNone(na.assert_state_owner(state, self.config))
        legacy_schema = sorted(na.LEGACY_SCHEMAS)[0]
        legacy = {**state, "schema": legacy_schema, "config_digest": self.config["legacy_config_digests"][legacy_schema]}
        self.assertIsNone(na.assert_state_owner(legacy, self.config))

    def test_assert_state_owner_refuses_another_activation(self):
        state = na.new_state(self.config, "p", generation="a" * 32, status="deactivate")
        for label, over in (("another activation", {"activation_id": "OTHER-ACTIVATION-1"}), ("another digest", {"config_digest": "0" * 64})):
            with self.subTest(f"{label} is refused"), self.assertRaises(na.Refused):
                na.assert_state_owner({**state, **over}, self.config)

    def test_archive_receipt_retains_the_exact_terminal_receipt_once(self):
        state = na.new_state(self.config, "p", generation="a" * 32, status="deactivate")
        na.persist(self.state_path, state)
        first = na.archive_receipt(self.state_path, na.read_state(self.state_path))
        again = na.archive_receipt(self.state_path, na.read_state(self.state_path))
        self.assertEqual(first, again)
        self.assertEqual(REAL_PATH(first["path"]).read_bytes(), self.state_path.read_bytes())

    def test_archive_receipt_refuses_a_receipt_that_differs_from_verified_state(self):
        state = na.new_state(self.config, "p", generation="a" * 32, status="deactivate")
        na.persist(self.state_path, state)
        with self.assertRaises(na.Refused):
            na.archive_receipt(self.state_path, {**state, "status": "active"})

    def test_run_step_journals_and_runs_each_command(self):
        state = na.new_state(self.config, "p", generation="a" * 32, status="activating")
        na.run_step(self.state_path, state, "loopback", [["/usr/sbin/ip", "-n", suite.DIAG_NS, "link", "set", "lo", "up"]], fail_after=None)
        self.assertEqual((state["completed_steps"], state["pending_step"]), (["loopback"], ""))
        self.assertEqual(self.host.calls[-1][-2:], ["lo", "up"])

    def test_run_step_leaves_the_step_pending_when_its_command_fails(self):
        state = na.new_state(self.config, "p", generation="a" * 32, status="activating")
        self.host.fail_on = "link set lo up"
        with self.assertRaises(subprocess.CalledProcessError):
            na.run_step(self.state_path, state, "loopback", [["/usr/sbin/ip", "-n", suite.DIAG_NS, "link", "set", "lo", "up"]], fail_after=None)
        self.assertEqual(self.state()["pending_step"], "loopback")

    def test_resolver_paths_returns_the_namespace_resolver(self):
        self.assertEqual(na.resolver_paths(self.config, self.netns_etc),
                         (self.netns_etc / suite.DIAG_NS, self.netns_etc / suite.DIAG_NS / "resolv.conf"))

    def test_resolver_paths_of_two_namespaces_never_collide(self):
        other = {**self.config, "namespace": "nmas-test-other"}
        self.assertNotEqual(na.resolver_paths(self.config, self.netns_etc)[1], na.resolver_paths(other, self.netns_etc)[1])

    def test_resolver_content_returns_one_nameserver_line_each(self):
        self.assertEqual(na.resolver_content({"dns_servers": ["93.184.216.53", "2001:db8::53"]}),
                         b"nameserver 93.184.216.53\nnameserver 2001:db8::53\n")

    def test_resolver_content_without_resolvers_is_empty(self):
        self.assertEqual(na.resolver_content({"dns_servers": []}), b"")


# =========================================================================================================== host policy
class HostPolicyTests(Harness):
    def test_host_policy_and_route_commands_return_the_exact_diagnostic_policy(self):
        policy = na.host_policy(self.config, "a" * 32)
        self.assertIn(f'comment "{na.marker(self.config, "a" * 32)}"', policy)
        self.assertIn("198.51.100.1 . 2222", policy)
        self.assertIn("snat ip to 198.51.100.100", policy)
        self.assertEqual(na.route_commands(self.config, 4)[0][-5:], ["198.51.100.1", "via", "169.254.86.1", "dev", "nmas-test0"])

    def test_route_commands_never_add_a_default_route_for_diagnostics(self):
        self.assertFalse(any("default" in argv for version in (4, 6) for argv in na.route_commands(self.config, version)))

    def test_host_link_table_sysctl_and_names_return_observed_host_state(self):
        self.assertEqual(na.namespace_names(), {HOST_NS})
        self.assertEqual(na.host_sysctl(self.config, "net.ipv4.ip_forward"), "1")
        self.activated()
        self.assertEqual(na.host_link(self.config)["ifindex"], 7)
        self.assertEqual(na.table_comment(na.host_table(self.config)), na.marker(self.config, self.state()["generation"]))
        self.assertEqual(na.ownership_marker(self.config["namespace"]), na.marker(self.config, self.state()["generation"]))

    def test_host_link_table_and_marker_of_absent_objects_are_none(self):
        with self.subTest("an absent host veth is none"):
            self.assertIsNone(na.host_link(self.config))
        with self.subTest("an absent host table is none"):
            self.assertIsNone(na.host_table(self.config))
        with self.subTest("an absent namespace has no marker"):
            self.assertIsNone(na.ownership_marker("nmas-test-nowhere"))
        with self.subTest("an unreadable sysctl raises"):
            self.host.fail_on = "sysctl -n"
            with self.assertRaises(subprocess.CalledProcessError):
                na.host_sysctl(self.config, "net.ipv4.ip_forward")


# ====================================================================================================== lifecycle
class LifecycleTests(Harness):
    def test_preflight_returns_a_read_only_report(self):
        report = na.preflight(self.config, self.state_path, self.netns_etc)
        self.assertEqual((report["state"], report["mutations"]), ("absent", 0))
        self.assertFalse(any(argv[:3] == ["/usr/sbin/ip", "netns", "add"] for argv in self.host.calls))

    def test_preflight_refuses_overlaps_disabled_forwarding_or_foreign_resources(self):
        with self.subTest("disabled host forwarding is refused"):
            self.host.sysctl_host = "0"
            with self.assertRaises(na.Refused):
                na.preflight(self.config, self.state_path, self.netns_etc)
            self.host.sysctl_host = "1"
        with self.subTest("a nat source the egress lacks is refused"):
            self.host.egress = ["10.9.9.9/24"]
            with self.assertRaises(na.Refused):
                na.preflight(self.config, self.state_path, self.netns_etc)
        with self.subTest("an unowned namespace of the same name is refused"):
            self.host.egress = FakeHost(self.config, self.run_dir).egress
            self.host.namespaces.add(self.config["namespace"])
            with self.assertRaises(na.Refused):
                na.preflight(self.config, self.state_path, self.netns_etc)

    def test_activate_and_validate_active_build_the_exact_approved_namespace(self):
        result = self.activated()
        self.assertEqual(result["result"], "activated")
        state = self.state()
        self.assertEqual((state["status"], state["pending_step"]), ("active", ""))
        self.assertEqual(state["completed_steps"][:2], ["netns", "marker"])
        self.assertEqual(na.validate_active(self.config, self.state_path, self.netns_etc)["result"], "valid")
        self.assertEqual(self.activated()["result"], "already-active")

    def test_activate_failure_cleans_up_and_validate_active_refuses_drift(self):
        with self.subTest("an injected failure cleans up every owned object"):
            with self.assertRaises(na.Refused):
                na.activate(self.config, self.state_path, self.netns_etc, fail_after="host_move")
            self.assertEqual(self.state()["status"], "activation-failed-cleaned")
            self.assertEqual((self.host.namespaces, self.host.host_end, self.host.host_policy), ({HOST_NS}, None, None))
        with self.subTest("an extra namespace route is refused"):
            self.activated()
            self.host.routes[4].append({"dst": "default", "gateway": "169.254.86.1", "dev": "nmas-test0"})
            with self.assertRaises(na.Refused):
                na.validate_active(self.config, self.state_path, self.netns_etc)
        with self.subTest("no ownership state is refused"):
            with self.assertRaises(na.Refused):
                na.validate_active(self.config, self.root / "state" / "absent.json", self.netns_etc)

    def test_cleanup_and_deactivate_remove_only_owned_objects(self):
        self.activated()
        self.assertEqual(na.deactivate(self.config, self.state_path, self.netns_etc, "deactivate")["result"], "deactivate")
        self.assertEqual((self.host.namespaces, self.host.host_end, self.host.host_policy), ({HOST_NS}, None, None))
        self.assertEqual(na.deactivate(self.config, self.state_path, self.netns_etc, "deactivate")["result"], "already-deactivate")
        self.activated()
        na.cleanup(self.config, self.state_path, self.state(), self.netns_etc, "rollback")
        self.assertEqual(self.state()["status"], "rollback")

    def test_cleanup_and_deactivate_refuse_changed_or_unowned_objects(self):
        with self.subTest("an unowned namespace is never deleted"):
            self.host.namespaces.add(self.config["namespace"])
            with self.assertRaises(na.Refused):
                na.deactivate(self.config, self.state_path, self.netns_etc, "deactivate")
            self.host.namespaces.discard(self.config["namespace"])
        with self.subTest("a host veth with a changed marker is never deleted"):
            self.activated()
            self.host.host_end["ifalias"] = "someone-else"
            with self.assertRaises(na.Refused):
                na.cleanup(self.config, self.state_path, self.state(), self.netns_etc, "rollback")
            self.assertIsNotNone(self.host.host_end)

    def test_begin_and_verify_terminal_generation_start_a_fresh_generation(self):
        first = na.begin_generation(self.config, self.state_path, self.netns_etc, status="activating")
        state = {**first, "status": "deactivate"}
        na.persist(self.state_path, state)
        self.assertIsNone(na.verify_terminal_generation(self.config, na.read_state(self.state_path), self.netns_etc))
        second = na.begin_generation(self.config, self.state_path, self.netns_etc, status="activating")
        self.assertNotEqual(second["generation"], first["generation"])
        self.assertEqual(second["previous_generation"], first["generation"])

    def test_begin_and_verify_terminal_generation_refuse_a_live_generation(self):
        na.begin_generation(self.config, self.state_path, self.netns_etc, status="active")
        with self.subTest("a non-terminal generation is refused"):
            with self.assertRaises(na.Refused):
                na.verify_terminal_generation(self.config, na.read_state(self.state_path), self.netns_etc)
        with self.subTest("starting over a live generation is refused"):
            with self.assertRaises(na.Refused):
                na.begin_generation(self.config, self.state_path, self.netns_etc, status="activating")

    def test_diagnostic_overlay_targets_returns_receipt_targets_for_the_production_base(self):
        production = {**self.config, "host_namespace": None}
        self.assertEqual(na.diagnostic_overlay_targets(self.config), set())       # a test namespace keeps its exact set
        receipt = {"schema": "nmas.diagnostic-target-overlay-receipt/1", "status": "active", "base_activation_id": production["activation_id"],
                   "base_config_digest": production["config_digest"], "expires_at": "2999-01-01T00:00:00Z",
                   "targets": [{"address": "192.168.200.2", "port": 22}]}
        (self.root / "state" / "diagnostic-target-overlay.json").write_text("x")
        with mock.patch.object(na, "PRODUCTION_STATE", self.root / "state"), \
                mock.patch.object(na, "read_secure_regular", return_value=(None, json.dumps(receipt).encode())):
            self.assertEqual(na.diagnostic_overlay_targets(production), {("192.168.200.2", 22)})

    def test_diagnostic_overlay_targets_refuses_an_untrusted_or_expired_receipt(self):
        production = {**self.config, "host_namespace": None}
        (self.root / "state" / "diagnostic-target-overlay.json").write_text("{}")
        with mock.patch.object(na, "PRODUCTION_STATE", self.root / "state"):
            with self.subTest("a user-owned receipt is refused"), self.assertRaises(na.Refused):
                na.diagnostic_overlay_targets(production)
            expired = {"schema": "nmas.diagnostic-target-overlay-receipt/1", "status": "active", "expires_at": "2000-01-01T00:00:00Z",
                       "base_activation_id": production["activation_id"], "base_config_digest": production["config_digest"], "targets": []}
            with self.subTest("an expired receipt is refused"), \
                    mock.patch.object(na, "read_secure_regular", return_value=(None, json.dumps(expired).encode())), \
                    self.assertRaises(na.Refused):
                na.diagnostic_overlay_targets(production)


class ResearchResolverTests(Harness):
    kind = "research"

    def setUp(self):
        super().setUp()
        for name, fake in (("secure_directory", trusted_regular), ("secure_regular", trusted_regular), ("read_secure_regular", trusted_read)):
            patcher = mock.patch.object(na, name, side_effect=fake)
            patcher.start()
            self.addCleanup(patcher.stop)
        for patcher in (mock.patch.object(na.os, "fchown"), mock.patch.object(na, "resolver_root_safe", return_value=True)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_create_and_validate_resolver_state_write_the_approved_file(self):
        state = na.begin_generation(self.config, self.state_path, self.netns_etc, status="preparing-resolver")
        na.create_resolver(self.config, self.netns_etc, self.state_path, state, None)
        resolv = na.resolver_paths(self.config, self.netns_etc)[1]
        self.assertEqual(resolv.read_bytes(), b"nameserver 93.184.216.53\n")
        self.assertIsNone(na.validate_resolver_state(self.config, self.netns_etc, na.read_state(self.state_path)))

    def test_create_and_validate_resolver_state_refuse_foreign_or_changed_files(self):
        state = na.begin_generation(self.config, self.state_path, self.netns_etc, status="preparing-resolver")
        directory, resolv = na.resolver_paths(self.config, self.netns_etc)
        directory.mkdir()
        with self.subTest("a pre-existing resolver directory is refused"), self.assertRaises(na.Refused):
            na.create_resolver(self.config, self.netns_etc, self.state_path, state, None)
        directory.rmdir()
        na.create_resolver(self.config, self.netns_etc, self.state_path, state, None)
        resolv.write_text("nameserver 8.8.8.8\n")
        with self.subTest("changed resolver content is refused"), self.assertRaises(na.Refused):
            na.validate_resolver_state(self.config, self.netns_etc, na.read_state(self.state_path))

    def test_prepare_resolver_creates_once_and_returns_already_prepared(self):
        self.assertEqual(na.prepare_resolver(self.config, self.state_path, self.netns_etc)["result"], "prepared")
        self.assertEqual(na.prepare_resolver(self.config, self.state_path, self.netns_etc)["result"], "already-prepared")

    def test_prepare_resolver_refuses_diagnostics_and_cleans_up_a_failed_preparation(self):
        with self.subTest("a diagnostic namespace is refused"), self.assertRaises(na.Refused):
            na.prepare_resolver({**self.config, "kind": "diagnostic"}, self.state_path, self.netns_etc)
        with self.subTest("an injected failure removes the owned resolver"):
            with self.assertRaises(na.Refused):
                na.prepare_resolver(self.config, self.state_path, self.netns_etc, fail_after="dns")
            self.assertEqual(self.state()["status"], "resolver-prepare-failed-cleaned")
            self.assertFalse(na.resolver_paths(self.config, self.netns_etc)[0].exists())

    def test_service_preflight_returns_valid_for_the_approved_namespace_and_resolver(self):
        na.prepare_resolver(self.config, self.state_path, self.netns_etc)
        resolv = na.resolver_paths(self.config, self.netns_etc)[1]
        (self.run_dir / self.config["namespace"]).write_text("")

        def mapped(*parts):
            p = REAL_PATH(*parts)
            return {"/run/netns": self.run_dir, "/proc/self/ns/net": self.run_dir / self.config["namespace"],
                    "/etc/resolv.conf": resolv}.get(str(p), p)

        def opened(path, *args, **kwargs):
            return REAL_OPEN(str(resolv) if path == "/etc/resolv.conf" else path, *args, **kwargs)
        with mock.patch.object(na, "Path", mapped), mock.patch.object(na.os, "open", side_effect=opened):
            out = na.service_preflight(self.config, self.env, self.netns_etc)
        self.assertEqual((out["result"], out["ipv6"]), ("valid", "disabled"))

    def test_service_preflight_refuses_diagnostics_or_another_network_namespace(self):
        with self.subTest("a diagnostic configuration is refused"), self.assertRaises(na.Refused):
            na.service_preflight({**self.config, "kind": "diagnostic"}, self.env, self.netns_etc)
        na.prepare_resolver(self.config, self.state_path, self.netns_etc)
        with self.subTest("a worker outside its namespace is refused"), self.assertRaises(na.Refused):
            na.service_preflight(self.config, self.env, self.netns_etc)


class MainTests(Harness):
    def test_main_returns_zero_after_printing_the_host_policy(self):
        out = io.StringIO()
        with mock.patch.object(na, "normalized_config", return_value=self.config), redirect_stdout(out):
            self.assertEqual(na.main(["host-policy", "diagnostic", str(self.env)]), 0)
        self.assertIn(f"table inet {self.config['host_table']}", out.getvalue())

    def test_main_refuses_production_failure_injection_and_unprivileged_mutation(self):
        with self.subTest("failure injection outside test mode is refused"), self.assertRaises(na.Refused):
            na.main(["activate", "diagnostic", str(self.env), "--fail-after", "link"])
        with self.subTest("an unprivileged activation is refused"), \
                mock.patch.object(na, "normalized_config", return_value=self.config), mock.patch.object(na.os, "geteuid", return_value=1000), \
                self.assertRaises(na.Refused):
            na.main(["activate", "diagnostic", str(self.env)])
