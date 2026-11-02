from __future__ import annotations

import hashlib
import inspect
import json
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import yaml
from django.conf import settings
from django.test import SimpleTestCase, TestCase

from core.services import nsot_git, nsot_netbox, platform_drivers
from core.services.platform_drivers import CapabilityStatus, PlatformCapability
from core.services.validation import sources
from core.tests.helpers.validation import Dev, codes, link, make_sources, new_change, topology_data, validate


class _Endpoint:
    """Read-only fake pynetbox endpoint: anything but filter()/all() is a test failure."""

    def __init__(self, rows, log, name):
        self._rows, self._log, self._name = rows, log, name

    def filter(self, **kwargs):
        self._log.append(f"{self._name}.filter")
        return list(self._rows)

    def all(self):
        self._log.append(f"{self._name}.all")
        return list(self._rows)

    def __getattr__(self, item):
        raise AssertionError(f"unexpected NetBox call {self._name}.{item}")


def fake_client(log):
    ip = SimpleNamespace(
        address="192.0.2.1/24", role=SimpleNamespace(value="vrrp"),
        assigned_object=SimpleNamespace(name="Ethernet1", device=SimpleNamespace(name="R1")))
    unassigned = SimpleNamespace(address="192.0.2.9/24", role=None, assigned_object=None)
    prefix = SimpleNamespace(prefix="192.0.2.0/24", vlan=SimpleNamespace(vid=10), custom_fields={"dhcp_relay_targets": "192.168.200.100, 192.168.200.2"})
    vlan = SimpleNamespace(vid=10)
    iface = SimpleNamespace(name="Ethernet1", device=SimpleNamespace(name="R1"),
                            custom_fields={"ipv4_assignment_mode": "static", "ipv6_assignment_mode": None})
    device = SimpleNamespace(name="R1", tags=[SimpleNamespace(slug="managed")], custom_fields={"iac_managed": True})
    return SimpleNamespace(
        ipam=SimpleNamespace(ip_addresses=_Endpoint([ip, unassigned], log, "ip_addresses"), prefixes=_Endpoint([prefix], log, "prefixes"),
                             vlans=_Endpoint([vlan], log, "vlans")),
        dcim=SimpleNamespace(interfaces=_Endpoint([iface], log, "interfaces"), devices=_Endpoint([device], log, "devices")),
    )


class NetBoxAdapterTests(SimpleTestCase):
    def facts(self, log):
        ranges = [{"start": "192.0.2.100", "end": "192.0.2.150", "family": 4, "server": "primary", "description": "x"}]
        with mock.patch.object(nsot_netbox, "_client", return_value=fake_client(log)), \
                mock.patch.object(nsot_netbox.nb, "get_dhcp_ranges", return_value=ranges):
            return nsot_netbox.project_facts()

    def test_adapter_only_reads(self):
        log = []
        envelope = self.facts(log)
        self.assertEqual(envelope["status"], "available")
        self.assertTrue(log)
        self.assertTrue(all(entry.endswith((".filter", ".all")) for entry in log), log)

    def test_facts_are_normalized_and_free_of_urls_tokens_and_descriptions(self):
        data = self.facts([])["data"]
        self.assertEqual(data["ip_addresses"][0]["device"], "R1")
        self.assertEqual(data["prefixes"][0]["relay_targets"], ["192.168.200.100", "192.168.200.2"])
        self.assertEqual(data["interface_modes"][0]["ipv4_mode"], "static")
        self.assertEqual(data["managed_devices"], ["R1"])
        self.assertEqual(data["dhcp_ranges"][0], {"start": "192.0.2.100", "end": "192.0.2.150", "family": 4, "server": "primary"})
        text = json.dumps(data).lower()
        for word in ("token", "http", "description"):
            self.assertNotIn(word, text)

    def test_collect_netbox_is_deterministic_and_fingerprinted(self):
        envelope = self.facts([])
        with mock.patch.object(nsot_netbox, "project_facts", return_value=envelope):
            a, b = sources.collect_netbox(), sources.collect_netbox()
        self.assertEqual((a.status, a.fingerprint), (b.status, b.fingerprint))
        self.assertRegex(a.fingerprint, r"^[0-9a-f]{64}$")

    def test_outage_is_sanitized_and_never_raises(self):
        boom = ConnectionError("http://10.9.9.9:8000/api/ipam token=abc123secret")
        with mock.patch.object(nsot_netbox, "_client", side_effect=boom):
            result = sources.collect_netbox()
        self.assertEqual(result.status, "unavailable")
        self.assertEqual(result.message, "NetBox is temporarily unavailable.")
        self.assertEqual(result.fingerprint, "UNAVAILABLE")
        self.assertNotIn("abc123", json.dumps(result.provenance()))
        self.assertNotIn("10.9.9.9", json.dumps(result.provenance()))

    def test_adapter_functions_take_no_browser_supplied_arguments(self):
        for fn in (sources.collect_netbox, sources.collect_topology, sources.collect_inventory, sources.build_source_bundle,
                   nsot_netbox.project_facts):
            self.assertEqual(list(inspect.signature(fn).parameters), [], fn.__name__)


class NetBoxOutageInEngineTests(TestCase):
    def test_outage_details_never_reach_the_stored_report(self):
        change = new_change()
        r1 = Dev(change, "R1"); r1.address(r1.iface("Ethernet1"), "192.0.2.0/31")
        boom = ConnectionError("http://10.9.9.9:8000 token=abc123secret")
        with mock.patch.object(nsot_netbox, "_client", side_effect=boom), \
                mock.patch.object(sources, "collect_topology", return_value=make_sources().topology), \
                mock.patch.object(sources, "collect_inventory", return_value=make_sources().inventory), \
                mock.patch.object(sources, "repository_head", return_value="deadbeef"):
            from core.services import change_validation_service as cvs
            run = cvs.validate_change(change, actor="t")
        blob = json.dumps(run.report) + json.dumps(run.source_provenance)
        self.assertEqual(run.status, "INCOMPLETE")
        self.assertIn("SOURCE_NETBOX_UNAVAILABLE", codes(run))
        self.assertNotIn("abc123", blob)
        self.assertNotIn("10.9.9.9", blob)


class TopologyAdapterTests(SimpleTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.runtime = self.dir / "topology-data.json"
        self.runtime.write_text(json.dumps({
            "name": "lab", "nodes": {
                "R1": {"kind": "arista_ceos", "image": "ceos", "mgmt-ipv4-address": "172.20.20.12", "mac-address": "aa:bb:cc:dd:ee:ff"},
                "R3": {"kind": "linux", "image": "ubuntu"}},
            "links": [
                {"endpoints": {"a": {"node": "R3", "interface": "eth1", "mac": "aa:aa"}, "z": {"node": "R1", "interface": "eth2", "mac": "bb:bb"}}},
                {"endpoints": {"a": {"node": "host", "interface": "nmas-mgmt"}, "z": {"node": "R1", "interface": "eth9"}}},
            ]}))
        self.config = self.dir / "topology.yml"
        self.config.write_text(yaml.safe_dump({"runtime_metadata": str(self.runtime)}))

    def collect(self):
        with mock.patch.object(sources, "TOPOLOGY_CONFIG_PATH", self.config):
            return sources.collect_topology()

    def test_reads_nodes_and_links_without_mutating_the_source(self):
        before = hashlib.sha256(self.runtime.read_bytes()).hexdigest()
        result = self.collect()
        self.assertEqual(result.status, "available")
        self.assertEqual(hashlib.sha256(self.runtime.read_bytes()).hexdigest(), before)
        self.assertEqual(sorted(result.data["nodes"]), ["R1", "R3"])
        (only,) = result.data["links"]                          # the host attachment is not a lab node
        self.assertEqual({e["device"] for e in (only["a"], only["z"])}, {"R1", "R3"})

    def test_interface_names_are_mapped_for_ceos_only(self):
        (only,) = self.collect().data["links"]
        names = {only["a"]["device"]: only["a"]["interface"], only["z"]["device"]: only["z"]["interface"]}
        self.assertEqual(names, {"R1": "Ethernet2", "R3": "eth1"})

    def test_macs_and_management_addresses_are_not_carried(self):
        text = json.dumps(self.collect().data)
        for secret in ("aa:bb:cc", "172.20.20.12", "aa:aa", "mac"):
            self.assertNotIn(secret, text)

    def test_fingerprint_ignores_mac_noise_but_tracks_topology(self):
        first = self.collect().fingerprint
        raw = json.loads(self.runtime.read_text())
        raw["links"][0]["endpoints"]["a"]["mac"] = "cc:cc"
        self.runtime.write_text(json.dumps(raw))
        self.assertEqual(self.collect().fingerprint, first)
        raw["links"].pop(0)
        self.runtime.write_text(json.dumps(raw))
        self.assertNotEqual(self.collect().fingerprint, first)

    def test_missing_or_corrupt_source_is_unavailable_with_a_fixed_message(self):
        self.runtime.write_text("{not json /etc/passwd")
        result = self.collect()
        self.assertEqual((result.status, result.message), ("unavailable", "Topology metadata is unavailable."))
        self.runtime.unlink()
        self.assertEqual(self.collect().status, "unavailable")

    def test_oversized_source_is_rejected(self):
        self.runtime.write_text(" " * (sources.MAX_SOURCE_FILE_BYTES + 10))
        self.assertEqual(self.collect().status, "unavailable")

    def test_real_repository_topology_source_path_is_fixed_in_repo_config(self):
        config = yaml.safe_load(sources.TOPOLOGY_CONFIG_PATH.read_text())
        self.assertTrue(str(sources.TOPOLOGY_CONFIG_PATH).startswith(str(settings.REPO_ROOT)))
        self.assertTrue(config["runtime_metadata"].endswith("topology-data.json"))


class InventoryAdapterTests(SimpleTestCase):
    def test_inventory_path_is_fixed_inside_the_repository(self):
        self.assertEqual(sources.INVENTORY_PATH, Path(settings.REPO_ROOT) / "inventory.yml")

    def test_credentials_and_snmp_material_are_never_read_into_a_report(self):
        raw = yaml.safe_load(sources.INVENTORY_PATH.read_text())
        result = sources.collect_inventory()
        text = json.dumps(result.data)
        self.assertEqual(result.status, "available")
        for secret in (str(raw.get("ceos_password", "")), str(raw.get("ceos_username", ""))):
            if secret:
                self.assertNotIn(secret, text)
        for word in ("password", "snmp", "auth", "privacy", "username"):
            self.assertNotIn(word, text.lower())

    def test_platform_mapping_and_management_addresses(self):
        data = sources.collect_inventory().data
        self.assertEqual(data["network_devices"]["R1"]["platform"], "arista_ceos")
        self.assertEqual(data["network_devices"]["R3"]["platform"], "ubuntu_frr")
        self.assertEqual(data["management"]["nmas_ipv4"], "192.168.200.100")

    def test_unreadable_inventory_is_unavailable(self):
        with mock.patch.object(sources, "INVENTORY_PATH", Path("/nonexistent/inventory.yml")):
            self.assertEqual(sources.collect_inventory().status, "unavailable")


class CapabilitySourceTests(SimpleTestCase):
    def test_uses_the_same_three_registries_and_tracks_them(self):
        base = sources.collect_capability()
        self.assertEqual(set(base.data), {"interfaces", "routing", "service_policy"})
        self.assertEqual(set(base.data["interfaces"]), set(platform_drivers.PLATFORM_CAPABILITIES))
        cap = PlatformCapability(CapabilityStatus.UNSUPPORTED, "x")
        with mock.patch.dict(platform_drivers.PLATFORM_CAPABILITIES["arista_ceos"], {"ROUTED_PHYSICAL": cap}):
            self.assertNotEqual(sources.collect_capability().fingerprint, base.fingerprint)
        self.assertEqual(sources.collect_capability().fingerprint, base.fingerprint)


class BundleTests(SimpleTestCase):
    def test_bundle_collects_everything_read_only_and_records_provenance(self):
        canned = make_sources()
        with mock.patch.object(sources, "collect_netbox", return_value=canned.netbox), \
                mock.patch.object(sources, "collect_topology", return_value=canned.topology), \
                mock.patch.object(sources, "collect_inventory", return_value=canned.inventory), \
                mock.patch.object(sources, "repository_head", return_value="cafe1234"):
            bundle = sources.build_source_bundle()
        provenance = bundle.provenance()
        self.assertEqual(provenance["repository_head"], "cafe1234")
        self.assertEqual(set(provenance["sources"]), {"NETBOX", "TOPOLOGY", "INVENTORY", "CAPABILITY"})
        self.assertRegex(provenance["source_hash"], r"^[0-9a-f]{64}$")
        self.assertNotIn("password", json.dumps(provenance).lower())

    def test_repository_head_uses_only_read_only_git_commands(self):
        calls = []

        def fake_run(args):
            calls.append(args)
            return "abc123\n"

        with mock.patch.object(nsot_git, "_run_git", side_effect=fake_run):
            head = sources.repository_head()
        self.assertTrue(calls)
        self.assertLessEqual({args[0] for args in calls}, {"rev-parse", "log", "status"})
        self.assertEqual(head, "abc123")

    def test_git_failure_is_provenance_only_and_not_fatal(self):
        with mock.patch.object(nsot_git, "get_repo_state", side_effect=OSError("git missing")):
            self.assertEqual(sources.repository_head(), "")


class PartialSourceFailureTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.change = new_change()
        r1, r2 = Dev(cls.change, "R1"), Dev(cls.change, "R2")
        r1.address(r1.iface("Ethernet1"), "192.0.2.0/31"); r2.address(r2.iface("Ethernet1"), "192.0.3.1/31")
        cls.topo = topology_data(links=[link("R1", "Ethernet1", "R2", "Ethernet1")], nodes=("R1", "R2"))

    def test_topology_down_netbox_up_still_runs_netbox_backed_checks(self):
        r1 = Dev(self.change, "R9"); r1.address(r1.iface("Ethernet1"), "192.0.2.77/24")
        from core.tests.helpers.validation import nb_ip, netbox_data
        run = validate(self.change, make_sources(topology=None, netbox=netbox_data(ip_addresses=[nb_ip("192.0.2.77/24", "H9", "eth0")])))
        self.assertIn("SOURCE_TOPOLOGY_UNAVAILABLE", codes(run))
        self.assertIn("IP_NETBOX_COLLISION", codes(run))
        self.assertEqual(run.status, "BLOCKED")

    def test_required_source_failure_without_blockers_is_incomplete(self):
        r3 = Dev(new_change(), "R3", platform="ubuntu_frr")
        run = validate(r3.change, make_sources(topology=None))
        self.assertIn(run.status, ("INCOMPLETE", "PASS_WITH_WARNINGS"))
        change = new_change(); d = Dev(change, "R1"); d.address(d.iface("Ethernet1"), "192.0.2.0/31")
        self.assertEqual(validate(change, make_sources(topology=None)).status, "INCOMPLETE")
