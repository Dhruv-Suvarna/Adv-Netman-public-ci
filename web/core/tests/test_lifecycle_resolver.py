"""V2 Lifecycle Phase 2: the one managed-device resolver, its engine parity, nsot_live integration and the NetBox mapping."""

from __future__ import annotations

import copy
from unittest import mock

from django.test import TestCase

from core import models
from core.services import nsot_live
from core.services.devices import netbox as device_netbox
from core.services.devices import resolver
from core.services.health import inventory as health_inventory
from core.services.provisioning.ipam import IpamUnavailable
from core.tests.helpers import lifecycle as L


def document(**devices):
    base = {"lab_name": "no-such-lab", "management": {"nmas_ipv4": "192.168.200.250/24", "nmas_ipv6": "2001:db8:200::250/64"},
            "network_devices": {}}
    base["network_devices"].update(devices)
    return base


def ceos(address="192.168.200.1", **extra):
    return {"monitoring": {"platform": "ceos", "address": address, "address_v6": "2001:db8:200::1"}, **extra}


class ResolverTests(TestCase):
    def test_resolve_all_returns_inventory_devices_with_scope_and_candidates(self):
        resolution = resolver.resolve_all()
        r1, r5, r3 = resolution.get("R1"), resolution.get("R5"), resolution.get("R3")
        self.assertEqual((r1.authority, r1.scope, r1.writable, r1.platform), ("INVENTORY_FILE", "WRITABLE", True, "arista_ceos"))
        self.assertEqual(r1.primary_address(4), "192.168.200.1")
        self.assertEqual(r1.primary_address(6), "2001:db8:200::1")
        self.assertEqual(r1.management_candidates[0].network, "VLAN200")
        self.assertEqual((r5.scope, r5.writable, r5.management_candidates, r5.transports), ("READ_ONLY", False, (), ()))
        self.assertEqual(r3.transports, ("SSH", "DOCKER_EXEC_LAB_RUNTIME"))
        self.assertIn("MANAGEMENT_ADDRESS_AUTO_REFUSED", {d.code for d in resolution.discrepancies})
        self.assertIsNone(resolution.get("H1"))

    def test_resolve_all_never_falls_back_to_containerlab_management(self):
        doc = document(X1=ceos("172.20.20.5", credential_ref="runtime://x"), X2=ceos("auto"), X3=ceos("not-an-ip"))
        resolution = resolver.resolve_all(document=doc, with_lifecycle=False)
        for name in ("X1", "X2", "X3"):
            with self.subTest(name=name):
                self.assertNotIn(4, {c.family for c in resolution.get(name).management_candidates})
        codes = {(d.code, d.name) for d in resolution.discrepancies}
        self.assertTrue({("CONTAINERLAB_MANAGEMENT_ADDRESS_REFUSED", "X1"), ("MANAGEMENT_ADDRESS_AUTO_REFUSED", "X2"),
                         ("MANAGEMENT_ADDRESS_INVALID", "X3")} <= codes)
        self.assertEqual(resolution.get("X1").primary_address(4), "")

    def test_resolve_all_keeps_only_device_references_and_never_a_secret(self):
        doc = document(X1=ceos(username="admin"), X2=ceos(credential_ref="runtime://own"), L1={
            "monitoring": {"platform": "linux", "address": "192.168.200.9"}, "username": "root", "ssh_key_ref": "runtime://k", "password": "x"})
        resolution = resolver.resolve_all(document=doc, with_lifecycle=False)
        self.assertEqual(resolution.get("X1").credential_refs, {"username": "admin"})
        self.assertEqual(resolution.get("X2").credential_refs["credential_ref"], "runtime://own")
        self.assertNotIn("password", resolution.get("L1").as_dict()["credential_refs"])

    def test_resolve_all_unreferenced_device_is_read_only(self):
        doc = document(X1=ceos())
        self.assertEqual(resolver.resolve_all(document=doc, with_lifecycle=False).get("X1").scope, "READ_ONLY")

    def test_inventory_wins_and_registration_conflict_is_recorded_not_merged(self):
        L.register(name="NEW1")
        doc = document(NEW1=ceos(credential_ref="runtime://x"))
        resolution = resolver.resolve_all(document=doc)
        self.assertEqual(resolution.get("NEW1").authority, "INVENTORY_FILE")
        self.assertIsNone(resolution.get("NEW1").lifecycle)
        self.assertIn(("REGISTRATION_SHADOWED_BY_INVENTORY", "NEW1"), {(d.code, d.name) for d in resolution.discrepancies})

    def test_registered_device_is_visible_not_managed_and_not_engine_resolvable(self):
        device = L.register().device
        target = resolver.resolve("NEW1")
        self.assertEqual((target.authority, target.scope, target.writable, target.device_id), ("NMAS_REGISTRY", "NOT_MANAGED_YET", False, device.device_id))
        self.assertIsNone(target.engine_entry)
        self.assertNotIn("NEW1", resolver.engine_devices())
        self.assertFalse(resolver.is_writable("NEW1"))

    def test_adopted_overlay_and_platform_mismatch_and_missing_inventory_device(self):
        adopted = L.adopt("R1", role="router").device
        target = resolver.resolve("R1")
        self.assertEqual((target.device_id, target.role, target.lifecycle["lifecycle_state"]), (adopted.device_id, "router", "IN_SERVICE"))
        doc = document(R1={"monitoring": {"platform": "linux", "address": "192.168.200.1"}, "ssh_key_ref": "runtime://k"})
        self.assertIn("LIFECYCLE_PLATFORM_MISMATCH", {d.code for d in resolver.resolve_all(document=doc).discrepancies})
        gone = resolver.resolve_all(document=document())
        self.assertIsNone(gone.get("R1"))
        self.assertIn(("ADOPTED_DEVICE_NOT_IN_INVENTORY", "R1"), {(d.code, d.name) for d in gone.discrepancies})

    def test_provisioning_registry_never_redefines_inventory(self):
        provisioned = {"R1": {"name": "R1", "platform": "ubuntu_frr", "address": "10.0.0.1"},
                       "EDGE1": {"name": "EDGE1", "platform": "ubuntu_frr", "address": "192.168.200.77", "container": "clab-x-EDGE1",
                                 "provisioning_state": models.ProvisionedDeviceState.ADMITTED}}
        with mock.patch.object(health_inventory, "provisioned_devices", return_value=provisioned):
            resolution = resolver.resolve_all()
            engine = resolver.engine_devices()
        self.assertEqual(resolution.get("R1").authority, "INVENTORY_FILE")
        self.assertEqual((resolution.get("EDGE1").authority, resolution.get("EDGE1").scope), ("PROVISIONING_REGISTRY", "WRITABLE_RESTRICTED"))
        self.assertIn("REGISTRY_SHADOWED_BY_INVENTORY", {d.code for d in resolution.discrepancies})
        self.assertEqual(engine["R1"]["platform"], health_inventory.inventory_devices()["R1"]["platform"])
        self.assertIn("EDGE1", engine)

    def test_engine_devices_is_identical_to_the_legacy_dictionary(self):
        legacy = health_inventory.inventory_devices()
        for name, entry in health_inventory.provisioned_devices().items():
            legacy.setdefault(name, entry)
        self.assertEqual(resolver.engine_devices(), legacy)
        self.assertEqual(health_inventory.managed_devices(), legacy)

    def test_engine_devices_with_empty_document_has_no_inventory_device(self):
        self.assertNotIn("R1", resolver.engine_devices(document=document()))

    def test_inventory_devices_accepts_preloaded_document(self):
        doc = health_inventory.load_inventory()
        self.assertEqual(health_inventory.inventory_devices(document=copy.deepcopy(doc)), health_inventory.inventory_devices())

    def test_lifecycle_registry_unavailable_is_reported_not_raised(self):
        with mock.patch.object(models.ManagedDevice.objects, "exclude", side_effect=resolver.DatabaseError("no table")):
            resolution = resolver.resolve_all()
        self.assertIn("LIFECYCLE_REGISTRY_UNAVAILABLE", {d.code for d in resolution.discrepancies})
        self.assertTrue(resolution.get("R1").writable)

    def test_resolve_unknown_name_is_none(self):
        self.assertIsNone(resolver.resolve("NOPE1"))
        self.assertIsNone(resolver.Resolution({}).get("X"))

    def test_is_writable_accepts_managed_and_refuses_read_only(self):
        self.assertTrue(resolver.is_writable("S1"))
        self.assertFalse(resolver.is_writable("R5"))

    def test_adoption_scope_accepts_writable_inventory_device(self):
        target, code = resolver.adoption_scope("mgmt_swt")
        self.assertEqual((target.name, code), ("mgmt_swt", ""))

    def test_adoption_scope_refuses_r5_endpoint_and_unmapped_platform(self):
        self.assertEqual(resolver.adoption_scope("R5")[1], "OUT_OF_WRITABLE_SCOPE")
        self.assertEqual(resolver.adoption_scope("H2"), (None, "NOT_IN_INVENTORY"))
        doc = document(Z1={"monitoring": {"platform": "junos", "address": "192.168.200.40"}, "credential_ref": "runtime://z"})
        self.assertEqual(resolver.adoption_scope("Z1", document=doc)[1], "PLATFORM_UNMAPPED")

    def test_forbidden_networks_returns_containerlab_defaults(self):
        found = {str(n) for n in resolver.forbidden_networks(document())}
        self.assertTrue({"172.20.20.0/24", "3fff:172:20:20::/64"} <= found)
        self.assertTrue({"172.20.20.0/24"} <= {str(n) for n in resolver.forbidden_networks()})

    def test_forbidden_networks_ignores_malformed_topology_subnet(self):
        with mock.patch.object(resolver, "_tracked_topology", return_value={"mgmt": {"ipv4-subnet": "not-a-net", "ipv6-subnet": "10.9.0.0/16"}}):
            found = {str(n) for n in resolver.forbidden_networks(document())}
        self.assertIn("10.9.0.0/16", found)
        self.assertNotIn("not-a-net", found)

    def test_target_and_candidate_dicts_render_without_secrets(self):
        target = resolver.resolve("R1")
        rendered = target.as_dict()
        self.assertEqual(rendered["management_candidates"][0], target.management_candidates[0].as_dict())
        self.assertTrue(rendered["engine_resolvable"])
        self.assertEqual(resolver.Discrepancy("C", "N").as_dict(), {"code": "C", "name": "N", "detail": ""})
        self.assertEqual(target.device_id, "")

    def test_primary_address_missing_family_is_empty(self):
        self.assertEqual(resolver.resolve("R5").primary_address(6), "")


class NsotLiveIntegrationTests(TestCase):
    def test_live_target_metadata_returns_declared_address(self):
        found = nsot_live.get_live_target_metadata("R1")
        self.assertEqual((found["platform"], found["address"]), ("ceos", "192.168.200.1"))
        self.assertEqual(nsot_live.get_live_target_metadata("R3")["platform"], "linux")

    def test_live_target_metadata_refuses_read_only_unknown_and_clab_address(self):
        self.assertIsNone(nsot_live.get_live_target_metadata("R5"))
        self.assertIsNone(nsot_live.get_live_target_metadata("H1"))
        doc = document(X1=ceos("172.20.20.9", credential_ref="runtime://x"))
        with mock.patch.object(nsot_live, "_load_inventory", return_value=doc):
            self.assertIsNone(nsot_live.get_live_target_metadata("X1"))


class FakeReader:
    def __init__(self, record=None, cables=(), fail=False):
        self.record, self._cables, self.fail = record, list(cables), fail

    def device(self, name):
        if self.fail:
            raise IpamUnavailable()
        return self.record

    def cables(self, name):
        if self.fail:
            raise IpamUnavailable()
        return self._cables


def fake_client(devices=(), interfaces=(), error=None):
    client = mock.Mock()
    if error:
        client.dcim.devices.filter.side_effect = error
        client.dcim.interfaces.filter.side_effect = error
    else:
        client.dcim.devices.filter.return_value = list(devices)
        client.dcim.interfaces.filter.return_value = list(interfaces)
    return client


class NetboxMappingTests(TestCase):
    def setUp(self):
        L.adopt()
        self.device = L.register().device

    def test_projection_maps_every_lifecycle_state(self):
        self.assertEqual(set(device_netbox.STATUS_PROJECTION), set(models.DeviceLifecycleState.values))
        self.assertEqual(device_netbox.projection(self.device), {"name": "NEW1", "status": "planned", "serial": L.SERIAL, "netbox_device_id": None})

    def test_projection_unknown_state_raises(self):
        with self.assertRaises(KeyError):
            device_netbox.projection(models.ManagedDevice(name="X", lifecycle_state="BOGUS"))

    def test_reader_client_builds_netbox_client_lazily(self):
        built = mock.Mock()
        with mock.patch("core.services.nsot_netbox._client", return_value=built) as factory:
            reader = device_netbox.NetboxDeviceReader()
            self.assertIs(reader.client, built)
            self.assertIs(reader.client, built)
        factory.assert_called_once_with()

    def test_compare_returns_no_discrepancy_for_matching_record(self):
        found = device_netbox.compare(self.device, FakeReader({"id": 7, "name": "NEW1", "status": "planned", "serial": "sn-new1"}))
        self.assertEqual((found["available"], found["discrepancies"]), (True, []))

    def test_compare_reports_mismatch_absent_and_unavailable(self):
        found = device_netbox.compare(self.device, FakeReader({"id": 7, "name": "NEW1", "status": "active", "serial": "SN-OTHER"}))
        self.assertEqual({d["code"] for d in found["discrepancies"]}, {"NETBOX_STATUS_DIFFERS", "NETBOX_SERIAL_DIFFERS"})
        self.assertEqual(device_netbox.compare(self.device, FakeReader(None))["discrepancies"][0]["code"], "NETBOX_DEVICE_ABSENT")
        self.assertEqual(device_netbox.compare(self.device, FakeReader(fail=True))["blockers"][0]["code"], "IPAM_UNAVAILABLE")

    def test_compare_withdrawn_device_with_netbox_record_is_unexpected(self):
        from core.services.devices import lifecycle

        lifecycle.withdraw(self.device, actor="x", reason="cancelled")
        self.device.refresh_from_db()
        found = device_netbox.compare(self.device, FakeReader({"id": 7, "name": "NEW1", "status": "planned", "serial": ""}))
        self.assertEqual([d["code"] for d in found["discrepancies"]], ["NETBOX_DEVICE_UNEXPECTED"])
        self.assertEqual(device_netbox.compare(self.device, FakeReader(None))["discrepancies"], [])

    def test_import_cable_attachments_creates_pending_netbox_attachments(self):
        cables = [{"local_interface": "Ethernet1", "upstream_device": "S1", "upstream_interface": "Ethernet7", "mgmt_only": False,
                   "mode": "access", "untagged_vlan": 30},
                  {"local_interface": "Management0", "upstream_device": "S1", "upstream_interface": "Ethernet8", "mgmt_only": True,
                   "mode": "tagged", "untagged_vlan": 200},
                  {"local_interface": "Ethernet2", "upstream_device": "S1", "upstream_interface": "Ethernet9", "mgmt_only": False,
                   "mode": "", "untagged_vlan": None}]
        found = device_netbox.import_cable_attachments(self.device, actor=L.OPERATOR, reader=FakeReader(cables=cables))
        self.assertEqual((found["ok"], len(found["created"]), found["skipped"]), (True, 3, []))
        rows = list(self.device.attachments.order_by("id"))
        self.assertEqual({(a.source, a.approval_state, a.verification_state) for a in rows}, {("NETBOX_CABLE", "PENDING", "UNVERIFIED")})
        self.assertEqual([(a.purpose, a.connectivity, a.vlan) for a in rows],
                         [("PRODUCTION", "ACCESS", 30), ("MANAGEMENT", "TRUNK", 200), ("PRODUCTION", "ROUTED", None)])

    def test_import_cable_attachments_skips_untrusted_upstream_and_refuses_unavailable(self):
        cables = [{"local_interface": "Ethernet1", "upstream_device": "R5", "upstream_interface": "Ethernet3", "mgmt_only": False,
                   "mode": "", "untagged_vlan": None}]
        found = device_netbox.import_cable_attachments(self.device, actor="o", reader=FakeReader(cables=cables))
        self.assertEqual((found["created"], found["skipped"][0]["codes"]), ([], ["UPSTREAM_NOT_TRUSTED"]))
        self.assertEqual(device_netbox.import_cable_attachments(self.device, actor="o", reader=FakeReader(fail=True))["blockers"][0]["code"],
                         "IPAM_UNAVAILABLE")

    def test_reader_device_returns_identity_fields(self):
        row = mock.Mock(id=4, serial="SN1", status=mock.Mock(value="active"))
        row.name = "NEW1"
        reader = device_netbox.NetboxDeviceReader(client=fake_client(devices=[row]))
        self.assertEqual(reader.device("NEW1"), {"id": 4, "name": "NEW1", "status": "active", "serial": "SN1"})
        self.assertIsNone(device_netbox.NetboxDeviceReader(client=fake_client()).device("NEW1"))

    def test_reader_errors_become_unavailable_without_upstream_text(self):
        reader = device_netbox.NetboxDeviceReader(client=fake_client(error=RuntimeError("token=abc at https://netbox")))
        for call in (reader.device, reader.cables):
            with self.subTest(call=call.__name__), self.assertRaises(IpamUnavailable) as raised:
                call("NEW1")
            self.assertNotIn("token", str(raised.exception))

    def test_reader_cables_returns_far_ends_only(self):
        peer = mock.Mock(device=mock.Mock())
        peer.name, peer.device.name = "Ethernet7", "S1"
        cabled = mock.Mock(cable=mock.Mock(), link_peers=[peer], mgmt_only=False, mode=mock.Mock(value="access"), untagged_vlan=mock.Mock(vid=30))
        cabled.name = "Ethernet1"
        loose = mock.Mock(cable=None)
        anonymous = mock.Mock(cable=mock.Mock(), link_peers=[mock.Mock(device=None)])
        reader = device_netbox.NetboxDeviceReader(client=fake_client(interfaces=[cabled, loose, anonymous]))
        self.assertEqual(reader.cables("NEW1"), [{"local_interface": "Ethernet1", "upstream_device": "S1", "upstream_interface": "Ethernet7",
                                                  "mgmt_only": False, "mode": "access", "untagged_vlan": 30}])

    def test_reader_has_no_write_method(self):
        self.assertFalse({name for name in dir(device_netbox.NetboxDeviceReader) if not name.startswith("_")}
                         - {"client", "device", "cables"})
