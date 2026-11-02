"""V2 Phase 8: NetBox reconciliation of VLANs (verify only) and the management VRF (existing VRF, NMAS-assigned address only).

NMAS never creates a VLAN or a VRF and never edits the peer's interface: what NetBox lacks or contradicts is a discrepancy.
In-memory ``FakeNetbox``; the live proof against a disposable NetBox is docs/evidence/v2-phase8-closure/.
"""

from __future__ import annotations

from django.test import TestCase, override_settings

from core import models
from core.services.infrastructure import dispatcher, nsot
from core.tests import test_infrastructure_fixtures as F

P = models.NsotProjectionState


def desired(**management):
    return {"name": "NEW1", "status": "active", "interfaces": ["Ethernet1"], "cables": [], "vlans": [],
            "management": {"interface": "Ethernet1", "ipv4": "10.99.0.1/30", **management}}


class VlanTests(TestCase):
    def setUp(self):
        self.env = F.lab()
        self.device, _ = F.new_device_with_verified_uplink()        # access attachment S1:Ethernet7, VLAN 30

    def netbox(self, **extra):
        return F.FakeNetbox(devices={"NEW1": "planned", "S1": "active"}, interfaces={"S1": ["Ethernet7"]}, **extra)

    def codes(self, fake):
        dispatcher.dispatch("nsot", limit=100, nsot_client=fake)
        projection = models.NsotProjection.objects.get(device=self.device)
        return projection, [p["code"] for p in projection.discrepancies]

    @override_settings(NMAS_NSOT_RECONCILE_WRITE=True)
    def test_vlan_carried_untagged_by_the_peer_interface_is_in_sync(self):
        fake = self.netbox(vlans={30}, port_vlans={("S1", "Ethernet7"): {"untagged": 30}})
        projection, codes = self.codes(fake)
        self.assertEqual((projection.state, codes), (P.IN_SYNC, []))
        self.assertEqual(projection.desired["vlans"][0]["vlan"], 30)
        self.assertFalse(any("vlan" in op["op"] for op in fake.applied))

    @override_settings(NMAS_NSOT_RECONCILE_WRITE=True)
    def test_vlan_missing_from_netbox_is_a_discrepancy_never_created(self):
        fake = self.netbox(port_vlans={("S1", "Ethernet7"): {"untagged": 30}})
        projection, codes = self.codes(fake)
        self.assertEqual((projection.state, codes), (P.DISCREPANCY, ["VLAN_NOT_IN_NETBOX"]))
        self.assertEqual(fake.vlans, set())

    @override_settings(NMAS_NSOT_RECONCILE_WRITE=True)
    def test_vlan_not_on_the_peer_interface_is_a_mismatch_and_the_peer_is_never_edited(self):
        fake = self.netbox(vlans={30, 40}, port_vlans={("S1", "Ethernet7"): {"untagged": 40, "tagged": [30]}})
        projection, codes = self.codes(fake)
        self.assertEqual(codes, ["VLAN_MISMATCH"])                    # an ACCESS attachment needs it untagged
        self.assertEqual(fake.port_vlans[("S1", "Ethernet7")]["untagged"], 40)

    def test_vlan_peer_interface_missing_is_a_discrepancy(self):
        fake = F.FakeNetbox(devices={"NEW1": "planned", "S1": "active"}, vlans={30})
        ops, problems = nsot.plan(nsot.desired_state(self.device), fake)
        self.assertIn("VLAN_PEER_INTERFACE_MISSING", [p["code"] for p in problems])

    def test_trunk_attachment_accepts_a_tagged_vlan(self):
        want = {"name": "NEW1", "status": "active", "interfaces": [], "cables": [], "management": {},
                "vlans": [{"peer_device": "S1", "peer_interface": "Ethernet7", "vlan": 30, "tagged_ok": True, "source": "ATT"}]}
        fake = self.netbox(vlans={30}, port_vlans={("S1", "Ethernet7"): {"tagged": [10, 30]}})
        self.assertEqual(nsot.plan(want, fake)[1], [])


class ManagementVrfTests(TestCase):
    def netbox(self, **extra):
        return F.FakeNetbox(devices={"NEW1": "active"}, interfaces={"NEW1": ["Ethernet1"]}, **extra)

    def test_assigned_management_address_is_placed_in_the_existing_vrf(self):
        fake = self.netbox(vrfs={"MGMT"}, ips={"10.99.0.1/30": {"device": "", "interface": ""}})
        ops, problems = nsot.plan(desired(vrf="MGMT"), fake)
        self.assertEqual(problems, [])
        self.assertEqual([op["op"] for op in ops], ["assign_ip", "set_ip_vrf"])
        for op in ops:
            fake.apply(op)
        self.assertEqual(nsot.plan(desired(vrf="MGMT"), fake), ([], []))           # converged: idempotent

    def test_missing_vrf_is_a_discrepancy_and_never_created(self):
        fake = self.netbox(ips={"10.99.0.1/30": {"device": "", "interface": ""}})
        ops, problems = nsot.plan(desired(vrf="MGMT"), fake)
        self.assertEqual([p["code"] for p in problems], ["VRF_NOT_IN_NETBOX"])
        self.assertEqual([op["op"] for op in ops], ["assign_ip"])                   # the address, never a VRF
        self.assertEqual(fake.vrfs, set())

    def test_address_in_another_vrf_is_a_mismatch_and_not_reassigned(self):
        fake = self.netbox(vrfs={"MGMT", "OTHER"}, ips={"10.99.0.1/30": {"device": "", "interface": "", "vrf": "OTHER"}})
        ops, problems = nsot.plan(desired(vrf="MGMT"), fake)
        self.assertEqual([p["code"] for p in problems], ["VRF_MISMATCH"])
        self.assertEqual(ops, [])

    def test_management_facts_take_the_vrf_of_the_active_routed_path_only(self):
        env = F.lab()
        r1 = env["devices"]["R1"]
        oob = F.activate(r1, F.oob_path(env))
        self.assertNotIn("vrf", nsot.management_facts(r1))                     # an out-of-band path carries no VRF
        F.activate(r1, F.vrf_path(r1, env), previous=oob, kind=F.K.FAILOVER)
        self.assertEqual(nsot.management_facts(r1)["vrf"], "MGMT")


class CableEndpointTests(TestCase):
    """Found against the real NetBox: the lab model declares interfaces ``virtual`` and NetBox refuses a cable there."""

    def setUp(self):
        self.env = F.lab()
        self.device, _ = F.new_device_with_verified_uplink()        # NEW1:Ethernet1 -> S1:Ethernet7

    def netbox(self, **extra):
        return F.FakeNetbox(devices={"NEW1": "planned", "S1": "active"}, interfaces={"S1": ["Ethernet7"], "NEW1": ["Ethernet1"]}, vlans={30},
                            port_vlans={("S1", "Ethernet7"): {"untagged": 30}}, **extra)

    @override_settings(NMAS_NSOT_RECONCILE_WRITE=True)
    def test_cable_on_a_virtual_endpoint_is_not_connectable_and_never_written(self):
        fake = self.netbox(types={("NEW1", "Ethernet1"): "virtual"})
        dispatcher.dispatch("nsot", limit=100, nsot_client=fake)
        projection = models.NsotProjection.objects.get(device=self.device)
        self.assertEqual((projection.state, [p["code"] for p in projection.discrepancies]), (P.DISCREPANCY, ["CABLE_ENDPOINT_NOT_CONNECTABLE"]))
        self.assertEqual(projection.discrepancies[0]["endpoints"], ["NEW1:Ethernet1"])
        self.assertNotIn("create_cable", [op["op"] for op in fake.applied])
        self.assertEqual(fake.cables, {})

    @override_settings(NMAS_NSOT_RECONCILE_WRITE=True)
    def test_cable_between_physical_endpoints_is_created_once(self):
        fake = self.netbox(types={("NEW1", "Ethernet1"): "1000base-t", ("S1", "Ethernet7"): "1000base-t"})
        dispatcher.dispatch("nsot", limit=100, nsot_client=fake)
        self.assertEqual(models.NsotProjection.objects.get(device=self.device).state, P.IN_SYNC)
        self.assertEqual(fake.cables[("NEW1", "Ethernet1")], ("S1", "Ethernet7"))
        self.assertEqual([op["op"] for op in fake.applied].count("create_cable"), 1)

    def test_nonconnectable_types_are_netbox_own_list(self):
        self.assertTrue({"virtual", "lag", "bridge", "channel", "lte", "ieee802.11ax"} <= nsot.NONCONNECTABLE_TYPES)
        self.assertFalse({"other", "1000base-t", "10gbase-x-sfpp"} & nsot.NONCONNECTABLE_TYPES)
