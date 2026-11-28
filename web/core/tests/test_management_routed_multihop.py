"""Multi-hop ROUTED_VRF management paths: NMAS -> gateway (R4, over the management VLAN) -> R2 -> S4 (the lab's R4 -> R6 -> R7 shape, on tracked inventory names), each hop proven by the
registry (approved + VERIFIED routed attachments, a HEALTHY path on every device in front) and by the device's own running
configuration (VRF subinterface on the attachment, return route via the attachment's neighbour, VRF isolation)."""

from __future__ import annotations

from django.test import TestCase, override_settings

from core import models
from core.services.devices import attachments, lifecycle
from core.services.management import eos_facts, guard, paths, probes
from core.tests.helpers import management as M

T = models.ManagementPathType
HEALTHY = models.ManagementPathHealth.HEALTHY


def routed_attachment(device, *, upstream, port, local, verify=True):
    result = attachments.register_attachment(device, upstream_device=upstream, upstream_interface=port, local_interface=local,
                                             purpose=models.AttachmentPurpose.PRODUCTION,
                                             connectivity=models.AttachmentConnectivity.ROUTED, actor=M.OPERATOR)
    assert result.ok, result.blockers
    result = attachments.approve_attachment(device, result.attachment.pk, actor=M.APPROVER)
    assert result.ok, result.blockers
    if verify:
        M.observe_attachment(device, result.attachment)
    result.attachment.refresh_from_db()
    return result.attachment


def vrf_config(hostname, *, endpoint="10.254.250.2/30", parent="Ethernet1", sub="Ethernet1.250", return_hop="10.254.250.1",
               extra_members=(), routes=None) -> str:
    lines = [f"hostname {hostname}", "!", "vrf instance MGMT", "!", "ip routing", "ip routing vrf MGMT", "!",
             f"interface {parent}", "   no switchport", "   ip address 10.254.90.2/29", "!",
             f"interface {sub}", "   encapsulation dot1q vlan 250", "   vrf MGMT", f"   ip address {endpoint}", "!"]
    for name in extra_members:
        lines += [f"interface {name}", "   no switchport", "   vrf MGMT", "   ip address 10.9.9.1/30", "!"]
    for route in (routes if routes is not None else [f"ip route vrf MGMT 192.168.200.100/32 {return_hop}"]):
        lines.append(route)
    lines += ["!", "management ssh", "   vrf MGMT", "      no shutdown", "!", "end"]
    return "\n".join(lines) + "\n"


@override_settings(NMAS_MGMT_MIN_PROBE_INTERVAL_SECONDS=0)
class _Chain(TestCase):
    def setUp(self):
        self.lab = M.lab()
        self.nmas = self.lab["nmas"]
        patcher = M.fake_credentials()
        patcher.start()
        self.addCleanup(patcher.stop)
        self.devices = {}
        for name in ("R4", "R2", "S4"):
            result = lifecycle.adopt_existing(name, role="router", actor=M.APPROVER)
            assert result.ok, result.blockers
            self.devices[name] = result.device
        gateway_link = M.management_attachment(self.devices["R4"], upstream="mgmt_swt", port="Ethernet3", local="eth3")
        self.gateway = M.path(self.devices["R4"], self.nmas, attachment=gateway_link, endpoint="192.168.200.4")
        self.healthy(self.gateway)
        self.r6_link = routed_attachment(self.devices["R2"], upstream="R4", port="eth4", local="Ethernet1")
        self.r7_link = routed_attachment(self.devices["S4"], upstream="R2", port="Ethernet2", local="Ethernet1")

    @staticmethod
    def healthy(path):
        models.ManagementPath.objects.filter(pk=path.pk).update(health_state=HEALTHY)
        path.refresh_from_db()

    def register(self, name, link, endpoint, *, via="R4"):
        return paths.register_path(self.devices[name], path_type=T.ROUTED_VRF, vrf="MGMT", endpoint_address=endpoint,
                                   attachment_id=link.pk if link else None, via_device=via, nmas_attachment_id=self.nmas.pk,
                                   credential_source="INVENTORY", expected_host_key=M.HOST_KEY, actor=M.OPERATOR)

    def approved(self, name, link, endpoint):
        result = self.register(name, link, endpoint)
        assert result.ok, result.codes
        result = paths.approve_path(result.path, actor=M.APPROVER)
        assert result.ok, result.codes
        return result.path


class RoutedChainTests(_Chain):
    def test_is_on_link_routed_is_true_for_the_nmas_neighbour(self):
        self.assertTrue(paths.is_on_link_routed(self.devices["R4"], M.nmas_attachment(name="n2", interface="n2", upstream="R4",
                                                                                     source="10.40.0.2", network="10.40.0.0/30")))

    def test_is_on_link_routed_is_not_set_for_a_device_behind_a_hop_or_without_an_attachment(self):
        self.assertFalse(paths.is_on_link_routed(self.devices["R2"], self.nmas))
        self.assertFalse(paths.is_on_link_routed(self.devices["R2"], None))

    def test_routed_chain_walks_r7_through_r6_to_the_gateway_in_order(self):
        r6 = self.approved("R2", self.r6_link, "10.254.250.2")
        self.assertEqual([hop.get("device") or hop.get("nmas") for hop in r6.expected_topology["hops"]], ["R2", "R4", "NMA-000001"])
        self.healthy(r6)
        hops, problems = paths.routed_chain(self.devices["S4"], self.r7_link, self.nmas, "R4", "MGMT")
        self.assertEqual(problems, [])
        self.assertEqual([(hop.get("device") or hop.get("nmas"), hop.get("interface", "")) for hop in hops],
                         [("S4", "Ethernet1"), ("R2", "Ethernet2"), ("R4", "eth4"), ("NMA-000001", "")])
        self.assertTrue(self.register("S4", self.r7_link, "10.254.250.6").ok)

    def test_routed_chain_refuses_r7_before_r6_is_healthy(self):
        self.approved("R2", self.r6_link, "10.254.250.2")                    # approved, not yet verified HEALTHY
        refused = self.register("S4", self.r7_link, "10.254.250.6")
        self.assertIn("L1_TOPOLOGY_UNVERIFIED", refused.codes)
        self.assertIn("transit R2", refused.blockers[-1]["details"]["reason"])

    def test_routed_chain_refuses_unproven_hops(self):
        cases = {
            "no attachment": (None, "R4", "neither a direct NMAS neighbor"),
            "no gateway named": (self.r6_link, "", "names its gateway"),
            "gateway without a healthy path": (self.r6_link, "R2", "transit R4"),
        }
        for label, (link, via, reason) in cases.items():
            with self.subTest(label):
                _hops, problems = paths.routed_chain(self.devices["R2"], link, self.nmas, via, "MGMT")
                self.assertTrue(problems and reason in problems[0]["details"]["reason"], problems)
        models.ManagementPath.objects.filter(pk=self.gateway.pk).update(health_state=models.ManagementPathHealth.FAILED)
        _hops, problems = paths.routed_chain(self.devices["R2"], self.r6_link, self.nmas, "R4", "MGMT")
        self.assertIn("gateway R4", problems[0]["details"]["reason"])
        unverified = routed_attachment(self.devices["S4"], upstream="R4", port="eth6", local="Ethernet3", verify=False)
        _hops, problems = paths.routed_chain(self.devices["S4"], unverified, self.nmas, "R4", "MGMT")
        self.assertEqual(problems[0]["code"], "L1_TOPOLOGY_UNVERIFIED")

    def test_register_refuses_another_devices_attachment(self):
        refused = self.register("S4", self.r6_link, "10.254.250.6")
        self.assertIn("MGMT_PATH_ATTACHMENT_INVALID", refused.codes)

    def test_routed_problems_holds_for_a_proven_chain(self):
        r6 = self.approved("R2", self.r6_link, "10.254.250.2")
        self.assertEqual(paths.routed_problems(r6), [])
        self.assertEqual(paths.topology_problems(r6), [])
        stored, refusals = guard.authorized_target(r6)
        self.assertEqual((stored.pk, refusals), (r6.pk, []))

    def test_routed_problems_refuses_once_a_transit_hop_fails_and_nothing_is_contacted(self):
        r6 = self.approved("R2", self.r6_link, "10.254.250.2")
        self.healthy(r6)
        r7 = self.approved("S4", self.r7_link, "10.254.250.6")
        models.ManagementPath.objects.filter(pk=r6.pk).update(health_state=models.ManagementPathHealth.FAILED)
        self.assertEqual(paths.routed_problems(r7)[0]["code"], "L1_TOPOLOGY_UNVERIFIED")
        transport = M.FakeTransport()
        _report, row, refusals = probes.probe(r7, transport=transport)
        self.assertEqual(([r["code"] for r in refusals], row, transport.calls), (["L1_TOPOLOGY_UNVERIFIED"], None, []))


class RoutedHopConfigurationTests(_Chain):
    def setUp(self):
        super().setUp()
        self.r6 = self.approved("R2", self.r6_link, "10.254.250.2")

    def problems(self, config):
        facts = eos_facts.parse(config)
        return probes.routed_hop_problems(self.r6, facts, facts.interface_holding(self.r6.endpoint_address))

    def test_routed_hop_problems_is_empty_for_the_vrf_subinterface_with_a_return_route(self):
        self.assertEqual(self.problems(vrf_config("R2")), [])
        config = vrf_config("R2")
        transport = M.FakeTransport(outputs=M.eos_outputs(hostname="R2", serial="SN-R2", links={"Ethernet1": "connected"}, config=config))
        report, row, refusals = probes.probe(self.r6, transport=transport)
        self.assertEqual(refusals, [])
        self.assertTrue(report.passed, report.as_list())
        self.assertEqual((row.highest_layer, transport.calls[0]["address"], transport.calls[0]["interface"]),
                         (6, "10.254.250.2", "nmas-mgmt"))

    def test_routed_hop_problems_refuses_each_unsafe_configuration(self):
        cases = {
            "endpoint on the physical port": (vrf_config("R2", sub="Ethernet9.250"), "not a subinterface of the path's attachment"),
            "no return route": (vrf_config("R2", routes=[]), "no specific return route"),
            "only a default route": (vrf_config("R2", routes=["ip route vrf MGMT 0.0.0.0/0 10.254.250.1"]), "no specific return route"),
            "return route via another neighbour": (vrf_config("R2", return_hop="10.9.9.2"), "not on the attachment's link"),
            "data-plane port in the VRF": (vrf_config("R2", extra_members=("Ethernet2",)), "isolation"),
        }
        for label, (config, reason) in cases.items():
            with self.subTest(label):
                found = self.problems(config)
                self.assertTrue(any(reason in p["details"]["reason"] for p in found), found)

    def test_probe_refuses_a_routed_path_whose_vrf_is_not_isolated(self):
        config = vrf_config("R2", extra_members=("Vlan10",))
        transport = M.FakeTransport(outputs=M.eos_outputs(hostname="R2", serial="SN-R2", links={"Ethernet1": "connected"}, config=config))
        report, _row, _refusals = probes.probe(self.r6, transport=transport)
        self.assertFalse(report.passed)
        self.assertEqual(report.failure_code, "L2_CONFIG_MISMATCH")
