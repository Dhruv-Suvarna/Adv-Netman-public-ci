from __future__ import annotations

from unittest import mock

from django.test import TestCase

from core import models
from core.services import platform_drivers as pd
from core.services.platform_drivers import CapabilityStatus, PlatformCapability, RoutingProtocol, ServicePolicyFeature
from core.services.validation import capabilities as cap_module
from core.tests.helpers.validation import Dev, codes, findings, new_change, validate


def cap(status):
    return PlatformCapability(status, "test evidence")


class CapabilityValidationTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.change = new_change()
        cls.r1 = Dev(cls.change, "R1")
        cls.e1 = cls.r1.iface("Ethernet1")

    def platform_codes(self, run):
        return [c for c in codes(run) if c.startswith("PLATFORM_FEATURE") or c == "PLATFORM_RENDERER_INCONSISTENT"]

    def test_supported_objects_are_accepted_and_renderer_consistent(self):
        o = self.r1.ospf(); self.r1.bind("ospf", o, self.e1)
        self.r1.static_route("10.9.0.0/24", next_hop="192.0.2.1")
        svi = self.r1.iface("Vlan10", kind="SVI", vlan_id=10)
        self.r1.fhrp(svi, vips=["192.168.10.1"]); self.r1.relay(svi, "192.168.200.100")
        acl = self.r1.acl(); self.r1.attach_acl(acl, svi)
        run = validate(self.change)
        self.assertEqual(self.platform_codes(run), [])
        self.assertGreaterEqual(run.summary["checked"]["capability_objects"], 7)

    def test_ubuntu_supported_objects_are_consistent(self):
        change = new_change()
        r3 = Dev(change, "R3", platform=models.Platform.UBUNTU_FRR)
        e1 = r3.iface("eth1"); r3.iface("lo", kind="LOOPBACK"); r3.iface("eth1.10", kind="SUBINTERFACE", parent_id=e1["id"], encapsulation_vlan=10)
        r3.nat_rule(outside=e1, source="10.0.0.0/8")
        self.assertEqual(self.platform_codes(validate(change)), [])

    def test_not_implemented_blocks_planning(self):
        # Phase 20.5: SONiC now implements ROUTED_PHYSICAL (e1's kind), so use an
        # interface kind still genuinely NOT_IMPLEMENTED for SONiC.
        self.r1.force(f"interfaces.{self.e1['id']}.kind", "LAG")
        self.r1.switch_platform(models.Platform.SONIC)
        run = validate(self.change)
        (finding,) = findings(run, "PLATFORM_FEATURE_NOT_IMPLEMENTED")
        self.assertTrue(finding["blocking"])
        self.assertEqual(run.status, "BLOCKED")
        self.assertEqual(finding["evidence"]["status"], "NOT_IMPLEMENTED")

    def test_unsupported_blocks_planning(self):
        self.r1.force(f"interfaces.{self.e1['id']}.kind", "BOND")
        (finding,) = findings(validate(self.change), "PLATFORM_FEATURE_UNSUPPORTED")
        self.assertTrue(finding["blocking"])

    def test_unknown_makes_result_incomplete_not_pass_and_not_blocking(self):
        self.r1.force(f"interfaces.{self.e1['id']}.kind", "VIRTUAL")
        run = validate(self.change)
        (finding,) = findings(run, "PLATFORM_FEATURE_UNKNOWN")
        self.assertEqual((finding["blocking"], finding["incomplete"]), (False, True))
        self.assertEqual(run.status, "INCOMPLETE")

    def test_platform_switch_preserved_intent_is_surfaced_explicitly(self):
        svi = self.r1.iface("Vlan10", kind="SVI", vlan_id=10)
        self.r1.fhrp(svi, vips=["192.168.10.1"])
        self.r1.switch_platform(models.Platform.UBUNTU_FRR)
        objects = {f["object_type"] for f in findings(validate(self.change)) if f["code"].startswith("PLATFORM_FEATURE")}
        self.assertIn("fhrp", objects)

    def test_interface_capabilities_reuse_the_same_registry(self):
        with mock.patch.dict(pd.PLATFORM_CAPABILITIES["arista_ceos"], {"ROUTED_PHYSICAL": cap(CapabilityStatus.NOT_IMPLEMENTED)}):
            self.assertIn("PLATFORM_FEATURE_NOT_IMPLEMENTED", codes(validate(self.change)))
        self.assertNotIn("PLATFORM_FEATURE_NOT_IMPLEMENTED", codes(validate(self.change)))

    def test_routing_capabilities_reuse_the_same_registry(self):
        o = self.r1.ospf(); self.r1.bind("ospf", o, self.e1)
        with mock.patch.dict(pd.ROUTING_CAPABILITIES["arista_ceos"], {RoutingProtocol.OSPFV2: cap(CapabilityStatus.UNSUPPORTED)}):
            run = validate(self.change)
        self.assertTrue([f for f in run.report["findings"] if f["code"] == "PLATFORM_FEATURE_UNSUPPORTED" and f["object_type"] == "routing_ospf"])

    def test_phase12_capabilities_reuse_the_same_registry(self):
        svi = self.r1.iface("Vlan10", kind="SVI", vlan_id=10); self.r1.fhrp(svi, vips=["192.168.10.1"])
        with mock.patch.dict(pd.SERVICE_POLICY_CAPABILITIES["arista_ceos"], {ServicePolicyFeature.FHRP_VARP_IPV4: cap(CapabilityStatus.NOT_IMPLEMENTED)}):
            run = validate(self.change)
        self.assertTrue([f for f in run.report["findings"] if f["code"] == "PLATFORM_FEATURE_NOT_IMPLEMENTED" and f["object_type"] == "fhrp"])

    def test_validation_holds_no_capability_table_of_its_own(self):
        import ast, pathlib
        source = pathlib.Path(cap_module.__file__).read_text()
        tree = ast.parse(source)
        tables = [n for n in ast.walk(tree) if isinstance(n, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id.isupper() and "CAPAB" in t.id for t in n.targets)]
        self.assertEqual(tables, [])

    def test_renderer_inconsistency_registry_supported_but_renderer_refuses(self):
        def inject(sections):
            sections.setdefault("policy", {"pbr": {"policies": {}, "attachments": {}}})
            sections["policy"]["pbr"]["policies"]["pbr_x"] = {"id": "pbr_x", "sequence": 1, "name": "P", "family": "IPV4", "description": "", "sequences": {}}
        self.r1.inject(inject)
        with mock.patch.dict(pd.SERVICE_POLICY_CAPABILITIES["arista_ceos"], {ServicePolicyFeature.PBR_IPV4: cap(CapabilityStatus.SUPPORTED)}):
            run = validate(self.change)
        (finding,) = findings(run, "PLATFORM_RENDERER_INCONSISTENT")
        self.assertTrue(finding["blocking"])
        self.assertEqual(run.status, "BLOCKED")

    def test_renderer_inconsistency_deployable_output_for_unsupported_object(self):
        # Phase 20.5: SONiC now implements ROUTED_PHYSICAL (e1's kind), so this needs
        # a kind still genuinely NOT_IMPLEMENTED for SONiC to have anything to flag.
        self.r1.force(f"interfaces.{self.e1['id']}.kind", "LAG")
        self.r1.switch_platform(models.Platform.SONIC)
        fake = {"markers": 0, "deployable": ["interface PortChannel10"], "emitted": 1}
        with mock.patch.object(cap_module, "probe_object", return_value=fake):
            run = validate(self.change)
        self.assertIn("PLATFORM_RENDERER_INCONSISTENT", codes(run))

    def test_renderer_exception_for_supported_object_is_inconsistent(self):
        with mock.patch.object(cap_module, "probe_object", side_effect=ValueError("template exploded")):
            run = validate(self.change)
        (finding,) = findings(run, "PLATFORM_RENDERER_INCONSISTENT")
        self.assertEqual(finding["evidence"]["renderer_error"], "ValueError")

    def test_inventory_platform_mismatch_blocks(self):
        self.r1.switch_platform(models.Platform.UBUNTU_FRR)
        self.assertTrue(findings(validate(self.change), "PLATFORM_INVENTORY_MISMATCH")[0]["blocking"])

    def test_unknown_existing_device_is_warned(self):
        Dev(self.change, "ZZ9")
        self.assertIn("DEVICE_NOT_IN_INVENTORY", codes(validate(self.change)))

    def test_intent_without_revision_is_blocking(self):
        from core.services import intent_service
        intent, _ = intent_service.create_or_get_device_intent(change=self.change, device_name="R7", platform="arista_ceos")
        self.assertTrue(findings(validate(self.change), "INTENT_REVISION_MISSING")[0]["blocking"])
