from django.test import TestCase

from core.services.planning import configlet_factory
from core.tests.helpers.candidates import add_interface, make_candidate


class LoopbackCapabilityClassificationTests(TestCase):
    def test_loopback_configlet_carries_exact_feature_key(self):
        _change, intent, revision = make_candidate()
        loopback = add_interface(revision, kind="LOOPBACK", name="Loopback44")
        context = configlet_factory.DeviceContext(intent, revision, {})
        node = {
            "id": f"R1/interface/{loopback['id']}", "type": "interface",
            "object_id": loopback["id"], "label": "Loopback44",
        }
        spec = configlet_factory._interface(context, node)[0]  # exact planner handler under test
        self.assertEqual(spec.capability_feature, "interface.LOOPBACK")
        self.assertNotEqual(spec.capability_feature, "interface.ROUTED_PHYSICAL")

    def test_address_on_loopback_keeps_loopback_feature_key(self):
        _change, intent, revision = make_candidate()
        loopback = add_interface(revision, kind="LOOPBACK", name="Loopback44")
        from core.services import interface_intent_service
        address = interface_intent_service.add_address(
            revision=revision, interface_id=loopback["id"], family="IPV4", source="MANUAL",
        )
        context = configlet_factory.DeviceContext(intent, revision, {})
        node = {
            "id": f"R1/address/{address['id']}", "type": "address",
            "object_id": address["id"], "label": "Loopback44 address",
        }
        self.assertEqual(configlet_factory._address(context, node)[0].capability_feature, "interface.LOOPBACK")
