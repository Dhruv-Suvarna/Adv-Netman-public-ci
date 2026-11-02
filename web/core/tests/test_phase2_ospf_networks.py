"""Focused OSPFv2 network-statement creation, rendering, import and validation."""

from django.test import TestCase

from core import models
from core.services import candidate_renderer, network_config_validation, routing_intent_service
from core.services.config_import import parser_ceos, parser_frr
from core.tests.helpers.candidates import add_instance, make_candidate
from core.tests.helpers.validation import make_sources


class OspfNetworkStatementTests(TestCase):
    def test_create_normalizes_and_ceos_renderer_emits_network_statement(self):
        _change, intent, revision = make_candidate(platform=models.Platform.ARISTA_CEOS, device_name="R1")
        instance = add_instance(revision, family="ospf", version="OSPFV2")
        network = routing_intent_service.add_ospf_network(
            revision=revision, instance_id=instance["id"], prefix="10.10.0.0/24", area="1"
        )
        self.assertEqual(network["prefix"], "10.10.0.0/24")
        self.assertEqual(network["area"], "0.0.0.1")
        rendered = candidate_renderer.render(intent, revision)["text"]
        self.assertIn("network 10.10.0.0/24 area 0.0.0.1", rendered)

    def test_ospfv3_refuses_network_statement_and_removal_requires_confirmation(self):
        _change, _intent, revision = make_candidate(platform=models.Platform.UBUNTU_FRR, device_name="R3")
        ospfv3 = add_instance(revision, family="ospf", version="OSPFV3")
        with self.assertRaises(routing_intent_service.CollectionMutationError):
            routing_intent_service.add_ospf_network(
                revision=revision, instance_id=ospfv3["id"], prefix="2001:db8::/64", area="0"
            )

        ospfv2 = add_instance(revision, family="ospf", version="OSPFV2")
        network = routing_intent_service.add_ospf_network(
            revision=revision, instance_id=ospfv2["id"], prefix="10.20.0.0/16", area="0"
        )
        with self.assertRaises(routing_intent_service.CollectionMutationError):
            routing_intent_service.remove_ospf_network(
                revision=revision, instance_id=ospfv2["id"], net_id=network["id"], confirmation=""
            )
        routing_intent_service.remove_ospf_network(
            revision=revision, instance_id=ospfv2["id"], net_id=network["id"], confirmation="REMOVE"
        )
        self.assertNotIn(network["id"], routing_intent_service.get_protocol_instance(revision, "ospf", ospfv2["id"])["networks"])

    def test_ceos_and_frr_importers_parse_network_statements(self):
        ceos = parser_ceos.parse("router ospf 10\n   network 10.10.0.0/24 area 0.0.0.1\n")
        frr = parser_frr.parse("router ospf\n network 10.20.0.0/16 area 0\nexit\n")
        self.assertEqual(ceos.routing_instances[0].networks, [{"prefix": "10.10.0.0/24", "area": "0.0.0.1"}])
        self.assertEqual(frr.routing_instances[0].networks, [{"prefix": "10.20.0.0/16", "area": "0"}])

    def test_network_config_validation_blocks_corrupt_historical_statement(self):
        change, _intent, revision = make_candidate(platform=models.Platform.ARISTA_CEOS, device_name="R1")
        instance = add_instance(revision, family="ospf", version="OSPFV2")
        network = routing_intent_service.add_ospf_network(
            revision=revision, instance_id=instance["id"], prefix="10.10.0.0/24", area="0"
        )
        models.IntentFieldState.objects.filter(
            revision=revision,
            path=f"routing.ospf.{instance['id']}.networks.{network['id']}.prefix",
        ).update(accepted_value="10.10.0.7/24", draft_value="10.10.0.7/24")
        run = network_config_validation.validate_candidate(change, sources=make_sources())
        self.assertEqual(run.status, models.NetworkConfigValidationStatus.BLOCKED)
        check = next(row for row in run.checks if row["check"] == "OSPF_NETWORK_STATEMENTS")
        self.assertEqual(check["evidence"]["problems"][0]["reason"], "INVALID_IPV4_PREFIX")
