"""Importing a running configuration that contains IS-IS (every access device since the baseline migration).

Regression: ``config_import.service._apply_parsed_config`` indexed its managed-object lists by routing family and had no
``isis`` list, so the import of any device with ``router isis NMAS`` raised ``KeyError: 'isis'`` -- before Tier-2
validation and before Configuration Validation could be dispatched.  Fake read-only sessions only; no device."""

from __future__ import annotations

import copy
from unittest import mock

from django.test import TestCase, override_settings

from core import models
from core.services import candidate_renderer, change_plan_service as cps, change_validation_service as cvs, interface_intent_service, routing_intent_service
from core.services.config_import import service as config_import_service
from core.services.config_workbench import contribution, snapshots
from core.services.configuration_validation import bundle as bundle_module
from core.services.configuration_validation import service as configuration_validation
from core.tests.helpers import health as h
from core.tests.helpers.candidates import make_candidate
from core.tests.helpers.validation import make_sources
from core.tests.helpers.workbench import use_scope

# The access devices as ``show running-config`` prints them after the migration (the statements of templates/R1.cfg.j2
# and templates/S1.cfg.j2, one block per interface).
R1 = """hostname R1
interface Ethernet2
   description RIP_IPV4_STATIC_IPV6_TO_S1
   no switchport
   ip address 192.168.110.0/31
   ipv6 address 2001:db8:110:1::1/64
   isis enable NMAS
   isis metric 10
interface Loopback0
   ip address 192.168.255.1/32
   ipv6 address 2001:db8:255::1/128
ipv6 route 2001:db8::/32 2001:db8:3050::10
router isis NMAS
   net 49.0110.1921.6825.5001.00
   is-type level-2
   address-family ipv6 unicast
      redistribute static route-map STATIC6-TO-ISIS6
router ospf 10
   router-id 192.168.255.1
end
"""
S1 = """hostname S1
vlan 10,20,30,99
interface Ethernet1
   description RIP_IPV4_STATIC_IPV6_TO_R1
   no switchport
   ip address 192.168.110.1/31
   ipv6 address 2001:db8:110:1::2/64
   isis enable NMAS
   isis metric 10
interface Vlan10
   ip address 192.168.10.2/24
   ipv6 address 2001:db8:10::2/64
   isis enable NMAS
   isis passive
interface Vlan99
   ip address 192.168.110.4/31
   ipv6 address 2001:db8:110:3::1/64
   isis enable NMAS
   isis metric 10
router isis NMAS
   net 49.0110.1921.6825.5011.00
   is-type level-2
   address-family ipv6 unicast
end
"""
NO_ISIS = """hostname R1
interface Ethernet2
   no switchport
   ip address 192.168.110.0/31
router ospf 10
   router-id 192.168.255.1
end
"""


def imported(device: str, text: str):
    change, intent, revision = make_candidate(device_name=device, target_type=models.DeviceIntentTargetType.EXISTING_DEVICE)
    result = config_import_service.import_existing_device(change=change, intent=intent, revision=revision, device_name=device,
                                                          session_factory=h.session_factory({device: h.eos_outputs(config=text)}))
    revision.refresh_from_db()
    return result, intent, revision


def isis_of(revision) -> dict:
    (instance,) = routing_intent_service.ordered_instances(revision, "isis")
    bindings = {interface_intent_service.get_interface(revision, b["interface_id"])["name"]: b for b in (instance.get("interfaces") or {}).values()}
    return {"instance": instance, "bindings": bindings}


class IsisImportTests(TestCase):
    def test_a_configuration_without_isis_imports_exactly_as_before(self):
        result, _intent, revision = imported("R1", NO_ISIS)
        self.assertEqual((result.status, result.feature_counts["routing_instances"]), ("imported", 1))
        self.assertEqual(routing_intent_service.ordered_instances(revision, "isis"), [])
        self.assertEqual(sorted(k for k in revision.sections["_import"]["managed_object_ids"] if k in routing_intent_service.INSTANCE_FAMILIES), ["ospf"])

    def test_router_isis_no_longer_raises_key_error(self):
        result, _intent, revision = imported("R1", R1)                       # KeyError: 'isis' before the fix
        self.assertEqual(result.status, "imported")
        self.assertEqual(len(revision.sections["_import"]["managed_object_ids"]["isis"]), 1)

    def test_importing_the_same_device_again_replaces_the_process_instead_of_adding_one(self):
        change, intent, revision = make_candidate(device_name="S1", target_type=models.DeviceIntentTargetType.EXISTING_DEVICE)
        for _attempt in range(2):
            result = config_import_service.import_existing_device(change=change, intent=intent, revision=revision, device_name="S1",
                                                                  session_factory=h.session_factory({"S1": h.eos_outputs(config=S1)}))
            self.assertEqual(result.status, "imported")
            revision.refresh_from_db()
        self.assertEqual(len(isis_of(revision)["bindings"]), 3)             # one process (isis_of unpacks exactly one), three bindings
        lines = candidate_renderer.render(intent, revision)["text"].splitlines()
        self.assertEqual((lines.count("router isis NMAS"), lines.count("   isis enable NMAS")), (1, 3))

    def test_post_migration_r1_keeps_its_process_its_interface_binding_and_what_is_not_modelled(self):
        result, intent, revision = imported("R1", R1)
        found = isis_of(revision)
        self.assertEqual((found["instance"]["net"], found["instance"]["level"], found["instance"]["address_family_ipv6"], found["instance"]["address_family_ipv4"]),
                         ("49.0110.1921.6825.5001.00", "LEVEL_2", True, False))
        (binding,) = found["bindings"].values()
        self.assertEqual((binding.get("metric"), bool(binding.get("passive"))), (10, False))
        preserved = "\n".join(block["text"] for block in revision.sections["_import"]["unmanaged"])
        self.assertIn("redistribute static route-map STATIC6-TO-ISIS6", preserved)          # not interpreted, not discarded
        text = candidate_renderer.render(intent, revision)
        self.assertEqual(text.get("composition_conflicts") or [], [])
        for line in ("router isis NMAS", "   net 49.0110.1921.6825.5001.00", "   is-type level-2", "   address-family ipv6 unicast", "   isis enable NMAS", "   isis metric 10"):
            self.assertEqual(text["text"].splitlines().count(line), 1, line)
        self.assertEqual(result.feature_counts["routing_instances"], 2)

    def test_post_migration_s1_keeps_the_transit_and_the_passive_client_interface(self):
        _result, intent, revision = imported("S1", S1)
        bindings = isis_of(revision)["bindings"]
        self.assertEqual(len(bindings), 3)
        state = sorted((bool(b.get("passive")), b.get("metric")) for b in bindings.values())
        self.assertEqual(state, [(False, 10), (False, 10), (True, None)])
        lines = candidate_renderer.render(intent, revision)["text"].splitlines()
        self.assertEqual((lines.count("router isis NMAS"), lines.count("   isis enable NMAS"), lines.count("   isis passive"), lines.count("   isis metric 10")), (1, 3, 1, 2))
        vlan99 = lines[lines.index("interface Vlan99"):]
        self.assertIn("   isis enable NMAS", vlan99[:vlan99.index("!") if "!" in vlan99 else 8])

    def test_import_and_render_round_trip_is_stable(self):
        _result, intent, revision = imported("S1", S1)
        first = candidate_renderer.render(intent, revision)["text"]
        again, intent2, revision2 = imported("S1", first)                     # what NMAS rendered imports to the same model
        self.assertEqual(again.status, "imported")
        strip = lambda found: {(name, bool(b.get("passive")), b.get("metric")) for name, b in found["bindings"].items()}  # noqa: E731
        self.assertEqual(len(strip(isis_of(revision2))), 3)
        self.assertEqual(sorted((p, m) for _n, p, m in strip(isis_of(revision2))), sorted((p, m) for _n, p, m in strip(isis_of(revision))))
        second = candidate_renderer.render(intent2, revision2)["text"]
        keep = lambda text: [line for line in text.splitlines() if "isis" in line or line.startswith(("   net ", "   is-type", "   address-family"))]  # noqa: E731
        self.assertEqual(keep(first), keep(second))


@override_settings(NMAS_CONFIGURATION_VALIDATION_ENABLED=True)
class SaveDraftOnAnIsisDeviceTests(TestCase):
    """Configuration Change -> Save Draft -> import as context -> Tier-2 -> Configuration Validation dispatch."""

    def setUp(self):
        use_scope(self)
        self.sent = []
        fake = mock.Mock(wraps=configuration_validation.github)
        fake.dispatch = lambda event, payload: self.sent.append((event, copy.deepcopy(payload)))
        fake.repository = lambda: "example/nmas"
        patch = mock.patch.object(configuration_validation, "github", fake)
        patch.start()
        self.addCleanup(patch.stop)

    def test_save_draft_reaches_tier2_and_the_dispatch_hook_and_plans_only_the_contribution(self):
        factory = h.session_factory({"R1": h.eos_outputs(config=R1)})
        snapshot, error = snapshots.capture_snapshot("R1", actor="tester", session_factory=factory)
        self.assertEqual(error, "")
        change = contribution.create_contribution_change(snapshot=snapshot, actor="tester", session_factory=factory,     # KeyError: 'isis' before the fix
                                                         operations=[{"op": "static_route", "destination": "10.9.0.0/24", "next_hop": "192.168.110.1"}])
        sources = make_sources()
        run = cvs.validate_change(change, actor="tester", sources=sources)
        self.assertIn(run.status, ("PASS", "PASS_WITH_WARNINGS"), [(f["code"], f["message"]) for f in run.report["findings"] if f["severity"] == "ERROR"])
        row = configuration_validation.latest(change)
        self.assertEqual((row.status, row.snapshot_hash, len(self.sent)), (models.ConfigurationValidationStatus.QUEUED, run.input_hash, 1))
        bundle = bundle_module.decode(self.sent[0][1])
        self.assertEqual((bundle["change"]["change_id"], bundle["devices"][0]["device"]), (change.change_id, "R1"))
        self.assertIn("routing.ISIS", bundle["devices"][0]["features"])
        plan, _ = cps.build_change_plan(change, actor="tester", sources=sources)
        self.assertEqual([c.rendered_config for c in plan.configlets.order_by("sequence")], ["ip route 10.9.0.0/24 192.168.110.1"])    # no IS-IS statement is re-sent
        self.assertEqual(models.ChangeExecutionRun.objects.count(), 0)
