"""V2 Phase 9 -- a RIP instance disabled in intent.

Before: every platform rendered only the comment ``! RIP instance disabled in intent; not rendered``.  A plan then produced a
comment-only Configlet (``NO_DEPLOYABLE_CONFIG``: nothing sent, a running RIP process left in place), and on cEOS the importer's
``enabled: False`` (``router rip`` + ``shutdown``) could not be rendered back.

Now: cEOS renders the instance administratively shut down (live-verified on cEOS 4.36.2F, see
``docs/evidence/v2-phase9-closure/disabled-rip/``); FRR (ripd has no shutdown), IOS XE and IOS XR carry an explicit
unsupported marker, which planning refuses (``UNSUPPORTED_OBJECT``) instead of silently doing nothing.
"""

from __future__ import annotations

from django.test import SimpleTestCase

from core.services import candidate_renderer, platform_drivers as D
from core.services.config_import import parser_ceos
from core.services.planning import snippets

INTERFACES = {"if_1": {"id": "if_1", "name": "Ethernet1", "addresses": {"a": {"id": "a", "sequence": 1, "family": "IPV4", "cidr": "10.254.86.1/31"}}},
              "if_2": {"id": "if_2", "name": "Loopback77", "addresses": {"b": {"id": "b", "sequence": 1, "family": "IPV4", "cidr": "203.0.113.1/24"}}}}


def instance(enabled):
    return {"id": "rip_1", "address_family": "IPV4", "enabled": enabled,
            "interfaces": {"b1": {"id": "b1", "interface_id": "if_1", "passive": False, "sequence": 1},
                           "b2": {"id": "b2", "interface_id": "if_2", "passive": False, "sequence": 2}}}


def text(descriptors):
    return [line for d in descriptors if (line := candidate_renderer.descriptor_text(d)) is not None]


class DisabledRipTests(SimpleTestCase):
    def test_ceos_disabled_instance_renders_the_process_administratively_shut_down(self):
        self.assertEqual(text(D._ceos_rip_descriptors(instance(False), INTERFACES)),      # pylint: disable=protected-access
                         ["router rip", "   shutdown", "   network 10.254.86.0/31", "   network 203.0.113.0/24"])

    def test_ceos_enabled_instance_rendering_is_preserved(self):
        self.assertEqual(text(D._ceos_rip_descriptors(instance(True), INTERFACES)),       # pylint: disable=protected-access
                         ["router rip", "   no shutdown", "   network 10.254.86.0/31", "   network 203.0.113.0/24"])

    def test_ceos_disabled_instance_round_trips_through_the_importer(self):
        rendered = text(D._ceos_rip_descriptors(instance(False), INTERFACES))             # pylint: disable=protected-access
        device = ["hostname X", "interface Ethernet1", "   no switchport", "   ip address 10.254.86.1/31", "!",
                  "interface Loopback77", "   ip address 203.0.113.1/24", "!"]
        parsed = parser_ceos.parse("\n".join([*device, *rendered, "!"]))
        rip, = [i for i in parsed.routing_instances if i.family == "rip"]
        self.assertEqual((rip.fields["enabled"], sorted(b["interface_name"] for b in rip.bindings)), (False, ["Ethernet1", "Loopback77"]))
        self.assertTrue(snippets.deployable(rendered))                                    # a real change, never a comment-only Configlet

    def test_disabled_instance_without_a_verified_form_is_refused_never_silently_skipped(self):
        for render in (D._frr_rip_descriptors, D._iosxe_rip_descriptors, D._iosxr_rip_descriptors):   # pylint: disable=protected-access
            with self.subTest(render=render.__name__):
                lines = text(render(instance(False), INTERFACES))
                self.assertTrue(snippets.has_unsupported_marker(lines), lines)
                self.assertFalse(snippets.deployable([line for line in lines if not line.startswith(D.UNSUPPORTED_OBJECT_MARKER)]))

    def test_frr_enabled_instance_rendering_is_preserved(self):
        self.assertEqual(text(D._frr_rip_descriptors(instance(True), INTERFACES)),        # pylint: disable=protected-access
                         ["router rip", "   version 2", "   network Ethernet1", "   network Loopback77"])
