"""Phase 20.5 (spec sections 10-12): existing-device SSH-equivalent import,
live-config -> structured-data -> template, and immutable preservation of
everything this project does not yet understand.

Every device read below goes through the SAME real, tested read-only
transport as the legacy-bootstrap capture (`core.services.bootstrap.capture`
/ `core.services.health.live`), with only the session factory swapped for a
fake one -- exactly the pattern `test_bootstrap.py` uses. No real device,
network or credential is touched.
"""

from __future__ import annotations

from django.test import TestCase
from django.urls import reverse

from core import models
from core.services import candidate_renderer, interface_intent_service
from core.services.config_import import service as config_import_service
from core.tests.helpers import health as h
from core.tests.helpers.candidates import make_candidate

DEVICE = "R1"

RUNNING_CONFIG = """! Command: show running-config
!
hostname R1-IMPORTED
!
interface Ethernet1
   description uplink to R2
   mtu 9000
   no switchport
   ip address 192.0.2.1/31
!
interface Ethernet2
   shutdown
!
router ospf 10
   router-id 1.1.1.1
!
monitor session 1 source Ethernet1
   destination Ethernet2
!
end
"""


def fake_factory(config=RUNNING_CONFIG, *, fail=None):
    return h.session_factory({DEVICE: h.eos_outputs(config=config)}, fail=fail)


class ImportServiceTests(TestCase):
    def new_existing_device_candidate(self):
        return make_candidate(device_name=DEVICE, target_type=models.DeviceIntentTargetType.EXISTING_DEVICE)

    def test_supported_fields_become_normal_editable_draft_state(self):
        change, intent, revision = self.new_existing_device_candidate()
        result = config_import_service.import_existing_device(
            change=change, intent=intent, revision=revision, device_name=DEVICE, session_factory=fake_factory(),
        )
        self.assertEqual(result.status, "imported")
        self.assertEqual(result.interfaces_imported, 2)

        revision.refresh_from_db()
        intent.refresh_from_db()
        self.assertEqual(intent.device_name, DEVICE)  # import never renames intent.device_name itself
        field_state = revision.field_states.get(path="device.hostname")
        self.assertEqual(field_state.accepted_value, "R1-IMPORTED")

        interfaces = interface_intent_service.ordered_interfaces(revision)
        eth1 = next(i for i in interfaces if i["name"] == "Ethernet1")
        self.assertEqual(eth1["description"], "uplink to R2")
        self.assertEqual(eth1["mtu"], 9000)
        self.assertEqual(eth1["admin_state"], "ENABLED")
        addresses = list(eth1["addresses"].values())
        self.assertEqual(len(addresses), 1)
        self.assertEqual(addresses[0]["cidr"], "192.0.2.1/31")
        self.assertEqual(addresses[0]["source"], "MANUAL")

        eth2 = next(i for i in interfaces if i["name"] == "Ethernet2")
        self.assertEqual(eth2["admin_state"], "DISABLED")

    def test_round_trip_supported_config_renders_correctly(self):
        change, intent, revision = self.new_existing_device_candidate()
        config_import_service.import_existing_device(
            change=change, intent=intent, revision=revision, device_name=DEVICE, session_factory=fake_factory(),
        )
        revision.refresh_from_db()
        candidate = candidate_renderer.render(intent, revision)
        text = candidate["text"]
        self.assertIn("hostname R1-IMPORTED", text)
        self.assertIn("interface Ethernet1", text)
        self.assertIn("   mtu 9000", text)
        self.assertIn("   ip address 192.0.2.1/31", text)
        self.assertIn("   shutdown", text)  # Ethernet2

    def test_unsupported_config_is_preserved_and_never_rendered_into_the_candidate(self):
        change, intent, revision = self.new_existing_device_candidate()
        result = config_import_service.import_existing_device(
            change=change, intent=intent, revision=revision, device_name=DEVICE, session_factory=fake_factory(),
        )
        self.assertGreater(result.unmanaged_block_count, 0)
        revision.refresh_from_db()
        unmanaged = revision.sections["_import"]["unmanaged"]
        labels = {b["label"] for b in unmanaged}
        self.assertIn("Unrecognized configuration (monitor)", labels)
        monitor_block = next(b for b in unmanaged if b["label"] == "Unrecognized configuration (monitor)")
        self.assertIn("destination Ethernet2", monitor_block["text"])

        candidate = candidate_renderer.render(intent, revision)
        # Supported OSPF is canonical/rendered. Unsupported monitor-session
        # text is retained in planning metadata, never injected into CLI.
        self.assertIn("router-id 1.1.1.1", candidate["text"])
        self.assertNotIn("monitor session", candidate["text"])
        self.assertEqual(candidate["import_metadata"]["unmanaged"], unmanaged)

    def test_unsupported_config_survives_editing_a_supported_feature(self):
        change, intent, revision = self.new_existing_device_candidate()
        config_import_service.import_existing_device(
            change=change, intent=intent, revision=revision, device_name=DEVICE, session_factory=fake_factory(),
        )
        revision.refresh_from_db()
        interfaces = interface_intent_service.ordered_interfaces(revision)
        eth1 = next(i for i in interfaces if i["name"] == "Ethernet1")
        interface_intent_service.add_address(revision=revision, interface_id=eth1["id"], family="IPV6", source="MANUAL")

        revision.refresh_from_db()
        unmanaged_after = revision.sections["_import"]["unmanaged"]
        self.assertTrue(any(b["label"] == "Unrecognized configuration (monitor)" for b in unmanaged_after))

    def test_provenance_is_recorded(self):
        change, intent, revision = self.new_existing_device_candidate()
        result = config_import_service.import_existing_device(
            change=change, intent=intent, revision=revision, device_name=DEVICE, session_factory=fake_factory(),
        )
        self.assertEqual(result.provenance["device"], DEVICE)
        self.assertEqual(result.provenance["platform"], "ceos")
        self.assertTrue(result.provenance["config_digest"])
        self.assertTrue(result.provenance["captured_at"])
        self.assertEqual(result.provenance["parser_version"], "ceos-2.1")

    def test_a_failed_fetch_never_creates_partial_draft_state(self):
        change, intent, revision = self.new_existing_device_candidate()
        result = config_import_service.import_existing_device(
            change=change, intent=intent, revision=revision, device_name=DEVICE,
            session_factory=fake_factory(fail={DEVICE: ConnectionError("simulated unreachable")}),
        )
        self.assertEqual(result.status, "unavailable")
        revision.refresh_from_db()
        self.assertFalse(revision.sections.get("interfaces"))
        self.assertNotIn("_import", revision.sections)

    def test_import_is_read_only_no_configuration_command_is_ever_sent(self):
        factory = fake_factory()
        change, intent, revision = self.new_existing_device_candidate()
        config_import_service.import_existing_device(
            change=change, intent=intent, revision=revision, device_name=DEVICE, session_factory=factory,
        )
        _name, session = factory.created[0]
        # Reuses the same allowlisted, read-only "show"-class command set the
        # legacy-bootstrap capture already proved read-only; no write/config
        # command is ever part of that allowlist.
        self.assertIn("running_config", session.ran)
        for forbidden in ("configure", "write", "reload", "copy", "no ", "shutdown"):
            self.assertFalse(any(forbidden in cmd for cmd in session.ran), session.ran)

    def test_unknown_device_is_refused_without_creating_anything(self):
        change, intent, revision = self.new_existing_device_candidate()
        result = config_import_service.import_existing_device(
            change=change, intent=intent, revision=revision, device_name="NOT-A-REAL-DEVICE",
        )
        self.assertEqual(result.status, "unavailable")
        revision.refresh_from_db()
        self.assertNotIn("_import", revision.sections)


class ImportViewTests(TestCase):
    def url(self, change, intent):
        return reverse("core:device_builder_import_existing_config", args=[change.change_id, intent.pk])

    def test_get_is_not_allowed(self):
        change, intent, _ = make_candidate(device_name=DEVICE, target_type=models.DeviceIntentTargetType.EXISTING_DEVICE)
        self.assertEqual(self.client.get(self.url(change, intent)).status_code, 405)

    def test_new_device_intent_refuses_import(self):
        change, intent, revision = make_candidate(device_name="BRAND-NEW", target_type=models.DeviceIntentTargetType.NEW_DEVICE)
        response = self.client.post(self.url(change, intent))
        self.assertEqual(response.status_code, 302)
        self.assertIn("import_error", response.url)
        revision.refresh_from_db()
        self.assertNotIn("_import", revision.sections)

    def test_editor_shows_import_button_and_unmanaged_blocks_after_import(self):
        import unittest.mock as mock
        change, intent, revision = make_candidate(device_name=DEVICE, target_type=models.DeviceIntentTargetType.EXISTING_DEVICE)
        edit_url = reverse("core:device_builder_edit", args=[change.change_id, intent.pk])
        response = self.client.get(edit_url)
        self.assertContains(response, "Import Live Configuration")

        with mock.patch.object(config_import_service, "import_existing_device") as mocked:
            mocked.return_value = config_import_service.ImportResult(
                status="imported", interfaces_imported=1, unmanaged_block_count=1,
                provenance={"device": DEVICE, "platform": "ceos", "source": "netmiko-ssh", "captured_at": "2026-01-01T00:00:00+00:00",
                            "config_digest": "abc123", "parser_version": "ceos-2.0", "credential_ref": "x"},
            )
            post_response = self.client.post(self.url(change, intent))
        self.assertEqual(post_response.status_code, 302)
        self.assertIn("import_notice", post_response.url)

    def test_failed_import_shows_a_clear_error_and_the_draft_stays_as_it_was(self):
        import unittest.mock as mock
        change, intent, revision = make_candidate(device_name=DEVICE, target_type=models.DeviceIntentTargetType.EXISTING_DEVICE)
        with mock.patch.object(config_import_service, "import_existing_device") as mocked:
            mocked.return_value = config_import_service.ImportResult(status="unavailable", message="Could not read R1: TIMEOUT")
            response = self.client.post(self.url(change, intent))
        self.assertEqual(response.status_code, 302)
        self.assertIn("import_error", response.url)
        revision.refresh_from_db()
        self.assertNotIn("_import", revision.sections)


FRR_CONFIG = """Building configuration...
Current configuration:
!
hostname R3
!
interface eth1
 description R2 transit
 ip ospf area 0.0.0.0
!
ip route 203.0.113.0/24 192.0.2.2 25
!
router ospf
 ospf router-id 10.255.0.3
 redistribute connected
!
router bgp 65003
 bgp router-id 10.255.0.3
 neighbor 192.0.2.2 remote-as 65002
 address-family ipv4 unicast
  neighbor 192.0.2.2 activate
  network 10.255.0.3/32
 exit-address-family
!
route-map DIRECT permit 10
!
end
"""

NFT_CONFIG = """table ip EDGE_PAT {
 chain postrouting {
  type nat hook postrouting priority srcnat; policy accept;
  oifname \"eth1\" ip saddr 10.0.0.0/8 masquerade
 }
}
table ip filter { chain input { type filter hook input priority filter; policy accept; } }
"""


class UbuntuFrrImportTests(TestCase):
    def candidate(self):
        return make_candidate(
            platform=models.Platform.UBUNTU_FRR, device_name="R3",
            target_type=models.DeviceIntentTargetType.EXISTING_DEVICE,
        )

    def factory(self, *, config=FRR_CONFIG):
        outputs = h.linux_outputs(
            interfaces={"eth1": ["192.0.2.3/31"]}, frr_config=config, nft=NFT_CONFIG,
        )
        return h.session_factory({"R3": outputs})

    def test_frr_import_populates_canonical_intent_and_round_trips_semantically(self):
        change, intent, revision = self.candidate()
        result = config_import_service.import_existing_device(
            change=change, intent=intent, revision=revision, device_name="R3", session_factory=self.factory(),
        )
        self.assertEqual(result.status, "imported")
        self.assertEqual(result.provenance["parser_version"], "ubuntu-frr-1.0")
        self.assertEqual(result.feature_counts["static_routes"], 1)
        self.assertEqual(result.feature_counts["routing_instances"], 2)
        self.assertEqual(result.feature_counts["nat_rules"], 1)

        revision.refresh_from_db()
        candidate = candidate_renderer.render(intent, revision)
        text = candidate["text"]
        # Feature-aware equivalence: syntax/order normalization is allowed,
        # but every supported semantic object must be present.
        for expected in (
            "hostnamectl set-hostname R3", "ip addr replace 192.0.2.3/31 dev eth1",
            "ip route 203.0.113.0/24 192.0.2.2 25", "router ospf",
            "ospf router-id 10.255.0.3", "router bgp 65003",
            "neighbor 192.0.2.2 remote-as 65002", "network 10.255.0.3/32",
            'oifname "eth1" ip saddr 10.0.0.0/8 masquerade',
        ):
            self.assertIn(expected, text)

        unmanaged = candidate["import_metadata"]["unmanaged"]
        self.assertTrue(any("Complete nftables ruleset" in block["label"] for block in unmanaged))
        self.assertTrue(any("route-map DIRECT" in block["text"] for block in unmanaged))
        self.assertTrue(any("redistribute connected" in block["text"] for block in unmanaged))
        self.assertNotIn("table ip filter", text)

    def test_reimport_replaces_prior_imported_objects_and_rediscovers_direct_change(self):
        change, intent, revision = self.candidate()
        config_import_service.import_existing_device(
            change=change, intent=intent, revision=revision, device_name="R3", session_factory=self.factory(),
        )
        changed = FRR_CONFIG.replace("description R2 transit", "description changed directly")
        result = config_import_service.import_existing_device(
            change=change, intent=intent, revision=revision, device_name="R3",
            session_factory=self.factory(config=changed),
        )
        self.assertEqual(result.status, "imported")
        revision.refresh_from_db()
        interfaces = interface_intent_service.ordered_interfaces(revision)
        self.assertEqual(len([row for row in interfaces if row["name"] == "eth1"]), 1)
        self.assertEqual(next(row for row in interfaces if row["name"] == "eth1")["description"], "changed directly")
