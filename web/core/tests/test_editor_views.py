"""Device Builder page behavior that is NOT a generic HTTP boundary.

Method / CSRF / draft-only / foreign-ID / escaping rules live in
``test_view_boundaries``; validator and renderer semantics live at service
level.  What remains here is what a page must actually show or do:
structure, Basic/Advanced parity, create flows, downloads/diff, platform
switching and the VLAN 200 guarantee.
"""

from __future__ import annotations

import json
from urllib.parse import parse_qs, urlsplit

from django.test import TestCase
from django.urls import reverse

from core import models
from core.services import change_service, interface_intent_service, intent_service, service_policy_intent_service
from core.tests.helpers.candidates import add_fhrp, add_instance, add_interface, commit, make_candidate


def edit_url(change, intent):
    return reverse("core:device_builder_edit", args=[change.change_id, intent.pk])


def advanced_url(change, intent, query=""):
    return reverse("core:device_builder_advanced", args=[change.change_id, intent.pk]) + query


class EditorPageTests(TestCase):
    def test_editor_page_structure_and_honest_labels(self):
        change, intent, _ = make_candidate()
        response = self.client.get(edit_url(change, intent))
        for fragment in (
            'class="device-builder-editor"', "device-builder-editor__left", "device-builder-editor__right",  # split screen
            "module-card", "Device Identity", "Interfaces &amp; Addressing", "Add Interface", "Add Static Route",
            "FHRP", "NAT", "Services · DHCP", "Security · ACLs", "Policy · PBR",  # major catalogue is real
            "data-candidate-preview", "Candidate Configuration",  # right-hand preview
            "data-copy-candidate", "Download Candidate", "Diff (Accepted vs Draft)",
            "no project/network-semantic validation has run", "Traffic-impact validation has not run",
        ):
            with self.subTest(fragment=fragment):
                self.assertContains(response, fragment)
        self.assertNotContains(response, "Available in a later phase")  # no decorative locked module
        self.assertContains(response, change.get_lifecycle_state_display())
        self.assertEqual(change.lifecycle_state, models.ChangeLifecycleState.DRAFT)

    def test_new_device_shows_image_reference_and_existing_device_does_not_require_it(self):
        _, new_intent, _ = make_candidate(device_name="N1")
        new_intent.target_type = models.DeviceIntentTargetType.NEW_DEVICE
        new_intent.save(update_fields=["target_type"])
        response = self.client.get(advanced_url(new_intent.change, new_intent))
        self.assertContains(response, 'data-field-path="device.image_reference"')

        change, intent, revision = make_candidate()
        response = self.client.post(
            reverse("core:device_builder_field_commit", args=[change.change_id, intent.pk]),
            data=json.dumps({"path": "device.image_reference", "value": "", "revisionId": revision.pk}),
            content_type="application/json",
        )
        self.assertTrue(response.json()["ok"])

    def test_capabilities_page_is_one_binary_matrix_covering_every_family(self):
        response = self.client.get(reverse("core:device_builder_capabilities"))
        self.assertEqual(response.status_code, 200)
        for fragment in (
            "arista_ceos", "interface.ROUTED_PHYSICAL", "routing.OSPFV2", "routing.BGP_IPV4",
            "service_policy.ACL_IPV4_EXTENDED", "service_policy.NAT_NAT_PT_STATIC", "SUPPORTED", "UNSUPPORTED",
        ):
            with self.subTest(fragment=fragment):
                self.assertContains(response, fragment)
        for obsolete in (
            "Routing Protocol Capabilities", "Service / Security / Policy Capabilities", "badge--info", "badge--neutral",
        ):
            with self.subTest(obsolete=obsolete):
                self.assertNotContains(response, obsolete)


class BasicAdvancedParityTests(TestCase):
    """Basic and Advanced are two views of the SAME DeviceIntent / revision / objects."""

    def test_basic_and_advanced_share_intent_revision_and_objects(self):
        change, intent, revision = make_candidate()
        interface = add_interface(revision, kind="SVI", name="Vlan10")
        fhrp = add_fhrp(revision, interface["id"])
        basic = self.client.get(edit_url(change, intent))
        advanced = self.client.get(advanced_url(change, intent))
        self.assertEqual(basic.context["intent"].pk, advanced.context["intent"].pk)
        self.assertEqual(basic.context["revision"].pk, advanced.context["revision"].pk)
        self.assertEqual(basic.context["selected_interface"]["id"], advanced.context["selected_interface"]["id"])
        for label, response in (("basic", basic), ("advanced", advanced)):
            with self.subTest(view=label):
                self.assertContains(response, fhrp["id"])
                self.assertContains(response, interface["id"])  # stable ID is rendered, not an array index

    def test_advanced_view_renders_stable_address_ids_and_controls(self):
        change, intent, revision = make_candidate()
        interface = add_interface(revision)
        address = interface_intent_service.add_address(revision=revision, interface_id=interface["id"])
        response = self.client.get(advanced_url(change, intent, f"?interface={interface['id']}"))
        for fragment in (address["id"], "Host CIDR", "WAN / Peer Metadata"):
            with self.subTest(fragment=fragment):
                self.assertContains(response, fragment)

    def test_a_commit_made_through_either_view_is_visible_in_the_other(self):
        change, intent, revision = make_candidate()
        commit(change, intent, revision, "device.hostname", "FROM-BASIC")
        self.assertContains(self.client.get(advanced_url(change, intent)), "FROM-BASIC")
        commit(change, intent, revision, "device.description", "FROM-ADVANCED-DESC")
        # Basic does not render the description inline, but the shared bootstrap state must reflect it.
        self.assertContains(self.client.get(edit_url(change, intent)), "FROM-ADVANCED-DESC")


class CreateFlowTests(TestCase):
    def test_explicit_posts_create_changes_and_intents_and_redirect_to_the_editor(self):
        response = self.client.post(reverse("core:device_builder_create_change"), {"title": "My draft"})
        self.assertIn(response.status_code, (301, 302))
        self.assertEqual(models.Change.objects.filter(title="My draft").count(), 1)

        response = self.client.post(
            reverse("core:device_builder_create_change"),
            {"title": "With device", "device_name": "R9", "platform": "arista_ceos", "target_type": "EXISTING_DEVICE"},
        )
        change = models.Change.objects.get(title="With device")
        intent = models.DeviceIntent.objects.get(change=change, device_name="R9")
        self.assertRedirects(response, edit_url(change, intent))

        bare = change_service.create_change(title="Bare change")
        response = self.client.post(
            reverse("core:device_builder_create_intent", args=[bare.change_id]),
            {"device_name": "R5", "platform": "sonic", "target_type": "NEW_DEVICE", "image_reference": "sonic:2024.05"},
        )
        added = models.DeviceIntent.objects.get(change=bare, device_name="R5")
        self.assertRedirects(response, edit_url(bare, added))
        self.assertIsNotNone(added.latest_revision())

    def test_change_detail_links_to_the_editor_and_renders_the_latest_revision(self):
        # Regression: a prior template used `|last` on a QuerySet (unsupported negative indexing).
        change, intent, _ = make_candidate()
        response = self.client.get(reverse("core:device_builder_change_detail", args=[change.change_id]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, edit_url(change, intent))
        self.assertContains(response, "R1")


class CandidateDownloadAndDiffTests(TestCase):
    def test_download_is_the_accepted_candidate_with_a_safe_filename_and_ignores_query_input(self):
        change, intent, revision = make_candidate()
        add_interface(revision)
        url = reverse("core:device_builder_candidate_download", args=[change.change_id, intent.pk])
        response = self.client.get(url + "?draft=1&file=../../etc/passwd")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"hostname R1", response.content)
        self.assertIn(b"interface Ethernet1", response.content)
        disposition = response["Content-Disposition"]
        self.assertRegex(disposition, r'filename="[A-Za-z0-9_-]+-candidate\.txt"')
        self.assertNotIn("..", disposition)
        self.assertNotIn("/", disposition)

    def test_diff_shows_draft_divergence_for_device_and_interface_fields(self):
        change, intent, revision = make_candidate()
        interface = add_interface(revision)
        url = reverse("core:device_builder_candidate_diff", args=[change.change_id, intent.pk])
        self.assertEqual(self.client.get(url).status_code, 200)
        intent_service.set_draft_field(revision=revision, path="device.hostname", draft_value="DIVERGED")
        revision.field_states.filter(path=f"interfaces.{interface['id']}.description").update(draft_value="if-draft", dirty=True)
        response = self.client.get(url)
        self.assertContains(response, "DIVERGED")
        self.assertContains(response, "if-draft")


class PlatformSwitchViewTests(TestCase):
    def test_switching_platform_warns_and_narrows_selectors_now_and_after_reload(self):
        change, intent, revision = make_candidate()
        add_interface(revision, kind="ACCESS")
        add_instance(revision, family="bgp", local_asn=65001)
        response = self.client.post(
            reverse("core:device_builder_field_commit", args=[change.change_id, intent.pk]),
            data=json.dumps({"path": "device.platform", "value": models.Platform.UBUNTU_FRR, "revisionId": revision.pk}),
            content_type="application/json",
        )
        data = response.json()
        self.assertTrue(data["platformWarning"])
        self.assertNotIn("ACCESS", {row["value"] for row in data["newInterfaceTypeChoices"]})
        self.assertTrue(data["routingFamilySelectable"]["bgp"])  # FRR supports BGP

        reloaded = self.client.get(edit_url(change, intent))
        self.assertContains(reloaded, "Some features are not supported")
        self.assertContains(reloaded, "Platform supports; project not implemented")

        sonic = self.client.post(
            reverse("core:device_builder_field_commit", args=[change.change_id, intent.pk]),
            data=json.dumps({"path": "device.platform", "value": "sonic", "revisionId": revision.pk}),
            content_type="application/json",
        )
        # Phase 20.5: SONiC now implements BGP (config_db BGP_GLOBALS/BGP_NEIGHBOR), so
        # it no longer demonstrates narrowing here; OSPF has no verified config_db
        # schema yet and remains the genuinely-not-selectable case for this platform.
        self.assertTrue(sonic.json()["routingFamilySelectable"]["bgp"])
        self.assertFalse(sonic.json()["routingFamilySelectable"]["ospf"])


class Vlan200ViewTests(TestCase):
    """VLAN 200 is static management: hidden in the UI AND refused server-side."""

    def test_vlan200_auto_and_dhcp_are_hidden_and_rejected(self):
        change, intent, revision = make_candidate()
        management = add_interface(revision, kind="MANAGEMENT", name="Vlan200")
        address = interface_intent_service.add_address(revision=revision, interface_id=management["id"])
        response = self.client.get(advanced_url(change, intent, f"?interface={management['id']}"))
        self.assertContains(response, "MANAGEMENT · STATIC")
        self.assertNotContains(response, '<option value="AUTO"')
        self.assertNotContains(response, "DHCPv6 reservation")
        self.assertContains(response, address["id"])

        self.client.post(
            reverse("core:device_builder_address_add", args=[change.change_id, intent.pk, management["id"]]),
            {"family": "IPV4", "source": "AUTO"},
        )
        revision.refresh_from_db()
        self.assertEqual(len(interface_intent_service.get_interface(revision, management["id"])["addresses"]), 1)

        redirect = self.client.post(
            reverse("core:device_builder_phase12_add", args=[change.change_id, intent.pk, "dhcp_client"]),
            {"family": "IPV4", "interface_id": management["id"]},
        )
        self.assertEqual(redirect.status_code, 302)
        revision.refresh_from_db()
        self.assertEqual(service_policy_intent_service.structured_sections(revision)["services"]["dhcp"]["clients"], {})
        self.assertNotIn("reservation", redirect.url.lower())


class BasicAddressingTests(TestCase):
    """Phase 20.5 (spec section 4): Basic exposes manual IPv4/IPv6 addressing
    on the SAME canonical address objects Advanced edits -- no second/parallel
    addressing model, and Basic <-> Advanced stay consistent."""

    def test_basic_shows_add_edit_and_remove_for_a_manual_address(self):
        change, intent, revision = make_candidate()
        eth = add_interface(revision, name="Ethernet1")
        response = self.client.get(edit_url(change, intent) + f"?interface={eth['id']}")
        self.assertContains(response, "Addressing (IPv4")
        self.assertContains(response, reverse("core:device_builder_address_add", args=[change.change_id, intent.pk, eth["id"]]))
        self.assertContains(response, "No addresses yet.")

        address = interface_intent_service.add_address(revision=revision, interface_id=eth["id"], family="IPV4", source="MANUAL")
        cidr_path = f"interfaces.{eth['id']}.addresses.{address['id']}.cidr"
        response = self.client.get(edit_url(change, intent) + f"?interface={eth['id']}")
        self.assertContains(response, address["id"])
        self.assertContains(response, f'data-field-path="{cidr_path}"')
        self.assertContains(response, "Remove Address")
        # Basic's simplified add-form never offers AUTO -- VLAN 200 / IPAM
        # complexity stays exclusive to Advanced.
        addressing_block = response.content.decode().split("Addressing (IPv4")[1].split("Remove Interface")[0]
        self.assertNotIn(">AUTO<", addressing_block)
        self.assertNotIn("AUTO (unresolved)", addressing_block)

    def test_basic_shows_an_auto_address_created_in_advanced_as_read_only(self):
        change, intent, revision = make_candidate()
        eth = add_interface(revision, name="Ethernet1")
        auto_address = interface_intent_service.add_address(revision=revision, interface_id=eth["id"], family="IPV4", source="AUTO")
        cidr_path = f"interfaces.{eth['id']}.addresses.{auto_address['id']}.cidr"
        response = self.client.get(edit_url(change, intent) + f"?interface={eth['id']}")
        self.assertContains(response, auto_address["id"])
        self.assertContains(response, "manage from Advanced")
        self.assertNotContains(response, f'data-field-path="{cidr_path}"')

    def test_an_address_added_in_basic_appears_correctly_in_advanced(self):
        change, intent, revision = make_candidate()
        eth = add_interface(revision, name="Ethernet1")
        response = self.client.post(
            reverse("core:device_builder_address_add", args=[change.change_id, intent.pk, eth["id"]]),
            {"family": "IPV4", "source": "MANUAL"},
            HTTP_REFERER=edit_url(change, intent) + f"?interface={eth['id']}",
        )
        self.assertEqual(response.status_code, 302)
        revision.refresh_from_db()
        address = next(iter(interface_intent_service.get_interface(revision, eth["id"])["addresses"].values()))
        self.assertEqual(address["source"], "MANUAL")

        advanced_response = self.client.get(advanced_url(change, intent, f"?interface={eth['id']}"))
        self.assertContains(advanced_response, "Detailed Addressing")
        self.assertContains(advanced_response, address["id"])
        self.assertContains(advanced_response, 'value="MANUAL" selected')

    def test_an_address_edited_in_advanced_appears_correctly_in_basic(self):
        change, intent, revision = make_candidate()
        eth = add_interface(revision, name="Ethernet1")
        address = interface_intent_service.add_address(revision=revision, interface_id=eth["id"], family="IPV4", source="MANUAL")
        cidr_path = f"interfaces.{eth['id']}.addresses.{address['id']}.cidr"
        self.client.post(
            reverse("core:device_builder_field_commit", args=[change.change_id, intent.pk]),
            data=json.dumps({"path": cidr_path, "value": "192.168.100.20/31", "revisionId": revision.pk}),
            content_type="application/json",
        )
        response = self.client.get(edit_url(change, intent) + f"?interface={eth['id']}")
        self.assertContains(response, "192.168.100.20/31")


def _query(url: str) -> dict:
    return {key: values[0] for key, values in parse_qs(urlsplit(url).query).items()}


class CollectionRedirectPreservesEditorStateTests(TestCase):
    """Phase 20.5 (spec section 3): a collection add/remove must return the
    operator to the same mode (Basic/Advanced) and the same
    interface/routing selection they were on, never silently drop them into
    Basic or reset an unrelated selection. See docs/DEVICE_BUILDER_FOUNDATION.md
    "Non-refresh editing model"."""

    def test_adding_an_interface_from_advanced_mode_stays_in_advanced_and_selects_the_new_interface(self):
        change, intent, revision = make_candidate()
        referer = advanced_url(change, intent)
        response = self.client.post(
            reverse("core:device_builder_interface_add", args=[change.change_id, intent.pk]),
            {"name": "Ethernet9", "kind": "ROUTED_PHYSICAL"},
            HTTP_REFERER=referer,
        )
        self.assertEqual(response.status_code, 302)
        self.assertTrue(urlsplit(response.url).path.endswith("/advanced/") or "advanced" in urlsplit(response.url).path)
        revision.refresh_from_db()
        new_id = next(
            item["id"] for item in interface_intent_service.ordered_interfaces(revision) if item["name"] == "Ethernet9"
        )
        self.assertEqual(_query(response.url).get("interface"), new_id)

    def test_adding_an_interface_from_basic_mode_stays_in_basic(self):
        change, intent, _ = make_candidate()
        referer = edit_url(change, intent)
        response = self.client.post(
            reverse("core:device_builder_interface_add", args=[change.change_id, intent.pk]),
            {"name": "Ethernet9", "kind": "ROUTED_PHYSICAL"},
            HTTP_REFERER=referer,
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            urlsplit(response.url).path, urlsplit(reverse("core:device_builder_edit", args=[change.change_id, intent.pk])).path
        )

    def test_removing_the_selected_interface_clears_its_selection_but_keeps_mode(self):
        change, intent, revision = make_candidate()
        eth = add_interface(revision, name="Ethernet1")
        referer = advanced_url(change, intent, f"?interface={eth['id']}")
        response = self.client.post(
            reverse("core:device_builder_interface_remove", args=[change.change_id, intent.pk, eth["id"]]),
            {"confirmation": "REMOVE"},
            HTTP_REFERER=referer,
        )
        self.assertEqual(response.status_code, 302)
        self.assertNotEqual(_query(response.url).get("interface"), eth["id"])
        self.assertIn(
            urlsplit(reverse("core:device_builder_advanced", args=[change.change_id, intent.pk])).path,
            urlsplit(response.url).path,
        )

    def test_adding_an_address_preserves_advanced_mode_and_the_current_interface(self):
        change, intent, revision = make_candidate()
        eth = add_interface(revision, name="Ethernet1")
        referer = advanced_url(change, intent, f"?interface={eth['id']}")
        response = self.client.post(
            reverse("core:device_builder_address_add", args=[change.change_id, intent.pk, eth["id"]]),
            {"family": "IPV4", "source": "MANUAL"},
            HTTP_REFERER=referer,
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(_query(response.url).get("interface"), eth["id"])
        self.assertIn(
            urlsplit(reverse("core:device_builder_advanced", args=[change.change_id, intent.pk])).path,
            urlsplit(response.url).path,
        )

    def test_adding_a_routing_instance_preserves_mode_family_and_selects_the_new_instance(self):
        change, intent, revision = make_candidate()
        referer = advanced_url(change, intent, "?routing_family=ospf")
        response = self.client.post(
            reverse("core:device_builder_routing_instance_add", args=[change.change_id, intent.pk, "ospf"]),
            {"version": "OSPFV2"},
            HTTP_REFERER=referer,
        )
        self.assertEqual(response.status_code, 302)
        query = _query(response.url)
        self.assertEqual(query.get("routing_family"), "ospf")
        self.assertIn(
            urlsplit(reverse("core:device_builder_advanced", args=[change.change_id, intent.pk])).path,
            urlsplit(response.url).path,
        )
        revision.refresh_from_db()
        self.assertIn(query.get("routing_instance"), revision.sections["routing"]["ospf"])

    def test_removing_the_selected_routing_instance_clears_instance_but_keeps_family_and_mode(self):
        change, intent, revision = make_candidate()
        ospf = add_instance(revision, family="ospf", version="OSPFV2")
        referer = advanced_url(change, intent, f"?routing_family=ospf&routing_instance={ospf['id']}")
        response = self.client.post(
            reverse("core:device_builder_routing_instance_remove", args=[change.change_id, intent.pk, "ospf", ospf["id"]]),
            {"confirmation": "REMOVE"},
            HTTP_REFERER=referer,
        )
        self.assertEqual(response.status_code, 302)
        query = _query(response.url)
        self.assertEqual(query.get("routing_family"), "ospf")
        self.assertNotEqual(query.get("routing_instance"), ospf["id"])
        self.assertIn(
            urlsplit(reverse("core:device_builder_advanced", args=[change.change_id, intent.pk])).path,
            urlsplit(response.url).path,
        )

    def test_a_neighbor_add_inside_a_selected_bgp_instance_preserves_that_selection(self):
        change, intent, revision = make_candidate()
        bgp = add_instance(revision, family="bgp", local_asn=65000)
        referer = advanced_url(change, intent, f"?routing_family=bgp&routing_instance={bgp['id']}")
        response = self.client.post(
            reverse("core:device_builder_bgp_neighbor_add", args=[change.change_id, intent.pk, bgp["id"]]),
            {"peer_address": "192.0.2.1", "remote_asn": "65001"},
            HTTP_REFERER=referer,
        )
        self.assertEqual(response.status_code, 302)
        query = _query(response.url)
        self.assertEqual(query.get("routing_family"), "bgp")
        self.assertEqual(query.get("routing_instance"), bgp["id"])

    def test_no_referer_defaults_to_basic_rather_than_crashing(self):
        change, intent, _ = make_candidate()
        response = self.client.post(
            reverse("core:device_builder_interface_add", args=[change.change_id, intent.pk]),
            {"name": "Ethernet9", "kind": "ROUTED_PHYSICAL"},
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            urlsplit(response.url).path, urlsplit(reverse("core:device_builder_edit", args=[change.change_id, intent.pk])).path
        )
