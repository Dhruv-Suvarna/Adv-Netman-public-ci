"""HTTP boundary contract for the Device Builder (the "view layer" of the test pyramid).

Each rule is asserted ONCE over every relevant endpoint as a labelled matrix
(``subTest(endpoint=...)``), instead of once per endpoint per phase:

    * mutation endpoints reject GET (405) and a POST without a CSRF token (403)
    * read-only pages reject POST (405)
    * an explicit POST adds exactly one object; removal needs the REMOVE word
    * a non-DRAFT Change is refused; another candidate's object IDs are rejected
    * unknown / foreign parents are 404; the commit endpoint's error statuses
    * (Phase 15) the health / precheck POST actions and pages are rows in the same tables
    * untrusted text is HTML-escaped on every surface that renders it

Internal semantics (validators, renderers, validation findings) are NOT
re-run through HTTP here -- they are covered at service level.  A new endpoint
joins the matching table below; it does not get its own copy of these tests.
"""

from __future__ import annotations

import json

from django.conf import settings
from core.tests.runner import OperatorClient  # V2 Phase 1: authenticated, MFA-verified operator
from django.test import TestCase
from django.urls import reverse

from core import models
from core.services import change_service, configlet_service, interface_intent_service
from core.services.health import persistence
from core.services.health.results import CheckResult
from core.tests.helpers.candidates import (
    add_bgp_neighbor,
    add_bgp_network,
    add_binding,
    add_fhrp,
    add_instance,
    add_interface,
    add_static_route,
    commit,
    make_candidate,
)

REMOVE = "REMOVE"
XSS = "<script>alert(1)</script>"


def object_ids(node) -> set[str]:
    """Every stable object ID anywhere in a revision's sections (interfaces, addresses, routes, ...)."""
    found: set[str] = set()
    if isinstance(node, dict):
        if isinstance(node.get("id"), str):
            found.add(node["id"])
        for value in node.values():
            found |= object_ids(value)
    elif isinstance(node, list):
        for value in node:
            found |= object_ids(value)
    return found


class CandidateEndpointFixture(TestCase):
    """One rich candidate (R1) so every mutation endpoint has a real target."""

    @classmethod
    def setUpTestData(cls):
        cls.change, cls.intent, cls.revision = make_candidate()
        rev = cls.revision
        cls.eth = add_interface(rev, name="Ethernet1")
        cls.svi = add_interface(rev, kind="SVI", name="Vlan10")
        cls.spare = add_interface(rev, name="Ethernet3")  # referenced by nothing, so it is removable
        cls.address = interface_intent_service.add_address(revision=rev, interface_id=cls.eth["id"])
        cls.route = add_static_route(rev)
        cls.ospf = add_instance(rev, family="ospf", version="OSPFV2")
        cls.binding = add_binding(rev, family="ospf", instance_id=cls.ospf["id"], interface_id=cls.eth["id"])
        cls.bgp = add_instance(rev, family="bgp", local_asn=65000)
        cls.neighbor = add_bgp_neighbor(rev, instance_id=cls.bgp["id"], peer_address="192.0.2.1", remote_asn=65001)
        cls.network = add_bgp_network(rev, instance_id=cls.bgp["id"], family="IPV4", cidr="192.0.2.0/24")
        cls.fhrp = add_fhrp(rev, cls.svi["id"])

    # -- helpers ---------------------------------------------------------------------------
    def url(self, name, *extra):
        return reverse(f"core:{name}", args=[self.change.change_id, self.intent.pk, *extra])

    def state(self):
        """Everything a mutation endpoint could change: objects, Changes, validation runs."""
        return (self.ids(), models.Change.objects.count(), models.ChangeValidationRun.objects.count())

    def ids(self, revision=None) -> set[str]:
        revision = revision or self.revision
        revision.refresh_from_db()
        return object_ids(revision.sections)

    # -- endpoint tables (label -> url [, payload]) ---------------------------------------
    def add_endpoints(self):
        """POST endpoints that add exactly one stable object."""
        return {
            "interface": (self.url("device_builder_interface_add"), {"name": "Ethernet2", "kind": "ROUTED_PHYSICAL"}),
            "address": (self.url("device_builder_address_add", self.eth["id"]), {"family": "IPV4", "source": "MANUAL"}),
            "static_route": (self.url("device_builder_static_route_add"), {"family": "IPV4"}),
            "ospf_instance": (self.url("device_builder_routing_instance_add", "ospf"), {"version": "OSPFV2"}),
            "bgp_instance": (self.url("device_builder_routing_instance_add", "bgp"), {"local_asn": "65100"}),
            "ospf_binding": (
                self.url("device_builder_routing_binding_add", "ospf", self.ospf["id"]), {"interface_id": self.svi["id"]},
            ),
            "bgp_neighbor": (
                self.url("device_builder_bgp_neighbor_add", self.bgp["id"]), {"peer_address": "192.0.2.9", "remote_asn": "65009"},
            ),
            "bgp_network": (
                self.url("device_builder_bgp_network_add", self.bgp["id"]), {"family": "IPV4", "cidr": "198.51.100.0/24"},
            ),
            "fhrp": (
                self.url("device_builder_phase12_add", "fhrp"),
                {"protocol": "VARP", "address_family": "IPV6", "interface_id": self.svi["id"]},
            ),
            "acl": (self.url("device_builder_phase12_add", "acl"), {"name": "NEW-ACL", "family": "IPV4", "acl_type": "EXTENDED"}),
        }

    def remove_endpoints(self):
        """POST endpoints that remove one stable object -> (url, removed object id)."""
        return {
            "interface": (self.url("device_builder_interface_remove", self.spare["id"]), self.spare["id"]),
            "address": (self.url("device_builder_address_remove", self.eth["id"], self.address["id"]), self.address["id"]),
            "static_route": (self.url("device_builder_static_route_remove", self.route["id"]), self.route["id"]),
            "ospf_binding": (
                self.url("device_builder_routing_binding_remove", "ospf", self.ospf["id"], self.binding["id"]), self.binding["id"],
            ),
            "bgp_neighbor": (
                self.url("device_builder_bgp_neighbor_remove", self.bgp["id"], self.neighbor["id"]), self.neighbor["id"],
            ),
            "bgp_network": (
                self.url("device_builder_bgp_network_remove", self.bgp["id"], self.network["id"]), self.network["id"],
            ),
            "ospf_instance": (self.url("device_builder_routing_instance_remove", "ospf", self.ospf["id"]), self.ospf["id"]),
            "fhrp": (self.url("device_builder_phase12_remove", "fhrp", self.fhrp["id"]), self.fhrp["id"]),
        }

    def mutation_urls(self) -> dict[str, str]:
        """Every state-changing POST endpoint, for the method / CSRF rules."""
        urls = {f"add:{k}": u for k, (u, _) in self.add_endpoints().items()}
        urls.update({f"remove:{k}": u for k, (u, _) in self.remove_endpoints().items()})
        urls.update({
            "field_commit": self.url("device_builder_field_commit"),
            "service_mode": self.url("device_builder_service_mode", "dhcp"),
            "ipam_prefixes": self.url("device_builder_ipam_prefixes", self.eth["id"], self.address["id"]),
            "create_change": reverse("core:device_builder_create_change"),
            "create_intent": reverse("core:device_builder_create_intent", args=[self.change.change_id]),
            "validation_run": reverse("core:change_validation_run", args=[self.change.change_id]),
            "plan_build": reverse("core:change_plan_build", args=[self.change.change_id]),
            # Phase 15: explicit, CSRF-protected, read-only operational actions
            "precheck_run": reverse("core:change_precheck_run", args=[self.change.change_id]),
            "health_fleet_snapshot": reverse("core:health_fleet_snapshot"),
            "health_device_deep": reverse("core:health_device_deep", args=["R1"]),
            # Phase 22: explicit, CSRF-protected, read-only IP connectivity check
            "health_device_connectivity": reverse("core:health_device_connectivity", args=["R1"]),
            # Phase 17: the ONLY endpoint that can reach the execution engine (explicit POST + CSRF)
            "execute_run": reverse("core:change_execute_run", args=[self.change.change_id]),
        })
        return urls


class MutationEndpointMethodAndCsrfTests(CandidateEndpointFixture):
    def test_mutations_reject_get(self):
        for label, url in self.mutation_urls().items():
            with self.subTest(endpoint=label):
                before = self.state()
                self.assertEqual(self.client.get(url).status_code, 405)
                self.assertEqual(self.state(), before)

    def test_mutations_require_csrf(self):
        strict = OperatorClient(enforce_csrf_checks=True)
        payloads = {label: data for label, (_, data) in self.add_endpoints().items()}
        for label, url in self.mutation_urls().items():
            with self.subTest(endpoint=label):
                before = self.state()
                data = payloads.get(label.removeprefix("add:"), {"title": "No CSRF"}) if label.startswith("add:") else {"title": "No CSRF"}
                self.assertEqual(strict.post(url, data).status_code, 403)
                self.assertEqual(self.state(), before)

    def test_read_only_pages_reject_post(self):
        read_only = {
            "changes_list": reverse("core:device_builder_changes"),
            "change_detail": reverse("core:device_builder_change_detail", args=[self.change.change_id]),
            "editor": self.url("device_builder_edit"),
            "advanced": self.url("device_builder_advanced"),
            "candidate_download": self.url("device_builder_candidate_download"),
            "candidate_diff": self.url("device_builder_candidate_diff"),
            "validation_page": reverse("core:change_validation", args=[self.change.change_id]),
            "plan_page": reverse("core:change_plan", args=[self.change.change_id]),
            "precheck_page": reverse("core:change_precheck", args=[self.change.change_id]),
            "health_fleet": reverse("core:health_fleet"),
            "health_device": reverse("core:health_device", args=["R1"]),
            "execute_page": reverse("core:change_execute", args=[self.change.change_id]),
            "executions_page": reverse("core:change_executions", args=[self.change.change_id]),
        }
        for label, url in read_only.items():
            with self.subTest(page=label):
                self.assertEqual(self.client.post(url).status_code, 405)

    def test_csrf_middleware_is_enabled(self):
        self.assertIn("django.middleware.csrf.CsrfViewMiddleware", settings.MIDDLEWARE)


class ExplicitAddRemoveTests(CandidateEndpointFixture):
    def test_explicit_post_adds_exactly_one_object(self):
        for label, (url, data) in self.add_endpoints().items():
            with self.subTest(endpoint=label):
                before = self.ids()
                response = self.client.post(url, data)
                self.assertEqual(response.status_code, 302)
                self.assertEqual(len(self.ids() - before), 1, "expected exactly one new stable object")

    def test_remove_needs_the_explicit_confirmation_word(self):
        for label, (url, target) in self.remove_endpoints().items():
            with self.subTest(endpoint=label):
                self.assertIn(target, self.ids())
                self.client.post(url, {"confirmation": "no"})
                self.assertIn(target, self.ids(), "an unconfirmed removal must keep the object")
                self.client.post(url, {"confirmation": REMOVE})
                self.assertNotIn(target, self.ids())

    def test_non_draft_change_refuses_every_add(self):
        self.change.lifecycle_state = models.ChangeLifecycleState.VALIDATED
        self.change.save(update_fields=["lifecycle_state", "updated_at"])
        for label, (url, data) in self.add_endpoints().items():
            with self.subTest(endpoint=label):
                before = self.ids()
                self.client.post(url, data)
                self.assertEqual(self.ids(), before)

    def test_arbitrary_routing_family_is_rejected_not_a_500(self):
        before = self.ids()
        response = self.client.post(self.url("device_builder_routing_instance_add", "not_a_real_family"), {})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.ids(), before)


class ForeignObjectRejectionTests(CandidateEndpointFixture):
    """A URL for candidate A must never reach candidate B's objects."""

    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        _, cls.foreign_intent, cls.foreign_revision = make_candidate(device_name="R2")
        rev = cls.foreign_revision
        cls.f_eth = add_interface(rev, name="Ethernet1")
        cls.f_svi = add_interface(rev, kind="SVI", name="Vlan20")
        cls.f_address = interface_intent_service.add_address(revision=rev, interface_id=cls.f_eth["id"])
        cls.f_ospf = add_instance(rev, family="ospf", version="OSPFV2")
        cls.f_fhrp = add_fhrp(rev, cls.f_svi["id"])
        cls.f_route = add_static_route(rev)

    def test_remove_with_a_foreign_object_id_changes_nothing(self):
        attempts = {
            "interface": self.url("device_builder_interface_remove", self.f_eth["id"]),
            "address": self.url("device_builder_address_remove", self.eth["id"], self.f_address["id"]),
            "ospf_instance": self.url("device_builder_routing_instance_remove", "ospf", self.f_ospf["id"]),
            "fhrp": self.url("device_builder_phase12_remove", "fhrp", self.f_fhrp["id"]),
        }
        for label, url in attempts.items():
            with self.subTest(endpoint=label):
                mine, foreign = self.ids(), self.ids(self.foreign_revision)
                self.client.post(url, {"confirmation": REMOVE})
                self.assertEqual(self.ids(), mine)
                self.assertEqual(self.ids(self.foreign_revision), foreign)

    def test_field_commit_with_a_foreign_object_path_is_forbidden(self):
        path = f"routing.static_routes.{self.f_route['id']}.destination"
        response = self.client.post(
            self.url("device_builder_field_commit"),
            data=json.dumps({"path": path, "value": "10.0.0.0/24"}), content_type="application/json",
        )
        self.assertEqual(response.status_code, 403)
        self.foreign_revision.refresh_from_db()
        self.assertEqual(self.foreign_revision.sections["routing"]["static_routes"][self.f_route["id"]].get("destination", ""), "")

    def test_an_intent_is_only_reachable_through_its_own_change(self):
        other_change = change_service.create_change(title="Other change")
        for label, url in {
            "editor": reverse("core:device_builder_edit", args=[other_change.change_id, self.intent.pk]),
            "commit": reverse("core:device_builder_field_commit", args=[other_change.change_id, self.intent.pk]),
        }.items():
            with self.subTest(endpoint=label):
                response = self.client.post(url, data=json.dumps({"path": "device.hostname", "value": "hijack"}), content_type="application/json") \
                    if label == "commit" else self.client.get(url)
                self.assertEqual(response.status_code, 404)

    def test_unknown_change_ids_are_404(self):
        for name in ("device_builder_change_detail", "change_validation", "change_plan", "change_precheck", "change_execute", "change_executions"):
            with self.subTest(route=name):
                self.assertEqual(self.client.get(reverse(f"core:{name}", args=["CHG-00000000-9999"])).status_code, 404)
        for name in ("change_validation_run", "change_plan_build", "change_precheck_run", "change_execute_run"):
            with self.subTest(route=f"{name} (POST)"):
                self.assertEqual(self.client.post(reverse(f"core:{name}", args=["CHG-00000000-9999"])).status_code, 404)


class FieldCommitEndpointContractTests(CandidateEndpointFixture):
    """Error-status vocabulary of the one mutation endpoint the browser calls."""

    def post(self, path, value, revision_id="current"):
        revision_id = self.revision.pk if revision_id == "current" else revision_id
        return self.client.post(
            self.url("device_builder_field_commit"),
            data=json.dumps({"path": path, "value": value, "revisionId": revision_id}), content_type="application/json",
        )

    def test_rejections_use_distinct_statuses(self):
        cases = {
            "unknown_path": (self.post("interfaces.Ethernet1.ipv4", "192.0.2.1/31"), 400),
            "stale_revision": (self.post("device.hostname", "R1", revision_id=999999), 409),
            "malformed_json": (self.client.post(self.url("device_builder_field_commit"), data="not json", content_type="application/json"), 400),
        }
        for label, (response, expected) in cases.items():
            with self.subTest(case=label):
                self.assertEqual(response.status_code, expected)

    def test_valid_commit_returns_the_authoritative_python_render(self):
        data = self.post("device.hostname", "R1-new").json()
        self.assertTrue(data["ok"])
        self.assertEqual(data["acceptedValue"], "R1-new")
        self.assertIn("hostname R1-new", data["candidate"]["text"])

    def test_invalid_commit_rolls_back_only_that_field_and_still_returns_the_candidate(self):
        obj = self.fhrp
        sibling = f"fhrp.instances.{obj['id']}.description"
        priority = f"fhrp.instances.{obj['id']}.priority"
        self.post(sibling, "gateway")
        data = self.post(priority, 999).json()
        self.assertEqual(data["validationState"], models.FieldValidationState.INVALID)
        self.assertIn("Candidate Configuration", data["candidate"]["text"])
        self.assertEqual(self.revision.field_states.get(path=sibling).accepted_value, "gateway")
        hostname = self.post("device.hostname", "%%%bad%%%").json()
        self.assertFalse(hostname["ok"])
        self.assertEqual((hostname["acceptedValue"], hostname["draftValue"]), ("R1", "R1"))


class EscapingBoundaryTests(TestCase):
    """Untrusted text is auto-escaped on every surface that renders it (never ``|safe``)."""

    def assert_escaped(self, response, *, must_render=True):
        self.assertNotContains(response, XSS)
        if must_render:  # prove the value really reached the page, so the check is not vacuous
            self.assertContains(response, "&lt;script&gt;")

    def test_untrusted_text_is_escaped_on_every_rendering_surface(self):
        def change_title_in_list():
            change_service.create_change(title=XSS)
            return reverse("core:device_builder_changes")

        def change_title_on_landing():
            change_service.create_change(title=XSS)
            return reverse("core:device_builder")

        def configlet_description_in_detail():
            change = change_service.create_change(title="Escape fixture")
            configlet_service.create_configlet(
                change=change, target_device="R1", feature_namespace=models.FeatureNamespace.INTERFACES,
                operation_type=models.ConfigletOperationType.CREATE_DEFINE,
                deployment_priority=models.DeploymentPriority.INTERFACE_CONSTRUCTION, description=XSS,
            )
            return reverse("core:device_builder_change_detail", args=[change.change_id])

        def committed(builder):
            def run():
                change, intent, revision = make_candidate()
                path = builder(revision)
                commit(change, intent, revision, path, XSS)
                return reverse("core:device_builder_advanced", args=[change.change_id, intent.pk])
            return run

        def change_title_on_precheck_page():
            change = change_service.create_change(title=XSS)
            return reverse("core:change_precheck", args=[change.change_id])

        def change_title_on_execute_page():
            change = change_service.create_change(title=XSS)
            return reverse("core:change_execute", args=[change.change_id])

        def stored_run_message_on_run_page():
            run = persistence.record_run(
                mode="DEVICE_DEEP", status="UNKNOWN", device="R1", actor="tester",
                results=[CheckResult("DEVICE_UNREACHABLE", "UNKNOWN", "R1", XSS, "LIVE", observed={"note": XSS}, subject=XSS)],
            )
            return reverse("core:health_run", args=[run.run_id])

        cases = {
            "change title (precheck page)": change_title_on_precheck_page,
            "change title (execute page)": change_title_on_execute_page,
            "stored health result message / subject (run page)": stored_run_message_on_run_page,
            "change title (list)": change_title_in_list,
            "change title (landing)": change_title_on_landing,
            # The detail page does not render descriptions today; the raw-markup check still guards a future template.
            "configlet description (change detail)": configlet_description_in_detail,
            "device description": committed(lambda rev: "device.description"),
            "interface description": committed(lambda rev: f"interfaces.{add_interface(rev)['id']}.description"),
            "static route description": committed(lambda rev: f"routing.static_routes.{add_static_route(rev)['id']}.description"),
            "FHRP description": committed(
                lambda rev: f"fhrp.instances.{add_fhrp(rev, add_interface(rev, kind='SVI', name='Vlan10')['id'])['id']}.description"
            ),
        }
        not_rendered_today = {"configlet description (change detail)"}
        for label, build in cases.items():
            with self.subTest(surface=label):
                self.assert_escaped(self.client.get(build()), must_render=label not in not_rendered_today)
