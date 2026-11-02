"""Lab 7 closure -- the V2 Phase 4 management surface, each new public function called directly.

* ``management.vrf`` helpers (empty / section / present / binding_for / render / problems / sonic_config_db /
  capability_matrix) and ``validation.management_vrf.validate_management_vrf`` against a minimal validation context;
* ``validation.context.DeviceModel.management``;
* the cEOS executor's ``structural_commands`` flattening;
* the management pages and POST actions (``management_views``) through the Django test client, with the existing RBAC and
  CSRF conventions, plus the view helpers ``_Codes`` / ``device_summary`` / ``editor_context``;
* the ``nmas_management`` command (read-only subcommands and the actor permission check);
* bootstrap credential retirement helpers (``bootstrap_session`` / ``target`` / ``session_username`` / ``status`` /
  ``cancel`` / ``_Keys``), the ``BootstrapCredentialTransition`` model guards and ``FileSecretProvider.retire``.

NEGATIVE cases: absent / malformed intent, unsupported platforms, unbound VRFs, a binding that would move the device's
management address, self-approval, blank reasons, revoked attachments, unknown devices, unknown collections, actors
without the permission, a device without a verified bootstrap, closed transitions and pending provider replacements.
No device is contacted: the probe transport, the SSH session and the enrollment provider are in-memory or temporary.
"""

from __future__ import annotations

import io
import json
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from django.core.management import CommandError, call_command
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse

from core import management_views as views
from core import models
from core.services.execution.executors import ceos
from core.services.management import bootstrap_credentials as B, capability_evidence, paths, probes, selector, vrf
from core.services.validation import management_vrf as validation
from core.services.validation.context import DeviceModel
from core.tests.helpers import lifecycle as L
from core.tests.helpers import management as M
from core.tests.helpers.validation import Dev, new_change
from core.tests.test_bootstrap_retirement import BcredMixin
from core.tests.test_lifecycle_views import user_client
from modules.device_credentials import FileSecretProvider, SecretConflict, SecretNotFound

S = models.BootstrapCredentialState


def intent(*, bound=True, services=("SSH",), address="10.99.0.1/30", kind="ROUTED_PHYSICAL", name="MGMT"):
    """(management, interfaces) in the stored intent shape."""
    interfaces = {"if1": {"id": "if1", "name": "Ethernet5", "kind": kind,
                          "addresses": {"a1": {"id": "a1", "cidr": address}} if address else {}}}
    management = {"vrfs": {"v1": {"id": "v1", "name": name, "description": ""}},
                  "bindings": {"b1": {"id": "b1", "vrf_id": "v1", "interface_id": "if1"}} if bound else {},
                  "routes": {"r1": {"id": "r1", "vrf_id": "v1", "family": "IPV4", "destination": "0.0.0.0/0", "next_hop": "10.99.0.2"}},
                  "services": {f"s{i}": {"id": f"s{i}", "vrf_id": "v1", "service": kind_, "host": "", "source_interface_id": ""} for i, kind_ in enumerate(services)}}
    return management, interfaces


class _Ctx:
    def __init__(self, devices, inventory=None):
        self.model = SimpleNamespace(devices=devices)
        self.inventory = inventory or {}
        self.findings = []

    def add(self, code, message, **fields):
        self.findings.append((getattr(code, "value", code), message, fields))

    def codes(self):
        return [code for code, _m, _f in self.findings]


def device(management, interfaces, platform="arista_ceos"):
    return DeviceModel(name="R1", platform=platform, target_type="device", entry={"management": management, "interfaces": interfaces})


class VrfHelperClosureTests(SimpleTestCase):
    def test_empty_returns_the_four_collections(self):
        self.assertEqual(vrf.empty(), {"vrfs": {}, "bindings": {}, "routes": {}, "services": {}})

    def test_section_of_malformed_or_missing_management_is_empty(self):
        self.assertEqual(vrf.section(SimpleNamespace(sections={"management": {"vrfs": "not-a-dict", "bindings": []}})), vrf.empty())
        self.assertEqual(vrf.section(SimpleNamespace(sections=None)), vrf.empty())

    def test_present_of_none_or_empty_management_is_false(self):
        self.assertFalse(vrf.present(None))
        self.assertFalse(vrf.present(vrf.empty()))

    def test_binding_for_returns_the_bound_vrf_name(self):
        management, _ifaces = intent()
        self.assertEqual(vrf.binding_for(management, "if1"), "MGMT")

    def test_binding_for_unbound_interface_or_missing_vrf_is_blank(self):
        management, _ifaces = intent()
        self.assertEqual(vrf.binding_for(management, "if9"), "")
        management["vrfs"] = {}
        self.assertEqual(vrf.binding_for(management, "if1"), "")

    def test_rendering_without_management_or_unknown_platform_off_definitions_is_empty(self):
        self.assertEqual(vrf.render("arista_ceos", "definitions", None), [])
        management, _ifaces = intent()
        self.assertEqual(vrf.render("juniper_junos", "services", management), [])
        self.assertTrue(vrf.render("juniper_junos", "definitions", management)[0]["text"].startswith(vrf.UNSUPPORTED))

    def test_problems_of_a_complete_intent_returns_nothing_to_fix(self):
        management, interfaces = intent()
        self.assertEqual(vrf.problems("arista_ceos", management, list(interfaces.values())), [])

    def test_sonic_config_db_returns_mgmt_vrf_config_for_the_builtin_vrf(self):
        management, _ifaces = intent(bound=False, name="mgmt")
        management["routes"], management["services"] = {}, {}
        unsupported = []
        self.assertEqual(vrf.sonic_config_db(management, unsupported), {"MGMT_VRF_CONFIG": {"vrf_global": {"mgmtVrfEnabled": "true"}}})
        self.assertEqual(unsupported, [])

    def test_capability_matrix_without_live_evidence_never_claims_execution_or_live(self):
        with mock.patch.dict(capability_evidence.LIVE, {}, clear=True):
            matrix = vrf.capability_matrix(live_evidence={})
        self.assertEqual({row["execute"] for row in matrix["arista_ceos"].values()}, {"NOT_IMPLEMENTED"})
        self.assertEqual({row["live_verified"] for rows in matrix.values() for row in rows.values()}, {"NOT_VERIFIED"})
        self.assertEqual({row["render"] for row in matrix["juniper_junos"].values()}, {"OUT_OF_SCOPE"})

    def test_device_model_management_returns_the_intent_or_empty(self):
        management, interfaces = intent()
        self.assertEqual(device(management, interfaces).management, management)
        self.assertEqual(DeviceModel(name="R2", platform="arista_ceos", target_type="device", entry={}).management, {})

    def test_structural_commands_returns_exit_after_each_nested_section(self):
        self.assertEqual(ceos.structural_commands(["management api gnmi", "   transport grpc MGMT", "      vrf MGMT", "end"]),
                         ["management api gnmi", "transport grpc MGMT", "vrf MGMT", "exit", "exit"])


    def test_structural_commands_of_empty_or_wrapper_only_input_is_empty(self):
        self.assertEqual(ceos.structural_commands([]), [])
        self.assertEqual(ceos.structural_commands(["configure", "end", "   "]), [])


class ValidateManagementVrfClosureTests(SimpleTestCase):
    def test_validate_management_vrf_complete_eos_intent_passes(self):
        ctx = _Ctx({"R1": device(*intent())})
        validation.validate_management_vrf(ctx)
        self.assertEqual(ctx.findings, [])

    def test_validate_management_vrf_unbound_unsupported_and_management_move_blocks(self):
        ctx = _Ctx({"R1": device(*intent(bound=False, services=("NETCONF",)))})
        validation.validate_management_vrf(ctx)
        self.assertTrue({"MGMT_VRF_UNBOUND", "MGMT_VRF_FEATURE_UNSUPPORTED"} <= set(ctx.codes()))
        moving = _Ctx({"R1": device(*intent())}, inventory={"network_devices": {"R1": {"monitoring_address": "10.99.0.1"}}})
        validation.validate_management_vrf(moving)
        self.assertEqual(moving.codes(), ["MGMT_VRF_MOVES_MANAGEMENT_ADDRESS"])
        other = _Ctx({"R1": device(*intent(), platform="ubuntu_frr")})
        validation.validate_management_vrf(other)
        self.assertIn("MGMT_VRF_EXECUTION_NOT_IMPLEMENTED", other.codes())


@override_settings(NMAS_MGMT_MIN_PROBE_INTERVAL_SECONDS=0)
class ManagementViewClosureTests(TestCase):
    def setUp(self):
        self.operator = user_client("olivia", "NMAS Operator")
        self.approver = user_client("arthur", "NMAS Approver")
        self.viewer = user_client("vera", "NMAS Viewer")
        self.lab = M.lab()
        self.r1 = self.lab["devices"]["R1"]
        patcher = M.fake_credentials()
        patcher.start()
        self.addCleanup(patcher.stop)

    def attachment(self, verify=True):
        return M.nmas_attachment(name="nmas-b", interface="nmas-b", upstream="S1", source="10.77.0.10", network="10.77.0.0/24",
                                 domain="rack-b", verify=verify)

    def oob(self):
        return M.path(self.r1, self.lab["nmas"], attachment=self.lab["oob"])

    def test_codes_wrapper_ok_without_blockers(self):
        wrapped = views._Codes([])
        self.assertEqual((wrapped.ok, wrapped.codes), (True, []))

    def test_codes_wrapper_with_blockers_is_refused(self):
        wrapped = views._Codes([{"code": "MGMT_NO_USABLE_PATH"}])
        self.assertEqual((wrapped.ok, wrapped.codes), (False, ["MGMT_NO_USABLE_PATH"]))

    def test_device_summary_returns_paths_and_approved_count(self):
        path = self.oob()
        summary = views.device_summary(self.r1)
        self.assertEqual(([p.pk for p in summary["paths"]], summary["approved"]), ([path.pk], 1))

    def test_device_summary_without_paths_is_legacy_and_empty(self):
        summary = views.device_summary(self.r1)
        self.assertEqual((summary["paths"], summary["approved"], summary["state"], summary["endpoint"].source), ([], 0, None, "LEGACY"))

    def test_management_overview_page_renders_spof_attachments_and_capability(self):
        response = self.viewer.get(reverse("core:management_overview"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Single points of failure")
        self.assertContains(response, "Capability")

    def test_management_device_unknown_device_not_found(self):
        self.assertEqual(self.viewer.get(reverse("core:management_device", args=["DEV-999999"])).status_code, 404)

    def test_management_device_json_unevaluated_paths_report_blocked_not_usable(self):
        self.oob()
        doc = self.viewer.get(reverse("core:management_device_json", args=[self.r1.device_id])).json()
        self.assertEqual((doc["endpoint"]["source"], doc["endpoint"]["codes"]), ("BLOCKED", ["MGMT_NO_USABLE_PATH"]))
        self.assertEqual(self.viewer.get(reverse("core:management_device_json", args=["DEV-999999"])).status_code, 404)

    def test_management_attachment_approve_by_its_registrant_refused(self):
        result = paths.register_nmas_attachment(name="nmas-c", host_interface="nmas-c", upstream_device="S1", source_address="10.78.0.10",
                                                network="10.78.0.0/24", actor="olivia")
        response = self.operator.post(reverse("core:management_attachment_approve", args=[result.attachment.attachment_id]))
        self.assertEqual(response.status_code, 403)          # an Operator lacks Approve; the approver who registered it:
        own = paths.register_nmas_attachment(name="nmas-d", host_interface="nmas-d", upstream_device="S1", source_address="10.79.0.10",
                                             network="10.79.0.0/24", actor="arthur")
        response = self.approver.post(reverse("core:management_attachment_approve", args=[own.attachment.attachment_id]))
        self.assertIn("MGMT_PATH_SELF_APPROVAL", response.url)

    def test_management_attachment_observe_records_a_read_only_observation(self):
        attachment = self.attachment(verify=False)
        response = self.operator.post(reverse("core:management_attachment_observe", args=[attachment.attachment_id]))
        self.assertNotIn("codes=", response.url)
        attachment.refresh_from_db()
        self.assertIsNotNone(attachment.observed_at)
        self.assertEqual(attachment.observation["source"], "sysfs+iproute2 (read-only)")

    def test_management_attachment_observe_revoked_or_unknown_refused(self):
        attachment = self.attachment()
        paths.revoke_nmas_attachment(attachment, actor="arthur", reason="gone")
        self.assertIn("MGMT_PATH_REVOKED", self.operator.post(reverse("core:management_attachment_observe", args=[attachment.attachment_id])).url)
        self.assertEqual(self.operator.post(reverse("core:management_attachment_observe", args=["NMA-999999"])).status_code, 404)

    def test_management_attachment_revoke_with_reason_succeeds(self):
        attachment = self.attachment()
        response = self.approver.post(reverse("core:management_attachment_revoke", args=[attachment.attachment_id]), {"reason": "rewired"})
        self.assertNotIn("codes=", response.url)
        attachment.refresh_from_db()
        self.assertEqual(attachment.approval_state, models.ManagementApproval.REVOKED)

    def test_management_attachment_revoke_without_reason_refused(self):
        attachment = self.attachment()
        response = self.approver.post(reverse("core:management_attachment_revoke", args=[attachment.attachment_id]), {"reason": ""})
        self.assertIn("REASON_REQUIRED", response.url)

    def test_management_path_register_without_attachment_or_host_key_refused(self):
        data = {"path_type": models.ManagementPathType.DIRECT_OOB, "endpoint_address": "192.168.200.1",
                "nmas_attachment_id": self.lab["nmas"].pk, "credential_source": models.ManagementCredentialSource.INVENTORY,
                "credential_reference": "R1"}
        response = self.operator.post(reverse("core:management_path_register", args=[self.r1.device_id]), data)
        self.assertIn("codes=", response.url)
        self.assertFalse(models.ManagementPath.objects.filter(device=self.r1).exists())

    def test_management_path_approve_by_its_registrant_refused(self):
        direct = M.nmas_attachment(name="nmas-vrf", interface="nmas-vrf", upstream="R1", source="10.30.0.2",
                                   network="10.30.0.0/30", domain="direct-vrf")
        result = paths.register_path(self.r1, path_type=models.ManagementPathType.ROUTED_VRF, endpoint_address="10.30.0.1", vrf="MGMT",
                                     nmas_attachment_id=direct.pk, credential_source=models.ManagementCredentialSource.INVENTORY,
                                     credential_reference="R1", expected_host_key=M.HOST_KEY, actor="arthur")
        self.assertTrue(result.ok, result.codes)
        response = self.approver.post(reverse("core:management_path_approve", args=[self.r1.device_id, result.path.path_id]))
        self.assertIn("MGMT_PATH_SELF_APPROVAL", response.url)

    def test_management_path_revoke_without_reason_refused(self):
        path = self.oob()
        response = self.approver.post(reverse("core:management_path_revoke", args=[self.r1.device_id, path.path_id]), {"reason": ""})
        self.assertIn("REASON_REQUIRED", response.url)

    def test_management_evaluate_unreachable_paths_report_no_usable_path(self):
        self.oob()
        with mock.patch.object(probes, "ParamikoTransport", lambda: M.FakeTransport(lambda address, source: (3, "L3_UNREACHABLE"))):
            response = self.operator.post(reverse("core:management_evaluate", args=[self.r1.device_id]))
        self.assertIn("MGMT_NO_USABLE_PATH", response.url)

    def reconciliation_required(self):
        state = selector.state_for(self.r1)
        selector._save_state(state, reconciliation_required=True, reconciliation_reason="path changed under RUN-000001")

    def test_management_reconcile_with_reason_clears_the_flag(self):
        self.reconciliation_required()
        response = self.approver.post(reverse("core:management_reconcile", args=[self.r1.device_id]), {"reason": "config re-read"})
        self.assertNotIn("codes=", response.url)
        self.assertFalse(selector.state_for(self.r1).reconciliation_required)

    def test_management_reconcile_without_reason_refused(self):
        self.reconciliation_required()
        response = self.approver.post(reverse("core:management_reconcile", args=[self.r1.device_id]), {"reason": ""})
        self.assertIn("REASON_REQUIRED", response.url)
        self.assertTrue(selector.state_for(self.r1).reconciliation_required)


class DeviceBuilderClosureTests(TestCase):
    def setUp(self):
        self.operator = user_client("olivia", "NMAS Operator")
        self.dev = Dev(new_change(), "R1")
        self.port = self.dev.iface("Ethernet5")
        self.dev.address(self.port, "10.99.0.1/30")

    def test_editor_context_returns_vrf_names_and_eos_capability(self):
        revision = self.dev.refresh()
        mvrf = vrf.add_vrf(revision, name="MGMT")
        context = views.editor_context(self.dev.intent, self.dev.refresh())
        self.assertEqual(context["management_vrf_names"], {mvrf["id"]: "MGMT"})
        self.assertIn("VRF_DEFINE", context["management_capability"])
        self.assertEqual(context["management_host_services"], ["NTP", "SYSLOG"])

    def test_editor_context_without_management_is_empty(self):
        context = views.editor_context(self.dev.intent, self.dev.refresh())
        self.assertEqual((context["management"], context["management_vrf_names"]), (vrf.empty(), {}))

    def test_device_builder_management_remove_unknown_object_or_kind_refused(self):
        url = reverse("core:device_builder_management_remove", args=[self.dev.change.change_id, self.dev.intent.pk, "vrf", "mvrf_unknown"])
        response = self.operator.post(url)
        self.assertEqual(response.status_code, 302)
        self.assertIn("MGMT", response.url)
        bad = reverse("core:device_builder_management_remove", args=[self.dev.change.change_id, self.dev.intent.pk, "telnet", "x"])
        self.assertEqual(self.operator.post(bad).status_code, 404)


class CommandClosureTests(TestCase):
    def setUp(self):
        user_client("erin", "NMAS Executor")
        user_client("vera", "NMAS Viewer")
        self.lab = M.lab()

    def run_command(self, *args):
        out = io.StringIO()
        call_command("nmas_management", *args, stdout=out)
        return json.loads(out.getvalue())

    def test_command_handle_read_only_subcommands_return_json(self):
        self.assertEqual(self.run_command("spof")["blockers"][0]["code"], "NMAS_SINGLE_ATTACHMENT")
        self.assertFalse(self.run_command("telemetry")["telemetry_follows_failover"])
        capability = self.run_command("capability")
        self.assertEqual([row["key"] for row in capability["lifecycle"]],
                         ["lifecycle.CREDENTIAL_ONBOARDING", "lifecycle.MGMT_VRF", "lifecycle.MGMT_FAILOVER"])
        self.assertEqual(self.run_command("status", "--device", "R1")["devices"][0]["status"], "LEGACY")
        self.assertEqual(self.run_command("recover", "--actor", "erin"), {"repairs": []})

    def test_command_add_arguments_registers_every_subcommand(self):
        from core.management.commands.nmas_management import Command

        parser = Command().create_parser("manage.py", "nmas_management")
        self.assertEqual(parser.parse_args(["evaluate", "--all", "--actor", "erin"]).action, "evaluate")

    def test_command_handle_actor_without_permission_or_unknown_target_refused(self):
        with self.assertRaisesMessage(CommandError, "--actor must be an active user holding core."):
            call_command("nmas_management", "recover", "--actor", "vera", stdout=io.StringIO())
        with self.assertRaisesMessage(CommandError, "unknown managed device"):
            call_command("nmas_management", "status", "--device", "NOPE", stdout=io.StringIO())
        with self.assertRaisesMessage(CommandError, "expected BCRED-NNNNNN"):
            call_command("nmas_management", "bcred-execute", "--transition", "42", "--actor", "erin", stdout=io.StringIO())


class BootstrapRetirementClosureTests(BcredMixin, TestCase):
    def test_bootstrap_session_returns_the_verified_enrollment_session(self):
        self.assertEqual(B.bootstrap_session(self.device).pk, self.session.pk)

    def test_bootstrap_session_none_for_a_device_without_ztp(self):
        other = M.lab()["devices"]["R1"]
        self.assertIsNone(B.bootstrap_session(other))

    def test_session_username_returns_the_enrollment_account(self):
        self.assertEqual(B.session_username(), "nmas-enroll")

    def test_target_returns_the_enrollment_address_and_pinned_key(self):
        row = self.approved()
        self.assertEqual(B.target(row), (self.session.reserved_address, 22, self.session.enrolled_host_key))

    def test_target_of_a_transition_without_path_never_uses_another_address(self):
        row = self.approved()
        row.path_id = None
        address, port, host_key = B.target(row)
        self.assertNotEqual(address, "")
        self.assertEqual((address, host_key), (self.session.reserved_address, self.session.enrolled_host_key))
        self.assertNotIn(address, ("127.0.0.1", "172.20.20.1"))

    def test_status_returns_steps_and_the_complete_flag(self):
        row = self.approved()
        self.execute(row)
        row.refresh_from_db()
        doc = B.status(row)
        self.assertEqual((doc["state"], doc["complete"], doc["id"]), (S.COMPLETE, True, row.transition_id))

    def test_status_of_a_failed_transition_is_not_complete(self):
        self.eos.fail["unreachable"] = True
        row = self.approved()
        self.execute(row)
        row.refresh_from_db()
        doc = B.status(row)
        self.assertFalse(doc["complete"])
        self.assertNotIn("PRIVATE", json.dumps(doc))

    def test_cancel_without_reason_or_after_completion_refused(self):
        row = self.approved()
        self.assertEqual(B.cancel(row, actor=L.OPERATOR, reason="").codes, ["REASON_REQUIRED"])
        self.execute(row)
        row.refresh_from_db()
        self.assertEqual(B.cancel(row, actor=L.OPERATOR, reason="late").codes, ["BCRED_STATE_INVALID"])

    def test_keys_bootstrap_returns_the_provider_held_enrollment_key(self):
        row = self.approved()
        key = B._Keys.bootstrap(row)
        self.assertEqual(key.get_base64(), self.session.enrollment_public_key.split()[1])

    def test_keys_bootstrap_after_retirement_unavailable(self):
        row = self.approved()
        provider = __import__("core.services.ztp.management", fromlist=["secret_provider"]).secret_provider()
        provider.retire(row.bootstrap_key_reference, provider.current(row.bootstrap_key_reference).version)
        with self.assertRaises(Exception) as caught:
            B._Keys.bootstrap(row)
        self.assertIsInstance(caught.exception, SecretNotFound)

    def test_keys_replacement_returns_the_service_key_from_the_provider(self):
        row = self.approved()
        sentinel = object()
        with mock.patch("modules.device_credentials.load_ssh_private_key", return_value=sentinel) as loader:
            self.assertIs(B._Keys.replacement(row), sentinel)
        loader.assert_called_once_with(self.credential.ssh_key_ref)

    def test_keys_replacement_missing_from_the_provider_raises(self):
        row = self.approved()
        with mock.patch("modules.device_credentials.load_ssh_private_key", side_effect=SecretNotFound("absent")):
            with self.assertRaises(SecretNotFound):
                B._Keys.replacement(row)

    def test_transition_id_and_is_open_returns_identity_and_state(self):
        row = self.approved()
        self.assertEqual(row.transition_id, f"BCRED-{row.pk:06d}")
        self.assertTrue(row.is_open)
        self.assertEqual(models.BootstrapCredentialTransition(device=self.device).transition_id, "BCRED-NEW")

    def test_transition_save_accepts_a_state_change_of_an_open_transition(self):
        row = self.approved()
        row.reason = "operator note"
        row.save()
        self.assertEqual(models.BootstrapCredentialTransition.objects.get(pk=row.pk).reason, "operator note")

    def test_transition_save_of_immutable_fields_or_closed_history_refused(self):
        row = self.approved()
        fresh = models.BootstrapCredentialTransition.objects.get(pk=row.pk)
        fresh.replacement_username = "someone-else"
        with self.assertRaises(ValueError):
            fresh.save()
        fresh = models.BootstrapCredentialTransition.objects.get(pk=row.pk)
        fresh.bootstrap_key_fingerprint = "md5:00"
        with self.assertRaises(ValueError):
            fresh.save()
        B.cancel(row, actor=L.OPERATOR, reason="stop")
        closed = models.BootstrapCredentialTransition.objects.get(pk=row.pk)
        closed.reason = "rewrite history"
        with self.assertRaises(ValueError):
            closed.save()

    def test_transition_rows_raise_on_delete(self):
        row = self.approved()
        with self.assertRaises(ValueError):
            row.delete()
        self.assertTrue(models.BootstrapCredentialTransition.objects.filter(pk=row.pk).exists())


@override_settings(NMAS_MGMT_MIN_PROBE_INTERVAL_SECONDS=0)
class BcredViewClosureTests(BcredMixin, TestCase):
    def setUp(self):
        super().setUp()
        self.operator = user_client("olivia", "NMAS Operator")
        self.approver = user_client("arthur", "NMAS Approver")
        self.executor = user_client("erin", "NMAS Executor")

    def url(self, name, *extra):
        return reverse(f"core:{name}", args=[self.device.device_id, *extra])

    def planned(self):
        response = self.operator.post(self.url("bcred_plan"), {"replacement_credential_id": str(self.credential.pk), "reason": "retire"})
        self.assertNotIn("codes=", response.url, response.url)
        return self.device.bootstrap_credential_transitions.get()

    def test_bcred_plan_records_a_planned_transition(self):
        self.assertEqual(self.planned().state, S.PLANNED)
        page = self.operator.get(self.url("management_device"))
        self.assertContains(page, "Bootstrap credential retirement")
        self.assertNotContains(page, "PRIVATE KEY")

    def test_bcred_approve_with_the_bound_digest_succeeds(self):
        row = self.planned()
        response = self.approver.post(self.url("bcred_approve", row.transition_id), {"digest": row.binding_digest})
        self.assertNotIn("codes=", response.url)
        row.refresh_from_db()
        self.assertEqual(row.state, S.APPROVED)

    def test_bcred_approve_wrong_digest_refused(self):
        row = self.planned()
        response = self.approver.post(self.url("bcred_approve", row.transition_id), {"digest": "0" * 64})
        self.assertIn("BCRED_DIGEST_MISMATCH", response.url)

    def test_bcred_cancel_with_reason_succeeds(self):
        row = self.planned()
        response = self.approver.post(self.url("bcred_cancel", row.transition_id), {"reason": "postponed"})
        self.assertNotIn("codes=", response.url)
        row.refresh_from_db()
        self.assertEqual(row.state, S.CANCELLED)

    def test_bcred_cancel_without_reason_refused(self):
        row = self.planned()
        self.assertIn("REASON_REQUIRED", self.approver.post(self.url("bcred_cancel", row.transition_id), {"reason": ""}).url)
        self.assertEqual(self.approver.post(self.url("bcred_cancel", "BCRED-999999"), {"reason": "x"}).status_code, 404)

    def test_bcred_execute_completes_after_proof(self):
        row = self.approved()
        real = B.execute
        with mock.patch.object(B, "execute", lambda transition, actor: real(transition, actor=actor, connect=self.eos.connect, keys=self.keys)):
            response = self.executor.post(self.url("bcred_execute", row.transition_id))
        self.assertNotIn("codes=", response.url, response.url)
        row.refresh_from_db()
        self.assertEqual(row.state, S.COMPLETE)
        self.assertFalse(self.secret_present())

    def test_bcred_execute_unapproved_refused_and_nothing_sent(self):
        row = self.planned()
        real = B.execute
        with mock.patch.object(B, "execute", lambda transition, actor: real(transition, actor=actor, connect=self.eos.connect, keys=self.keys)):
            response = self.executor.post(self.url("bcred_execute", row.transition_id))
        self.assertIn("BCRED_STATE_INVALID", response.url)
        self.assertEqual(self.eos.connects, [])


class SecretRetireClosureTests(SimpleTestCase):
    def setUp(self):
        directory = Path(tempfile.mkdtemp(prefix="nmas-retire-"))
        self.addCleanup(__import__("shutil").rmtree, directory, True)
        self.provider = FileSecretProvider(directory / "store.json")
        self.reference = "runtime://device-credentials/bootstrap-key"
        self.version = self.provider.initialize(self.reference, "material-for-test")

    def test_retire_removes_exactly_the_verified_version(self):
        self.assertEqual(self.provider.retire(self.reference, self.version), self.version)
        with self.assertRaises(SecretNotFound):
            self.provider.current(self.reference)

    def test_retire_with_pending_replacement_or_stale_version_refused(self):
        with self.assertRaises(SecretConflict):
            self.provider.retire(self.reference, "stale-version")
        self.provider.stage(self.reference, "replacement-material")
        with self.assertRaises(SecretConflict):
            self.provider.retire(self.reference, self.version)
        self.assertEqual(self.provider.current(self.reference).version, self.version)
