"""The ONE route -> action authorization table for the NMAS website.

Every ``core:`` URL name is classified exactly once (a contract test enforces completeness):

* ``READ_ROUTES``       GET/HEAD only.  Requires ``Action.VIEW`` unless ``READ_ACTION_OVERRIDES`` raises it.  An unsafe
                        method on a read route is refused (fail closed) before the view runs.
* ``MUTATION_ROUTES``   the action an unsafe method (POST/PUT/PATCH/DELETE) requires.  A GET on such a route still
                        requires VIEW (some routes render a form on GET).

``SENSITIVE_READ_ROUTES`` are GETs that export configuration / evidence or show security state: they are allowed for the
action above but always audited.  Unknown ``core:`` routes are DENIED, never assumed safe.

Authorization is checked server-side by core.middleware.NmasAccessMiddleware through ``user.has_perm`` -- hiding a
button is never the control.  Roles are ordinary Django groups seeded by migration 0019.
"""

from __future__ import annotations

from enum import StrEnum


class Action(StrEnum):
    VIEW = "nmas_view"
    EDIT = "nmas_edit"
    VALIDATE = "nmas_validate"
    PLAN = "nmas_plan"
    APPROVE = "nmas_approve"
    EXECUTE = "nmas_execute"
    SECURITY_ADMIN = "nmas_security_admin"


def permission_name(action: Action) -> str:
    return f"core.{action.value}"


# Role groups (seeded by migration 0019; keep the frozen copy there equal -- contract test).
ROLE_PERMISSIONS: dict[str, tuple[str, ...]] = {
    "NMAS Viewer": (Action.VIEW,),
    "NMAS Operator": (Action.VIEW, Action.EDIT, Action.VALIDATE, Action.PLAN),
    "NMAS Approver": (Action.VIEW, Action.APPROVE),
    "NMAS Executor": (Action.VIEW, Action.EXECUTE),
    "NMAS Security Admin": (Action.VIEW, Action.SECURITY_ADMIN),
}

# Routes reachable without an authenticated, MFA-verified session.  Each one is justified:
PUBLIC_ROUTES = frozenset({
    "login",        # the login form itself
    "healthz",      # a constant "ok" for the reverse proxy / tunnel health check: no data, no DB read
})
# Reachable with a password-authenticated session that has NOT yet completed website MFA (the MFA flow itself).
MFA_PENDING_ROUTES = frozenset({"logout", "mfa_verify", "mfa_enroll"})

READ_ROUTES = frozenset({
    "home", "topology_data", "monitoring_landing", "monitoring_resources", "monitoring_link_events",
    "monitoring_link_state_traffic", "device_builder", "device_builder_capabilities", "device_builder_changes",
    "device_builder_change_detail", "device_builder_edit", "device_builder_advanced", "device_builder_candidate_download",
    "device_builder_candidate_diff", "change_validation", "change_validation_detail", "change_validation_report", "change_configuration_validation",
    "network_config_validation", "network_config_validation_detail", "network_config_validation_report",
    "change_plan", "change_plan_detail", "change_plan_report", "raw_configlets", "raw_configlet_new",
    "raw_configlet_detail", "raw_configlet_revision", "raw_configlet_verification", "nsot", "nsot_devices",
    "nsot_device_detail", "nsot_device_running_config", "nsot_interfaces", "nsot_ipam", "nsot_vlans", "nsot_routing",
    "nsot_platforms", "nsot_templates", "nsot_drift", "health_fleet", "health_device", "health_run", "health_run_report",
    "change_precheck", "change_precheck_detail", "change_execute", "change_executions", "change_execution_detail",
    "change_execution_report", "bundles_list", "bundle_detail", "bundle_manifest", "soaks_list", "soak_detail",
    "provisioning_list", "provisioning_detail", "traffic_workbench", "traffic_run_detail", "probation_overview",
    "bootstrap_home", "bootstrap_run_detail", "automation_landing", "workbench_changes", "workbench_remove",
    "credential_status", "credential_status_json", "automation_section", "notifications", "notification_detail",
    "profile", "mfa_status", "audit_log",
    # V2 Phase 3 -- template library
    "template_library", "template_detail", "template_version_detail", "template_export",
    # V2 Maintenance Mode -- read-only pages (no device is contacted)
    "maintenance_list", "maintenance_detail", "maintenance_readiness", "maintenance_plan", "maintenance_history",
    # Lab 7 -- test governance (persisted evidence only; no test, device or GitHub call on a page view)
    "quality_unit_tests", "quality_artifact", "quality_coverage", "quality_cell",
    # V2 Lifecycle Phase 2 -- managed devices (NMAS database reads only; no device or NetBox call on a page view)
    "managed_devices", "managed_devices_json", "managed_device_detail", "managed_device_json",
    # V2 Phase 3 -- native ZTP (NMAS database reads only; no device, DHCP or lease-file access on a page view)
    "ztp_networks", "ztp_adapters_json", "ztp_session_json",
    # V2 Phase 4 -- management multihoming (NMAS database reads only; no device or host access on a page view)
    "management_overview", "management_spof_json", "management_device", "management_device_json",
    # V2 Phases 5 / 6 -- isolation, commissioning and admission (NMAS database reads only; no device access on a page view)
    "commissioning_overview", "commissioning_device", "commissioning_device_json",
    # V2 Phases 7 / 8 -- decommissioning and the infrastructure projections (NMAS database reads only on a page view)
    "decommission_overview", "decommission_device", "infrastructure_overview", "infrastructure_json",
})

READ_ACTION_OVERRIDES: dict[str, Action] = {
    "credential_status": Action.SECURITY_ADMIN,
    "credential_status_json": Action.SECURITY_ADMIN,
    "audit_log": Action.SECURITY_ADMIN,
}

SENSITIVE_READ_ROUTES = frozenset({
    "device_builder_candidate_download", "device_builder_candidate_diff", "change_validation_report",
    "network_config_validation_report", "change_plan_report",
    "template_export",
    "nsot_device_running_config", "health_run_report", "change_execution_report", "bundle_manifest",
    "credential_status", "credential_status_json", "audit_log",
    "managed_devices_json", "managed_device_json",
    "ztp_session_json",
    "management_spof_json", "management_device_json",
    "commissioning_device_json",
})

MUTATION_ROUTES: dict[str, Action] = {
    # Change / intent authoring
    "device_builder_create_change": Action.EDIT,
    "device_builder_delete_change": Action.EDIT,
    "device_builder_create_intent": Action.EDIT,
    "device_builder_import_existing_config": Action.EDIT,
    "device_builder_field_commit": Action.EDIT,
    "device_builder_interface_add": Action.EDIT,
    "device_builder_interface_remove": Action.EDIT,
    "device_builder_address_add": Action.EDIT,
    "device_builder_address_remove": Action.EDIT,
    "device_builder_ipam_prefixes": Action.EDIT,
    "device_builder_static_route_add": Action.EDIT,
    "device_builder_static_route_remove": Action.EDIT,
    "device_builder_routing_instance_add": Action.EDIT,
    "device_builder_routing_instance_remove": Action.EDIT,
    "device_builder_routing_binding_add": Action.EDIT,
    "device_builder_routing_binding_remove": Action.EDIT,
    "device_builder_bgp_neighbor_add": Action.EDIT,
    "device_builder_bgp_neighbor_remove": Action.EDIT,
    "device_builder_bgp_network_add": Action.EDIT,
    "device_builder_bgp_network_remove": Action.EDIT,
    "device_builder_ospf_network_add": Action.EDIT,
    "device_builder_ospf_network_remove": Action.EDIT,
    "device_builder_phase12_add": Action.EDIT,
    "device_builder_phase12_remove": Action.EDIT,
    "device_builder_service_mode": Action.EDIT,
    "raw_configlet_create": Action.EDIT,
    "raw_configlet_save": Action.EDIT,
    "raw_configlet_toggle": Action.EDIT,
    "workbench_snapshot": Action.EDIT,
    "workbench_changes_preview": Action.EDIT,
    "workbench_changes_save": Action.EDIT,
    "workbench_remove_save": Action.EDIT,
    "workbench_revise": Action.EDIT,
    "workbench_archive": Action.EDIT,
    # V2 Phase 3 -- templates: authoring is EDIT; publishing / retiring an immutable artifact is an APPROVE decision.
    # Cloning only creates a Draft Change (EDIT); pushing it is still change_execute_run (EXECUTE).
    "template_extract": Action.EDIT,
    "template_import": Action.EDIT,
    "template_discard": Action.EDIT,
    "template_clone": Action.EDIT,
    "template_version_from_change": Action.EDIT,
    "template_publish": Action.APPROVE,
    "template_retire": Action.APPROVE,
    # validation / verification / live checks
    "change_validation_run": Action.VALIDATE,
    "change_configuration_validation_refresh": Action.VALIDATE,
    "network_config_validation_run": Action.VALIDATE,
    "workbench_validate_running": Action.VALIDATE,
    "raw_configlet_verify": Action.VALIDATE,
    "health_fleet_snapshot": Action.VALIDATE,
    "health_device_deep": Action.VALIDATE,
    "health_device_connectivity": Action.VALIDATE,
    "change_precheck_run": Action.VALIDATE,
    "workbench_revalidate": Action.VALIDATE,
    "bootstrap_probe": Action.VALIDATE,
    # planning
    "change_plan_build": Action.PLAN,
    # approval / promotion (artifacts, soaks, the one-time bootstrap, Golden decisions)
    "change_execution_bundle_create": Action.APPROVE,
    "bundle_derive_probation": Action.APPROVE,
    "bundle_soak_start": Action.APPROVE,
    # V2 Phase 5A new-device provisioning: each stage carries the permission of the lifecycle step it performs
    "provisioning_create": Action.EDIT,
    "provisioning_identity": Action.EDIT,
    "provisioning_candidate": Action.EDIT,
    "provisioning_cancel": Action.EDIT,
    "provisioning_bootstrap": Action.VALIDATE,
    "provisioning_capability": Action.VALIDATE,
    "provisioning_validation": Action.VALIDATE,
    "provisioning_precheck": Action.VALIDATE,
    "provisioning_ipam": Action.PLAN,
    "provisioning_plan": Action.PLAN,
    "provisioning_approve": Action.APPROVE,
    "provisioning_nsot_sync": Action.APPROVE,
    "provisioning_probation": Action.APPROVE,
    "provisioning_decommission": Action.APPROVE,
    "soak_cancel": Action.APPROVE,
    "soak_decision": Action.APPROVE,
    "bootstrap_capture": Action.APPROVE,
    "bootstrap_start": Action.APPROVE,
    "bootstrap_cancel": Action.APPROVE,
    "bootstrap_approve": Action.APPROVE,
    # V2 Maintenance Mode: each step carries the permission of what it is.  Requesting / cancelling before entry is
    # application state (EDIT); the readiness evaluation is a read-only observation (VALIDATE); approving the hashed plan
    # is an APPROVE decision; entering and restoring change devices (EXECUTE) -- they are queued for the worker.
    "maintenance_request": Action.EDIT,
    "maintenance_cancel": Action.EDIT,
    "maintenance_evaluate": Action.VALIDATE,
    # Lab 7: fetch the Tier-3 test-governance artifact for the deployed commit (read-only toward GitHub, code, devices)
    "quality_refresh": Action.VALIDATE,
    "maintenance_approve": Action.APPROVE,
    "maintenance_enter": Action.EXECUTE,
    "maintenance_restore": Action.EXECUTE,
    # V2 Lifecycle Phase 2: recording expectations is EDIT; adopting a device, approving / revoking an attachment or a
    # bootstrap authorization and promoting an observed identity are APPROVE decisions; reading NetBox and a dry-run
    # authorization decision are VALIDATE.  None of them contacts a device or writes to NetBox.
    "managed_device_register": Action.EDIT,
    "managed_device_identity": Action.EDIT,
    "managed_device_withdraw": Action.EDIT,
    "managed_device_attachment_add": Action.EDIT,
    "managed_device_netbox_import": Action.EDIT,
    "bootstrap_authorization_request": Action.EDIT,
    "managed_device_adopt": Action.APPROVE,
    "managed_device_attachment_approve": Action.APPROVE,
    "managed_device_attachment_revoke": Action.APPROVE,
    "managed_device_verify_identity": Action.APPROVE,
    "bootstrap_authorization_approve": Action.APPROVE,
    "bootstrap_authorization_revoke": Action.APPROVE,
    "managed_device_netbox_compare": Action.VALIDATE,
    "bootstrap_authorization_evaluate": Action.VALIDATE,
    # V2 Phase 3 native ZTP: opening a session (reserving an address, rendering the minimal bootstrap) is EDIT; defining a
    # bootstrap network, cancelling a session, enrolling a host key and marking a device FAILED are APPROVE decisions;
    # validating DHCP policy, folding the lease database and the key-exchange-only host-key read are VALIDATE; writing
    # the isolated DHCP provider and the authenticated management verification (-> BOOTSTRAPPED) are EXECUTE.
    "ztp_session_open": Action.EDIT,
    "ztp_network_create": Action.APPROVE,
    "ztp_session_cancel": Action.APPROVE,
    "ztp_session_enroll": Action.APPROVE,
    "ztp_session_fail_device": Action.APPROVE,
    "ztp_network_validate": Action.VALIDATE,
    "ztp_network_ingest": Action.VALIDATE,
    "ztp_session_contact": Action.VALIDATE,
    "ztp_network_apply": Action.EXECUTE,
    "ztp_network_rollback": Action.EXECUTE,
    "ztp_session_verify": Action.EXECUTE,
    # V2 Phase 4 management multihoming: registering an expectation (NMAS attachment, path, credential transition plan)
    # and editing management-VRF intent are EDIT; approving / revoking an attachment or path, acknowledging reconciliation
    # and approving / cancelling a credential transition are APPROVE decisions (a different operator, enforced by the
    # services); a read-only host observation, a pinned-key probe and a selector evaluation are VALIDATE; changing the
    # device's accounts (the bootstrap credential transition) is EXECUTE.
    "management_attachment_register": Action.EDIT,
    "management_path_register": Action.EDIT,
    "bcred_plan": Action.EDIT,
    "device_builder_management_add": Action.EDIT,
    "device_builder_management_remove": Action.EDIT,
    "management_attachment_approve": Action.APPROVE,
    "management_attachment_revoke": Action.APPROVE,
    "management_path_approve": Action.APPROVE,
    "management_path_revoke": Action.APPROVE,
    "management_reconcile": Action.APPROVE,
    "bcred_approve": Action.APPROVE,
    "bcred_cancel": Action.APPROVE,
    "management_attachment_observe": Action.VALIDATE,
    "management_path_probe": Action.VALIDATE,
    "management_evaluate": Action.VALIDATE,
    "bcred_execute": Action.EXECUTE,
    # V2 Phases 5 / 6: requesting isolation, planning it, opening a commissioning, declaring a dependency and planning an
    # admission are EDIT; read-only device checks (precheck, verify, drift, readiness assessment, configuration postcheck) are
    # VALIDATE; approvals, cancellations, aborts, dependency removal and reconciliation decisions are APPROVE (a different operator
    # from the requester, enforced by the services); changing the trusted upstream (applying isolation, releasing it for
    # admission) is EXECUTE.
    "isolation_require": Action.EDIT,
    "isolation_plan": Action.EDIT,
    "commissioning_open": Action.EDIT,
    "dependency_add": Action.EDIT,
    "admission_plan": Action.EDIT,
    "isolation_precheck": Action.VALIDATE,
    "isolation_verify": Action.VALIDATE,
    "isolation_drift": Action.VALIDATE,
    "commissioning_assess": Action.VALIDATE,
    "commissioning_record": Action.VALIDATE,
    "admission_precheck": Action.VALIDATE,
    "isolation_approve": Action.APPROVE,
    "isolation_cancel": Action.APPROVE,
    "isolation_reconcile": Action.APPROVE,
    "commissioning_approve": Action.APPROVE,
    "commissioning_abort": Action.APPROVE,
    "commissioning_reconcile": Action.APPROVE,
    "dependency_remove": Action.APPROVE,
    "admission_approve": Action.APPROVE,
    "admission_cancel": Action.APPROVE,
    "admission_reconcile": Action.APPROVE,
    "isolation_apply": Action.EXECUTE,
    "admission_execute": Action.EXECUTE,
    # V2 Phase 7 -- decommissioning / restoration (evaluate reads the device; execute writes it through the governed transaction)
    "decommission_request": Action.EDIT,
    "restoration_request": Action.EDIT,
    "decommission_evaluate": Action.VALIDATE,
    "restoration_check": Action.VALIDATE,
    "decommission_approve": Action.APPROVE,
    "decommission_cancel": Action.APPROVE,
    "decommission_reconcile": Action.APPROVE,
    "restoration_approve": Action.APPROVE,
    "restoration_cancel": Action.APPROVE,
    "decommission_execute": Action.EXECUTE,
    "restoration_execute": Action.EXECUTE,
    # V2 Phase 8 -- one outbox dispatch batch (NMAS-side projections; NetBox writes stay behind NMAS_NSOT_RECONCILE_WRITE)
    "infrastructure_dispatch": Action.APPROVE,
    # execution (the only device-push route)
    "change_execute_run": Action.EXECUTE,
    # V2 Phase 5B: a traffic test puts real (bounded) traffic on the lab network; it configures nothing
    "traffic_run_create": Action.EXECUTE,
    # per-user state with no network or shared-control-plane effect
    "notification_mark_read": Action.VIEW,
    "notification_mark_all_read": Action.VIEW,
    "notification_retry_slack": Action.EDIT,
    "set_theme": Action.VIEW,
}

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


class Decision:
    ALLOW = "ALLOW"
    DENY = "DENY"
    METHOD_NOT_ALLOWED = "METHOD_NOT_ALLOWED"


def required_action(url_name: str, method: str) -> tuple[str, Action | None]:
    """(decision, action) for one ``core:`` route.  Unknown routes are DENIED (fail closed)."""
    safe = method.upper() in SAFE_METHODS
    if url_name in MUTATION_ROUTES:
        return Decision.ALLOW, (Action.VIEW if safe else MUTATION_ROUTES[url_name])
    if url_name in READ_ROUTES:
        if not safe:
            return Decision.METHOD_NOT_ALLOWED, None
        return Decision.ALLOW, READ_ACTION_OVERRIDES.get(url_name, Action.VIEW)
    return Decision.DENY, None


def action_category(url_name: str, method: str) -> str:
    """Audit category for a request: the action name (``edit`` / ``execute`` / ...) or ``read``."""
    decision, action = required_action(url_name, method)
    if decision != Decision.ALLOW or action is None:
        return "denied"
    if method.upper() in SAFE_METHODS:
        return "sensitive_read" if url_name in SENSITIVE_READ_ROUTES else "read"
    return action.value.removeprefix("nmas_")


def user_can(user, action: Action) -> bool:
    return bool(user and user.is_authenticated and user.is_active and user.has_perm(permission_name(action)))


def user_actions(user) -> dict[str, bool]:
    """Template helper: {"edit": True, ...} -- presentation only; the middleware is the enforcement point."""
    return {a.value.removeprefix("nmas_"): user_can(user, a) for a in Action}
