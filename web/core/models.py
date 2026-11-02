"""
Phase 4 normalized notification/event model.

This is the one persistence point for the notification/event backbone
described in docs/NOTIFICATION_AND_SLACK_ARCHITECTURE.md. It is deliberately
generic (event_type/severity/metadata) so future producers -- health
alerts, GitHub Actions results, deployment/rollback outcomes, Golden/soak
lifecycle events -- can publish through core.services.notification_service
without a schema change for each new kind of event.

Audience model: Phase 4 intentionally has no operator-account system yet
(see docs/DJANGO_UI_FOUNDATION.md Section 10), so every notification here
is global/system-wide, not per-user. This keeps "mark all read" and unread
counts simple and honest instead of inventing accounts to satisfy this
phase. See the architecture doc for the future per-user extension path.

Security: this model never stores a Slack webhook URL, token, or any other
secret -- only a delivery status/error summary. The webhook is read from
the environment at send time only (core.services.slack_service) and is
never persisted anywhere.
"""

from __future__ import annotations

import re
import uuid

from django.conf import settings
from django.core.validators import MinValueValidator, RegexValidator
from django.db import models
from django.db.models import F, Q
from django.urls import reverse


class Notification(models.Model):
    class Severity(models.TextChoices):
        INFO = "INFO", "Info"
        SUCCESS = "SUCCESS", "Success"
        WARNING = "WARNING", "Warning"
        ERROR = "ERROR", "Error"
        CRITICAL = "CRITICAL", "Critical"

    class EventType(models.TextChoices):
        # Generic / Phase 4 tooling
        TEST = "TEST", "Test notification"
        GENERIC = "GENERIC", "Generic event"
        # Future producer map (not wired up in Phase 4 -- see architecture doc)
        GOLDEN_PROMOTION_BLOCKED = "GOLDEN_PROMOTION_BLOCKED", "Golden promotion blocked"
        SOAK_REGRESSION = "SOAK_REGRESSION", "Soak regression detected"
        SOAK_COMPLETE = "SOAK_COMPLETE", "Soak complete"
        # Phase 20 producers (services/soak): started / decided events (failure, invalidation and "ready" reuse the two reserved values above)
        SOAK_STARTED = "SOAK_STARTED", "Probation soak started"
        GOLDEN_APPROVED = "GOLDEN_APPROVED", "Golden approved"
        GOLDEN_REJECTED = "GOLDEN_REJECTED", "Golden rejected"
        DEPLOYMENT_FAILED = "DEPLOYMENT_FAILED", "Deployment failed"
        DEPLOYMENT_SUCCEEDED = "DEPLOYMENT_SUCCEEDED", "Deployment succeeded"
        UAT_PARTIAL = "UAT_PARTIAL", "UAT partial"
        GITHUB_ACTIONS_FAILED = "GITHUB_ACTIONS_FAILED", "GitHub Actions failed"
        GITHUB_ACTIONS_PASSED = "GITHUB_ACTIONS_PASSED", "GitHub Actions passed"
        ROLLBACK_FAILED = "ROLLBACK_FAILED", "Rollback failed"
        ROLLBACK_SUCCEEDED = "ROLLBACK_SUCCEEDED", "Rollback succeeded"
        DEVICE_HEALTH_CRITICAL = "DEVICE_HEALTH_CRITICAL", "Device health critical"
        LINK_STATE_CRITICAL = "LINK_STATE_CRITICAL", "Link state critical"

    class SlackStatus(models.TextChoices):
        NOT_CONFIGURED = "NOT_CONFIGURED", "Not configured"
        PENDING = "PENDING", "Pending"
        SENT = "SENT", "Sent"
        FAILED = "FAILED", "Failed"
        SKIPPED = "SKIPPED", "Skipped"

    # --- Identity / classification ---------------------------------------
    event_type = models.CharField(max_length=64, choices=EventType.choices)
    severity = models.CharField(max_length=16, choices=Severity.choices)

    # --- Presentation text -------------------------------------------------
    title = models.CharField(max_length=200)
    message = models.TextField()
    detail = models.TextField(blank=True, default="")

    # --- Provenance ----------------------------------------------------------
    source = models.CharField(max_length=100, blank=True, default="")

    # --- Optional structured context --------------------------------------
    device = models.CharField(max_length=100, blank=True, default="")
    interface = models.CharField(max_length=100, blank=True, default="")
    change_id = models.CharField(max_length=100, blank=True, default="")
    lifecycle_state = models.CharField(max_length=100, blank=True, default="")
    metadata = models.JSONField(default=dict, blank=True)
    detail_url = models.CharField(
        max_length=500,
        blank=True,
        default="",
        help_text="Optional external reference URL (e.g. a GitHub Actions run). Never the in-app route.",
    )

    # --- Deduplication / correlation ----------------------------------------
    correlation_key = models.CharField(
        max_length=200,
        blank=True,
        default="",
        db_index=True,
        help_text="Optional key used to suppress duplicate events within a short window.",
    )

    # --- Read state ----------------------------------------------------------
    is_read = models.BooleanField(default=False)
    read_at = models.DateTimeField(null=True, blank=True)

    # --- Timestamps ----------------------------------------------------------
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # --- Slack delivery ------------------------------------------------------
    slack_status = models.CharField(
        max_length=16, choices=SlackStatus.choices, default=SlackStatus.PENDING
    )
    slack_error = models.TextField(blank=True, default="")
    slack_attempted_at = models.DateTimeField(null=True, blank=True)

    # --- Synthetic test marker -----------------------------------------------
    is_test = models.BooleanField(
        default=False,
        help_text="True only for notifications created by send_test_notification.",
    )

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["is_read"]),
            models.Index(fields=["severity"]),
            models.Index(fields=["event_type"]),
            models.Index(fields=["-created_at"]),
        ]

    def __str__(self):
        return f"[{self.severity}] {self.title}"

    def get_absolute_url(self):
        return reverse("core:notification_detail", args=[self.pk])


# =============================================================================
# Phase 8 -- Device Intent / Change / Configlet control-plane data model.
#
# Structure only: no config rendering, no validation beyond structural
# invariants, no deployment, no NetBox write, no live device access. See
# docs/DEVICE_INTENT_CHANGE_MODEL.md for the full architecture, ownership
# boundaries, and Phase-9 handoff contract.
#
# Non-negotiable rules encoded below (see the doc for rationale):
#   - NetBox stays passive: devices are referenced by a plain external name
#     string (matching modules/netbox_ipam.py / nsot_service.py convention),
#     never by a Django ForeignKey into a NetBox-mirroring table.
#   - Secrets are never stored directly -- only "*_ref" reference metadata,
#     enforced by core.services.secret_policy at the service layer.
#   - Change.change_id / Configlet.cfg_id / DeviceIntentRevision.revision are
#     immutable once persisted (enforced in save(), not just convention).
#   - ChangeLifecycleEvent / AuditEvent rows are append-only.
# =============================================================================

DEVICE_NAME_VALIDATOR = RegexValidator(
    r"^[A-Za-z0-9_-]{1,64}$",
    "Device name must be 1-64 characters: letters, digits, underscore, "
    "hyphen -- the same external-identity pattern nsot_service.py enforces.",
)


def _forbid_field_mutation(instance, field_name: str) -> None:
    """Raise ValueError if `field_name` differs from what is already persisted."""
    if instance.pk:
        current = (
            type(instance).objects.filter(pk=instance.pk).values_list(field_name, flat=True).first()
        )
        if current is not None and current != getattr(instance, field_name):
            raise ValueError(f"{type(instance).__name__}.{field_name} is immutable after creation.")


def _forbid_row_mutation(instance) -> None:
    """Raise ValueError if this row already exists -- append-only records."""
    if instance.pk and type(instance).objects.filter(pk=instance.pk).exists():
        raise ValueError(f"{type(instance).__name__} records are append-only and cannot be modified.")


class ExecutionMode(models.TextChoices):
    COMPLETE = "COMPLETE", "Complete"
    PARTIAL_UAT = "PARTIAL_UAT", "Partial (UAT)"


class ChangeCategory(models.TextChoices):
    CONFIGURATION_CHANGE = "CONFIGURATION_CHANGE", "Configuration change"
    NEW_DEVICE_PROVISIONING = "NEW_DEVICE_PROVISIONING", "New device provisioning"
    DECOMMISSION = "DECOMMISSION", "Decommission"
    ROLLBACK = "ROLLBACK", "Rollback"
    OTHER = "OTHER", "Other"


class ValidationState(models.TextChoices):
    """Structural validation state only -- no network-semantic validation (Phase 13)."""

    PENDING = "PENDING", "Pending"
    PASSED = "PASSED", "Passed"
    FAILED = "FAILED", "Failed"


class ChangeLifecycleState(models.TextChoices):
    """
    Forward-compatible lifecycle vocabulary. Phase 8 defines representation
    and append-only history only -- no transition here is automatic, and
    GOLDEN/PROBATION/UAT carry no soak/promotion/rollback behavior yet. See
    docs/DEVICE_INTENT_CHANGE_MODEL.md 'Lifecycle model' for the mapping onto
    Notification.EventType's reserved (currently unwired) producer values.
    """

    DRAFT = "DRAFT", "Draft"
    VALIDATED = "VALIDATED", "Validated"
    CI_PENDING = "CI_PENDING", "CI pending"
    CI_FAILED = "CI_FAILED", "CI failed"
    READY_TO_DEPLOY = "READY_TO_DEPLOY", "Ready to deploy"
    DEPLOYING = "DEPLOYING", "Deploying"
    DEPLOYED = "DEPLOYED", "Deployed"
    UAT = "UAT", "UAT"
    PROBATION = "PROBATION", "Probation"
    GOLDEN = "GOLDEN", "Golden"
    FAILED = "FAILED", "Failed"
    ROLLED_BACK = "ROLLED_BACK", "Rolled back"
    SUPERSEDED = "SUPERSEDED", "Superseded"


class DeviceIntentTargetType(models.TextChoices):
    EXISTING_DEVICE = "EXISTING_DEVICE", "Existing device"
    NEW_DEVICE = "NEW_DEVICE", "New device"


class Platform(models.TextChoices):
    """The intended Device Builder platform catalogue (Phase 10+ populates capability filtering)."""

    ARISTA_CEOS = "arista_ceos", "Arista cEOS"
    NOKIA_SRLINUX = "nokia_srlinux", "Nokia SR Linux"
    UBUNTU_FRR = "ubuntu_frr", "Ubuntu / FRR"
    CISCO_C8000V_IOSXE = "cisco_c8000v_iosxe", "Cisco Catalyst 8000V / IOS XE"
    CISCO_IOSXR = "cisco_iosxr", "Cisco IOS XR"
    SONIC = "sonic", "SONiC"


class FeatureNamespace(models.TextChoices):
    """Modular intent/configlet namespaces. Phase 10+ populates contents; Phase 8 only reserves the slots."""

    INTERFACES = "interfaces", "Interfaces"
    ROUTING = "routing", "Routing"
    NAT = "nat", "NAT"
    FHRP = "fhrp", "FHRP"
    SERVICES = "services", "Services"
    SECURITY = "security", "Security"
    OTHER = "other", "Other"


class FieldValidationState(models.TextChoices):
    """Set only by a future Phase-9 field-level validator -- Phase 8 never sets this to VALID/INVALID itself."""

    UNVALIDATED = "UNVALIDATED", "Unvalidated"
    VALID = "VALID", "Valid"
    INVALID = "INVALID", "Invalid"


class ConfigletOperationType(models.TextChoices):
    """CREATE_DEFINE (e.g. defining an ACL) vs ACTIVATE_ATTACH (e.g. applying it to an interface, traffic-affecting).

    Intentional removal is first-class (Remove Configuration workflow): DEACTIVATE_DETACH undoes an attachment /
    activation (an ACL on an interface, a secondary address, a BGP AF activation) and REMOVE_DELETE deletes a defined
    object (a VLAN, an SVI, a BGP neighbor, an ACL).  Neither is failure compensation or rollback.
    """

    CREATE_DEFINE = "CREATE_DEFINE", "Create / Define"
    ACTIVATE_ATTACH = "ACTIVATE_ATTACH", "Activate / Attach"
    DEACTIVATE_DETACH = "DEACTIVATE_DETACH", "Deactivate / Detach"
    REMOVE_DELETE = "REMOVE_DELETE", "Remove / Delete"


class DeploymentPriority(models.IntegerChoices):
    """Stable ordering taxonomy for the future unified deployment engine (Phase 13+). Not executed in Phase 8."""

    FOUNDATION_ACCESS = 1, "Foundation / access"
    INTERFACE_CONSTRUCTION = 2, "Interface construction"
    ADDRESSING = 3, "Addressing"
    BASIC_FORWARDING = 4, "Basic forwarding"
    DYNAMIC_ROUTING = 5, "Dynamic routing"
    HIGHER_LEVEL_SERVICES = 6, "Higher-level services"
    TRAFFIC_AFFECTING_POLICY = 7, "Traffic-affecting policy"
    MONITORING_MIRRORING = 8, "Monitoring / mirroring"
    PERSISTENCE = 9, "Persistence"


class ConfigletExecutionStatus(models.TextChoices):
    PENDING = "PENDING", "Pending"
    RENDERED = "RENDERED", "Rendered"
    DEPLOYED = "DEPLOYED", "Deployed"
    FAILED = "FAILED", "Failed"
    ROLLED_BACK = "ROLLED_BACK", "Rolled back"


class AuditEventType(models.TextChoices):
    CHANGE_CREATED = "CHANGE_CREATED", "Change created"
    INTENT_CREATED = "INTENT_CREATED", "Intent created"
    INTENT_REVISED = "INTENT_REVISED", "Intent revised"
    CONFIGLET_CREATED = "CONFIGLET_CREATED", "Configlet created"
    LIFECYCLE_CHANGED = "LIFECYCLE_CHANGED", "Lifecycle changed"
    FIELD_ACCEPTED = "FIELD_ACCEPTED", "Field accepted"
    VALIDATION_RECORDED = "VALIDATION_RECORDED", "Validation recorded"
    PLAN_BUILT = "PLAN_BUILT", "Plan built"
    HEALTH_RUN_RECORDED = "HEALTH_RUN_RECORDED", "Health run recorded"
    PRECHECK_RECORDED = "PRECHECK_RECORDED", "Precheck recorded"
    POSTCHECK_RECORDED = "POSTCHECK_RECORDED", "Postcheck recorded"
    DEPLOYMENT_RECORDED = "DEPLOYMENT_RECORDED", "Deployment recorded"
    ROLLBACK_RECORDED = "ROLLBACK_RECORDED", "Rollback (compensation) recorded"
    RAW_CONFIGLET_CREATED = "RAW_CONFIGLET_CREATED", "Raw Configlet created"
    RAW_REVISION_SAVED = "RAW_REVISION_SAVED", "Raw Configlet revision saved"
    RAW_ENABLED_CHANGED = "RAW_ENABLED_CHANGED", "Raw Configlet added to / removed from the effective Change"
    RAW_VERIFICATION_REQUESTED = "RAW_VERIFICATION_REQUESTED", "Raw verification requested"
    RAW_VERIFICATION_COMPLETED = "RAW_VERIFICATION_COMPLETED", "Raw verification completed"
    UAT_BUNDLE_CREATED = "UAT_BUNDLE_CREATED", "UAT bundle created"
    PROBATION_BUNDLE_CREATED = "PROBATION_BUNDLE_CREATED", "Probation bundle created"
    DEPLOYED_BUNDLE_CREATED = "DEPLOYED_BUNDLE_CREATED", "Deployed (Complete) bundle created"
    BUNDLE_INTEGRITY_FAILED = "BUNDLE_INTEGRITY_FAILED", "Bundle integrity check failed"
    PROBATION_SOAK_STARTED = "PROBATION_SOAK_STARTED", "Probation soak started"
    PROBATION_SOAK_CANCELLED = "PROBATION_SOAK_CANCELLED", "Probation soak cancelled"
    PROBATION_SOAK_FAILED = "PROBATION_SOAK_FAILED", "Probation soak failed"
    PROBATION_SOAK_INCOMPLETE = "PROBATION_SOAK_INCOMPLETE", "Probation soak incomplete"
    PROBATION_SOAK_INVALIDATED = "PROBATION_SOAK_INVALIDATED", "Probation soak invalidated"
    PROBATION_SOAK_READY = "PROBATION_SOAK_READY", "Probation soak ready for the Golden decision"
    GOLDEN_APPROVED = "GOLDEN_APPROVED", "Golden approved"
    GOLDEN_REJECTED = "GOLDEN_REJECTED", "Golden rejected"
    LEGACY_BASELINE_CAPTURED = "LEGACY_BASELINE_CAPTURED", "Legacy baseline candidate captured"
    LEGACY_BOOTSTRAP_STARTED = "LEGACY_BOOTSTRAP_STARTED", "Legacy bootstrap observation started"
    LEGACY_BOOTSTRAP_FAILED = "LEGACY_BOOTSTRAP_FAILED", "Legacy bootstrap observation failed"
    LEGACY_BOOTSTRAP_INCOMPLETE = "LEGACY_BOOTSTRAP_INCOMPLETE", "Legacy bootstrap observation incomplete"
    LEGACY_BOOTSTRAP_INVALIDATED = "LEGACY_BOOTSTRAP_INVALIDATED", "Legacy bootstrap observation invalidated"
    LEGACY_BOOTSTRAP_CANCELLED = "LEGACY_BOOTSTRAP_CANCELLED", "Legacy bootstrap observation cancelled"
    LEGACY_BOOTSTRAP_READY = "LEGACY_BOOTSTRAP_READY", "Legacy bootstrap observation ready for the operator's decision"
    LEGACY_GOLDEN_APPROVED = "LEGACY_GOLDEN_APPROVED", "Initial Golden approved (legacy bootstrap)"
    # Phase 20.5 -- explicit operator abandonment of a never-executed DRAFT Change (see
    # change_service.delete_draft_change). This event's own `change` FK is left NULL by
    # AuditEvent's existing on_delete=SET_NULL: the audit row survives the Change it describes.
    DRAFT_CHANGE_DELETED = "DRAFT_CHANGE_DELETED", "Draft Change deleted by the operator"
    # Phase 24 -- reviewed R1 human-2FA pilot helper steps (validate / checkpoint / stage / verify / confirm / replace).
    MFA_PILOT_STEP = "MFA_PILOT_STEP", "R1 2FA pilot step recorded"
    # V2 Phase 1 -- NMAS WEBSITE identity / access / request evidence.  The APP_MFA_* events concern the website's own
    # Microsoft Authenticator TOTP and are deliberately distinct from MFA_PILOT_STEP and every network-device MFA record.
    AUTH_LOGIN_SUCCEEDED = "AUTH_LOGIN_SUCCEEDED", "Website login succeeded"
    AUTH_LOGIN_FAILED = "AUTH_LOGIN_FAILED", "Website login failed"
    AUTH_LOGIN_THROTTLED = "AUTH_LOGIN_THROTTLED", "Website login refused (too many failures)"
    AUTH_LOGOUT = "AUTH_LOGOUT", "Website logout"
    APP_MFA_ENROLLED = "APP_MFA_ENROLLED", "Website MFA enrolled"
    APP_MFA_VERIFIED = "APP_MFA_VERIFIED", "Website MFA verified"
    APP_MFA_FAILED = "APP_MFA_FAILED", "Website MFA verification failed"
    APP_MFA_RESET = "APP_MFA_RESET", "Website MFA reset by an administrator"
    ACCESS_DENIED = "ACCESS_DENIED", "Website access denied"
    WEB_ACTION = "WEB_ACTION", "Website action (state-changing request)"
    SENSITIVE_READ = "SENSITIVE_READ", "Website sensitive read / export"
    CAPABILITY_EVIDENCE_RECORDED = "CAPABILITY_EVIDENCE_RECORDED", "Capability evidence recorded"
    NETWORK_CONFIG_VALIDATED = "NETWORK_CONFIG_VALIDATED", "Network configuration validation recorded"
    CHANGE_ARCHIVED = "CHANGE_ARCHIVED", "Change archived"
    # V2 Phase 3 -- configuration templates (core.services.config_templates).  Never carries intent values or secrets.
    TEMPLATE_EXTRACTED = "TEMPLATE_EXTRACTED", "Template extracted from a running configuration"
    TEMPLATE_CREATED = "TEMPLATE_CREATED", "Template created"
    TEMPLATE_VERSION_CREATED = "TEMPLATE_VERSION_CREATED", "Template version created"
    TEMPLATE_PUBLISHED = "TEMPLATE_PUBLISHED", "Template version published"
    TEMPLATE_DRAFT_DISCARDED = "TEMPLATE_DRAFT_DISCARDED", "Template draft discarded"
    TEMPLATE_EXPORTED = "TEMPLATE_EXPORTED", "Template exported"
    TEMPLATE_IMPORTED = "TEMPLATE_IMPORTED", "Template package imported"
    TEMPLATE_IMPORT_REJECTED = "TEMPLATE_IMPORT_REJECTED", "Template package rejected"
    TEMPLATE_CLONED = "TEMPLATE_CLONED", "Template cloned into a Change"
    TEMPLATE_PUSH_RECORDED = "TEMPLATE_PUSH_RECORDED", "Template-derived push recorded"
    TEMPLATE_RETIRED = "TEMPLATE_RETIRED", "Template retired"
    # V2 Phase 5 -- new-device provisioning (core.services.provisioning).  Metadata never carries a credential.
    PROVISIONING_REQUESTED = "PROVISIONING_REQUESTED", "Provisioning request created"
    PROVISIONING_STAGE_RECORDED = "PROVISIONING_STAGE_RECORDED", "Provisioning stage recorded"
    PROVISIONING_BLOCKED = "PROVISIONING_BLOCKED", "Provisioning stage blocked"
    PROVISIONING_APPROVED = "PROVISIONING_APPROVED", "Provisioning approved"
    PROVISIONING_COMPLETED = "PROVISIONING_COMPLETED", "Provisioning completed"
    PROVISIONING_FAILED = "PROVISIONING_FAILED", "Provisioning failed"
    PROVISIONING_RECONCILED = "PROVISIONING_RECONCILED", "Provisioning NetBox / registry state reconciled"
    PROVISIONING_CANCELLED = "PROVISIONING_CANCELLED", "Provisioning cancelled"
    DEVICE_DECOMMISSIONED = "DEVICE_DECOMMISSIONED", "Provisioned device retired from NMAS"
    # V2 Phase 5B -- traffic / test workbench (core.services.traffic).  Metadata is the run id, endpoints and verdict; never a command line.
    TRAFFIC_RUN_STARTED = "TRAFFIC_RUN_STARTED", "Traffic test run started"
    TRAFFIC_RUN_FINISHED = "TRAFFIC_RUN_FINISHED", "Traffic test run finished"
    TRAFFIC_RUN_REFUSED = "TRAFFIC_RUN_REFUSED", "Traffic test request refused"
    TRAFFIC_RUN_RECONCILED = "TRAFFIC_RUN_RECONCILED", "Abandoned traffic test run reconciled"
    # State reconciliation (core.services.reconciliation_service).  Metadata is digests and references; never configuration text.
    STATE_RECONCILIATION_ACCEPTED = "STATE_RECONCILIATION_ACCEPTED", "Current device state accepted as the expected baseline"
    NSOT_STATUS_PROJECTED = "NSOT_STATUS_PROJECTED", "NetBox device status set explicitly from a reconciliation"
    # V2 Maintenance Mode (core.services.maintenance_mode).  Metadata is the record id, states, plan hash and finding codes; never configuration text.
    MAINTENANCE_TRANSITION = "MAINTENANCE_TRANSITION", "Maintenance state changed"
    MAINTENANCE_REFUSED = "MAINTENANCE_REFUSED", "Maintenance step refused"
    MAINTENANCE_QUEUED = "MAINTENANCE_QUEUED", "Maintenance device action queued for the worker"
    # V2 Lifecycle Phase 2 -- managed-device identity / attachment / bootstrap authorization (core.services.devices).
    # Metadata is the device id, states, codes and digests; never a credential.
    DEVICE_REGISTERED = "DEVICE_REGISTERED", "Expected device registered"
    DEVICE_ADOPTED = "DEVICE_ADOPTED", "Existing device adopted into the lifecycle registry"
    DEVICE_LIFECYCLE_CHANGED = "DEVICE_LIFECYCLE_CHANGED", "Managed-device lifecycle / identity / attachment recorded"
    DEVICE_LIFECYCLE_REFUSED = "DEVICE_LIFECYCLE_REFUSED", "Managed-device lifecycle action refused"
    BOOTSTRAP_AUTH_REQUESTED = "BOOTSTRAP_AUTH_REQUESTED", "Bootstrap authorization requested"
    BOOTSTRAP_AUTH_APPROVED = "BOOTSTRAP_AUTH_APPROVED", "Bootstrap authorization approved"
    BOOTSTRAP_AUTH_REVOKED = "BOOTSTRAP_AUTH_REVOKED", "Bootstrap authorization revoked"
    BOOTSTRAP_AUTH_DECIDED = "BOOTSTRAP_AUTH_DECIDED", "Bootstrap authorization decision recorded"
    ZTP_SESSION_CHANGED = "ZTP_SESSION_CHANGED", "Native ZTP session opened / progressed / closed"
    ZTP_DISCOVERY_OBSERVED = "ZTP_DISCOVERY_OBSERVED", "Native DHCP discovery observed through a bootstrap network"
    ZTP_ARTIFACT_DELIVERY = "ZTP_ARTIFACT_DELIVERY", "Bootstrap artifact request served or refused"
    ZTP_MANAGEMENT_VERIFIED = "ZTP_MANAGEMENT_VERIFIED", "Bootstrap management verification recorded"
    DEVICE_BOOTSTRAPPED = "DEVICE_BOOTSTRAPPED", "Device bootstrapped (pending commission; not admitted)"
    DHCP_POLICY_APPLIED = "DHCP_POLICY_APPLIED", "Isolated bootstrap DHCP policy validated / applied / recovered"
    MANAGEMENT_PATH_CHANGED = "MANAGEMENT_PATH_CHANGED", "Management path registered / approved / revoked / probed"
    MANAGEMENT_PATH_SWITCHED = "MANAGEMENT_PATH_SWITCHED", "Active management path failed over / failed back / lost"
    BOOTSTRAP_CREDENTIAL_CHANGED = "BOOTSTRAP_CREDENTIAL_CHANGED", "Bootstrap credential replacement / retirement step recorded"
    ISOLATION_CHANGED = "ISOLATION_CHANGED", "Trusted-upstream isolation policy planned / applied / verified / released"
    COMMISSIONING_CHANGED = "COMMISSIONING_CHANGED", "Commissioning dependency / readiness / approval recorded"
    PRODUCTION_ADMISSION_CHANGED = "PRODUCTION_ADMISSION_CHANGED", "Production admission planned / approved / executed / restored"
    LIFECYCLE_OUTBOX_RECORDED = "LIFECYCLE_OUTBOX_RECORDED", "Lifecycle outbox event recorded / delivered"
    DECOMMISSION_CHANGED = "DECOMMISSION_CHANGED", "Decommission readiness / plan / approval / execution recorded"
    RESTORATION_CHANGED = "RESTORATION_CHANGED", "Restoration check / plan / approval / execution recorded"
    INFRASTRUCTURE_RECONCILED = "INFRASTRUCTURE_RECONCILED", "NetBox / topology / monitoring projection reconciled"


class Change(models.Model):
    """
    One controlled, operator-approved unit of work that may affect one or
    more devices. This is the top-level control-plane object every
    DeviceIntent, Configlet, and lifecycle/audit record hangs off of.

    `change_id` (e.g. "CHG-20260920-0001") is the stable, human-readable,
    URL/log/Git-safe identifier -- immutable after creation (see save()).
    The integer `id` primary key is an internal implementation detail only.

    Git/GitHub Actions/deployment reference fields are deliberately nullable
    and unpopulated in Phase 8 -- later phases fill them in as those
    integrations are built, never with placeholder/fake values.
    """

    change_id = models.CharField(max_length=32, unique=True, editable=False)
    title = models.CharField(max_length=200)
    description = models.TextField(blank=True, default="")

    category = models.CharField(
        max_length=32, choices=ChangeCategory.choices, default=ChangeCategory.CONFIGURATION_CHANGE
    )
    execution_mode = models.CharField(
        max_length=16,
        choices=ExecutionMode.choices,
        default=ExecutionMode.COMPLETE,
        help_text="Complete or Partial (UAT). Deployment semantics for either are not implemented in Phase 8.",
    )
    lifecycle_state = models.CharField(
        max_length=32, choices=ChangeLifecycleState.choices, default=ChangeLifecycleState.DRAFT
    )
    validation_state = models.CharField(
        max_length=16, choices=ValidationState.choices, default=ValidationState.PENDING
    )

    created_by = models.CharField(max_length=150, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # --- Partial (UAT) future acknowledgement -------------------------------
    # Every field below defaults to False/blank/null and is never pre-checked
    # or auto-acknowledged by any Phase 8 code path. Recording a real
    # acknowledgement is Phase 9+ scope.
    uat_ack_target_is_authorized_nonprod = models.BooleanField(default=False)
    uat_ack_partial_success_may_remain_applied = models.BooleanField(default=False)
    uat_ack_dependent_stages_may_stop = models.BooleanField(default=False)
    uat_ack_adjacent_traffic_may_be_affected = models.BooleanField(default=False)
    uat_ack_operator_accepts_risk = models.BooleanField(default=False)
    uat_acknowledged_by = models.CharField(max_length=150, blank=True, default="")
    uat_acknowledged_at = models.DateTimeField(null=True, blank=True)

    # --- Future integration references (nullable, never fabricated) --------
    git_branch_ref = models.CharField(max_length=200, blank=True, default="")
    git_commit_ref = models.CharField(max_length=64, blank=True, default="")
    github_actions_run_ref = models.CharField(max_length=200, blank=True, default="")
    deployment_reference = models.CharField(max_length=200, blank=True, default="")
    candidate_revision = models.PositiveIntegerField(
        null=True,
        blank=True,
        help_text="Overall candidate-bundle revision counter for this Change, if/when the whole bundle is redone.",
    )

    supersedes = models.ForeignKey(
        "self",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="superseded_by",
    )

    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["-created_at"]),
            models.Index(fields=["lifecycle_state"]),
            models.Index(fields=["execution_mode"]),
        ]

    def __str__(self):
        return f"{self.change_id}: {self.title}"

    def get_absolute_url(self):
        return reverse("core:device_builder_change_detail", args=[self.change_id])

    def save(self, *args, **kwargs):
        _forbid_field_mutation(self, "change_id")
        super().save(*args, **kwargs)


class ChangeTarget(models.Model):
    """
    One device affected by a Change. Device identity is a plain external
    name string, never a NetBox database foreign key -- NetBox stays passive
    storage the Django control plane merely references.
    """

    change = models.ForeignKey(Change, on_delete=models.CASCADE, related_name="targets")
    device_name = models.CharField(max_length=64, validators=[DEVICE_NAME_VALIDATOR])
    netbox_device_ref = models.CharField(
        max_length=100,
        blank=True,
        default="",
        help_text="Optional external NetBox object reference (e.g. its NetBox name/ID) -- read-only lookup key, not an FK.",
    )
    site = models.CharField(max_length=100, blank=True, default="")

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["change", "device_name"], name="unique_change_target_device"),
        ]
        ordering = ["device_name"]

    def __str__(self):
        return f"{self.change.change_id} -> {self.device_name}"


class DeviceIntent(models.Model):
    """
    What the operator wants one device/network feature to become, for one
    Change. Distinct from DEVICE OBSERVED STATE (live device facts, never
    stored here as authoritative) and from NETBOX STATE (passive inventory).

    `device_name` is an external reference (existing device) or a proposed
    name (new device) -- see DeviceIntentTargetType. The actual structured,
    versioned intent payload lives on DeviceIntentRevision, not here.
    """

    change = models.ForeignKey(Change, on_delete=models.CASCADE, related_name="device_intents")
    device_name = models.CharField(max_length=64, validators=[DEVICE_NAME_VALIDATOR])
    target_type = models.CharField(
        max_length=20, choices=DeviceIntentTargetType.choices, default=DeviceIntentTargetType.EXISTING_DEVICE
    )
    platform = models.CharField(max_length=32, choices=Platform.choices)
    image_reference = models.CharField(
        max_length=255,
        blank=True,
        default="",
        help_text="New-device image name/tag/reference only -- never a binary. Images stay local on NMAS.",
    )
    netbox_device_ref = models.CharField(max_length=100, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["change", "device_name"], name="unique_change_device_intent"),
        ]
        ordering = ["device_name"]

    def __str__(self):
        return f"{self.change.change_id} / {self.device_name} ({self.get_target_type_display()})"

    def latest_revision(self) -> "DeviceIntentRevision | None":
        return self.revisions.order_by("-revision").first()


class DeviceIntentRevision(models.Model):
    """
    One candidate revision of a DeviceIntent's structured payload. A new
    revision is a new row -- prior revisions are never destructively
    overwritten, so audit/history survives later Probation-stage edits.

    `sections` is the modular, namespaced feature payload (interfaces,
    routing, nat, fhrp, services, security, ...). Phase 10+ populates
    contents; Phase 8 only guarantees the namespace/versioning contract.
    Per-field draft/accepted state lives on IntentFieldState, not here.
    """

    device_intent = models.ForeignKey(DeviceIntent, on_delete=models.CASCADE, related_name="revisions")
    revision = models.PositiveIntegerField(validators=[MinValueValidator(1)])
    schema_version = models.PositiveIntegerField(default=1, validators=[MinValueValidator(1)])
    sections = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.CharField(max_length=150, blank=True, default="")
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["device_intent", "revision"], name="unique_intent_revision"),
        ]
        ordering = ["device_intent", "revision"]

    def __str__(self):
        return f"{self.device_intent} rev {self.revision}"

    def save(self, *args, **kwargs):
        _forbid_field_mutation(self, "revision")
        _forbid_field_mutation(self, "device_intent_id")
        super().save(*args, **kwargs)


class IntentFieldState(models.Model):
    """
    Draft/accepted state for exactly one field path within one
    DeviceIntentRevision. This is the Phase-9 Device Builder's durable
    server-side contract:

        accepted_value: the most recent value that passed field-level
                         commit validation.
        draft_value:    what the operator is currently typing/previewing.

    Typing does NOT trigger Python validation (that happens on commit/Enter
    in Phase 9, via a validator this phase does not implement). An invalid
    commit rolls draft_value back to accepted_value for THIS field only --
    sibling IntentFieldState rows are untouched by construction, since each
    field is its own row. Keystrokes are never persisted here; the browser
    owns immediate typing state (see docs/DEVICE_INTENT_CHANGE_MODEL.md).
    """

    revision = models.ForeignKey(DeviceIntentRevision, on_delete=models.CASCADE, related_name="field_states")
    path = models.CharField(max_length=255, help_text='Dotted namespace path, e.g. "interfaces.Ethernet1.ipv4_address".')
    draft_value = models.JSONField(null=True, blank=True)
    accepted_value = models.JSONField(null=True, blank=True)
    dirty = models.BooleanField(default=False)
    last_committed_at = models.DateTimeField(null=True, blank=True)
    validation_state = models.CharField(
        max_length=16, choices=FieldValidationState.choices, default=FieldValidationState.UNVALIDATED
    )
    validation_message = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["revision", "path"], name="unique_revision_field_path"),
        ]
        ordering = ["path"]

    def __str__(self):
        return f"{self.revision} :: {self.path}"


class ConfigletOrigin(models.TextChoices):
    """Where an execution artifact came from: the structured planner, or an operator-authored Raw Configlet (Phase 18)."""

    STRUCTURED = "STRUCTURED", "Structured"
    RAW = "RAW", "Raw"
    REMOVAL = "REMOVAL", "Removal"


class Configlet(models.Model):
    """
    One atomic-ish deployable configuration unit inside a Change.
    `cfg_id` (e.g. "CFG-004") is independently addressable and stable, so a
    future operator can say "rollback CFG-004 but leave CFG-001/CFG-002" --
    it is generated from `sequence` and never rewritten after creation.

    No actual device configuration is generated in Phase 8: `rendered_config`
    and `rollback_config` stay empty until a later phase's renderer exists.
    """

    change = models.ForeignKey(Change, on_delete=models.CASCADE, related_name="configlets")
    plan = models.ForeignKey(
        "ChangePlan", null=True, blank=True, on_delete=models.CASCADE, related_name="configlets",
        help_text="Set for Phase-14 generated Configlets (one immutable plan generation); null for Phase-8 hand-created ones.",
    )
    cfg_id = models.CharField(max_length=16, editable=False)
    sequence = models.PositiveIntegerField(validators=[MinValueValidator(1)])
    target_device = models.CharField(max_length=64, validators=[DEVICE_NAME_VALIDATOR])
    device_intent = models.ForeignKey(
        DeviceIntent, null=True, blank=True, on_delete=models.SET_NULL, related_name="configlets"
    )
    feature_namespace = models.CharField(max_length=32, choices=FeatureNamespace.choices)
    description = models.TextField(blank=True, default="")
    operation_type = models.CharField(max_length=20, choices=ConfigletOperationType.choices)
    deployment_priority = models.PositiveSmallIntegerField(choices=DeploymentPriority.choices)

    previous_state_ref = models.JSONField(
        default=dict, blank=True, help_text="Reference/representation only -- never raw secrets."
    )
    desired_state_ref = models.JSONField(
        default=dict, blank=True, help_text="Reference/representation only -- never raw secrets."
    )
    rendered_config = models.TextField(blank=True, default="")
    rollback_config = models.TextField(blank=True, default="")
    verification_spec = models.JSONField(default=dict, blank=True)
    execution_status = models.CharField(
        max_length=16, choices=ConfigletExecutionStatus.choices, default=ConfigletExecutionStatus.PENDING
    )
    git_reference = models.CharField(max_length=200, blank=True, default="")
    metadata = models.JSONField(default=dict, blank=True)

    # Phase 18: an EXPLICIT typed origin (never inferred from a name or description).  A RAW Configlet pins the exact immutable
    # revision and the exact verification run it was planned from; historical Phase-14/17 Configlets default to STRUCTURED.
    origin = models.CharField(max_length=12, choices=ConfigletOrigin.choices, default=ConfigletOrigin.STRUCTURED)
    raw_revision = models.ForeignKey(
        "RawConfigletRevision", null=True, blank=True, on_delete=models.RESTRICT, related_name="plan_configlets",
    )
    raw_verification = models.ForeignKey(
        "RawConfigletVerificationRun", null=True, blank=True, on_delete=models.RESTRICT, related_name="plan_configlets",
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # Fields a generated (plan-owned) Configlet may never change after creation.  Execution-phase
    # fields (execution_status, previous_state_ref, rollback_config, git_reference, metadata) stay
    # writable for the later phases that own them.
    PLAN_FROZEN_FIELDS = (
        "plan_id", "cfg_id", "sequence", "target_device", "feature_namespace", "operation_type",
        "deployment_priority", "rendered_config", "desired_state_ref", "verification_spec", "description",
        "origin", "raw_revision_id", "raw_verification_id",
    )

    class Meta:
        constraints = [
            # Phase-8 semantics, unchanged, for plan-less Configlets.
            models.UniqueConstraint(
                fields=["change", "sequence"], condition=Q(plan__isnull=True), name="unique_change_configlet_sequence"
            ),
            models.UniqueConstraint(
                fields=["change", "cfg_id"], condition=Q(plan__isnull=True), name="unique_change_cfg_id"
            ),
            # Phase 14: identity is unique per plan generation, so history can coexist.
            models.UniqueConstraint(
                fields=["plan", "sequence"], condition=Q(plan__isnull=False), name="unique_plan_configlet_sequence"
            ),
            models.UniqueConstraint(
                fields=["plan", "cfg_id"], condition=Q(plan__isnull=False), name="unique_plan_cfg_id"
            ),
        ]
        ordering = ["change", "plan", "sequence"]

    def __str__(self):
        return f"{self.change.change_id} / {self.cfg_id}"

    @property
    def full_identifier(self) -> str:
        return f"{self.change.change_id} / {self.cfg_id}"

    def save(self, *args, **kwargs):
        _forbid_field_mutation(self, "cfg_id")
        if self.pk and self.plan_id:
            existing = type(self).objects.filter(pk=self.pk).values(*self.PLAN_FROZEN_FIELDS).first()
            if existing is not None:
                for field_name in self.PLAN_FROZEN_FIELDS:
                    if existing[field_name] != getattr(self, field_name):
                        raise ValueError(f"Configlet.{field_name} of a generated plan is immutable after creation.")
        super().save(*args, **kwargs)


class ConfigletDependency(models.Model):
    """
    A directed dependency: `configlet` depends on `depends_on`. Same-Change
    only for now (cross-Change dependency planning is Phase 13's dependency
    engine); self-dependency is rejected at both the DB (CheckConstraint)
    and service layer.
    """

    configlet = models.ForeignKey(Configlet, on_delete=models.CASCADE, related_name="dependencies")
    depends_on = models.ForeignKey(Configlet, on_delete=models.CASCADE, related_name="dependents")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["configlet", "depends_on"], name="unique_configlet_dependency"),
            models.CheckConstraint(
                check=~Q(configlet=F("depends_on")), name="configlet_dependency_no_self_dependency"
            ),
        ]

    def __str__(self):
        return f"{self.configlet.cfg_id} depends on {self.depends_on.cfg_id}"

    def save(self, *args, **kwargs):
        if self.configlet_id == self.depends_on_id:
            raise ValueError("A Configlet cannot depend on itself.")
        if self.configlet.change_id != self.depends_on.change_id:
            raise ValueError("Configlet dependencies must reference Configlets within the same Change.")
        super().save(*args, **kwargs)


class ChangeLifecycleEvent(models.Model):
    """
    Append-oriented lifecycle history for one Change. Every explicit
    lifecycle transition recorded by lifecycle_service.record_lifecycle_event
    creates one new row here -- rows are never edited after creation, and no
    autonomous process writes one in Phase 8 (no Golden promotion, no soak
    timer, no auto-rollback).
    """

    change = models.ForeignKey(Change, on_delete=models.CASCADE, related_name="lifecycle_events")
    from_state = models.CharField(max_length=32, choices=ChangeLifecycleState.choices, blank=True, default="")
    to_state = models.CharField(max_length=32, choices=ChangeLifecycleState.choices)
    reason = models.TextField(blank=True, default="")
    actor = models.CharField(max_length=150, blank=True, default="")
    occurred_at = models.DateTimeField(auto_now_add=True)
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["occurred_at"]
        indexes = [models.Index(fields=["change", "occurred_at"])]

    def __str__(self):
        return f"{self.change.change_id}: {self.from_state or '(none)'} -> {self.to_state}"

    def save(self, *args, **kwargs):
        _forbid_row_mutation(self)
        super().save(*args, **kwargs)


# V2 Phase 1: website request / identity evidence.  Distinguished from DOMAIN audit events (validation, plan,
# execution, bundle, soak, ...) so "this GET changed no domain state" stays expressible: ``AuditEvent.domain``.
WEB_AUDIT_EVENT_TYPES = frozenset({
    "AUTH_LOGIN_SUCCEEDED", "AUTH_LOGIN_FAILED", "AUTH_LOGIN_THROTTLED", "AUTH_LOGOUT", "APP_MFA_ENROLLED",
    "APP_MFA_VERIFIED", "APP_MFA_FAILED", "APP_MFA_RESET", "ACCESS_DENIED", "WEB_ACTION", "SENSITIVE_READ",
})


class DomainAuditEventManager(models.Manager):
    def get_queryset(self):
        return super().get_queryset().exclude(event_type__in=WEB_AUDIT_EVENT_TYPES)


class AuditEvent(models.Model):
    """
    General-purpose, append-only audit trail for control-plane mutations
    other than lifecycle transitions (which get their own structured
    ChangeLifecycleEvent). Phase 8 populates this only for explicit
    model/service actions it performs itself -- future validation/
    deployment/rollback event types are reserved here but unused until
    those phases exist.
    """

    event_type = models.CharField(max_length=32, choices=AuditEventType.choices)
    change = models.ForeignKey(
        Change, null=True, blank=True, on_delete=models.SET_NULL, related_name="audit_events"
    )
    object_type = models.CharField(max_length=64, blank=True, default="")
    object_id = models.CharField(max_length=64, blank=True, default="")
    actor = models.CharField(max_length=150, blank=True, default="")
    summary = models.CharField(max_length=255)
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    # V2 Phase 1 -- request correlation.  ``actor`` stays the acting principal string (a human username, or an explicit
    # non-human principal such as "execution-engine" / "probation-soak-collector"); ``actor_user`` is the AUTHENTICATED
    # website user who initiated the request, filled for every event written inside an NMAS request (including domain
    # events written by services) from core.services.identity.context.  Everything below is redacted evidence only: no
    # request body, cookie, header value, password or OTP is ever stored.
    actor_user = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="nmas_audit_events"
    )
    request_id = models.CharField(max_length=64, blank=True, default="", db_index=True)
    outcome = models.CharField(max_length=16, blank=True, default="")
    http_method = models.CharField(max_length=8, blank=True, default="")
    route = models.CharField(max_length=128, blank=True, default="")
    status_code = models.PositiveSmallIntegerField(null=True, blank=True)
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=255, blank=True, default="")

    objects = models.Manager()
    domain = DomainAuditEventManager()

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["-created_at"]),
            models.Index(fields=["event_type"]),
        ]

    def __str__(self):
        return f"[{self.event_type}] {self.summary}"

    def save(self, *args, **kwargs):
        _forbid_row_mutation(self)
        super().save(*args, **kwargs)


class ValidationRunStatus(models.TextChoices):
    """Overall Tier-2 result vocabulary. STALE is a currency state, never a result."""

    PASS = "PASS", "Pass"
    PASS_WITH_WARNINGS = "PASS_WITH_WARNINGS", "Pass with warnings"
    BLOCKED = "BLOCKED", "Blocked"
    INCOMPLETE = "INCOMPLETE", "Incomplete"


class ChangeValidationRun(models.Model):
    """
    One completed Phase-13 Tier-2 (project-aware) validation of a whole Change.

    Append-only evidence: a run is created finished and is never modified --
    a later intent edit, a NetBox change, or an operator re-run creates a NEW
    row.  All structured output is sanitized JSON on this one row (no
    per-finding table).  It never changes Change.lifecycle_state; validation
    status and lifecycle are separate concepts.
    """

    run_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    change = models.ForeignKey(Change, on_delete=models.CASCADE, related_name="validation_runs")
    status = models.CharField(max_length=24, choices=ValidationRunStatus.choices)
    engine_version = models.CharField(max_length=32)
    input_hash = models.CharField(max_length=64, help_text="SHA-256 of the normalized accepted Change snapshot.")
    source_hash = models.CharField(max_length=64, help_text="SHA-256 over the external-source fingerprints consumed.")
    repository_head = models.CharField(max_length=64, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.CharField(max_length=150, blank=True, default="")
    summary = models.JSONField(default=dict, blank=True)
    report = models.JSONField(default=dict, blank=True)
    derived_facts = models.JSONField(default=list, blank=True)
    dependency_graph = models.JSONField(default=dict, blank=True)
    intent_revision_map = models.JSONField(default=dict, blank=True)
    source_provenance = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-created_at", "-id"]
        indexes = [models.Index(fields=["change", "-created_at"])]

    def __str__(self):
        return f"{self.change.change_id} validation {str(self.run_id)[:8]}: {self.status}"

    def save(self, *args, **kwargs):
        if self.status not in ValidationRunStatus.values:
            raise ValueError(f"Invalid validation status {self.status!r}.")
        _forbid_row_mutation(self)
        super().save(*args, **kwargs)


class ConfigurationValidationStatus(models.TextChoices):
    """State of one external (GitHub Actions) Configuration Validation of a validated Change snapshot."""

    NOT_TRIGGERED = "NOT_TRIGGERED", "Not triggered"
    QUEUED = "QUEUED", "Queued"
    IN_PROGRESS = "IN_PROGRESS", "In progress"
    PASS = "PASS", "Pass"
    FAIL = "FAIL", "Fail"
    ERROR = "ERROR", "Error"
    STALE = "STALE", "Stale"


class ConfigurationValidationRun(models.Model):
    """One dispatch of the GitHub Actions workflow "Configuration Validation" for ONE immutable Tier-2 validation run.

    The row is bound to the exact snapshot and candidate that were sent (``snapshot_hash``, ``candidate_hash``,
    ``bundle_sha256``): a PASS applies to that candidate only.  The Tier-2 run it points at is never modified; this row
    is the only thing that changes, and only in its GitHub tracking fields.  It holds no secret and no configuration text.
    """

    correlation_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    change = models.ForeignKey(Change, on_delete=models.CASCADE, related_name="configuration_validation_runs")
    validation_run = models.ForeignKey(ChangeValidationRun, on_delete=models.CASCADE, related_name="configuration_validation_runs")
    snapshot_hash = models.CharField(max_length=64, editable=False, help_text="Input hash of the Tier-2 run: the immutable Change snapshot.")
    candidate_hash = models.CharField(max_length=64, blank=True, default="", editable=False)
    bundle_sha256 = models.CharField(max_length=64, blank=True, default="", editable=False)
    status = models.CharField(max_length=16, choices=ConfigurationValidationStatus.choices, default=ConfigurationValidationStatus.NOT_TRIGGERED)
    repository = models.CharField(max_length=140, blank=True, default="")
    github_run_id = models.BigIntegerField(null=True, blank=True)
    run_url = models.URLField(max_length=300, blank=True, default="")
    tested_sha = models.CharField(max_length=64, blank=True, default="", help_text="Repository commit the workflow tested against.")
    failure_summary = models.CharField(max_length=500, blank=True, default="")
    demonstration = models.BooleanField(default=False, editable=False,
                                        help_text="A deliberately invalid bundle sent to show a failing run.  Never satisfies the execution gate.")
    triggered_by = models.CharField(max_length=150, blank=True, default="")
    triggered_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at", "-id"]
        indexes = [models.Index(fields=["change", "-created_at"])]

    def __str__(self):
        return f"{self.change.change_id} configuration validation {str(self.correlation_id)[:8]}: {self.status}"


class NetworkConfigValidationStatus(models.TextChoices):
    """Result vocabulary for device-configuration validation (never Tier-3)."""

    PASS = "PASS", "Pass"
    WARNING = "WARNING", "Pass with warnings"
    BLOCKED = "BLOCKED", "Blocked before write"
    FAIL = "FAIL", "Live state failed validation"


class NetworkConfigValidationOperation(models.TextChoices):
    CANDIDATE = "CANDIDATE", "Candidate configuration"
    RUNNING = "RUNNING", "Existing running configuration"
    REMOVAL_PRECHECK = "REMOVAL_PRECHECK", "Removal pre-validation"
    POST_PUSH = "POST_PUSH", "Post-push live validation"
    POST_REMOVAL = "POST_REMOVAL", "Post-removal live validation"


class NetworkConfigValidationRun(models.Model):
    """Append-only evidence that validates NETWORK DEVICE CONFIGURATION.

    This is intentionally separate from ``ChangeValidationRun`` (Tier-2 whole-change/project validation),
    ``OperationalCheckRun`` (health/pre/post checks), and hosted Tier-3 (NMAS application validation).
    Structured findings are bounded and sanitized by the service; raw device output and secrets are never stored.
    """

    run_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    operation_type = models.CharField(max_length=24, choices=NetworkConfigValidationOperation.choices)
    status = models.CharField(max_length=12, choices=NetworkConfigValidationStatus.choices)
    change = models.ForeignKey(
        Change, null=True, blank=True, on_delete=models.SET_NULL, related_name="network_config_validation_runs"
    )
    revision = models.ForeignKey(
        DeviceIntentRevision, null=True, blank=True, on_delete=models.SET_NULL,
        related_name="network_config_validation_runs",
    )
    snapshot = models.ForeignKey(
        "RunningConfigSnapshot", null=True, blank=True, on_delete=models.RESTRICT,
        related_name="network_config_validation_runs",
    )
    execution_run = models.ForeignKey(
        "ChangeExecutionRun", null=True, blank=True, on_delete=models.RESTRICT,
        related_name="network_config_validation_runs",
    )
    operational_run = models.ForeignKey(
        "OperationalCheckRun", null=True, blank=True, on_delete=models.RESTRICT,
        related_name="network_config_validation_runs",
    )
    device = models.CharField(max_length=64, blank=True, default="")
    platform = models.CharField(max_length=32, blank=True, default="")
    engine_version = models.CharField(max_length=32)
    input_hash = models.CharField(max_length=64)
    source_hash = models.CharField(max_length=64, blank=True, default="")
    checks = models.JSONField(default=list, blank=True)
    warnings = models.JSONField(default=list, blank=True)
    errors = models.JSONField(default=list, blank=True)
    netbox_observations = models.JSONField(default=list, blank=True)
    syntax_result = models.JSONField(default=dict, blank=True)
    semantic_result = models.JSONField(default=dict, blank=True)
    live_result = models.JSONField(default=dict, blank=True)
    provenance = models.JSONField(default=dict, blank=True)
    created_by = models.CharField(max_length=150, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at", "-id"]
        indexes = [
            models.Index(fields=["change", "-created_at"]),
            models.Index(fields=["device", "-created_at"]),
            models.Index(fields=["operation_type", "-created_at"]),
        ]

    def __str__(self):
        target = self.change.change_id if self.change_id else self.device
        return f"{target} network-config {self.operation_type} {str(self.run_id)[:8]}: {self.status}"

    def save(self, *args, **kwargs):
        if self.pk:
            raise ValueError("NetworkConfigValidationRun rows are append-only evidence.")
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("NetworkConfigValidationRun rows are immutable evidence and cannot be deleted.")


class ChangePlan(models.Model):
    """
    One generated Phase-14 deployment PLAN for a Change: an immutable snapshot of
    the ordered Configlets built from exactly ONE CURRENT Phase-13 validation run.

    Append-only evidence (like ChangeValidationRun): a plan is created finished and
    never modified.  Its Configlets (``configlets``) and their dependency edges are
    owned by it and frozen (see ``Configlet.PLAN_FROZEN_FIELDS``).  Whether a plan is
    still CURRENT is a computed currency state, never stored -- a plan stales when its
    pinned validation stales or is superseded.  A plan is not a deployment lifecycle:
    it never changes ``Change.lifecycle_state`` and executes nothing.
    """

    plan_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    change = models.ForeignKey(Change, on_delete=models.CASCADE, related_name="plans")
    validation_run = models.ForeignKey(ChangeValidationRun, on_delete=models.RESTRICT, related_name="plans")
    planner_version = models.CharField(max_length=32)
    validation_input_hash = models.CharField(max_length=64)
    validation_source_hash = models.CharField(max_length=64)
    validation_engine_version = models.CharField(max_length=32)
    plan_hash = models.CharField(
        max_length=64, help_text="SHA-256 of the canonical semantic plan (ignores run IDs and timestamps)."
    )
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.CharField(max_length=150, blank=True, default="")
    summary = models.JSONField(default=dict, blank=True)
    warnings = models.JSONField(default=list, blank=True)
    provenance = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-created_at", "-id"]
        indexes = [models.Index(fields=["change", "-created_at"])]
        constraints = [
            models.UniqueConstraint(
                fields=["validation_run", "planner_version"], name="unique_plan_per_validation_run_and_planner"
            ),
        ]

    def __str__(self):
        return f"{self.change.change_id} plan {str(self.plan_id)[:8]}"

    def save(self, *args, **kwargs):
        _forbid_row_mutation(self)
        super().save(*args, **kwargs)


class OperationalRunMode(models.TextChoices):
    FLEET_QUICK = "FLEET_QUICK", "Fleet Quick snapshot"
    DEVICE_DEEP = "DEVICE_DEEP", "Device Deep Health"
    CHANGE_PRECHECK = "CHANGE_PRECHECK", "Change precheck"
    CHANGE_POSTCHECK = "CHANGE_POSTCHECK", "Change postcheck"


# Each mode has its own small status vocabulary (see core/services/health/codes.py); ONE table stores them all.
OPERATIONAL_RUN_STATUSES = {
    OperationalRunMode.FLEET_QUICK: ("HEALTHY", "DEGRADED", "UNHEALTHY", "UNKNOWN"),
    OperationalRunMode.DEVICE_DEEP: ("HEALTHY", "DEGRADED", "UNHEALTHY", "UNKNOWN"),
    OperationalRunMode.CHANGE_PRECHECK: ("PASS", "PASS_WITH_WARNINGS", "BLOCKED", "INCOMPLETE"),
    OperationalRunMode.CHANGE_POSTCHECK: ("PASS", "PASS_WITH_WARNINGS", "FAIL", "INCOMPLETE"),
}


class OperationalCheckRun(models.Model):
    """
    One completed Phase-15 operational check: a Fleet Quick snapshot, a per-device Deep Health run, a Change
    precheck, or a Change postcheck.  Health / verification evidence is NOT validation evidence, so this is its own
    model (``ChangeValidationRun`` stays Phase-13-only) -- but ONE generalized model rather than one per mode.

    Append-only (a run is created finished and never modified).  ``report`` holds only normalized, sanitized,
    bounded facts and check results -- never raw command output or credentials.  A run never changes
    ``Change.lifecycle_state``, a plan, a Configlet or a validation run.
    """

    run_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    mode = models.CharField(max_length=20, choices=OperationalRunMode.choices)
    status = models.CharField(max_length=24)
    device = models.CharField(max_length=64, blank=True, default="", help_text="DEVICE_DEEP: the managed device.")
    change = models.ForeignKey(Change, null=True, blank=True, on_delete=models.CASCADE, related_name="operational_runs")
    plan = models.ForeignKey(ChangePlan, null=True, blank=True, on_delete=models.SET_NULL, related_name="operational_runs")
    engine_version = models.CharField(max_length=32)
    started_at = models.DateTimeField()
    finished_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.CharField(max_length=150, blank=True, default="")
    summary = models.JSONField(default=dict, blank=True)
    report = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-created_at", "-id"]
        indexes = [
            models.Index(fields=["mode", "-created_at"]),
            models.Index(fields=["change", "-created_at"]),
            models.Index(fields=["device", "-created_at"]),
        ]

    def __str__(self):
        return f"{self.mode} {str(self.run_id)[:8]}: {self.status}"

    def save(self, *args, **kwargs):
        if self.mode not in OperationalRunMode.values:
            raise ValueError(f"Invalid operational run mode {self.mode!r}.")
        if self.status not in OPERATIONAL_RUN_STATUSES[self.mode]:
            raise ValueError(f"Invalid status {self.status!r} for {self.mode}.")
        _forbid_row_mutation(self)
        super().save(*args, **kwargs)


# =============================================================================
# Phase 17 -- structured execution (Complete / Partial (UAT)).
#
# Persistence for the explicit, operator-triggered execution of a CURRENT plan's structured Configlets.  Like the
# validation / plan / operational-check models these are append-oriented evidence: a run is created RUNNING when an
# attempt starts (so a crash is visible and the concurrency guard has something to hold), is finalised exactly ONCE,
# and is immutable afterwards.  Per-Configlet results follow the same rule.  Neither model stores raw device output,
# credentials or unbounded text -- only sanitized error categories and bounded, secret-free facts.  Execution never
# changes ``Change.lifecycle_state`` (Golden / Probation / soak belong to later phases).
# =============================================================================


class ExecutionRunState(models.TextChoices):
    RUNNING = "RUNNING", "Running"
    FINISHED = "FINISHED", "Finished"


class ExecutionOutcome(models.TextChoices):
    """Final outcome vocabulary of one execution attempt.  Deliberately NOT the validation / precheck / postcheck words."""

    SUCCEEDED = "SUCCEEDED", "Succeeded (Complete)"
    UAT_SCOPE_APPLIED = "UAT_SCOPE_APPLIED", "UAT scope applied and verified"
    UAT_SCOPE_APPLIED_UNVERIFIED = "UAT_SCOPE_APPLIED_UNVERIFIED", "UAT scope applied, verification incomplete"
    UAT_SCOPE_APPLIED_POSTCHECK_FAILED = "UAT_SCOPE_APPLIED_POSTCHECK_FAILED", "UAT scope applied, postcheck failed"
    FAILED_PARTIAL_APPLIED = "FAILED_PARTIAL_APPLIED", "Failed; earlier work preserved (UAT)"
    FAILED_NO_MUTATION = "FAILED_NO_MUTATION", "Failed; no device was changed"
    FAILED_ROLLED_BACK = "FAILED_ROLLED_BACK", "Failed; compensation restored the prior state"
    FAILED_COMPENSATION_INCOMPLETE = "FAILED_COMPENSATION_INCOMPLETE", "Failed; compensation incomplete"
    POSTCHECK_FAILED_ROLLED_BACK = "POSTCHECK_FAILED_ROLLED_BACK", "Applied but postcheck failed; compensation restored the prior state"
    POSTCHECK_FAILED_COMPENSATION_INCOMPLETE = "POSTCHECK_FAILED_COMPENSATION_INCOMPLETE", "Applied but postcheck failed; compensation incomplete"
    BLOCKED = "BLOCKED", "Blocked before any device change"
    INTERRUPTED = "INTERRUPTED", "Interrupted; device state unknown"


class ExecutionResultPhase(models.TextChoices):
    APPLY = "APPLY", "Apply"
    COMPENSATE = "COMPENSATE", "Compensate"


class ExecutionResultStatus(models.TextChoices):
    IN_PROGRESS = "IN_PROGRESS", "In progress"
    APPLIED = "APPLIED", "Applied"
    ALREADY_SATISFIED = "ALREADY_SATISFIED", "Already satisfied (nothing sent)"
    FAILED = "FAILED", "Failed"
    UNKNOWN = "UNKNOWN", "Unknown"
    NOT_ATTEMPTED = "NOT_ATTEMPTED", "Not attempted"
    COMPENSATED = "COMPENSATED", "Compensated and verified"
    COMPENSATION_FAILED = "COMPENSATION_FAILED", "Compensation failed"
    COMPENSATION_UNVERIFIED = "COMPENSATION_UNVERIFIED", "Compensation not verified"


class ChangeExecutionRun(models.Model):
    """One explicit execution attempt of a Change's CURRENT plan (Complete or Partial (UAT))."""

    run_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    change = models.ForeignKey(Change, on_delete=models.CASCADE, related_name="execution_runs")
    plan = models.ForeignKey(ChangePlan, on_delete=models.RESTRICT, related_name="execution_runs")
    validation_run = models.ForeignKey(ChangeValidationRun, on_delete=models.RESTRICT, related_name="execution_runs")
    precheck_run = models.ForeignKey(
        OperationalCheckRun, null=True, blank=True, on_delete=models.RESTRICT, related_name="execution_runs_as_precheck"
    )
    postcheck_run = models.ForeignKey(
        OperationalCheckRun, null=True, blank=True, on_delete=models.RESTRICT, related_name="execution_runs_as_postcheck"
    )
    mode = models.CharField(max_length=16, choices=ExecutionMode.choices)
    state = models.CharField(max_length=16, choices=ExecutionRunState.choices, default=ExecutionRunState.RUNNING)
    outcome = models.CharField(max_length=48, choices=ExecutionOutcome.choices, blank=True, default="")
    actor = models.CharField(max_length=150, blank=True, default="")
    engine_version = models.CharField(max_length=32)
    plan_hash = models.CharField(max_length=64)
    validation_input_hash = models.CharField(max_length=64)
    validation_source_hash = models.CharField(max_length=64)
    scope = models.JSONField(default=dict, blank=True)
    devices = models.JSONField(default=list, blank=True)
    started_at = models.DateTimeField()
    finished_at = models.DateTimeField(null=True, blank=True)
    lease_expires_at = models.DateTimeField()
    summary = models.JSONField(default=dict, blank=True)
    report = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-started_at", "-id"]
        indexes = [models.Index(fields=["change", "-started_at"]), models.Index(fields=["state"])]
        constraints = [
            # DB-enforced: a Change can have at most ONE active execution, however many requests race.
            models.UniqueConstraint(
                fields=["change"], condition=Q(state="RUNNING"), name="unique_active_execution_per_change"
            ),
        ]

    def __str__(self):
        return f"{self.change.change_id} execution {str(self.run_id)[:8]}: {self.outcome or self.state}"

    def save(self, *args, **kwargs):
        if self.mode not in ExecutionMode.values:
            raise ValueError(f"Invalid execution mode {self.mode!r}.")
        if self.state == ExecutionRunState.FINISHED and self.outcome not in ExecutionOutcome.values:
            raise ValueError("A finished execution run needs a valid outcome.")
        if self.state == ExecutionRunState.RUNNING and self.outcome:
            raise ValueError("A running execution run has no outcome yet.")
        if self.pk:
            persisted = type(self).objects.filter(pk=self.pk).values_list("state", flat=True).first()
            if persisted == ExecutionRunState.FINISHED:
                raise ValueError("ChangeExecutionRun records are immutable once finished.")
        super().save(*args, **kwargs)


class ConfigletExecutionResult(models.Model):
    """One Configlet's APPLY (or COMPENSATE) attempt inside one run.  Finalised once, immutable afterwards."""

    run = models.ForeignKey(ChangeExecutionRun, on_delete=models.CASCADE, related_name="results")
    configlet = models.ForeignKey(Configlet, null=True, blank=True, on_delete=models.SET_NULL, related_name="execution_results")
    cfg_id = models.CharField(max_length=16)
    sequence = models.PositiveIntegerField()
    device = models.CharField(max_length=64)
    object_type = models.CharField(max_length=64, blank=True, default="")
    operation = models.CharField(max_length=20, blank=True, default="")
    phase = models.CharField(max_length=12, choices=ExecutionResultPhase.choices, default=ExecutionResultPhase.APPLY)
    status = models.CharField(max_length=32, choices=ExecutionResultStatus.choices)
    error_code = models.CharField(max_length=48, blank=True, default="")
    partial_effects = models.BooleanField(default=False, help_text="A device change may remain even though this attempt failed.")
    lines_sent = models.PositiveIntegerField(default=0)
    started_at = models.DateTimeField()
    finished_at = models.DateTimeField(null=True, blank=True)
    previous_state = models.JSONField(default=dict, blank=True)
    detail = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["run", "phase", "sequence"]
        constraints = [
            models.UniqueConstraint(fields=["run", "sequence", "phase"], name="unique_execution_result_per_phase"),
        ]

    def __str__(self):
        return f"{self.run.change.change_id} {self.cfg_id} {self.phase}: {self.status}"

    def save(self, *args, **kwargs):
        if self.status not in ExecutionResultStatus.values:
            raise ValueError(f"Invalid execution result status {self.status!r}.")
        if self.pk:
            persisted = type(self).objects.filter(pk=self.pk).values_list("status", flat=True).first()
            if persisted is not None and persisted != ExecutionResultStatus.IN_PROGRESS:
                raise ValueError("ConfigletExecutionResult records are immutable once finalised.")
        super().save(*args, **kwargs)


class ExecutionDeviceLock(models.Model):
    """Transient lock row: one device is being changed by at most one run.  Deleted when the run finalises.

    The UNIQUE constraint makes overlapping executions impossible at the database level (not merely improbable).  The holder
    is either a Change execution run or a maintenance transaction (exactly one of the two): a Change and a maintenance drain
    or restore can never write to the same device at the same time.
    """

    device = models.CharField(max_length=64, unique=True)
    run = models.ForeignKey(ChangeExecutionRun, on_delete=models.CASCADE, related_name="device_locks", null=True, blank=True)
    maintenance = models.ForeignKey("MaintenanceRecord", on_delete=models.CASCADE, related_name="device_locks", null=True, blank=True)
    acquired_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.CheckConstraint(
                condition=(Q(run__isnull=False) & Q(maintenance__isnull=True)) | (Q(run__isnull=True) & Q(maintenance__isnull=False)),
                name="execution_device_lock_one_holder",
            ),
        ]

    def __str__(self):
        holder = str(self.run.run_id)[:8] if self.run_id else (self.maintenance.record_id if self.maintenance_id else "?")
        return f"{self.device} locked by {holder}"


# =============================================================================
# Phase 18 -- Raw Configlets + isolated verifier / sandbox.
#
# Raw Configlets are an EXPLICIT, separate escape hatch from the structured Device Builder (nothing here touches DeviceIntent
# sections).  They are INPUT objects: the planner may materialise a VERIFIED revision into a normal, immutable plan Configlet
# (``Configlet.origin == RAW``) that pins the exact revision and verification run.  Everything semantic lives on the immutable
# revision, so "editing" always means a NEW revision and historical plans / verifications / executions keep referring to exactly
# what existed.  Verification runs are append-only evidence (created RUNNING, finalised exactly once, immutable afterwards) and
# are never mutated into a later result.  No model here stores a credential, a raw sandbox log or an environment dump.
# =============================================================================


class RawVerificationState(models.TextChoices):
    RUNNING = "RUNNING", "Running"
    FINISHED = "FINISHED", "Finished"


class RawVerificationResult(models.TextChoices):
    """Verification RESULT vocabulary.  STALE / NEVER_RUN are CURRENCY states, computed, never stored as a result."""

    PASS = "PASS", "Pass"
    PASS_WITH_WARNINGS = "PASS_WITH_WARNINGS", "Pass with warnings"
    BLOCKED = "BLOCKED", "Blocked"
    INCOMPLETE = "INCOMPLETE", "Incomplete"


class RawConfiglet(models.Model):
    """Stable identity of one Raw Configlet inside a Change (``RAW-001``...).  Content lives on its immutable revisions.

    ``raw_id`` is deterministic, per-Change, immutable and the only identifier operators and dependency references use (the
    integer primary key is an implementation detail).  ``enabled`` is the ONLY mutable state: a disabled Raw Configlet is
    removed from the EFFECTIVE Change input (so validation / plan currency go STALE) while every revision, verification and
    historical plan reference is preserved.  Rows are never deleted by the application.
    """

    change = models.ForeignKey(Change, on_delete=models.CASCADE, related_name="raw_configlets")
    raw_id = models.CharField(max_length=16, editable=False)
    sequence = models.PositiveIntegerField(validators=[MinValueValidator(1)])
    enabled = models.BooleanField(default=True)
    created_by = models.CharField(max_length=150, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["change", "raw_id"], name="unique_change_raw_id"),
            models.UniqueConstraint(fields=["change", "sequence"], name="unique_change_raw_sequence"),
        ]
        ordering = ["change", "sequence"]

    def __str__(self):
        return f"{self.change.change_id} / {self.raw_id}"

    @property
    def full_identifier(self) -> str:
        return f"{self.change.change_id} / {self.raw_id}"

    def latest_revision(self) -> "RawConfigletRevision | None":
        return self.revisions.order_by("-revision").first()

    def save(self, *args, **kwargs):
        _forbid_field_mutation(self, "raw_id")
        _forbid_field_mutation(self, "change_id")
        super().save(*args, **kwargs)


class RawConfigletRevision(models.Model):
    """One IMMUTABLE revision: exact text + everything semantic (target, platform, priority, dependencies, assertions).

    A new save is a new row; a revision is never edited (a database-level edit is refused in ``save``).  ``content_hash`` is the
    SHA-256 of the normalized text: it is what verification is pinned to and what the executor re-checks before sending a byte.
    """

    raw = models.ForeignKey(RawConfiglet, on_delete=models.CASCADE, related_name="revisions")
    revision = models.PositiveIntegerField(validators=[MinValueValidator(1)])
    schema_version = models.PositiveIntegerField(default=1, validators=[MinValueValidator(1)])
    name = models.CharField(max_length=120)
    description = models.TextField(blank=True, default="")
    target_device = models.CharField(max_length=64, validators=[DEVICE_NAME_VALIDATOR])
    platform = models.CharField(max_length=32, choices=Platform.choices)
    priority = models.PositiveSmallIntegerField(choices=DeploymentPriority.choices)
    dependencies = models.JSONField(default=list, blank=True, help_text="Stable node references, e.g. R1/interface/<id> or R1/raw_configlet/RAW-001.")
    assertions = models.JSONField(default=list, blank=True, help_text="Closed-catalogue structured postcheck assertions (never commands).")
    content = models.TextField()
    content_hash = models.CharField(max_length=64)
    content_bytes = models.PositiveIntegerField(default=0)
    content_lines = models.PositiveIntegerField(default=0)
    policy_version = models.CharField(max_length=32, help_text="The static policy version this text passed when it was saved.")
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.CharField(max_length=150, blank=True, default="")

    class Meta:
        constraints = [models.UniqueConstraint(fields=["raw", "revision"], name="unique_raw_revision")]
        ordering = ["raw", "revision"]

    def __str__(self):
        return f"{self.raw} rev {self.revision}"

    def save(self, *args, **kwargs):
        _forbid_row_mutation(self)
        super().save(*args, **kwargs)


class RawConfigletVerificationRun(models.Model):
    """One append-only verification attempt of ONE exact revision in an isolated sandbox / parser.

    Created RUNNING (which is also the database-enforced duplicate-run guard: at most one RUNNING run per revision) and finalised
    exactly ONCE; a finished run is immutable and is never turned into a later result -- a new attempt is a new row.  Only bounded,
    sanitized, structured findings and evidence are stored: never unbounded sandbox output, an environment dump or a credential.
    """

    run_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    revision = models.ForeignKey(RawConfigletRevision, on_delete=models.RESTRICT, related_name="verification_runs")
    state = models.CharField(max_length=16, choices=RawVerificationState.choices, default=RawVerificationState.RUNNING)
    result = models.CharField(max_length=24, choices=RawVerificationResult.choices, blank=True, default="")
    content_hash = models.CharField(max_length=64)
    platform = models.CharField(max_length=32)
    verifier_version = models.CharField(max_length=32)
    policy_version = models.CharField(max_length=32)
    adapter_id = models.CharField(max_length=48, blank=True, default="")
    adapter_version = models.CharField(max_length=32, blank=True, default="")
    backend = models.CharField(max_length=120, blank=True, default="", help_text="Sandbox backend identity (server-owned image tag).")
    actor = models.CharField(max_length=150, blank=True, default="")
    started_at = models.DateTimeField()
    finished_at = models.DateTimeField(null=True, blank=True)
    lease_expires_at = models.DateTimeField()
    static_result = models.JSONField(default=dict, blank=True)
    findings = models.JSONField(default=list, blank=True)
    evidence = models.JSONField(default=dict, blank=True)
    provenance = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-started_at", "-id"]
        indexes = [models.Index(fields=["revision", "-started_at"]), models.Index(fields=["state"])]
        constraints = [
            # DB-enforced: however many requests race, one revision has at most ONE active verification.
            models.UniqueConstraint(fields=["revision"], condition=Q(state="RUNNING"), name="unique_active_raw_verification_per_revision"),
        ]

    def __str__(self):
        return f"{self.revision} verification {str(self.run_id)[:8]}: {self.result or self.state}"

    def save(self, *args, **kwargs):
        if self.state == RawVerificationState.FINISHED and self.result not in RawVerificationResult.values:
            raise ValueError("A finished verification run needs a valid result.")
        if self.state == RawVerificationState.RUNNING and self.result:
            raise ValueError("A running verification run has no result yet.")
        if self.pk:
            persisted = type(self).objects.filter(pk=self.pk).values_list("state", flat=True).first()
            if persisted == RawVerificationState.FINISHED:
                raise ValueError("RawConfigletVerificationRun records are immutable once finished.")
        super().save(*args, **kwargs)


# =============================================================================
# Phase 19 -- immutable configuration bundles (UAT -> Probation -> Golden foundations).
#
# A bundle is EVIDENCE, not a mutable "current configuration" record: an immutable, content-addressed artifact that freezes
# exactly what a historical Partial (UAT) execution applied, with its provenance.  A lifecycle transition never edits a bundle:
# UAT -> Probation and (Phase 20) Probation -> Golden each create a NEW bundle whose ``parent`` is the previous one, so every
# artifact stays what it was forever.  Bundle KIND and soak STATE are different concepts; no soak state exists here (Phase 20).
#
# Layers of protection (none of them is "the button is disabled"): creation only through ``core.services.bundle_service``; a
# row can be written once (``save`` refuses a second write, and the queryset refuses ``update`` / ``delete`` / ``bulk_update``);
# every foreign key to history is PROTECT/RESTRICT (nothing a bundle pins can be deleted from under it); database constraints for
# kind/parent shape and one-bundle-per-source uniqueness; no admin or edit form; and an on-demand integrity verifier that
# recomputes the canonical digests from the stored contents (a stored "integrity_ok" flag is never trusted).
# =============================================================================


class BundleKind(models.TextChoices):
    """Explicit typed bundle kind -- never inferred from a name, an id prefix or the existence of a parent."""

    UAT = "UAT", "UAT"
    # V2 Phase 5: the root artifact of a verified COMPLETE execution (an ordinary configuration Change or a new-device provisioning Change).
    # It is NOT a UAT bundle and is never
    # labelled as one: Complete applied the whole plan, the postcheck confirmed it, and nothing was left partially applied.
    DEPLOYED = "DEPLOYED", "Deployed (Complete, verified)"
    PROBATION = "PROBATION", "Probation"
    GOLDEN = "GOLDEN", "Golden"
    LEGACY_BASELINE = "LEGACY_BASELINE", "Legacy baseline candidate"   # one-time bootstrap: the observed pre-automation network (never Golden by itself)


class BundleProvenance(models.TextChoices):
    """WHERE a bundle's configuration came from -- an explicit, typed fact, never inferred.

    EXECUTION_LINEAGE is the normal path (Change -> plan -> Partial UAT execution -> UAT -> Probation -> soak -> Golden).  LEGACY_BOOTSTRAP is
    the ONE-TIME adoption of a network that was configured traditionally BEFORE the automation framework existed: it has no Change, plan or
    execution to point at, and none is fabricated.  It is only valid for a LEGACY_BASELINE candidate and the single Golden sealed from it."""

    EXECUTION_LINEAGE = "EXECUTION_LINEAGE", "Execution lineage"
    LEGACY_BOOTSTRAP = "LEGACY_BOOTSTRAP", "Legacy bootstrap"


BUNDLE_ID_PREFIX = {BundleKind.UAT: "BND-UAT-", BundleKind.DEPLOYED: "BND-DEP-", BundleKind.PROBATION: "BND-PROB-",
                    BundleKind.GOLDEN: "BND-GOLD-", BundleKind.LEGACY_BASELINE: "BND-LEGACY-"}
# The ONLY legal lineages: UAT (root) -> PROBATION -> GOLDEN, and DEPLOYED (root) -> PROBATION -> GOLDEN.  No skipping, no reversing, no
# arbitrary parent.  A root derives from an execution: UAT from a Partial (UAT) run, DEPLOYED from a verified Complete run (ordinary or provisioning Change).
BUNDLE_ROOT_KINDS = (BundleKind.UAT, BundleKind.DEPLOYED)
BUNDLE_ROOT_MODE = {BundleKind.UAT: "PARTIAL_UAT", BundleKind.DEPLOYED: "COMPLETE"}
BUNDLE_PARENT_KIND = {BundleKind.PROBATION: BUNDLE_ROOT_KINDS, BundleKind.GOLDEN: (BundleKind.PROBATION,)}
_HEX64 = re.compile(r"[0-9a-f]{64}")   # a SHA-256 digest: 64 lowercase hexadecimal characters


class _ImmutableQuerySet(models.QuerySet):
    """Refuses every bulk mutation.  (``bulk_create`` stays available: bundles are only ever CREATED, by the service, atomically.)"""

    def update(self, **kwargs):
        raise ValueError(f"{self.model.__name__} records are immutable and cannot be updated.")

    def bulk_update(self, objs, fields, batch_size=None):
        raise ValueError(f"{self.model.__name__} records are immutable and cannot be updated.")

    def delete(self):
        raise ValueError(f"{self.model.__name__} records are historical artifacts and cannot be deleted.")


_ImmutableManager = models.Manager.from_queryset(_ImmutableQuerySet)


_NORMAL_SOURCE_FIELDS = ("change_id", "plan_id", "validation_run_id", "execution_run_id")
_ALL_SOURCE_FIELDS = (*_NORMAL_SOURCE_FIELDS, "postcheck_run_id")


def _validate_bundle_lineage(bundle) -> None:
    """Structural lineage rules, enforced when a bundle row is first written (the integrity verifier re-checks them later).

    Two provenance types, and NO shared shortcut between them:

    * EXECUTION_LINEAGE (the normal path): UAT (root) -> PROBATION -> GOLDEN, every bundle pinning a Change / plan / validation / execution.
    * LEGACY_BOOTSTRAP (the one-time adoption of the pre-automation network): a LEGACY_BASELINE candidate (root, NO Change / plan / execution)
      -> exactly ONE GOLDEN.  A missing Change / plan / execution is valid ONLY here; it is never valid for a normal Golden bundle.
    """
    if bundle.kind not in BundleKind.values:
        raise ValueError(f"Invalid bundle kind {bundle.kind!r}.")
    if bundle.provenance not in BundleProvenance.values:
        raise ValueError(f"Invalid bundle provenance {bundle.provenance!r}.")
    if bundle.bundle_id != f"{BUNDLE_ID_PREFIX[bundle.kind]}{int(bundle.sequence):06d}":
        raise ValueError("The bundle id must match its kind and sequence.")
    for name in ("payload_digest", "bundle_digest"):
        if not _HEX64.fullmatch(str(getattr(bundle, name) or "")):
            raise ValueError(f"{name} must be a SHA-256 digest (64 lowercase hexadecimal characters).")
    if bundle.provenance == BundleProvenance.LEGACY_BOOTSTRAP:
        _validate_legacy_lineage(bundle)
        return
    if bundle.kind == BundleKind.LEGACY_BASELINE:
        raise ValueError("A legacy baseline candidate can only carry LEGACY_BOOTSTRAP provenance.")
    if any(getattr(bundle, name) is None for name in _NORMAL_SOURCE_FIELDS):
        raise ValueError("A bundle with execution-lineage provenance pins its Change, plan, validation and execution; only a legacy-bootstrap bundle has none.")
    required_parent = BUNDLE_PARENT_KIND.get(bundle.kind)
    if required_parent is None:  # UAT / DEPLOYED: a root; it derives from an execution, never from another bundle
        if bundle.parent_id or bundle.source_uat_id:
            raise ValueError(f"A {bundle.kind} bundle is a lineage root and has no parent bundle.")
        return
    if not bundle.parent_id:
        raise ValueError(f"A {bundle.kind} bundle must derive from a {' or '.join(required_parent)} bundle.")
    parent = bundle.parent
    if parent.kind not in required_parent:
        raise ValueError(f"A {bundle.kind} bundle can only derive from a {' or '.join(required_parent)} bundle, never from a {parent.kind} bundle.")
    if parent.provenance != BundleProvenance.EXECUTION_LINEAGE:
        raise ValueError("A normal bundle can never derive from a legacy-bootstrap bundle.")
    root_id = parent.pk if parent.kind in BUNDLE_ROOT_KINDS else parent.source_uat_id
    if bundle.source_uat_id != root_id:
        raise ValueError("The source UAT bundle must be the root of the parent's lineage.")
    for name in _ALL_SOURCE_FIELDS:
        if getattr(bundle, name) != getattr(parent, name):
            raise ValueError(f"A derived bundle pins the same historical source as its parent ({name}).")
    if bundle.payload_digest != parent.payload_digest:
        raise ValueError("A derived bundle freezes the SAME configuration payload as its parent; a different payload is a new UAT candidate.")


def _validate_legacy_lineage(bundle) -> None:
    if any(getattr(bundle, name) is not None for name in _ALL_SOURCE_FIELDS) or bundle.source_uat_id:
        raise ValueError("A legacy-bootstrap bundle has no Change, plan, validation, execution or UAT: none is ever fabricated.")
    if bundle.kind == BundleKind.LEGACY_BASELINE:
        if bundle.parent_id:
            raise ValueError("A legacy baseline candidate is a lineage root.")
        return
    if bundle.kind != BundleKind.GOLDEN:
        raise ValueError("Legacy-bootstrap provenance is valid only for a legacy baseline candidate and its single Golden bundle.")
    parent = bundle.parent if bundle.parent_id else None
    if parent is None or parent.kind != BundleKind.LEGACY_BASELINE or parent.provenance != BundleProvenance.LEGACY_BOOTSTRAP:
        raise ValueError("A legacy-bootstrap Golden bundle derives only from a legacy baseline candidate.")
    if bundle.payload_digest != parent.payload_digest:
        raise ValueError("The initial Golden freezes the SAME baseline payload as its candidate.")


class ConfigurationBundle(models.Model):
    """One immutable, content-addressed configuration artifact (UAT, Probation or Golden).

    ``bundle_id`` (``BND-UAT-000001``...) is the stable operator-visible identity; it is NOT part of any digest.  The
    ``payload_digest`` covers the semantic configuration + its frozen source provenance (identical for a UAT bundle and the
    Probation bundle sealed from it); the ``bundle_digest`` additionally covers kind, schema version and lineage digests and is
    the tamper / provenance identity.  ``created_at`` / ``created_by`` / ``bundle_id`` / ``builder_version`` are immutable
    creation metadata and deliberately outside both digests.
    """

    bundle_id = models.CharField(max_length=24, unique=True, editable=False)
    kind = models.CharField(max_length=20, choices=BundleKind.choices, editable=False)
    provenance = models.CharField(
        max_length=20, choices=BundleProvenance.choices, default=BundleProvenance.EXECUTION_LINEAGE, editable=False,
        help_text="Where the configuration came from.  LEGACY_BOOTSTRAP is the one-time adoption of the pre-automation network (no Change / plan / execution exists).",
    )
    sequence = models.PositiveIntegerField(editable=False, help_text="Per-kind counter behind the bundle id.")
    schema_version = models.PositiveSmallIntegerField(editable=False)
    builder_version = models.CharField(max_length=32, editable=False)
    payload_digest = models.CharField(max_length=64, editable=False)
    bundle_digest = models.CharField(max_length=64, editable=False, db_index=True)
    manifest = models.JSONField(editable=False, help_text="Canonical manifest: kind, lineage and the frozen payload.  Digests are stored beside it, never inside it.")

    parent = models.ForeignKey("self", null=True, blank=True, on_delete=models.PROTECT, related_name="children", editable=False)
    source_uat = models.ForeignKey("self", null=True, blank=True, on_delete=models.PROTECT, related_name="descendants", editable=False)
    # NULL only for LEGACY_BOOTSTRAP provenance (database check ``bundle_provenance_sources``): the pre-automation network has no Change, plan or
    # execution, and none is fabricated to satisfy a foreign key.
    change = models.ForeignKey(Change, null=True, blank=True, on_delete=models.PROTECT, related_name="bundles", editable=False)
    plan = models.ForeignKey(ChangePlan, null=True, blank=True, on_delete=models.PROTECT, related_name="bundles", editable=False)
    validation_run = models.ForeignKey(ChangeValidationRun, null=True, blank=True, on_delete=models.PROTECT, related_name="bundles", editable=False)
    execution_run = models.ForeignKey(ChangeExecutionRun, null=True, blank=True, on_delete=models.PROTECT, related_name="bundles", editable=False)
    postcheck_run = models.ForeignKey(
        OperationalCheckRun, null=True, blank=True, on_delete=models.PROTECT, related_name="bundles", editable=False
    )

    created_by = models.CharField(max_length=150, blank=True, default="", editable=False)
    created_at = models.DateTimeField(auto_now_add=True)

    objects = _ImmutableManager()

    class Meta:
        ordering = ["-created_at", "-id"]
        indexes = [models.Index(fields=["kind", "-created_at"]), models.Index(fields=["change", "-created_at"])]
        constraints = [
            models.UniqueConstraint(fields=["kind", "sequence"], name="unique_bundle_sequence_per_kind"),
            # Idempotency enforced by the database, however many requests race: one UAT bundle per execution run, one Probation
            # bundle per UAT bundle, one Golden bundle per Probation bundle.
            models.UniqueConstraint(fields=["execution_run"], condition=Q(kind="UAT"), name="unique_uat_bundle_per_execution"),
            models.UniqueConstraint(fields=["execution_run"], condition=Q(kind="DEPLOYED"), name="unique_deployed_bundle_per_execution"),
            models.UniqueConstraint(fields=["parent"], condition=Q(kind="PROBATION"), name="unique_probation_bundle_per_uat"),
            models.UniqueConstraint(fields=["parent"], condition=Q(kind="GOLDEN"), name="unique_golden_bundle_per_probation"),
            models.CheckConstraint(
                check=(
                    Q(provenance="EXECUTION_LINEAGE")
                    & (Q(kind__in=("UAT", "DEPLOYED"), parent__isnull=True, source_uat__isnull=True)
                       | Q(kind__in=("PROBATION", "GOLDEN"), parent__isnull=False, source_uat__isnull=False))
                ) | (
                    Q(provenance="LEGACY_BOOTSTRAP", source_uat__isnull=True)
                    & (Q(kind="LEGACY_BASELINE", parent__isnull=True) | Q(kind="GOLDEN", parent__isnull=False))
                ),
                name="bundle_kind_parent_shape",
            ),
            # A missing Change / plan / execution is valid ONLY for the one-time legacy-bootstrap provenance -- never for a normal bundle.
            models.CheckConstraint(
                check=(
                    Q(provenance="EXECUTION_LINEAGE", change__isnull=False, plan__isnull=False, validation_run__isnull=False, execution_run__isnull=False)
                    | Q(provenance="LEGACY_BOOTSTRAP", change__isnull=True, plan__isnull=True, validation_run__isnull=True, execution_run__isnull=True,
                        postcheck_run__isnull=True)
                ),
                name="bundle_provenance_sources",
            ),
            # The ONE-TIME lockout, in the database: at most one Golden bundle can ever carry legacy-bootstrap provenance, restart or no restart.
            models.UniqueConstraint(fields=["provenance"], condition=Q(kind="GOLDEN", provenance="LEGACY_BOOTSTRAP"), name="unique_legacy_bootstrap_golden"),
        ]

    def __str__(self):
        return f"{self.bundle_id} ({self.get_kind_display()})"

    def get_absolute_url(self):
        return reverse("core:bundle_detail", args=[self.bundle_id])

    def save(self, *args, **kwargs):
        _forbid_row_mutation(self)
        _validate_bundle_lineage(self)
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("ConfigurationBundle records are historical artifacts and cannot be deleted.")

    # -- read-only views of the frozen manifest (never a second copy of state) -----------------------------------------------
    @property
    def payload(self) -> dict:
        return (self.manifest or {}).get("payload") or {}

    @property
    def lineage(self) -> dict:
        return (self.manifest or {}).get("lineage") or {}

    @property
    def verification(self) -> dict:
        return self.payload.get("verification") or {}

    @property
    def verification_state(self) -> str:
        return self.verification.get("state", "")

    @property
    def item_count(self) -> int:
        return len(self.payload.get("items") or [])


class ConfigurationBundleItem(models.Model):
    """One ordered Configlet of a bundle: a normalized projection of ``manifest.payload.items[i]``.

    The full canonical record is kept in ``record``; the columns exist so the database can PIN what the item was built from (the plan
    Configlet, the exact raw revision and verification run, the execution result) and so a bundle can be queried.  The integrity
    verifier proves ``record`` equals the manifest entry and every column agrees with it.  ``sequence`` is the exact effective order
    the run applied -- it is persisted, never re-derived from priority.
    """

    bundle = models.ForeignKey(ConfigurationBundle, on_delete=models.PROTECT, related_name="items", editable=False)
    sequence = models.PositiveIntegerField(editable=False)
    cfg_id = models.CharField(max_length=16, editable=False)
    device = models.CharField(max_length=64, editable=False)
    platform = models.CharField(max_length=32, blank=True, default="", editable=False)
    origin = models.CharField(max_length=12, choices=ConfigletOrigin.choices, editable=False)
    operation = models.CharField(max_length=20, editable=False)
    priority = models.PositiveSmallIntegerField(editable=False)
    payload = models.TextField(editable=False)
    payload_hash = models.CharField(max_length=64, editable=False)
    item_digest = models.CharField(max_length=64, editable=False)
    record = models.JSONField(editable=False)
    configlet = models.ForeignKey(Configlet, on_delete=models.PROTECT, related_name="bundle_items", editable=False)
    raw_revision = models.ForeignKey(
        RawConfigletRevision, null=True, blank=True, on_delete=models.PROTECT, related_name="bundle_items", editable=False
    )
    raw_verification = models.ForeignKey(
        RawConfigletVerificationRun, null=True, blank=True, on_delete=models.PROTECT, related_name="bundle_items", editable=False
    )
    execution_result = models.ForeignKey(
        ConfigletExecutionResult, null=True, blank=True, on_delete=models.PROTECT, related_name="bundle_items", editable=False
    )

    objects = _ImmutableManager()

    class Meta:
        ordering = ["bundle", "sequence"]
        constraints = [
            models.UniqueConstraint(fields=["bundle", "sequence"], name="unique_bundle_item_sequence"),
            models.UniqueConstraint(fields=["bundle", "cfg_id"], name="unique_bundle_item_cfg_id"),
        ]

    def __str__(self):
        return f"{self.bundle.bundle_id} #{self.sequence} {self.cfg_id}"

    def save(self, *args, **kwargs):
        _forbid_row_mutation(self)
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("ConfigurationBundleItem records are historical artifacts and cannot be deleted.")


# =============================================================================
# Phase 20 -- probation soak evidence and the operator's Golden decision.
#
# A soak is the OBSERVATION of one exact, immutable Probation bundle over real elapsed time.  It is evidence, not configuration: nothing
# here holds a device lock, a transaction or a session open for the window (the collector opens and closes short read-only units of work
# on a schedule).  All three models are append-oriented:
#
#   ProbationSoakRun     one observation window.  Created RUNNING, finalised EXACTLY ONCE (COMPLETED / INVALIDATED / CANCELLED) and immutable
#                        afterwards; the start, the required end and the policy it started under are pinned and never edited.
#   ProbationSoakSample  one bounded, sanitized evidence record per sample interval ("bucket").  Never updated, never deleted: a later result
#                        never rewrites what an earlier sample observed.  Raw telemetry stays in InfluxDB; only auditable facts live here.
#   GoldenDecision       the operator's explicit APPROVE / REJECT of one technically passed soak.  Immutable: a REJECT is never edited into an
#                        APPROVE; reconsidering requires a NEW soak.
#
# State (lifecycle) and result (technical evaluation) are different questions and are different fields.  GOLDEN is a bundle kind / decision
# outcome, never a soak state or result.
# =============================================================================


class SoakState(models.TextChoices):
    RUNNING = "RUNNING", "Running"
    COMPLETED = "COMPLETED", "Completed"
    INVALIDATED = "INVALIDATED", "Invalidated"
    CANCELLED = "CANCELLED", "Cancelled"


class SoakResult(models.TextChoices):
    """The technical evaluation of a COMPLETED soak.  Empty while RUNNING and for an INVALIDATED / CANCELLED soak."""

    PASS = "PASS", "Pass"
    FAIL = "FAIL", "Fail"
    INCOMPLETE = "INCOMPLETE", "Incomplete"


class SoakSampleResult(models.TextChoices):
    PASS = "PASS", "Pass"
    PASS_WITH_WARNINGS = "PASS_WITH_WARNINGS", "Pass with warnings"
    INCOMPLETE = "INCOMPLETE", "Incomplete (required evidence unavailable or stale)"
    FAIL = "FAIL", "Fail"
    INVALIDATED = "INVALIDATED", "Invalidated (integrity or interference)"


class GoldenDecisionKind(models.TextChoices):
    APPROVE = "APPROVE", "Approve"
    REJECT = "REJECT", "Reject"


class ProbationSoakRun(models.Model):
    """One observation window over one immutable Probation bundle.  ``soak_id`` is derived from the primary key (``SOAK-000001``)."""

    bundle = models.ForeignKey(ConfigurationBundle, on_delete=models.PROTECT, related_name="soak_runs", editable=False)
    bundle_digest = models.CharField(max_length=64, editable=False, help_text="The Probation bundle digest this window observes, pinned at start.")
    state = models.CharField(max_length=12, choices=SoakState.choices, default=SoakState.RUNNING)
    result = models.CharField(max_length=12, choices=SoakResult.choices, blank=True, default="")
    terminal_reason = models.CharField(max_length=48, blank=True, default="", help_text="Stable code of why the run ended (empty while RUNNING).")
    policy_version = models.CharField(max_length=16, editable=False)
    policy = models.JSONField(editable=False, help_text="The exact duration / cadence / gap / coverage policy this run started under (never re-read from settings).")
    started_at = models.DateTimeField(editable=False)
    required_end_at = models.DateTimeField(editable=False, help_text="started_at + the pinned duration, computed once by the server.")
    finished_at = models.DateTimeField(null=True, blank=True)
    started_by = models.CharField(max_length=150, blank=True, default="", editable=False)
    # V2 Phase 5C: the immutable START-TIME baseline -- what exactly entered probation: per-device configuration digests read at start,
    # the pre / post change digests where the lineage has them, and references to the validation / postcheck / health / topology evidence.
    baseline = models.JSONField(default=dict, blank=True, editable=False, help_text="Digests and references only; never configuration text.")
    baseline_digest = models.CharField(max_length=64, blank=True, default="", editable=False, help_text="SHA-256 of the canonical baseline.")
    ended_by = models.CharField(max_length=150, blank=True, default="", help_text="Set for a cancellation; the collector is 'probation-soak-collector'.")
    evaluation = models.JSONField(default=dict, blank=True, help_text="The final structured evaluation (coverage, findings, evidence summary).")
    evidence_digest = models.CharField(max_length=64, blank=True, default="", help_text="SHA-256 of the canonical final evidence summary.")
    created_at = models.DateTimeField(auto_now_add=True)

    objects = _ImmutableManager()

    class Meta:
        ordering = ["-started_at", "-id"]
        indexes = [models.Index(fields=["bundle", "-started_at"]), models.Index(fields=["state"])]
        constraints = [
            # DB-enforced: a Probation bundle can have at most ONE active soak, however many requests race.
            models.UniqueConstraint(fields=["bundle"], condition=Q(state="RUNNING"), name="unique_active_soak_per_bundle"),
            # a result exists exactly for a COMPLETED soak
            models.CheckConstraint(
                check=(Q(state="COMPLETED", result__in=("PASS", "FAIL", "INCOMPLETE")) | (~Q(state="COMPLETED") & Q(result=""))),
                name="soak_result_only_when_completed",
            ),
        ]

    _IMMUTABLE = ("bundle_id", "bundle_digest", "policy_version", "policy", "started_at", "required_end_at", "started_by", "created_at",
                  "baseline", "baseline_digest")

    def __str__(self):
        return f"{self.soak_id} ({self.state}{'/' + self.result if self.result else ''})"

    @property
    def soak_id(self) -> str:
        return f"SOAK-{self.pk:06d}" if self.pk else "SOAK-NEW"

    def get_absolute_url(self):
        return reverse("core:soak_detail", args=[self.soak_id])

    @property
    def duration_seconds(self) -> int:
        return int((self.policy or {}).get("duration_seconds", 0))

    @property
    def is_running(self) -> bool:
        return self.state == SoakState.RUNNING

    @property
    def is_technical_pass(self) -> bool:
        return self.state == SoakState.COMPLETED and self.result == SoakResult.PASS

    def save(self, *args, **kwargs):
        if self.state not in SoakState.values:
            raise ValueError(f"Invalid soak state {self.state!r}.")
        if self.result and self.result not in SoakResult.values:
            raise ValueError(f"Invalid soak result {self.result!r}.")
        if self.state == SoakState.RUNNING and (self.result or self.finished_at or self.terminal_reason):
            raise ValueError("A running soak has no result, reason or finish time yet.")
        if self.state == SoakState.COMPLETED and not self.result:
            raise ValueError("A completed soak needs a technical result.")
        if self.state != SoakState.COMPLETED and self.result:
            raise ValueError("Only a COMPLETED soak carries a result.")
        if self.state != SoakState.RUNNING and self.finished_at is None:
            raise ValueError("A finished soak needs its finish time.")
        if self.pk:
            persisted = type(self).objects.filter(pk=self.pk).values("state", *self._IMMUTABLE).first()
            if persisted is not None:
                if persisted["state"] != SoakState.RUNNING:
                    raise ValueError("A finished ProbationSoakRun is immutable: a retry is a NEW run.")
                for name in self._IMMUTABLE:
                    if persisted[name] != getattr(self, name):
                        raise ValueError(f"ProbationSoakRun.{name.removesuffix('_id')} is immutable after creation.")
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("ProbationSoakRun records are historical evidence and cannot be deleted.")


class ProbationSoakSample(models.Model):
    """One evidence record.  ``bucket`` is the sample interval index since the run started: UNIQUE per run, so two collectors (or a repeated
    tick) can never record the same interval twice.  Append-only."""

    run = models.ForeignKey(ProbationSoakRun, on_delete=models.PROTECT, related_name="samples", editable=False)
    bucket = models.PositiveIntegerField(editable=False)
    sampled_at = models.DateTimeField(editable=False, help_text="Server clock when the evidence was read (never supplied by a browser).")
    result = models.CharField(max_length=20, choices=SoakSampleResult.choices, editable=False)
    integrity_ok = models.BooleanField(editable=False)
    interference = models.BooleanField(editable=False, help_text="A later overlapping execution touched the candidate's devices.")
    expected_state_result = models.CharField(max_length=24, blank=True, default="", editable=False, help_text="The Phase-15 postcheck verdict of the pinned descriptors.")
    device_health = models.CharField(max_length=12, blank=True, default="", editable=False)
    telemetry_freshness = models.CharField(max_length=12, blank=True, default="", editable=False, help_text="The WORST freshness among the scoped devices.")
    monitoring_state = models.CharField(max_length=16, blank=True, default="", editable=False)
    terminal_failure = models.BooleanField(default=False, editable=False, help_text="A demonstrated intended-state failure: ends the soak.")
    config_drift = models.BooleanField(default=False, editable=False, help_text="A device's configuration digest differs from the soak's baseline: invalidates the soak.")
    resource_critical = models.JSONField(default=list, blank=True, editable=False, help_text="'DEVICE:CODE' keys at a critical resource level (streak rule).")
    counts = models.JSONField(default=dict, blank=True, editable=False)
    findings = models.JSONField(default=list, blank=True, editable=False, help_text="Bounded, sanitized non-PASS findings.")
    evidence = models.JSONField(default=dict, blank=True, editable=False, help_text="Bounded per-device facts and the evidence timestamps -- not raw telemetry.")
    collector_version = models.CharField(max_length=16, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)

    objects = _ImmutableManager()

    class Meta:
        ordering = ["run", "bucket"]
        constraints = [models.UniqueConstraint(fields=["run", "bucket"], name="unique_soak_sample_per_bucket")]

    def __str__(self):
        return f"{self.run.soak_id} #{self.bucket}: {self.result}"

    def save(self, *args, **kwargs):
        if self.result not in SoakSampleResult.values:
            raise ValueError(f"Invalid soak sample result {self.result!r}.")
        _forbid_row_mutation(self)
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("ProbationSoakSample records are historical evidence and cannot be deleted.")


class GoldenDecision(models.Model):
    """The operator's explicit decision about one technically passed soak.  Immutable; at most one per soak run."""

    run = models.OneToOneField(ProbationSoakRun, on_delete=models.PROTECT, related_name="decision", editable=False)
    bundle = models.ForeignKey(ConfigurationBundle, on_delete=models.PROTECT, related_name="golden_decisions", editable=False)
    decision = models.CharField(max_length=8, choices=GoldenDecisionKind.choices, editable=False)
    decided_by = models.CharField(max_length=150, editable=False)
    decided_at = models.DateTimeField(editable=False)
    reason = models.CharField(max_length=500, blank=True, default="", editable=False)
    probation_bundle_digest = models.CharField(max_length=64, editable=False)
    evidence_digest = models.CharField(max_length=64, editable=False)
    policy_version = models.CharField(max_length=16, editable=False)
    golden_bundle = models.OneToOneField(
        ConfigurationBundle, null=True, blank=True, on_delete=models.PROTECT, related_name="golden_decision", editable=False
    )
    created_at = models.DateTimeField(auto_now_add=True)

    objects = _ImmutableManager()

    class Meta:
        ordering = ["-decided_at", "-id"]
        constraints = [
            models.CheckConstraint(
                check=(Q(decision="APPROVE", golden_bundle__isnull=False) | Q(decision="REJECT", golden_bundle__isnull=True)),
                name="golden_decision_bundle_only_when_approved",
            ),
        ]

    def __str__(self):
        return f"{self.run.soak_id}: {self.decision} by {self.decided_by}"

    def save(self, *args, **kwargs):
        if self.decision not in GoldenDecisionKind.values:
            raise ValueError(f"Invalid decision {self.decision!r}.")
        _forbid_row_mutation(self)
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("GoldenDecision records are durable history and cannot be deleted.")


# =============================================================================
# One-time LEGACY BASELINE BOOTSTRAP (between Phase 20 and Phase 21).
#
# The lab was configured traditionally BEFORE the automation framework existed, so its running configuration cannot honestly be pushed through
# Change -> plan -> Partial UAT -> Probation -> 7-day soak.  These models record the ONE explicit exception the operator approved: observe what is
# actually running (a LEGACY_BASELINE candidate bundle), watch it for a short real window, and -- only on the operator's explicit approval -- seal
# it as the initial Golden bundle with LEGACY_BOOTSTRAP provenance.  They are deliberately SEPARATE from ProbationSoakRun: a bootstrap run must
# never look like a Probation soak, and no fake Change / plan / UAT / soak is created to satisfy the normal lineage.
#
# Same guarantees as the Phase-20 models: append-oriented, guarded manager (no queryset update / delete), finalised exactly once, never deleted.
# =============================================================================


class LegacyBootstrapRun(models.Model):
    """One observation window over one LEGACY_BASELINE candidate.  ``run_id`` is derived from the primary key (``BOOT-000001``)."""

    candidate = models.ForeignKey(ConfigurationBundle, on_delete=models.PROTECT, related_name="bootstrap_runs", editable=False)
    candidate_digest = models.CharField(max_length=64, editable=False, help_text="The candidate bundle digest this window observes, pinned at start.")
    state = models.CharField(max_length=12, choices=SoakState.choices, default=SoakState.RUNNING)
    result = models.CharField(max_length=12, choices=SoakResult.choices, blank=True, default="")
    terminal_reason = models.CharField(max_length=48, blank=True, default="")
    policy_version = models.CharField(max_length=40, editable=False)
    policy = models.JSONField(editable=False, help_text="The exact bootstrap policy this run started under (never re-read from settings).")
    started_at = models.DateTimeField(editable=False)
    required_end_at = models.DateTimeField(editable=False, help_text="started_at + the pinned duration, computed once by the server.")
    finished_at = models.DateTimeField(null=True, blank=True)
    started_by = models.CharField(max_length=150, blank=True, default="", editable=False)
    ended_by = models.CharField(max_length=150, blank=True, default="")
    evaluation = models.JSONField(default=dict, blank=True)
    evidence_digest = models.CharField(max_length=64, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)

    objects = _ImmutableManager()

    class Meta:
        ordering = ["-started_at", "-id"]
        indexes = [models.Index(fields=["candidate", "-started_at"]), models.Index(fields=["state"])]
        constraints = [
            # DB-enforced: only ONE bootstrap observation may be running at any time, however many requests race.
            models.UniqueConstraint(fields=["state"], condition=Q(state="RUNNING"), name="unique_active_legacy_bootstrap_run"),
            models.CheckConstraint(
                check=(Q(state="COMPLETED", result__in=("PASS", "FAIL", "INCOMPLETE")) | (~Q(state="COMPLETED") & Q(result=""))),
                name="legacy_bootstrap_result_only_when_completed",
            ),
        ]

    _IMMUTABLE = ("candidate_id", "candidate_digest", "policy_version", "policy", "started_at", "required_end_at", "started_by", "created_at")

    def __str__(self):
        return f"{self.run_id} ({self.state}{'/' + self.result if self.result else ''})"

    @property
    def run_id(self) -> str:
        return f"BOOT-{self.pk:06d}" if self.pk else "BOOT-NEW"

    def get_absolute_url(self):
        return reverse("core:bootstrap_run_detail", args=[self.run_id])

    @property
    def duration_seconds(self) -> int:
        return int((self.policy or {}).get("duration_seconds", 0))

    @property
    def is_running(self) -> bool:
        return self.state == SoakState.RUNNING

    @property
    def is_technical_pass(self) -> bool:
        return self.state == SoakState.COMPLETED and self.result == SoakResult.PASS

    def save(self, *args, **kwargs):
        if self.state not in SoakState.values:
            raise ValueError(f"Invalid bootstrap state {self.state!r}.")
        if self.result and self.result not in SoakResult.values:
            raise ValueError(f"Invalid bootstrap result {self.result!r}.")
        if self.state == SoakState.RUNNING and (self.result or self.finished_at or self.terminal_reason):
            raise ValueError("A running bootstrap observation has no result, reason or finish time yet.")
        if self.state == SoakState.COMPLETED and not self.result:
            raise ValueError("A completed bootstrap observation needs a technical result.")
        if self.state != SoakState.COMPLETED and self.result:
            raise ValueError("Only a COMPLETED bootstrap observation carries a result.")
        if self.state != SoakState.RUNNING and self.finished_at is None:
            raise ValueError("A finished bootstrap observation needs its finish time.")
        if self.pk:
            persisted = type(self).objects.filter(pk=self.pk).values("state", *self._IMMUTABLE).first()
            if persisted is not None:
                if persisted["state"] != SoakState.RUNNING:
                    raise ValueError("A finished LegacyBootstrapRun is immutable: a retry is a NEW run from a freshly captured baseline.")
                for name in self._IMMUTABLE:
                    if persisted[name] != getattr(self, name):
                        raise ValueError(f"LegacyBootstrapRun.{name.removesuffix('_id')} is immutable after creation.")
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("LegacyBootstrapRun records are historical evidence and cannot be deleted.")


class LegacyBootstrapSample(models.Model):
    """One evidence record of a bootstrap observation.  ``bucket`` is unique per run.  Append-only; raw telemetry stays in InfluxDB."""

    run = models.ForeignKey(LegacyBootstrapRun, on_delete=models.PROTECT, related_name="samples", editable=False)
    bucket = models.PositiveIntegerField(editable=False)
    sampled_at = models.DateTimeField(editable=False)
    result = models.CharField(max_length=20, choices=SoakSampleResult.choices, editable=False)
    integrity_ok = models.BooleanField(editable=False, help_text="The candidate bundle still verifies against its recorded digests.")
    interference = models.BooleanField(editable=False, help_text="A network configuration execution touched an included device after the baseline was captured.")
    config_drift = models.BooleanField(editable=False, help_text="A device's current sanitized configuration differs from the captured baseline.")
    expected_state_result = models.CharField(max_length=24, blank=True, default="", editable=False)
    device_health = models.CharField(max_length=12, blank=True, default="", editable=False)
    telemetry_freshness = models.CharField(max_length=12, blank=True, default="", editable=False)
    monitoring_state = models.CharField(max_length=16, blank=True, default="", editable=False)
    terminal_failure = models.BooleanField(default=False, editable=False)
    resource_critical = models.JSONField(default=list, blank=True, editable=False)
    counts = models.JSONField(default=dict, blank=True, editable=False)
    findings = models.JSONField(default=list, blank=True, editable=False)
    evidence = models.JSONField(default=dict, blank=True, editable=False)
    collector_version = models.CharField(max_length=16, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)

    objects = _ImmutableManager()

    class Meta:
        ordering = ["run", "bucket"]
        constraints = [models.UniqueConstraint(fields=["run", "bucket"], name="unique_legacy_bootstrap_sample_per_bucket")]

    def __str__(self):
        return f"{self.run.run_id} #{self.bucket}: {self.result}"

    def save(self, *args, **kwargs):
        if self.result not in SoakSampleResult.values:
            raise ValueError(f"Invalid bootstrap sample result {self.result!r}.")
        _forbid_row_mutation(self)
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("LegacyBootstrapSample records are historical evidence and cannot be deleted.")


class LegacyBootstrapDecision(models.Model):
    """The operator's explicit APPROVE of one technically passed bootstrap observation.  Immutable; at most one per run, and it always has its
    Golden bundle (there is no REJECT row: not approving simply leaves the run without a decision, and a new bootstrap is a new baseline)."""

    run = models.OneToOneField(LegacyBootstrapRun, on_delete=models.PROTECT, related_name="decision", editable=False)
    candidate = models.ForeignKey(ConfigurationBundle, on_delete=models.PROTECT, related_name="bootstrap_decisions", editable=False)
    decided_by = models.CharField(max_length=150, editable=False)
    decided_at = models.DateTimeField(editable=False)
    reason = models.CharField(max_length=500, blank=True, default="", editable=False)
    candidate_digest = models.CharField(max_length=64, editable=False)
    evidence_digest = models.CharField(max_length=64, editable=False)
    policy_version = models.CharField(max_length=40, editable=False)
    golden_bundle = models.OneToOneField(ConfigurationBundle, on_delete=models.PROTECT, related_name="bootstrap_decision", editable=False)
    created_at = models.DateTimeField(auto_now_add=True)

    objects = _ImmutableManager()

    class Meta:
        ordering = ["-decided_at", "-id"]

    def __str__(self):
        return f"{self.run.run_id}: APPROVE by {self.decided_by}"

    def save(self, *args, **kwargs):
        _forbid_row_mutation(self)
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("LegacyBootstrapDecision records are durable history and cannot be deleted.")


# =============================================================================
# Phase 23 -- managed-device credential metadata and password-rotation audit.
#
# Secret values NEVER enter these tables. ``secret_ref`` points to the
# protected runtime provider; version fields are opaque, non-secret IDs.
# =============================================================================


class CredentialStatus(models.TextChoices):
    NEVER = "NEVER", "Never attempted"
    IN_PROGRESS = "IN_PROGRESS", "Rotation in progress"
    SUCCESS = "SUCCESS", "Last rotation succeeded"
    FAILED = "FAILED", "Last rotation failed safely"
    UNCERTAIN = "UNCERTAIN", "Device/secret state requires recovery"
    BLOCKED = "BLOCKED", "Blocked by policy or platform safety"


class RotationTrigger(models.TextChoices):
    SCHEDULED = "SCHEDULED", "Scheduled"
    MANUAL = "MANUAL", "Manual"
    RECONCILE = "RECONCILE", "Operator reconciliation"


class RotationRunStatus(models.TextChoices):
    STARTED = "STARTED", "Started"
    SUCCESS = "SUCCESS", "Success"
    FAILED = "FAILED", "Failed safely"
    UNCERTAIN = "UNCERTAIN", "Uncertain / recovery required"
    BLOCKED = "BLOCKED", "Blocked"


class CredentialRotationPhase(models.TextChoices):
    """Durable, non-secret progress marker for crash-safe reconciliation."""

    CLAIMED = "CLAIMED", "Database claim recorded"
    PROVIDER_STAGED = "PROVIDER_STAGED", "Pending provider version staged"
    DEVICE_TIMER_ARMED = "DEVICE_TIMER_ARMED", "EOS commit timer armed"
    NEW_VERIFIED = "NEW_VERIFIED", "New credential accepted"
    OLD_REJECTED = "OLD_REJECTED", "Previous credential rejected"
    OPERATIONAL_VALIDATED = "OPERATIONAL_VALIDATED", "Operational checks passed"
    DEVICE_CONFIRMED = "DEVICE_CONFIRMED", "EOS transaction confirmed"
    STARTUP_PERSISTED = "STARTUP_PERSISTED", "Startup equals running"
    PROVIDER_PROMOTED = "PROVIDER_PROMOTED", "Pending provider version promoted"
    COMPLETE = "COMPLETE", "Database finalization complete"


ACCOUNT_NAME_VALIDATOR = RegexValidator(
    regex=r"^[A-Za-z_][A-Za-z0-9_.-]{0,63}$",
    message="Account names use letters, digits, underscore, dot, and hyphen only.",
)
SECRET_REF_VALIDATOR = RegexValidator(
    regex=r"^runtime://device-credentials/[a-z0-9][a-z0-9_.-]{2,63}$",
    message="Use a protected runtime://device-credentials/<key> reference.",
)
SSH_FINGERPRINT_VALIDATOR = RegexValidator(
    regex=r"^SHA256:[A-Za-z0-9+/]{43}$",
    message="Use an OpenSSH SHA256:<base64> public-key fingerprint.",
)
MFA_SECRET_REF_VALIDATOR = RegexValidator(
    regex=r"^runtime://human-mfa/radius/[a-z0-9][a-z0-9_.-]{0,63}$",
    message="Use a protected runtime://human-mfa/radius/<device> reference.",
)


class AccountKind(models.TextChoices):
    SERVICE = "SERVICE", "NMAS automation service account (non-interactive)"
    HUMAN = "HUMAN", "Named human operator"
    BREAK_GLASS = "BREAK_GLASS", "Emergency / break-glass"
    LEGACY_SHARED = "LEGACY_SHARED", "Legacy fleet-shared account (pre-Phase-23)"


class DeviceAuthMethod(models.TextChoices):
    PASSWORD = "PASSWORD", "Password only (single factor)"
    PUBLICKEY = "PUBLICKEY", "SSH public key only (machine identity)"
    PUBLICKEY_AND_PASSWORD = "PUBLICKEY_AND_PASSWORD", "Legacy SSH key + password (automation-capable; not current human 2FA)"
    PASSWORD_AND_TOTP = "PASSWORD_AND_TOTP", "Human password + Microsoft Authenticator TOTP"


class DeviceCredential(models.Model):
    """Safe account/policy metadata for one managed network device."""

    device_name = models.CharField(max_length=64, validators=[DEVICE_NAME_VALIDATOR])
    platform = models.CharField(max_length=32)
    username = models.CharField(max_length=64, validators=[ACCOUNT_NAME_VALIDATOR])
    account_kind = models.CharField(max_length=16, choices=AccountKind.choices, default=AccountKind.SERVICE)
    auth_method = models.CharField(max_length=32, choices=DeviceAuthMethod.choices, default=DeviceAuthMethod.PASSWORD)
    # Blank only for HUMAN accounts: an operator's password is known to the
    # operator and is never held by NMAS.
    secret_ref = models.CharField(max_length=128, blank=True, default="", validators=[SECRET_REF_VALIDATOR])
    # SSH possession factor.  Only the provider REFERENCE to a service
    # account's private key and the PUBLIC fingerprint are stored here.
    ssh_key_ref = models.CharField(max_length=128, blank=True, default="", validators=[SECRET_REF_VALIDATOR])
    ssh_public_key_fingerprint = models.CharField(max_length=64, blank=True, default="", validators=[SSH_FINGERPRINT_VALIDATOR])
    ssh_public_key = models.TextField(blank=True, default="", help_text="OpenSSH PUBLIC key line (not secret).")
    account_role = models.CharField(max_length=64, blank=True, default="")
    privilege_level = models.PositiveSmallIntegerField(null=True, blank=True)

    rotation_enabled = models.BooleanField(default=False)
    rotation_interval_days = models.PositiveIntegerField(default=90, validators=[MinValueValidator(1)])
    last_rotated_at = models.DateTimeField(null=True, blank=True)
    next_due_at = models.DateTimeField(null=True, blank=True)
    last_attempt_at = models.DateTimeField(null=True, blank=True)
    last_status = models.CharField(max_length=16, choices=CredentialStatus.choices, default=CredentialStatus.NEVER)
    last_result_code = models.CharField(max_length=64, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["device_name", "username"]
        constraints = [
            models.UniqueConstraint(fields=["device_name", "username"], name="unique_device_management_account"),
            models.CheckConstraint(
                check=Q(privilege_level__isnull=True) | Q(privilege_level__lte=15),
                name="credential_privilege_level_lte_15",
            ),
        ]
        indexes = [models.Index(fields=["rotation_enabled", "next_due_at"]), models.Index(fields=["secret_ref"])]

    def __str__(self):
        return f"{self.device_name}/{self.username}"

    def save(self, *args, **kwargs):
        if self.account_kind != AccountKind.HUMAN and self.auth_method != DeviceAuthMethod.PUBLICKEY and not self.secret_ref:
            raise ValueError("Non-human accounts require a protected password reference.")
        if "PRIVATE KEY" in (self.ssh_public_key or ""):
            raise ValueError("Only an SSH PUBLIC key may be stored in metadata.")
        if self.auth_method not in DeviceAuthMethod.values:
            raise ValueError("Unsupported device authentication method.")
        if self.auth_method in (DeviceAuthMethod.PUBLICKEY, DeviceAuthMethod.PUBLICKEY_AND_PASSWORD) and not self.ssh_public_key_fingerprint:
            raise ValueError("Public-key accounts require an enrolled public-key fingerprint.")
        if self.auth_method == DeviceAuthMethod.PUBLICKEY and not self.ssh_public_key:
            raise ValueError("Public-key-only accounts require an enrolled SSH public key.")
        if self.account_kind == AccountKind.SERVICE and self.auth_method in (
            DeviceAuthMethod.PUBLICKEY, DeviceAuthMethod.PUBLICKEY_AND_PASSWORD,
        ) and not self.ssh_key_ref:
            raise ValueError("A key-enabled service account needs its private key held by the protected provider (ssh_key_ref).")
        if self.auth_method == DeviceAuthMethod.PUBLICKEY and self.account_kind != AccountKind.SERVICE:
            raise ValueError("Public-key-only authentication is reserved for machine service identities.")
        if self.auth_method == DeviceAuthMethod.PASSWORD_AND_TOTP and self.account_kind != AccountKind.HUMAN:
            raise ValueError("Password + TOTP is reserved for named human operators.")
        if self.account_kind == AccountKind.HUMAN and self.ssh_key_ref:
            raise ValueError("Human operators keep their own private keys; NMAS must never hold them.")
        if self.ssh_key_ref and self.ssh_key_ref == self.secret_ref:
            raise ValueError("The password and SSH key must be distinct provider references.")
        if self.rotation_enabled and self.account_kind != AccountKind.SERVICE:
            raise ValueError("Automatic rotation applies to NMAS service accounts only.")
        if self.rotation_enabled and self.next_due_at is None:
            raise ValueError("An enabled rotation policy requires next_due_at.")
        super().save(*args, **kwargs)


class CredentialRotationRun(models.Model):
    """One non-secret audit record; created before any device mutation."""

    run_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    credential = models.ForeignKey(DeviceCredential, on_delete=models.PROTECT, related_name="rotation_runs", editable=False)
    trigger_reason = models.CharField(max_length=16, choices=RotationTrigger.choices, editable=False)
    started_at = models.DateTimeField(editable=False)
    completed_at = models.DateTimeField(null=True, blank=True)
    prior_secret_version = models.CharField(max_length=64, blank=True, default="", editable=False)
    new_secret_version = models.CharField(max_length=64, blank=True, default="", editable=False)
    phase = models.CharField(
        max_length=32, choices=CredentialRotationPhase.choices,
        default=CredentialRotationPhase.CLAIMED,
    )
    session_name = models.CharField(max_length=64, blank=True, default="")
    checkpoint_file = models.CharField(max_length=128, blank=True, default="")
    checkpoint_sha256 = models.CharField(max_length=64, blank=True, default="")
    checkpoint_md5 = models.CharField(max_length=32, blank=True, default="")
    pre_change_digest = models.CharField(max_length=64, blank=True, default="")
    post_change_digest = models.CharField(max_length=64, blank=True, default="")
    transaction_metadata = models.JSONField(default=dict, blank=True)
    device_change_result = models.CharField(max_length=32, blank=True, default="NOT_ATTEMPTED")
    login_verification_result = models.CharField(max_length=32, blank=True, default="NOT_ATTEMPTED")
    old_login_verification_result = models.CharField(max_length=32, blank=True, default="NOT_ATTEMPTED")
    operational_validation_result = models.CharField(max_length=32, blank=True, default="NOT_ATTEMPTED")
    transaction_confirmation_result = models.CharField(max_length=32, blank=True, default="NOT_ATTEMPTED")
    persistence_result = models.CharField(max_length=32, blank=True, default="NOT_ATTEMPTED")
    startup_verification_result = models.CharField(max_length=32, blank=True, default="NOT_ATTEMPTED")
    provider_promotion_result = models.CharField(max_length=32, blank=True, default="NOT_ATTEMPTED")
    final_status = models.CharField(max_length=16, choices=RotationRunStatus.choices, default=RotationRunStatus.STARTED)
    error_category = models.CharField(max_length=64, blank=True, default="")
    completed_detail = models.CharField(max_length=200, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-started_at", "-id"]
        indexes = [models.Index(fields=["credential", "-started_at"]), models.Index(fields=["final_status"])]

    def __str__(self):
        return f"{self.run_id} {self.credential} {self.final_status}"

    def delete(self, *args, **kwargs):
        raise ValueError("Credential rotation audit records are durable history.")


class MfaMechanism(models.TextChoices):
    RADIUS_TOTP = "RADIUS_TOTP", "Local RADIUS password + Microsoft Authenticator TOTP"
    LEGACY_EOS_SSH_KEY_PASSWORD = "LEGACY_EOS_SSH_KEY_PASSWORD", "Superseded EOS SSH public-key + password design"
    LEGACY_OPENSSH_KEY_PASSWORD = "LEGACY_OPENSSH_KEY_PASSWORD", "Superseded OpenSSH public-key + password design"
    UNSUPPORTED = "UNSUPPORTED", "No verified two-factor mechanism"


class MfaEnforcementState(models.TextChoices):
    PLANNED = "PLANNED", "Designed; non-live candidate only"
    CONFIGURED = "CONFIGURED", "Central AAA configured; device enforcement not active"
    ENFORCED = "ENFORCED", "Applied to the device; awaiting verification"
    LIVE_VERIFIED = "LIVE_VERIFIED", "Applied and independently verified (single-factor refused)"
    BLOCKED = "BLOCKED", "Blocked by a documented prerequisite"


class CentralAaaState(models.TextChoices):
    PLANNED = "PLANNED", "Planned; no central AAA service is live"
    CONFIGURED = "CONFIGURED", "Central AAA service configured"
    VERIFIED = "VERIFIED", "Central AAA service independently verified"


class DeviceLoginMfaPolicy(models.Model):
    """Per-device two-factor login policy (metadata only -- no key, seed or password)."""

    device_name = models.CharField(max_length=64, unique=True, validators=[DEVICE_NAME_VALIDATOR])
    platform = models.CharField(max_length=32)
    required = models.BooleanField(default=True)
    mechanism = models.CharField(max_length=40, choices=MfaMechanism.choices)
    enforcement_state = models.CharField(max_length=16, choices=MfaEnforcementState.choices, default=MfaEnforcementState.PLANNED)
    central_aaa_state = models.CharField(max_length=16, choices=CentralAaaState.choices, default=CentralAaaState.PLANNED)
    radius_server = models.GenericIPAddressField(default="192.168.200.100")
    radius_secret_ref = models.CharField(max_length=128, blank=True, default="", validators=[MFA_SECRET_REF_VALIDATOR])
    radius_source_interface = models.CharField(max_length=32, blank=True, default="")
    automation_exempt = models.BooleanField(default=True)
    blocked_reason = models.CharField(max_length=64, blank=True, default="")
    emergency_path = models.CharField(max_length=128, blank=True, default="")
    candidate_digest = models.CharField(max_length=64, blank=True, default="")
    last_verified_at = models.DateTimeField(null=True, blank=True)
    last_verification_result = models.CharField(max_length=64, blank=True, default="")
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["device_name"]

    def __str__(self):
        return f"{self.device_name} {self.mechanism} {self.enforcement_state}"

    def save(self, *args, **kwargs):
        if self.enforcement_state == MfaEnforcementState.LIVE_VERIFIED and self.last_verified_at is None:
            raise ValueError("LIVE_VERIFIED requires recorded verification evidence.")
        if self.mechanism == MfaMechanism.UNSUPPORTED and self.enforcement_state not in (
            MfaEnforcementState.BLOCKED, MfaEnforcementState.PLANNED,
        ):
            raise ValueError("An unsupported platform cannot be marked as enforcing two-factor login.")
        if self.mechanism == MfaMechanism.RADIUS_TOTP and not self.radius_secret_ref:
            raise ValueError("RADIUS TOTP policy requires a protected shared-secret reference.")
        if (
            self.mechanism == MfaMechanism.RADIUS_TOTP
            and self.enforcement_state == MfaEnforcementState.LIVE_VERIFIED
            and self.central_aaa_state != CentralAaaState.VERIFIED
        ):
            raise ValueError("LIVE_VERIFIED requires independently verified central AAA.")
        super().save(*args, **kwargs)



# =============================================================================
# Automation workflows -- Configuration Changes / Remove Configuration.
#
# A RunningConfigSnapshot is the SANITIZED running configuration an operator
# looked at (the same sanitizer and digest formula as the Phase-20.5 import
# provenance).  Line numbers on both workbench pages refer to its text, and a
# Change built from it carries its digest so execution refuses a stale basis.
# =============================================================================


class ChangeWorkflow(models.TextChoices):
    CONFIGURATION_CHANGES = "CONFIGURATION_CHANGES", "Configuration Changes (incremental patch)"
    REMOVE_CONFIGURATION = "REMOVE_CONFIGURATION", "Remove Configuration"


class RunningConfigSnapshot(models.Model):
    """Immutable, sanitized running-configuration capture (no secret values -- see bundles.legacy_sanitize)."""

    snapshot_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    device_name = models.CharField(max_length=64, validators=[DEVICE_NAME_VALIDATOR])
    platform = models.CharField(max_length=32, choices=Platform.choices)
    digest = models.CharField(max_length=64)
    text = models.TextField()
    line_count = models.PositiveIntegerField()
    redacted_lines = models.PositiveIntegerField(default=0)
    source = models.CharField(max_length=160)
    captured_at = models.DateTimeField()
    created_by = models.CharField(max_length=150, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-captured_at", "-id"]
        indexes = [models.Index(fields=["device_name", "-captured_at"])]

    def __str__(self):
        return f"{self.device_name} {self.digest[:12]} @ {self.captured_at:%Y-%m-%d %H:%M:%S}"

    def save(self, *args, **kwargs):
        if self.pk is not None:
            raise ValueError("RunningConfigSnapshot rows are immutable evidence.")
        super().save(*args, **kwargs)


class RemovalMode(models.TextChoices):
    LINE_RANGE = "LINE_RANGE", "Line range"
    SEMANTIC = "SEMANTIC", "Smart / semantic"


class RemovalAnalysisStatus(models.TextChoices):
    READY = "READY", "Ready"
    BLOCKED = "BLOCKED", "Blocked"


class ConfigRemoval(models.Model):
    """One device's intentional removal selection inside a Change (Remove Configuration workflow).

    ``selection`` is what the operator chose against ``snapshot`` (a line range or semantic object ids, plus explicitly
    accepted proposals).  ``analysis`` is the deterministic server-side result (items, blockers, proposals) -- the
    validator re-derives it from the snapshot text, so this copy is presentation, never authority.
    """

    change = models.ForeignKey(Change, on_delete=models.CASCADE, related_name="config_removals")
    device_name = models.CharField(max_length=64, validators=[DEVICE_NAME_VALIDATOR])
    platform = models.CharField(max_length=32, choices=Platform.choices)
    snapshot = models.ForeignKey(RunningConfigSnapshot, on_delete=models.PROTECT, related_name="removals")
    mode = models.CharField(max_length=16, choices=RemovalMode.choices)
    selection = models.JSONField(default=dict)
    analysis = models.JSONField(default=dict)
    status = models.CharField(max_length=8, choices=RemovalAnalysisStatus.choices)
    content_hash = models.CharField(max_length=64)
    created_by = models.CharField(max_length=150, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["device_name"]
        constraints = [models.UniqueConstraint(fields=["change", "device_name"], name="unique_change_device_removal")]

    def __str__(self):
        return f"{self.change.change_id} / {self.device_name} removal ({self.status})"



# --- V2 Phase 1: NMAS website identity / authorization / MFA ------------------------------------------------------------


class NmasAccess(models.Model):
    """Holder for the NMAS website's action permissions.  Its table is intentionally always empty: it exists only so
    the permissions have a content type and so generic model iteration (table counts, admin checks) keeps working.

    Django creates these permissions for the ``core`` app; the groups seeded by migration 0018 bundle them into roles.
    Authorization is ALWAYS evaluated through ``user.has_perm("core.<codename>")`` (core.services.identity.policy) --
    never by username.
    """

    class Meta:
        default_permissions = ()
        permissions = [
            ("nmas_view", "View NMAS operator pages"),
            ("nmas_edit", "Create / edit Changes, intents, Raw Configlets and workbench drafts"),
            ("nmas_validate", "Run validation, verification, prechecks and live health checks"),
            ("nmas_plan", "Build Change plans"),
            ("nmas_approve", "Approve / promote: bundles, soaks, bootstrap and Golden decisions"),
            ("nmas_execute", "Execute (push) a planned Change to devices"),
            ("nmas_security_admin", "Security administration: credential status, website MFA reset, audit review"),
        ]


class AppMfaDevice(models.Model):
    """The NMAS WEBSITE's TOTP authenticator for one Django user (Microsoft Authenticator compatible, RFC 6238).

    Completely separate from network-device MFA: it never references privacyIDEA, RADIUS, DeviceLoginMfaPolicy or any
    device credential, and its seed is generated, stored and verified only by core.services.identity.mfa.  The seed is
    stored ENCRYPTED (Fernet, key from NMAS_APP_MFA_KEY or derived from SECRET_KEY) and is never logged, audited or
    rendered after enrollment.  ``last_used_step`` rejects replay of an already-accepted code.
    """

    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="nmas_app_mfa")
    encrypted_seed = models.TextField()
    confirmed_at = models.DateTimeField(null=True, blank=True)
    last_used_step = models.BigIntegerField(null=True, blank=True)
    last_verified_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "website MFA authenticator"
        verbose_name_plural = "website MFA authenticators"

    def __str__(self):
        state = "confirmed" if self.confirmed_at else "pending"
        return f"Website MFA for {self.user} ({state})"


# --- V2 Phase 1: capability evidence --------------------------------------------------------------------------------------


class CapabilityEvidence(models.Model):
    """One piece of EMPIRICAL capability evidence for (platform, feature, axis).

    Registry evidence (what the code implements) is derived live by core.services.capabilities from the existing
    registries; this table holds what was OBSERVED -- an automated test result, a live read / write / post-write
    validation or a compensation run -- so the matrix is driven by evidence rather than labels.  Rows are append-only;
    the newest row per (platform, feature, axis) is authoritative.  Version 2 Phase 4 fills this table.
    """

    platform = models.CharField(max_length=32)
    feature = models.CharField(max_length=64)
    axis = models.CharField(max_length=32)
    status = models.CharField(max_length=16)
    source = models.CharField(max_length=64)
    evidence_type = models.CharField(max_length=16, default="STATIC")
    detail = models.CharField(max_length=500, blank=True, default="")
    evidence_ref = models.CharField(max_length=255, blank=True, default="")
    repository_head = models.CharField(max_length=40, blank=True, default="")
    runtime_version = models.CharField(max_length=128, blank=True, default="")
    recorded_by = models.CharField(max_length=150, blank=True, default="")
    recorded_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-recorded_at", "-id"]
        indexes = [models.Index(fields=["platform", "feature", "axis", "-recorded_at"])]

    def __str__(self):
        return f"{self.platform}/{self.feature}/{self.axis}: {self.status}"

    def save(self, *args, **kwargs):
        if self.pk:
            raise ValueError("CapabilityEvidence rows are append-only.")
        super().save(*args, **kwargs)


class CapabilityAssessment(models.Model):
    """Append-only, per-cell probe ledger; a red matrix cell is not an assessment.

    Completeness is derived by the assessment service from individual probe
    outcomes, not an operator-editable flag. Evidence remains in CapabilityEvidence.
    """

    platform = models.CharField(max_length=32)
    feature = models.CharField(max_length=64)
    probes = models.JSONField(default=dict)
    evidence_ids = models.JSONField(default=list)
    repository_head = models.CharField(max_length=40)
    runtime_version = models.CharField(max_length=128, blank=True, default="")
    recorded_by = models.CharField(max_length=150, blank=True, default="")
    recorded_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-recorded_at", "-id"]
        indexes = [models.Index(fields=["platform", "feature", "-recorded_at"], name="cap_assessment_cell_time")]

    def save(self, *args, **kwargs):
        if self.pk:
            raise ValueError("CapabilityAssessment rows are append-only.")
        super().save(*args, **kwargs)


# --- V2 Phase 3: intent-based configuration templates ---------------------------------------------------------------------
#
# A template is REUSABLE SEMANTIC INTENT, never a CLI blob: ``intent`` is the vendor-neutral, name-keyed structure the
# config importers already produce (core.services.config_import.schema), with ``{{ parameter }}`` placeholders for
# device-specific values.  It is rendered to platform configuration only by cloning it into an ordinary Change /
# DeviceIntentRevision (core.services.config_templates.clone) and running the existing Jinja2 renderer and lifecycle.


class TemplateFamily(models.TextChoices):
    ACCESS_SWITCH = "ACCESS_SWITCH", "Access layer switch"
    GATEWAY_ROUTER = "GATEWAY_ROUTER", "Default gateway router"
    MULTILAYER_SWITCH = "MULTILAYER_SWITCH", "Multilayer switch"
    SPINE = "SPINE", "Spine device"
    INTERNET_UPLINK = "INTERNET_UPLINK", "Internet uplink device"
    END_DEVICE = "END_DEVICE", "End device (outside NMAS management)"
    CUSTOM = "CUSTOM", "Custom"


class TemplateOrigin(models.TextChoices):
    BASELINE = "BASELINE", "Baseline (derived from the lab's source devices)"
    EXTRACTED = "EXTRACTED", "Extracted from a running configuration"
    DERIVED = "DERIVED", "Derived from a Device Builder working intent"
    IMPORTED = "IMPORTED", "Imported package"


class TemplateVersionStatus(models.TextChoices):
    DRAFT = "DRAFT", "Draft"
    PUBLISHED = "PUBLISHED", "Published (immutable)"


class ConfigurationTemplate(models.Model):
    """Identity of one reusable configuration template.  The reusable content lives on its immutable versions."""

    template_id = models.CharField(max_length=40, unique=True, editable=False)
    name = models.CharField(max_length=120)
    family = models.CharField(max_length=32, choices=TemplateFamily.choices, default=TemplateFamily.CUSTOM)
    origin = models.CharField(max_length=16, choices=TemplateOrigin.choices, default=TemplateOrigin.EXTRACTED)
    description = models.TextField(blank=True, default="")
    created_by = models.CharField(max_length=150, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    retired_at = models.DateTimeField(null=True, blank=True)
    retired_by = models.CharField(max_length=150, blank=True, default="")
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["family", "name"]
        indexes = [models.Index(fields=["family"]), models.Index(fields=["origin"])]

    def __str__(self):
        return f"{self.template_id}: {self.name}"

    @property
    def is_baseline(self) -> bool:
        return self.origin == TemplateOrigin.BASELINE

    def latest_published(self) -> "ConfigurationTemplateVersion | None":
        return self.versions.filter(status=TemplateVersionStatus.PUBLISHED).order_by("-version").first()

    def save(self, *args, **kwargs):
        _forbid_field_mutation(self, "template_id")
        _forbid_field_mutation(self, "family")
        _forbid_field_mutation(self, "origin")
        super().save(*args, **kwargs)


class _TemplateVersionQuerySet(models.QuerySet):
    """Bulk mutation would bypass the published-version immutability check in ``save`` / ``delete``, so it is refused."""

    def update(self, **kwargs):
        raise ValueError("ConfigurationTemplateVersion rows cannot be bulk-updated; published versions are immutable.")

    def bulk_update(self, objs, fields, batch_size=None):
        raise ValueError("ConfigurationTemplateVersion rows cannot be bulk-updated; published versions are immutable.")

    def delete(self):
        if self.filter(status=TemplateVersionStatus.PUBLISHED).exists():
            raise ValueError("Published template versions are immutable and cannot be deleted.")
        return super().delete()


class ConfigurationTemplateVersion(models.Model):
    """One numbered revision of a template.  A DRAFT may only be published or discarded; a PUBLISHED row never changes.

    ``digest`` is the SHA-256 of the canonical content (core.services.config_templates.package.content_digest) and is
    what an exported package carries, so an import can prove the content was not altered in transit.
    """

    template = models.ForeignKey(ConfigurationTemplate, on_delete=models.PROTECT, related_name="versions")
    version = models.PositiveIntegerField(validators=[MinValueValidator(1)])
    schema_version = models.PositiveIntegerField(default=1, validators=[MinValueValidator(1)])
    status = models.CharField(max_length=16, choices=TemplateVersionStatus.choices, default=TemplateVersionStatus.DRAFT)
    intent = models.JSONField(default=dict)
    parameters = models.JSONField(default=dict, blank=True)
    parameter_sets = models.JSONField(default=dict, blank=True)
    platforms = models.JSONField(default=list, blank=True)
    required_features = models.JSONField(default=list, blank=True)
    constraints = models.JSONField(default=dict, blank=True)
    provenance = models.JSONField(default=dict, blank=True)
    exclusions = models.JSONField(default=list, blank=True)
    notes = models.TextField(blank=True, default="")
    digest = models.CharField(max_length=64)
    source_version = models.ForeignKey("self", null=True, blank=True, on_delete=models.PROTECT, related_name="derived_versions")
    created_by = models.CharField(max_length=150, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    published_by = models.CharField(max_length=150, blank=True, default="")
    published_at = models.DateTimeField(null=True, blank=True)

    objects = _TemplateVersionQuerySet.as_manager()

    class Meta:
        ordering = ["template", "-version"]
        constraints = [models.UniqueConstraint(fields=["template", "version"], name="unique_template_version")]

    def __str__(self):
        return f"{self.template.template_id} v{self.version} ({self.status})"

    @property
    def ref(self) -> str:
        return f"{self.template.template_id}@v{self.version}"

    @property
    def is_published(self) -> bool:
        return self.status == TemplateVersionStatus.PUBLISHED

    _PUBLISH_FIELDS = frozenset({"status", "published_by", "published_at"})

    def save(self, *args, **kwargs):
        if self.pk:
            stored = type(self).objects.filter(pk=self.pk).values().first()
            if stored is not None:
                if stored["status"] == TemplateVersionStatus.PUBLISHED:
                    raise ValueError("A published template version is immutable; create a new version instead.")
                changed = {name for name, value in stored.items() if value != getattr(self, name)}
                if changed - self._PUBLISH_FIELDS:
                    raise ValueError("A draft template version can only be published or discarded, not edited in place.")
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        if self.pk and type(self).objects.filter(pk=self.pk, status=TemplateVersionStatus.PUBLISHED).exists():
            raise ValueError("Published template versions are immutable and cannot be deleted.")
        return super().delete(*args, **kwargs)


# =============================================================================
# V2 Phase 5A -- NEW DEVICE PROVISIONING (core.services.provisioning).
#
# A provisioning run is the operator's request to bring ONE device that NMAS does not manage yet under management.  It is an orchestration and
# evidence record OVER the existing Change lifecycle, never a second one: the candidate, its validation, plan, precheck, execution and postcheck
# are the ordinary Phase-13..17 artifacts and are REFERENCED here (PROTECT), never copied.
#
#   ProvisioningRun     the request and its current stage.  Identity (name, platform, role, requester) is fixed when the row is created; the row is
#                       immutable once it reaches a terminal status.
#   ProvisioningEvent   one append-only record per attempted stage transition (advanced, blocked or failed) with the bounded evidence that
#                       justified it.  The stage history is these rows, never an edited field.
#   ProvisionedDevice   the registry that admits a provisioned device into ``health.inventory.managed_devices()``.  ``inventory.yml`` stays the
#                       tracked IaC inventory of the production lab and always wins on a name; this registry only ADDS devices a run admitted.
#
# No credential is ever stored: a bootstrap target is a container / address reference, and secret-shaped text is refused by the service.
# =============================================================================


class ProvisioningStatus(models.TextChoices):
    DRAFT = "DRAFT", "Draft"
    IDENTIFIED = "IDENTIFIED", "Identity / platform defined"
    BOOTSTRAP_CLASSIFIED = "BOOTSTRAP_CLASSIFIED", "Bootstrap connectivity classified"
    CAPABILITY_RESOLVED = "CAPABILITY_RESOLVED", "Capabilities resolved"
    IPAM_PLANNED = "IPAM_PLANNED", "NetBox / IPAM planned and reserved"
    CANDIDATE_READY = "CANDIDATE_READY", "Candidate generated"
    VALIDATED = "VALIDATED", "Validated"
    PLANNED = "PLANNED", "Provisioning plan built"
    PRECHECKED = "PRECHECKED", "Prechecked"
    APPROVED = "APPROVED", "Approved"
    PROVISIONING = "PROVISIONING", "Provisioning"
    POSTCHECKED = "POSTCHECKED", "Provisioned and postchecked"
    NSOT_SYNCED = "NSOT_SYNCED", "NSOT synchronized"
    PROBATION = "PROBATION", "In Golden probation"
    FAILED = "FAILED", "Failed"
    ROLLED_BACK = "ROLLED_BACK", "Failed and rolled back"
    CANCELLED = "CANCELLED", "Cancelled"
    DECOMMISSIONED = "DECOMMISSIONED", "Provisioned, then retired from NMAS"


PROVISIONING_TERMINAL = frozenset({ProvisioningStatus.PROBATION, ProvisioningStatus.FAILED, ProvisioningStatus.ROLLED_BACK,
                                   ProvisioningStatus.CANCELLED, ProvisioningStatus.DECOMMISSIONED})


class BootstrapState(models.TextChoices):
    """Three different situations, never one workflow."""

    UNKNOWN = "UNKNOWN", "Not classified yet"
    UNREACHABLE = "UNREACHABLE", "Device not reachable yet (plan / reserve only)"
    REACHABLE_BOOTSTRAP = "REACHABLE_BOOTSTRAP", "Reachable bootstrap device"
    ALREADY_CONFIGURED = "ALREADY_CONFIGURED", "Already configured device (onboarding, not provisioning)"


class BootstrapTransport(models.TextChoices):
    DOCKER_EXEC = "DOCKER_EXEC", "Container exec (credential-free)"
    SSH = "SSH", "SSH"
    GNMI = "GNMI", "gNMI"
    ZTP_MANAGEMENT = "ZTP_MANAGEMENT", "ZTP-onboarded management session (pinned host key, retired bootstrap credential)"


class ProvisioningEventOutcome(models.TextChoices):
    ADVANCED = "ADVANCED", "Advanced"
    BLOCKED = "BLOCKED", "Blocked"
    FAILED = "FAILED", "Failed"
    RECONCILED = "RECONCILED", "Reconciled"


class ProvisioningRun(models.Model):
    """One request to provision one new device.  ``prov_id`` is derived from the primary key (``PROV-000001``)."""

    status = models.CharField(max_length=24, choices=ProvisioningStatus.choices, default=ProvisioningStatus.DRAFT)
    device_name = models.CharField(max_length=64, validators=[DEVICE_NAME_VALIDATOR], editable=False)
    platform = models.CharField(max_length=32, choices=Platform.choices, editable=False)
    role = models.CharField(max_length=32, editable=False, help_text="Intended device role, e.g. router / switch.")
    site = models.CharField(max_length=100, blank=True, default="")
    image_reference = models.CharField(max_length=255, blank=True, default="", help_text="Image name/tag only -- never a binary.")
    requested_by = models.CharField(max_length=150, editable=False)
    disposable = models.BooleanField(default=False, editable=False, help_text="A disposable proof device: must live outside the production lab.")

    bootstrap_state = models.CharField(max_length=24, choices=BootstrapState.choices, default=BootstrapState.UNKNOWN)
    bootstrap_transport = models.CharField(max_length=16, choices=BootstrapTransport.choices, blank=True, default="")
    bootstrap_target = models.JSONField(default=dict, blank=True, help_text="Container / lab / address reference.  Never a credential.")
    management = models.JSONField(default=dict, blank=True, help_text="Planned management addressing: interface, ipv4, ipv6, vlan.")

    template_version = models.ForeignKey("ConfigurationTemplateVersion", null=True, blank=True, on_delete=models.PROTECT, related_name="provisioning_runs")
    capability_resolution = models.JSONField(default=dict, blank=True, help_text="Per-feature Phase-4 terminal status and the blocking reason.")
    planned_interfaces = models.JSONField(default=list, blank=True)
    planned_addresses = models.JSONField(default=list, blank=True)
    netbox = models.JSONField(default=dict, blank=True, help_text="NetBox references this run created or planned (ids and names only).")

    # References into the ordinary Change lifecycle -- never copies of its immutable evidence.
    change = models.OneToOneField(Change, null=True, blank=True, on_delete=models.PROTECT, related_name="provisioning_run")
    validation_run = models.ForeignKey(ChangeValidationRun, null=True, blank=True, on_delete=models.PROTECT, related_name="+")
    network_config_validation_run = models.ForeignKey(NetworkConfigValidationRun, null=True, blank=True, on_delete=models.PROTECT, related_name="+")
    plan = models.ForeignKey(ChangePlan, null=True, blank=True, on_delete=models.PROTECT, related_name="+")
    precheck_run = models.ForeignKey(OperationalCheckRun, null=True, blank=True, on_delete=models.PROTECT, related_name="+")
    execution_run = models.ForeignKey(ChangeExecutionRun, null=True, blank=True, on_delete=models.PROTECT, related_name="+")
    postcheck_run = models.ForeignKey(OperationalCheckRun, null=True, blank=True, on_delete=models.PROTECT, related_name="+")
    probation_bundle = models.ForeignKey(ConfigurationBundle, null=True, blank=True, on_delete=models.PROTECT, related_name="+")
    soak_run = models.ForeignKey(ProbationSoakRun, null=True, blank=True, on_delete=models.PROTECT, related_name="+")

    candidate_config = models.TextField(blank=True, default="", help_text="The plan's rendered candidate, in plan order (secret-free by construction).")
    candidate_hash = models.CharField(max_length=64, blank=True, default="")
    approval = models.JSONField(default=dict, blank=True, help_text="Who approved which exact candidate hash and plan, and when.")
    pre_config_digest = models.CharField(max_length=64, blank=True, default="")
    post_config_digest = models.CharField(max_length=64, blank=True, default="")
    result = models.JSONField(default=dict, blank=True, help_text="Resulting runtime identity, NetBox identity and execution outcome.")
    failure = models.JSONField(default=dict, blank=True, help_text="Stage, stable code and rollback / reconciliation evidence of a failure.")
    repository_head = models.CharField(max_length=40, blank=True, default="")

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at", "-id"]
        indexes = [models.Index(fields=["status"]), models.Index(fields=["device_name"])]
        constraints = [
            # DB-enforced: at most ONE live request per device name, however many requests race.
            models.UniqueConstraint(
                fields=["device_name"], condition=~Q(status__in=("FAILED", "ROLLED_BACK", "CANCELLED", "PROBATION", "DECOMMISSIONED")),
                name="unique_active_provisioning_per_device",
            ),
        ]

    _IMMUTABLE = ("device_name", "platform", "role", "requested_by", "disposable")

    def __str__(self):
        return f"{self.prov_id}: {self.device_name} ({self.status})"

    @property
    def prov_id(self) -> str:
        return f"PROV-{self.pk:06d}" if self.pk else "PROV-NEW"

    @property
    def is_terminal(self) -> bool:
        return self.status in PROVISIONING_TERMINAL

    def get_absolute_url(self):
        return reverse("core:provisioning_detail", args=[self.prov_id])

    def save(self, *args, **kwargs):
        if self.status not in ProvisioningStatus.values:
            raise ValueError(f"Invalid provisioning status {self.status!r}.")
        if self.pk:
            persisted = type(self).objects.filter(pk=self.pk).values("status", *self._IMMUTABLE).first()
            if persisted is not None:
                if persisted["status"] in PROVISIONING_TERMINAL:
                    raise ValueError("A finished ProvisioningRun is immutable: a retry is a NEW request.")
                for name in self._IMMUTABLE:
                    if persisted[name] != getattr(self, name):
                        raise ValueError(f"ProvisioningRun.{name} is immutable after creation.")
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("ProvisioningRun records are historical evidence and cannot be deleted.")


class ProvisioningEvent(models.Model):
    """One attempted stage transition.  Append-only."""

    run = models.ForeignKey(ProvisioningRun, on_delete=models.PROTECT, related_name="events", editable=False)
    sequence = models.PositiveIntegerField(editable=False)
    stage = models.CharField(max_length=32, editable=False)
    outcome = models.CharField(max_length=12, choices=ProvisioningEventOutcome.choices, editable=False)
    from_status = models.CharField(max_length=24, editable=False)
    to_status = models.CharField(max_length=24, editable=False)
    actor = models.CharField(max_length=150, blank=True, default="", editable=False)
    blockers = models.JSONField(default=list, blank=True, editable=False)
    evidence = models.JSONField(default=dict, blank=True, editable=False, help_text="Bounded, secret-free facts that justified the transition.")
    created_at = models.DateTimeField(auto_now_add=True)

    objects = _ImmutableManager()

    class Meta:
        ordering = ["run", "sequence"]
        constraints = [models.UniqueConstraint(fields=["run", "sequence"], name="unique_provisioning_event_sequence")]

    def __str__(self):
        return f"{self.run.prov_id} #{self.sequence} {self.stage}: {self.outcome}"

    def save(self, *args, **kwargs):
        if self.outcome not in ProvisioningEventOutcome.values:
            raise ValueError(f"Invalid provisioning event outcome {self.outcome!r}.")
        _forbid_row_mutation(self)
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("ProvisioningEvent records are historical evidence and cannot be deleted.")


class ProvisionedDeviceState(models.TextChoices):
    ADMITTED = "ADMITTED", "Admitted for its provisioning Change only"
    ACTIVE = "ACTIVE", "Managed"
    RETIRED = "RETIRED", "Retired"


class ProvisionedDevice(models.Model):
    """The registry entry that makes a provisioned device resolvable by the execution, health and soak engines.

    ADMITTED: reachable by the engines, but only its own provisioning Change may execute against it.  ACTIVE: an ordinary managed device.
    RETIRED: no longer resolvable; the row stays as history (a re-provision is a new row).
    """

    name = models.CharField(max_length=64, validators=[DEVICE_NAME_VALIDATOR], editable=False)
    platform = models.CharField(max_length=32, choices=Platform.choices, editable=False)
    state = models.CharField(max_length=12, choices=ProvisionedDeviceState.choices, default=ProvisionedDeviceState.ADMITTED)
    run = models.OneToOneField(ProvisioningRun, on_delete=models.PROTECT, related_name="registry_entry", editable=False)
    transport = models.CharField(max_length=16, choices=BootstrapTransport.choices, editable=False)
    container = models.CharField(max_length=128, blank=True, default="", editable=False)
    lab = models.CharField(max_length=64, blank=True, default="", editable=False)
    address = models.CharField(max_length=64, blank=True, default="")
    address_v6 = models.CharField(max_length=64, blank=True, default="")
    disposable = models.BooleanField(default=False, editable=False)
    netbox_device_id = models.PositiveIntegerField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    retired_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["name", "-id"]
        constraints = [
            models.UniqueConstraint(fields=["name"], condition=~Q(state="RETIRED"), name="unique_live_provisioned_device_name"),
        ]

    _IMMUTABLE = ("name", "platform", "run_id", "transport", "container", "lab", "disposable")

    def __str__(self):
        return f"{self.name} ({self.state})"

    def save(self, *args, **kwargs):
        if self.state not in ProvisionedDeviceState.values:
            raise ValueError(f"Invalid provisioned-device state {self.state!r}.")
        if self.pk:
            persisted = type(self).objects.filter(pk=self.pk).values("state", *self._IMMUTABLE).first()
            if persisted is not None:
                if persisted["state"] == ProvisionedDeviceState.RETIRED:
                    raise ValueError("A retired ProvisionedDevice is history: re-provisioning creates a new entry.")
                for name in self._IMMUTABLE:
                    if persisted[name] != getattr(self, name):
                        raise ValueError(f"ProvisionedDevice.{name.removesuffix('_id')} is immutable after creation.")
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("ProvisionedDevice records are history: retire the device instead of deleting it.")


# =============================================================================
# V2 Phase 5B -- TRAFFIC / TEST WORKBENCH (core.services.traffic).
#
# One row per controlled network test between two catalogued lab ENDPOINTS (H1-H4, WebServer).  Endpoints stay unmanaged: a run never
# creates a managed device, a registry entry or a NetBox object.  A run is evidence: it stores what was asked, the bounded parameters the
# server actually used, a STRUCTURED description of the operation (tool + validated arguments -- never a shell string), the parsed metrics
# and a bounded copy of the tool output.  It is written once when requested, moved to RUNNING, finalised exactly once, and immutable and
# undeletable afterwards.  No credential is involved anywhere: tests run host diagnostic binaries inside the endpoint's network namespace.
# =============================================================================


class TrafficTestFamily(models.TextChoices):
    ICMP = "ICMP", "ICMP ping"
    TRACEROUTE = "TRACEROUTE", "Traceroute / path"
    TCP_CONNECT = "TCP_CONNECT", "TCP connectivity"
    UDP_PROBE = "UDP_PROBE", "UDP probe"
    IPERF3 = "IPERF3", "iperf3 throughput"


class TrafficAddressFamily(models.TextChoices):
    IPV4 = "IPV4", "IPv4"
    IPV6 = "IPV6", "IPv6"


class TrafficRunStatus(models.TextChoices):
    CREATED = "CREATED", "Created"
    RUNNING = "RUNNING", "Running"
    PASSED = "PASSED", "Passed"
    FAILED = "FAILED", "Failed"
    TIMED_OUT = "TIMED_OUT", "Timed out"
    INTERRUPTED = "INTERRUPTED", "Interrupted (abandoned run reconciled)"


TRAFFIC_ACTIVE = frozenset({TrafficRunStatus.CREATED, TrafficRunStatus.RUNNING})


class TrafficRun(models.Model):
    """One controlled test run.  ``run_id`` (a UUID) is the stable public identifier."""

    run_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    operator = models.CharField(max_length=150, editable=False)
    source = models.CharField(max_length=64, editable=False, help_text="Catalogue endpoint name the test runs FROM.")
    destination = models.CharField(max_length=64, editable=False, help_text="Catalogue endpoint name the test runs TO.")
    address_family = models.CharField(max_length=4, choices=TrafficAddressFamily.choices, editable=False)
    family = models.CharField(max_length=16, choices=TrafficTestFamily.choices, editable=False)
    protocol = models.CharField(max_length=8, editable=False, help_text="ICMP / TCP / UDP.")
    source_address = models.CharField(max_length=64, blank=True, default="", editable=False, help_text="Discovered at run time, never typed.")
    destination_address = models.CharField(max_length=64, blank=True, default="", editable=False)
    requested = models.JSONField(default=dict, editable=False, help_text="The parameters as requested.")
    parameters = models.JSONField(default=dict, editable=False, help_text="The bounded, normalized parameters the server used.")
    operation = models.JSONField(default=dict, blank=True, help_text="Structured operation: tool, role and validated arguments.  Never a shell string.")
    status = models.CharField(max_length=12, choices=TrafficRunStatus.choices, default=TrafficRunStatus.CREATED)
    failure_reason = models.CharField(max_length=48, blank=True, default="", help_text="Stable code; empty for a PASSED run.")
    metrics = models.JSONField(default=dict, blank=True, help_text="Parsed result: throughput, loss, jitter, RTT, hops -- whatever the test measures.")
    raw_output = models.TextField(blank=True, default="", help_text="Bounded copy of the tool output (evidence).")
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    deadline_at = models.DateTimeField(null=True, blank=True, help_text="After this instant a still-active run is abandoned and may be reconciled.")
    change = models.ForeignKey(Change, null=True, blank=True, on_delete=models.PROTECT, related_name="traffic_runs", editable=False)
    provisioning_run = models.ForeignKey(ProvisioningRun, null=True, blank=True, on_delete=models.PROTECT, related_name="traffic_runs", editable=False)
    soak_run = models.ForeignKey(ProbationSoakRun, null=True, blank=True, on_delete=models.PROTECT, related_name="traffic_runs", editable=False)
    repository_head = models.CharField(max_length=40, blank=True, default="", editable=False)
    engine_version = models.CharField(max_length=16, blank=True, default="", editable=False)
    active_slot = models.PositiveSmallIntegerField(default=1, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at", "-id"]
        indexes = [models.Index(fields=["status"]), models.Index(fields=["source", "destination"])]
        constraints = [
            # DB-enforced concurrency bound: at most ONE test is active in the lab at a time, however many requests race.
            models.UniqueConstraint(fields=["active_slot"], condition=Q(status__in=("CREATED", "RUNNING")), name="one_active_traffic_run"),
        ]

    _IMMUTABLE = ("run_id", "operator", "source", "destination", "address_family", "family", "protocol", "requested", "parameters",
                  "change_id", "provisioning_run_id", "soak_run_id", "repository_head", "engine_version")

    def __str__(self):
        return f"{self.run_id} {self.family} {self.source}->{self.destination} ({self.status})"

    @property
    def is_active(self) -> bool:
        return self.status in TRAFFIC_ACTIVE

    def get_absolute_url(self):
        return reverse("core:traffic_run_detail", args=[self.run_id])

    def save(self, *args, **kwargs):
        if self.status not in TrafficRunStatus.values:
            raise ValueError(f"Invalid traffic run status {self.status!r}.")
        if self.pk:
            persisted = type(self).objects.filter(pk=self.pk).values("status", *self._IMMUTABLE).first()
            if persisted is not None:
                if persisted["status"] not in TRAFFIC_ACTIVE:
                    raise ValueError("A finished TrafficRun is immutable evidence: a retry is a NEW run.")
                for name in self._IMMUTABLE:
                    if persisted[name] != getattr(self, name):
                        raise ValueError(f"TrafficRun.{name.removesuffix('_id')} is immutable after creation.")
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("TrafficRun records are historical evidence and cannot be deleted.")


# =============================================================================
# State reconciliation: "what NMAS last expected of a device" != "the current state the operator accepts".
#
# NMAS history is true history: a Change that ran, ran.  When a device was later restored OUTSIDE NMAS, that history no
# longer describes the device, and nothing may be edited to pretend otherwise.  A StateReconciliation is the append-only
# statement that closes the gap: it names the execution runs whose resulting state is no longer the accepted baseline,
# pins the digest NMAS expected and the digest that was actually observed, and records who accepted the observed state
# and why.  It never changes a Change, an ExecutionRun, a Configlet or a device, and it holds digests only -- never
# configuration text.  This is not Maintenance Mode and carries no maintenance state.
# =============================================================================


class ReconciliationCause(models.TextChoices):
    OUTSIDE_NMAS_RESTORATION = "OUTSIDE_NMAS_RESTORATION", "Device restored to service outside NMAS"
    OUTSIDE_NMAS_CHANGE = "OUTSIDE_NMAS_CHANGE", "Device changed outside NMAS"


class StateReconciliation(models.Model):
    """One accepted difference between NMAS's previous expected state of a device and its observed current state."""

    record_id = models.CharField(max_length=16, unique=True, editable=False, help_text="REC-000001")
    device_name = models.CharField(max_length=64, editable=False)
    cause = models.CharField(max_length=32, choices=ReconciliationCause.choices, editable=False)
    actor = models.CharField(max_length=150, editable=False)
    reason = models.CharField(max_length=500, editable=False)
    acknowledgement = models.CharField(max_length=160, editable=False, help_text="The exact phrase the actor supplied to accept this baseline.")
    observed_at = models.DateTimeField(editable=False, help_text="When the device was read.")
    previous_expected_digest = models.CharField(max_length=64, editable=False)
    previous_expected_basis = models.JSONField(default=dict, editable=False, help_text="What the previous expectation was derived from.")
    accepted_digest = models.CharField(max_length=64, editable=False, help_text="Digest of the observed, sanitized running configuration.")
    section_digests = models.JSONField(default=dict, editable=False)
    startup_digest = models.CharField(max_length=64, blank=True, default="", editable=False)
    affected_sections = models.JSONField(default=list, editable=False)
    execution_run_ids = models.JSONField(default=list, editable=False, help_text="Runs whose resulting state is superseded as the baseline.")
    evidence = models.JSONField(default=dict, editable=False, help_text="Metadata about the observation; never configuration text.")
    record_digest = models.CharField(max_length=64, unique=True, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)

    objects = _ImmutableManager()

    class Meta:
        ordering = ["-id"]
        constraints = [
            models.UniqueConstraint(
                fields=["device_name", "previous_expected_digest", "accepted_digest"], name="state_reconciliation_once_per_transition",
            ),
        ]
        indexes = [models.Index(fields=["device_name", "-id"])]

    def __str__(self):
        return f"{self.record_id}: {self.device_name} accepted {self.accepted_digest[:12]}"

    def save(self, *args, **kwargs):
        for name in ("previous_expected_digest", "accepted_digest", "record_digest"):
            if not _HEX64.fullmatch(getattr(self, name) or ""):
                raise ValueError(f"{name} must be a SHA-256 digest.")
        if self.startup_digest and not _HEX64.fullmatch(self.startup_digest):
            raise ValueError("startup_digest must be a SHA-256 digest.")
        if self.cause not in ReconciliationCause.values:
            raise ValueError(f"Invalid cause {self.cause!r}.")
        _forbid_row_mutation(self)
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("StateReconciliation records are durable history and cannot be deleted.")


# ---------------------------------------------------------------------------------------------------- V2: Maintenance Mode
class MaintenanceRecord(models.Model):
    """One maintenance transaction of one device.  The lifecycle is ``core.services.maintenance_mode.lifecycle``; this row
    is its CURRENT stored form.  ``snapshot`` holds the readiness report, the plan, the findings and the history.  What
    happened is recorded separately, append-only and hash-chained, in ``MaintenanceEvidence``.

    ``plan_hash`` binds an approval to the exact plan the approver saw; ``queued_*`` is an explicit operator request for the
    worker (entry or restore) and ``claim_*`` is the worker's lease while it holds the record: a second worker, a second
    tick or a browser request can never act on a claimed record."""

    device_name = models.CharField(max_length=64, editable=False)
    state = models.CharField(max_length=32)
    requested_by = models.CharField(max_length=150, editable=False)
    reason = models.CharField(max_length=500, editable=False)
    requested_at = models.DateTimeField(editable=False)
    requested_duration_seconds = models.PositiveIntegerField(editable=False)
    approved_by = models.CharField(max_length=150, blank=True, default="")
    entered_at = models.DateTimeField(null=True, blank=True)
    deadline_at = models.DateTimeField(null=True, blank=True, help_text="The safety deadline: entry time plus the 7-day maintenance cycle.")
    restore_trigger = models.CharField(max_length=16, blank=True, default="")
    escalated = models.BooleanField(default=False)
    plan_hash = models.CharField(max_length=64, blank=True, default="", help_text="SHA-256 of the current immutable plan document.")
    plan_status = models.CharField(max_length=16, blank=True, default="", help_text="CURRENT, STALE or SUPERSEDED.")
    queued_action = models.CharField(max_length=16, blank=True, default="", help_text="ENTER or RESTORE, requested explicitly by an operator.")
    queued_by = models.CharField(max_length=150, blank=True, default="")
    queued_at = models.DateTimeField(null=True, blank=True)
    claim_token = models.CharField(max_length=32, blank=True, default="")
    claim_action = models.CharField(max_length=16, blank=True, default="")
    claimed_at = models.DateTimeField(null=True, blank=True)
    heartbeat_at = models.DateTimeField(null=True, blank=True)
    snapshot = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-id"]
        indexes = [models.Index(fields=["device_name", "-id"]), models.Index(fields=["state"])]
        default_permissions = ()             # access is the existing NMAS actions only (core.services.identity.policy); no model permission

    def __str__(self):
        return f"{self.record_id}: {self.device_name} {self.state}"

    @property
    def record_id(self) -> str:
        return f"MNT-{self.pk:06d}" if self.pk else ""


class MaintenanceEvidence(models.Model):
    """One immutable piece of evidence of a maintenance transaction: a transition, an observation, the plan, a refusal, a
    drain or restore run.  Append-only (row, queryset and manager), numbered per record and hash-chained: ``entry_digest``
    covers the payload digest and the previous entry's digest, so a removed or altered entry is detectable."""

    record = models.ForeignKey(MaintenanceRecord, on_delete=models.PROTECT, related_name="evidence_entries", editable=False)
    sequence = models.PositiveIntegerField(editable=False)
    kind = models.CharField(max_length=32, editable=False)
    at = models.DateTimeField(editable=False)
    actor = models.CharField(max_length=150, editable=False)
    state_from = models.CharField(max_length=32, blank=True, default="", editable=False)
    state_to = models.CharField(max_length=32, blank=True, default="", editable=False)
    summary = models.CharField(max_length=300, blank=True, default="", editable=False)
    payload = models.JSONField(default=dict, editable=False)
    payload_digest = models.CharField(max_length=64, editable=False)
    previous_digest = models.CharField(max_length=64, blank=True, default="", editable=False)
    entry_digest = models.CharField(max_length=64, unique=True, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)

    objects = _ImmutableManager()

    class Meta:
        ordering = ["record", "sequence"]
        constraints = [models.UniqueConstraint(fields=["record", "sequence"], name="maintenance_evidence_sequence_per_record")]
        default_permissions = ()

    def __str__(self):
        return f"{self.record.record_id} #{self.sequence} {self.kind}"

    def save(self, *args, **kwargs):
        for name in ("payload_digest", "entry_digest"):
            if not _HEX64.fullmatch(getattr(self, name) or ""):
                raise ValueError(f"{name} must be a SHA-256 digest.")
        if self.previous_digest and not _HEX64.fullmatch(self.previous_digest):
            raise ValueError("previous_digest must be a SHA-256 digest.")
        _forbid_row_mutation(self)
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("MaintenanceEvidence records are durable history and cannot be deleted.")


# =============================================================================
# V2 Lifecycle Phase 2 -- MANAGED-DEVICE IDENTITY, ATTACHMENTS AND BOOTSTRAP AUTHORIZATION (core.services.devices).
#
# ``ManagedDevice`` is the lifecycle / identity layer over the EXISTING inventory sources, not a second inventory: a device
# NMAS already manages through ``inventory.yml`` keeps every address and credential reference there (the tracked file stays
# the authority) and is ADOPTED here explicitly; a new device is REGISTERED here before any bootstrap exists.  Separate
# concerns stay separate fields: the operational lifecycle, the identity verification, the production admission, ZTP and
# configuration compliance.  None of them implies another (an approved bootstrap authorization never admits a device to
# production; an adopted in-service device is not ZTP-verified).  Maintenance stays ``MaintenanceRecord``'s concern.
#
# Lifecycle-owned fields are written only through the service (``core.services.devices.lifecycle``), which sets the
# per-instance write token and uses a version compare-and-swap; a plain ``save()`` / ``QuerySet.update()`` that touches them
# is refused.  Observations, lifecycle events are append-only; events are hash-chained per device.
# No credential, private key, token or shared secret is ever stored by any model in this section.
# =============================================================================

SERIAL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,63}$")
MAC_RE = re.compile(r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$")
INTERFACE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9/._:-]{0,63}$")
HOST_KEY_RE = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}$")


class DeviceLifecycleState(models.TextChoices):
    """The persistent operational lifecycle of one managed device (not a workflow, not an authorization)."""

    REGISTERED = "REGISTERED", "Registered / expected"
    DISCOVERED = "DISCOVERED", "Discovered (untrusted until verified)"
    BOOTSTRAPPED = "BOOTSTRAPPED", "Bootstrapped"
    ISOLATED = "ISOLATED", "Pre-commissioning isolated"
    READY_FOR_COMMISSIONING = "READY_FOR_COMMISSIONING", "Ready for commissioning"
    COMMISSIONING = "COMMISSIONING", "Commissioning"
    IN_SERVICE = "IN_SERVICE", "In service"
    DECOMMISSION_PENDING = "DECOMMISSION_PENDING", "Decommission pending"
    DECOMMISSIONED = "DECOMMISSIONED", "Decommissioned / retired"
    WITHDRAWN = "WITHDRAWN", "Registration withdrawn (never in service)"
    FAILED = "FAILED", "Failed / blocked"


DEVICE_LIFECYCLE_TERMINAL = frozenset({DeviceLifecycleState.DECOMMISSIONED, DeviceLifecycleState.WITHDRAWN})


class DeviceOrigin(models.TextChoices):
    """How the device entered the lifecycle registry -- historical provenance, never rewritten."""

    LEGACY_ADOPTION = "LEGACY_ADOPTION", "Adopted existing device (no NMAS onboarding history)"
    REGISTERED_NEW = "REGISTERED_NEW", "Registered new device"
    RESTORED = "RESTORED", "Restored successor of a decommissioned registration"


class InventoryAuthority(models.TextChoices):
    """Which source is authoritative for the device's addresses and credential references."""

    INVENTORY_FILE = "INVENTORY_FILE", "Tracked inventory.yml"
    NMAS_REGISTRY = "NMAS_REGISTRY", "NMAS lifecycle registry"


class IdentityVerificationState(models.TextChoices):
    UNVERIFIED = "UNVERIFIED", "Unverified (no independent identity evidence)"
    PENDING_VERIFICATION = "PENDING_VERIFICATION", "Discovered; identity pending verification"
    VERIFIED = "VERIFIED", "Verified from independently observed evidence"
    MISMATCH = "MISMATCH", "Observed identity conflicts with the authorized identity"


class ProductionAdmissionState(models.TextChoices):
    NOT_ADMITTED = "NOT_ADMITTED", "Not admitted to production"
    LEGACY_PREEXISTING = "LEGACY_PREEXISTING", "Pre-existing production participation (predates NMAS admission control)"
    ADMITTED = "ADMITTED", "Admitted to production by NMAS"
    WITHDRAWN = "WITHDRAWN", "Production admission withdrawn"


class ZtpState(models.TextChoices):
    UNKNOWN = "UNKNOWN", "Unknown (not observed)"
    ENABLED = "ENABLED", "ZTP enabled (observed)"
    DISABLED_VERIFIED = "DISABLED_VERIFIED", "ZTP disabled (verified)"


class ComplianceState(models.TextChoices):
    UNKNOWN = "UNKNOWN", "Unknown (not verified)"
    VERIFIED = "VERIFIED", "Configuration compliance verified"
    DRIFT = "DRIFT", "Configuration drift observed"


class DeviceLifecycleEventOutcome(models.TextChoices):
    ADVANCED = "ADVANCED", "Advanced"
    UNCHANGED = "UNCHANGED", "Unchanged (idempotent repeat)"
    RECORDED = "RECORDED", "Recorded"
    REFUSED = "REFUSED", "Refused"


class _ManagedDeviceQuerySet(models.QuerySet):
    """Refuses bulk writes of lifecycle-owned fields and every delete; the service's compare-and-swap is the one writer."""

    def update(self, **kwargs):
        guarded = set(kwargs) & set(ManagedDevice.LIFECYCLE_FIELDS)
        if guarded:
            raise ValueError(f"ManagedDevice lifecycle fields {sorted(guarded)} change only through core.services.devices.lifecycle.")
        return super().update(**kwargs)

    def compare_and_swap(self, pk, version: int, **fields) -> int:
        """Write ``fields`` (plus version + 1) only if the row is still at ``version``.  -> rows written (0 = a concurrent writer won)."""
        rows = super().filter(pk=pk, version=version)
        return models.QuerySet.update(rows, version=version + 1, updated_at=_now(), **fields)   # bypasses the guarded update()

    def delete(self, *args, **kwargs):
        raise ValueError("ManagedDevice records are lifecycle history and cannot be deleted.")


def _now():
    from django.utils import timezone

    return timezone.now()


class ManagedDevice(models.Model):
    """One managed device's identity and lifecycle.  ``device_id`` is derived from the primary key (``DEV-000001``).

    Identity has four tiers kept apart: ``expected_*`` is the operator-authorized identity; claims and independent
    observations are ``DeviceObservation`` rows; ``verified_*`` is written only by identity verification from an
    independently observed record.  Blank means unknown -- nothing is ever invented.
    """

    LIFECYCLE_FIELDS = ("lifecycle_state", "identity_state", "admission_state", "ztp_state", "compliance_state",
                        "expected_serial", "expected_base_mac",
                        "verified_serial", "verified_base_mac", "verified_host_key", "identity_verified_at", "identity_verified_by",
                        "retired_at", "version")
    _IMMUTABLE = ("name", "platform", "origin", "inventory_authority", "registered_by", "predecessor_id")

    name = models.CharField(max_length=64, validators=[DEVICE_NAME_VALIDATOR], editable=False)
    platform = models.CharField(max_length=32, choices=Platform.choices, editable=False)
    role = models.CharField(max_length=32)
    origin = models.CharField(max_length=24, choices=DeviceOrigin.choices, editable=False)
    inventory_authority = models.CharField(max_length=24, choices=InventoryAuthority.choices, editable=False)

    lifecycle_state = models.CharField(max_length=32, choices=DeviceLifecycleState.choices)
    identity_state = models.CharField(max_length=24, choices=IdentityVerificationState.choices, default=IdentityVerificationState.UNVERIFIED)
    admission_state = models.CharField(max_length=24, choices=ProductionAdmissionState.choices, default=ProductionAdmissionState.NOT_ADMITTED)
    ztp_state = models.CharField(max_length=24, choices=ZtpState.choices, default=ZtpState.UNKNOWN)
    compliance_state = models.CharField(max_length=16, choices=ComplianceState.choices, default=ComplianceState.UNKNOWN)

    manufacturer = models.CharField(max_length=64, blank=True, default="")
    model = models.CharField(max_length=64, blank=True, default="")
    expected_serial = models.CharField(max_length=64, blank=True, default="", help_text="Operator-authorized serial; blank = unknown.")
    expected_base_mac = models.CharField(max_length=17, blank=True, default="", help_text="Operator-authorized chassis MAC; blank = unknown.")
    verified_serial = models.CharField(max_length=64, blank=True, default="")
    verified_base_mac = models.CharField(max_length=17, blank=True, default="")
    verified_host_key = models.CharField(max_length=51, blank=True, default="", help_text="SHA256 SSH host-key fingerprint (public).")
    identity_verified_at = models.DateTimeField(null=True, blank=True)
    identity_verified_by = models.CharField(max_length=150, blank=True, default="")

    netbox_device_id = models.PositiveIntegerField(null=True, blank=True, help_text="NetBox object id (reference only; NetBox stays authoritative).")
    provisioning_run = models.ForeignKey("ProvisioningRun", null=True, blank=True, on_delete=models.PROTECT, related_name="managed_devices")
    predecessor = models.ForeignKey("self", null=True, blank=True, on_delete=models.PROTECT, related_name="successors", editable=False,
                                    help_text="V2 Phase 7: the decommissioned registration this restored device succeeds.")

    registered_by = models.CharField(max_length=150, editable=False)
    repository_head = models.CharField(max_length=40, blank=True, default="")
    version = models.PositiveIntegerField(default=1)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    retired_at = models.DateTimeField(null=True, blank=True)

    objects = models.Manager.from_queryset(_ManagedDeviceQuerySet)()

    class Meta:
        ordering = ["name", "-id"]
        default_permissions = ()             # access is the existing NMAS actions (core.services.identity.policy)
        indexes = [models.Index(fields=["lifecycle_state"]), models.Index(fields=["origin"])]
        constraints = [
            models.UniqueConstraint(fields=["name"], condition=~Q(lifecycle_state__in=("DECOMMISSIONED", "WITHDRAWN")),
                                    name="unique_live_managed_device_name"),
            models.UniqueConstraint(fields=["expected_serial"], condition=~Q(expected_serial="") & ~Q(lifecycle_state__in=("DECOMMISSIONED", "WITHDRAWN")),
                                    name="unique_live_expected_serial"),
            models.UniqueConstraint(fields=["expected_base_mac"], condition=~Q(expected_base_mac="") & ~Q(lifecycle_state__in=("DECOMMISSIONED", "WITHDRAWN")),
                                    name="unique_live_expected_base_mac"),
            models.UniqueConstraint(fields=["verified_serial"], condition=~Q(verified_serial="") & ~Q(lifecycle_state__in=("DECOMMISSIONED", "WITHDRAWN")),
                                    name="unique_live_verified_serial"),
            models.UniqueConstraint(fields=["verified_base_mac"], condition=~Q(verified_base_mac="") & ~Q(lifecycle_state__in=("DECOMMISSIONED", "WITHDRAWN")),
                                    name="unique_live_verified_base_mac"),
            models.UniqueConstraint(fields=["verified_host_key"], condition=~Q(verified_host_key="") & ~Q(lifecycle_state__in=("DECOMMISSIONED", "WITHDRAWN")),
                                    name="unique_live_verified_host_key"),
            # an adopted device is always an inventory-file device; a VERIFIED identity always names who verified it
            models.CheckConstraint(condition=~Q(origin="LEGACY_ADOPTION") | Q(inventory_authority="INVENTORY_FILE"),
                                   name="adopted_device_is_inventory_device"),
            models.CheckConstraint(condition=~Q(identity_state="VERIFIED") | ~Q(identity_verified_by=""),
                                   name="verified_identity_names_verifier"),
        ]

    def __str__(self):
        return f"{self.device_id}: {self.name} ({self.lifecycle_state})"

    @property
    def device_id(self) -> str:
        return f"DEV-{self.pk:06d}" if self.pk else "DEV-NEW"

    @property
    def is_terminal(self) -> bool:
        return self.lifecycle_state in DEVICE_LIFECYCLE_TERMINAL

    def get_absolute_url(self):
        return reverse("core:managed_device_detail", args=[self.device_id])

    def save(self, *args, **kwargs):
        for name, choices in (("lifecycle_state", DeviceLifecycleState), ("identity_state", IdentityVerificationState),
                              ("admission_state", ProductionAdmissionState), ("ztp_state", ZtpState),
                              ("compliance_state", ComplianceState), ("origin", DeviceOrigin),
                              ("inventory_authority", InventoryAuthority), ("platform", Platform)):
            if getattr(self, name) not in choices.values:
                raise ValueError(f"Invalid ManagedDevice.{name} {getattr(self, name)!r}.")
        for name, pattern in (("expected_serial", SERIAL_RE), ("verified_serial", SERIAL_RE), ("expected_base_mac", MAC_RE),
                              ("verified_base_mac", MAC_RE), ("verified_host_key", HOST_KEY_RE)):
            value = getattr(self, name)
            if value and not pattern.fullmatch(value):
                raise ValueError(f"ManagedDevice.{name} is malformed.")
        authorized = self.__dict__.pop("_lifecycle_write", False)   # one save only: the flag never stays on the instance
        persisted = type(self).objects.filter(pk=self.pk).values(*self._IMMUTABLE, *self.LIFECYCLE_FIELDS).first() if self.pk else None
        if persisted is None:
            if not authorized:
                raise ValueError("ManagedDevice records are created only through core.services.devices.")
        else:
            if persisted["lifecycle_state"] in DEVICE_LIFECYCLE_TERMINAL:
                raise ValueError("A decommissioned or withdrawn ManagedDevice is immutable history.")
            for name in self._IMMUTABLE:
                if persisted[name] != getattr(self, name):
                    raise ValueError(f"ManagedDevice.{name} is immutable after creation.")
            changed = [name for name in self.LIFECYCLE_FIELDS if persisted[name] != getattr(self, name)]
            if changed and not authorized:
                raise ValueError(f"ManagedDevice lifecycle fields {changed} change only through core.services.devices.lifecycle.")
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("ManagedDevice records are lifecycle history and cannot be deleted.")


class AttachmentPurpose(models.TextChoices):
    MANAGEMENT = "MANAGEMENT", "Management"
    PRODUCTION = "PRODUCTION", "Production uplink"


class AttachmentConnectivity(models.TextChoices):
    ACCESS = "ACCESS", "Physical, untagged access"
    TRUNK = "TRUNK", "Physical, tagged trunk"
    ROUTED = "ROUTED", "Physical, routed"
    SUBINTERFACE = "SUBINTERFACE", "Logical 802.1Q subinterface"


class AttachmentSource(models.TextChoices):
    """Where the EXPECTED attachment comes from (expectation, never observation)."""

    OPERATOR = "OPERATOR", "Authorized operator registration"
    NETBOX_CABLE = "NETBOX_CABLE", "NetBox cable relationship"
    LAB_REFERENCE = "LAB_REFERENCE", "Lab topology reference (not device authentication)"


class AttachmentApproval(models.TextChoices):
    PENDING = "PENDING", "Pending approval"
    APPROVED = "APPROVED", "Approved"
    REVOKED = "REVOKED", "Revoked"


class AttachmentVerification(models.TextChoices):
    UNVERIFIED = "UNVERIFIED", "Unverified"
    VERIFIED = "VERIFIED", "Verified by a trusted observation"
    MISMATCH = "MISMATCH", "A trusted observation contradicts it"


class DeviceAttachment(models.Model):
    """One EXPECTED connection of a device to a managed upstream device's interface.  A device may have several (multihoming).

    The upstream is named, never inferred: it must resolve to a managed device when the expectation is recorded.  What was
    really seen is a ``DeviceObservation``; ``verification_state`` is derived from trusted observations only.
    """

    _IMMUTABLE = ("device_id", "upstream_device", "upstream_interface", "local_interface", "purpose", "connectivity", "vlan", "source", "created_by")

    device = models.ForeignKey(ManagedDevice, on_delete=models.PROTECT, related_name="attachments", editable=False)
    upstream_device = models.CharField(max_length=64, validators=[DEVICE_NAME_VALIDATOR], editable=False)
    upstream_interface = models.CharField(max_length=64, editable=False)
    local_interface = models.CharField(max_length=64, blank=True, default="", editable=False)
    purpose = models.CharField(max_length=16, choices=AttachmentPurpose.choices, editable=False)
    connectivity = models.CharField(max_length=16, choices=AttachmentConnectivity.choices, editable=False)
    vlan = models.PositiveSmallIntegerField(null=True, blank=True, editable=False)
    source = models.CharField(max_length=16, choices=AttachmentSource.choices, default=AttachmentSource.OPERATOR, editable=False)
    approval_state = models.CharField(max_length=12, choices=AttachmentApproval.choices, default=AttachmentApproval.PENDING)
    verification_state = models.CharField(max_length=12, choices=AttachmentVerification.choices, default=AttachmentVerification.UNVERIFIED)
    mismatch = models.JSONField(default=dict, blank=True)
    observed_at = models.DateTimeField(null=True, blank=True)
    created_by = models.CharField(max_length=150, editable=False)
    approved_by = models.CharField(max_length=150, blank=True, default="")
    approved_at = models.DateTimeField(null=True, blank=True)
    revoked_by = models.CharField(max_length=150, blank=True, default="")
    revoked_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["device", "id"]
        default_permissions = ()
        constraints = [
            # one physical upstream port carries one expected device
            models.UniqueConstraint(fields=["upstream_device", "upstream_interface"], condition=~Q(approval_state="REVOKED"),
                                    name="unique_live_attachment_upstream_port"),
            models.UniqueConstraint(fields=["device", "local_interface"], condition=~Q(local_interface="") & ~Q(approval_state="REVOKED"),
                                    name="unique_live_attachment_local_port"),
            models.CheckConstraint(condition=Q(vlan__isnull=True) | Q(vlan__gte=1, vlan__lte=4094), name="attachment_vlan_range"),
        ]

    def __str__(self):
        return f"{self.device.name} -> {self.upstream_device}:{self.upstream_interface} ({self.purpose})"

    def save(self, *args, **kwargs):
        for name, choices in (("purpose", AttachmentPurpose), ("connectivity", AttachmentConnectivity), ("source", AttachmentSource),
                              ("approval_state", AttachmentApproval), ("verification_state", AttachmentVerification)):
            if getattr(self, name) not in choices.values:
                raise ValueError(f"Invalid DeviceAttachment.{name} {getattr(self, name)!r}.")
        for name in ("upstream_interface", "local_interface"):
            value = getattr(self, name)
            if (value or name == "upstream_interface") and not INTERFACE_RE.fullmatch(value or ""):
                raise ValueError(f"DeviceAttachment.{name} is malformed.")
        if self.pk:
            persisted = type(self).objects.filter(pk=self.pk).values("approval_state", *self._IMMUTABLE).first()
            if persisted is not None:
                if persisted["approval_state"] == AttachmentApproval.REVOKED:
                    raise ValueError("A revoked DeviceAttachment is immutable history.")
                for name in self._IMMUTABLE:
                    if persisted[name] != getattr(self, name):
                        raise ValueError(f"DeviceAttachment.{name.removesuffix('_id')} is immutable after creation.")
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("DeviceAttachment records are history: revoke the attachment instead of deleting it.")


class ObservationKind(models.TextChoices):
    IDENTITY = "IDENTITY", "Identity"
    ATTACHMENT = "ATTACHMENT", "Attachment"


class ObservationSource(models.TextChoices):
    DHCP_CLIENT_CLAIM = "DHCP_CLIENT_CLAIM", "DHCP client claim (option 61 / client MAC / hostname)"
    LLDP_NEIGHBOR_CLAIM = "LLDP_NEIGHBOR_CLAIM", "LLDP advertisement of the device itself"
    LAB_TOPOLOGY_REFERENCE = "LAB_TOPOLOGY_REFERENCE", "Lab topology metadata (reference only)"
    NETBOX_CABLE = "NETBOX_CABLE", "NetBox cable record (documented intent)"
    TRUSTED_UPSTREAM_INTERFACE = "TRUSTED_UPSTREAM_INTERFACE", "Trusted upstream device's own interface observation"
    DHCP_RELAY_ATTACHMENT = "DHCP_RELAY_ATTACHMENT", "Trusted DHCP relay attachment information"
    AUTHENTICATED_SESSION = "AUTHENTICATED_SESSION", "Read over an authenticated management session"


class ObservationTrust(models.TextChoices):
    CLAIMED = "CLAIMED", "Claimed by the device (untrusted)"
    REFERENCE = "REFERENCE", "Reference data (not an observation of the device)"
    OBSERVED = "OBSERVED", "Independently observed by trusted infrastructure"


# Trust is a property of the SOURCE, never chosen by the caller.
OBSERVATION_TRUST = {
    ObservationSource.DHCP_CLIENT_CLAIM: ObservationTrust.CLAIMED,
    ObservationSource.LLDP_NEIGHBOR_CLAIM: ObservationTrust.CLAIMED,
    ObservationSource.LAB_TOPOLOGY_REFERENCE: ObservationTrust.REFERENCE,
    ObservationSource.NETBOX_CABLE: ObservationTrust.REFERENCE,
    ObservationSource.TRUSTED_UPSTREAM_INTERFACE: ObservationTrust.OBSERVED,
    ObservationSource.DHCP_RELAY_ATTACHMENT: ObservationTrust.OBSERVED,
    ObservationSource.AUTHENTICATED_SESSION: ObservationTrust.OBSERVED,
}


class ObservationResult(models.TextChoices):
    MATCH = "MATCH", "Matches the authorized expectation"
    MISMATCH = "MISMATCH", "Contradicts the authorized expectation"
    UNTRUSTED = "UNTRUSTED", "Recorded; untrusted evidence proves nothing"
    RECORDED = "RECORDED", "Recorded (nothing to compare)"


class DeviceObservation(models.Model):
    """One piece of identity or attachment evidence about a device, as seen.  Append-only; ``trust`` follows ``source``."""

    device = models.ForeignKey(ManagedDevice, on_delete=models.PROTECT, related_name="observations", editable=False)
    kind = models.CharField(max_length=12, choices=ObservationKind.choices, editable=False)
    source = models.CharField(max_length=32, choices=ObservationSource.choices, editable=False)
    trust = models.CharField(max_length=12, choices=ObservationTrust.choices, editable=False)
    claims = models.JSONField(default=dict, blank=True, editable=False, help_text="Bounded, secret-free identity claims (serial, base_mac, host_key, hostname).")
    upstream_device = models.CharField(max_length=64, blank=True, default="", editable=False)
    upstream_interface = models.CharField(max_length=64, blank=True, default="", editable=False)
    local_interface = models.CharField(max_length=64, blank=True, default="", editable=False)
    attachment = models.ForeignKey(DeviceAttachment, null=True, blank=True, on_delete=models.PROTECT, related_name="observations", editable=False)
    result = models.CharField(max_length=12, choices=ObservationResult.choices, editable=False)
    mismatches = models.JSONField(default=list, blank=True, editable=False)
    recorded_by = models.CharField(max_length=150, editable=False)
    observed_at = models.DateTimeField(editable=False)
    created_at = models.DateTimeField(auto_now_add=True)

    objects = _ImmutableManager()

    class Meta:
        ordering = ["-observed_at", "-id"]
        default_permissions = ()
        indexes = [models.Index(fields=["device", "kind", "-observed_at"])]

    def __str__(self):
        return f"{self.device.name} {self.kind} {self.source}: {self.result}"

    def save(self, *args, **kwargs):
        if self.source not in ObservationSource.values or self.kind not in ObservationKind.values or self.result not in ObservationResult.values:
            raise ValueError("Invalid DeviceObservation source / kind / result.")
        if self.trust != OBSERVATION_TRUST[ObservationSource(self.source)]:
            raise ValueError("DeviceObservation.trust is determined by its source.")
        _forbid_row_mutation(self)
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("DeviceObservation records are evidence and cannot be deleted.")


class BootstrapAuthorizationState(models.TextChoices):
    PENDING_APPROVAL = "PENDING_APPROVAL", "Pending approval"
    APPROVED = "APPROVED", "Approved (bootstrap only -- never production admission)"
    REVOKED = "REVOKED", "Revoked"
    EXPIRED = "EXPIRED", "Expired"
    CONSUMED = "CONSUMED", "Consumed (use limit reached)"


BOOTSTRAP_AUTHORIZATION_OPEN = frozenset({BootstrapAuthorizationState.PENDING_APPROVAL, BootstrapAuthorizationState.APPROVED})
_BOOTSTRAP_AUTHORIZATION_EDGES = {
    BootstrapAuthorizationState.PENDING_APPROVAL: {BootstrapAuthorizationState.APPROVED, BootstrapAuthorizationState.REVOKED,
                                                   BootstrapAuthorizationState.EXPIRED},
    BootstrapAuthorizationState.APPROVED: {BootstrapAuthorizationState.REVOKED, BootstrapAuthorizationState.EXPIRED,
                                           BootstrapAuthorizationState.CONSUMED},
}


class BootstrapAuthorization(models.Model):
    """The authorization context a future bootstrap request must match (``BAUTH-000001``).  Grants bootstrap scope only.

    Bound at request time to the device's authorized identity, platform, one approved expected attachment, the scope, the
    validity window and the use limit (``binding_digest``).  An approval confirms that exact digest; if the bound context
    changes afterwards the decision engine reports the authorization STALE.  Carries no credential of any kind.
    """

    _IMMUTABLE = ("device_id", "attachment_id", "expected_platform", "scope", "requested_by", "valid_from", "valid_until", "max_uses",
                  "binding_digest")

    device = models.ForeignKey(ManagedDevice, on_delete=models.PROTECT, related_name="bootstrap_authorizations", editable=False)
    attachment = models.ForeignKey(DeviceAttachment, on_delete=models.PROTECT, related_name="bootstrap_authorizations", editable=False)
    expected_platform = models.CharField(max_length=32, choices=Platform.choices, editable=False)
    scope = models.JSONField(default=list, editable=False, help_text="Bootstrap scope tokens only (DHCP / bootstrap fetch / initial management).")
    state = models.CharField(max_length=20, choices=BootstrapAuthorizationState.choices, default=BootstrapAuthorizationState.PENDING_APPROVAL)
    requested_by = models.CharField(max_length=150, editable=False)
    reason = models.CharField(max_length=300, blank=True, default="")
    valid_from = models.DateTimeField(editable=False)
    valid_until = models.DateTimeField(editable=False)
    max_uses = models.PositiveSmallIntegerField(default=1, editable=False)
    use_count = models.PositiveSmallIntegerField(default=0)
    binding_digest = models.CharField(max_length=64, editable=False)
    approved_by = models.CharField(max_length=150, blank=True, default="")
    approved_at = models.DateTimeField(null=True, blank=True)
    approval_digest = models.CharField(max_length=64, blank=True, default="")
    revoked_by = models.CharField(max_length=150, blank=True, default="")
    revoked_at = models.DateTimeField(null=True, blank=True)
    revocation_reason = models.CharField(max_length=300, blank=True, default="")
    closed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at", "-id"]
        default_permissions = ()
        indexes = [models.Index(fields=["device", "state"])]
        constraints = [
            models.UniqueConstraint(fields=["device"], condition=Q(state__in=("PENDING_APPROVAL", "APPROVED")),
                                    name="unique_open_bootstrap_authorization_per_device"),
            models.CheckConstraint(condition=Q(valid_until__gt=F("valid_from")), name="bootstrap_authorization_window"),
            models.CheckConstraint(condition=Q(max_uses__gte=1, max_uses__lte=10) & Q(use_count__lte=F("max_uses")),
                                   name="bootstrap_authorization_use_bounds"),
            models.CheckConstraint(condition=Q(approved_by="") | ~Q(approved_by=F("requested_by")),
                                   name="bootstrap_authorization_not_self_approved"),
        ]

    def __str__(self):
        return f"{self.auth_id}: {self.device.name} ({self.state})"

    @property
    def auth_id(self) -> str:
        return f"BAUTH-{self.pk:06d}" if self.pk else "BAUTH-NEW"

    @property
    def is_open(self) -> bool:
        return self.state in BOOTSTRAP_AUTHORIZATION_OPEN

    def save(self, *args, **kwargs):
        if self.state not in BootstrapAuthorizationState.values:
            raise ValueError(f"Invalid bootstrap authorization state {self.state!r}.")
        if not _HEX64.fullmatch(self.binding_digest or "") or (self.approval_digest and not _HEX64.fullmatch(self.approval_digest)):
            raise ValueError("Bootstrap authorization digests must be SHA-256 digests.")
        if self.pk:
            persisted = type(self).objects.filter(pk=self.pk).values("state", *self._IMMUTABLE).first()
            if persisted is not None:
                if persisted["state"] not in BOOTSTRAP_AUTHORIZATION_OPEN:
                    raise ValueError("A revoked, expired or consumed bootstrap authorization is immutable history.")
                if persisted["state"] != self.state and self.state not in _BOOTSTRAP_AUTHORIZATION_EDGES[persisted["state"]]:
                    raise ValueError(f"Bootstrap authorization cannot move {persisted['state']} -> {self.state}.")
                for name in self._IMMUTABLE:
                    if persisted[name] != getattr(self, name):
                        raise ValueError(f"BootstrapAuthorization.{name.removesuffix('_id')} is immutable after creation.")
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("BootstrapAuthorization records are history and cannot be deleted.")


class DeviceLifecycleEvent(models.Model):
    """One attempted lifecycle / identity / attachment / authorization action on one device -- advanced, unchanged, recorded or
    refused.  Append-only, numbered per device and hash-chained (``entry_digest`` covers the payload and the previous entry)."""

    device = models.ForeignKey(ManagedDevice, on_delete=models.PROTECT, related_name="lifecycle_events", editable=False)
    sequence = models.PositiveIntegerField(editable=False)
    action = models.CharField(max_length=40, editable=False)
    outcome = models.CharField(max_length=12, choices=DeviceLifecycleEventOutcome.choices, editable=False)
    from_state = models.CharField(max_length=32, blank=True, default="", editable=False)
    to_state = models.CharField(max_length=32, blank=True, default="", editable=False)
    actor = models.CharField(max_length=150, editable=False)
    actor_kind = models.CharField(max_length=12, editable=False, help_text="HUMAN or AUTOMATION -- never a device identity.")
    authorization = models.JSONField(default=dict, blank=True, editable=False, help_text="Required action and the decision.")
    blockers = models.JSONField(default=list, blank=True, editable=False)
    evidence = models.JSONField(default=dict, blank=True, editable=False, help_text="Bounded, secret-free references and facts.")
    bootstrap_authorization = models.ForeignKey(BootstrapAuthorization, null=True, blank=True, on_delete=models.PROTECT, related_name="events", editable=False)
    attachment = models.ForeignKey(DeviceAttachment, null=True, blank=True, on_delete=models.PROTECT, related_name="events", editable=False)
    observation = models.ForeignKey(DeviceObservation, null=True, blank=True, on_delete=models.PROTECT, related_name="events", editable=False)
    correlation_id = models.CharField(max_length=36, editable=False)
    repository_head = models.CharField(max_length=40, blank=True, default="", editable=False)
    previous_digest = models.CharField(max_length=64, blank=True, default="", editable=False)
    entry_digest = models.CharField(max_length=64, unique=True, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)

    objects = _ImmutableManager()

    class Meta:
        ordering = ["device", "sequence"]
        default_permissions = ()
        constraints = [models.UniqueConstraint(fields=["device", "sequence"], name="unique_device_lifecycle_event_sequence")]

    def __str__(self):
        return f"{self.device.device_id} #{self.sequence} {self.action}: {self.outcome}"

    def save(self, *args, **kwargs):
        if self.outcome not in DeviceLifecycleEventOutcome.values:
            raise ValueError(f"Invalid device lifecycle event outcome {self.outcome!r}.")
        if not _HEX64.fullmatch(self.entry_digest or "") or (self.previous_digest and not _HEX64.fullmatch(self.previous_digest)):
            raise ValueError("Device lifecycle event digests must be SHA-256 digests.")
        _forbid_row_mutation(self)
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("DeviceLifecycleEvent records are durable history and cannot be deleted.")


# =============================================================================
# V2 Lifecycle Phase 3 -- native ZTP, DHCP discovery and secure bootstrap (``core.services.ztp``)
#
# A ``BootstrapNetwork`` is an explicitly modelled, isolated bootstrap path (never VLAN 200, never the Containerlab
# management network, never a production pool).  A ``ZtpSession`` is ONE onboarding attempt of ONE registered device under ONE
# approved Phase 2 ``BootstrapAuthorization``: it records the selected native adapter and transport and the separate evidence
# stages (discovery, delivery, management reach, management verification).  It never holds a credential: the enrollment private
# key lives in the protected runtime secret provider (``enrollment_key_ref`` is an opaque reference) and only the PUBLIC key and
# fingerprints are stored.  Artifacts are secret-free by construction; deliveries and DHCP lease observations are evidence.
# Nothing here admits a device to production.
# =============================================================================


class DhcpProviderKind(models.TextChoices):
    ISC_DHCP = "ISC_DHCP", "ISC DHCP (isc-dhcp-server)"
    KEA = "KEA", "ISC Kea DHCPv4 (configuration generation / validation only)"


class BootstrapNetworkState(models.TextChoices):
    ACTIVE = "ACTIVE", "Active"
    RETIRED = "RETIRED", "Retired"


class BootstrapNetwork(models.Model):
    """One isolated bootstrap subnet served by one DHCP provider and one NMAS artifact service.  ``trusted_relays`` maps each
    relay (giaddr) the provider may hear from to the managed upstream device that inserts option 82 -- the only source of
    trusted attachment evidence.  A lease that did not come through a listed relay is recorded and never trusted."""

    name = models.CharField(max_length=64, unique=True, validators=[DEVICE_NAME_VALIDATOR])
    provider = models.CharField(max_length=12, choices=DhcpProviderKind.choices, default=DhcpProviderKind.ISC_DHCP)
    ipv4_prefix = models.CharField(max_length=43)
    gateway = models.GenericIPAddressField(protocol="IPv4")
    pool_start = models.GenericIPAddressField(protocol="IPv4")
    pool_end = models.GenericIPAddressField(protocol="IPv4")
    vlan = models.PositiveSmallIntegerField(null=True, blank=True)
    service_address = models.GenericIPAddressField(protocol="IPv4", help_text="NMAS artifact service address on the bootstrap path.")
    service_prefix = models.CharField(max_length=43, help_text="The NMAS bootstrap-service link the relays forward to.")
    http_port = models.PositiveIntegerField(default=8080)
    tftp_port = models.PositiveIntegerField(default=69)
    trusted_relays = models.JSONField(default=list, blank=True, help_text='[{"relay_address": "...", "upstream_device": "..."}]')
    config_root = models.CharField(max_length=255, help_text="Isolated provider configuration directory (never /etc/dhcp).")
    lease_file = models.CharField(max_length=255, blank=True, default="")
    netbox_prefix_id = models.PositiveIntegerField(null=True, blank=True)
    isolated = models.BooleanField(default=True, help_text="Phase 3 serves isolated bootstrap networks only.")
    state = models.CharField(max_length=12, choices=BootstrapNetworkState.choices, default=BootstrapNetworkState.ACTIVE)
    created_by = models.CharField(max_length=150, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]
        default_permissions = ()
        constraints = [
            models.CheckConstraint(condition=Q(vlan__isnull=True) | (Q(vlan__gte=1, vlan__lte=4094) & ~Q(vlan=200)),
                                   name="bootstrap_network_never_vlan200"),
            models.CheckConstraint(condition=Q(isolated=True), name="bootstrap_network_isolated_only"),
        ]

    def __str__(self):
        return f"{self.name} ({self.ipv4_prefix}, {self.provider})"

    def delete(self, *args, **kwargs):
        raise ValueError("BootstrapNetwork records are history: retire the network instead of deleting it.")


class ZtpSessionStage(models.TextChoices):
    AWAITING_DISCOVERY = "AWAITING_DISCOVERY", "Awaiting native DHCP discovery"
    DISCOVERED = "DISCOVERED", "Discovered (trusted relay evidence correlated)"
    DELIVERED = "DELIVERED", "Bootstrap artifact delivered (not proof of application)"
    MANAGEMENT_REACHED = "MANAGEMENT_REACHED", "Management reached; host key not yet trusted"
    MANAGEMENT_VERIFIED = "MANAGEMENT_VERIFIED", "Minimal management bootstrap verified over an authenticated session"
    BOOTSTRAPPED = "BOOTSTRAPPED", "Bootstrapped (pending commission; not admitted)"
    FAILED = "FAILED", "Failed"
    CANCELLED = "CANCELLED", "Cancelled"


ZTP_SESSION_OPEN = frozenset({ZtpSessionStage.AWAITING_DISCOVERY, ZtpSessionStage.DISCOVERED, ZtpSessionStage.DELIVERED,
                              ZtpSessionStage.MANAGEMENT_REACHED, ZtpSessionStage.MANAGEMENT_VERIFIED})


class ZtpSession(models.Model):
    """One native-ZTP onboarding attempt (``ZTP-000001``).  Stage moves forward only through ``core.services.ztp.workflow``."""

    _IMMUTABLE = ("device_id", "authorization_id", "network_id", "adapter", "platform", "transport", "reserved_address",
                  "enrollment_key_ref", "enrollment_public_key", "enrollment_key_fingerprint", "opened_by")

    device = models.ForeignKey(ManagedDevice, on_delete=models.PROTECT, related_name="ztp_sessions", editable=False)
    authorization = models.ForeignKey(BootstrapAuthorization, on_delete=models.PROTECT, related_name="ztp_sessions", editable=False)
    network = models.ForeignKey(BootstrapNetwork, on_delete=models.PROTECT, related_name="ztp_sessions", editable=False)
    adapter = models.CharField(max_length=32, editable=False)
    platform = models.CharField(max_length=32, choices=Platform.choices, editable=False)
    transport = models.CharField(max_length=8, editable=False, help_text="Selected bootstrap transport (HTTP / HTTPS / TFTP).")
    transport_decision = models.JSONField(default=dict, blank=True, help_text="Candidates, policy and the reason for the selection.")
    reserved_address = models.GenericIPAddressField(protocol="IPv4", editable=False)
    stage = models.CharField(max_length=24, choices=ZtpSessionStage.choices, default=ZtpSessionStage.AWAITING_DISCOVERY)
    enrollment_key_ref = models.CharField(max_length=128, editable=False, help_text="Opaque runtime:// reference; never the key.")
    enrollment_public_key = models.TextField(editable=False)
    enrollment_key_fingerprint = models.CharField(max_length=51, editable=False)
    observed_host_key = models.CharField(max_length=51, blank=True, default="", help_text="First host key seen (untrusted until enrolled).")
    enrolled_host_key = models.CharField(max_length=51, blank=True, default="")
    host_key_enrolled_by = models.CharField(max_length=150, blank=True, default="")
    host_key_enrollment_basis = models.CharField(max_length=200, blank=True, default="")
    discovery = models.JSONField(default=dict, blank=True, help_text="The correlated trusted lease (ids and facts only).")
    verification = models.JSONField(default=dict, blank=True, help_text="The last management verification report.")
    failure = models.JSONField(default=dict, blank=True, help_text="Stable code, retryability and the native recovery guidance.")
    attempts = models.PositiveSmallIntegerField(default=0)
    opened_by = models.CharField(max_length=150, editable=False)
    closed_by = models.CharField(max_length=150, blank=True, default="")
    version = models.PositiveIntegerField(default=1)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    closed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at", "-id"]
        default_permissions = ()
        indexes = [models.Index(fields=["device", "stage"]), models.Index(fields=["network", "stage"])]
        constraints = [
            models.UniqueConstraint(fields=["device"], condition=Q(stage__in=("AWAITING_DISCOVERY", "DISCOVERED", "DELIVERED",
                                                                              "MANAGEMENT_REACHED", "MANAGEMENT_VERIFIED")),
                                    name="unique_open_ztp_session_per_device"),
            models.UniqueConstraint(fields=["network", "reserved_address"], condition=Q(stage__in=(
                "AWAITING_DISCOVERY", "DISCOVERED", "DELIVERED", "MANAGEMENT_REACHED", "MANAGEMENT_VERIFIED")),
                name="unique_open_ztp_reserved_address"),
            models.CheckConstraint(condition=Q(enrolled_host_key="") | ~Q(host_key_enrolled_by=""), name="ztp_enrolled_host_key_names_enroller"),
        ]

    def __str__(self):
        return f"{self.session_id}: {self.device.name} ({self.stage})"

    @property
    def session_id(self) -> str:
        return f"ZTP-{self.pk:06d}" if self.pk else "ZTP-NEW"

    @property
    def is_open(self) -> bool:
        return self.stage in ZTP_SESSION_OPEN

    def save(self, *args, **kwargs):
        if self.stage not in ZtpSessionStage.values:
            raise ValueError(f"Invalid ZTP session stage {self.stage!r}.")
        for name in ("observed_host_key", "enrolled_host_key", "enrollment_key_fingerprint"):
            value = getattr(self, name)
            if value and not HOST_KEY_RE.fullmatch(value):
                raise ValueError(f"ZtpSession.{name} must be an OpenSSH SHA256 fingerprint.")
        if "PRIVATE KEY" in (self.enrollment_public_key or ""):
            raise ValueError("ZtpSession stores public key material only.")
        if self.pk:
            persisted = type(self).objects.filter(pk=self.pk).values("stage", *self._IMMUTABLE).first()
            if persisted is not None:
                if persisted["stage"] not in ZTP_SESSION_OPEN and persisted["stage"] != self.stage:
                    raise ValueError("A closed ZTP session is immutable history.")
                for name in self._IMMUTABLE:
                    if persisted[name] != getattr(self, name):
                        raise ValueError(f"ZtpSession.{name.removesuffix('_id')} is immutable after creation.")
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("ZtpSession records are history and cannot be deleted.")


class BootstrapArtifactState(models.TextChoices):
    ACTIVE = "ACTIVE", "Active"
    REVOKED = "REVOKED", "Revoked"
    EXPIRED = "EXPIRED", "Expired"
    SUPERSEDED = "SUPERSEDED", "Superseded by a re-rendered artifact"


class BootstrapArtifact(models.Model):
    """One rendered, secret-free bootstrap artifact.  ``artifact_id`` is deterministic (session + content digest) and is the
    only path component a device ever requests; the content is immutable after creation."""

    _IMMUTABLE = ("session_id", "artifact_id", "filename", "content", "content_type", "sha256", "transport", "expires_at", "max_deliveries")

    session = models.ForeignKey(ZtpSession, on_delete=models.PROTECT, related_name="artifacts", editable=False)
    artifact_id = models.CharField(max_length=40, unique=True, editable=False)
    filename = models.CharField(max_length=64, editable=False)
    content = models.TextField(editable=False)
    content_type = models.CharField(max_length=64, editable=False)
    sha256 = models.CharField(max_length=64, editable=False)
    transport = models.CharField(max_length=8, editable=False)
    state = models.CharField(max_length=12, choices=BootstrapArtifactState.choices, default=BootstrapArtifactState.ACTIVE)
    expires_at = models.DateTimeField(editable=False)
    max_deliveries = models.PositiveSmallIntegerField(default=5, editable=False)
    delivery_count = models.PositiveSmallIntegerField(default=0)
    authorization_use_counted = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at", "-id"]
        default_permissions = ()
        constraints = [
            models.CheckConstraint(condition=Q(delivery_count__lte=F("max_deliveries")), name="bootstrap_artifact_delivery_bound"),
            models.UniqueConstraint(fields=["session"], condition=Q(state="ACTIVE"), name="unique_active_artifact_per_session"),
        ]

    def __str__(self):
        return f"{self.artifact_id} {self.filename} ({self.state})"

    def save(self, *args, **kwargs):
        if self.state not in BootstrapArtifactState.values:
            raise ValueError(f"Invalid artifact state {self.state!r}.")
        if not _HEX64.fullmatch(self.sha256 or ""):
            raise ValueError("BootstrapArtifact.sha256 must be a SHA-256 digest.")
        if self.pk:
            persisted = type(self).objects.filter(pk=self.pk).values("state", *self._IMMUTABLE).first()
            if persisted is not None:
                if persisted["state"] != BootstrapArtifactState.ACTIVE and persisted["state"] != self.state:
                    raise ValueError("A revoked, expired or superseded artifact is immutable history.")
                for name in self._IMMUTABLE:
                    if persisted[name] != getattr(self, name):
                        raise ValueError(f"BootstrapArtifact.{name.removesuffix('_id')} is immutable after creation.")
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("BootstrapArtifact records are delivery history and cannot be deleted.")


class BootstrapDeliveryOutcome(models.TextChoices):
    SERVED = "SERVED", "Served"
    REFUSED = "REFUSED", "Refused"
    FAILED = "FAILED", "Failed in transfer"


class BootstrapDelivery(models.Model):
    """One artifact request as the NMAS transport saw it (append-only).  A served delivery is NOT proof of application."""

    artifact = models.ForeignKey(BootstrapArtifact, null=True, blank=True, on_delete=models.PROTECT, related_name="deliveries", editable=False)
    session = models.ForeignKey(ZtpSession, null=True, blank=True, on_delete=models.PROTECT, related_name="deliveries", editable=False)
    transport = models.CharField(max_length=8, editable=False)
    client_address = models.GenericIPAddressField(editable=False)
    request_digest = models.CharField(max_length=64, editable=False, help_text="SHA-256 of the requested path (never the path itself).")
    outcome = models.CharField(max_length=8, choices=BootstrapDeliveryOutcome.choices, editable=False)
    code = models.CharField(max_length=40, blank=True, default="", editable=False)
    bytes_sent = models.PositiveIntegerField(default=0, editable=False)
    duplicate = models.BooleanField(default=False, editable=False)
    counted_authorization_use = models.BooleanField(default=False, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)

    objects = _ImmutableManager()

    class Meta:
        ordering = ["-created_at", "-id"]
        default_permissions = ()

    def save(self, *args, **kwargs):
        if self.outcome not in BootstrapDeliveryOutcome.values:
            raise ValueError("Invalid delivery outcome.")
        _forbid_row_mutation(self)
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("BootstrapDelivery records are evidence and cannot be deleted.")


class DhcpLeaseOutcome(models.TextChoices):
    CORRELATED = "CORRELATED", "Correlated to an open ZTP session through a trusted relay"
    UNTRUSTED_RELAY = "UNTRUSTED_RELAY", "No trusted relay evidence (recorded, never trusted)"
    UNAUTHORIZED = "UNAUTHORIZED", "No authorized device is expected on this relay port"
    IDENTITY_MISMATCH = "IDENTITY_MISMATCH", "Claimed identity contradicts the authorized identity"
    REFUSED = "REFUSED", "Refused by the bootstrap authorization decision"


class DhcpLeaseObservation(models.Model):
    """One distinct DHCP binding the NMAS-controlled provider granted, read from the provider's own lease database.

    Idempotent: retransmissions and renewals of the same binding update ``last_seen`` / ``seen_count`` only (no new lifecycle
    evidence).  Client-supplied fields (MAC, client id, vendor class, hostname) are CLAIMS; the relay address and the circuit id
    are trusted only when the relay is listed on the network."""

    _EVIDENCE = ("network_id", "idempotency_key", "address", "client_mac", "client_id", "vendor_class", "user_class", "hostname",
                 "relay_address", "circuit_id", "remote_id", "relay_trusted", "upstream_device", "upstream_interface",
                 "outcome", "code", "session_id", "device_id", "identity_observation_id", "attachment_observation_id")

    network = models.ForeignKey(BootstrapNetwork, on_delete=models.PROTECT, related_name="lease_observations", editable=False)
    session = models.ForeignKey(ZtpSession, null=True, blank=True, on_delete=models.PROTECT, related_name="lease_observations", editable=False)
    device = models.ForeignKey(ManagedDevice, null=True, blank=True, on_delete=models.PROTECT, related_name="lease_observations", editable=False)
    idempotency_key = models.CharField(max_length=64, unique=True, editable=False)
    provider = models.CharField(max_length=12, choices=DhcpProviderKind.choices, editable=False)
    address = models.GenericIPAddressField(protocol="IPv4", editable=False)
    client_mac = models.CharField(max_length=17, editable=False)
    client_id = models.CharField(max_length=128, blank=True, default="", editable=False)
    vendor_class = models.CharField(max_length=128, blank=True, default="", editable=False)
    user_class = models.CharField(max_length=128, blank=True, default="", editable=False)
    hostname = models.CharField(max_length=64, blank=True, default="", editable=False)
    relay_address = models.CharField(max_length=39, blank=True, default="", editable=False)
    circuit_id = models.CharField(max_length=64, blank=True, default="", editable=False)
    remote_id = models.CharField(max_length=64, blank=True, default="", editable=False)
    relay_trusted = models.BooleanField(default=False, editable=False)
    upstream_device = models.CharField(max_length=64, blank=True, default="", editable=False)
    upstream_interface = models.CharField(max_length=64, blank=True, default="", editable=False)
    binding_state = models.CharField(max_length=16, blank=True, default="")
    lease_starts = models.DateTimeField(null=True, blank=True)
    lease_ends = models.DateTimeField(null=True, blank=True)
    outcome = models.CharField(max_length=20, choices=DhcpLeaseOutcome.choices, editable=False)
    code = models.CharField(max_length=40, blank=True, default="", editable=False)
    identity_observation = models.ForeignKey(DeviceObservation, null=True, blank=True, on_delete=models.PROTECT, related_name="+", editable=False)
    attachment_observation = models.ForeignKey(DeviceObservation, null=True, blank=True, on_delete=models.PROTECT, related_name="+", editable=False)
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField()
    seen_count = models.PositiveIntegerField(default=1)

    class Meta:
        ordering = ["-last_seen", "-id"]
        default_permissions = ()
        indexes = [models.Index(fields=["network", "address"]), models.Index(fields=["session", "-last_seen"])]

    def __str__(self):
        return f"{self.network.name} {self.address} {self.client_mac} ({self.outcome})"

    def save(self, *args, **kwargs):
        if self.outcome not in DhcpLeaseOutcome.values:
            raise ValueError("Invalid lease outcome.")
        if self.pk:
            persisted = type(self).objects.filter(pk=self.pk).values(*self._EVIDENCE).first()
            if persisted is not None:
                for name in self._EVIDENCE:
                    if persisted[name] != getattr(self, name):
                        raise ValueError(f"DhcpLeaseObservation.{name.removesuffix('_id')} is evidence and immutable.")
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("DhcpLeaseObservation records are evidence and cannot be deleted.")


class DhcpRelayReadbackSource(models.TextChoices):
    POSTCHECK = "POSTCHECK", "Postcheck of a governed option 82 change"
    READ = "READ", "Read-only refresh through NMAS's device transport"


class DhcpRelayReadback(models.Model):
    """V2 Phase 9: one read-back of a relay's DHCP relay agent information (option 82) configuration, as NMAS read it over its own
    device transport -- the postcheck of a governed option 82 change or a read-only refresh.  ZTP trusts a relayed discovery only
    against the latest FRESH read-back (``ztp.relay_option82``): the relay's option 82 state is never taken from intent alone.

    Append-only evidence: a newer read-back supersedes an older one; none is ever edited or deleted."""

    device = models.CharField(max_length=64, editable=False)
    source = models.CharField(max_length=12, choices=DhcpRelayReadbackSource.choices, editable=False)
    change = models.ForeignKey("Change", null=True, blank=True, on_delete=models.PROTECT, related_name="relay_readbacks", editable=False)
    run_id = models.CharField(max_length=64, blank=True, default="", editable=False)
    readback = models.JSONField(default=dict, editable=False)          # dhcp_relay_option82.parse_eos: enabled + per-port ids, helpers, addresses
    config_digest = models.CharField(max_length=64, editable=False)    # the relay's configuration state digest at the read
    captured_by = models.CharField(max_length=150, editable=False)
    captured_at = models.DateTimeField(editable=False)

    objects = _ImmutableManager()

    class Meta:
        ordering = ["-captured_at", "-id"]
        default_permissions = ()
        indexes = [models.Index(fields=["device", "-captured_at"])]

    def __str__(self):
        return f"{self.device} option 82 read-back ({self.source}) {self.captured_at:%Y-%m-%d %H:%M}"

    def save(self, *args, **kwargs):
        if self.pk:
            raise ValueError("DhcpRelayReadback rows are append-only evidence.")
        if self.source not in DhcpRelayReadbackSource.values:
            raise ValueError("Invalid relay read-back source.")
        if not _HEX64.fullmatch(self.config_digest or ""):
            raise ValueError("A relay read-back carries the SHA-256 configuration digest it was read at.")
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("DhcpRelayReadback rows are evidence and cannot be deleted.")


class DhcpApplicationState(models.TextChoices):
    VALIDATED = "VALIDATED", "Rendered and validated by the provider (not applied)"
    APPLIED = "APPLIED", "Applied to the isolated provider and read back"
    FAILED = "FAILED", "Validation or application failed (previous configuration kept)"
    ROLLED_BACK = "ROLLED_BACK", "Previous configuration restored"


class DhcpProviderApplication(models.Model):
    """One render / validate / apply / recover attempt of a bootstrap network's DHCP policy (append-only, secret-free)."""

    network = models.ForeignKey(BootstrapNetwork, on_delete=models.PROTECT, related_name="applications", editable=False)
    provider = models.CharField(max_length=12, choices=DhcpProviderKind.choices, editable=False)
    state = models.CharField(max_length=12, choices=DhcpApplicationState.choices, editable=False)
    config_sha256 = models.CharField(max_length=64, editable=False)
    previous_sha256 = models.CharField(max_length=64, blank=True, default="", editable=False)
    config_text = models.TextField(editable=False)
    sessions = models.JSONField(default=list, blank=True, editable=False, help_text="Session ids included in the policy.")
    validation = models.JSONField(default=dict, blank=True, editable=False)
    read_back = models.JSONField(default=dict, blank=True, editable=False)
    code = models.CharField(max_length=40, blank=True, default="", editable=False)
    actor = models.CharField(max_length=150, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)

    objects = _ImmutableManager()

    class Meta:
        ordering = ["-created_at", "-id"]
        default_permissions = ()

    def save(self, *args, **kwargs):
        if self.state not in DhcpApplicationState.values or not _HEX64.fullmatch(self.config_sha256 or ""):
            raise ValueError("Invalid DHCP application record.")
        _forbid_row_mutation(self)
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("DhcpProviderApplication records are evidence and cannot be deleted.")


# =============================================================================
# V2 Lifecycle Phase 4 -- MANAGEMENT MULTIHOMING, MANAGEMENT VRF, FAILOVER AND BOOTSTRAP CREDENTIAL RETIREMENT
# (core.services.management).
#
# A device may have several registered management paths.  Each path is an EXPECTATION with physical provenance (the approved
# ``DeviceAttachment`` it rides on, or a routed management VRF), an NMAS-side attachment and an endpoint; it becomes usable
# only after approval by a second person AND layered verification (topology, configuration, reachability, return path,
# pinned-host-key authentication, service capability).  The priority class is fixed by the path type and never chosen by the
# caller.  At most one path per device is active; the selector (core.services.management.selector) is the only writer of
# health counters, the active flag and the per-device management state, under a version compare-and-swap.
# No path record holds a credential: credential SOURCES are references (inventory key, DeviceCredential id, ZTP enrollment).
# =============================================================================

MGMT_VRF_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,31}$")


class ManagementPathType(models.TextChoices):
    DIRECT_OOB = "DIRECT_OOB", "Direct authorized out-of-band management"
    VLAN_ADJACENT_SWITCH = "VLAN_ADJACENT_SWITCH", "VLAN 200 through an adjacent authorized switch"
    ROUTED_VRF = "ROUTED_VRF", "Routed management VRF"


# The priority hierarchy is a property of the path TYPE (1 = most preferred).  Within class 2 the order is by ascending
# adjacent-switch identity (natural name order, then DEV id) -- see core.services.management.paths.priority_key.
MANAGEMENT_PATH_CLASS = {
    ManagementPathType.DIRECT_OOB: 1,
    ManagementPathType.VLAN_ADJACENT_SWITCH: 2,
    ManagementPathType.ROUTED_VRF: 3,
}


class ManagementTransport(models.TextChoices):
    SSH = "SSH", "SSH (CLI)"
    EAPI = "EAPI", "Arista eAPI over HTTPS"
    NETCONF = "NETCONF", "NETCONF over SSH"
    GNMI = "GNMI", "gNMI"


class ManagementCredentialSource(models.TextChoices):
    """Where the credential for this path comes from -- a REFERENCE, never the credential."""

    INVENTORY = "INVENTORY", "The tracked inventory's credential references"
    DEVICE_CREDENTIAL = "DEVICE_CREDENTIAL", "An NMAS DeviceCredential (service account)"
    ZTP_ENROLLMENT = "ZTP_ENROLLMENT", "The ZTP enrollment key (bootstrap only, to be retired)"


class ManagementApproval(models.TextChoices):
    PENDING = "PENDING", "Pending approval"
    APPROVED = "APPROVED", "Approved"
    REVOKED = "REVOKED", "Revoked"


class ManagementPathHealth(models.TextChoices):
    UNVERIFIED = "UNVERIFIED", "Not yet verified"
    HEALTHY = "HEALTHY", "Verified healthy"
    DEGRADED = "DEGRADED", "Failing (below the failure threshold)"
    FAILED = "FAILED", "Failed (threshold reached)"
    INELIGIBLE = "INELIGIBLE", "Ineligible (topology / configuration prerequisites not met)"


class NmasManagementAttachment(models.Model):
    """One attachment of the NMAS host to a management network (``NMA-000001``).  Expectation + read-only observation.

    ``failure_domain`` names the infrastructure whose loss takes this attachment down (normally the upstream switch).  Two
    attachments in the same failure domain are NOT independent; full management-switch failure tolerance requires at least
    two VERIFIED attachments in different failure domains (core.services.management.nmas_side.spof_report).
    """

    _IMMUTABLE = ("name", "host_interface", "upstream_device", "upstream_interface", "source_address", "network", "failure_domain",
                  "created_by")

    name = models.CharField(max_length=64, validators=[DEVICE_NAME_VALIDATOR], editable=False)
    host_interface = models.CharField(max_length=32, editable=False, help_text="NMAS host interface name (observed read-only).")
    upstream_device = models.CharField(max_length=64, validators=[DEVICE_NAME_VALIDATOR], editable=False)
    upstream_interface = models.CharField(max_length=64, blank=True, default="", editable=False)
    source_address = models.GenericIPAddressField(editable=False, help_text="The NMAS address probes are bound to on this attachment.")
    network = models.CharField(max_length=49, editable=False, help_text="The management prefix (CIDR) reachable on this attachment.")
    failure_domain = models.CharField(max_length=64)
    approval_state = models.CharField(max_length=12, choices=ManagementApproval.choices, default=ManagementApproval.PENDING)
    verification_state = models.CharField(max_length=12, choices=AttachmentVerification.choices, default=AttachmentVerification.UNVERIFIED)
    observation = models.JSONField(default=dict, blank=True, help_text="Last read-only host observation (facts only).")
    observed_at = models.DateTimeField(null=True, blank=True)
    created_by = models.CharField(max_length=150, editable=False)
    approved_by = models.CharField(max_length=150, blank=True, default="")
    approved_at = models.DateTimeField(null=True, blank=True)
    revoked_by = models.CharField(max_length=150, blank=True, default="")
    revoked_at = models.DateTimeField(null=True, blank=True)
    version = models.PositiveIntegerField(default=1)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name", "id"]
        default_permissions = ()
        constraints = [
            models.UniqueConstraint(fields=["name"], condition=~Q(approval_state="REVOKED"), name="unique_live_nmas_attachment_name"),
            models.UniqueConstraint(fields=["host_interface", "source_address"], condition=~Q(approval_state="REVOKED"),
                                    name="unique_live_nmas_attachment_source"),
        ]

    def __str__(self):
        return f"{self.attachment_id}: {self.host_interface} -> {self.upstream_device}"

    @property
    def attachment_id(self) -> str:
        return f"NMA-{self.pk:06d}" if self.pk else "NMA-NEW"

    def save(self, *args, **kwargs):
        if self.approval_state not in ManagementApproval.values or self.verification_state not in AttachmentVerification.values:
            raise ValueError("Invalid NmasManagementAttachment state.")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._@-]{0,31}", self.host_interface or ""):
            raise ValueError("NmasManagementAttachment.host_interface is malformed.")
        if self.upstream_interface and not INTERFACE_RE.fullmatch(self.upstream_interface):
            raise ValueError("NmasManagementAttachment.upstream_interface is malformed.")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}", self.failure_domain or ""):
            raise ValueError("NmasManagementAttachment.failure_domain is malformed.")
        if self.pk:
            persisted = type(self).objects.filter(pk=self.pk).values("approval_state", *self._IMMUTABLE).first()
            if persisted is not None:
                if persisted["approval_state"] == ManagementApproval.REVOKED:
                    raise ValueError("A revoked NmasManagementAttachment is immutable history.")
                for name in self._IMMUTABLE:
                    if persisted[name] != getattr(self, name):
                        raise ValueError(f"NmasManagementAttachment.{name} is immutable after creation.")
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("NmasManagementAttachment records are history: revoke instead of deleting.")


class ManagementPath(models.Model):
    """One registered management path to one managed device (``MPATH-000001``)."""

    _IMMUTABLE = ("device_id", "path_type", "preference_class", "attachment_id", "via_device", "local_interface", "remote_interface",
                  "vlan", "tagged", "vrf", "endpoint_address", "transport", "port", "credential_source", "credential_reference",
                  "device_credential_id", "expected_host_key", "nmas_attachment_id", "expected_topology", "services", "policy", "created_by")
    SELECTOR_FIELDS = ("health_state", "consecutive_failures", "consecutive_successes", "last_probe_at", "last_success_at",
                       "last_failure_at", "last_failure_code", "last_layer_passed", "is_active", "activated_at", "verified_topology",
                       "version")

    device = models.ForeignKey(ManagedDevice, on_delete=models.PROTECT, related_name="management_paths", editable=False)
    path_type = models.CharField(max_length=24, choices=ManagementPathType.choices, editable=False)
    preference_class = models.PositiveSmallIntegerField(editable=False, help_text="Derived from the path type (1 = most preferred).")
    attachment = models.ForeignKey(DeviceAttachment, null=True, blank=True, on_delete=models.PROTECT, related_name="management_paths",
                                   editable=False, help_text="Physical provenance (required for OOB and VLAN-adjacent paths).")
    via_device = models.CharField(max_length=64, blank=True, default="", editable=False,
                                  help_text="The management / adjacent switch the path rides through.")
    local_interface = models.CharField(max_length=64, blank=True, default="", editable=False)
    remote_interface = models.CharField(max_length=64, blank=True, default="", editable=False)
    vlan = models.PositiveSmallIntegerField(null=True, blank=True, editable=False)
    tagged = models.BooleanField(default=False, editable=False)
    vrf = models.CharField(max_length=32, blank=True, default="", editable=False, help_text="Routed management VRF name.")
    endpoint_address = models.GenericIPAddressField(editable=False, help_text="The device's management address on this path.")
    transport = models.CharField(max_length=8, choices=ManagementTransport.choices, default=ManagementTransport.SSH, editable=False)
    port = models.PositiveIntegerField(default=22, editable=False)
    services = models.JSONField(default=list, blank=True, help_text="Service capabilities verified at L6 (SSH / EAPI / GNMI).")
    credential_source = models.CharField(max_length=20, choices=ManagementCredentialSource.choices, editable=False)
    credential_reference = models.CharField(max_length=128, blank=True, default="", editable=False,
                                            help_text="Opaque reference (inventory key / ZTP session id); never the credential.")
    device_credential = models.ForeignKey("DeviceCredential", null=True, blank=True, on_delete=models.PROTECT, related_name="management_paths",
                                          editable=False)
    expected_host_key = models.CharField(max_length=51, blank=True, default="", help_text="Pinned SHA256 host-key fingerprint.")
    nmas_attachment = models.ForeignKey(NmasManagementAttachment, on_delete=models.PROTECT, related_name="paths", editable=False)
    expected_topology = models.JSONField(default=dict, blank=True, help_text="Expected hop chain (device / interfaces / VLAN).")
    verified_topology = models.JSONField(default=dict, blank=True, help_text="What the last L1/L2 verification observed.")
    policy = models.JSONField(default=dict, blank=True, help_text="Bounded per-path overrides (failure / restore thresholds).")
    approval_state = models.CharField(max_length=12, choices=ManagementApproval.choices, default=ManagementApproval.PENDING)
    health_state = models.CharField(max_length=12, choices=ManagementPathHealth.choices, default=ManagementPathHealth.UNVERIFIED)
    consecutive_failures = models.PositiveIntegerField(default=0)
    consecutive_successes = models.PositiveIntegerField(default=0)
    last_probe_at = models.DateTimeField(null=True, blank=True)
    last_success_at = models.DateTimeField(null=True, blank=True)
    last_failure_at = models.DateTimeField(null=True, blank=True)
    last_failure_code = models.CharField(max_length=48, blank=True, default="")
    last_layer_passed = models.PositiveSmallIntegerField(default=0)
    is_active = models.BooleanField(default=False)
    activated_at = models.DateTimeField(null=True, blank=True)
    reason = models.CharField(max_length=200, blank=True, default="")
    created_by = models.CharField(max_length=150, editable=False)
    approved_by = models.CharField(max_length=150, blank=True, default="")
    approved_at = models.DateTimeField(null=True, blank=True)
    revoked_by = models.CharField(max_length=150, blank=True, default="")
    revoked_at = models.DateTimeField(null=True, blank=True)
    version = models.PositiveIntegerField(default=1)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["device", "preference_class", "id"]
        default_permissions = ()
        indexes = [models.Index(fields=["device", "approval_state", "preference_class"])]
        constraints = [
            models.UniqueConstraint(fields=["device"], condition=Q(is_active=True), name="unique_active_management_path"),
            models.UniqueConstraint(fields=["device", "path_type", "endpoint_address", "via_device", "vrf"], condition=~Q(approval_state="REVOKED"),
                                    name="unique_live_management_path"),
            models.CheckConstraint(condition=(Q(path_type="DIRECT_OOB", preference_class=1) | Q(path_type="VLAN_ADJACENT_SWITCH", preference_class=2)
                                              | Q(path_type="ROUTED_VRF", preference_class=3)), name="management_path_class_matches_type"),
            models.CheckConstraint(condition=Q(path_type="ROUTED_VRF") | Q(attachment__isnull=False), name="management_path_needs_attachment"),
            models.CheckConstraint(condition=~Q(path_type="VLAN_ADJACENT_SWITCH") | (Q(vlan__isnull=False) & ~Q(via_device="")),
                                   name="vlan_path_names_vlan_and_switch"),
            models.CheckConstraint(condition=~Q(path_type="ROUTED_VRF") | ~Q(vrf=""), name="routed_path_names_vrf"),
            models.CheckConstraint(condition=Q(is_active=False) | Q(approval_state="APPROVED"), name="active_path_is_approved"),
            models.CheckConstraint(condition=Q(port__gte=1, port__lte=65535), name="management_path_port_range"),
            models.CheckConstraint(condition=Q(vlan__isnull=True) | Q(vlan__gte=1, vlan__lte=4094), name="management_path_vlan_range"),
        ]

    def __str__(self):
        return f"{self.path_id}: {self.device.name} {self.path_type} {self.endpoint_address}"

    @property
    def path_id(self) -> str:
        return f"MPATH-{self.pk:06d}" if self.pk else "MPATH-NEW"

    def save(self, *args, **kwargs):
        for name, choices in (("path_type", ManagementPathType), ("transport", ManagementTransport),
                              ("credential_source", ManagementCredentialSource), ("approval_state", ManagementApproval),
                              ("health_state", ManagementPathHealth)):
            if getattr(self, name) not in choices.values:
                raise ValueError(f"Invalid ManagementPath.{name} {getattr(self, name)!r}.")
        if self.preference_class != MANAGEMENT_PATH_CLASS[ManagementPathType(self.path_type)]:
            raise ValueError("ManagementPath.preference_class is determined by the path type.")
        for name in ("local_interface", "remote_interface"):
            value = getattr(self, name)
            if value and not INTERFACE_RE.fullmatch(value):
                raise ValueError(f"ManagementPath.{name} is malformed.")
        if self.vrf and not MGMT_VRF_NAME_RE.fullmatch(self.vrf):
            raise ValueError("ManagementPath.vrf is malformed.")
        if self.expected_host_key and not HOST_KEY_RE.fullmatch(self.expected_host_key):
            raise ValueError("ManagementPath.expected_host_key must be an OpenSSH SHA256 fingerprint.")
        if self.credential_reference and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}", self.credential_reference):
            raise ValueError("ManagementPath.credential_reference must be an opaque reference.")
        if self.credential_source == ManagementCredentialSource.DEVICE_CREDENTIAL and not self.device_credential_id:
            raise ValueError("A DEVICE_CREDENTIAL path names the DeviceCredential it uses.")
        authorized = self.__dict__.pop("_selector_write", False)
        if self.pk:
            persisted = type(self).objects.filter(pk=self.pk).values("approval_state", *self._IMMUTABLE, *self.SELECTOR_FIELDS).first()
            if persisted is not None:
                if persisted["approval_state"] == ManagementApproval.REVOKED:
                    raise ValueError("A revoked ManagementPath is immutable history.")
                for name in self._IMMUTABLE:
                    if persisted[name] != getattr(self, name):
                        raise ValueError(f"ManagementPath.{name.removesuffix('_id')} is immutable after creation.")
                changed = [name for name in self.SELECTOR_FIELDS if persisted[name] != getattr(self, name)]
                if changed and not authorized:
                    raise ValueError(f"ManagementPath fields {changed} change only through core.services.management.selector.")
        elif self.is_active:
            raise ValueError("A ManagementPath is never created active.")
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("ManagementPath records are history: revoke the path instead of deleting it.")


class ProbePurpose(models.TextChoices):
    VERIFY = "VERIFY", "Operator-requested verification"
    MONITOR = "MONITOR", "Periodic health monitoring"
    FAILOVER = "FAILOVER", "Failover candidate verification"
    FAILBACK = "FAILBACK", "Failback candidate verification"
    PRE_EXECUTION = "PRE_EXECUTION", "Pre-execution path check"


class ManagementPathProbe(models.Model):
    """One layered verification of one path: every layer's result, the first failing layer and its stable code.  Append-only."""

    path = models.ForeignKey(ManagementPath, on_delete=models.PROTECT, related_name="probes", editable=False)
    device = models.ForeignKey(ManagedDevice, on_delete=models.PROTECT, related_name="management_probes", editable=False)
    purpose = models.CharField(max_length=16, choices=ProbePurpose.choices, editable=False)
    passed = models.BooleanField(editable=False)
    highest_layer = models.PositiveSmallIntegerField(editable=False, help_text="Highest consecutive layer that passed (0-6).")
    failure_code = models.CharField(max_length=48, blank=True, default="", editable=False)
    layers = models.JSONField(default=list, blank=True, editable=False, help_text="[{layer, name, ok, code, detail}] -- bounded, secret-free.")
    presented_host_key = models.CharField(max_length=51, blank=True, default="", editable=False)
    duration_ms = models.PositiveIntegerField(default=0, editable=False)
    actor = models.CharField(max_length=150, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)

    objects = _ImmutableManager()

    class Meta:
        ordering = ["-created_at", "-id"]
        default_permissions = ()
        indexes = [models.Index(fields=["path", "-created_at"]), models.Index(fields=["device", "-created_at"])]

    def save(self, *args, **kwargs):
        if self.purpose not in ProbePurpose.values or not 0 <= self.highest_layer <= 6:
            raise ValueError("Invalid ManagementPathProbe.")
        if self.passed and (self.highest_layer != 6 or self.failure_code):
            raise ValueError("A passing probe passed every layer and carries no failure code.")
        if not self.passed and not self.failure_code:
            raise ValueError("A failing probe names its stable failure code.")
        _forbid_row_mutation(self)
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("ManagementPathProbe records are evidence and cannot be deleted.")


class ManagementTransitionKind(models.TextChoices):
    ACTIVATE = "ACTIVATE", "Initial activation"
    FAILOVER = "FAILOVER", "Failover to a lower-priority path"
    FAILBACK = "FAILBACK", "Failback to a restored higher-priority path"
    LOST = "LOST", "All paths lost (management unreachable)"
    RECOVERED = "RECOVERED", "Recovered from no path"
    DEFERRED = "DEFERRED", "Switch deferred (execution in flight / hold-down)"
    DEACTIVATE = "DEACTIVATE", "Active path deactivated (revoked)"
    RESTART_RECOVERY = "RESTART_RECOVERY", "State re-derived after an NMAS restart"


class ManagementPathTransition(models.Model):
    """One change (or deliberately deferred change) of a device's active management path.  Append-only evidence."""

    device = models.ForeignKey(ManagedDevice, on_delete=models.PROTECT, related_name="management_transitions", editable=False)
    kind = models.CharField(max_length=20, choices=ManagementTransitionKind.choices, editable=False)
    from_path = models.ForeignKey(ManagementPath, null=True, blank=True, on_delete=models.PROTECT, related_name="transitions_from", editable=False)
    to_path = models.ForeignKey(ManagementPath, null=True, blank=True, on_delete=models.PROTECT, related_name="transitions_to", editable=False)
    reason_code = models.CharField(max_length=48, editable=False)
    evidence = models.JSONField(default=dict, blank=True, editable=False)
    probe = models.ForeignKey(ManagementPathProbe, null=True, blank=True, on_delete=models.PROTECT, related_name="transitions", editable=False)
    actor = models.CharField(max_length=150, editable=False)
    actor_kind = models.CharField(max_length=12, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)

    objects = _ImmutableManager()

    class Meta:
        ordering = ["-created_at", "-id"]
        default_permissions = ()
        indexes = [models.Index(fields=["device", "-created_at"])]

    def save(self, *args, **kwargs):
        if self.kind not in ManagementTransitionKind.values or self.actor_kind not in ("HUMAN", "AUTOMATION"):
            raise ValueError("Invalid ManagementPathTransition.")
        _forbid_row_mutation(self)
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("ManagementPathTransition records are evidence and cannot be deleted.")


class ManagementStatus(models.TextChoices):
    LEGACY = "LEGACY", "No approved paths (legacy inventory address)"
    ACTIVE = "ACTIVE", "Active path healthy"
    DEGRADED = "DEGRADED", "Active path failing; still within threshold"
    NO_PATH = "NO_PATH", "Management unreachable: no usable path"
    UNKNOWN = "UNKNOWN", "Not evaluated yet"


class DeviceManagementState(models.Model):
    """The selector's per-device state.  Durable, so a restart re-derives exactly what was active and why."""

    device = models.OneToOneField(ManagedDevice, on_delete=models.PROTECT, related_name="management_state", editable=False)
    status = models.CharField(max_length=12, choices=ManagementStatus.choices, default=ManagementStatus.UNKNOWN)
    active_path = models.ForeignKey(ManagementPath, null=True, blank=True, on_delete=models.PROTECT, related_name="active_for")
    reconciliation_required = models.BooleanField(default=False, help_text="A path changed while a write was in flight: no write until reconciled.")
    reconciliation_reason = models.CharField(max_length=200, blank=True, default="")
    failback_not_before = models.DateTimeField(null=True, blank=True, help_text="Hold-down: no failback before this time.")
    last_transition_at = models.DateTimeField(null=True, blank=True)
    last_evaluated_at = models.DateTimeField(null=True, blank=True)
    version = models.PositiveIntegerField(default=1)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        default_permissions = ()
        constraints = [
            models.CheckConstraint(condition=~Q(status="ACTIVE") | Q(active_path__isnull=False), name="active_management_state_names_path"),
            models.CheckConstraint(condition=~Q(status="NO_PATH") | Q(active_path__isnull=True), name="no_path_state_has_no_active_path"),
        ]

    def save(self, *args, **kwargs):
        if self.status not in ManagementStatus.values:
            raise ValueError("Invalid DeviceManagementState.status.")
        if not self.__dict__.pop("_selector_write", False):
            raise ValueError("DeviceManagementState changes only through core.services.management.selector.")
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("DeviceManagementState is history and cannot be deleted.")


class BootstrapCredentialState(models.TextChoices):
    PLANNED = "PLANNED", "Planned (awaiting approval)"
    APPROVED = "APPROVED", "Approved (not started)"
    REPLACEMENT_INSTALLED = "REPLACEMENT_INSTALLED", "Replacement installed (not yet verified)"
    REPLACEMENT_VERIFIED = "REPLACEMENT_VERIFIED", "Replacement verified over an independent session"
    REVOCATION_PENDING = "REVOCATION_PENDING", "Bootstrap access revoked on the device (awaiting proof)"
    RETIREMENT_PENDING = "RETIREMENT_PENDING", "Revoked and proven; bootstrap secret retirement outstanding"
    COMPLETE = "COMPLETE", "Bootstrap access revoked, proven rejected and secret retired"
    FAILED = "FAILED", "Failed safely (bootstrap access intact)"
    UNCERTAIN = "UNCERTAIN", "Outcome uncertain (reconcile before anything else)"
    CANCELLED = "CANCELLED", "Cancelled before execution"


BOOTSTRAP_CREDENTIAL_OPEN = frozenset({"PLANNED", "APPROVED", "REPLACEMENT_INSTALLED", "REPLACEMENT_VERIFIED", "REVOCATION_PENDING",
                                       "RETIREMENT_PENDING", "UNCERTAIN"})


class BootstrapCredentialTransition(models.Model):
    """One governed replacement of a device's bootstrap (ZTP enrollment) credential by its operational service credential and
    the retirement of the bootstrap credential (``BCRED-000001``).  References and public fingerprints only."""

    _IMMUTABLE = ("device_id", "ztp_session_id", "bootstrap_username", "bootstrap_key_reference", "bootstrap_key_fingerprint",
                  "replacement_credential_id", "replacement_username", "replacement_key_fingerprint", "path_id", "requested_by",
                  "binding_digest")

    device = models.ForeignKey(ManagedDevice, on_delete=models.PROTECT, related_name="bootstrap_credential_transitions", editable=False)
    ztp_session = models.ForeignKey("ZtpSession", on_delete=models.PROTECT, related_name="credential_transitions", editable=False)
    bootstrap_username = models.CharField(max_length=64, editable=False)
    bootstrap_key_reference = models.CharField(max_length=128, editable=False, help_text="Opaque runtime:// reference; never the key.")
    bootstrap_key_fingerprint = models.CharField(max_length=51, editable=False)
    replacement_credential = models.ForeignKey("DeviceCredential", on_delete=models.PROTECT, related_name="bootstrap_transitions", editable=False)
    replacement_username = models.CharField(max_length=64, editable=False)
    replacement_key_fingerprint = models.CharField(max_length=51, editable=False)
    path = models.ForeignKey(ManagementPath, null=True, blank=True, on_delete=models.PROTECT, related_name="credential_transitions", editable=False)
    state = models.CharField(max_length=24, choices=BootstrapCredentialState.choices, default=BootstrapCredentialState.PLANNED)
    binding_digest = models.CharField(max_length=64, editable=False)
    steps = models.JSONField(default=list, blank=True, help_text="[{step, ok, code, at, facts}] -- bounded, secret-free.")
    failure = models.JSONField(default=dict, blank=True)
    requested_by = models.CharField(max_length=150, editable=False)
    approved_by = models.CharField(max_length=150, blank=True, default="")
    approved_at = models.DateTimeField(null=True, blank=True)
    executed_by = models.CharField(max_length=150, blank=True, default="")
    reason = models.CharField(max_length=200, blank=True, default="")
    version = models.PositiveIntegerField(default=1)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at", "-id"]
        default_permissions = ()
        constraints = [
            models.UniqueConstraint(fields=["device"], condition=Q(state__in=tuple(sorted(BOOTSTRAP_CREDENTIAL_OPEN))),
                                    name="unique_open_bootstrap_credential_transition"),
            models.CheckConstraint(condition=Q(approved_by="") | ~Q(approved_by=F("requested_by")),
                                   name="bootstrap_credential_approver_differs"),
            models.CheckConstraint(condition=~Q(state__in=("APPROVED", "REPLACEMENT_INSTALLED", "REPLACEMENT_VERIFIED", "REVOCATION_PENDING",
                                                           "RETIREMENT_PENDING", "COMPLETE")) | ~Q(approved_by=""),
                                   name="executed_bootstrap_credential_transition_is_approved"),
        ]

    def __str__(self):
        return f"{self.transition_id}: {self.device.name} ({self.state})"

    @property
    def transition_id(self) -> str:
        return f"BCRED-{self.pk:06d}" if self.pk else "BCRED-NEW"

    @property
    def is_open(self) -> bool:
        return self.state in BOOTSTRAP_CREDENTIAL_OPEN

    def save(self, *args, **kwargs):
        if self.state not in BootstrapCredentialState.values or not _HEX64.fullmatch(self.binding_digest or ""):
            raise ValueError("Invalid BootstrapCredentialTransition.")
        for name in ("bootstrap_key_fingerprint", "replacement_key_fingerprint"):
            if not HOST_KEY_RE.fullmatch(getattr(self, name) or ""):
                raise ValueError(f"BootstrapCredentialTransition.{name} must be an OpenSSH SHA256 fingerprint.")
        if self.bootstrap_username == self.replacement_username:
            raise ValueError("The replacement credential must be a different account from the bootstrap account.")
        if self.pk:
            persisted = type(self).objects.filter(pk=self.pk).values("state", *self._IMMUTABLE).first()
            if persisted is not None:
                if persisted["state"] not in BOOTSTRAP_CREDENTIAL_OPEN:
                    raise ValueError("A closed bootstrap credential transition is immutable history.")
                for name in self._IMMUTABLE:
                    if persisted[name] != getattr(self, name):
                        raise ValueError(f"BootstrapCredentialTransition.{name.removesuffix('_id')} is immutable after creation.")
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("BootstrapCredentialTransition records are history and cannot be deleted.")


# =============================================================================
# V2 Phases 5 + 6 -- TRUSTED UPSTREAM ISOLATION, GOVERNED COMMISSIONING AND PRODUCTION ADMISSION
# (core.services.isolation, core.services.commissioning)
#
#   IsolationPolicy        ISO-000001: the enforcement NMAS keeps on a TRUSTED UPSTREAM's port while an untrusted device sits behind
#                          it.  Bound to one approved attachment; its configuration reaches the upstream only through a governed
#                          Change (validation, plan, precheck, approval by a second operator, execution with exact compensation).
#   IsolationCheck         append-only verification evidence of one policy (read-back, routing, management plane, attachment,
#                          traffic, drift, release).
#   CommissioningDependency  "device X may only be admitted after device Y" (generic; derived from attachments or declared).
#   CommissioningRecord    COM-000001: one commissioning of one ISOLATED device -- readiness, the evidence-bound approval of its
#                          production configuration (a ProvisioningRun / ordinary Change), and the link to its admission.
#   ProductionAdmission    ADM-000001: the controlled release of isolation that admits the device to production, verified by
#                          routing and traffic evidence, restored on failure; UNCERTAIN when restoration cannot be proven.
#   LifecycleOutboxEvent   durable, idempotent hand-off records (NSOT / topology / monitoring) for the consumers of Phase 8.
#
# Nothing here stores a credential, private key or token.
# =============================================================================


class IsolationState(models.TextChoices):
    REQUIRED = "REQUIRED", "Required (nothing planned)"
    PLANNED = "PLANNED", "Planned (governed Change awaiting precheck / approval)"
    APPLYING = "APPLYING", "Applying on the trusted upstream"
    ENFORCED = "ENFORCED", "Enforced and read back (traffic not yet verified)"
    VERIFIED = "VERIFIED", "Enforced and verified (read-back, routing, management plane, traffic)"
    DRIFTED = "DRIFTED", "Drifted: the upstream no longer holds the enforced policy"
    UNCERTAIN = "UNCERTAIN", "Uncertain: enforcement or restoration could not be proven"
    BLOCKED = "BLOCKED", "Blocked: the upstream cannot enforce this policy"
    RELEASE_PENDING = "RELEASE_PENDING", "Release pending (production admission in progress)"
    RELEASED = "RELEASED", "Released (production admission verified)"


ISOLATION_TERMINAL = frozenset({IsolationState.RELEASED})
# states in which the upstream may hold (part of) the policy: the port is never handed to another policy meanwhile
ISOLATION_ON_DEVICE = frozenset({IsolationState.APPLYING, IsolationState.ENFORCED, IsolationState.VERIFIED, IsolationState.DRIFTED,
                                 IsolationState.UNCERTAIN, IsolationState.RELEASE_PENDING})


class IsolationPolicy(models.Model):
    """One trusted-upstream isolation policy (``ISO-000001``).  Written only by ``core.services.isolation.service``."""

    _IMMUTABLE = ("device_id", "attachment_id", "network_id", "upstream_device", "upstream_interface", "upstream_platform", "requested_by")

    device = models.ForeignKey(ManagedDevice, on_delete=models.PROTECT, related_name="isolation_policies", editable=False)
    attachment = models.ForeignKey(DeviceAttachment, on_delete=models.PROTECT, related_name="isolation_policies", editable=False)
    network = models.ForeignKey("BootstrapNetwork", null=True, blank=True, on_delete=models.PROTECT, related_name="isolation_policies",
                                editable=False)
    upstream_device = models.CharField(max_length=64, validators=[DEVICE_NAME_VALIDATOR], editable=False)
    upstream_interface = models.CharField(max_length=64, editable=False)
    upstream_platform = models.CharField(max_length=32, choices=Platform.choices, editable=False)
    state = models.CharField(max_length=16, choices=IsolationState.choices, default=IsolationState.REQUIRED)
    intent = models.JSONField(default=dict, blank=True, help_text="The policy elements (L2, routed IPv4 / IPv6, control plane, management plane).")
    intent_hash = models.CharField(max_length=64, blank=True, default="")
    plan = models.JSONField(default=dict, blank=True, help_text="Rendered operations: lines, exact inverse, presence paths.")
    plan_hash = models.CharField(max_length=64, blank=True, default="")
    preflight = models.JSONField(default=dict, blank=True, help_text="What the upstream held when the policy was planned (bounded facts).")
    basis_digest = models.CharField(max_length=64, blank=True, default="", help_text="Upstream configuration digest the plan was built on.")
    enforced_digest = models.CharField(max_length=64, blank=True, default="", help_text="Upstream configuration digest right after enforcement.")
    apply_change = models.ForeignKey("Change", null=True, blank=True, on_delete=models.PROTECT, related_name="+")
    release_change = models.ForeignKey("Change", null=True, blank=True, on_delete=models.PROTECT, related_name="+")
    verification = models.JSONField(default=dict, blank=True, help_text="Summary of the latest verification.")
    drift = models.JSONField(default=dict, blank=True)
    failure = models.JSONField(default=dict, blank=True)
    requested_by = models.CharField(max_length=150, editable=False)
    approved_by = models.CharField(max_length=150, blank=True, default="")
    approved_at = models.DateTimeField(null=True, blank=True)
    enforced_at = models.DateTimeField(null=True, blank=True)
    verified_at = models.DateTimeField(null=True, blank=True)
    released_at = models.DateTimeField(null=True, blank=True)
    version = models.PositiveIntegerField(default=1)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at", "-id"]
        default_permissions = ()
        constraints = [
            models.UniqueConstraint(fields=["attachment"], condition=~Q(state="RELEASED"), name="unique_live_isolation_per_attachment"),
            models.UniqueConstraint(fields=["upstream_device", "upstream_interface"], condition=~Q(state="RELEASED"),
                                    name="unique_live_isolation_per_upstream_port"),
            models.CheckConstraint(condition=Q(approved_by="") | ~Q(approved_by=F("requested_by")), name="isolation_approver_differs"),
        ]

    def __str__(self):
        return f"{self.policy_id}: {self.device.name} behind {self.upstream_device}:{self.upstream_interface} ({self.state})"

    @property
    def policy_id(self) -> str:
        return f"ISO-{self.pk:06d}" if self.pk else "ISO-NEW"

    @property
    def is_terminal(self) -> bool:
        return self.state in ISOLATION_TERMINAL

    def save(self, *args, **kwargs):
        if self.state not in IsolationState.values or self.upstream_platform not in Platform.values:
            raise ValueError("Invalid IsolationPolicy state or platform.")
        if not INTERFACE_RE.fullmatch(self.upstream_interface or ""):
            raise ValueError("IsolationPolicy.upstream_interface is malformed.")
        for name in ("intent_hash", "plan_hash", "basis_digest", "enforced_digest"):
            if getattr(self, name) and not _HEX64.fullmatch(getattr(self, name)):
                raise ValueError(f"IsolationPolicy.{name} must be a SHA-256 digest.")
        if not self.__dict__.pop("_isolation_write", False):
            raise ValueError("IsolationPolicy records change only through core.services.isolation.")
        if self.pk:
            persisted = type(self).objects.filter(pk=self.pk).values("state", *self._IMMUTABLE).first()
            if persisted is not None:
                if persisted["state"] in ISOLATION_TERMINAL:
                    raise ValueError("A released IsolationPolicy is immutable history.")
                for name in self._IMMUTABLE:
                    if persisted[name] != getattr(self, name):
                        raise ValueError(f"IsolationPolicy.{name.removesuffix('_id')} is immutable after creation.")
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("IsolationPolicy records are history and cannot be deleted.")


class IsolationCheckKind(models.TextChoices):
    READ_BACK = "READ_BACK", "Configuration read back from the upstream"
    L2 = "L2", "Layer-2 attachment (routed port, no subinterfaces)"
    ROUTING = "ROUTING", "Routing suppression (no adjacency, no leaked route)"
    MANAGEMENT_PLANE = "MANAGEMENT_PLANE", "Upstream management plane closed to the bootstrap prefix"
    ATTACHMENT = "ATTACHMENT", "Device observed on the enforced port"
    TRAFFIC = "TRAFFIC", "Permitted / denied flows at the enforcement point"
    DRIFT = "DRIFT", "Drift check"
    RELEASE = "RELEASE", "Release verification"


class IsolationCheck(models.Model):
    """One verification result of one policy.  Append-only; the verification history is these rows."""

    policy = models.ForeignKey(IsolationPolicy, on_delete=models.PROTECT, related_name="checks", editable=False)
    kind = models.CharField(max_length=20, choices=IsolationCheckKind.choices, editable=False)
    ok = models.BooleanField(editable=False)
    code = models.CharField(max_length=48, blank=True, default="", editable=False)
    with_device = models.BooleanField(default=False, editable=False, help_text="Ran while the device sat on the port.")
    facts = models.JSONField(default=dict, blank=True, editable=False, help_text="Bounded, secret-free facts.")
    recorded_by = models.CharField(max_length=150, editable=False)
    correlation_id = models.CharField(max_length=36, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)

    objects = _ImmutableManager()

    class Meta:
        ordering = ["policy", "id"]
        default_permissions = ()
        indexes = [models.Index(fields=["policy", "kind"])]

    def save(self, *args, **kwargs):
        if self.kind not in IsolationCheckKind.values:
            raise ValueError("Invalid IsolationCheck.kind.")
        _forbid_row_mutation(self)
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("IsolationCheck records are evidence and cannot be deleted.")


class DependencyKind(models.TextChoices):
    ATTACHMENT_UPSTREAM = "ATTACHMENT_UPSTREAM", "The device's authorized attachment rides on the upstream"
    ROUTING = "ROUTING", "The device's production routing depends on the upstream"
    DECLARED = "DECLARED", "Declared by an operator"


class DependencyState(models.TextChoices):
    ACTIVE = "ACTIVE", "Active"
    REMOVED = "REMOVED", "Removed"


class CommissioningDependency(models.Model):
    """``device`` may be admitted to production only after ``upstream`` is IN_SERVICE and ADMITTED (or a legacy in-service device)."""

    device = models.ForeignKey(ManagedDevice, on_delete=models.PROTECT, related_name="commissioning_dependencies", editable=False)
    upstream = models.ForeignKey(ManagedDevice, on_delete=models.PROTECT, related_name="commissioning_dependents", editable=False)
    kind = models.CharField(max_length=24, choices=DependencyKind.choices, editable=False)
    state = models.CharField(max_length=8, choices=DependencyState.choices, default=DependencyState.ACTIVE)
    reason = models.CharField(max_length=200, blank=True, default="")
    created_by = models.CharField(max_length=150, editable=False)
    removed_by = models.CharField(max_length=150, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    removed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["device", "id"]
        default_permissions = ()
        constraints = [
            models.UniqueConstraint(fields=["device", "upstream"], condition=Q(state="ACTIVE"), name="unique_active_commissioning_dependency"),
            models.CheckConstraint(condition=~Q(device=F("upstream")), name="commissioning_dependency_not_self"),
        ]

    def save(self, *args, **kwargs):
        if self.kind not in DependencyKind.values or self.state not in DependencyState.values:
            raise ValueError("Invalid CommissioningDependency.")
        if self.pk:
            persisted = type(self).objects.filter(pk=self.pk).values("state", "device_id", "upstream_id", "kind").first()
            if persisted is not None:
                if persisted["state"] == DependencyState.REMOVED:
                    raise ValueError("A removed CommissioningDependency is history.")
                if (persisted["device_id"], persisted["upstream_id"], persisted["kind"]) != (self.device_id, self.upstream_id, self.kind):
                    raise ValueError("CommissioningDependency endpoints are immutable.")
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("CommissioningDependency records are history: remove the dependency instead.")


class CommissioningState(models.TextChoices):
    OPEN = "OPEN", "Open (readiness not yet established)"
    READY = "READY", "Ready (evidence bound; awaiting approval)"
    APPROVED = "APPROVED", "Approved (production configuration may be applied)"
    CONFIGURING = "CONFIGURING", "Production configuration being applied"
    CONFIGURED = "CONFIGURED", "Production configuration applied and postchecked (still isolated)"
    ADMITTING = "ADMITTING", "Production admission in progress"
    ADMITTED = "ADMITTED", "Admitted to production"
    ABORTED = "ABORTED", "Aborted (device remains isolated)"
    FAILED = "FAILED", "Failed"
    UNCERTAIN = "UNCERTAIN", "Uncertain (reconcile before anything else)"


COMMISSIONING_OPEN = frozenset({"OPEN", "READY", "APPROVED", "CONFIGURING", "CONFIGURED", "ADMITTING", "UNCERTAIN"})


class CommissioningRecord(models.Model):
    """One commissioning of one ISOLATED device (``COM-000001``).  Written only by ``core.services.commissioning``."""

    _IMMUTABLE = ("device_id", "isolation_policy_id", "requested_by")

    device = models.ForeignKey(ManagedDevice, on_delete=models.PROTECT, related_name="commissioning_records", editable=False)
    isolation_policy = models.ForeignKey(IsolationPolicy, on_delete=models.PROTECT, related_name="commissioning_records", editable=False)
    provisioning_run = models.OneToOneField("ProvisioningRun", null=True, blank=True, on_delete=models.PROTECT, related_name="commissioning_record")
    state = models.CharField(max_length=16, choices=CommissioningState.choices, default=CommissioningState.OPEN)
    readiness = models.JSONField(default=dict, blank=True, help_text="The latest readiness report: every check with its code.")
    evidence = models.JSONField(default=dict, blank=True, help_text="The evidence the approval is bound to (ids and digests only).")
    evidence_digest = models.CharField(max_length=64, blank=True, default="")
    requested_by = models.CharField(max_length=150, editable=False)
    approved_by = models.CharField(max_length=150, blank=True, default="")
    approved_at = models.DateTimeField(null=True, blank=True)
    failure = models.JSONField(default=dict, blank=True)
    version = models.PositiveIntegerField(default=1)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    closed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at", "-id"]
        default_permissions = ()
        constraints = [
            models.UniqueConstraint(fields=["device"], condition=Q(state__in=tuple(sorted(COMMISSIONING_OPEN))),
                                    name="unique_open_commissioning_per_device"),
            models.CheckConstraint(condition=Q(approved_by="") | ~Q(approved_by=F("requested_by")), name="commissioning_approver_differs"),
            models.CheckConstraint(condition=~Q(state__in=("APPROVED", "CONFIGURING", "CONFIGURED", "ADMITTING", "ADMITTED")) | ~Q(approved_by=""),
                                   name="approved_commissioning_names_approver"),
        ]

    def __str__(self):
        return f"{self.commissioning_id}: {self.device.name} ({self.state})"

    @property
    def commissioning_id(self) -> str:
        return f"COM-{self.pk:06d}" if self.pk else "COM-NEW"

    @property
    def is_open(self) -> bool:
        return self.state in COMMISSIONING_OPEN

    def save(self, *args, **kwargs):
        if self.state not in CommissioningState.values:
            raise ValueError("Invalid CommissioningRecord.state.")
        if self.evidence_digest and not _HEX64.fullmatch(self.evidence_digest):
            raise ValueError("CommissioningRecord.evidence_digest must be a SHA-256 digest.")
        if not self.__dict__.pop("_commissioning_write", False):
            raise ValueError("CommissioningRecord records change only through core.services.commissioning.")
        if self.pk:
            persisted = type(self).objects.filter(pk=self.pk).values("state", *self._IMMUTABLE).first()
            if persisted is not None:
                if persisted["state"] not in COMMISSIONING_OPEN:
                    raise ValueError("A closed CommissioningRecord is immutable history.")
                for name in self._IMMUTABLE:
                    if persisted[name] != getattr(self, name):
                        raise ValueError(f"CommissioningRecord.{name.removesuffix('_id')} is immutable after creation.")
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("CommissioningRecord records are history and cannot be deleted.")


class AdmissionState(models.TextChoices):
    PLANNED = "PLANNED", "Planned (awaiting approval)"
    APPROVED = "APPROVED", "Approved"
    RELEASING = "RELEASING", "Releasing isolation"
    ADMITTED = "ADMITTED", "Admitted (release verified)"
    RESTORED = "RESTORED", "Admission failed; isolation restored and verified"
    FAILED = "FAILED", "Failed before any change"
    UNCERTAIN = "UNCERTAIN", "Uncertain: isolation restoration could not be proven"
    CANCELLED = "CANCELLED", "Cancelled"


ADMISSION_OPEN = frozenset({"PLANNED", "APPROVED", "RELEASING", "UNCERTAIN"})


class ProductionAdmission(models.Model):
    """One controlled release of a device's isolation into production (``ADM-000001``)."""

    _IMMUTABLE = ("commissioning_id", "device_id", "isolation_policy_id", "requested_by", "evidence_digest")

    commissioning = models.ForeignKey(CommissioningRecord, on_delete=models.PROTECT, related_name="admissions", editable=False)
    device = models.ForeignKey(ManagedDevice, on_delete=models.PROTECT, related_name="production_admissions", editable=False)
    isolation_policy = models.ForeignKey(IsolationPolicy, on_delete=models.PROTECT, related_name="admissions", editable=False)
    release_change = models.ForeignKey("Change", null=True, blank=True, on_delete=models.PROTECT, related_name="+")
    state = models.CharField(max_length=12, choices=AdmissionState.choices, default=AdmissionState.PLANNED)
    evidence_digest = models.CharField(max_length=64, editable=False)
    expectations = models.JSONField(default=dict, blank=True, help_text="What must hold after release: adjacencies, routes, flows.")
    verification = models.JSONField(default=dict, blank=True)
    restoration = models.JSONField(default=dict, blank=True)
    failure = models.JSONField(default=dict, blank=True)
    requested_by = models.CharField(max_length=150, editable=False)
    approved_by = models.CharField(max_length=150, blank=True, default="")
    approved_at = models.DateTimeField(null=True, blank=True)
    executed_by = models.CharField(max_length=150, blank=True, default="")
    version = models.PositiveIntegerField(default=1)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at", "-id"]
        default_permissions = ()
        constraints = [
            models.UniqueConstraint(fields=["device"], condition=Q(state__in=tuple(sorted(ADMISSION_OPEN))), name="unique_open_admission_per_device"),
            models.CheckConstraint(condition=Q(approved_by="") | ~Q(approved_by=F("requested_by")), name="admission_approver_differs"),
            models.CheckConstraint(condition=~Q(state__in=("APPROVED", "RELEASING", "ADMITTED")) | ~Q(approved_by=""),
                                   name="executed_admission_is_approved"),
        ]

    def __str__(self):
        return f"{self.admission_id}: {self.device.name} ({self.state})"

    @property
    def admission_id(self) -> str:
        return f"ADM-{self.pk:06d}" if self.pk else "ADM-NEW"

    @property
    def is_open(self) -> bool:
        return self.state in ADMISSION_OPEN

    def save(self, *args, **kwargs):
        if self.state not in AdmissionState.values or not _HEX64.fullmatch(self.evidence_digest or ""):
            raise ValueError("Invalid ProductionAdmission.")
        if not self.__dict__.pop("_admission_write", False):
            raise ValueError("ProductionAdmission records change only through core.services.commissioning.")
        if self.pk:
            persisted = type(self).objects.filter(pk=self.pk).values("state", *self._IMMUTABLE).first()
            if persisted is not None:
                if persisted["state"] not in ADMISSION_OPEN:
                    raise ValueError("A finished ProductionAdmission is immutable history.")
                for name in self._IMMUTABLE:
                    if persisted[name] != getattr(self, name):
                        raise ValueError(f"ProductionAdmission.{name.removesuffix('_id')} is immutable after creation.")
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("ProductionAdmission records are history and cannot be deleted.")


class OutboxTopic(models.TextChoices):
    NSOT_DEVICE_ADMITTED = "NSOT_DEVICE_ADMITTED", "NetBox: device admitted (status / interfaces / addresses)"
    TOPOLOGY_DEVICE_ADMITTED = "TOPOLOGY_DEVICE_ADMITTED", "Topology graph: device and its production links"
    MONITORING_TARGET_ADMITTED = "MONITORING_TARGET_ADMITTED", "Monitoring: new target (telemetry, syslog, health)"
    # V2 Phase 8: one lifecycle fact (discovered, verified, isolated, commissioned, maintenance, decommissioned, restored,
    # attachment / management-path change, ...) per consumer; consumers apply it in per-device ``sequence`` order
    NSOT_DEVICE_STATE = "NSOT_DEVICE_STATE", "NetBox: device lifecycle fact"
    TOPOLOGY_DEVICE_STATE = "TOPOLOGY_DEVICE_STATE", "Topology graph: device lifecycle fact"
    MONITORING_TARGET_STATE = "MONITORING_TARGET_STATE", "Monitoring: target lifecycle / management-path fact"


class OutboxState(models.TextChoices):
    PENDING = "PENDING", "Pending delivery"
    DELIVERED = "DELIVERED", "Delivered and acknowledged by the consumer"
    FAILED = "FAILED", "Delivery failed (retryable)"


class LifecycleOutboxEvent(models.Model):
    """One durable hand-off to a downstream consumer.  Written in the transaction that made the fact true; delivered at least once,
    applied at most once by the consumer (``idempotency_key``).  The payload is a versioned contract, secret-free."""

    device = models.ForeignKey(ManagedDevice, on_delete=models.PROTECT, related_name="outbox_events", editable=False)
    topic = models.CharField(max_length=32, choices=OutboxTopic.choices, editable=False)
    sequence = models.PositiveBigIntegerField(default=0, editable=False, help_text="Per-device fact order (0 = an admission hand-off).")
    contract_version = models.PositiveSmallIntegerField(default=1, editable=False)
    idempotency_key = models.CharField(max_length=64, unique=True, editable=False)
    payload = models.JSONField(default=dict, editable=False)
    payload_digest = models.CharField(max_length=64, editable=False)
    state = models.CharField(max_length=12, choices=OutboxState.choices, default=OutboxState.PENDING)
    attempts = models.PositiveIntegerField(default=0)
    last_error = models.CharField(max_length=64, blank=True, default="")
    consumer = models.CharField(max_length=64, blank=True, default="")
    next_attempt_at = models.DateTimeField(null=True, blank=True, help_text="Earliest retry of a FAILED delivery (backoff).")
    created_at = models.DateTimeField(auto_now_add=True)
    delivered_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["created_at", "id"]
        default_permissions = ()
        indexes = [models.Index(fields=["topic", "state"])]

    def save(self, *args, **kwargs):
        if self.topic not in OutboxTopic.values or self.state not in OutboxState.values or not _HEX64.fullmatch(self.payload_digest or ""):
            raise ValueError("Invalid LifecycleOutboxEvent.")
        if self.pk:
            persisted = type(self).objects.filter(pk=self.pk).values("state", "payload", "payload_digest", "idempotency_key", "topic").first()
            if persisted is not None:
                if persisted["state"] == OutboxState.DELIVERED:
                    raise ValueError("A delivered outbox event is history.")
                if (persisted["payload"], persisted["payload_digest"], persisted["idempotency_key"], persisted["topic"]) != (
                        self.payload, self.payload_digest, self.idempotency_key, self.topic):
                    raise ValueError("An outbox event's payload and key are immutable.")
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("LifecycleOutboxEvent records are history and cannot be deleted.")


# ================================================================================================================================
# V2 Phases 7 + 8: governed decommissioning / restoration, and the infrastructure projections (NetBox, topology, monitoring)
# ================================================================================================================================
class DeviceConfigSnapshot(models.Model):
    """One immutable, sanitized running configuration of a managed device, captured through NMAS's own device session.

    ``sha256`` is over ``text`` exactly; restoration re-verifies it before it relies on the snapshot.  Secret material is
    removed by the capture (``bundles.legacy_sanitize``) -- a snapshot is evidence and a restore basis, never a credential store."""

    class Purpose(models.TextChoices):
        DECOMMISSION_BASELINE = "DECOMMISSION_BASELINE", "Before decommissioning"
        DECOMMISSION_RESULT = "DECOMMISSION_RESULT", "After decommissioning"
        RESTORE_RESULT = "RESTORE_RESULT", "After restoration"

    device = models.ForeignKey(ManagedDevice, on_delete=models.PROTECT, related_name="config_snapshots", editable=False)
    purpose = models.CharField(max_length=24, choices=Purpose.choices, editable=False)
    platform = models.CharField(max_length=32, choices=Platform.choices, editable=False)
    text = models.TextField(editable=False)
    sha256 = models.CharField(max_length=64, editable=False)
    state_digest = models.CharField(max_length=64, blank=True, default="", editable=False,
                                    help_text="The executor's configuration-state digest at capture (what compensation compares).")
    captured_by = models.CharField(max_length=150, editable=False)
    source = models.CharField(max_length=64, editable=False, help_text="How it was read (executor / transport), never a credential.")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at", "-id"]
        default_permissions = ()

    @property
    def snapshot_id(self) -> str:
        return f"SNP-{self.pk:06d}" if self.pk else "SNP-NEW"

    def save(self, *args, **kwargs):
        import hashlib

        if self.pk:
            raise ValueError("DeviceConfigSnapshot rows are immutable evidence.")
        if self.purpose not in self.Purpose.values or self.platform not in Platform.values:
            raise ValueError("Invalid DeviceConfigSnapshot.")
        if self.sha256 != hashlib.sha256((self.text or "").encode()).hexdigest():
            raise ValueError("DeviceConfigSnapshot.sha256 does not match its text.")
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("DeviceConfigSnapshot rows are immutable evidence.")


class DecommissionState(models.TextChoices):
    REQUESTED = "REQUESTED", "Requested"
    READINESS_CHECKING = "READINESS_CHECKING", "Readiness being evaluated"
    BLOCKED = "BLOCKED", "Blocked (readiness / dependency / traffic)"
    READY = "READY", "Ready (traffic can transition, or the device is quiescent)"
    APPROVED = "APPROVED", "Approved (exact plan and readiness)"
    TRAFFIC_TRANSITION = "TRAFFIC_TRANSITION", "Traffic transition under measurement"
    DECOMMISSIONING = "DECOMMISSIONING", "Removal executing"
    DECOMMISSIONED = "DECOMMISSIONED", "Decommissioned (postchecked, retired)"
    ROLLED_BACK = "ROLLED_BACK", "Failed and restored to the baseline"
    UNCERTAIN = "UNCERTAIN", "Uncertain: the device state could not be proven (reconcile before any retry)"
    CANCELLED = "CANCELLED", "Cancelled"


DECOMMISSION_OPEN = frozenset({DecommissionState.REQUESTED, DecommissionState.READINESS_CHECKING, DecommissionState.BLOCKED,
                               DecommissionState.READY, DecommissionState.APPROVED, DecommissionState.TRAFFIC_TRANSITION,
                               DecommissionState.DECOMMISSIONING, DecommissionState.UNCERTAIN})


class DecommissionReadiness(models.TextChoices):
    UNKNOWN = "UNKNOWN", "Not evaluated"
    REDUNDANT_TRANSITION = "REDUNDANT_TRANSITION", "Active production traffic; a verified existing alternate carries it"
    QUIESCENT = "QUIESCENT", "No production traffic observed (no transition needed)"
    BLOCKED = "BLOCKED", "Blocked"


class DecommissionRecord(models.Model):
    """One governed decommissioning of one managed device: readiness evidence, the exact removal plan (a governed Change), the
    approval bound to both, the traffic measurement through the transition and the outcome.  ``version`` is a compare-and-swap."""

    device = models.ForeignKey(ManagedDevice, on_delete=models.PROTECT, related_name="decommissions", editable=False)
    state = models.CharField(max_length=20, choices=DecommissionState.choices, default=DecommissionState.REQUESTED)
    reason = models.CharField(max_length=300, editable=False)
    readiness_mode = models.CharField(max_length=24, choices=DecommissionReadiness.choices, default=DecommissionReadiness.UNKNOWN)
    readiness = models.JSONField(default=dict, blank=True, help_text="Flows, windows, counters, alternates, blind spots, verdict.")
    readiness_digest = models.CharField(max_length=64, blank=True, default="")
    dependencies = models.JSONField(default=dict, blank=True, help_text="Downstream / routing / management / monitoring dependencies.")
    blockers = models.JSONField(default=list, blank=True)
    baseline = models.ForeignKey(DeviceConfigSnapshot, null=True, blank=True, on_delete=models.PROTECT, related_name="+")
    result_snapshot = models.ForeignKey(DeviceConfigSnapshot, null=True, blank=True, on_delete=models.PROTECT, related_name="+")
    plan = models.JSONField(default=dict, blank=True, help_text="Operations (each with its exact inverse), transition and removal stages.")
    plan_hash = models.CharField(max_length=64, blank=True, default="")
    change = models.ForeignKey("Change", null=True, blank=True, on_delete=models.PROTECT, related_name="+")
    transition = models.JSONField(default=dict, blank=True, help_text="Traffic measured before / during / after the transition.")
    outcome = models.JSONField(default=dict, blank=True)
    requested_by = models.CharField(max_length=150, editable=False)
    approved_by = models.CharField(max_length=150, blank=True, default="")
    approved_at = models.DateTimeField(null=True, blank=True)
    approval_expires_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    version = models.PositiveIntegerField(default=1)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at", "-id"]
        default_permissions = ()
        constraints = [
            models.UniqueConstraint(fields=["device"], condition=Q(state__in=("REQUESTED", "READINESS_CHECKING", "BLOCKED", "READY", "APPROVED",
                                                                               "TRAFFIC_TRANSITION", "DECOMMISSIONING", "UNCERTAIN")),
                                    name="unique_open_decommission_per_device"),
            models.CheckConstraint(condition=~Q(state="APPROVED") | ~Q(approved_by=""), name="approved_decommission_names_approver"),
        ]

    @property
    def record_id(self) -> str:
        return f"DCM-{self.pk:06d}" if self.pk else "DCM-NEW"

    @property
    def is_open(self) -> bool:
        return self.state in DECOMMISSION_OPEN

    def save(self, *args, **kwargs):
        if self.state not in DecommissionState.values or self.readiness_mode not in DecommissionReadiness.values:
            raise ValueError("Invalid DecommissionRecord.")
        if self.pk:
            persisted = type(self).objects.filter(pk=self.pk).values("state").first()
            if persisted is not None and persisted["state"] in (DecommissionState.DECOMMISSIONED, DecommissionState.CANCELLED,
                                                                DecommissionState.ROLLED_BACK) and persisted["state"] != self.state:
                raise ValueError("A closed decommission record is history.")
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("DecommissionRecord rows are history and cannot be deleted.")


class RestorationState(models.TextChoices):
    REQUESTED = "REQUESTED", "Requested"
    BLOCKED = "BLOCKED", "Blocked (integrity / platform / conflict / identity)"
    REENROLLMENT_REQUIRED = "REENROLLMENT_REQUIRED", "Identity cannot be re-verified: re-enroll through ZTP, isolation and commissioning"
    PLANNED = "PLANNED", "Planned (governed Change awaiting precheck / approval)"
    APPROVED = "APPROVED", "Approved"
    RESTORING = "RESTORING", "Restoring"
    RESTORED = "RESTORED", "Restored, postchecked and readmitted"
    ROLLED_BACK = "ROLLED_BACK", "Failed and returned to the decommissioned state"
    UNCERTAIN = "UNCERTAIN", "Uncertain: reconcile before any retry"
    CANCELLED = "CANCELLED", "Cancelled"


RESTORATION_OPEN = frozenset({RestorationState.REQUESTED, RestorationState.BLOCKED, RestorationState.PLANNED, RestorationState.APPROVED,
                              RestorationState.RESTORING, RestorationState.UNCERTAIN})


class RestorationRecord(models.Model):
    """One governed restoration of a decommissioned device from a verified historical snapshot."""

    decommission = models.ForeignKey(DecommissionRecord, on_delete=models.PROTECT, related_name="restorations", editable=False)
    device = models.ForeignKey(ManagedDevice, on_delete=models.PROTECT, related_name="restorations", editable=False)
    successor = models.ForeignKey(ManagedDevice, null=True, blank=True, on_delete=models.PROTECT, related_name="+")
    snapshot = models.ForeignKey(DeviceConfigSnapshot, on_delete=models.PROTECT, related_name="+", editable=False)
    result_snapshot = models.ForeignKey(DeviceConfigSnapshot, null=True, blank=True, on_delete=models.PROTECT, related_name="+")
    state = models.CharField(max_length=24, choices=RestorationState.choices, default=RestorationState.REQUESTED)
    checks = models.JSONField(default=dict, blank=True, help_text="Integrity, platform, conflicts, attachment, credentials, identity, isolation.")
    blockers = models.JSONField(default=list, blank=True)
    plan = models.JSONField(default=dict, blank=True)
    plan_hash = models.CharField(max_length=64, blank=True, default="")
    change = models.ForeignKey("Change", null=True, blank=True, on_delete=models.PROTECT, related_name="+")
    outcome = models.JSONField(default=dict, blank=True)
    requested_by = models.CharField(max_length=150, editable=False)
    approved_by = models.CharField(max_length=150, blank=True, default="")
    approved_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    version = models.PositiveIntegerField(default=1)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at", "-id"]
        default_permissions = ()
        constraints = [
            models.UniqueConstraint(fields=["device"], condition=Q(state__in=("REQUESTED", "BLOCKED", "PLANNED", "APPROVED", "RESTORING", "UNCERTAIN")),
                                    name="unique_open_restoration_per_device"),
            models.CheckConstraint(condition=~Q(state="APPROVED") | ~Q(approved_by=""), name="approved_restoration_names_approver"),
        ]

    @property
    def record_id(self) -> str:
        return f"RST-{self.pk:06d}" if self.pk else "RST-NEW"

    def save(self, *args, **kwargs):
        if self.state not in RestorationState.values:
            raise ValueError("Invalid RestorationRecord.")
        if self.pk:
            persisted = type(self).objects.filter(pk=self.pk).values("state").first()
            if persisted is not None and persisted["state"] in (RestorationState.RESTORED, RestorationState.CANCELLED,
                                                                RestorationState.ROLLED_BACK, RestorationState.REENROLLMENT_REQUIRED) \
                    and persisted["state"] != self.state:
                raise ValueError("A closed restoration record is history.")
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("RestorationRecord rows are history and cannot be deleted.")


class TopologyNodeState(models.TextChoices):
    PLANNED = "PLANNED", "Planned (expected record only)"
    DISCOVERED = "DISCOVERED", "Discovered (untrusted)"
    AUTHENTICATED = "AUTHENTICATED", "Authenticated / bootstrapped"
    ISOLATED = "ISOLATED", "Isolated"
    COMMISSIONED = "COMMISSIONED", "Commissioned (not yet admitted)"
    IN_SERVICE = "IN_SERVICE", "Admitted / in service"
    MAINTENANCE = "MAINTENANCE", "In maintenance"
    DECOMMISSIONED = "DECOMMISSIONED", "Decommissioned"
    UNCERTAIN = "UNCERTAIN", "Uncertain"


class TopologyNode(models.Model):
    """The persisted operational-topology node of one managed device (stable key: the device), rebuilt into NetworkX on demand."""

    device = models.OneToOneField(ManagedDevice, on_delete=models.PROTECT, related_name="topology_node", editable=False)
    name = models.CharField(max_length=64, editable=False)
    platform = models.CharField(max_length=32, editable=False)
    role = models.CharField(max_length=32, blank=True, default="")
    state = models.CharField(max_length=16, choices=TopologyNodeState.choices, default=TopologyNodeState.PLANNED)
    last_sequence = models.PositiveBigIntegerField(default=0)
    facts = models.JSONField(default=dict, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]
        default_permissions = ()


class TopologyEdgeKind(models.TextChoices):
    PRODUCTION = "PRODUCTION", "Production link"
    MANAGEMENT = "MANAGEMENT", "Management path"


class TopologyEdge(models.Model):
    """One verified link (from a verified attachment or an approved management path) -- never inferred from addressing."""

    device = models.ForeignKey(ManagedDevice, on_delete=models.PROTECT, related_name="topology_edges", editable=False)
    local_interface = models.CharField(max_length=64, blank=True, default="", editable=False)
    peer = models.CharField(max_length=64, editable=False, help_text="Upstream device name (managed or inventory).")
    peer_interface = models.CharField(max_length=64, editable=False)
    kind = models.CharField(max_length=12, choices=TopologyEdgeKind.choices, editable=False)
    source = models.CharField(max_length=40, editable=False, help_text="ATT-n / MPATH-n: the record that proves the link.")
    active = models.BooleanField(default=True)
    facts = models.JSONField(default=dict, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["device", "kind", "peer", "peer_interface"]
        default_permissions = ()
        constraints = [models.UniqueConstraint(fields=["device", "local_interface", "peer", "peer_interface", "kind"],
                                               name="unique_topology_edge")]


class MonitoringTargetState(models.TextChoices):
    PENDING = "PENDING", "Pending (no authorized management path yet)"
    ACTIVE = "ACTIVE", "Actively monitored"
    SUSPENDED = "SUSPENDED", "Suspended (maintenance / path lost)"
    RETIRED = "RETIRED", "Retired (decommissioned; history kept)"
    BLOCKED = "BLOCKED", "Blocked (lifecycle or capability does not permit monitoring)"


class MonitoringTarget(models.Model):
    """One dynamically registered monitoring target.  The address is the device's authorized management path as the Phase 4
    selector chose it; ``generation`` increments whenever collectors must reconnect (path change, restore)."""

    device = models.OneToOneField(ManagedDevice, on_delete=models.PROTECT, related_name="monitoring_target", editable=False)
    name = models.CharField(max_length=64, editable=False)
    platform = models.CharField(max_length=32, editable=False)
    state = models.CharField(max_length=12, choices=MonitoringTargetState.choices, default=MonitoringTargetState.PENDING)
    address = models.CharField(max_length=64, blank=True, default="")
    management_path = models.ForeignKey("ManagementPath", null=True, blank=True, on_delete=models.PROTECT, related_name="+")
    generation = models.PositiveIntegerField(default=0)
    collectors = models.JSONField(default=dict, blank=True, help_text="{collector: {enabled, reason}} from the platform's real capabilities.")
    last_sequence = models.PositiveBigIntegerField(default=0)
    history = models.JSONField(default=list, blank=True, help_text="Bounded registration / path / retirement history.")
    registered_at = models.DateTimeField(null=True, blank=True)
    retired_at = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]
        default_permissions = ()


class NsotProjectionState(models.TextChoices):
    PENDING = "PENDING", "Pending"
    IN_SYNC = "IN_SYNC", "NetBox matches the lifecycle"
    PLANNED = "PLANNED", "Changes computed; writes disabled (dry run)"
    DISCREPANCY = "DISCREPANCY", "NetBox disagrees and NMAS must not invent the fix"
    UNAVAILABLE = "UNAVAILABLE", "NetBox unavailable (retrying)"


class NsotProjection(models.Model):
    """What NetBox should show for one managed device, what was applied, and what NMAS refused to invent."""

    device = models.OneToOneField(ManagedDevice, on_delete=models.PROTECT, related_name="nsot_projection", editable=False)
    name = models.CharField(max_length=64, editable=False)
    state = models.CharField(max_length=12, choices=NsotProjectionState.choices, default=NsotProjectionState.PENDING)
    desired = models.JSONField(default=dict, blank=True)
    applied = models.JSONField(default=list, blank=True)
    discrepancies = models.JSONField(default=list, blank=True)
    last_sequence = models.PositiveBigIntegerField(default=0)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]
        default_permissions = ()
