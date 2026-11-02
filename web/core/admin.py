from django.contrib import admin

from .models import (
    AppMfaDevice,
    AuditEvent,
    CapabilityEvidence,
    Change,
    ChangeLifecycleEvent,
    ChangeTarget,
    Configlet,
    ConfigletDependency,
    CredentialRotationRun,
    DeviceCredential,
    DeviceIntent,
    DeviceLoginMfaPolicy,
    DeviceIntentRevision,
    IntentFieldState,
    Notification,
)


@admin.register(DeviceCredential)
class DeviceCredentialAdmin(admin.ModelAdmin):
    list_display = ("device_name", "platform", "username", "account_kind", "auth_method", "rotation_enabled", "next_due_at", "last_status")
    list_filter = ("platform", "rotation_enabled", "last_status")
    search_fields = ("device_name", "username", "secret_ref")
    readonly_fields = ("ssh_key_ref", "ssh_public_key_fingerprint", "last_rotated_at", "last_attempt_at", "last_status", "last_result_code",
                       "created_at", "updated_at")


@admin.register(DeviceLoginMfaPolicy)
class DeviceLoginMfaPolicyAdmin(admin.ModelAdmin):
    list_display = ("device_name", "platform", "required", "mechanism", "central_aaa_state", "enforcement_state", "automation_exempt", "blocked_reason", "last_verified_at")
    list_filter = ("platform", "mechanism", "central_aaa_state", "enforcement_state", "automation_exempt")
    # Evidence/digests are written only by the dedicated render/verification commands.
    readonly_fields = ("candidate_digest", "last_verified_at", "last_verification_result", "updated_at")


@admin.register(CredentialRotationRun)
class CredentialRotationRunAdmin(admin.ModelAdmin):
    list_display = ("run_id", "credential", "trigger_reason", "started_at", "completed_at", "final_status", "error_category")
    list_filter = ("trigger_reason", "final_status", "error_category")
    search_fields = ("run_id", "credential__device_name", "credential__username")

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    """
    Local debugging aid only -- not the primary operator UI (that's the
    header dropdown / Notification Center). Never exposes a secret: the
    model itself has no webhook/token field to display.
    """

    list_display = (
        "id",
        "created_at",
        "severity",
        "event_type",
        "title",
        "is_read",
        "slack_status",
        "is_test",
    )
    list_filter = ("severity", "event_type", "is_read", "slack_status", "is_test")
    search_fields = ("title", "message", "device", "change_id", "correlation_key")
    readonly_fields = ("created_at", "updated_at", "slack_attempted_at")
    date_hierarchy = "created_at"


# =============================================================================
# Phase 8 -- Device Intent / Change / Configlet, read-only development aids.
#
# These registrations are for local inspection only, not the intended
# operator workflow (that is Phase 9's Device Builder UI). Identifiers and
# history are read-only here on purpose: change_id/cfg_id/revision are
# immutable at the model layer already, and lifecycle/audit rows are
# append-only, so the admin must not offer an edit path that could look
# like it rewrites history. No field here ever holds a raw secret --
# *_ref/metadata JSON is policed by core.services.secret_policy at the
# service layer before it ever reaches these rows.
# =============================================================================


class ChangeTargetInline(admin.TabularInline):
    model = ChangeTarget
    extra = 0
    readonly_fields = ("device_name", "netbox_device_ref", "site")
    can_delete = False


@admin.register(Change)
class ChangeAdmin(admin.ModelAdmin):
    list_display = (
        "change_id",
        "title",
        "category",
        "execution_mode",
        "lifecycle_state",
        "validation_state",
        "created_by",
        "created_at",
    )
    list_filter = ("category", "execution_mode", "lifecycle_state", "validation_state")
    search_fields = ("change_id", "title", "created_by")
    readonly_fields = ("change_id", "created_at", "updated_at")
    date_hierarchy = "created_at"
    inlines = [ChangeTargetInline]


class ConfigletInline(admin.TabularInline):
    model = Configlet
    extra = 0
    fields = ("cfg_id", "sequence", "target_device", "feature_namespace", "operation_type", "execution_status")
    readonly_fields = fields
    can_delete = False


@admin.register(DeviceIntent)
class DeviceIntentAdmin(admin.ModelAdmin):
    list_display = ("device_name", "change", "target_type", "platform", "created_at")
    list_filter = ("target_type", "platform")
    search_fields = ("device_name", "change__change_id")
    readonly_fields = ("created_at", "updated_at")


@admin.register(DeviceIntentRevision)
class DeviceIntentRevisionAdmin(admin.ModelAdmin):
    list_display = ("device_intent", "revision", "schema_version", "created_by", "created_at")
    list_filter = ("schema_version",)
    search_fields = ("device_intent__device_name",)
    readonly_fields = ("device_intent", "revision", "created_at")


@admin.register(IntentFieldState)
class IntentFieldStateAdmin(admin.ModelAdmin):
    """
    Draft/accepted values are structural (IP addresses, enum-shaped config
    values), never secrets -- secret-shaped field values belong behind a
    *_ref, enforced upstream in intent_service, so displaying draft/accepted
    here is safe by construction.
    """

    list_display = ("revision", "path", "dirty", "validation_state", "last_committed_at")
    list_filter = ("dirty", "validation_state")
    search_fields = ("path", "revision__device_intent__device_name")
    readonly_fields = ("revision", "path", "created_at", "updated_at")


@admin.register(Configlet)
class ConfigletAdmin(admin.ModelAdmin):
    list_display = (
        "cfg_id",
        "change",
        "target_device",
        "feature_namespace",
        "operation_type",
        "deployment_priority",
        "execution_status",
    )
    list_filter = ("feature_namespace", "operation_type", "deployment_priority", "execution_status")
    search_fields = ("cfg_id", "change__change_id", "target_device")
    readonly_fields = ("cfg_id", "sequence", "created_at", "updated_at")


@admin.register(ConfigletDependency)
class ConfigletDependencyAdmin(admin.ModelAdmin):
    list_display = ("configlet", "depends_on", "created_at")
    search_fields = ("configlet__cfg_id", "depends_on__cfg_id")
    readonly_fields = ("created_at",)


@admin.register(ChangeLifecycleEvent)
class ChangeLifecycleEventAdmin(admin.ModelAdmin):
    """Append-only history: no add/change/delete from the admin UI, view only."""

    list_display = ("change", "from_state", "to_state", "actor", "occurred_at")
    list_filter = ("from_state", "to_state")
    search_fields = ("change__change_id", "actor")
    date_hierarchy = "occurred_at"

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(AuditEvent)
class AuditEventAdmin(admin.ModelAdmin):
    """Append-only history: no add/change/delete from the admin UI, view only."""

    list_display = ("event_type", "change", "object_type", "object_id", "actor", "created_at")
    list_filter = ("event_type", "object_type")
    search_fields = ("change__change_id", "object_id", "actor", "summary")
    date_hierarchy = "created_at"

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False



# --- V2 Phase 1: website MFA (recovery path) and capability evidence --------------------------------------------------

@admin.register(AppMfaDevice)
class AppMfaDeviceAdmin(admin.ModelAdmin):
    """Website MFA authenticators.  The encrypted seed is never displayed; the only mutation is an audited reset."""

    list_display = ("user", "confirmed_at", "last_verified_at", "created_at")
    fields = ("user", "confirmed_at", "last_verified_at", "created_at")
    readonly_fields = fields
    actions = ["reset_authenticators"]

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    @admin.action(description="Reset selected website authenticators (user re-enrolls at next sign-in)")
    def reset_authenticators(self, request, queryset):
        from .models import AuditEventType
        from .services.identity import audit

        if not request.user.has_perm("core.nmas_security_admin"):
            self.message_user(request, "Requires the NMAS security-admin permission.", level="error")
            return
        for device in queryset.select_related("user"):
            username = device.user.get_username()
            device.delete()
            audit.record(AuditEventType.APP_MFA_RESET, f"Website MFA reset for {username} (admin)", request=request,
                         outcome=audit.OUTCOME_SUCCESS, object_type="User", object_id=str(device.user_id),
                         metadata={"target_username": username, "path": "django_admin"})
        self.message_user(request, "Selected website authenticators were reset.")


@admin.register(CapabilityEvidence)
class CapabilityEvidenceAdmin(admin.ModelAdmin):
    list_display = ("platform", "feature", "axis", "status", "evidence_type", "runtime_version", "source", "recorded_by", "recorded_at")
    list_filter = ("platform", "axis", "status", "evidence_type")
    search_fields = ("feature", "source", "evidence_ref", "repository_head", "runtime_version")

    def has_change_permission(self, request, obj=None):
        return False
