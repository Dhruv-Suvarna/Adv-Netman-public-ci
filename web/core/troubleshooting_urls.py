"""URL routes for the troubleshooting UI and the versioned API (included additively from ``core.urls``)."""

from django.urls import path

from . import troubleshooting_views as v

# Remediation plan actions.  Each action is its own named route so that NmasAccessMiddleware can require the matching NMAS
# permission (core.services.identity.policy): dry-run/precheck -> VALIDATE, approve/reject -> APPROVE, execute -> EXECUTE.
# The view still re-checks the troubleshooting role, tenant/device scope and server-side action availability.
PLAN_ACTIONS = ("dry_run", "precheck", "approve", "reject", "execute")

urlpatterns = [
    # operator UI
    path("troubleshooting/", v.ui_list, name="troubleshooting_list"),
    path("troubleshooting/new/", v.ui_intake, name="troubleshooting_intake"),
    path("troubleshooting/<str:case_id>/", v.ui_detail, name="troubleshooting_detail"),
    path("troubleshooting/<str:case_id>/run/", v.ui_run, name="troubleshooting_run"),
    path("troubleshooting/<str:case_id>/ai/escalate/", v.ui_escalate, name="troubleshooting_escalate"),
    *(path(f"troubleshooting/<str:case_id>/remediation/<str:plan_id>/{a}/", v.ui_plan_action, {"action": a},
           name=f"troubleshooting_plan_{a}") for a in PLAN_ACTIONS),
    # API v1
    path("api/v1/troubleshooting/cases/", v.api_cases, name="ts_api_cases"),
    path("api/v1/troubleshooting/metrics/", v.api_metrics, name="ts_api_metrics"),
    path("api/v1/troubleshooting/cases/<str:case_id>/", v.api_case, name="ts_api_case"),
    path("api/v1/troubleshooting/cases/<str:case_id>/run/", v.api_run, name="ts_api_run"),
    path("api/v1/troubleshooting/cases/<str:case_id>/stages/", v.api_stages, name="ts_api_stages"),
    path("api/v1/troubleshooting/cases/<str:case_id>/evidence/", v.api_evidence, name="ts_api_evidence"),
    path("api/v1/troubleshooting/cases/<str:case_id>/evidence/<str:evidence_id>/", v.api_evidence_item, name="ts_api_evidence_item"),
    path("api/v1/troubleshooting/cases/<str:case_id>/report/", v.api_report, name="ts_api_report"),
    path("api/v1/troubleshooting/cases/<str:case_id>/ai/", v.api_ai, name="ts_api_ai"),
    path("api/v1/troubleshooting/cases/<str:case_id>/remediation/", v.api_remediation, name="ts_api_remediation"),
    *(path(f"api/v1/troubleshooting/cases/<str:case_id>/remediation/<str:plan_id>/{a}/", v.api_plan_action, {"action": a},
           name=f"ts_api_plan_{a}") for a in PLAN_ACTIONS),
    path("api/v1/troubleshooting/cases/<str:case_id>/exceptions/", v.api_exception, name="ts_api_exception"),
    path("api/v1/troubleshooting/cases/<str:case_id>/audit/", v.api_audit, name="ts_api_audit"),
    path("api/v1/troubleshooting/cases/<str:case_id>/export/", v.api_export, name="ts_api_export"),
]
