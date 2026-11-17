# Operator guide — troubleshooting UI and API v1

## UI
`/troubleshooting/` (history), `/troubleshooting/new/` (intake), `/troubleshooting/<case_id>/` (stages, evidence, hypotheses,
AI handoffs, remediation plans, report). Plan actions are POST-only at
`/troubleshooting/<case>/remediation/<plan>/{dry_run,precheck,approve,reject,execute}/` (CSRF protected; one named route per action);
buttons are rendered disabled with the reason when `action_availability()` says the action is unsafe (no approval right, dry-run
missing, no alternate path, window closed) **or** the signed-in user lacks the NMAS permission for it.

The dashboard also shows each fixed model-broker socket, the global agent lease with its recent
acquire/transfer/pause/release history, and live fault-recovery campaigns (fixture simulations are never listed).
`POST /troubleshooting/<case>/ai/escalate/` (`nmas_validate`, `ts-operator` or higher) asks NMAS to open the governed AI
handoff. NMAS refuses while deterministic coverage is incomplete. The website holds no broker key and never runs a model:
an OPEN handoff shows the exact `nmas-troubleshooter-dispatch@<handoff>.service` an administrator starts, or the missing
prerequisite when no broker is running.

## Access (two independent layers)
1. `NmasAccessMiddleware`: authenticated session, completed website MFA and the NMAS permission of the route
   (`core/services/identity/policy.py`): reads -> `nmas_view` (raw evidence, report, export and audit are audited sensitive reads);
   open a case -> `nmas_edit`; run read-only collection -> `nmas_validate`; expected-anomaly exception -> `nmas_approve`;
   dry-run / precheck -> `nmas_validate`; approve / reject -> `nmas_approve`; execute -> `nmas_execute`.
2. The troubleshooting view: a `ts-viewer|ts-operator|ts-approver|ts-admin` group, `ts-tenant:<name>` tenancy and optional
   `ts-device:<name>` device scope.  Both layers must allow a request; neither can widen the other.

## API v1 (`/api/v1/troubleshooting/…`, JSON, `schema_version` in every payload)
`cases/` (GET list/POST intake), `metrics/`, `cases/<id>/` , `stages/`, `evidence/`, `evidence/<eid>/`, `report/`, `ai/`,
`remediation/` , `remediation/<plan>/<action>/`, `exceptions/`, `audit/`, `export/`.
All reads are tenant/scope filtered (cross-tenant ids return 404, UT-084/tenant isolation). Writes require the existing
authentication/role/MFA checks; unauthenticated API → JSON 401, unauthenticated page → login redirect, MFA pending → MFA
redirect, missing NMAS permission → 403 (audited ACCESS_DENIED), missing `ts-*` role → 401/403 from the view.

## Reading outcomes
UNKNOWN means evidence was unavailable, never "healthy". Mock/fixture runs are labelled non-live in the report.

## Tests
`core.tests.test_troubleshooting_views` (18 tests; UT-081–090) and `core.tests.test_troubleshooting_access` (11 tests; TSACC-*).

## Run
```
cd web && DJANGO_DEBUG=1 DJANGO_SECRET_KEY=test /opt/ai-orchestrator/nmas-env/bin/python manage.py test \
  core.tests.test_troubleshooting_ai core.tests.test_troubleshooting_governance core.tests.test_troubleshooting_views
```
Result in this run: `Ran 77 tests ... OK` (local, not gateway-attested).
