# Deployment and rollback of the troubleshooting / observation feature

The production deployment of this feature is the **compatibility overlay** in `deploy/compat/`. It is not a checkout of this
repository. The full guarded procedure, authorization steps and approval checklist are in `compat-deployment.md`. This page
summarises what the feature changes and how each part is undone.

Diagnostic and research host-network activation is a separate privileged change.
The independent commands, ownership state and namespace-specific rollback are in
`namespace-activation.md`. The frozen 205-operation package's combined namespace
helper is prohibited; only an independently reviewed successor candidate may be
used for activation.

## What the overlay changes
1. **Migrations** `0036_v2_phase9_relay_option82_readback` → `0037_troubleshooting` (`Ts*` tables) → `0038_device_observations`
   (`DeviceVersionObservation`) → `0039_observation_authorizations` (`ObservationAuthorization`, `ObservationAuthorizationUse`).
   - All four only create tables, indexes and constraints. No existing table is altered.
   - The rehearsal on a production snapshot showed:
     - all 87 pre-existing tables kept identical row counts
     - only `django_migrations`, `django_content_type` and `auth_permission` gained rows
     - reversal back to 0035 restored a byte-identical schema
2. **Routes**: `troubleshooting_urls` is included additively at the end of `core/urls.py` and classified in
   `core/services/identity/policy.py` (website MFA plus an NMAS permission per route).
3. **Settings** (`config/settings.py`, inherited by production's `config/settings_demo.py`): the two runtime-factory settings, and:
   - `NMAS_TS_DEPLOYMENT` stays **empty unless** `NMAS_TS_BINDING=nmas-v1` is set in the service environment. Enabling the
     binding is a separate, reversible step.
   - One observation source is registered only when `NMAS_OBSERVATION_SOURCE_ID` is set. Its key is read from
     `NMAS_OBSERVATION_KEY` and never stored in settings.
4. **System checks** (`core/checks.py`) fail closed on a misconfigured binding or source (`nmas.E001`–`E014`). They report names
   only.
5. Remediation execution stays **disabled**: `governance.UnconfiguredExecutor` refuses writes. AI tools are read-only and limited
   to proposals.

## Rollback (reverse order, each step independently verifiable)

| Undo | How | Data effect |
|---|---|---|
| Version binding | remove `NMAS_TS_BINDING` from the service environment, restart `nmas-web` | none (troubleshooting admission returns to "unbound") |
| Observation source | remove `/etc/nmas/nmas-observation.env` (or its `NMAS_OBSERVATION_SOURCE_ID`) | none; `device_observe` refuses `SOURCE_UNCONFIGURED` |
| Authorizations | `observation_authorize revoke` each open `OBSAUTH` | none (revocation is recorded) |
| Schema | stop the units; **export first** if any Ts case or observation history must be kept; then `manage.py migrate core 0038` → `0037` → `0036` → `0035` | drops the overlay tables and their rows |
| Source | `nmas_compat_overlay.py rollback --journal <backup>/journal.json --db web/db.sqlite3` (refuses while 0036–0039 are still applied) | restores the 8 shared files byte-for-byte, removes the 171 added files |
| Research namespace | stop only the research worker, then `namespace-activate.sh rollback research /etc/nmas/research-namespace.env` | removes only ownership-verified research namespace/veth/host-table/resolver/policy resources; diagnostic is untouched |
| Diagnostic namespace | stop only the diagnostic worker, then `namespace-activate.sh rollback diagnostic /etc/nmas/diagnostic-namespace.env` | removes only ownership-verified diagnostic namespace/veth/host-table/policy resources; research is untouched |
| Last resort | `nmas_compat_overlay.py db-restore` of the pre-deploy backup, plus extraction of the pre-deploy source archive | returns to the exact pre-deploy state, **losing all writes made after the backup** |

Reversing the migrations leaves 22 stale `django_content_type` rows and 72 `auth_permission` rows for the removed models. This is
standard Django behaviour and harmless. Run `manage.py remove_stale_contenttypes` only after checking that no group holds those
permissions.

Device-side remediation rollback is per plan: compensation and read-back by `governance._abort`. The legacy `rollback_service` is
not in production, so compensation reports `COMPENSATION_UNAVAILABLE`, which is a governed refusal and not a crash.
`ABORTED_UNRESTORED` requires manual restoration from the pre-change snapshot referenced in the plan.

## External prerequisites (not satisfied here)
Live gateway-attested evidence is not claimed. Tests use fakes. These are still needed:
- configured `Ports` (execution is a hand-off to the Change page)
- NetBox and flow-health sources
- real maintenance windows
- a gateway fixture run
