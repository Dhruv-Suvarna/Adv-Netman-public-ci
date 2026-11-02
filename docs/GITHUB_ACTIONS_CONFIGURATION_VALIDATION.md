# GitHub Actions: Configuration Validation

Second, independent workflow beside `Tier-3 validation`. Tier-3 tests **code** changes (pull requests, pushes).
`Configuration Validation` tests one **Configuration Change candidate**, and NMAS triggers it by itself.

GitHub Actions validates only. The workflow has `contents: read`, uses no secret, opens no device session, sends no
configuration, runs no Configlet and writes neither NetBox nor the NMAS database. Device prechecks and execution stay
in NMAS.

## 1. Flow

    create / edit a Change in NMAS
      -> Save Draft or Run Change Validation
      -> Tier-2 validation stores an immutable ChangeValidationRun
      -> if it PASSED: NMAS builds a sanitized bundle of exactly that snapshot and sends repository_dispatch
         (event type nmas_configuration_validation) -> ConfigurationValidationRun = QUEUED
      -> GitHub runs "Configuration Validation", named "NMAS Configuration Validation | CHG-... | <correlation id>"
      -> NMAS reads the result (Change validation page, and again at the execution gate) -> PASS / FAIL / ERROR
      -> execution is permitted only with PASS for the current candidate

Trigger point: `change_validation_service.validate_change`, the one function every whole-Change validation goes
through. A field edit triggers nothing. A Tier-2 run that did not pass triggers nothing.

## 2. Files

| Path | Content |
|---|---|
| `.github/workflows/configuration-validation.yml` | the workflow (`repository_dispatch` only) |
| `scripts/ci/validate_configuration_change.py` | CI entry point: decodes the bundle, runs the checks and the selected tests, writes the job summary |
| `web/core/services/configuration_validation/bundle.py` | the bundle, its three hashes, encoding, size limit, secret-format refusal |
| `web/core/services/configuration_validation/checks.py` | check categories A to E and the test selection F |
| `web/core/services/configuration_validation/github.py` | the only module that calls the GitHub API |
| `web/core/services/configuration_validation/service.py` | dispatch, refresh, staleness, execution gate |
| `core.models.ConfigurationValidationRun` (migration `0029`) | the tracking row |

## 3. Bundle

`client_payload` = `correlation_id`, `change_id`, `snapshot_hash`, `candidate_hash`, `bundle_sha256`, `bundle`
(gzip + base64 of the canonical JSON below). Limit 56,000 encoded bytes; a larger bundle is refused whole with
`CONFIG_VALIDATION_BUNDLE_TOO_LARGE` and nothing is sent.

| Field | Content |
|---|---|
| `change` | Change id, category, workflow, execution mode |
| `validation` | Tier-2 run id, status, engine version, input hash, source hash, repository SHA, blocking finding codes |
| `snapshot_hash` | input hash of the Tier-2 run (the immutable Change snapshot) |
| `candidate_hash` | one hash over every device's sanitized candidate and every removal's content hash |
| `devices` | device, platform, requested features, sanitized candidate text and its SHA-256 |
| `removals` | device, platform, mode, content hash |
| `intent` | the accepted snapshot (secret-shaped keys already redacted by `validation.snapshot`) |
| `dependencies` | nodes, edges and cycles of the Tier-2 dependency graph |
| `matrix` | capability status NMAS saw for each platform and feature |
| `scope` | managed-scope result of the candidate validation |

Candidate text passes `bundles.legacy_sanitize.sanitize_config`. A bundle in which a credential format is still
recognisable is refused (`CONFIG_VALIDATION_BUNDLE_NOT_SANITIZED`), not sent.

## 4. What the workflow tests

| | Category | Checks |
|---|---|---|
| A | Bundle integrity | bundle SHA-256, snapshot hash recomputed from the intent, each candidate's hash, candidate hash, envelope, provenance, Tier-2 passed |
| B | Candidate rendering | a renderer exists for the platform, the candidate parses, no placeholder, one block per interface, no conflicting single-valued statement |
| C | Platform support | every requested feature is `SUPPORTED` in the repository's own capability matrix; unknown or `NOT_IMPLEMENTED` fails |
| D | Intent and dependency | dependency graph consistent, protected VLAN 200 unchanged, every target inside the managed scope (R5 and unknown devices refused), authority boundaries |
| E | Syntax and semantics | addresses, VLAN ids, control characters, device error text, secret-shaped content |
| F | Path-scoped tests | the Django test modules for this platform, feature and Change type (8 to 10 modules, never the whole suite) |

Categories B to F run only when A passed. The job summary lists the Change, devices, platforms, features, hashes, the
Tier-2 run and every check.

## 5. Tracking, staleness and the gate

`ConfigurationValidationRun` holds the correlation id, the Change, the Tier-2 run, snapshot hash, candidate hash,
bundle hash, status, GitHub run id and URL, tested repository SHA, trigger and completion time and a short failure
reason. Status: `NOT_TRIGGERED`, `QUEUED`, `IN_PROGRESS`, `PASS`, `FAIL`, `ERROR`, `STALE`.

- A row is `STALE` as soon as the Change's current snapshot hash is not the row's, or a newer Tier-2 run exists. A new
  dispatch also marks every older row of that Change `STALE`.
- Execution eligibility adds one blocker, `CONFIGURATION_VALIDATION_NOT_PASSING`, for every status except `PASS` of the
  current candidate. No other gate was changed.
- A dispatch whose run does not appear within 15 minutes becomes `ERROR`.
- Exempt: a routing transition Change (`route_shield.lifecycle`) only. It has its own validation and executor and the
  general execution engine already refuses it.
- The automated test environment turns the feature off (`core.tests.runner`); its own tests turn it on.

### 5.1 How the result gets back to NMAS

NMAS polls GitHub; GitHub never calls NMAS, so no public path to NMAS is needed. `service.reconcile(change)` makes one
outbound list request and updates every row of the Change that still owes a result. It runs when the Change page or the
Configuration Validation page is opened, on the **Refresh from GitHub** button (POST), inside the execution gate, and
from `manage.py nmas_configuration_validation reconcile [--change CHG-...]`. It is stateless: a run that finished while
NMAS was down is picked up by the next call.

A GitHub run is accepted as a row's run only when all of these hold: it is a run of
`.github/workflows/configuration-validation.yml` in the configured repository, it was started by `repository_dispatch`,
and its name carries the row's correlation id and its Change id. Exactly one such run must exist; two is
`CONFIG_VALIDATION_RUN_AMBIGUOUS` (`ERROR`). Once a row knows its run id it accepts that run only. The candidate itself
is bound inside the workflow (category A recomputes the hashes of the dispatched bundle).

Only `completed` + `success` is `PASS`. `failure` is `FAIL`. Every other ending is `ERROR`. A row that was superseded
before its result was read keeps `STALE` and records the run id, URL, tested commit and what GitHub decided.

## 6. Setup on the NMAS host

The workflow file must be on the default branch: GitHub starts `repository_dispatch` workflows from there only.

Add to the protected `/etc/nmas/nmas-web.env` and restart `nmas-web`:

    NMAS_GITHUB_TOKEN=<fine-grained token: this repository only, Contents read and write, Actions read>
    NMAS_GITHUB_REPOSITORY=Dhruv-Suvarna/Adv-Netman        # optional, this is the default

Apply migration `0029`. Without a token every dispatch is recorded `NOT_TRIGGERED` and execution stays blocked.

## 7. Showing a failing run

    python manage.py nmas_configuration_validation demo-failure --change CHG-... --actor <name>

It copies the bundle of the Change's latest passing validation, appends `no interface Vlan200` to one candidate and
dispatches that. GitHub fails it in category D. The row is marked as a demonstration: it never counts for execution
and does not replace the real result. The Change is not modified and no device is contacted.

    python manage.py nmas_configuration_validation status --change CHG-...
    python manage.py nmas_configuration_validation reconcile [--change CHG-...]
