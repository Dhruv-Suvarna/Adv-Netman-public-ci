# Phase 24 — R1 pilot source remediation and remaining live gates

Status (2026-09-28): **SOURCE-ONLY REMEDIATION. NO R1 CHANGE, ACCOUNT
CREATION, TOTP ENROLLMENT, AAA/SSH CHANGE, OR CREDENTIAL ROTATION WAS
PERFORMED.** The literal `<NAMED_OPERATOR>` is a redacted placeholder, not an
EOS/privacyIDEA username. An actual valid, unique username is still required.

## 1. Persistent TLS correction

The tracked FreeRADIUS 3.2.1 `rlm_rest` configuration now uses:

```text
ca_info_file = /run/secrets/privacyidea-ca.pem
check_cert = yes
check_cert_cn = yes
```

`ca_info_file` supplies libcurl's CA trust bundle. FreeRADIUS 3.2.1 maps
`ca_file` to `CURLOPT_ISSUERCERT`; it does not make the private CA trusted.
The CA itself remains ignored runtime material. A source test rejects a return
of the incorrect `ca_file` directive.

## 2. R1 automation identity routing

`inventory.yml` selects `nmas-automation` and
`runtime://device-credentials/r1-nmas-automation` for R1 only. R2, R5, S1-S4
and `mgmt_swt` continue to inherit the fleet `admin` profile. One shared
resolver is consumed by:

- Health live reads;
- NSOT and running-config retrieval;
- Configuration Changes and Remove Configuration execution;
- `master.py` push/verification paths;
- `address_report.py`.

For R1, consumers try the per-device identity first. The fleet identity is a
bounded transition/rollback candidate: it preserves existing behavior before
the R1 service account exists, and becomes usable after rollback restores
`admin`. Activation removes `admin`, so this fallback cannot authenticate
during MFA enforcement. An enrolled SSH key that cannot load still fails the
whole resolver closed; it never degrades to password-only.

The fallback does not make retaining `admin` during enforcement acceptable.
Post-change evidence must prove `admin` is absent and that each NMAS consumer
actually authenticated as `nmas-automation`.

## 3. Rollout metadata and exact staged candidate

The source-only command below creates database metadata; it never connects to
R1, reads a secret, creates an EOS user, or enrolls a token:

```text
python web/manage.py prepare_r1_mfa_rollout_metadata --human-username <actual-valid-username>
```

It requires the existing R1 `admin` rollback row, permits exactly one R1 human,
and records:

- `nmas-automation`: local SERVICE, protected R1-specific reference;
- `r1-breakglass`: local BREAK_GLASS, separate protected reference;
- the named human: central HUMAN, password plus TOTP, no local secret.

The renderer emits two stages. Provider placeholders are substituted only by
the protected execution boundary after explicit approval.

Prepare and verify first:

```text
username nmas-automation privilege 15 role network-admin secret <provider:runtime://device-credentials/r1-nmas-automation>
username r1-breakglass privilege 15 role network-admin secret <provider:runtime://device-credentials/r1-breakglass>
```

Activation is one atomic configuration-session commit:

```text
no username admin
radius-server host 192.168.200.100 key 0 <provider:runtime://human-mfa/radius/r1>
aaa group server radius NMAS-HUMAN-MFA
   server 192.168.200.100
ip radius source-interface Vlan200
aaa authentication login console local
aaa authentication login default local group NMAS-HUMAN-MFA
aaa authorization commands all default local
management ssh
   authentication protocol password
```

The named human is intentionally absent from these local EOS account lines.
The shared `admin` is removed in the same atomic activation that enables the
local-first/RADIUS method list.

## 4. Complete rollback

The exact rendered device rollback is:

```text
management ssh
   default authentication protocol
no aaa authorization commands all default local
no aaa authentication login default
no aaa authentication login console
no aaa group server radius NMAS-HUMAN-MFA
no radius-server host 192.168.200.100
no ip radius source-interface
username admin privilege 15 role network-admin secret <provider:runtime://device-credentials/ceos-admin-shared>
no username r1-breakglass
no username nmas-automation
```

Apply rollback from the retained console/current session. AAA is removed before
legacy recovery is restored; pilot accounts are removed last. The R1 consumer
then fails its dedicated identity and uses the restored fleet profile. Verify
that behavior before closing recovery access. The actual pre-change R1 config
must still be compared with this renderer immediately before approval.

## 5. Authorization limitation

The pilot metadata uses `network-admin`/privilege 15 because the required NMAS
configuration and removal actions need write access and the lab's cEOS
engineering build previously failed to enforce tested restricted roles. This
is not least privilege. The pilot must report the effective privilege honestly;
a lower command-authorized role requires separate proof on the exact image.

## 6. privacyIDEA npm audit applicability

Audit scope was the exact privacyIDEA v3.13.4 commit
`9688ada43e30b7c97b126f460aa75b92315e1dd8`. On 2026-09-28,
`privacyidea/static_new/package-lock.json` reported 45 findings: 4 low, 16
moderate, 22 high and 3 critical. `npm audit --omit=dev` reported 8 production
dependency findings (5 moderate, 3 high) and **zero critical**, proving the
three critical rows are development dependency paths, but not proving they are
irrelevant. The separate legacy `privacyidea/static` lockfile reported 5
findings (4 moderate, 1 high) and zero critical.

| Critical package/advisory | Exact dependency path | Applicability here |
|---|---|---|
| `shell-quote` 1.8.3, GHSA-w7jw-789q-3m8p | `@angular-devkit/build-angular` → `webpack-dev-server` → `launch-editor` → `shell-quote` | Installed in the image builder. The vulnerable dev-server/editor path is not started by `ng build`, is absent from the final image, and is not in the browser bundle. It is not remotely reachable from the deployed privacyIDEA API/UI, but remains build-tool attack surface. |
| `tar` 7.5.13, GHSA-23hp-3jrh-7fpw | `@angular/cli` → `pacote` (and `node-gyp`) → `tar` | Installed and the Angular CLI is executed during the build. The vulnerable archive parsing is not used by the served privacyIDEA process and the package is absent from the final image. This is the most applicable of the three to build integrity, even though the pinned/trusted build does not feed it an operator-supplied archive. |
| `websocket-driver` 0.7.4, GHSA-xv26-6w52-cph6 | `@angular-devkit/build-angular` → `webpack-dev-server` → `sockjs`/`faye-websocket` → `websocket-driver` | Installed in the builder, but no webpack development server is launched. It is absent from the final image and browser bundle, so the deployed service exposes no vulnerable WebSocket listener from this package. |

The final multi-stage image contains compiled Angular assets, but no Node/npm,
no `node_modules`, and no copy of these three modules; searches of the compiled
distribution found none of their package identifiers. Consequently the three
critical findings do not affect the Python privacyIDEA validation API or the
served UI at runtime. They do affect the trust placed in image construction and
must stay in the security record.

An isolated `npm audit fix --package-lock-only` experiment (not applied to the
pinned source) selected `shell-quote` 1.10.0, `tar` 7.5.22 and
`websocket-driver` 0.7.5, reducing critical findings to zero. It still reported
20 lower-severity findings. The production Angular dependencies also have
non-critical runtime advisories. Therefore remediation means reviewing a
patched lockfile/upstream privacyIDEA revision, rebuilding, repeating the full
npm audit, reviewing the browser dependency updates, and re-running
privacyIDEA API, enrollment, TLS and factor-matrix tests. Silently mutating the
lockfile after checking out the pinned commit is not acceptable.

## 7. Sensitive prior transcript

An earlier tool transcript exposed EOS password-hash text and localized SNMPv3
key material. Those values are intentionally not reproduced here. Treat that
transcript as sensitive. Later rotation of affected credentials/key material
may be appropriate, but requires separate authorization. Rotations executed by
this remediation: **0**.

## 8. Remaining gates before requesting live approval

After this source change is reviewed and promoted, the live pilot still needs:

1. an actual valid value replacing `<NAMED_OPERATOR>`;
2. deployment promotion and database/application compatibility checks;
3. rebuild/restart of the isolated FreeRADIUS service from corrected tracked
   source, followed by TLS/connectivity/log/time evidence;
4. an explicit decision on the privacyIDEA frontend update risk above;
5. protected secrets for `nmas-automation` and `r1-breakglass`, followed by
   creation and verification of those R1 accounts from retained recovery paths;
6. named human creation and private Microsoft Authenticator enrollment;
7. a fresh R1 baseline, exact rendered candidate/rollback and proof of console,
   current-session and RADIUS-outage recovery;
8. explicit operator authorization: `APPLY THE R1 2FA PILOT`.

Until all gates are presented and approved, R1 remains unchanged and the UI
must not claim `LIVE_VERIFIED`.
