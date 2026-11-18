# NMAS V2 final 210-operation release acceptance

Date: 2026-11-15 (America/Denver)

## Decision

**TECHNICALLY_ACCEPTED — EXTERNAL_AUTHORIZATION_PENDING**

The immutable 210-operation candidate passes the requested independent technical
acceptance. No blocking defect or production baseline drift was found. This is
not deployment authorization, university infrastructure authorization,
namespace/firewall activation authorization, device authorization, research
egress authorization, Gate B approval, or proof of live containment.

No package, production file, production database, service configuration,
firewall, namespace, VM1 route/address, Containerlab object, or device was
modified. The package was not deployed.

## Accepted package identity

- Package: `/home/student/Scripts/nmas-independent-namespaces-release-20261115T050919Z/package`
- Operations: 210 — 201 ADD, 8 REPLACE, 1 MERGE
- Entries SHA-256: `5dab9de7e6af5d29fcfb23bb194ae65bde944c276f72cb8b3afe2c6bc0bd520f`
- Manifest SHA-256: `47c98c1a0952bf0cd52e2271685dfa1d2e3891409d1e3989072702efa8da6242`
- Manifest problems: none
- `SHA256SUMS`: `manifest.json` and `nmas_compat_overlay.py` both verified
- Independent payload audit: 210 unique safe relative paths, no payload
  symlinks, and every payload SHA-256 matched its manifest entry
- Production preconditions: `VERIFIED (pre): all 210 entries match`

The previously reviewed 205-operation package remains unchanged at
`/home/student/Scripts/nmas-sandbox-workers-release-20261114T220008Z/package`
with entries identity
`514f49bafd8aa38d178c4c36e275f85211867fc3f00ae600b59284800dd63ddc`
and manifest SHA-256
`dfbe2f5e8b589c63853ee8f823b6adf08a682da3126d923b3091f856b2330352`.

## Exact change from the reviewed 205-operation candidate

Five files were added:

- `deploy/sandbox/diagnostic-namespace.env.in`
- `deploy/sandbox/namespace_activation.py`
- `deploy/sandbox/research-namespace.env.in`
- `deploy/sandbox/test_namespace_activation.py`
- `docs/troubleshooting/namespace-activation.md`

Six existing candidate payloads changed:

- `deploy/sandbox/namespace-activate.sh` is now a small launcher for the
  independent Python controller; the coupled two-namespace implementation was
  removed.
- `deploy/sandbox/troubleshooter-namespaces.env.in` is retired and cannot be
  rendered as an activation configuration.
- Diagnostic and research nft templates now have separate default-drop input,
  forward, and output chains and only permit IPv6 neighbor discovery needed for
  static on-link operation.
- `docs/troubleshooting/deployment-rollback.md` documents independent rollback.
- `web/core/tests/test_troubleshooting_sandbox_artifacts.py` asserts the new
  controller, retired combined template, three default-drop chains, and
  separate configuration templates.

No migration, Django model, web startup hook, worker/IPC implementation,
target-policy implementation, research broker, or production shared-file patch
changed from the accepted 205-operation candidate. The adjacent earlier
independent-namespace build is not used as the comparison baseline.

## Security and lifecycle review

The namespace controller was reviewed in full.

- One invocation selects exactly `diagnostic` or `research`; state and locks are
  separate per kind.
- Production configuration must be a root-owned, regular, non-symlink file that
  is not group/world writable. Mutating actions require EUID 0.
- Production state is fixed at `/var/lib/nmas-ts-namespaces`, must be root-owned
  mode 0700, and contains mode-0600 atomic journals and locks.
- Configuration requires `AUTHORIZATION_APPROVED=yes` plus attributable IDs for
  the activation, authorization, source uniqueness, upstream ACL, firewall
  policy, and every enabled-family return route. Research additionally requires
  a research-egress approval ID and literal approved DNS servers with UDP and
  TCP explicitly enabled.
- Each address family must be explicitly enabled or disabled. Enabled families
  require a source CIDR and distinct on-link gateway; disabled families reject
  stray network values. At least one family must be enabled.
- The exact nft policy digest is pinned and syntax-checked. Preflight does not
  run `ip route get`, discover a network, infer ownership, or mutate state.
- Every resource step is journaled before execution and after completion.
  Handled interruption or failure invokes ownership-scoped cleanup; incomplete
  owned state is reconciled on retry.
- Namespace deletion requires the same kind, activation ID, configuration
  digest, and namespace marker. Research resolver deletion also requires the
  recorded content digest. Changed or unowned resources are refused rather
  than broadly deleted.
- Activation forces IPv4 and IPv6 forwarding off. Validation requires the exact
  source addresses/default routes, one expected nft table, and default-drop
  input/forward/output chains.
- Diagnostic nft allows only rendered address-plus-TCP-port tuples. Research
  allows DNS only to approved literal resolvers, drops special/private/protected
  IPv4 and IPv6 space, and then allows TCP/443. Application DNS pinning,
  redirect, TLS-hostname, content, and hostname controls remain independent.
- The new files are never imported by Django startup. Mutation occurs only after
  an explicit root invocation of the launcher. Worker and IPC behavior is
  unchanged from the 205 candidate and passed focused compatibility tests.

No new path automatically contacts university infrastructure. A root operator
could activate only after supplying a root-owned approved configuration; that
privileged act remains prohibited until the external gates are signed. Current
routes, DNS, reachability, RFC1918 address class, and sudo access are not treated
as authorization.

## Targeted verification performed

| Verification | Result |
|---|---|
| Exact manifest/checksum/payload/path audit | PASS; exact identities above, 210 entries, `problems: []` |
| Production precondition verifier | PASS, 210/210 |
| Python in-memory compilation and launcher `sh -n` | PASS |
| Disposable namespace integration | PASS; 10 named checks |
| Namespace authorization-negative cases | PASS; missing authorization, parent, CIDR, return-route, firewall, and DNS inputs refused |
| Namespace partial-failure recovery | PASS at every diagnostic and research creation step |
| Namespace rollback isolation | PASS in both directions; the other namespace state/digest was unchanged |
| Dual-stack containment | PASS; exact synthetic endpoints allowed, wrong ports and non-authorized endpoints denied |
| Host address/route/rule preservation during namespace test | PASS |
| Exact staged package postconditions | PASS, 210/210 |
| Focused worker/IPC/target/research/model/runtime/artifact tests | PASS, 50/50 in 5.409 s |
| Disposable production-copy migration plan | PASS; only core 0036, 0037, 0038, 0039 |
| Disposable forward migration | PASS; head 0039, integrity `ok`, zero FK violations |
| Disposable reverse migration | PASS; head 0035, integrity `ok`, zero FK violations, byte-identical `sqlite_master` schema digest |
| Disposable package apply/post-verify | PASS; 210 entries applied and 210/210 postconditions |
| Disposable package rollback/pre-verify | PASS; 201 additions removed, 9 shared files restored, no leftover directories, 210/210 preconditions |
| Rendered diagnostic/research nft syntax | PASS with `nft -c`; no rules loaded |
| Rendered systemd unit syntax | PASS on disposable copies with `ExecStart=/usr/bin/true` substituted for the not-yet-installed future venv command; no unit installed |
| Offline systemd security analysis | PASS; diagnostic 1.4 OK, runtime 0.6 SAFE, research 1.5 OK |

Disposable evidence remains at `/tmp/nmas-210-acceptance-BHJb9d`,
`/tmp/nmas-210-apply-O8UCut`, and `/tmp/nmas-210-render-r9rjut`. These paths
contain test copies and simulated render output, not production configuration or
authorization.

Broad NMAS regressions were not repeated because the 210 delta does not change
the application, migrations, workers, IPC, target policy, or broker. The focused
50-test run and the existing accepted 205 evidence cover those unchanged
boundaries; the new lifecycle code received its own root integration suite.

## Production preservation result

Final read-only inspection established:

- production Git HEAD remains
  `129d3f090f8b94b982178b1e8f3ec51047278068` on
  `deploy/lab8-production-20261102`; its same pre-existing 13 modified and 3
  untracked paths remain present;
- production database remains at
  `0035_v2_phase7_9_decommission_dynamic`, with `integrity_check=ok`, zero
  foreign-key violations, 88 tables, and schema SHA-256
  `d0c55100ddcf908f5b259c4538f7c49c76da1aaa8cfefdcdcec320a673866a39`,
  matching the consistent pre-test copy;
- VM1 routes, policy rules, and normalized nftables digests match the initial
  snapshot; SSH still listens on IPv4 and IPv6 port 22. Raw address JSON contains
  changing lease-lifetime counters and is not used as a stable digest;
- no `nmas-ts-diagnostic` or `nmas-ts-research` namespace and no installed
  `nmas-ts-*` unit appeared;
- `nmas-web` and all four existing timers remain active. Timer-driven oneshot
  services retain their normal inactive/running cycle; the observed demo
  telemetry run completed successfully and no service command was issued by
  this acceptance;
- localhost `/healthz` and `/accounts/login/` return 200; the expected
  pre-deployment `/troubleshooting/` remains 404;
- all 15 `clab-srlceos01-*` containers remain `Up`; no Containerlab lifecycle or
  device command ran.

The production database can receive normal background collector writes, so a
stable whole-file hash is deliberately not claimed. No production schema,
migration, release file, service definition, or network policy changed.

## Missing approvals and values

The authoritative minimum gate is
`final-production-go-no-go.md`. In summary, all of the following remain missing:

1. Application change-window authorization, named operator/reviewer, approved
   backup/restore/quiescence plan, install paths/owners, and rollback owners.
2. University/infrastructure confirmation of VM1 and protected IPv4/IPv6
   boundaries, lab prefix ownership, recovery/OOB method, and whether the
   required namespace/cgroup/nft mechanisms are permitted.
3. Separate diagnostic and research parent interfaces/VLANs, unique non-host
   source CIDRs, gateways, return routes, upstream ACLs, protected sets, and
   attributable approvals for each enabled family.
4. A current per-device `ManagementPath` with verified identity, topology and
   lifecycle/admission state, exact address/port/source binding, host-key pin,
   credential reference, health, operation family, expiry, owners, and named
   approvers. Production currently has no approved path; R5 remains excluded.
5. Approved research resolvers/transports, direct-HTTPS or proxy decision,
   exact hostname allowlist, privacy/logging/retention decision, and public
   egress approval.
6. Dedicated service identities, exact UIDs/GIDs/ownership, three independent
   IPC-key lifecycles, model-broker ownership/provider/TLS/privacy controls, and
   final live read-only acceptance evidence.

## Prepared operator sequence — not authorized or executed

The operator must replace every `@...@` only from signed change records. An
unresolved placeholder is a stop condition.

```sh
PKG=/home/student/Scripts/nmas-independent-namespaces-release-20261115T050919Z/package
PROD=/home/student/Scripts/clab_dualstack_lab-deploy
PY=/home/student/Scripts/.venv/bin/python
ENTRIES=5dab9de7e6af5d29fcfb23bb194ae65bde944c276f72cb8b3afe2c6bc0bd520f
CHG=@APPROVED_APPLICATION_CHANGE_ID@
BK=@APPROVED_ROOT_ONLY_BACKUP_DIRECTORY@
DJ="sudo systemd-run --uid=student --gid=student --wait --collect --pipe -p WorkingDirectory=$PROD/web -p EnvironmentFile=/etc/nmas/nmas-web.env $PY manage.py"
```

Read-only application entry checks:

```sh
cd "$PKG" && sha256sum -c SHA256SUMS
sha256sum "$PKG/manifest.json"
python3 -I "$PKG/nmas_compat_overlay.py" verify --package "$PKG" --tree "$PROD" --phase pre
git -C "$PROD" rev-parse HEAD
git -C "$PROD" status --short --branch
$DJ showmigrations core
```

Only after application authorization, approved quiescence, and OOB readiness:

```sh
sudo systemctl stop nmas-maintenance-tick.timer nmas-probation-soak-tick.timer nmas-credential-rotation.timer nmas-demo-telemetry.timer
systemctl is-active nmas-maintenance-tick.service nmas-probation-soak-tick.service nmas-credential-rotation.service nmas-demo-telemetry.service
sudo systemctl stop nmas-web.service
python3 -I "$PKG/nmas_compat_overlay.py" db-backup --db "$PROD/web/db.sqlite3" --out "$BK/db.pre-$CHG.sqlite3"
python3 -I "$PKG/nmas_compat_overlay.py" source-archive --production "$PROD" --out "$BK/source.pre-$CHG.tar.gz"
python3 -I "$PKG/nmas_compat_overlay.py" apply --package "$PKG" --production "$PROD" --backup-dir "$BK/apply" --change-id "$CHG" --confirm "${ENTRIES:0:16}"
python3 -I "$PKG/nmas_compat_overlay.py" verify --package "$PKG" --tree "$PROD" --phase post
$DJ check
$DJ makemigrations --check --dry-run
$DJ migrate core 0039 --plan
$DJ migrate core 0039 --noinput
$DJ showmigrations core
```

The migration plan must contain only 0036–0039. Start only the previously
existing application unit and timers after DB and application checks pass;
workers, sockets, namespaces, policies, research hosts, and model settings stay
inactive.

Application rollback, after stopping only package-importing processes and
exporting any post-deployment Troubleshooter data that must be retained:

```sh
$DJ migrate core 0038
$DJ migrate core 0037
$DJ migrate core 0036
$DJ migrate core 0035
python3 -I "$PKG/nmas_compat_overlay.py" rollback --journal "$BK/apply/journal.json" --db "$PROD/web/db.sqlite3"
```

If migration reversal fails, use only the approved restore decision; it loses
writes since the backup:

```sh
python3 -I "$PKG/nmas_compat_overlay.py" db-restore --backup "$BK/db.pre-$CHG.sqlite3" --db "$PROD/web/db.sqlite3" --confirm @BACKUP_SHA256_PREFIX_AT_LEAST_12_HEX@
python3 -I "$PKG/nmas_compat_overlay.py" rollback --journal "$BK/apply/journal.json" --db "$PROD/web/db.sqlite3"
```

Namespace commands are separate privileged changes. Use the same retained,
root-owned config throughout each lifecycle:

```sh
sudo deploy/sandbox/namespace-activate.sh preflight diagnostic /etc/nmas/diagnostic-namespace.env
sudo deploy/sandbox/namespace-activate.sh activate diagnostic /etc/nmas/diagnostic-namespace.env
sudo deploy/sandbox/namespace-activate.sh validate diagnostic /etc/nmas/diagnostic-namespace.env

sudo deploy/sandbox/namespace-activate.sh preflight research /etc/nmas/research-namespace.env
sudo deploy/sandbox/namespace-activate.sh activate research /etc/nmas/research-namespace.env
sudo deploy/sandbox/namespace-activate.sh validate research /etc/nmas/research-namespace.env
```

Rollback only the selected namespace after stopping and confirming exit of only
its worker:

```sh
sudo deploy/sandbox/namespace-activate.sh rollback research /etc/nmas/research-namespace.env
sudo deploy/sandbox/namespace-activate.sh rollback diagnostic /etc/nmas/diagnostic-namespace.env
```

Never run both rollback commands by default. Run only the one authorized for the
affected namespace, then compare VM1 SSH, addresses, routes/rules, global
firewall, Docker/Containerlab, NMAS units, and the other namespace to baseline.

## Final disposition

**TECHNICALLY_ACCEPTED — EXTERNAL_AUTHORIZATION_PENDING**

