# Stage B activation proposal

Evidence date: 2026-11-15/16 (America/Denver). This is an owner-review bundle,
not an activation record. No live namespace, nftables table, NAT rule, user,
unit, ManagementPath, device session, model or fault action was activated.

Activation refinement: the exact zero-target/research-only command sequence,
empty-diagnostic controller limitation, current DNS revalidation, resolver-root
ownership and corrected four-file DNS-integration overlay are in
`stage-b-final-fail-closed-activation-plan.md`.

## Decision state

Production has zero approved ManagementPaths, zero approved/verified NMAS-side
attachments and zero approved/verified device MANAGEMENT attachments. Therefore
the approved-eligible diagnostic set is empty. The exact conditional batch is:

| Device | Platform | Static management endpoint | Frozen attachment | Captured key candidate |
|---|---|---|---|---|
| R1 | Arista cEOS | `192.168.200.1:22/tcp` | `Ethernet3 -> mgmt_swt:Ethernet1`, access VLAN 200 | `SHA256:y8B6G1mNVvWqLtA2Tg+PJRykEnfm1/tD2ftr+syJ9JI` |
| R2 | Arista cEOS | `192.168.200.2:22/tcp` | `Ethernet3 -> mgmt_swt:Ethernet2`, access VLAN 200 | `SHA256:OyuxmXszJ9liLZjlWuKOvoKhGCxuryrmLDf0GIB4dtk` |
| S1 | Arista cEOS | `192.168.200.11:22/tcp` | `Ethernet5 -> mgmt_swt:Ethernet5`, access VLAN 200 | `SHA256:xXEM3ufwHxXNZj7yvS95DqCduvfsLp+emRKHYTYI2fg` |
| S2 | Arista cEOS | `192.168.200.12:22/tcp` | `Ethernet5 -> mgmt_swt:Ethernet6`, access VLAN 200 | `SHA256:gP+fDNPL/e7fhS5B9Gv3k5GJTD/51mmlBUvNcaT/xh0` |
| S3 | Arista cEOS | `192.168.200.13:22/tcp` | `Ethernet4 -> mgmt_swt:Ethernet7`, access VLAN 200 | `SHA256:KQy/cTH2PcNWzDJgwsOiV0+29hHRO/8HkxOuRMB1NGo` |
| S4 | Arista cEOS | `192.168.200.14:22/tcp` | `Ethernet4 -> mgmt_swt:Ethernet8`, access VLAN 200 | `SHA256:zkq3EvkJx3SD/0TaC6D9U4+vCrDOX3c7JPRUJe6IrGU` |

Addresses come only from tracked `inventory.yml`; attachment interfaces come
from the frozen tracked Containerlab topology. Read-only checks found each
Vlan200 address up and SSH listening on port 22 through `nmas-mgmt`. The key
values are candidates captured through the authorized container-host channel,
not enrolled trust or an admission decision. Exact evidence hashes and blockers
are in `deploy/sandbox/stage-b/diagnostic-candidate-batch.json.proposed`.

R2 alone is already a legacy adopted row: `IN_SERVICE`,
`LEGACY_PREEXISTING`, `UNVERIFIED`. R1/S1-S4 are not adopted. `mgmt_swt` must
be legacy-adopted as the attachment upstream, but is not a target: the current
schema cannot truthfully represent the direct NMAS-host-to-same-switch path.
R3/R4 are managed-scope Ubuntu/FRR devices but the path verifier and diagnostic
consumer do not support that platform. R5, WebServer, H1-H4 and registry-only
R6/R7/R8/S5 are excluded.

## Required governed device actions

One owner change decision may authorize the batch, but it does not replace the
separation enforced by NMAS. The owner must name distinct eligible accounts for
registration, approval, observation authorization/collection and identity
verification. Under those identities, and in this order:

1. Use only **Adopt Existing Device** for R1, S1-S4 and `mgmt_swt`. Preserve
   `LEGACY_PREEXISTING`; do not grant `ADMITTED` or mark identity verified.
2. Register `nmas-mgmt`, source `192.168.200.100`, network
   `192.168.200.0/24`, upstream `mgmt_swt:Ethernet9`, failure domain
   `mgmt_swt`. A different actor approves it; `nmas_management observe`
   records the read-only host observation and must reach `VERIFIED`.
3. Register the six exact access/VLAN-200 MANAGEMENT attachments in the table.
   Different actors approve and an authorized observation independently verifies
   each. Topology/reference data alone is not verification.
4. Independently authenticate and enroll each listed host-key fingerprint under
   an ObservationAuthorization. The collector/enroller must not be the identity
   verifier. Any changed or ambiguous key stops the batch.
5. Register six `DIRECT_OOB`, SSH/22, `credential_source=INVENTORY`
   ManagementPaths against the approved NMAS attachment and matching device
   attachment. A different actor approves each path.
6. Collect authenticated-session identity evidence and have the independent
   verifier approve it. Do not convert an identity based only on inventory or a
   discovered address.
7. Run the existing read-only path evaluator. Only paths that become
   `APPROVED + HEALTHY + ACTIVE` enter the final diagnostic manifest. If any
   path fails, remove its tuple and regenerate/reapprove both nft/config hashes;
   do not widen the policy.

## Research policy proposed for owner review

VM1 currently uses the default route through `ens33` via `10.224.76.1`.
systemd-resolved reported these ens33 resolver candidates: `128.138.129.76`,
`128.138.130.30`, `128.138.240.1`. They are candidates, not authorization.

| Hostname | Reviewed IPv4 TCP/443 tuples |
|---|---|
| `docs.frrouting.org` | `104.16.253.120:443`, `104.16.254.120:443` |
| `www.arista.com` | `199.232.66.132:443` |
| `www.rfc-editor.org` | `104.18.20.81:443`, `104.18.21.81:443` |

IPv6 is disabled. The application requires the hostname and every DNS answer to
match `research-destinations.json.proposed`, repeats the check across redirects,
connects to a reviewed literal address with TLS SNI/hostname verification, and
permits GET/HEAD textual responses only. Namespace and host nftables separately
allow DNS only to the three candidate resolvers and HTTPS only to the five exact
address/443 tuples. All other destinations fail closed, so an unknown university
public CIDR cannot broaden access. A changed DNS answer is a stop condition and
requires a regenerated, newly approved policy. There is no shell, proxy
environment, upload, credential, downloaded-code execution or device transport.

## Exact artifacts and worker installation

Review identities:

| Artifact | SHA-256 |
|---|---|
| `diagnostic-candidate-batch.json.proposed` | `17e0e3ed6408de6aa668c39dab6dd92460f3dd136cf63331c78648cc0fa1b96a` |
| `diagnostic-egress.nft.proposed` | `b166c4d7554750c0894ddc3d741cf8925d3f47e51f18302bff8739ce11d978ee` |
| `diagnostic-namespace.env.proposed` | `ea320f260659aaf549de5a4cd920ccb4439075e3553b303e399cdb5c63f2fbe4` |
| `research-destinations.json.proposed` | `945a47225fbc351c3dc5106e15d9dbc9d38c86ae9ae566ff884a752dd893d548` |
| `research-egress.nft.proposed` | `49e1f29de49a3a0a9bfc1b1c6a7cea9c855d8b119d241f2fae1a71379fb26970` |
| `research-namespace.env.proposed` | `2f0a9e24f1824b8bc2bde83bc0acf7210d1e6f6ba220a0ea07f32bb9b623183a` |
| `worker-source-manifest.json.proposed` | `b1b9c67111bede1cf4e3e9a6cac962f8a89e065179923e500ca3b3da6b835f91` |
| `worker-runtime.lock` | `71fd8820338b2ce757bac57580d445a9f95e580b48c8d175165fe4087f23bcfa` |

`worker_runtime.py` installs only `/opt/nmas/current` and `/opt/nmas/venv`,
with ownership state under `/var/lib/nmas-worker-runtime`. The source manifest
binds 1,964 files from the deployed, verified Stage A tree
`/home/student/Scripts/clab_dualstack_lab-deploy`; database, credentials,
runtime secrets, Git data and generated caches are excluded. The isolated venv
has no pip and copies 12 exact distributions (5,234 RECORD-verified files) from
the existing production venv. It refuses source/lock drift, foreign runtime or
state objects, unexpected symlinks and dependency hash/version mismatch. A
repeat install verifies and makes zero mutations. Uninstall refuses active
worker units/namespaces, verifies the complete owned tree and removes only the
owned runtime/state.

Mutation-free review command:

```text
python3 deploy/sandbox/worker_runtime.py plan \
  --source /home/student/Scripts/clab_dualstack_lab-deploy \
  --source-manifest deploy/sandbox/stage-b/worker-source-manifest.json.proposed \
  --source-venv /home/student/Scripts/.venv \
  --lock deploy/sandbox/worker-runtime.lock
```

After approval, install with the same arguments and action `install`, then
`verify`. Install rendered, hash-reviewed copies of
`nmas-troubleshooter-device-worker.service` and
`nmas-research-broker.service`; create only the sysusers identities
`nmas-ts-diagnostic`, `nmas-research`, `nmas-ts-runtime` and their three IPC
groups. Refuse any pre-existing nonmatching file or identity. The service
templates have empty capability sets, `NoNewPrivileges`, strict filesystem and
device protection, nologin identities, no sudo/Docker/containerd access and
separate network namespaces. Do not enable `nmas-troubleshooter-runtime@`, live
models or `break.py` in Stage B.

## Exact activation sequence after all gates close

1. Record the single owner change ID and replace every `PENDING-*` approval
   marker; change `AUTHORIZATION_APPROVED` to `yes` only after the governed rows
   above exist. Re-render diagnostic targets from the six approved paths and
   confirm the hashes still match, otherwise return for approval.
2. Install/verify the worker runtime. Install root-owned mode-0600 rendered env
   and nft files under `/etc/nmas`, exact rendered service units, and sysusers;
   run `systemctl daemon-reload`. Units remain disabled/stopped.
3. Run mutation-free `preflight` and `host-policy` review for diagnostic, then
   research. Confirm `nmas-mgmt`, `ens33`, existing forwarding, exact nft
   digests, no foreign object collision and IPv6 disabled.
4. Activate and validate `diagnostic` with
   `namespace-activate.sh`; start only
   `nmas-troubleshooter-device-worker.service`; validate the unit and exact
   six-target containment.
5. Activate and validate `research`; start only
   `nmas-research-broker.service`; validate the unit, exact DNS/HTTPS sets,
   redirect/DNS fail-closed behavior and private/host/VM2/Containerlab denial.
6. Record health, namespace ownership and baseline evidence. Do not alter
   `ens33`, `nmas-mgmt`, host routes, SSH, Docker, Containerlab or routing.

## Independent rollback

1. Stop/disable the affected worker unit and prove no process remains in that
   namespace.
2. Run `namespace-activate.sh rollback research ...` or
   `namespace-activate.sh rollback diagnostic ...` independently. Exact state,
   activation ID, digest and ownership markers are required; never flush a
   foreign table or broadly delete namespaces.
3. Remove only rendered env/unit/nft files whose hashes match the installation
   receipt, then `systemctl daemon-reload`. Retaining locked nologin sysusers is
   safe; account removal needs a separate verified ownership/no-files decision.
4. Once both units are inactive and both namespaces absent, run
   `worker_runtime.py uninstall` with the same manifest/lock arguments. It
   refuses drift and foreign objects. Existing production source, venv, DB and
   services are never removed or overwritten.
5. Re-run the host baseline checks. Marker mismatch, cleanup refusal or runtime
   drift is an escalation condition, not authority for broad recovery. No
   recovery guarantee is asserted without the owner's maintenance/OOB plan.

## Focused verification observed

- Inventory/admission/platform/exclusion disposable test: PASS; live read-only
  report produced zero approved endpoints and the six exact candidates above.
- Research broker, worker and sandbox artifact Django tests: PASS, 28/28.
- Worker runtime install/idempotency/drift/foreign-object/symlink/rollback test:
  PASS; production-source plan: 1,964 source files, 12 dependencies, 5,234 files,
  zero mutations.
- Namespace integration: PASS, 18 groups including exact target/port controls,
  DNS/HTTPS allowlists, private/campus/host denial, IPv6 containment, independent
  rollback, every-step failure cleanup, ownership preservation and unchanged
  real-host address/route/rule/firewall/SSH/namespace baseline.
- Proposed nft syntax and env/schema/digest checks: PASS; diagnostic hard-disable
  and incomplete-configuration fail-closed behavior observed.
- Post-test read-only regression: `nmas-web`, existing NMAS collectors/runners,
  rsyslog/SNMP services remained active; all frozen Lab 1 containers remained
  running; the two proposed worker units remained inactive.

## Inputs still required in one owner response

Approve or reject change `CHG-NMAS-20261115-STAGE-B-001` as the exact bundle
above and provide: the attributable authorization/change ID; named distinct
NMAS registrar, endpoint/attachment approver, observation authorizer/collector
and identity verifier accounts; explicit selection of the three resolver
candidates and three hostname/five-address HTTPS policy; authorization for the
two VM-local veths, owned nftables tables and the stated diagnostic SNAT/research
masquerade; maintenance window and actual console/OOB recovery arrangement.

That consolidated owner response authorizes the change workflow only. NMAS must
still record the separated per-row decisions and successful observations. Until
then both proposed env files retain `AUTHORIZATION_APPROVED=no`, no live install
or activation is permitted, and Stage B remains blocked.

`STAGE_B_BLOCKED — consolidated owner authorization, named separated governance actors, endpoint admission/verification, resolver/research-policy selection, and maintenance/OOB inputs remain`
