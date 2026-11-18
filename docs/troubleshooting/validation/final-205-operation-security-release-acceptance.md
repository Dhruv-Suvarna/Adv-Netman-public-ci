# NMAS V2 sandbox-worker release acceptance

Date: 2026-11-14 (America/Denver)

## Decision summary

The submitted 203-operation package is **technically rejected and must not be
activated**.  Its identity is intact, but the runtime systemd unit makes the
SQLite database file writable while leaving its parent directory read-only.
The production database uses SQLite `journal_mode=delete`; a disposable
production copy proved that the first write fails with `OperationalError:
attempt to write a readonly database` because SQLite cannot create its rollback
journal.

Submitted package identity:

- path: `/home/student/Scripts/nmas-sandbox-workers-release-20261114T212024Z/package`
- entries: 203 (194 ADD, 8 REPLACE, 1 MERGE)
- entries identity: `cab1ac29d8be78b11dc9ecfa130843634a754049afe6c7dd012fef3e25d091d1`
- manifest SHA-256: `75010e99e83b49a9a562caa8305cf363214490bd298251f473913f6492b7d596`
- manifest problems: none
- checksum verification: PASS

A new immutable successor package was therefore built.  The submitted package
was not modified or reused.

Successor package identity:

- path: `/home/student/Scripts/nmas-sandbox-workers-release-20261114T220008Z/package`
- entries: 205 (196 ADD, 8 REPLACE, 1 MERGE)
- entries identity: `514f49bafd8aa38d178c4c36e275f85211867fc3f00ae600b59284800dd63ddc`
- manifest SHA-256: `dfbe2f5e8b589c63853ee8f823b6adf08a682da3126d923b3091f856b2330352`
- manifest problems: none
- checksum verification: PASS

The successor is **technically accepted only for application-package review and
inactive staging**.  It is **not university-authorized, operationally activated,
or live-containment verified**.  Namespace, firewall, systemd worker, live
device, research egress, and model-provider activation remain NO-GO until the
owner inputs and approvals in this report are supplied.

## Scope and restrictions observed

The review covered the environment reconstruction, trust-boundary matrix,
worker and web implementation, package overlay, sandbox artifacts, tests,
compatibility rollout, migration, and rollback material.  All manifest entries
were independently enumerated and security-sensitive source was traced across
the web/runtime, diagnostic, research, model-provider, database, and Change
Engine boundaries.

No ESXi, vCenter, university infrastructure, other students' VMs, or live
network devices were contacted.  No namespace, nftables policy, systemd worker,
or production migration was activated.  No topology lifecycle command was run.
Production and topology inspection was read-only.  Rendered nftables policies
were syntax-checked only.

## Findings and implementation disposition

### Submitted 203-operation package: blocking defect

The original runtime unit bound only `web/db.sqlite3` into a code tree protected
by read-only filesystem controls.  SQLite's rollback-journal file is created in
the database's parent directory, so the apparent writable database binding does
not provide a writable SQLite database.  This is a deterministic production
runtime blocker, not a documentation concern.  The submitted package remains
immutable and rejected.

### Successor database isolation

The successor binds the production `web` directory at the private runtime alias
`/var/lib/nmas-ts-runtime/dbroot`, preserving SQLite lock and journal semantics
against the same underlying directory.  Runtime settings accept only
`/var/lib/nmas-ts-runtime/dbroot/db.sqlite3` when restricted mode is enabled;
another path raises `RuntimeError`.  Known code, configuration, static, and
backup entries under the alias are made inaccessible by the unit.

Residual risk: SQLite cannot give per-table operating-system authorization, and
the runtime must be able to create SQLite journal files in the aliased database
directory.  The trusted runtime code and SQL policy wrapper remain the
application enforcement layer.  Any unexpected non-SQLite sibling file created
there is an immediate stop condition.  The infrastructure owner and security
reviewer must explicitly accept this residual before activation.

### Completion-only model-provider adapter

The successor adds a fixed, completion-only authenticated Unix-socket adapter:

- exact socket: `/run/nmas-ts-model/provider.sock`
- distinct IPC kind and HMAC key from diagnostic and research workers
- bounded `ai-model-request/1` and `ai-model-response/1` envelopes only
- exact configured provider/model identity match
- no arbitrary RPC method, command, destination, URL, shell, Docker, device
  credential, or network SDK surface

The adapter only requests completion text.  The external provider broker is not
included or activated and must run under a separate identity and authority.
Model access therefore remains separate from shell, Docker, device, and
research capabilities.

### IPC authentication, replay, and separation

Diagnostic, research, and model IPC use separate sockets, message kinds, keys,
service identities, and systemd groups.  Requests are bounded and authenticated;
timestamps/nonces are checked and replayed nonces are rejected.  Peer UID checks
fail closed.  A diagnostic envelope presented to research was rejected both
with a wrong key and, when correctly signed under the research key, with
`PROTOCOL_MISMATCH`.  Model tests likewise show that research identity/key and
the wrong model identity cannot impersonate the completion broker.

The diagnostic process has no research egress authority.  The research process
has no inventory database, device credential, SSH, or diagnostic socket
authority.  The runtime has AF_UNIX-only networking and no device credential,
Docker socket, or direct research-network capability.

### Target authorization and diagnostic privilege

The web request does not carry a raw command, credential, arbitrary endpoint,
or configurable transport.  The diagnostic worker independently resolves the
current approved SSH management path, checks lifecycle and target policy,
requires the expected host-key pin and source binding, acquires the credential
through the credential broker, and revalidates authorization around use.
Unhealthy, stale, unapproved, lifecycle-ineligible, or protected targets fail
closed.

The rendered diagnostic kernel policy is an exact destination-address and
destination-port allow policy plus cgroup address controls.  It is not active,
and its final source address, route, ownership, and protected destinations are
unknown.  Consequently this review does not claim live diagnostic containment.

### Research egress

Research is HTTPS-only to an exact, empty-by-default hostname allowlist.  The
worker rejects credentials in URLs, non-HTTPS schemes, unsupported methods,
private/reserved/special address results, unsafe content, oversized responses,
and unauthorized redirects.  DNS is resolved and revalidated, TLS uses the
authorized hostname, response handling is bounded, and environment proxies are
not inherited.  The staged firewall permits only approved DNS resolver traffic
and public TCP/443 while dropping protected address space.

Resolver addresses and exact research hosts were deliberately not guessed.
The policy is not active, so live research containment is not claimed.

### Change governance

The AI runtime exposes read-only/terminal model tools only.  Proposal/write
tools are not present in the model tool set.  `APPLY_CHANGE` is always handed
off or refused; the default executor is unconfigured, and the Change Engine
executor remains a governed handoff rather than an alternate writer.  The NMAS
Change Engine remains the sole configuration-write authority.  Device policy,
eligibility, lifecycle, isolation, commissioning, and execution regression
tests passed.

## Verification evidence

| Check | Result |
|---|---|
| Submitted identity and checksum set | PASS; exact expected values |
| Successor identity and checksum set | PASS; new immutable identity |
| Manifest path uniqueness/traversal/symlink/payload hash audit | PASS |
| Successor pre-verify against production tree | PASS, 205/205 |
| Successor staged post-verify | PASS, 205/205 |
| Python compilation | PASS |
| Focused successor source tests | PASS, 27/27 |
| Full Troubleshooter source suite | PASS, 774/774 |
| Staged successor package suite | PASS, 135/135 |
| Cross-domain preservation suite | PASS, 395/395 |
| Disposable production DB migrations 0036 through 0039 | PASS |
| Migrated DB integrity / foreign-key check / expected head | PASS / 0 violations / 0039 |
| Scratch apply/post-verify/rollback/pre-verify | PASS, 205/205 restored |
| Rendered diagnostic and research nftables syntax | PASS |
| Rendered systemd unit syntax/security analysis | PASS with expected absent future venv-binary warnings |
| systemd security exposure scores | diagnostic 1.4 OK; research 1.5 OK; runtime 0.6 SAFE |
| Production package application or migration | NOT RUN (prohibited) |
| Live namespace/firewall/service/device containment | NOT RUN (authorization and inputs absent) |

Test qualifications:

- An initial full-suite invocation used slash paths where the Django runner
  requires module labels; this was a harness invocation error.  The corrected
  full run passed 771/771 on the submitted tree and 774/774 after the successor
  changes.
- One staged IPC run returned signed `WORKER_UNAVAILABLE` rather than the more
  specific signed `PEER_UID_REFUSED` when the peer closed the Unix socket.  Both
  outcomes are fail-closed.  The exact IPC suite then passed 12/12 five
  consecutive times, and the complete staged suite passed 135/135.
- An intentionally broad legacy production-suite selection encountered the
  already documented baseline mismatch between legacy tests and the dirty
  production source and was stopped.  It is not counted as successor evidence.

Static review found no deployed Python shell/subprocess execution primitive.
Network-capable imports were limited to the research implementation, AF_UNIX
IPC/URL parsing, the pre-existing authorized SSH management transport, and
tests.  Migration files contain no `RunPython`, `RunSQL`, subprocess, or socket
operation.  Credential scanning found only schema/test literals; no runtime
credential or API token was placed in source or either package.

## Production and VM1 preservation result

Before/after evidence shows:

- production checkout HEAD and its pre-existing dirty status: unchanged
- IP addresses (ignoring lease lifetimes), routes, and policy rules: unchanged
- nftables ruleset (ignoring dynamic counters and handles): unchanged
- seven observed NMAS service active states: unchanged
- no `nmas-ts-*` unit installed
- no diagnostic or research network namespace created
- all 15 `clab-srlceos01-*` topology containers remained `Up`
- no topology deploy, destroy, restart, or configuration operation occurred

The production database was not byte-for-byte static because an already active
collector continued normal work during the multi-hour review.  Comparing the
initial production copy with a consistent final snapshot found the same 87
tables, row counts, schema head 0035, integrity result, and zero foreign-key
violations.  Exactly one table changed: one existing DHCP lease observation
advanced only `last_seen` and `seen_count`.  No release migration, schema
change, or package write ran against production.  Thus release validation left
the production database structurally unchanged, but this report deliberately
does not claim a stable file hash.

The final read-only service check returned 200 for `/healthz` and
`/accounts/login/`, and the expected pre-deployment 404 for
`/troubleshooting/`.  A final privileged, read-only nftables capture matched
the initial ruleset after removing dynamic counters and rule handles.  No rule
was applied by this review, no NMAS sandbox namespace or unit exists, and the
rendered candidate policies were checked only off-line.  These limits reinforce
that live containment remains unverified.

## Infrastructure-owner inputs required before activation

Activation must stop until the owner supplies all applicable items below in a
reviewed change record.  Values must not be inferred from the current host.

1. The authoritative VM1 management interfaces, addresses, default route,
   source-selection rules, SSH management endpoint, and complete protected
   destination set.
2. Ownership and approval for every diagnostic device destination IP and port,
   the device/lab scope, and explicit exclusions (including R5 where required).
3. Dedicated diagnostic and research source CIDRs, namespace parent interfaces,
   gateways, uniqueness confirmation, return routing, and upstream ACLs.  They
   must not reuse an existing VM1 address.
4. The authoritative university-protected networks and assets, including
   ESXi/vCenter, other student networks, metadata endpoints, shared services,
   and any other forbidden infrastructure.
5. Exact approved DNS resolver IPs, their ownership, namespace reachability,
   permitted transport, and proxy/no-proxy policy.
6. Exact research hostnames and the privacy/data-handling approval for content
   sent to or received from them.
7. The active approved ManagementPath records: device identity, address/port,
   source binding, host-key pins, credential references, lifecycle state, and
   named approvers.
8. Model-broker ownership and design: service UID/GID, socket ownership at
   `/run/nmas-ts-model/provider.sock`, runtime membership, IPC key creation,
   distribution and rotation, exact provider/model identity, provider
   destination/TLS/privacy controls, and confirmation the broker has no shell,
   Docker, or device authority.
9. Production install root, Python virtual-environment executable, file owners
   and modes, allocated service UIDs/GIDs, and runtime/state-directory ownership.
10. Approved maintenance window, user impact/downtime, console or out-of-band
    recovery, named operator and reviewer, and two-person authorization where
    university policy requires it.
11. Database backup, retention, encryption, restore-test, and export decisions,
    including how concurrent web writes are quiesced for migration and rollback.

## Activation checklist

No item below was executed by this review.

### Gate A: application package

- [ ] Reconfirm successor entries identity and manifest SHA-256 from this report.
- [ ] Confirm production still pre-verifies 205/205 and review every local dirty
      overlap.
- [ ] Quiesce approved writers; make and restore-test a database and source
      backup.
- [ ] Stage, inspect the exact diff, apply, migrate only through 0039, and run
      integrity and foreign-key checks.
- [ ] Start only the existing application service and verify health, login,
      monitoring, topology inventory, and existing change workflows.

**Stop/rollback:** any identity mismatch, dirty-file conflict, backup failure,
unexpected migration, integrity/foreign-key error, service regression, topology
change, or credential discovery.  Stop new processes, restore the database
backup first when migration ran, run the package rollback, restore the source
archive if needed, and re-verify the prior service baseline.

### Gate B: identities, secrets, and inactive units

- [ ] Create only the reviewed service users/groups and exact runtime directories.
- [ ] Generate distinct high-entropy diagnostic, research, and model IPC keys;
      install through the approved secret mechanism with reviewed ownership.
- [ ] Install rendered units and environment files without enabling or starting
      them; repeat `systemd-analyze verify` and security review on the target.
- [ ] Confirm the model broker is separately owned and has completion-only
      authority before adding runtime socket access.

**Stop/rollback:** reused key, broad group membership, unexpected supplementary
group, secret in arguments/logs/source, writable unit or code, wrong UID/GID, or
unexpected socket owner.  Remove the inactive artifacts and rotate exposed keys.

### Gate C: namespaces, routing, and firewall

- [ ] Obtain all university/network-owner inputs above and render with exact
      source, gateway, resolver, protected-network, device, and host values.
- [ ] Review routes and nftables output line by line with the infrastructure
      owner; syntax-check and capture the pre-change ruleset.
- [ ] Activate in the approved window with console recovery and test denied
      destinations before allowed destinations.

**Stop/rollback:** source conflict, ambiguous subnet ownership, missing protected
range, default-route leak, private/reserved research reachability, management
loss, unexpected DNS/proxy path, or access to an unauthorized device.  Stop
workers, remove only the named sandbox rules/namespaces using the reviewed
rollback, and restore the captured network baseline.

### Gate D: diagnostic device access

- [ ] Approve each ManagementPath, host-key pin, credential reference, source,
      device, and command family.
- [ ] Start the diagnostic worker only; prove research/model sockets and public
      Internet are unreachable from it.
- [ ] Test an approved disposable target and explicit protected/unauthorized
      targets with audit evidence.

**Stop/rollback:** stale authorization accepted, wrong source, host-key mismatch,
credential leakage, command outside the allowlist, unauthorized destination, or
replay accepted.  Stop the worker, revoke/rotate affected credentials and IPC
key, and remove diagnostic namespace policy.

### Gate E: research egress

- [ ] Approve exact hostnames, resolvers, privacy terms, and content constraints.
- [ ] Start the research worker only; prove diagnostic, database, credentials,
      model socket, private networks, and non-443 destinations are unreachable.
- [ ] Test DNS rebinding, redirects, private results, oversize and unsafe content,
      proxy variables, and unauthorized hosts under live policy.

**Stop/rollback:** any private/protected reachability, hostname bypass, proxy
inheritance, unsafe redirect, credential-bearing URL, or unexpected egress.
Stop the worker, remove research namespace policy, and preserve audit evidence.

### Gate F: model broker and runtime

- [ ] Verify exact broker provider/model identity, socket owner/mode, distinct
      key, response limits, privacy controls, and lack of shell/Docker/device
      authority.
- [ ] Start runtime with AF_UNIX-only networking; prove it cannot reach device,
      research, Docker, credential, or arbitrary Unix sockets.
- [ ] Confirm read-only AI tools and Change Engine handoff; inspect the production
      database directory for only expected SQLite database/journal artifacts.
- [ ] Perform live containment tests and obtain the named security and university
      sign-offs before declaring the service operational.

**Stop/rollback:** arbitrary RPC, provider/model mismatch, shell/Docker/device
capability, direct write outside Change Engine, unexpected database sibling
file, runtime network egress, cross-worker access, replay acceptance, or missing
audit event.  Stop runtime and broker, rotate the model IPC key, remove socket
access, and roll back application/database changes under Gate A if required.

## Final release separation

- **Submitted 203-operation package technical acceptance:** REJECT / NO-GO.
- **Successor 205-operation application package technical acceptance:**
  CONDITIONAL GO for independent review and inactive staging only.
- **University authorization:** NOT GRANTED / REQUIRED.
- **Operational activation:** NOT PERFORMED / NO-GO pending all gates and inputs.
- **Live containment verification:** NOT PERFORMED / cannot be claimed until
  owner-approved namespaces, firewall, services, sources, resolvers, device
  paths, and provider broker are activated and tested in the approved window.

This separation is mandatory: passing offline implementation and compatibility
tests does not authorize university infrastructure access and does not prove
live containment.
