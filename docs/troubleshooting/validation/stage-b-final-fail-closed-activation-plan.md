# Stage B corrected research activation plan

Change: `CHG-NMAS-20261115-STAGE-B-001`

Status: the authorized 2026-11-16 17:54 MST retry proved compatibility with the
actual preserved schema-v2 receipt and prepared a new resolver generation, but
was ownership-scoped rolled back before network activation when the reviewed
host-policy comparison artifact retained the obsolete v2 ownership-marker
digest. The comparison artifact is corrected and byte-matches the authorized
controller's generated v3 policy. A live retry still requires an exact owner
approval and current maintenance window; no prior authorization is reusable.

The 2026-11-16 operator-facing website deployment changed twelve reviewed
production-source files and created transient `web/var/device-locks` during
regression. The runtime builder now excludes all `web/var/` state, a regression
proves that exclusion, and the source/release manifests were regenerated from
the exact post-deployment production tree. This supersedes release COMPLETE-05
without changing the namespace controller, resolver, broker, nftables policy,
destinations, systemd unit, or rollback design.
The follow-up intake integration added an authoritative inventory/topology
selector and updated three existing UI/test paths. COMPLETE-09 binds that exact
deployed source; it changes no research-network artifact.
See the 17:54 MST section in `nmas-v2-final-operational-acceptance.md`.
The 2026-11-16 19:57 MST source update `CHG-NMAS-20261116-FINAL-WEB-003` (model brokers, lease-bound dispatch, AI
escalation page) added fourteen production files and changed fourteen. COMPLETE-10 binds that exact 1,971-file tree and
supersedes COMPLETE-09 (`05ce9cc1…696bad`, source manifest `1d5e4934…efba9`). The controller, overlay, resolver, research
broker, nftables policies, destinations and systemd unit are byte-identical to COMPLETE-09.

Diagnostic activation remains prohibited because `TARGETS` is empty. Live AI
models, autonomous device writes, `break.py` and
`nmas-troubleshooter-runtime@` remain outside this plan.

## Corrected release identity

The immutable Stage A 218-operation release is unchanged. Stage B installs the
existing reviewed worker runtime plus the following complete, content-addressed
activation release. The release manifest binds the overlay and every generated
or reviewed deployment dependency, so a stale comparison artifact cannot be
approved independently of its controller:

| Artifact | SHA-256 |
| --- | --- |
| `research-activation-release.json` | `bbb0da54a5bbc0196ebd3db809dbb11e7820b5e5285ac23359e3bf85e9c56057` |
| `research_release.py` | `6fb08198896ff5f4d6797a2bc4d73bd1c71bca8966d205e8f7252f8116382958` |
| `worker-source-manifest.json.proposed` | `5093674fec9064d4e287c103a9acfdc81d1e7df2288bbe2549581827f74e818b` |
| `worker_runtime.py` | `d25a017049cf62c2e432895206fff1f5252f09eb3adb5ac24b406806edf80051` |
| `worker-overlay-manifest.json.legacy-receipt-review` | `ecbfc3687bbe0c1ac7565fc6489a577f3517b5598fb9ae286306d1fa40b40430` |
| `worker-runtime.lock` | `71fd8820338b2ce757bac57580d445a9f95e580b48c8d175165fe4087f23bcfa` |
| `namespace_activation.py` | `fd375d3cc4b86cca7a8d888745122a682999ab369d501a98b543d67009a992b8` |
| `nmas-research-broker.service.in` | `f4aea87ff4cd12fe47e6efa40dc84e579dafecd9a22d213b0ebe3a20682aea89` |
| `resolver_root.py` | `35515c56d96dbc86714d232784e8dce2e0db5e949daa592da09a0ca897f066fc` |
| `research-egress.nft.proposed` | `49e1f29de49a3a0a9bfc1b1c6a7cea9c855d8b119d241f2fae1a71379fb26970` |
| `research-host-egress.nft.activation-review` | `7a1ba4249d09b896ddaedd9b3d111992925338230bdee7655ca0924d8382d0e4` |

The prior release SHA-256 `c58264ef…144a2c` is obsolete after the website
deployment. The prior overlay SHA-256 values
`45a3f5a2c084367d0d8d229580a055e7356265d62742875d72e157d45ebcfc36`
and `c037e81a17e0f31981dd72270f0fd200a48cf8a11612ffe687f490031d39349a`
and `f56dfc5c2ed067fc071522a6755e269cbe6f969f452369a3e8ae10294a37f21b`
are obsolete. The new overlay contains the same reviewed IPv4-only broker and
service template plus only the generation-aware namespace controller. The
`worker_runtime.py plan` action observed 1,971 base files, four overlay files,
12 distributions, 5,234 dependency files and zero mutations.

## DNS correction and fail-closed contract

The service uses both:

```text
NetworkNamespacePath=/run/netns/nmas-ts-research
BindReadOnlyPaths=/etc/netns/nmas-ts-research/resolv.conf:/etc/resolv.conf
```

systemd 255 supports both directives and implies a private mount namespace for
`NetworkNamespacePath=`. The bind is unit-private and read-only; it does not
modify the host's `/etc/resolv.conf` symlink or its target.

Before the broker executable runs, root-only `service-preflight` verifies:

- `/etc/netns` is the exact root-owned `0755` inode recorded by
  `/var/lib/nmas-stage-b-resolver-root.json` (`root:root 0600`);
- the receipt change ID equals the research authorization ID;
- the namespace resolver directory is root-owned `0755`, its file is a
  non-symlink root-owned regular file at `0644`, and both inode identities
  match the namespace lifecycle receipt;
- the resolver bytes are exactly the ordered `DNS_SERVERS` values;
- `/etc/resolv.conf` inside the service resolves to that same source inode;
- the process has joined the exact `nmas-ts-research` network namespace;
- the root-owned research configuration and nft policy match their reviewed
  digest; and
- IPv6 is disabled.

Any missing file, symlink, owner/mode/content/inode drift, policy drift,
namespace mismatch or bind mismatch prevents service startup. The broker still
resolves twice with `getaddrinfo(AF_INET)` and rejects empty, changed,
non-public or unapproved answers before opening TLS.

The namespace lifecycle now gives every attempt a random 128-bit generation
identifier. Before a new generation starts, the prior receipt must be in a
known inactive terminal state, have no pending step or ownership flag, and
have no matching namespace, veth, nftables table or resolver object. The exact
old root-only receipt bytes are then atomically archived under the root-only
per-kind history directory; the current receipt is never converted in place.
New ownership starts with all flags false and resource identities are bound to
the generation in the namespace/veth/table markers.

Receipt replacement is atomic and fsyncs both file and directory. Per-kind
`flock` serialization prevents concurrent activation. Namespace, host-veth,
resolver-file and resolver-directory device/inode identities are journaled
before later steps. Interrupted and partial cleanup remains blocked until the
owned generation is reconciled; old receipts cannot match or remove current
resources. Rollback is idempotent and deletes only exact owned identities.
Research `activate` now requires that the same generation already be in
`resolver-prepared`; the prohibited resolver-after-network fallback no longer
exists.

## systemd mount-namespace correction

VM1 runs systemd 255. Its installed `systemd.exec(5)` documents that a leading
`-` on a path in `InaccessiblePaths=` ignores only the missing-source case.
When the source exists, systemd still mounts it inaccessible in the service's
private filesystem namespace.

The research unit now applies that prefix to the six protection targets that
are legitimately allowed to be absent: the diagnostic environment, diagnostic
state/log directories, production database, `device_configs` and `configs`.
The three present container-runtime sockets plus reviewed inventory and
monitoring tree remain mandatory inaccessible paths. No protected path was
removed, and no service identity, capability, syscall, filesystem, namespace
or network restriction was relaxed.

## Exact research policy revalidated 2026-11-16

The current `ens33` resolver set remains:

```text
128.138.129.76
128.138.130.30
128.138.240.1
```

All three resolvers returned the same reviewed A-address set:

| Hostname | Exact allowed IPv4 TCP/443 destinations |
| --- | --- |
| `docs.frrouting.org` | `104.16.253.120`, `104.16.254.120` |
| `www.arista.com` | `199.232.66.132` |
| `www.rfc-editor.org` | `104.18.20.81`, `104.18.21.81` |

Hostname-verified TLS succeeded directly to all five literal addresses. No new
address was added. Published AAAA answers are not candidates because the
broker requests only reviewed families, the namespace has no IPv6 link or
route, IPv6 sysctls are disabled, and both nft policies contain empty IPv6
allow sets.

DNS is allowed only to the three exact addresses on UDP/TCP 53. HTTPS is
allowed only to the five exact address/TCP-443 tuples. The namespace and host
tables both deny all other traffic. No university-private CIDR is authorized;
the three specific resolver/port tuples are the only university service
exception in this research policy.

## Observed development and disposable verification

- Resolver-root lifecycle, no-follow ownership, idempotency, foreign-object
  preservation and conditional rollback: PASS.
- The exact production source manifest plus corrected four-file overlay was
  installed into a disposable runtime, verified against its complete tree
  receipt, byte-compared for all four overlay files and independently
  uninstalled: PASS.
- Disposable containment: PASS, 32 groups. This included resolver preparation
  before activation, systemd-equivalent private read-only binding, actual
  `getaddrinfo()` over UDP and TCP DNS, hostname-verified TLS/HTTPS, exact
  destination enforcement, IPv6 denial, unauthorized DNS/TCP/UDP denial,
  every-step cleanup, independent rollback and unchanged real-host
  address/route/rule/firewall/SSH/namespace baseline. Three distinct research
  generations completed with archived immutable receipts and real transient
  systemd startup. Stale flags, partial rollback, foreign collisions,
  concurrent attempts, interrupted receipt writes, changed inode/symlink,
  mismatched generations and host drift all failed closed and recovered only
  through ownership-scoped actions. The exact observed schema-v2
  `status=rollback`, all-flags-false receipt started a schema-v3 generation,
  completed the real-systemd probe and remained byte-preserved in history.
- Missing resolver, wrong owner, unsafe symlink, wrong bytes, missing bind and
  policy drift all failed closed.
- A real transient systemd fixture on VM1 proved that a missing optional
  protected file permits startup, the same file is unreadable when present,
  `NetworkNamespacePath=` coexists with the exact read-only resolver bind,
  an unrelated readable fixture stays readable, the Docker socket remains
  inaccessible, and a mandatory missing path still fails with
  `226/NAMESPACE`. The fixture left no unit, namespace or file behind.
- Combined focused Django research, worker, admission, three-agent failover,
  deterministic-engine, governance and Change Engine suites: 321/321 PASS.
- `systemd-analyze verify` passed with only the future runtime executable
  replaced by `/usr/bin/true`; direct verification's only finding was the
  expected absent `/opt/nmas/venv/bin/python` before runtime install.
- `systemd-analyze security --offline` remains **1.5 OK**.
- Live read-only DNS revalidation and direct hostname-verified HTTPS checks:
  PASS for the three names and five reviewed addresses.

## One combined privileged activation

Run only after the owner supplies a new active maintenance window, confirms
working VM1 console recovery, and accepts the exact consolidated bundle below.
Every stop condition rolls back only Stage B-owned objects.

### 1. Verify VM1 health and recovery

Capture and retain hashes/JSON for all addresses, links, routes, rules, nftables
rules, SSH configuration, active NMAS services and all 15 Containerlab
containers. Confirm `ens33`, `nmas-mgmt`, the current SSH session, `nmas-web`
and monitoring services are healthy. The operator must open and test the VM1
console before continuing.

### 2. Verify the current window

Record these non-empty values in the activation record:

```text
MAINTENANCE_WINDOW=<new owner-approved start/end/timezone>
VM1_CONSOLE_RECOVERY_METHOD=<tested current method>
OWNER_AUTHORIZATION_ID=<attributable decision>
```

Stop if the current time is outside the recorded window.

### 3. Install and verify the worker overlay

Before any installation, validate the complete dependency graph:

```bash
python3 deploy/sandbox/research_release.py \
  deploy/sandbox/stage-b/research-activation-release.json
```

Require release SHA-256
`bbb0da54a5bbc0196ebd3db809dbb11e7820b5e5285ac23359e3bf85e9c56057`,
18 verified files, current config digest `fd019891…a86a`, legacy digest
`d0ce9ede…20290`, and host-policy SHA-256 `7a1ba424…2d0e4`.

Use the same arguments for `install`, `verify` and eventual `uninstall`:

```bash
sudo /usr/bin/python3 deploy/sandbox/worker_runtime.py install \
  --source /home/student/Scripts/clab_dualstack_lab-deploy \
  --source-manifest deploy/sandbox/stage-b/worker-source-manifest.json.proposed \
  --overlay-root /home/student/Scripts/nmas-public-dev-troubleshooting \
  --overlay-manifest deploy/sandbox/stage-b/worker-overlay-manifest.json.legacy-receipt-review \
  --source-venv /home/student/Scripts/.venv \
  --lock deploy/sandbox/worker-runtime.lock

sudo /usr/bin/python3 deploy/sandbox/worker_runtime.py verify \
  --source /home/student/Scripts/clab_dualstack_lab-deploy \
  --source-manifest deploy/sandbox/stage-b/worker-source-manifest.json.proposed \
  --overlay-root /home/student/Scripts/nmas-public-dev-troubleshooting \
  --overlay-manifest deploy/sandbox/stage-b/worker-overlay-manifest.json.legacy-receipt-review \
  --source-venv /home/student/Scripts/.venv \
  --lock deploy/sandbox/worker-runtime.lock

cmp -s deploy/sandbox/namespace_activation.py /opt/nmas/current/deploy/sandbox/namespace_activation.py
cmp -s deploy/sandbox/nmas-research-broker.service.in /opt/nmas/current/deploy/sandbox/nmas-research-broker.service.in
```

Install the reviewed sysusers fragment only if absent, run `systemd-sysusers`,
and verify the locked nologin identities. `nmas-research` is the broker UID;
`nmas-ts-runtime` is the only accepted IPC client UID. Neither may have sudo,
Docker, containerd, a shell or capabilities.

### 4. Install the resolver root and ownership receipt

```bash
sudo /usr/bin/python3 deploy/sandbox/resolver_root.py install \
  --change-id CHG-NMAS-20261115-STAGE-B-001
sudo /usr/bin/python3 deploy/sandbox/resolver_root.py verify \
  --change-id CHG-NMAS-20261115-STAGE-B-001
```

Require exactly `root:root 0755 /etc/netns` and `root:root 0600` for
`/var/lib/nmas-stage-b-resolver-root.json`. Do not use `mkdir -p` or adopt a
pre-existing object.

### 5. Install reviewed configuration and prepare the resolver

Install, with foreign-object stop gates, the exact research nft file and
activation env as `root:root 0600`, the corrected unit as `root:root 0644`, and
the generated secret-bearing broker env as `root:nmas-research 0640`. Record
all installed hashes in the existing mode-0600 Stage B installation receipt.

```bash
sudo deploy/sandbox/namespace-activate.sh prepare-resolver research \
  /etc/nmas/research-namespace.env
sudo stat -c '%F %U:%G %a %n dev=%d inode=%i' \
  /etc/netns/nmas-ts-research /etc/netns/nmas-ts-research/resolv.conf
```

The resolver file must contain only the three approved `nameserver` lines.

### 6. Run corrected preflight

Re-run runtime verification, resolver-root verification, DNS A-answer
revalidation and:

```bash
sudo deploy/sandbox/namespace-activate.sh preflight research \
  /etc/nmas/research-namespace.env
sudo deploy/sandbox/namespace-activate.sh host-policy research \
  /etc/nmas/research-namespace.env \
  | diff -u <(tail -n +3 deploy/sandbox/stage-b/research-host-egress.nft.activation-review) -
```

Also run diagnostic preflight and require exit 65 for missing `TARGETS`. Never
run `activate diagnostic`.

### 7–8. Activate research and validate only NMAS-owned policy

```bash
sudo deploy/sandbox/namespace-activate.sh activate research \
  /etc/nmas/research-namespace.env
sudo deploy/sandbox/namespace-activate.sh validate research \
  /etc/nmas/research-namespace.env
```

The single lifecycle action creates the namespace and VM-local veth, but loads
the namespace and host nftables tables before bringing the veth up so there is
no unfiltered interval. Validate that the only new objects are
`nmas-ts-research`, `nmas-ts-resh0`, `nmas_research`,
`nmas_host_research`, the `/30` link and its scoped masquerade. No existing
interface, route, sysctl or foreign nftables table may change.

### 9. Start the least-privileged service

Install the unit from the hash-reviewed overlay copy, run `daemon-reload`, keep
it disabled, then start it once. Both `ExecStartPre` and the main process must
succeed. Confirm the main process UID/GID/groups, empty capability sets,
network namespace identity and absence of forbidden socket/file access.

### 10. Verify actual resolver and approved HTTPS

Using the service `MainPID`, compare the worker's `/proc/<pid>/ns/net` to
`/run/netns/nmas-ts-research` and verify from its mount namespace that
`/etc/resolv.conf` has the same device/inode/hash as the lifecycle file. Submit
one authenticated broker request per approved hostname and confirm
`getaddrinfo()` returns only the reviewed A set, TLS hostname verification
succeeds and the audit log records an allowed bounded GET/HEAD.

### 11. Verify denials with safe fixtures

Use the reviewed broker negative cases and disposable/synthetic endpoints only.
Confirm unapproved A answers, AAAA candidates, alternate DNS servers, private
and university-private destinations, VM1, VM2, device, Containerlab, alternate
TCP ports and all unauthorized UDP are denied. Do not probe prohibited real
university systems.

### 12. Reconfirm the host and lab baseline

Require the pre-activation hashes and health checks to match for SSH, ens33,
nmas-mgmt, existing routes/rules/sysctls, foreign nftables, all NMAS services
and all 15 containers. Record the Stage B-owned delta separately.

### 13. Preserve receipts

Retain the worker runtime state, resolver-root receipt, namespace activation
state and installation hash receipt at their root-only modes. They are the
authority for independent rollback.

## Independent rollback

```bash
sudo systemctl stop nmas-research-broker.service
sudo deploy/sandbox/namespace-activate.sh rollback research \
  /etc/nmas/research-namespace.env
sudo /usr/bin/python3 deploy/sandbox/resolver_root.py rollback \
  --change-id CHG-NMAS-20261115-STAGE-B-001
```

Then verify the installation receipt, unlink only matching Stage B files, run
`daemon-reload`, and uninstall the runtime with the exact overlay arguments
from step 3. Resolver-root rollback must occur only after namespace rollback
has removed the owned resolver file/directory; non-empty or changed identity
refuses deletion. Any mismatch is an escalation, not authority for broad
cleanup. The locked nologin identities may remain inert. Re-run the complete
host/lab baseline.

## Required consolidated owner decision

One response must approve or reject all of the following as one exact bundle:

1. complete research activation release SHA-256
   `bbb0da54a5bbc0196ebd3db809dbb11e7820b5e5285ac23359e3bf85e9c56057`
   (which binds overlay `ecbfc368…b40430`, controller `fd375d3…92b8` and
   reviewed host policy `7a1ba424…2d0e4`);
2. safe `/etc/netns` creation and its root-only ownership receipt;
3. the explicit systemd read-only resolver bind and root-only startup check;
4. locked `nmas-research`/`nmas-ts-runtime` identities and IPC relationship;
5. the three resolver UDP/TCP-53 tuples, three hostnames and five HTTPS tuples,
   IPv4-only veth, two owned nftables tables and scoped masquerade; and
6. the independent rollback above.

The same response must supply a new maintenance window and confirm current VM1
console recovery. No further staged approval is required after that decision;
runtime stop gates still apply if observed state or hashes differ.

Engineering disposition: `STAGE_B_RESEARCH_READY_FOR_FINAL_AUTHORIZATION`.

There is no remaining research lifecycle defect. The only prerequisites for a
live retry are an explicit owner decision bound to the new overlay hash above,
a new maintenance window with enough time for verification and rollback, and
fresh confirmation of VM1 console recovery. No receipt was deleted, rewritten
or bypassed, and no privileged live mutation was performed for this correction.
