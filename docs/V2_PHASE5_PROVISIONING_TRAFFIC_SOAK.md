# Version 2 Phase 5 — new-device provisioning, traffic workbench, real 7-day probation

**Status: IN PROGRESS — implementation complete, pull request open, real soak NOT started.**
Phase 5 is not complete until the real 7-day probation has actually been
started on the promoted deployment. That happens only after the human merge;
see [Remaining work](#remaining-work) and
[Post-merge deployment procedure](#post-merge-deployment-procedure).

| | Deliverable | State after session 3 |
|---|---|---|
| A | New device provisioning | Implemented, tested, and **proven live** against a disposable FRR node and the real NetBox. |
| B | Traffic / test workbench | Implemented, tested, and **proven live from the hardened web-service security context** through a dedicated traffic runner. `nmas-web.service` is unchanged. |
| C | Real 7-day Golden probation | Baseline bundle, drift detection, overview page and scheduler units implemented and tested. **Not installed; no real soak started.** |

## 1. Baseline

`main` at `e50f1cd` (merge of PR #39). The capability matrix is
**396 / 396 assessed, 0 unassessed, 46 supported**. Capability evidence lives
in the database, not in Git; the Phase 5 worktree database is a copy of the
Phase 4 worktree's. The production deploy database has not been promoted.

Production (`srlceos01`) was read-only throughout and is 15 / 15.

## 2. Execution boundary — one entry point

Session 1 let the provisioning stage machine call the execution engine and
widened the contract test that proves the engine has a single caller. That
was reviewed and **reverted**.

The existing design has exactly one execution orchestration boundary:
`execute_change`, reached from the one `change_execute_run` POST. All policy
lives inside it — eligibility, locking, the precheck currency rule,
compensation, audit, notification. The view above it only parses the POST.
Provisioning did converge on that function, so no policy was duplicated; but
it was a second privileged caller, and it had two real defects:

* **A bypass.** A provisioning Change is an ordinary Change. Once it was
  planned and prechecked, an operator could execute it from the ordinary
  execute page without the provisioning approval — the approval lived only in
  the provisioning caller.
* **Auto-acknowledgement.** For a Partial (UAT) run the provisioning caller
  supplied all five UAT acknowledgements itself.

Now:

```
provisioning request (APPROVED)
        │  operator opens the ordinary execution page
        ▼
change_execute_run  ──►  execute_change  ──►  eligibility gate ──► lock ──► prepare ──► apply ──► postcheck ──► compensate
                                                   ▲                              ▲                                   │
                              provisioning.gate.blockers(change)   before_first_mutation(change)        after_execution(run)
```

* The provisioning package contains **no** reference to the engine entry
  point. The original contract test is restored and now also asserts that.
* Provisioning contributes policy to the single boundary through three
  hooks the engine itself calls (`provisioning/gate.py`); they do nothing for
  a Change that is not a provisioning candidate:
  * `blockers` — part of the read-only gate: the request must be `APPROVED`,
    the approved candidate must still be the current one, and the device must
    be a reachable bootstrap device (`PROVISIONING_NOT_APPROVED`,
    `PROVISIONING_APPROVAL_STALE`, `PROVISIONING_DEVICE_UNREACHABLE`).
  * `before_first_mutation` — inside the device lock, after every Configlet
    is assessed: records the baseline configuration digest; refuses the run
    if it cannot be read (`PROVISIONING_BASELINE_UNREADABLE`).
  * `after_execution` — records the finalised outcome, or reconciles a
    failure.
* No provisioning route writes to a device. The `provisioning_provision`
  route is gone; the detail page links to the ordinary execution page.
* Partial (UAT) acknowledgements are the operator's, on the ordinary page.

Tests prove: an unapproved provisioning Change is refused by the engine,
directly and through the HTTP route; a stale approval and an unreachable
device are refused; a provisioned Change cannot be executed twice; an
ordinary Change is untouched by the hooks.

## 3. Complete mode and the probation lineage

Session 1 made Partial (UAT) the provisioning default because a Probation
bundle could only derive from a UAT bundle. That was wrong: a successful
provisioning should not pretend to be a UAT run.

A new root bundle kind, **`DEPLOYED`** (`BND-DEP-000001`), is sealed from a
`SUCCEEDED` Complete run of a provisioning Change — whole plan applied,
postcheck confirmed. A Probation bundle may now derive from a UAT **or** a
Deployed root.

```
Provisioning ─► Complete execution ─► postcheck PASS ─► NSOT sync ─► Deployed bundle ─► Probation bundle ─► 7-day soak
Ordinary Change ─► Complete execution ─► postcheck PASS ─► [Seal Deployed bundle] ─► [Create Probation bundle] ─► [Start soak]
```

For an ordinary Change each bracketed step is a separate, explicit,
approval-gated operator action; nothing starts by itself.

* Provisioning defaults to Complete. Partial (UAT) is still offered and
  keeps its own meaning and its own UAT lineage.
* A failed, blocked, rolled-back or postcheck-failed Complete run can never
  be sealed (`OUTCOME_NOT_DEPLOYED`).
* An ordinary configuration Change seals through the **same** service
  (`bundle_service.create_deployed_bundle`): provisioning does not own the
  Complete → Deployed lineage. A UAT bundle still refuses a Complete run.
  (As merged in PR #40 this was provisioning-only, `NOT_PROVISIONING_CHANGE`;
  see "Complete-Change lineage fix" below.)
* The bundle references the run's own pinned records. The integrity verifier
  cross-checks the root kind against the pinned execution mode.
* The ways to reach **Golden** are unchanged (the two seal sites and their
  referers are asserted by the existing contract test).

Migration `0025` adds the kind, its uniqueness constraint, the widened
parent-shape constraint and the `DECOMMISSIONED` status.

## 4. Provisioning workflow

`web/core/services/provisioning/` (facade `provisioning_service.py`),
pages under Automation → New Device Provisioning.

```
DRAFT → IDENTIFIED → BOOTSTRAP_CLASSIFIED → CAPABILITY_RESOLVED → IPAM_PLANNED → CANDIDATE_READY → VALIDATED → PLANNED
      → PRECHECKED → APPROVED → (PROVISIONING) → POSTCHECKED → NSOT_SYNCED → PROBATION
terminal: PROBATION · FAILED · ROLLED_BACK · CANCELLED · DECOMMISSIONED
```

| Module | Role |
|---|---|
| `codes.py` | Stage order; fixed message and remediation of every blocker. |
| `bootstrap.py` | Proven bootstrap transports; read-only probe; the three bootstrap states. |
| `capability_gate.py` | Fail-closed gate on the terminal Phase 4 status. |
| `ipam.py` | Conflict rules, VLAN policy, transactional reservation and release; `NetboxGateway`. |
| `registry.py` | The provisioned-device registry overlaid on `inventory.yml`. |
| `gate.py` | The three engine hooks. |
| `lifecycle.py` | The stage machine, reconciliation, cancellation, decommission. |

Models (`0024`): `ProvisioningRun` (the request; identity immutable; row
immutable once terminal), `ProvisioningEvent` (append-only record of every
stage attempt), `ProvisionedDevice` (the registry entry).

Rules worth knowing:

* **Device resolution.** `health.inventory.managed_devices()` is the tracked
  inventory plus live registry entries. `inventory.yml` always wins on a
  name. A device still `ADMITTED` serves only its own provisioning Change.
* **Capability.** Every plan Configlet must carry an exact
  `capability_feature` whose cell is terminally `SUPPORTED`. A renderer is
  not support.
* **Bootstrap.** Only Ubuntu / FRR over `docker exec` is supported. cEOS,
  SR Linux and IOS XE executors need inventory credentials a new device does
  not have.
* **Bootstrap states.** Unreachable → staged, never executed. Reachable
  bootstrap → full workflow. Already configured → refused as onboarding.
* **VLAN 200** is static IPv4 + IPv6 only. DHCP and DHCPv6 are refused there,
  decided from the address itself. A disposable device may not take a
  VLAN 200 address.
* **NetBox.** Reservation records the exact id of every object it creates;
  the same ids drive release. Nothing existing is edited. Provisioning
  objects carry `nmas-provisioning` and stay outside the IaC managed scope
  until NSOT sync; a disposable device never joins it.
* **Approval** is bound to the exact candidate hash and plan.
  `PROVISIONING_REQUIRE_SEPARATE_APPROVER` exists and defaults to off.

## 5. Live provisioning proof

Evidence: `docs/evidence/v2-phase5/provisioning/`.

**Setup.** A disposable Containerlab lab, `nmas-prov-proof`
(`deploy/labs/nmas-prov-proof.clab.yml`): one FRR 8.4.4 node with zebra and
staticd running and no configuration, on its own management network
(`172.31.250.0/24`, `fd00:ca:250::/64`). NetBox was inspected first: the
name, both addresses and both prefixes were unused, no DHCP range overlaps,
and nothing touches VLAN 200.

**NetBox credentials** were loaded into the driver process only, through
the repository's own `netbox_ipam` env-file parser against the deploy
checkout's protected `netbox/.env`. They were never printed, copied into the
worktree, written to evidence or committed.

**The run was driven through the real HTTP routes** as an authenticated
operator, including the Device Builder routes for the intent and the
ordinary `change_execute_run` route for execution.

| Step | Result |
|---|---|
| Request `PROV-000001`, device `PROVEDGE1`, Ubuntu/FRR, disposable | created |
| Bootstrap probe | `REACHABLE_BOOTSTRAP` |
| Capability | `interface.LOOPBACK` on `ubuntu_frr`: `SUPPORTED` |
| NetBox reservation | prefixes 67, 68 · device 23 · interface 83 · addresses 167, 168 |
| Candidate | Change `CHG-20261005-0001`, Complete mode; loopback `loopback10` with `198.51.100.10/32` and `2001:db8:5a::10/128` |
| Validation, plan, precheck, approval | passed |
| Execution (ordinary route) | `SUCCEEDED`; postcheck `PASS` |
| Device read-back | `loopback10` holds both addresses |
| Config digest | before `f6e49561…`, after `cacab448…` |
| NSOT sync | NetBox device and addresses `Active`; registry `ACTIVE`; IaC managed list unchanged |
| Visible in NMAS | fleet health, device health, provisioning and bundle pages |
| Probation candidate | `BND-DEP-000001` → `BND-PROB-000001`, both intact; soak **eligible, not started** |

### Defects the live run found (all fixed, all now covered by tests)

1. **Network-config validation refused the new device.** Its managed-scope
   check blocks any device outside NetBox's managed list. The unit-test
   sources never supplied that list, so the check degraded to a warning and
   the gap was invisible. The check now admits a device for its own
   provisioning Change only, and the test sources carry the list.
2. **An already-configured device was classified as pristine.** The probe
   read only the FRR running configuration; NMAS configures Linux loopbacks
   and addresses with iproute2. The probe now also reads the kernel address
   table.
3. **Two requests could claim one container.** Refused at identity now
   (`BOOTSTRAP_TARGET_IN_USE`).
4. **A decommissioned device kept its request open**, which kept the name
   and the container claimed. `DECOMMISSIONED` is now a terminal status.
5. **The NetBox gateway could not find the Ubuntu device type** (it looked
   for `frr`; NetBox calls it `ubuntu-24-04`).

Defects 2 and 3 together let a second request reach execution against an
already-configured device. The engine's own compensation-provability check
refused the write (`COMPENSATION_NOT_PROVABLE`), so nothing was written, but
the request should have been stopped two stages earlier, and now is.

### Controlled failures

| Case | Result |
|---|---|
| Management address already held in NetBox | `MGMT_IP_DUPLICATE` naming the holder; nothing created. |
| Unreachable device with free addresses | Staged through reservation and plan; precheck `DEVICE_UNREACHABLE`. |
| Executing that unapproved request from the ordinary route | Engine `BLOCKED`: `PROVISIONING_NOT_APPROVED`. |
| Cancelling it | Reservation released (device, interface, both addresses gone); registry `RETIRED`. |
| Container owned by a live device | `BOOTSTRAP_TARGET_IN_USE`. |
| Container already configured (after the owner was retired) | `DEVICE_ALREADY_CONFIGURED`, naming `loopback10`. |

### Cleanup

`PROVEDGE1` was decommissioned through the supported route: all six NetBox
objects released, registry `RETIRED`, request `DECOMMISSIONED`. The two tags
the gateway had created were deleted once unused. NetBox is back to its
exact baseline — 11 devices, 33 prefixes, 83 addresses, the original five
tags. The lab was destroyed with `--cleanup`.

## 6. Traffic / test workbench

Pages under Automation → Traffic / Test Workbench, migration `0026`.

### Architecture

```
browser ── authenticated POST (RBAC: Execute, CSRF) ──▶ Django / Gunicorn        nmas-web.service, NoNewPrivileges=yes
                                                          │  validation layer one, TrafficRun CREATED → RUNNING
                                                          │  one structured request (ids, enumerations, bounded integers)
                                                          ▼
                                     /run/nmas-traffic-runner/runner.sock          Unix socket, root:<web group> 0660
                                                          ▼
                                             traffic runner                        nmas-traffic-runner.service
                                                          │  peer uid check, validation layer two, own endpoint catalogue
                                                          ▼
                                  docker run <pinned tools image ID>               the ONE process boundary
                                  --network container:<endpoint container ID>
                                                          ▼
                                     endpoint network namespace                    H1–H4 / WebServer, nothing installed in them
                                                          ▼
                          exit status + bounded output ──▶ Django parses ──▶ immutable TrafficRun
```

| Where | Module | Role |
|---|---|---|
| website | `traffic/endpoints.py` | The catalogue: `inventory.yml` hosts plus WebServer. Renders the runner's configuration. |
| website | `traffic/limits.py` | Hard bounds, layer one. |
| website | `traffic/service.py` | validate → create → ask the runner → verdict → finalise; reconciliation. |
| website | `traffic/client.py` | The Unix-socket client. The only thing the website can do towards a test. |
| website | `traffic/parsers.py` | ping, traceroute, iperf3 JSON, probe output. |
| runner | `traffic/runner/policy.py` | The runner's own limits and the closed request schema, layer two. |
| runner | `traffic/runner/config.py` | Root-owned catalogue: endpoint id → container, tools image ID, allowed peer uids. |
| runner | `traffic/runner/runtime.py` | **The one process boundary** of the traffic subsystem. |
| runner | `traffic/runner/engine.py` | One run: resolve, discover addresses, execute, remove what it created. |
| runner | `traffic/runner/server.py`, `__main__.py` | Socket front end, peer check, audit line, entry point. |
| image | `deploy/traffic-tools/` | The pinned tools image and its two fixed socket probes. |

The runner package uses the standard library and relative imports only. The
installer copies it to a root-owned directory and runs that copy, not the
deployment checkout.

### Why the web service keeps `NoNewPrivileges`

The session-2 implementation entered an endpoint's namespace with
`sudo -n nsenter`. `nmas-web.service` sets `NoNewPrivileges=yes`, so that
cannot work from the deployed service, and the two ways to make it work —
dropping the flag, or giving the web account a sudo rule — both turn a
website compromise into root. Neither was done. `nmas-web.service` is
byte-for-byte unchanged in this phase, and a test pins its hardening lines.

The website now starts no process for a traffic test. A contract test
enforces it: the website's traffic code has no spawn, its only `socket` use
is `client.py`, and it never names the container runtime.

**Existing condition, not introduced here.** `nmas-web.service` has carried
`SupplementaryGroups=docker` since V2 Phase 1, for read-only device sessions
that use `docker exec`. The traffic path does not use it, and Phase 5 adds
nothing to it, but it means the web account can already reach the container
runtime for other features. Removing it is a separate piece of work (those
device sessions would need the same broker treatment) and is listed under
[Remaining work](#remaining-work).

### Runner IPC

* A Unix stream socket, `/run/nmas-traffic-runner/runner.sock`. Nothing
  listens on the network (`RestrictAddressFamilies=AF_UNIX`,
  `IPAddressDeny=any`).
* Created by systemd as `root:<web group> 0660` (socket activation). The
  runner starts on the first request.
* Every connection's kernel-reported peer uid (`SO_PEERCRED`) must be in the
  configured allow-list, which the installer sets to the web account's uid.
* One request per connection: one JSON object of at most 4096 bytes, one
  JSON reply. A slow or silent peer is dropped after 5 s.
* The website checks the reply before using it: protocol version, and the
  reply must answer *this* run id.

The request is a closed schema. Any other key is a refusal, not ignored:

```json
{"v": 1, "run_id": "<uuid4>", "source_endpoint_id": "H1", "destination_endpoint_id": "H2",
 "address_family": "IPV4", "test_type": "IPERF3", "protocol": "TCP",
 "parameters": {"port": 5201, "duration": 3, "bandwidth_kbps": 2000, "parallel": 1}}
```

There is no field for a command, argv, flag, container name or id, pid,
namespace, image, binary or address. Endpoint ids resolve through the
runner's own root-owned configuration (`/etc/nmas/traffic-runner.json`),
which accepts only `clab-<lab>-<id>` for each id. At run time the container
must be running and carry the lab's Containerlab labels for that node; the
run is then pinned to its container ID.

### Runner service

`deploy/systemd/nmas-traffic-runner.service`: `DynamicUser=yes` (not the web
account, not root), `SupplementaryGroups=docker` as its one privilege,
`NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, empty capability
bounding set, `MemoryDenyWriteExecute`, `SystemCallFilter=@system-service`.
It reads no environment file and holds no secret.

Docker-group access is root-equivalent in principle. What bounds it is that
the runner's code and configuration are root-owned copies the web account
cannot change, and that every runtime call is built by `runtime.py` from
fixed pieces.

### Tools runtime

`deploy/traffic-tools/Dockerfile`: `alpine:3.24.1` pinned by digest, with
`iputils-ping`, `traceroute`, `iperf3`, `iproute2-minimal` and `python3` at
pinned versions, plus the two fixed probe scripts. About 52 MB. Not built
from any NOS image. The installer builds it and records its image ID; the
runner starts it **by image ID** with `--pull never`, never by tag.

Each diagnostic is a throw-away container:

```
docker run --rm --pull never --name nmas-traffic-<run uuid hex>-<role>
  --label nmas.traffic.instance=… --label nmas.traffic.run=<run uuid> --label nmas.traffic.role=<role>
  --network container:<endpoint container ID>
  --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m
  --cap-drop ALL [--cap-add NET_RAW]  --security-opt no-new-privileges
  --pids-limit 32 --memory 96m --memory-swap 96m --cpus 1
  --user 65534:65534 | 0:0   --entrypoint <fixed binary>  <image ID>  <validated tokens>
```

No `--privileged`, no volume, no tty. `NET_RAW` and uid 0 are used only by
ping and ICMP traceroute; iperf3, the probes and `ip` run as `nobody` with no
capability. Nothing is installed into H1–H4 or WebServer.

### Validation, twice

| Check | Website (`limits`, `service`) | Runner (`policy`) |
|---|---|---|
| Endpoint allow-list | inventory catalogue | its own root-owned catalogue |
| Source ≠ destination, family supported by both | yes | yes |
| Test type, address family, protocol | yes | yes |
| Every numeric bound | yes | yes, from its own constants |
| Integer type | decimal digits only | real `int`, never bool / string / float |
| Unknown fields | ignored (never forwarded) | refused |
| Concurrency | database constraint, 1 active run | its own semaphore, 1 |

A contract test keeps the two sets of numbers identical.

**Families.**

| Family | Measures | Notes |
|---|---|---|
| ICMP | reachability, loss, RTT | Not a throughput test. |
| Traceroute | hops | A silent hop is reported as silent. |
| TCP connectivity | connected / refused / timeout | One attempt to one port. |
| UDP probe | refused / open-or-filtered | UDP cannot tell a silent listener from a filter; the page says so. |
| iperf3 | throughput; UDP adds jitter and loss | Temporary one-off server. |

**Limits.**

| Parameter | Bound |
|---|---|
| ICMP packets | 1–5 (the health engine's own ping bound) |
| ICMP payload | 16–1400 bytes |
| Traceroute hops | 1–20 |
| Probe port / timeout | 1–65535 / 1–5 s |
| UDP probe | 1–5 datagrams of 1–512 bytes |
| iperf3 ports | 5201–5210 |
| iperf3 duration | 1–10 s |
| iperf3 bitrate | 64 kbit/s – 10 Mbit/s, always set; no unlimited mode |
| iperf3 streams | 1–2 |
| iperf3 UDP datagram | 64–1400 bytes |
| Concurrent tests | 1 |

### iperf3 server lifecycle and run isolation

Start a one-off server (`-s -1`, bound to the discovered destination address,
with an idle timeout) in the destination namespace → wait for it to report
listening → run the client in the source namespace → read how the server
ended → remove that exact container → confirm it no longer exists. If the
port is already in use the server fails to bind and the run fails; the
foreign listener is never touched. A server that cannot be confirmed gone
fails the run.

Every temporary container is named from the run's UUID and removed by that
exact name. There is no name-pattern kill, `pkill`, `killall` or prune. Each
reply carries a `cleanup` record (containers removed, none left behind), and
it is stored on the run. A replayed run id is refused without touching the
earlier run's containers. When the runner starts it removes containers
carrying its own instance label that a crash left behind.

### States, failures and audit

`CREATED → RUNNING → PASSED | FAILED | TIMED_OUT`. A run left active past its
deadline is reconciled to `INTERRUPTED`, never to a pass, on the next request
or by `manage.py traffic_reconcile`. Runner unavailable, runner timeout, a
reply for another run, an endpoint that vanished mid-run, a tools container
that would not start and an unverified cleanup are each a recorded failure
with a stable code.

The runner writes one journal line per request: run id, endpoint ids, test
type, peer uid, outcome, container count, cleanup result, duration. No tool
output, addresses, environment or credentials. `TrafficRun` remains the
operator-facing evidence: requested and normalized parameters, the
structured operation, runner version, tools image ID, cleanup record, parsed
metrics, bounded raw output, discovered addresses, timestamps, operator,
repository HEAD, and optional references to a Change, a provisioning request
or a soak. Immutable once finished; never deleted.

### Live traffic proof — hardened web context

Evidence: `docs/evidence/v2-phase5/traffic/traffic-hardened-web.json`.
(`traffic-live.json` is the superseded session-2 shell proof.)

Two temporary services were rendered from the repository's own unit
templates as runtime-only units under `/run/systemd/system` and removed
afterwards. Nothing was installed persistently and the deployment checkout
was not touched.

* **Web:** `deploy/systemd/nmas-web.service` with only the environment file,
  Gunicorn config path and bind port changed. `NoNewPrivileges=yes`,
  `PrivateTmp`, `ProtectSystem=full`; `/proc/<pid>/status` showed
  `NoNewPrivs: 1` for the master and both workers. Website MFA required.
* **Runner:** `nmas-traffic-runner.socket` / `.service` with code and
  configuration as root-owned copies. Dynamic uid 64085, empty capability
  sets, socket `root:student 0660`.

Requests were ordinary HTTP: sign in, enroll TOTP, `POST
/automation/traffic/run/` with CSRF. An anonymous POST was redirected to the
login page; a Viewer-role POST got 403.

| Test | Path | Result |
|---|---|---|
| ICMP IPv4 | H1 → H2 | 5 / 5, avg 2.9 ms |
| ICMP IPv6 | H1 → H2 | 5 / 5, avg 3.4 ms |
| ICMP IPv6 | H1 → H4 | 3 / 3, avg 5.1 ms |
| Traceroute IPv4 | H1 → H2 | 2 hops, reached |
| Traceroute IPv6 | H1 → H2 | 2 hops, reached |
| iperf3 TCP IPv4 | H1 → H2 | 2.09 Mbit/s of 2 requested |
| iperf3 TCP IPv6 | H1 → H2 | 2.09 Mbit/s of 2 requested |
| iperf3 UDP IPv4 | H1 → H2 | 1.00 Mbit/s, jitter 0.49 ms, 0 % loss |
| iperf3 UDP IPv6 | H2 → H4 | 0.50 Mbit/s, jitter 1.39 ms, 0 % loss |
| TCP to a closed port | H1 → H2:81 | `FAILED` / `CONNECTION_REFUSED` |
| UDP to a closed port | H1 → H2:5353 | `FAILED` / `CONNECTION_REFUSED` |
| IPv4 to H4 | — | refused: `FAMILY_NOT_SUPPORTED_BY_ENDPOINT` |
| 3600 s iperf3 | — | refused: `PARAMETER_OUT_OF_BOUNDS` (duration) |
| R1 as source | — | refused: `SOURCE_NOT_AN_ENDPOINT` |
| `count="3 -f"` plus `command` / `container` fields | — | refused: `PARAMETER_OUT_OF_BOUNDS` (count) |

Every iperf3 server exited by itself with code 0 and its container was then
removed. Every run's cleanup record was verified, and no `nmas-traffic-*`
container existed afterwards.

Also proven live against the runner's socket, bypassing the website:

| Attempt | Result |
|---|---|
| Container name or `R1` as endpoint id | `UNKNOWN_ENDPOINT` |
| Extra `container`, `image`, `argv` key; `command` parameter | `MALFORMED_REQUEST` |
| Test type `SHELL` | `UNSUPPORTED_TEST_TYPE` |
| Duration 3600, bitrate 1 Gbit/s, iperf3 port 22, `"1 -f"` as count | `PARAMETER_OUT_OF_BOUNDS` |
| Connect as `nobody` | permission denied by the socket mode |
| Connect as root | `UNAUTHORIZED` by the peer uid check |
| Runner restarted with an abandoned labelled container present | removed at startup, logged |

Not proven live: an endpoint disappearing mid-run (it would mean stopping a
lab container) and a tools container failing to start. Both are covered by
unit tests only.

## 7. Probation baseline, drift and the scheduler

The 7-day mechanism (Phase 20) is unchanged and still pins its policy per
run. Phase 5C adds what was missing.

### Baseline (`soak/baseline.py`, migration `0027`)

When a soak starts, `ProbationSoakRun.baseline` and `baseline_digest` pin:

* the Probation bundle and its root (id, digests, root kind);
* the Change and, where there is one, the provisioning request;
* references to the validation, plan, execution and postcheck runs;
* **the configuration digest of every observed device, read at start**;
* the pre- and post-change digests where the lineage recorded them
  (a provisioning run does; an ordinary Change says `NOT_RECORDED` and why);
* the health / postcheck / telemetry picture at the start instant;
* the topology snapshot facts and the NSOT references;
* start, due, the policy (7 days) and whether it is a production duration;
* the repository HEAD of the running code and the collector version.

Digests and identifiers only — configuration text is sanitized, hashed and
discarded. The baseline is immutable.

**A soak does not start without a real baseline digest**
(`BASELINE_UNREADABLE`). This is new behaviour: starting a soak now makes one
read-only configuration read per observed device, outside any transaction.
It is on in every real environment; only the test runner turns it off, and
it installs a session that refuses every device read.

### Configuration drift (`soak/config_state.py`)

Each sample re-reads the configuration of every device the baseline pinned
and compares digests. It reuses the allowlisted read
(`live.read_device_with_raw`) and the legacy-bootstrap sanitizer; for Linux
it also hashes the kernel address table. nft packet counters and the
volatile fields of `ip -j addr` are normalized away.

| Observation | Sample | Soak |
|---|---|---|
| Digest matches | unchanged | continues |
| Digest differs | `INVALIDATED`, `config_drift` | `INVALIDATED` / `CONFIGURATION_DRIFT`, at once |
| Configuration unreadable | at best `INCOMPLETE` | continues; a lasting gap makes it Incomplete |

Drift invalidates rather than fails: the configuration under observation is
no longer the one that entered probation. Restoring it does not revive the
soak; a retry is a new run with a new clock. The clock is never reset.

### Failure semantics

| Event | Recorded as |
|---|---|
| Health or postcheck regression | sample `FAIL` → soak `FAIL` / `EXPECTED_STATE_FAILED` |
| Sustained critical CPU / memory | soak `FAIL` after the project's consecutive-sample limit |
| Management reachability lost, stale telemetry, stale collector | sample `INCOMPLETE`; insufficient coverage → soak `INCOMPLETE` |
| Configuration drift | soak `INVALIDATED` / `CONFIGURATION_DRIFT` |
| Later execution on the devices, bundle integrity | soak `INVALIDATED` |

Not implemented: a topology or NSOT inconsistency check during the soak.

### Overview page

Device Builder → Golden and probation (`/device-builder/probation/`):
current Golden; each candidate in probation with device, Change and
provisioning request, start, due, elapsed, remaining, the 7-day policy,
baseline and current configuration digests with drift state, health,
collector freshness, degraded and disqualifying events, and eligibility in
words. A candidate is called "in probation" or "eligible — operator decision
required", never Golden.

Collector freshness is stated, not assumed: `FRESH` (a sample within two
intervals), `NO_SAMPLE` (just started), `STALE` (the collector is not
sampling this soak).

### Scheduler (`deploy/systemd/`, not installed)

* `nmas-probation-soak-tick.service` — oneshot; runs
  `manage.py probation_soak_tick` in `@DEPLOY_ROOT@/web` with the website's
  protected environment file.
* `nmas-probation-soak-tick.timer` — every 5 minutes; `Persistent=false`.
* `deploy/scripts/install_soak_timer.sh` — renders, verifies, enables.
  Refuses a checkout whose database has unapplied migrations. Has a
  `--render-only` mode that installs nothing.

Cadence: one sample per 900-second interval, ticked at a third of that so
jitter cannot skip an interval; extra ticks are no-ops. Downtime is a real
gap and is never back-filled.

Verified without installing: the rendered units pass
`systemd-analyze verify`, and the command's dry run starts cleanly. **Nothing
was installed or enabled on the host.**

## 8. Tests

| Suite | Tests |
|---|---|
| `test_provisioning`, `test_provisioning_views` | 80 |
| `test_traffic`, `test_traffic_views` (website side, over the real runner with a scripted runtime) | 51 |
| `test_traffic_runner` (policy, process boundary, IPC, failures, cleanup, configuration) | 42 (1 opt-in live smoke test skipped) |
| `test_soak_baseline` | 28 |
| `test_web_deployment` (scheduler units, runner units, tools image, installer) | 10 for Phase 5 |

Full Django suite after session 3: **2,134 tests, 0 failures, 0 errors,
1 skipped**. `makemigrations --check`: no pending migration (Phase 5
migrations are `0024`–`0027`).

Local Tier-3 (`tier3.py --base origin/main --mode full`) on `cbc6820`:
**PASS**, exit 0, no warnings, no unclassified path. Hygiene 12,061 added
lines scanned; syntax 662 files; Django check; migration drift; 2,134 Django
tests; 476 monitoring tests; Grafana drift. The optional lab verifiers are
not part of the offline gate and were not run. Report:
`docs/evidence/v2-phase5/tier3-local.json`. The hosted run is recorded in the
pull request.

The runner tests cover: socket permission refusal, peer-uid refusal,
malformed bytes and requests, unknown endpoint ids, container-name / image /
command attempts, unsupported test types, duration / bitrate / port / stream
bounds, the concurrency limit, runner timeout and unavailability, an endpoint
missing, lost or replaced mid-run, the tools image missing or failing to
start, iperf3 server failures, restart reconciliation, replayed run ids and
exact cleanup.

**Mutation checks (session 3).** 45 mutants, each removing or weakening one
safety gate in the runner, the client, the verdict logic or the website
limits. 43 were caught. The two survivors are equivalent mutants in
`server.py` (the request-size check and the JSON-object check): the bounded
`recv` and the runner's schema validation refuse the same input one step
later. Session 1 and 2 mutation runs covered provisioning.

## Remaining work

1. **The real 7-day soak has not started.** It belongs on the promoted
   deployment after the human merge — see the procedure below.
2. **Hosted Tier-3 and human review** of the Phase 5 pull request.
3. **Existing web-service Docker access.** `nmas-web.service` has had
   `SupplementaryGroups=docker` since V2 Phase 1 for read-only device
   sessions. Phase 5 did not add or use it for traffic, but the web account
   is not free of container-runtime access until those sessions are moved
   behind a broker as well. Not in Phase 5 scope; needs a decision.
4. **Templates** are not wired into provisioning candidates.
5. **cEOS / SR Linux / IOS XE bootstrap** needs credential onboarding for a
   device that is not in `inventory.yml`.
6. Two traffic failure modes are covered by unit tests only (endpoint lost
   mid-run, tools container fails to start).

## Post-merge deployment procedure

Only after the pull request is merged by a human. Nothing below was done in
session 3. `D=/home/student/Scripts/clab_dualstack_lab-deploy`.

```
 1. Confirm production is healthy (15 / 15) and no Change is executing.
 2. Back up the deployment database:      cp -p $D/web/db.sqlite3 $D/web/db.sqlite3.pre-phase5
 3. Promote the checkout:                 git -C $D fetch origin && git -C $D checkout --detach origin/main
                                          (record the SHA; it must be the merge commit)
 4. Migrate (0024–0027), as the service user with the service environment:
                                          manage.py migrate --plan   → review   → manage.py migrate
                                          manage.py makemigrations --check
 5. Carry over the Phase 4 capability evidence (it lives in the database, not in Git).
 6. manage.py collectstatic --noinput;    sudo systemctl restart nmas-web.service;   check /healthz and sign-in
 7. Traffic runner:                       sudo $D/deploy/scripts/install_traffic_runner.sh --deploy-root $D
                                          systemctl is-active nmas-traffic-runner.socket
                                          run one ICMP test H1 → H2 from the workbench; confirm PASSED and
                                          `docker ps -a --filter name=nmas-traffic` is empty
 8. Soak collector:                       sudo $D/deploy/scripts/install_soak_timer.sh --deploy-root $D
                                          systemctl list-timers nmas-probation-soak-tick.timer
 9. Verify: nmas-web, nmas-traffic-runner.socket and the timer active; one collector tick logged; production 15 / 15.
10. Execute one real supported Change in Complete mode → start the real 7-day probation from its DEPLOYED bundle.
11. Record the soak id, start and due instants here. Phase 5 is complete when step 10 has happened.
```

The install scripts refuse a checkout that lacks the code, and the soak
timer script refuses an unmigrated database. The deploy checkout must not be
pointed at worktree code, and the soak must not be started before step 9.

## Handoff — session 3

Done this session: the traffic workbench moved behind a dedicated runner
(Unix socket, peer check, second validation layer, pinned tools image, exact
cleanup); `nmas-web.service` left unchanged; the full traffic matrix
re-proven from the hardened web context; runner failure and mutation tests;
runner units and installer; this document.

Next: human review and merge of the pull request, then the post-merge
procedure above, ending with the start of the real soak.

## Production deployment — 2026-10-06

| Item | Evidence |
|---|---|
| PR #40 | merged by merge commit `789a56b915568fc1460b411c1860e0b15c1af71f`, 2026-10-06T08:03:18Z; tree identical to the reviewed head `846b31f` (hosted Tier-3 run 37404055435) |
| Deployment checkout | `4adec06` → `789a56b` (`git checkout --detach origin/main`) |
| Database backup | `web/db.sqlite3.pre-phase5-20261006T080441Z` in the deployment checkout, 1,630,208 bytes, `student:student` 0644, SHA-256 equal to the source at copy time |
| Migrations | `0023`–`0027` applied (`0023` is the Phase 4 assessment table the database predated); `makemigrations --check`: none pending |
| Capability evidence | rebuilt from the committed `docs/evidence/v2-phase4-exhaustive/progress-ledger.json` (SHA-256 `516e3f0f…368d3f`) through `assessment.persist` (the application's validated, append-only path), actor `phase4-ledger-import@789a56b`. Result 396 / 396 assessed, 46 supported (cEOS 21, FRR 15, SR Linux 5, IOS XE 5, IOS XR 0, SONiC 0); every cell equal to the ledger apart from row ids and timestamps. Row timestamps are the import time; each cell keeps its original repository head, runtime version and `live:` / `gate:` / `runtime:` references. The provisioning gate reports the same counts. |
| Web | `collectstatic`, `nmas-web.service` restarted, `/healthz` 200, sign-in 200; `NoNewPrivileges=yes` unchanged |
| Traffic runner | `install_traffic_runner.sh`; socket enabled, `root:student 0660`, refused for another account; tools image pinned by id `sha256:45ccc056…3073de` |
| Deployed traffic run | `39902e6f-fdca-448b-9154-3cb94f33a7b8`, run by the operator from the deployed workbench, `PASSED`; no `nmas-traffic` container left |
| Soak timer | `install_soak_timer.sh`; enabled, 5-minute cadence; first service tick 2026-10-06T08:08:24Z, exit 0, `0 running soak(s)` |
| Blocked Change (kept as evidence) | `CHG-20261006-0001`: R1's whole running configuration imported plus Loopback105, 37 Configlets. Complete execution `c0d5bd3c` `BLOCKED` before any write, `COMPENSATION_NOT_PROVABLE` for the pre-existing Vlan101 / Vlan102. Lesson: a Change on an existing device carries only its delta. |
| Soak Change | `CHG-20261006-0002`, Complete, R1 `Loopback105` (`FOR-SOAK-TESTING`, `192.168.255.105/32`, `2001:db8:255::105/128`). Draft prepared through the Device Builder services by actor `phase5-soak-preparation`; network-config validation `58a46ff2` PASS; validation `f92ead2c` PASS; plan `06a04adc` (3 Configlets); precheck `a6c26afa` PASS |
| Execution | run `d666f36e-7e0e-4ac0-805f-cd3f6361bb44`, operator `dhruv` (MFA session), `SUCCEEDED`, 3 applied, 0 failed, 0 compensated; postcheck `c3714049-9aca-43fe-84bc-c02b84439c48` PASS (5 PASS) |
| Production | `srlceos01` 15 / 15 throughout; VLAN200, R5, WebServer and H1–H4 untouched |

### Complete-Change lineage fix

After that successful execution there was no way to reach probation: no
bundle existed for the Change and no page offered one.

**Root cause.** As merged, `DEPLOYED` was provisioning-only, in three places:

1. `bundles/snapshot.collect(kind=DEPLOYED)` refused every Change whose
   category was not `NEW_DEVICE_PROVISIONING` (`NOT_PROVISIONING_CHANGE`).
2. The only caller of `create_deployed_bundle` was
   `provisioning/lifecycle.py`. The execution page's bundle card and its POST
   were UAT-only, so an ordinary Complete run had no sealing action at all.
3. The bundle page treated every non-UAT, non-Probation bundle as Golden, so
   a Deployed root would have been shown under a "Golden bundle" heading with
   no "Create Probation bundle" action; `lineage_of` also did not recognise a
   Deployed root.

**Fix.** The category rule is removed: one service seals any `SUCCEEDED`
Complete run, and provisioning calls the same one. All other rules are
unchanged and still enforced by the same frozen-payload builder — finished
run, Complete mode, `SUCCEEDED` outcome, consistent plan / validation pins,
passing validation, whole-plan scope, every Configlet applied, nothing failed
or unapplied, the pinned postcheck linked and passing, no secret-shaped
payload, no other execution active — plus the per-execution uniqueness
constraint (migration `0025`). The execution page of a finished Complete run
now has a "Deployed bundle" card with **Seal Deployed bundle**; the same POST
route seals a UAT bundle for a Partial (UAT) run and a Deployed bundle for a
Complete run, chosen from the run's own recorded mode. The Deployed bundle
page offers **Create Probation bundle** (confirmed), and the Probation page
the existing soak panel. Sealing, deriving and starting are three separate
actions, each needing the existing approve permission and an MFA-verified
session. No migration.

**No Golden is needed first.** `soak/eligibility.check_start` requires a
verified, intact Probation bundle, no Golden already derived from it, no
active soak and no superseding execution. It does not look for a current
Golden. The first Golden can therefore come from this path: seven real days,
then the operator's explicit decision. The 30-minute legacy bootstrap is not
involved and was not run.

**What the Deployed bundle of an ordinary Change holds.** Change id;
execution run, mode and outcome; precheck run; plan id and hash; validation
run and its input / source hashes; postcheck run and result; the repository
head pinned at validation time; the ordered Configlets with payload hashes
and execution results; payload and bundle digests. It holds **no**
whole-configuration pre- or post-change digest: the execution engine records
the previous state of each modelled object, not a digest of the whole
configuration, for an ordinary Change. The soak baseline says so
(`NOT_RECORDED`) and pins the live configuration digest read at soak start,
which is the digest drift is measured against.

**Existing execution.** The fixed code was run against a throwaway copy of
the production database: execution `d666f36e` is eligible as it stands
(`VERIFIED`, no blocker), seals into a Deployed bundle that passes integrity
verification, derives a Probation bundle, and is soak-startable with no
Golden present. The two blocked runs of `CHG-20261006-0001` are refused
(`OUTCOME_NOT_DEPLOYED`). The copy was deleted; nothing was written to
production. No second execution is needed.

Tests: `core/tests/test_deployed_lineage.py` (22).

### Lineage fix — merged and deployed

PR #41, head `a63dfbfc5675c2cde4cd5db9e29a21c9fe8445cc`, hosted Tier-3 run
37447257032 success; merged 2026-10-06T10:12:15Z as
`8875bbe6b7c36ed2fc4ec0e1d1b8bbb8985e1010`. Local Tier-3 (full): PASS, 2,156
Django tests, 476 monitoring tests. Deployment checkout `789a56b` → `8875bbe`;
`nmas-web.service` restarted; no migration.

### Probation started — 2026-10-06

The operator (`dhruv`, MFA session) sealed the lineage and started the soak
in the browser. Read back from the production database afterwards:

| Item | Value |
|---|---|
| Deployed bundle | `BND-DEP-000001`, sealed 2026-10-06T10:54:38Z from execution `d666f36e` and postcheck `c3714049`; integrity verified |
| Probation bundle | `BND-PROB-000001`, created 2026-10-06T10:56:14Z, parent `BND-DEP-000001`, same payload digest `850aa841…`; integrity verified |
| Soak | `SOAK-000001`, state `RUNNING`, started by `dhruv` |
| Started | 2026-10-06T10:56:22.446525Z |
| Due | 2026-10-13T10:56:22.446525Z — exactly 7 days (604,800 s; production duration) |
| Baseline | root kind `DEPLOYED`; Change `CHG-20261006-0002` (no provisioning request); validation `f92ead2c` PASS; plan `06a04adc`; execution `d666f36e` `SUCCEEDED`; postcheck `c3714049` PASS; topology 15 nodes / 23 edges; deployment head `8875bbe`; baseline digest `3ea9249e…` |
| Baseline configuration digest | R1 `9cd6f5a17cf1374ce6c60b6b08f63784923b087b6db6466fd9130c6338fbc0bb`, read at soak start. Pre- / post-change digests: `NOT_RECORDED` for an ordinary Change (see above) |
| First active-soak sample | bucket 0, 2026-10-06T10:57:58Z, by the installed timer (`action=SAMPLED sample_result=PASS state=RUNNING`): result `PASS`; expected state `PASS` (11 pass, 0 warn, 0 fail, 0 unknown); device health `HEALTHY`; telemetry `FRESH`; bundle integrity ok; no interference |
| Drift | none — R1 current digest equals the baseline digest (`MATCH`, no changed section) |
| Collector | `FRESH`; one sample per 900 s, ticked every 5 minutes |
| Eligibility | `IN_PROBATION` — not yet eligible. No Golden bundle and no Golden decision exist |
| Device | R1 still holds `Loopback105` (`FOR-SOAK-TESTING`, `192.168.255.105/32`, `2001:db8:255::105/128`); the Change has exactly one execution run |
| Production | `srlceos01` 15 / 15; `nmas-web`, `nmas-traffic-runner.socket` and the soak timer active; no `nmas-traffic` container |

### Status

**Probation is ACTIVE. Nothing is Golden.** Golden eligibility requires the
soak to survive seven real days — until 2026-10-13T10:56:22Z — with sufficient
sample coverage and no failure, drift or invalidation, and then the
operator's explicit decision. Nothing shortens or back-fills that window; the
30-minute legacy bootstrap was not used.

### Known limitation — web service container-runtime group

`nmas-web.service` has had `SupplementaryGroups=docker` since V2 Phase 1; the
read-only device-session features use `docker exec`. It predates Phase 5 and
was neither removed nor widened. The traffic workbench does not rely on it:
it reaches the runner only through `nmas-traffic-runner.socket`. Later
hardening: move the remaining web-originated device sessions behind a broker
as well, then remove the group from the web unit. Not a Phase 5 blocker.
