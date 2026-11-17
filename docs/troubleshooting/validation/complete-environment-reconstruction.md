# Complete environment reconstruction

Date: 2026-11-14 (America/Denver)  
Method: local read-only inspection of both required trees, Git metadata, service state, the production database, Docker metadata, interfaces/routes/firewall state, and package manifests. Secret values were not read or copied.

## Conclusions

- Development authority is `/home/student/Scripts/nmas-public-dev-troubleshooting`, repository `Dhruv-Suvarna/Adv-Netman-public-ci`, branch `troubleshooting/job-9aa10b4e7ca7-port...origin/main`, inspected HEAD `4f950b36f97188f4d7b2c879006c472d9607bace`. It already contained the accepted Troubleshooter overlay and was dirty before this security work.
- Live production is `/home/student/Scripts/clab_dualstack_lab-deploy`, branch `deploy/lab8-production-20261102`, HEAD `129d3f090f8b94b982178b1e8f3ec51047278068`. It remains the private legacy deployment, not a development authority.
- Runtime topology is `/home/student/clab-quickstart`; its active topology is `srlceos01`. It is runtime state, not source authority.
- The reviewed 179-operation package has not been deployed. Production returns HTTP 404 for `/troubleshooting/` and its applied Django migration head is `0035_v2_phase7_9_decommission_dynamic`.
- Production is intentionally unchanged by this work. New guardrails form a new, unreviewed candidate and cannot inherit the previous approval.
- A separate 190-path evidence candidate was later built/staged at `nmas-sandbox-release-20261114T145500Z`; its entries identity is `955faa11...97a`. It is incomplete and not deployable because worker activation remains unresolved.

## Required-tree inventory

### `/home/student/Scripts`

The tree contained 229,608 files, 30,628 directories, 55 symlinks and one file larger than 100 MiB at inspection time. There were 120 `.git` markers, including worktrees and nested repositories. Large virtual environments, caches, images, logs, SQLite databases and binary artifacts were indexed by type/size and not recursively dumped.

Relevant project groups:

| Project/group | Role | Authority/state |
|---|---|---|
| `nmas-public-dev-troubleshooting` | Current NMAS V2 public development worktree | Authoritative for new work; dirty accepted overlay plus this guardrail change |
| `clab_dualstack_lab-deploy` | Live NMAS production source | Private legacy; exact production HEAD; 13 tracked modifications and 3 untracked files pre-existed |
| `nmas-compat-release-20261114T072224Z/package` | Reviewed compatibility package | Immutable accepted identity; not deployed |
| Other `nmas-compat-release-*`, job, phase, validation and public-dev worktrees | Historical build/review evidence | Archives or former worktrees; not assumed live or authoritative |
| `clab_dualstack_lab-*`, `Adv-Netman*` and phase-specific repositories | Earlier lab and implementation lines | Historical/private unless specifically referenced by live service paths |
| `/home/student/ai-orchestrator` | Dispatcher/agent source and documentation | Development/control-plane project; live registry/policy is root-owned under `/etc` and `/opt` |
| Virtual environments, test logs, compatibility scratch trees | Build/test support | Not deployment authority |

Sensitive-artifact inventory recorded metadata only: 70 PEM-like files, 34 key-like files, 4 `.env` files and 87 database files. No private-key, token, password, `.env`, vault or database secret value was included in evidence.

### `/home/student/clab-quickstart`

The runtime tree contained 2,116 files, 779 directories and 7 symlinks. Its approximately 4.7 GiB was predominantly vendor images (`images` approximately 4.5 GiB; Arista approximately 665 MiB, Cisco approximately 1.5 GiB and SONiC approximately 2.4 GiB). The active lab/runtime material was approximately 150 MiB; capability-validation material approximately 28 MiB. Topology definitions, generated lab state, device templates/configurations and runtime bind mounts were distinguished from images and cache material.

The active topology hash captured during discovery was `44fa83569c...3884`; 15 expected `srlceos01` topology containers were running. No topology container was restarted, recreated or modified.

## Production state

Production Git modifications observed before and after this work:

- `deploy/scripts/install_traffic_runner.sh`
- commissioning admission/service
- health evaluators
- isolation EOS/intent/service
- provisioning lifecycle/service
- topology service
- traffic runner configuration
- ZTP workflow
- `test_provisioning.py`
- untracked `DELIVERABLE_1_IAC_FRAMEWORK_SUMMARY.md`, `test_isolation_admission_ospf_release.py`, and a pre-Phase-5 SQLite backup

These belong to the existing production state and were not changed. Database checks were read-only: SQLite integrity `ok`, zero foreign-key violations, migration head `0035`. Current managed-device rows were:

| Devices | Origin/lifecycle | Identity/admission |
|---|---|---|
| R2, R4 | legacy adoption, in service | UNVERIFIED / LEGACY_PREEXISTING |
| R6, R7, R8, S5 | registered new, in service | VERIFIED / ADMITTED |

The database had no `ManagementPath` rows. Historical statements about seven unreconciled original devices therefore remain unresolved; no row was admitted or approved during this work. R5 remains inventory read-only/outside writable managed scope.

The NMAS web service, topology, gNMI, syslog, traffic and configured telemetry/timer units were inspected. A local health request and login page returned HTTP 200; `/troubleshooting/` returned 404. Exact unit activity can change between timer firings; this work issued no start/stop/restart command.

## Reviewed compatibility package and 179 operations

Package directory: `/home/student/Scripts/nmas-compat-release-20261114T072224Z/package`.

- Accepted identity in manifest: `8a4111f7b9f9553c0b78db5d633813b00beede08bd2a04bf57c9a3b6c49b8f70`.
- `manifest.json` SHA-256 reverified: `5d30929d1d197eca9dabeb449d198455b74683b18e641a37a4c35d958b2de252`.
- Operations: 171 ADD, 7 REPLACE, 1 MERGE.
- MERGE: `web/core/services/ci/rules.py`.
- REPLACE: settings, apps, middleware, models, device lifecycle, identity policy, and URLs.
- Adds migrations 0036-0039 and Troubleshooter, observation, reconciliation, templates, commands, tests, documentation and compatibility deployment support.
- The superseded `e5794558...` identity appears only as historical documentation and is not eligible for deployment.

Migrations 0036-0039 are schema operations; no `RunPython`, `RunSQL`, subprocess or network activity was found. Django import/startup and system checks do not initiate device access. New web routes become reachable only after deployment. Inventory/lifecycle/version binding requires `NMAS_TS_BINDING=nmas-v1`; all device transports are absent by default. AI model integration is absent by default. The remediation executor is unconfigured and the Change Engine adapter advertises no direct support/apply path.

## Actual activation model

| Function | Entry point/identity | Authorization and target source | Deploy-time state | Side effect/residual risk |
|---|---|---|---|---|
| Troubleshooter UI/API | authenticated Django/Gunicorn user | NMAS action permissions, case tenant/device state | route added by package; absent in production | Can start/read cases; live collection unavailable without transports |
| Deterministic collection | views or AI command as web/command service user | authoritative inventory+lifecycle+observed version; fixed command catalogs | inventory binding opt-in; transports empty | Generic provider hooks previously lacked an exact common endpoint grant; this change rejects direct production bindings |
| AI continuation | `troubleshooting_ai` command/runtime agent | NMAS opens handoff after deterministic exhaustion; typed allowlisted tools, targets, budgets | no provider configured | No raw shell/Docker/config tool; new research broker is separately opt-in |
| Device observation | explicit observation command/source identity | HMAC authorization, enrolled pin, fixed version command | source env opt-in | Bootstrap observation is not general diagnostic admission |
| Propose remediation | AI typed tool | evidence and case governance | proposal-only | Creates no execution authorization |
| Apply remediation | existing Change Engine | approvals, eligibility, device locks, validation, rollback | executor unconfigured; AI path unsupported | Must remain the only write route |
| Public research | typed AI tool through `ResearchBroker` | exact operator hostname set, HTTPS/DNS/address/redirect checks | empty hostname set, unavailable | Application control implemented; kernel namespace artifact awaits activation |
| Device worker containment | dedicated UID/service/cgroup exact IP policy | exported exact approved paths and short-lived target grants | template only | Requires privileged change-window activation and a completed worker command |

## Network reconstruction

- VM management: `ens33`, `10.224.77.0/22`, default route via `10.224.76.1`; SSH listened on port 22 on all addresses. This is Zone 1 and is not a device target.
- Lab management: `nmas-mgmt`, `192.168.200.100/24` and `2001:db8:200::100/64` plus IPv6 privacy addresses. Inventory identifies topology `srlceos01` and explicit device VLAN-200 addresses. R5 uses Containerlab-assigned management and remains excluded.
- IPv4 and IPv6 forwarding were enabled. IPv6 default routes existed through `nmas-mgmt`; reachability therefore cannot be equated with authorization.
- Firewall inventory: 8 nftables tables, 49 chains and 184 rules. IPv4 input/output/forward policies were broadly accepting; IPv6 forward was drop with Docker exceptions. `DOCKER-USER` accepted clab/capability bridges before returning. There was no default-deny Troubleshooter egress boundary.
- Docker: 49 containers, 25 privileged, no host-network containers, no Docker-socket mounts observed. Most relevant Docker networks were not `internal`.
- No unauthorized address was probed. Boundaries of university/shared networks cannot be inferred from routes, neighbor state, RFC1918 space or reachability.

## AI/orchestration state

The actual control plane consists of a dispatcher, Codex master, ClaudeA and ClaudeB workers, Slack orchestration, a root gateway and provider proxy. The live agent registry under `/etc/ai-orchestrator/agents.yaml` is root-owned. Agent processes use dedicated users, bubblewrap network unsharing and an AF_UNIX-only seccomp policy; external model egress is preconnected through a broker that validates global destinations, pins TLS destinations and audits requests.

The root gateway is host-networked and privileged. Its role allowlists and grants restrict operations, and zero current grants were observed, but root/Docker-capable infrastructure cannot be contained by Troubleshooter application checks. Broad development project mounts cover both authorized workspace roots; these are development identities and must not be reused by the production Troubleshooter. Slack/model/gateway egress is Zone 5 and does not create Zone-2 device authority.

## Trust zones and unknowns

1. VM1 management: preserve SSH, DNS, default route and ordinary client use; never a network-device target.
2. Authorized Containerlab: only exact inventory identity plus verified lifecycle/admission and approved management path; R5 excluded.
3. Shared university infrastructure: no scans, authentication or management; precise ownership/boundaries require university confirmation.
4. Public research: separately brokered HTTPS documentation only.
5. Orchestration/control: Slack/model/dispatcher/gateway traffic; cannot confer target authorization.

Unknowns requiring external or change-window resolution: authoritative university subnet/asset ownership, dedicated worker account creation, cgroup-BPF/systemd support, research namespace DNS design, exact public documentation hostname approvals, and a kernel-enforced production worker deployment. Sudo or route visibility is not evidence of ownership.

## 2026-11-14 completion update

The live privilege audit confirmed `nmas-web.service` runs as `student:student` with `SupplementaryGroups=docker`; `student` is also in `sudo`, `libvirt`, `clab_admins`, `kvm` and other broad groups. `ai-orchestrator.service` is also `student`, while `aiorch-gateway.service` is root and has the full capability bounding set. Those identities are excluded from the autonomous Troubleshooter boundary. The staged design instead uses `nmas-ts-runtime`, `nmas-ts-diagnostic` and `nmas-research`. No IPC key is added to the existing web service.

Kernel/runtime availability was verified read-only: Linux `7.0.0-30-generic`, systemd 255, unified cgroup v2, nftables 1.0.9 and unprivileged `SO_BINDTODEVICE` support. Disposable child namespaces enforced exact IPv4/IPv6 destination+port policies. This establishes deployability on VM1, not activation or university authorization.

Implementation is frozen in the separate 203-path candidate at `/home/student/Scripts/nmas-sandbox-workers-release-20261114T212024Z/package`: entries identity `cab1ac29d8be78b11dc9ecfa130843634a754049afe6c7dd012fef3e25d091d1`, manifest SHA-256 `75010e99e83b49a9a562caa8305cf363214490bd298251f473913f6492b7d596`, 194 additions, eight replacements and one merge. It has `problems: []`. The earlier 203-path builds are superseded and unapproved; the immutable 179-path and unapproved 190-path packages remain unchanged.
