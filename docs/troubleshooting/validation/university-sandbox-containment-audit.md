# NMAS V2 university sandbox containment and vSphere safety audit

Audit time: 2026-11-14 (America/Denver; host snapshot captured 2026-11-14 UTC)  
Host: `csci5840-vm1-dhsu9160`  
Method: read-only host, source, package, database-metadata and runtime inspection  
Decision: **NO-GO — BLOCKED_EXTERNAL**

## 1. Executive decision

The reviewed package does **not intentionally alter** VM1's management interface, DHCP configuration, routes, firewall, SSH daemon,
Docker/Containerlab topology, systemd unit files, VMware guest tools, vSphere, ESXi, vCenter, datastores, port groups or VM lifecycle.
All 179 operations are confined to NMAS source paths. The four migrations are additive Django schema migrations. No approved package
source contains a VMware/vSphere/ESXi API or command reference.

That source-level result is not sufficient to establish university-infrastructure containment. VM1 and most of its Docker networks
currently have general outbound routing through the university-facing `ens33` interface. The host output and IPv4 forwarding policies
are accept-by-default, Docker networks are not internal, and several Containerlab containers are privileged. NMAS web and timer
processes also have no destination allowlist. The authoritative NMAS resolver constrains device names and lifecycle state but does not
enforce one global permitted-address prefix for every `OTHER` management endpoint. Consequently, an erroneous or compromised target
record could cause a network-capable process to contact an address outside the lab.

The hypervisor and university virtual-network boundary cannot be observed from inside this guest without contacting infrastructure
management endpoints, which this audit correctly did not do. No supplied university/infrastructure-owner policy establishes that the
guest's `10.224.76.0/22` attachment is isolated from other students or authorizes unrestricted VM/container egress.

Therefore:

- Package content safety with respect to host/vSphere mutation: **PASS**.
- Technical containment from other students and university infrastructure: **FAIL**.
- Independent confirmation of the external vSphere/network boundary: **BLOCKED_EXTERNAL**.
- Overall deployment recommendation: **NO-GO**.
- A separate university/infrastructure-owner authorization or equivalent authoritative boundary statement **should be obtained before
  Gate B**. It must identify the assigned L2/L3 boundary and permitted destinations; project-owner status alone cannot attest to
  university infrastructure configuration.

This report does not authorize deployment. Gate B was not started.

## 2. Scope, identity and non-actions

The inspected package is the preserved release at
`/home/student/Scripts/nmas-compat-release-20261114T072224Z/package`:

| Identity | Verified value |
|---|---|
| Review identity (`entries_sha256`) | `8a4111f7b9f9553c0b78db5d633813b00beede08bd2a04bf57c9a3b6c49b8f70` |
| Manifest SHA-256 | `5d30929d1d197eca9dabeb449d198455b74683b18e641a37a4c35d958b2de252` |
| Packaged tool SHA-256 | `897c7923146e45c3988a1f8aac7d6194c5d79fe3447d688b84efe8faee29e8c1` |
| Public source revision | `4f950b36f97188f4d7b2c879006c472d9607bace` |
| Production baseline revision | `129d3f090f8b94b982178b1e8f3ec51047278068` |
| Operations | 179: 171 `ADD`, seven `REPLACE`, one `MERGE` |
| Manifest problems | none |
| Migrations | `0036`, `0037`, `0038`, `0039` |

Read-only verification produced:

```text
manifest.json: OK
nmas_compat_overlay.py: OK
VERIFIED (pre): all 179 entries match
```

The full affected-file manifest remains the immutable package `manifest.json`; this report does not duplicate or modify it. Inspection
covered every entry's action, path, source hash, destination hash and payload. A case-insensitive scan of all approved payload source
and the deployment tool found zero references to `VMware`, `vSphere`, `vCenter`, `ESXi`, `pyvmomi`, `govc`, `vim-cmd`, `esxcli`,
`vmtoolsd`, `vmware-rpctool` or `guestinfo`.

No packet was sent as part of this audit. No address was pinged, scanned, queried or authenticated. No live device command was run. No
service, timer, container or interface was stopped or started. No route, firewall, Docker network, systemd unit, production source,
database, package file or package hash was changed. No migration or deployment command was executed.

## 3. Exact trust boundaries

| Boundary | Observed state | Assurance |
|---|---|---|
| University/vSphere control plane | Outside VM1; not queried. VM1 has VMware guest tools, but the package neither imports nor invokes them. | Package non-interaction is verified; hypervisor-side isolation is **not** guest-verifiable. |
| University-facing guest uplink | `ens33`, DHCP, `10.224.77.0/22`; default IPv4 route via `10.224.76.1`. VMware OUI is present. | Shared/external trust domain. It is not an NMAS target network. |
| VM1 host administrative boundary | Root/systemd/Docker/firewall/network namespaces. SSH listens on all IPv4/IPv6 addresses. | Host root and Docker control are privileged boundaries, not application sandboxes. |
| NMAS dedicated management link | Host veth `nmas-mgmt` at `192.168.200.100/24` and `2001:db8:200::100/64`; peer is `eth9` in `clab-srlceos01-mgmt_swt`. | Direct private lab veth; neither endpoint is a member of the `ens33` bridge. |
| Containerlab management bridge | Docker bridge `clab`, `172.20.20.0/24` and `3fff:172:20:20::/64`, 15 containers. | Logically separate bridge, but `Internal=false` plus Docker NAT permits outbound routing. |
| Containerlab data-plane links | Point-to-point container namespace veth links declared by `srlceos01.clab.yml`. | Private inside VM1; no topology endpoint references `ens33`. |
| NMAS application boundary | `nmas-web` and management timers run as `student`; web and several timers inherit host networking. | No per-service IP allowlist. Web is also in the `docker` group. |
| AI gateway boundary | Root `aiorch-gateway` accessed through a Unix socket and role/operation policy. | Strong request-level controls exist, but the root service itself has host-network reach and no systemd IP deny policy. |
| AI disposable fixtures | Gateway-created `aiofx*` interfaces have nft input/forward drops; fixture limits and command allowlists apply. | Technically isolated for gateway-created fixtures only; this does not contain NMAS web/timers or existing Containerlab networks. |

The boundary drawing is therefore:

```text
vSphere / university network (external authority, unverified)
                    |
              ens33 + default route
                    |
       VM1 host/root/Docker/systemd
          |                    |
  nmas-mgmt veth          Docker bridges -- NAT --> ens33
          |                    |
  mgmt_swt container       Containerlab/monitoring containers
          |
  dedicated lab VLAN 200 and lab-routed endpoints
```

The presence of separate veths/bridges prevents accidental L2 attachment to `ens33`; it does not prevent L3 egress through VM1.

## 4. Host management-connectivity snapshot

### 4.1 Interfaces and routes

The management/uplink interface is administered by cloud-init netplan:

```yaml
network:
  version: 2
  ethernets:
    ens33:
      dhcp4: true
```

Observed key addresses and routes were:

```text
ens33            UP  10.224.77.0/22
nmas-mgmt@if404  UP  192.168.200.100/24
default via 10.224.76.1 dev ens33 proto dhcp src 10.224.77.0 metric 100
192.168.200.0/24 dev nmas-mgmt proto kernel scope link src 192.168.200.100
```

The `nmas-mgmt` peer relationship was verified by ifindex: host `nmas-mgmt@if404` is ifindex 403 and container
`clab-srlceos01-mgmt_swt:eth9@if403` is ifindex 404. Linux bridge membership showed Containerlab veths on Docker bridges; neither
`ens33` nor `nmas-mgmt` was enslaved to one of those bridges.

Specific host routes through `nmas-mgmt` exist for lab endpoints `10.254.82.2`, `.84.2`, `.85.2`, `.90.2`, `.92.2`, `.96.2`,
`192.168.10.2/.3`, and `192.168.20.2/.3`. IPv6 lab routes use documentation prefixes through the management VLAN. These narrow lab
routes are distinct from the university default route.

### 4.2 SSH

Effective `sshd -T` values were:

```text
port 22; listenaddress 0.0.0.0 and [::]
pubkeyauthentication yes
passwordauthentication no
kbdinteractiveauthentication no
permitrootlogin without-password
allowtcpforwarding yes; gatewayports no; permitopen any
x11forwarding yes; maxauthtries 50
```

The package contains no SSH daemon configuration or systemd unit. It cannot directly change these values. Existing unrestricted client
forwarding and all-address listening remain administrative exposure outside this package review.

### 4.3 Firewall and forwarding

Observed controls:

- UFW is installed but `ufw status` is `inactive`.
- nftables has eight tables, 49 chains and 184 rules.
- IPv4 `INPUT`, `OUTPUT` and `FORWARD` policies are `ACCEPT`; IPv6 forwarding has a `DROP` policy with Docker/libvirt exceptions.
- `net.ipv4.ip_forward=1` and `net.ipv6.conf.all.forwarding=1`.
- Docker forwarding/NAT rules permit non-internal bridge traffic to leave through the host. `DOCKER-USER` contains no default drop
  restricting Containerlab to authorized lab destinations.
- Existing nft rules include local service DNAT/proxy behavior. None is part of the package.

This is the decisive containment failure: separation is primarily by addressing and configuration, not by a default-deny egress
control at the VM boundary.

## 5. Container and interface audit

There were 49 running containers. None used Docker host-network mode and none mounted `/var/run/docker.sock`. Twenty-five were
privileged, including all 15 baseline Containerlab nodes and capability/demo network appliances.

| Docker network | Prefixes | Containers | `Internal` | Boundary finding |
|---|---|---:|---|---|
| `clab` | `172.20.20.0/24`, `3fff:172:20:20::/64` | 15 | false | Private bridge with general host-NAT egress. |
| `monitoring_default` | `172.18.0.0/16` | 2 | false | Outbound-capable. |
| `netbox_default` | `172.19.0.0/16` | 5 | false | Outbound-capable. |
| `nmas-human-mfa-backend` | `172.21.0.0/16` | 2 | false | Outbound-capable. |
| `nmas-human-mfa-pi_privacyidea-internal` | `172.22.0.0/16` | 3 | true | Docker-enforced internal network. |
| capability fixtures | `172.31.248.0/24`, `172.31.249.0/24` plus ULA v6 | 6 | false | Existing fixtures are outbound-capable; they are not the gateway's `aiofx*` isolated fixtures. |
| `none` | none | 11 | n/a | No Docker network attachment. |

The topology YAML has only container-to-container endpoints. R5 and WebServer lack the dedicated `nmas-mgmt` link. The package does
not contain a Containerlab lifecycle call, Docker network operation, topology file or interface configuration.

Privileged containers are a high-consequence pre-existing condition: a container escape, exposed appliance vulnerability or namespace
misconfiguration could affect VM1 networking. The package does not create or restart those containers, but their existence prevents a
claim of complete technical isolation.

## 6. Services, timers, collectors and privileges

| Component | Effective privilege/network posture | Relevant behavior |
|---|---|---|
| `nmas-web` | `student:student`, supplementary `docker`, host network, `NoNewPrivileges=yes`; no IP allow/deny and no CPU/memory limit | Gunicorn import/restart. New startup checks read settings only. The Docker group remains host-equivalent administrative capability if the web process is compromised. |
| Maintenance tick | `student`, supplementary `docker`, host network, no IP restriction, every minute | Can claim queued drains/restores and execute deadline restoration through the existing Change Engine. |
| Credential rotation | `student`, host network, no IP restriction, hourly persistent timer | Can perform authorized device account changes and persistence verification when a credential is due. |
| Probation-soak tick | `student`, supplementary `docker`, host network, no IP restriction | Samples existing evidence and updates database state; no package-added raw network transport. |
| Demo telemetry | `student`, host network, no IP restriction, every 30 seconds | Runs existing lab SSH collection and writes to loopback InfluxDB. |
| Traffic runner | Dynamic service user, empty capability set, `AF_UNIX` only and `IPAddressDeny=any` | Strong service confinement; executes root-owned, bounded namespace diagnostics through its configured interface. |
| gNMI collector | root, host network, broad bounding set, no IP restriction | Existing targets from `/etc/nmas-gnmi/devices.json`; writes to loopback InfluxDB. Not modified or restarted by the package. |
| Topology service | root, host network; loopback HTTP bind | Reads/presents monitoring data. Not modified or restarted by the package. |
| AI gateway | root, host network, broad capabilities, no IP restriction | Powerful fixture/GitHub/remote-dev operations, mediated by Unix-socket identity, role allowlists and grants. Not part of the package or restart list. |

Immediately before this report, read-only production-database queries found no queued/claimed maintenance action and no currently due
enabled credential:

```text
maintenance: CANCELLED=1, READINESS_BLOCKED=1, RESTORED=2
maintenance_queued=0; maintenance_claimed=0
credential last status: BLOCKED=12, NEVER=28, SUCCESS=1
rotation_enabled=1; enabled_with_due=0
probation soak: COMPLETED=1
```

This snapshot reduces immediate restart risk but is not an atomic deployment guard. The package's service list includes web plus the
maintenance, probation-soak, credential-rotation and demo-telemetry timers/services. Persistent timers and rapidly recurring timers can
run during a change window; database state can change after this snapshot. Restarting those timers can resume existing network reads or,
for maintenance/credential workflows, already-authorized network writes. Gate B currently needs an immediate pre-stop/pre-restart
zero-due/zero-queue assertion and a deliberate choice about whether write-capable timers are resumed in the package change window.

The website restart itself does not open a device session at import time. AST and source review found only registration, settings access,
URL construction and Django checks at module load. Actual SSH observation is command/run initiated and passes authorization, lifecycle,
credential and host-key gates. Nevertheless, because the web service has host networking and Docker-group membership, service compromise
would have broader reach than the intended application API.

## 7. Permitted NMAS targets

Permitted targets are exact inventory/lab identities, not all private addresses.

### 7.1 Dedicated management VLAN

The authoritative inventory declares:

| Devices | IPv4 | IPv6 | Platform/source |
|---|---|---|---|
| R1, R2, R3, R4 | `192.168.200.1`–`.4` | `2001:db8:200::1`–`::4` | cEOS for R1/R2; Linux/FRR for R3/R4; VLAN 200 |
| `mgmt_swt` | `192.168.200.10` | `2001:db8:200::10` | cEOS; VLAN 200 |
| S1–S4 | `192.168.200.11`–`.14` | `2001:db8:200::11`–`::14` | cEOS; VLAN 200 |
| NMAS host | `192.168.200.100` | `2001:db8:200::100` | `nmas-mgmt` |

R5 is inventory `edge: true`, address `auto`, and has no VLAN 200 identity. It is excluded from writable/observation admission by the
new resolver. Hosts H1–H4 and WebServer have no authorized NMAS device-management identity.

### 7.2 Later admitted lab endpoints

Existing host routes and production records identify the admitted lab endpoints R6 `10.254.90.2`, R7 `10.254.96.2`, R8
`10.254.82.2`, and S5 `10.254.85.2`. These are routed through `nmas-mgmt` lab gateways. Existing identity state is VERIFIED/ADMITTED
for R6/R7/R8/S5; R2/R4 remain UNVERIFIED/LEGACY_PREEXISTING. The current `ManagementPath` table is empty.

Other `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, university `10.224.76.0/22`, and IPv6 destinations are **not implicitly
authorized**. Authorization follows the named inventory/admission record and exact management endpoint.

## 8. Outbound pathways and enforcement strength

| Pathway | Possible destination | Current enforcement |
|---|---|---|
| New authenticated device observation (SSH) | Resolver-selected admitted device endpoint | **Code enforced in part:** named inventory/provisioning record, lifecycle/admission, purpose, dedicated credential, scoped authorization and exact host-key pin. `auto` and the default Containerlab management range are rejected. **Gap:** no universal subnet allowlist for every `OTHER` declared endpoint, so authoritative-data corruption/misconfiguration can select an external address. |
| New troubleshooting CLI/SNMP/gNMI/DNS/probe sources | Operator-injected providers only | **Fail-closed configuration:** deployed `NMAS_TS_DEPLOYMENT` binds inventory/lifecycle/version only; no CLI, SNMP, gNMI, DNS or probe transport is bound. Runtime defaults do not open sockets. Future bindings would need a separate review. |
| Troubleshooting remediation | Existing Change Engine handoff | `ChangeEngineExecutor.supports()` is false and its `apply` refuses. Troubleshooting adds no second device-configuration executor. Existing Change Engine remains separately capable. |
| Existing gNMI collector | `/etc/nmas-gnmi/devices.json` endpoints; loopback InfluxDB | Configured exact addresses, not firewall-enforced. The installed file currently includes R5 on the Containerlab bridge; collector predates this package and is not restarted by it. |
| Existing demo telemetry | R6/R7 lab endpoints; `127.0.0.1:8086` | Script/config selection plus host routes; no service-level destination firewall. Timer is in the restart set. |
| Existing credential rotation | Credential record's exact managed device | Application governance/credential state; no host egress filter. Timer is in the restart set. |
| Existing maintenance execution | Change Engine target devices | Application approval/queue/lock controls; no host egress filter. Timer is in the restart set. |
| Existing SNMP polling/traps/syslog | Inventory devices to/from `192.168.200.100` | Configuration-based. Receivers bind to the lab address; not changed by package. |
| HTTP services | NMAS web on loopback `8002`; Influx/Grafana/NetBox loopback or lab-published endpoints | Bind/DNAT configuration; package adds web routes but no new listener. |
| Docker/Containerlab traffic | Any route reachable through VM1 unless application/container restricts it | Host/Docker egress is not default-deny. This is the primary technical containment gap. |
| SSH client forwarding from VM1 accounts | Any route the host can reach | `AllowTcpForwarding=yes`, `PermitOpen=any`; SSH authentication is key-only. Package does not change it. |
| AI gateway fixtures | Gateway-owned isolated nodes | Unix peer credentials, role/operation allowlists, root-job ownership, command allowlists, maximum three fixtures/two per job, TTL up to 14,400 seconds, and nft drops on `aiofx*`. |
| AI remote dev VM/GitHub operations | Policy-defined remote execution host and allowlisted HTTPS sources/GitHub | Gateway policy and grants; powerful root service has no local IP filter. There were zero active grants in gateway state. The package does not import the gateway client or request an operation. |

The package adds `paramiko`/Netmiko networking only in the explicit observation transport. Tests use mocked transports. No package source
imports VMware tooling, Docker SDK, Containerlab, raw-packet/scanning libraries or a generic HTTP client for runtime discovery.

## 9. AI Orchestrator and gateway policy

The installed gateway policy uses a root-owned Unix socket, dispatcher identity, project/role operation allowlists and explicit grants
for GitHub writes. Available operations include disposable fixtures, bounded Python tests, evidence access, GitHub status/write
operations and disposable sandbox/remote-dev environments. GitHub branch push, PR creation and CI rerun require grants. Aggregate state
showed 191 historical sessions, 37 fixture records, 6,221 evidence records, 137 runs, five dev-VM records and **zero grants**.

Gateway fixture code checks per-platform command allowlists and creates internal/filtered fixture networks. The active nft table drops
input from and forwarding to/from `aiofx*` interfaces except established return traffic. That is a meaningful control, but it applies
only to fixtures created through that gateway. It does not constrain the NMAS web service, its timers, the baseline `clab` bridge or the
existing capability networks.

The gateway runs as root with full host-network reach, no `NoNewPrivileges`, no `PrivateNetwork`, no `IPAddressDeny` and no CPU/memory
limit. Its remote-development backend is enabled. This is a privileged administrative subsystem outside the approved 179 paths. The
package has no binding from troubleshooting to that gateway, and the local runtime context had no orchestrator proxy available; thus no
package startup path can invoke it. It remains a residual host-scope risk, not a package-induced change.

## 10. Package operations, imports and migrations

### 10.1 Filesystem/deployment behavior

The reviewed tool:

- pre-verifies all paths and refuses any source drift;
- backs up every replaced/merged file and uses per-file atomic replacement;
- adds only manifest paths under the selected production tree;
- records an apply journal and verifies the post-state;
- refuses apply while named services are active;
- does not modify `/etc`, `/usr`, `/var`, netplan, SSH, firewall, Docker, Containerlab or systemd unit files;
- backs up SQLite through the read-only SQLite backup API;
- requires overlay migrations to be reversed before source rollback;
- performs no VMware, hypervisor, storage, VM-lifecycle or university-network operation.

The production apply path is intentionally mutating and was not executed here. Its only subprocess call affecting the host at apply
precheck is a read-only `systemctl is-active`; service stops/starts and Django migration commands are operator steps in the Gate B
runbook, not hidden package-tool actions.

### 10.2 Django imports and startup

The settings change registers the new troubleshooting factory and observation settings. `CoreConfig.ready()` imports signal handlers and
Django system checks. Those checks inspect configuration and model/settings consistency; they do not make network connections. URL and
middleware changes are additive. No module-level socket, subprocess, route, firewall, Docker or VMware side effect was found.

### 10.3 Database migrations

Migrations `0036`–`0039` consist only of `CreateModel`, indexes and constraints. There is no `RunPython`, `RunSQL`, `DeleteModel`,
network call or host operation. Migration execution affects only the explicitly selected SQLite database. The existing independent
database-copy preflight remains the applicable data-safety evidence; this audit did not rerun or apply a production migration.

Schema rollback from `0039` to `0035` is destructive to the four newly created feature schemas and their post-deployment records. That
is documented deployment risk, but it cannot change vSphere or host networking.

## 11. vSphere and external-infrastructure finding

The approved package cannot directly manage vSphere:

- no VMware/vSphere/vCenter/ESXi SDK, endpoint, command or credential reference exists in any of the 179 payloads or the tool;
- no Terraform/Ansible VMware provider, `pyvmomi`, `govc`, `vim-cmd`, `esxcli`, PowerCLI or guest-tools RPC is invoked;
- no unit, timer, Docker network, NIC, route, bridge or netplan file is deployed;
- the tool writes only the selected NMAS tree, its separately named backup, and the separately named SQLite database backup;
- the website and new commands have no VM lifecycle feature.

VMware Tools (`vmtoolsd`) is installed and active because VM1 is a VMware guest. The package neither imports nor executes it.

What cannot be verified from VM1 is whether the `ens33` port group/VLAN permits L2 adjacency or L3 reachability to other student VMs,
whether anti-spoofing/promiscuous/MAC-change controls are enabled, and which private/university destinations VM1 is authorized to reach.
Querying ESXi/vCenter or other VMs to answer those questions was prohibited and unnecessary for the package static review. This missing
external attestation is a real boundary blocker, not evidence of an intended package action.

## 12. Resource-exhaustion assessment

Snapshot:

```text
RAM: 94 GiB total, 43 GiB used, 50 GiB available; swap unused
root filesystem: 121 GiB total, 90 GiB used, 26 GiB free (78%)
inodes: 16% used
Docker: 11.86 GiB images, 2.77 GiB containers, 3.43 GiB reclaimable build cache
```

Several network-appliance containers were each using roughly 30–70% CPU at the instant sampled; one IOS XE fixture used about 4 GiB RAM.
There was ample current memory and inode headroom, but only 26 GiB free disk and no useful cgroup CPU/memory caps on the web, timers,
gNMI collector, topology service or AI gateway. The new troubleshooting code has application budgets for commands/time/bytes/records,
but a bad loop, log growth, evidence growth, many concurrent requests or pre-existing container load could still cause VM-wide CPU,
memory, I/O or disk pressure.

Loss of disk or CPU can indirectly impair SSH and DHCP renewal even when no network configuration is changed. Current capacity is not a
guarantee; resource saturation remains a medium residual risk. Package deployment itself adds source files and schema, not large images
or traffic generators.

## 13. Credible management-connectivity and collateral-impact scenarios

Potential ways VM1 could lose management connectivity include:

1. VM-wide CPU, memory, process or disk exhaustion delaying `sshd`, DHCP renewal or system services.
2. Compromise of a Docker-group application process, privileged container or root gateway changing host routes/firewall/interfaces.
3. Operator error outside the manifest while stopping/starting services or selecting backup/database paths.
4. Existing Docker/libvirt/nft rule changes or a container escape, none of which the package performs.
5. An unrelated upstream DHCP, vSphere port-group or university-network change.

Potential ways other VMs or shared infrastructure could be affected include:

1. A misconfigured inventory/provisioning endpoint selecting a university-reachable address; application admission would validate the
   device record, but no universal destination-prefix filter would reject every out-of-lab address.
2. A compromised host-network service, Docker-group process or privileged container using the `ens33` default route.
3. Existing SSH client forwarding relaying traffic through VM1.
4. A runaway collector/probe/traffic process consuming shared bandwidth. New troubleshooting probes are unbound by default, but existing
   collectors and timers are configured rather than host-firewall constrained.
5. AI gateway misuse through an authorized high-privilege operation. Its project/fixture controls reduce this risk; the root service
   remains capable by design.

No reviewed package code intentionally performs any of these actions. They remain plausible because the technical boundary is permissive.

## 14. Controls that already reduce risk

- Exact immutable 179-entry manifest, path hashes, approval identity and pre/post verification.
- Package tool refuses drift, active services, partial/changed payload and unsafe database/source rollback order.
- No host configuration, service unit, topology, Docker, vSphere or guest-tools path in the manifest.
- Private direct `nmas-mgmt` veth and separate Containerlab bridges; no `ens33` bridge attachment.
- Named inventory, lifecycle/admission checks, R5 exclusion, dedicated credential references, scoped observation authorization and SSH
  host-key pin verification.
- Troubleshooting transports are unbound by default; missing providers fail closed.
- Read-only transport wrappers omit configuration methods.
- Change Engine handoff cannot execute from troubleshooting; no second configuration executor exists.
- Traffic-runner network/systemd confinement.
- Gateway Unix peer identity, role/operation allowlists, grant checks, fixture ownership/TTL/count limits, command allowlists and `aiofx*`
  firewall isolation.
- Current database snapshot has no queued maintenance action and no due enabled credential.

## 15. Missing controls and required disposition

Before Gate B can receive a containment GO, all critical items below need an authoritative disposition:

1. **Infrastructure boundary authorization — BLOCKED_EXTERNAL.** Obtain a university/infrastructure-owner statement identifying VM1's
   assigned VLAN/port-group/L3 boundary, whether other student VMs are reachable, and the destinations/protocols the project may use.
2. **Enforceable outbound scope — FAIL.** Apply an infrastructure-approved default-deny egress policy for NMAS/container processes with
   exact exceptions for the documented lab endpoints and required loopback services. Because firewall/network changes are outside this
   audit and may affect SSH, they require a separately reviewed change; this report does not prescribe executing them now.
3. **Target prefix validation — FAIL.** Add and separately review a global endpoint policy that binds every observation/collector/probe
   target to explicit authorized lab prefixes/host identities, including `OTHER` paths. Do not treat RFC1918 as authorization.
4. **Timer restart guard — FAIL.** Immediately before service stop and again before restart, verify zero queued/claimed maintenance
   records and zero due enabled credentials. Do not resume write-capable timers unless that behavior is explicitly within the approved
   window. Preserve the current no-Phase-C rule.
5. **Web privilege reduction — FAIL.** Remove unnecessary Docker-group membership and add destination/service sandboxing if compatible.
   This is a separate hardening change, not a permitted edit to the approved package.
6. **Resource controls — advisory FAIL.** Define service CPU/memory/task/log/disk limits and deployment free-space stop thresholds.
7. **Post-change invariant capture — required.** Capture and compare `ip -j address`, routes/rules, bridge membership, SSH effective
   configuration, nftables/iptables digests, Docker network definitions and vSphere guest NIC identity before and after deployment.
   Any difference is an automatic stop. These are observations, not permission to change those resources.

The first two items are critical. A documentation-only assertion by the project owner cannot substitute for an external network boundary
or a technical egress control.

## 16. Acceptance-gate matrix

| Gate | Status | Evidence/reason |
|---|---|---|
| Approved package identity and 179/179 production preconditions | **PASS** | Checksums valid; exact review identity; `problems: []`; pre-verify passed. |
| Package avoids host address/route/interface/firewall/SSH changes | **PASS** | All operations inspected; no applicable host configuration path or command. |
| Package avoids Docker/Containerlab lifecycle/network changes | **PASS** | No topology/network/unit operation; no Docker/Containerlab runtime import. |
| Package avoids VMware/vSphere/ESXi/vCenter/datastore/VM operations | **PASS** | Zero SDK/command references; no guest-tools invocation or infrastructure automation. |
| Import/startup side-effect safety | **PASS** | Startup imports/settings/checks are local; device transports are invoked only by explicit authorized operations. |
| Database migration host/network isolation | **PASS** | `0036`–`0039` are additive schema operations only. Production migration not run. |
| Exact lab trust-boundary mapping | **PASS** | `ens33`, `nmas-mgmt` peer, Docker bridges, routes and inventory mapped read-only. |
| No host-network Docker containers / no Docker socket mounts | **PASS** | 49 running; zero host-network and zero Docker-socket mount. |
| Container/host egress containment | **FAIL** | IPv4 accept/forward/NAT posture; most bridges non-internal; 25 privileged containers. |
| Application endpoint allowlisting | **FAIL** | Strong identity controls but no universal authorized-prefix policy for all resolver endpoint classes. |
| Timer restart cannot cause unauthorized network write | **FAIL** | Current queues are empty, but persistent write-capable timer execution is not atomically gated by the deployment checklist. |
| AI request-level fixture confinement | **PASS** | Unix identity, roles/grants, command allowlists, TTL/count limits and nft fixture isolation. |
| AI gateway host-level confinement | **FAIL** | Root/full host network with no IP/cgroup/systemd sandbox restrictions; outside package scope. |
| Resource headroom at audit instant | **PASS** | 50 GiB available RAM, 26 GiB free disk, inode headroom. |
| Resource-exhaustion controls | **FAIL** | Core services have unlimited CPU/memory and high task ceilings. |
| University/vSphere external boundary attestation | **BLOCKED_EXTERNAL** | Cannot be established from guest without prohibited external contact; no authoritative statement supplied. |
| Live proof against other students/management endpoints | **NOT_TESTED** | Correctly prohibited; no external endpoint was contacted. |

## 17. Final recommendation

**NO-GO — BLOCKED_EXTERNAL. Do not start Gate B.**

The approved package should remain byte-for-byte unchanged while the containment decision is resolved. Its static and deployment-tool
review supports the narrower conclusion that it has no intentional host-network or vSphere-management operation. It does **not** support
the broader conclusion that VM1, its containers and application processes are technically unable to reach or affect surrounding
university resources.

Obtain the infrastructure-owner boundary/authorization statement and an approved enforceable egress design, then repeat the read-only
firewall, route, Docker-network, service-privilege and timer-state checks. Only a subsequent report may reconsider containment GO. Even
then, the ordinary P1/P2/P3 and explicit Gate B records remain separate requirements, and this audit must not be represented as
production deployment or in-production acceptance.
