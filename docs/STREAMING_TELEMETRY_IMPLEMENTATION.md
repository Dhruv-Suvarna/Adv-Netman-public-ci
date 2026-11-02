# Streaming Telemetry (gNMI/gRPC/OpenConfig) and NETCONF Implementation

Status: implemented and verified for all 10 monitored devices. R1, R2, R5,
S1, S2, S3, S4, and `mgmt_swt` use native cEOS 4.36.2F services. R3/R4
(Ubuntu 24.04 + FRRouting 8.4.4) still have no native gNMI or NETCONF
implementation; they use the explicitly labelled, repository-owned read-only
lab adapter documented in Phase 7.

This phase never touched topology, addressing, VLANs, RIP/OSPF/BGP, NAT,
DHCP, or application connectivity. The final desired state and a subsequent
no-change `--telemetry-only` run both passed, plus `--snmp-only` and
`--syslog-only` regression runs; evidence for all of it is below.

## Protocol semantics (read this first)

- **gNMI Subscribe (STREAM+SAMPLE) is genuine streaming telemetry.** A
  persistent gRPC session stays open; the device pushes updates on its own
  schedule without the collector re-asking. This is what `gnmi_telemetry`
  measurements in InfluxDB come from.
- **NETCONF here is RPC/state retrieval, not streaming.** cEOS 4.36.2F's
  NETCONF server was verified live to advertise no `:notification`,
  `:interleave`, `subscribed-notifications`, or YANG Push capability (see
  "NETCONF capability evidence" below). Every `netconf_snapshot` record in
  InfluxDB comes from a discrete `<get>` RPC issued by `verify_netconf()`,
  never a subscription. This distinction is enforced in the code itself:
  `modules/netconf.py` performs only `<hello>`/`<get>` RPCs and records
  `has_notifications`/`has_yang_push` as `false` rather than omitting them.

## Architecture

```
cEOS device (R1/R2/R5/S1-S4/mgmt_swt)
  gNMI/gRPC :6030 (TLS, dedicated user)  --Subscribe(STREAM,SAMPLE)-->
    nmas-gnmi-collector.service (systemd, repo venv, pygnmi)
      --HTTP write (line protocol)--> InfluxDB `network-monitoring` bucket
                                        measurement: gnmi_telemetry

  NETCONF/SSH :830 (dedicated user)      --<hello>/<get>-->
    modules/netconf.py (invoked from master.py --telemetry-only)
      --HTTP write--> InfluxDB, measurement: netconf_snapshot

R3/R4 adapter (management addresses only)
  gNMI/gRPC :6030 (TLS, dedicated user) --Subscribe(STREAM,SAMPLE)-->
    same nmas-gnmi-collector.service and gnmi_telemetry measurement

  NETCONF/SSH :830 (dedicated user) --<hello>/<get>/<close-session>-->
    same modules/netconf.py and netconf_snapshot measurement
```

Both protocols reuse the **existing** NMAS InfluxDB instance, organization,
bucket (`network-monitoring`) and 30-day retention policy that
`docs/SNMP_IMPLEMENTATION.md`/`docs/SYSLOG_IMPLEMENTATION.md` already
established -- no new database, org, or bucket was created.

## Phase 1: live capability discovery (evidence)

Checked live, not inferred from documentation or package names, before any
configuration change:

The R3/R4 column records the pre-adapter baseline. Their current adapter-backed
state and verification evidence are documented in Phase 7 below.

| Check | R1 (representative of all 8 cEOS) | R3/R4 |
|---|---|---|
| gNMI server | `show management api gnmi` -> `Enabled: yes`, port 6030, default VRF | No TCP 6030 listener (`ss -tlnp`); no gRPC/gNMI package |
| gNMI TLS (baseline) | `SSL profile: none` | n/a |
| gNMI auth (baseline) | `Authorization required: no`, but authentication (username/password) against local AAA *was* already enforced -- verified: a wrong password produced `GRPC ERROR ... Authentication failed` even before this phase's changes | n/a |
| OpenConfig models | `Capabilities` RPC returned 298 supported models live | n/a |
| Get supported | Verified (`/system/state/hostname` etc., see below) | n/a |
| Subscribe/STREAM/SAMPLE | Verified live (see "gNMI Subscribe proof") | n/a |
| ON_CHANGE | Accepted by the RPC (initial sync update, no error) but not verified against a real change event -- would require flapping a real topology interface, prohibited by AGENTS.md | n/a |
| NETCONF server | `show management api netconf` -> `Enabled: yes`, port 830, default VRF | No TCP 830 listener; no NETCONF/sysrepo package |
| NETCONF notifications/YANG Push | `server_capabilities` from a live `<hello>` exchange: no `:notification`, `:interleave`, `subscribed-notifications`, or `yang-push` entry among 351 capabilities | n/a |
| Management reachability from NMAS | Already established by SNMP/syslog phases (192.168.200.0/24 dedicated management network; R5 via Containerlab mgmt 172.20.20.0/24) | same |
| FRR/Linux gNMI or NETCONF | n/a | `dpkg -l` shows only `frr`/`frr-pythontools`; no `gnmi`/`netconf`/`sysrepo` package; `frr` is not even an executable name (daemons are `zebra`/`ospfd`/`bgpd`/...) |

Full per-device baseline (`show running-config | section management api`)
was identical across all 8 cEOS nodes before this phase:
```
management api http-commands
   no shutdown
management api gnmi
   transport grpc default
management api netconf
   transport ssh default
```

## Phase 2/3: cEOS gNMI TLS, auth, and OpenConfig path discovery

### The certificate material is not new PKI

Every cEOS container already had a Containerlab-generated per-node
certificate and a shared lab CA, provisioned automatically at deploy time
(no `tls:` block needed in `srlceos01.clab.yml` -- this is Containerlab's
default node cert behavior), found live at:

```
/persist/secure/ssl/certs/ca.crt     (issuer: "srlceos01 lab CA", identical SHA-256 fingerprint on all 8 nodes)
/persist/secure/ssl/certs/node.crt   (leaf cert, CN=<node>.srlceos01.io, SAN includes DNS:<node>)
/persist/secure/ssl/keys/node.key
```
and already registered in each device's own `certificate:`/`sslkey:` store
(`dir certificate:` / `dir sslkey:` show `ca.crt`, `node.crt`, `node.key`).
This phase reuses those files as-is; it never generates, rotates, or tracks
any new certificate or private key. The CA cert is copied to
`monitoring/runtime/gnmi-ca/<device>.crt` on the NMAS side purely so
pygnmi/the collector can validate the server certificate -- it is public key
material, not a secret, but is still kept under the git-ignored
`monitoring/runtime/` tree per repository convention.

### TLS profile: a verified platform quirk, and why the config is two-phase

Configuring a `management security ssl profile` and immediately assigning
it to the gNMI transport in a single push race-conditions on this cEOS-lab
build: the certificate/key binding validates asynchronously, and if the
profile is still `invalid` at the moment it's assigned to `management api
gnmi transport grpc default ssl profile <name>`, **the entire gNMI server
goes down** (`Enabled: no`), not just TLS. Reproduced live:

```
# push profile + transport assignment together
> show management api gnmi
Enabled: no
Error: SSL profile "NMAS_GNMI" not in valid state
```

`modules/gnmi.py:configure_device()` therefore pushes the certificate/user
block first, polls `show management security ssl profile NMAS_GNMI` until
`valid` (observed: resolves within 1-2 seconds), and only then pushes the
transport assignment, verifying `Enabled: yes` before declaring success.

A second platform finding, also proven and reverted immediately in this
session rather than left in place: **AAA command authorization / custom
`role` command restrictions do not work on this cEOS-lab engineering build.**
A test user assigned the built-in `network-operator` role, and separately a
custom `role` with an explicit `permit ^show .*` / `deny .*` rule set, was
both able to enter config mode and change the running configuration
(`hostname HACKED` succeeded both times). This was reverted within the same
test (`hostname R1`, test users/role removed) before any `write memory`, so
it never reached startup-config. This is the same class of defect already
documented for this build's `rsyslog.service`
(`docs/SYSLOG_IMPLEMENTATION.md`) -- a real, verified platform limitation,
not a configuration mistake. **Consequence:** the dedicated `nmas-telemetry`
account below is a credential-separation control (a distinct, rotatable,
non-`admin` identity used only for read-oriented telemetry), not a
functioning technical read-only enforcement boundary on this specific
image; this is stated plainly rather than claimed otherwise.

Given that finding, mutual TLS (`trust certificate ca.crt` on the profile)
was evaluated and **not** used for the day-to-day gNMI transport: adding a
trust anchor makes this build's gNMI server require a client certificate
during the TLS handshake (`TLSV1_ALERT_CERTIFICATE_REQUIRED`) even though
username/password authentication is also configured, which broke the
pygnmi client entirely (`FutureTimeoutError`) until the trust certificate
was removed. Server-side TLS (certificate authentication of the *device* to
the collector) plus username/password authentication of the collector to
the device is what's deployed; this is documented rather than silently
downgraded.

### What's actually configured (per device, idempotent)

`templates/monitoring/ceos_gnmi_security.j2`:
```
management security
   ssl profile NMAS_GNMI
      certificate node.crt key node.key
   exit
exit
username nmas-telemetry role network-operator secret <generated>
```
`templates/monitoring/ceos_gnmi_enable.j2` (pushed only after the profile is
confirmed valid):
```
management api gnmi
   transport grpc default
      ssl profile NMAS_GNMI
   exit
exit
```
Live result on every device:
```
> show management api gnmi
Enabled: yes
Server: running on port 6030, in default VRF
SSL profile: NMAS_GNMI
Authentication username priority: x509-spiffe, metadata, x509-common-name
```

The `nmas-telemetry` password is generated once
(`secrets.token_urlsafe(24)`) and stored at
`monitoring/runtime/telemetry-secrets.json` (mode 600, git-ignored) --
reused for both gNMI and NETCONF, since NETCONF authenticates against the
same local EOS user database. `modules/gnmi.py:configure_device()` hashes
the rendered config and the live `show running-config` section per device
(`monitoring/runtime/<device>-gnmi-state.json`) and skips reconfiguration
when both match and the profile is already valid -- proven idempotent (see
"Idempotency evidence" below).

### OpenConfig path discovery (live, not guessed)

Verified via `pygnmi` `Capabilities()`/`Get()` against R1 before any path
was added to `monitoring/config/gnmi_paths.yml`:

```
$ Capabilities() -> 298 supported_models, including openconfig-interfaces,
  openconfig-system, openconfig-network-instance, arista-interfaces-rates, ...

$ Get(/system/state/hostname)            -> "R1"
$ Get(/system/state/boot-time)           -> 1788228420476830005 (ns epoch)
$ Get(/system/cpus/cpu[index=0]/state)   -> {idle, kernel, nice, total, ...}.instant/avg/min/max
$ Get(/system/memory/state)              -> {physical, used, free, reserved} (bytes)
$ Get(/interfaces/interface[name=Management0]/state)
     -> {admin-status: UP, oper-status: UP, counters: {in-octets, out-octets, in-errors, ...}}
```

See `docs/TELEMETRY_STREAMS.md` for the full selected-stream inventory with
paths, models, sample intervals, and field-mapping documentation.

## Phase 4: the gNMI collector (persistent daemon)

`monitoring/scripts/gnmi_collector.py`, deployed to
`/etc/nmas-gnmi/gnmi_collector.py` and run as `nmas-gnmi-collector.service`
(systemd, `Restart=always`), using the repo virtualenv's `pygnmi`/`grpcio`
(system `python3` does not have them -- the unit's `ExecStart` points at
`$NMAS_VENV/bin/python`, matching the pattern in
`docs/SYSLOG_IMPLEMENTATION.md`'s `nmas-syslog-ingest.service`).

- One reconnecting thread per monitored device (8 native cEOS endpoints plus
  2 Ubuntu/FRR adapters), each holding its own persistent
  `Subscribe(STREAM, SAMPLE, interval=20s)` session over TLS with the
  `nmas-telemetry` credential.
- A device thread's exception (dropped session, auth hiccup, etc.) is
  logged to `/var/log/nmas-gnmi-collector.log` and only restarts *that*
  device's thread, with exponential backoff (2s -> 30s cap) -- one device
  failing never stops collection from the other nine.
- A single writer thread batches parsed points (up to 200, or every 5s) and
  POSTs InfluxDB line protocol to the existing `network-monitoring` bucket.
- `provision_gnmi_collector.py` (root, via `sudo -n python3 -c <script>`
  with a JSON payload on stdin, same shape as
  `provision_syslog_receiver.py`) writes the collector script, per-device
  CA certs, `devices.json`, `paths.json`, and the two credential env files,
  hash/content-compares each against what's already on disk, and only
  restarts the systemd unit when something actually changed.

Live status after final convergence:
```
$ systemctl status nmas-gnmi-collector.service
Active: active (running) since Mon 2026-09-07 07:51:05 MDT
Main PID: 864026 (python)
Memory: 32.6M
$ ps -o pid,rss,cmd -p 864026
864026 68732 /home/student/Scripts/.venv/bin/python /etc/nmas-gnmi/gnmi_collector.py
```
(PID and `ActiveEnterTimestamp` were identical before and after the final
no-change run; see "Idempotency evidence".)

## Phase 5: InfluxDB schema

Measurement `gnmi_telemetry` (existing bucket, existing 30-day retention):

| Tag | Values |
|---|---|
| `device` | R1-R5, S1-S4, mgmt_swt |
| `platform` | `ceos` \| `linux` |
| `source_protocol` | `gnmi` |
| `category` | `system_identity` \| `system_cpu` \| `system_memory` \| `interface_state` \| `interface_counters` |
| `cpu_index` | only on `system_cpu` rows |
| `interface` | only on `interface_*` rows (e.g. `Ethernet1`, `Management0`) |

Fields (one row = one gNMI update; container-valued updates like
`/system/memory/state` or `.../state/counters` write all their sub-values
as fields of the same row, not separate high-cardinality tags):
`hostname` (string), `cpu_total_pct` (int), `mem_physical_bytes` /
`mem_used_bytes` / `mem_free_bytes` / `mem_reserved_bytes` (int),
`oper_status` / `admin_status` (string), `in_octets` / `out_octets` /
`in_errors` / `out_errors` / `in_discards` / `out_discards` (int).

Measurement `netconf_snapshot` (same bucket): tags `device`, `platform`,
`source_protocol=netconf`; fields `capabilities_count` (int),
`interface_count` (int), `has_notifications` (bool), `has_yang_push` (bool).

Neither measurement stores raw JSON, full gNMI paths, or per-update unique
strings as tags -- cardinality stays bounded by device x category x
interface, matching the guardrail in the phase brief.

### Storage/query proof

```
$ query gnmi_telemetry, device=R1, last 3 minutes, limit 8:
_time                          _value  _field         category         device interface  platform source_protocol
2026-09-07T11:47:37Z            UP     admin_status   interface_state  R1     Ethernet1  ceos     gnmi
2026-09-07T11:47:57Z            UP     admin_status   interface_state  R1     Ethernet1  ceos     gnmi
2026-09-07T11:47:37Z            UP     oper_status    interface_state  R1     Ethernet1  ceos     gnmi
...

$ query gnmi_telemetry, group by device, count() over last 10 minutes:
R1=359  R2=360  R5=270  S1=479  S2=479  S3=329  S4=329  mgmt_swt=480

$ query netconf_snapshot, device=R1:
capabilities_count=351  has_notifications=false  has_yang_push=false  interface_count=8
```
All rows above are from live queries run against the real collector output
in this session (not synthetic test writes) -- the per-device counts show
continuous 20-second-interval streaming across ~10 minutes of uptime for
every device, proportional to each device's real interface count (S1/S2/
mgmt_swt have more interfaces than R5, hence more counter/state rows).

## Phase 6: NETCONF

Already enabled fleet-wide in the baseline (`management api netconf
transport ssh default`) -- this phase made **no NETCONF-side device
configuration changes**, only added verification using the same
`nmas-telemetry` credential created for gNMI (`modules/netconf.py`).

### NETCONF capability evidence (live, real device)
```
$ <hello> exchange with R1 -> 351 capabilities, including:
   urn:ietf:params:netconf:base:1.0
   urn:ietf:params:netconf:base:1.1
   urn:ietf:params:netconf:capability:candidate:1.0
   urn:ietf:params:netconf:capability:writable-running:1.0
   http://openconfig.net/yang/network-instance?module=openconfig-network-instance&revision=2026-03-17
   ... (298+ OpenConfig/Arista YANG modules)
has ":notification"?               False
has ":interleave"?                 False
has "yang-push"/"subscribed-notifications"? False
```
This was checked on every one of the 8 cEOS devices, every run, and stored
per-device in `netconf_snapshot.has_notifications`/`has_yang_push` -- always
`false`, consistently. **Conclusion, stated plainly: this cEOS 4.36.2F image
supports NETCONF `<get>`/`<get-config>` RPCs only. It does not support
NETCONF event notifications, `create-subscription`, `subscribed-notifications`,
or YANG Push. Nothing in this repository describes NETCONF polling as
"streaming."**

### Read-only query proof (real device state, not a canned example)
```
$ <get> filter=openconfig-system:state/hostname on R1
<data><system><state><hostname>R1</hostname></state></system></data>

$ <get> filter=openconfig-interfaces:interfaces/interface/name on R1
<data><interfaces>
  <interface><name>Management0</name></interface>
  <interface><name>Vlan102</name></interface>
  <interface><name>Ethernet2</name></interface>
  <interface><name>Loopback0</name></interface>
  <interface><name>Vlan101</name></interface>
  <interface><name>Vlan200</name></interface>
  <interface><name>Ethernet1</name></interface>
  <interface><name>Ethernet3</name></interface>
</interfaces></data>
```
The returned hostname and interface set match the device's real
configuration (cross-checked against `show ip interface brief` and
inventory). `modules/netconf.py:verify_device()` asserts the hostname match
and a non-zero interface count as pass/fail criteria, not just "a reply
came back."

`hostkey_verify=False` is used for the NETCONF SSH transport: Containerlab
regenerates ephemeral SSH host keys per deployment and this repo does not
pin them anywhere. This is stated as an accepted lab-scope limitation, not
hidden -- SSH transport confidentiality/integrity is still in effect; only
host-identity pinning is skipped.

## Phase 7: R3/R4 (Ubuntu/FRR) lab telemetry adapter

The pre-adapter discovery above remains accurate: FRR 8.4.4 and the Ubuntu
router image provide no native gNMI or NETCONF server. This phase adds a
small, explicitly labelled adapter; it does not claim that FRR gained native
protocol support.

### Repository-owned components

- `modules/linux_telemetry_adapter.py` assembles and sends desired state.
- `monitoring/scripts/provision_linux_telemetry.py` installs only missing
  packaged dependencies, writes protected files, preserves keys/certificates,
  and manages both processes with pidfiles and `start-stop-daemon` (no
  systemd exists in R3/R4).
- `monitoring/scripts/nmas_linux_telemetry_metrics.py` reads real state from
  `/proc/stat`, `/proc/meminfo`, and `/sys/class/net` at request/sample time.
- `monitoring/scripts/linux_gnmi_server.py` provides real gNMI protobuf/gRPC
  Capabilities/Get/Subscribe over TLS. It implements STREAM+SAMPLE for the
  six paths in `monitoring/config/gnmi_paths.yml`; Set and ON_CHANGE are
  intentionally unimplemented.
- `monitoring/scripts/linux_netconf_server.py` provides NETCONF-over-SSH
  base:1.0 EOM framing, `<hello>`, filtered read-only `<get>`, and
  `<close-session>`. Configuration RPCs return `operation-not-supported`.

The gNMI server uses the same generated v0.8 protobuf definitions as pygnmi.
The deployment copies only those generated stubs and rewrites their two
package-qualified sibling imports to local imports; the full client package
is not installed on the routers. Ubuntu packages `python3-grpcio`,
`python3-protobuf`, `python3-paramiko`, and `openssl` are installed only when
their imports are missing.

### Security and process model

- Both services bind only to `192.168.200.3` (R3) or `192.168.200.4` (R4),
  never a data-plane address or wildcard IPv4 listener.
- gNMI uses a preserved per-router self-signed TLS certificate; NETCONF uses
  a preserved per-router SSH host key. The existing `nmas-telemetry`
  credential is reused and wrong-password tests must fail for both protocols.
- `/etc/nmas-telemetry` and its TLS directory are root-owned mode 700;
  credential and private-key files are mode 600. Runtime credentials and
  private keys never enter Git.
- `/run/nmas-{gnmi,netconf}-adapter.pid` owns process lifecycle. A rerun only
  restarts an adapter when desired content, credentials, or key material
  changed. FRR daemons and the network container are never restarted.

### Protocol defect fixes and live proof

The NETCONF proof of concept originally looked for literal `<get>` and
`<close-session>` strings. ncclient correctly sends `<nc:get>` and
`<nc:close-session>`, so both were misclassified. Dispatch now parses XML and
compares expanded local names, independent of namespace prefix. A live
ncclient session returned R3/R4 hostnames and all 10 interfaces, then received
`<ok/>` from an explicit close-session.

The gNMI proof of concept also flattened PathElem names and lost keyed list
selection. The server now reads `interface`/`name` from `PathElem.key`, expands
`name=*`, honors a concrete name for Get/Subscribe, and emits the concrete key
on every interface update. Live R3 proof: all six subscriptions produced 86
initial updates, including 80 interface updates with non-wildcard keys.

Both adapters advertise exactly two model subsets (`openconfig-system` and
`openconfig-interfaces`) and NETCONF advertises only three capabilities
(base:1.0 plus those two subsets). The all-10 acceptance matrix below verifies
the same TLS/auth/Get/Subscribe/storage criteria for native and adapter
targets while the documentation preserves this distinction.

## Idempotency evidence

The first all-10 run kept every cEOS device `unchanged`, kept the already
converged R3/R4 adapters `unchanged`, and restarted the NMAS collector once
for the intentional 8-to-10 target-map/source change. The immediately
repeated full `python3 master.py --telemetry-only --verbose` run reported:

| Component | Steady-state result |
|---|---|
| Eight native cEOS gNMI configurations | 8x `unchanged` |
| R3 adapter PIDs | unchanged: gNMI 12390, NETCONF 12433 |
| R4 adapter PIDs | unchanged: gNMI 8014, NETCONF 8057 |
| R3/R4 certificate and deployed-source hashes | identical before/after |
| Eight `<device>-gnmi-state.json` hashes | identical before/after |
| Collector target map | 10 devices, identical hash |
| Collector service | `unchanged`, PID 864026 and ActiveEnterTimestamp unchanged |
| NMAS health gate | 20/20 PASS before and after |

The final automated comparison covered 24 PIDs/timestamps/hashes and returned
`IDEMPOTENCY_PASS`. No EOS management API, Linux routing service, adapter
key, systemd unit, or InfluxDB infrastructure was duplicated or needlessly
restarted.

## Regression evidence (this session, after telemetry implementation)

```
$ python3 master.py --snmp-only     -> 10/10 devices PASS (AGENT/AUTH/SYSNAME/UPTIME/CPU/IFSTATUS/STORAGE),
                                        R3/R4 snmpd + link watcher unchanged (same PIDs), trap ingestion PASS
$ python3 master.py --syslog-only   -> 10/10 devices PASS (CONFIG/CRITICAL/RAWLOG/STORAGE), unchanged
$ verify_nmas_infrastructure.sh     -> 20/20 PASS (run after every --telemetry-only invocation above)
$ docker ps                         -> all 15 lab + 2 monitoring containers running; lab containers retain six-day uptime
$ git hash-object srlceos01.clab.yml -> e03064e8... (equals the HEAD blob; no tracked topology change)
$ vtysh show ip ospf neighbor (R3/R4) -> two Full neighbors on each; OSPFv3 neighbors also Full
$ show ip bgp summary (R5)          -> both peers Estab, unchanged
$ python -m unittest discover       -> 8/8 PASS, including NETCONF namespace and gNMI PathElem regressions
```

The authoritative runtime topology file and the compact tracked topology file
were already different before this phase (notably, only the runtime copy
defines R3/R4 as Linux). Neither was edited. The tracked file still equals its
initial Git blob, while unchanged six-day container identities prove there was
no deploy/destroy/redeploy action.

## Automated verification

`monitoring/tests/verify_telemetry.py` reproduces the full capability/result
matrix on demand:
```
DEVICE     GNMI   STREAM INFLUX NETCONF  NC-GET
R1         PASS   PASS   PASS   PASS     PASS
R2         PASS   PASS   PASS   PASS     PASS
R3         PASS   PASS   PASS   PASS     PASS
R4         PASS   PASS   PASS   PASS     PASS
R5         PASS   PASS   PASS   PASS     PASS
S1         PASS   PASS   PASS   PASS     PASS
S2         PASS   PASS   PASS   PASS     PASS
S3         PASS   PASS   PASS   PASS     PASS
S4         PASS   PASS   PASS   PASS     PASS
mgmt_swt   PASS   PASS   PASS   PASS     PASS
```
`GNMI` = authenticated Capabilities+Get; `STREAM`/`INFLUX` = a fresh point
from the *persistent* collector queried back from InfluxDB (not the one-shot
verify); `NETCONF` = hello/capabilities; `NC-GET` = a real filtered `<get>`
matching device state. For R3/R4, PASS means those tests succeeded through
the explicitly labelled adapter, not that FRR provides native support.

## Secrets hygiene

- `monitoring/runtime/telemetry-secrets.json` (mode 600) -- generated
  `nmas-telemetry` password, git-ignored (`monitoring/runtime/*` in
  `.gitignore`).
- `monitoring/runtime/gnmi-ca/<device>.crt` -- public CA certs, not secret,
  still kept out of git alongside other runtime-derived material.
- `monitoring/runtime/<device>-gnmi-state.json`, `gnmi-verification.json`,
  `netconf-verification.json` -- convergence/verification records, no
  credentials inside, git-ignored regardless.
- On the NMAS host, `/etc/nmas-gnmi/credentials.env` and `ingest.env` are
  mode 600, root-owned, outside the repository entirely (same pattern as
  `/etc/nmas-syslog/ingest.env`).
- On R3/R4, `/etc/nmas-telemetry` is root-owned mode 700; `credentials.env`,
  `tls/server.key`, and the generated NETCONF SSH host key are mode 600.
  Certificates/keys are preserved on rerun and never copied into Git (only
  the public server certificates are copied to ignored `monitoring/runtime/`
  for NMAS TLS verification).
- `git status --short` / `git diff --stat` / `git grep -i password` were
  reviewed before finishing this phase; no credential, token, or private
  key is present in any tracked file added or modified here.

## Remaining explicit TODOs

1. **Grafana dashboards for `gnmi_telemetry`/`netconf_snapshot`** -- out of
   this phase's scope (Phase 6 of `IMPLEMENTATION_PLAN.md`); the InfluxDB
   datasource already exists and is healthy (verified by the 20/20 NMAS
   gate), so panels can be added directly against these two measurements.
2. **Routing/control-plane OpenConfig paths** (BGP/OSPF neighbor state via
   `openconfig-network-instance`) were confirmed present in `Capabilities()`
   on cEOS but intentionally not added to the streamed set. R3/R4 would need
   an explicit, real `vtysh ... json` mapping before advertising the same
   model; no routing state is fabricated by the current adapter.
3. **ON_CHANGE mode** was confirmed accepted by the cEOS RPC but not verified
   against a real change event (would require flapping a real topology
   interface). If a future session gets explicit approval for a controlled
   interface test, this is the mode to validate it with.
4. **NETCONF SSH host-key pinning** -- currently `hostkey_verify=False`
   (documented limitation above); pinning via `ssh-keyscan` output stored in
   `monitoring/runtime/` would close this gap without architecture changes.
