# NMAS V2 deployment configuration and missing-input matrix

Prepared: 2026-11-14 (America/Denver)

This matrix separates observation and project inventory from authorization.
`Observed` never means `approved`. Values in the final column remain unset in
rendered production configuration until the named approval exists.

## Verified package and production facts

| Item | Source class | Verified value | Status / use |
|---|---|---|---|
| Candidate package | Local immutable artifact | `/home/student/Scripts/nmas-sandbox-workers-release-20261114T220008Z/package` | Review and inactive staging only |
| Manifest SHA-256 | Recomputed locally | `dfbe2f5e8b589c63853ee8f823b6adf08a682da3126d923b3091f856b2330352` | Matches acceptance report |
| Entries identity | Recomputed from canonical manifest entries | `514f49bafd8aa38d178c4c36e275f85211867fc3f00ae600b59284800dd63ddc` | Matches acceptance report |
| Manifest contents | Local audit | 205 entries: 196 ADD, 8 REPLACE, 1 MERGE; `problems: []`; unique safe relative paths; all payload hashes matched | PASS on 2026-11-14 |
| Independent-namespace successor | Local immutable artifact | `/home/student/Scripts/nmas-independent-namespaces-release-20261115T050919Z/package`; 210 entries; manifest `47c98c1a0952bf0cd52e2271685dfa1d2e3891409d1e3989072702efa8da6242`; entries `5dab9de7e6af5d29fcfb23bb194ae65bde944c276f72cb8b3afe2c6bc0bd520f` | New unapproved candidate; requires independent review and does not inherit 205-operation acceptance |
| Package checksum file | Local audit | `manifest.json: OK`; `nmas_compat_overlay.py: OK`; tool SHA-256 `46db050bd863183498203b796a21bb563026b97a829d1cdbe4678f0e5dd99a0e` | PASS on 2026-11-14 |
| Deployment artifacts | Worktree-to-package comparison | All 13 source artifacts under `deploy/sandbox/` matched their frozen package payload hashes | PASS; do not edit the frozen package |
| Production overlay preconditions | Read-only packaged verifier | `VERIFIED (pre): all 205 entries match` | Production overlay not applied |
| Production source baseline | Read-only local Git | HEAD `129d3f090f8b94b982178b1e8f3ec51047278068`, branch `deploy/lab8-production-20261102`, pre-existing dirty paths retained | Must be rechecked in the approved window |
| Production database baseline | Read-only SQLite URI | `integrity_check=ok`; zero foreign-key violations; latest core migration `0035_v2_phase7_9_decommission_dynamic` | No migration run; file hash intentionally not claimed |
| Production HTTP baseline | Localhost read-only GET | port 8002: `/healthz` 200, `/accounts/login/` 200, `/troubleshooting/` 404 | Expected pre-deployment state |
| Sandbox activation state | Local host inspection | no `nmas-ts-diagnostic` or `nmas-ts-research` namespace; no matching installed sandbox unit file | Inactive as required |
| Existing NMAS services | Local systemd inspection | web and four timers active; corresponding oneshot services inactive between timer runs | No service state changed |
| Topology runtime | Local Docker inspection | all 15 `clab-srlceos01-*` containers `Up` | No lifecycle command run |

## Network and authorization values

| Configuration item | Verified locally | Project inventory / design | Infrastructure-owner confirmation required | Production value before approval |
|---|---|---|---|---|
| VM1 primary management interface/address | Observed `ens33` with `10.224.77.0/22` | None grants authority | Confirm assignment, management prefix, protected endpoint, and required source policy | Observation only; never a worker source |
| VM1 primary IPv4 default route | Observed via `10.224.76.1` on `ens33` | None grants authority | Confirm authoritative gateway and whether namespaces may use this segment | Unset |
| Containerlab host attachment | Observed `nmas-mgmt`; project inventory lists `192.168.200.100/24` and `2001:db8:200::100/64` among its addresses | Frozen topology attachment | Confirm whether VLAN-200 prefixes are wholly project-local or shared/bridged | Protected host values only; never infer namespace attachment |
| Containerlab management network | Runtime/project inventory: `172.20.20.0/24`, `3fff:172:20:20::/64` | Frozen Docker/Containerlab management network | Confirm it requires no change and whether it must be included in protected sets for research | Do not modify |
| Diagnostic egress interface | `nmas-mgmt` is the host end of a veth into `mgmt_swt` (not a bridge) | VM-local routed veth; interface is read, never modified | Project owner names the interface; no external party owns it | `@DIAGNOSTIC_EGRESS_INTERFACE@` remains unset |
| Diagnostic link and NAT source | No external source needed | VM-local point-to-point prefix; source NAT to the existing NMAS management address | Host-networking approval for veth/forward/NAT on VM1 | `@DIAGNOSTIC_IPV4_LINK_CIDR_OR_EMPTY@`, `@DIAGNOSTIC_IPV4_NAT_SOURCE_OR_EMPTY@` remain unset |
| Diagnostic IPv6 forwarding | Docker-managed `ip6 filter FORWARD` has policy drop | Controller never edits a foreign chain | Chain owner admits the exact path, or IPv6 stays disabled | `IPV6_MODE` unset; approval ID unset |
| Research egress interface | `ens33` is the only public path, IPv4 only | VM-local routed veth; interface is read, never modified | Confirm NAT behind VM1's assigned address is permitted | `@RESEARCH_EGRESS_INTERFACE@` remains unset |
| Research link and NAT | No external source needed | VM-local point-to-point prefix; masquerade behind VM1's existing address | Institutional decision on NAT/forwarding from a worker namespace | `@RESEARCH_IPV4_LINK_CIDR_OR_EMPTY@`, `@RESEARCH_IPV4_NAT_OR_EMPTY@` remain unset |
| Research IPv6 | Only IPv6 default route is RA-learned from lab routers on `nmas-mgmt`; `ens33` has no global IPv6 | A route is not public reachability | None unless a public IPv6 path is provisioned | `IPV6_MODE=disabled` |
| DNS resolvers | Host stub/resolvers may be observable | Research requires exact recursive resolver IPs | Exact resolver IPs, UDP/TCP transport, reachability, ownership, logging | `RESEARCH_DNS_SERVERS` and manifest `dns_resolvers` remain empty |
| Institutional proxy | No proxy authorization inferred | Broker ignores proxy environment variables | State required/prohibited/not used; required proxy needs new reviewed design | Unset; direct public egress disabled |
| Protected networks/assets | Some host/lab addresses are known; private/special ranges are denied by built-in sets on both sides of the veth | Must also cover institutional public ranges and vSphere assets not in private space | Complete authoritative IPv4/IPv6 prefixes for `EXTRA_DENY_CIDRS` | `@RESEARCH_EXTRA_DENY_CIDRS_OR_EMPTY@` unset; activation prohibited |
| Public HTTPS | No live test performed | Research design permits TCP/443 after denials | Permit/deny public HTTPS from research source; specify monitoring/privacy conditions | Disabled |
| Research hostnames | Fixture hostname is simulation only | Exact, empty-by-default allowlist | Project owner and infrastructure/privacy reviewer approve each hostname | `NMAS_TS_RESEARCH_ALLOWED_HOSTS` remains empty |
| Namespace/cgroup/nft mechanisms | Independent per-namespace lifecycle now passes disposable dual-stack/failure/cross-rollback tests; current production inactive | Required containment mechanisms | Independently review the successor candidate; authorize dedicated users, systemd hardening, cgroup-BPF, namespaces, owned veth and veth-scoped host nft table, namespace-local nft and resolver files | Inactive; technical mechanism does not clear authorization |
| Maintenance and recovery | Existing SSH is currently functioning; no recovery exercise performed in this session | Console recovery required before privileged activation | Window, operator/reviewer, two-person rule, console/OOB method, escalation | Unset; no activation |

## Device and service authorization values

| Item | Verified locally / inventory | Required confirmation or approval | Until supplied |
|---|---|---|---|
| Topology identity | `srlceos01`; frozen 15-container deployment | Project owner confirms this remains the only topology scope | No device access |
| Eligible device endpoints | Production has six ManagedDevice rows but zero `ManagementPath` rows | Each device needs verified identity, admitted/in-service state, exact SSH IP/port, source binding, current host-key pin, credential reference, owners and named approvers | Target manifest must not be produced; device worker remains stopped |
| R5 | Explicitly excluded by policy and renderer | No approval requested | Remains excluded |
| Diagnostic command set | Fixed typed read-only catalog in candidate | Per-device approval must identify permitted operation families | No diagnostic execution |
| Production paths | Renderer fixes reviewed production DB/web/inventory/credential-store paths | Host owner confirms install root, venv, owners/modes and service UIDs/GIDs | Worker artifacts may not be installed |
| IPC secrets | Templates contain placeholders only | Approved secret generation, storage, ownership, distribution and rotation for distinct diagnostic/research/model keys | All key placeholders remain unset |
| Model provider | Completion-only Unix socket contract staged | Owner, UID/GID/socket mode, exact provider/model/version, key lifecycle, destination/TLS/privacy controls | Model settings remain unset; runtime not started |
| Database backup/restore | DB is healthy at 0035 | Backup location/retention/encryption, writer quiescence, restore test, migration/rollback operators | Application deployment blocked |
| Remediation | Existing Change Engine is sole writer | Existing per-change approvals, locks, prechecks and rollback remain mandatory | Troubleshooter cannot apply directly |

## Configuration rule

No production manifest or environment file may substitute observed values for
owner-confirmed values. Any unresolved value above remains an explicit
placeholder or empty allowlist, and the relevant stage remains NO-GO.

