# Stage B research activation attempt — fail-closed result

Change: `CHG-NMAS-20261115-STAGE-B-001`

Owner-authorized window start observed: `2026-11-16T06:15:42-07:00`
(`2026-11-16T13:15:42Z`). The owner supplied a 60-minute window, zero
permitted interruption, and verified vSphere Client Web Console access.

## Result

**Research was not activated.** No `activate research` command was run, so no
activation timestamp exists. Research preflight refused at
`2026-11-16T06:17:59.074547731-07:00`:

```text
REFUSED: approved namespace resolver root is missing or unsafe
```

Read-only inspection after rollback confirmed `/etc/netns` does not exist. The
reviewed command sequence did not authorize creating that missing root in the
window. Per the owner's stop condition, the attempt stopped without repair or
retry and used the independent rollback sequence.

## Observed prechecks

- Runtime plan: `plan-valid`; 1,964 base files, two reviewed overlay files, 12
  dependencies and 5,234 dependency files.
- Base manifest SHA-256:
  `b1b9c67111bede1cf4e3e9a6cac962f8a89e065179923e500ca3b3da6b835f91`.
- Overlay manifest SHA-256:
  `7ad0f2b9542b11b442dc46b0e6f65b12cde3cb40159e56e48b253c9f92e22da2`.
- Research namespace policy SHA-256:
  `49e1f29de49a3a0a9bfc1b1c6a7cea9c855d8b119d241f2fae1a71379fb26970`.
- ens33 resolvers remained `128.138.129.76`, `128.138.130.30`,
  `128.138.240.1`.
- A answers matched the approved set:
  `docs.frrouting.org` = `104.16.253.120`, `104.16.254.120`;
  `www.arista.com` = `199.232.66.132`; `www.rfc-editor.org` =
  `104.18.20.81`, `104.18.21.81`.
- The reviewed broker resolved each approved IPv4-only mapping twice and
  selected only an approved A address. Published AAAA records remained
  non-candidates because IPv6 was disabled and absent from the mapping.
- All intended NMAS-owned paths, units, namespaces and identities were absent
  before installation. Production still had zero ManagementPath rows.

## Work reached before refusal

1. The isolated `/opt/nmas` runtime installed and verified.
2. Locked nologin sysusers were created with no sudo/Docker membership:
   `nmas-ts-diagnostic` UID/GID 974, `nmas-research` UID/GID 973 and
   `nmas-ts-runtime` UID/GID 972.
3. Exact root-owned policies/configs and static units were staged and recorded
   in a mode-0600 SHA-256 receipt.
4. Diagnostic preflight refused as designed at
   `2026-11-16T06:17:49.902578327-07:00` with:

   ```text
   REFUSED: missing required approved configuration: TARGETS
   ```

   No diagnostic namespace, veth, nftables table, SNAT, service or device
   access was created.
5. Research preflight then refused on the resolver root before any research
   namespace mutation.

## Rollback observed

- Both worker units were inactive; neither unit was ever started.
- Neither research nor diagnostic namespace/veth/nftables table existed.
- Runtime uninstall returned `uninstalled` and removed `/opt/nmas` plus its
  ownership state.
- All eight staged artifacts passed their receipt checks before exact unlink.
- Both staged units, all five `/etc/nmas` Stage B files, the sysusers fragment
  and the installation receipt were removed.
- The locked nologin identities remain intentionally inert, as allowed by the
  reviewed rollback; deleting accounts requires a separate ownership/no-files
  decision.

Post-rollback baseline captured at `2026-11-16T06:18:58-07:00`:

- ens33 and nmas-mgmt addresses: unchanged.
- ens33 and nmas-mgmt route sets: unchanged.
- Host nftables SHA-256:
  `c0f2c0cd638bbc26dacd233867674c667a4fd52b2fc8cbcb2eaf8252b3cb80f8`,
  unchanged.
- SSH configuration SHA-256:
  `2e78aae499ba56bcdbc17bfa78dc80c27bb1bda39ed906de70cfa3c74ad46477`,
  unchanged.
- The pre-existing inbound SSH session
  `10.224.77.0:22 <- 198.11.30.90:58487` remained established.
- IPv4/IPv6 host forwarding remained `1/1`.
- `nmas-web`, gNMI, syslog ingest, topology, traffic runner, rsyslog, snmpd,
  snmptrapd and Docker remained active.
- All 15 frozen `clab-srlceos01-*` containers remained running.
- No research/diagnostic namespace, host nftables table, unit file, runtime or
  staged configuration survived.

## Required next decision

A future attempt requires a reviewed amendment that either supplies a safe,
root-owned `/etc/netns` resolver root before preflight or changes the lifecycle
implementation without weakening ownership checks. This attempt provides no
authorization to make that amendment or retry activation.

`STAGE_B_RESEARCH_NOT_ACTIVATED — preflight failed closed; rollback complete; host baseline unchanged`
