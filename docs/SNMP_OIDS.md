# SNMP OID Reference

Status: implemented and verified against live devices. Every OID below is drawn
verbatim from `monitoring/config/snmp_oids.yml`, the single source of truth
consumed by `modules/snmp.py`. No OID in this document is guessed; each was
confirmed with an authenticated SNMPv3 `snmpget`/`snmpwalk` against the running
lab (see the verification examples), and the CPU OID for both platforms was
discovered empirically rather than assumed from vendor documentation.

Security context for every example below: SNMPv3 `authPriv`, user
`nmas-monitor`, auth `SHA-256`, privacy `AES-128`, queried from the NMAS host
at `192.168.200.100` against each device's management address.

## Scalar OIDs

| OID | Symbolic name / MIB | Purpose | Platform | Behavior | Value interpretation |
|---|---|---|---|---|---|
| `1.3.6.1.2.1.1.5.0` | `SNMPv2-MIB::sysName.0` | Device identity check | cEOS, Ubuntu/FRR | Scalar | Octet string; must equal the inventory device name (`R1`, `R3`, ...). `modules/snmp.py:collect()` fails the run if it does not match. |
| `1.3.6.1.2.1.1.3.0` | `SNMPv2-MIB::sysUpTime.0` | Liveness / reboot detection | cEOS, Ubuntu/FRR | Scalar | `TimeTicks`, hundredths of a second since last (re)init. |
| `1.3.6.1.6.3.10.2.1.1.0` | `SNMP-FRAMEWORK-MIB::snmpEngineID.0` | USM authoritative engine discovery | Ubuntu/FRR (polled); cEOS engine ID is read via `show snmp engineID` CLI instead | Scalar | Hex-encoded `OCTET STRING`. Used only during receiver USM provisioning (`ensure_receiver()`), never for polling data. |

## Interface table OIDs (`IF-MIB::ifTable` / `ifXTable`)

| OID | Symbolic name / MIB | Purpose | Platform | Behavior | Value interpretation |
|---|---|---|---|---|---|
| `1.3.6.1.2.1.2.2.1.1` | `IF-MIB::ifIndex` | Interface table index | cEOS, Ubuntu/FRR | Indexed table (`walk`) | Integer, one row per interface; the table index used to correlate the other `if*` OIDs below. |
| `1.3.6.1.2.1.2.2.1.2` | `IF-MIB::ifDescr` | Interface description (legacy) | cEOS, Ubuntu/FRR | Indexed table | Octet string; not used for tagging, superseded by `ifName`. |
| `1.3.6.1.2.1.31.1.1.1.1` | `IF-MIB::ifXTable.ifName` | Interface name for tagging | cEOS, Ubuntu/FRR | Indexed table | Octet string (e.g. `Ethernet1`, `Vlan200`, `eth1`); used as the `interface` tag on every stored per-interface metric. |
| `1.3.6.1.2.1.2.2.1.7` | `IF-MIB::ifAdminStatus` | Configured interface state | cEOS, Ubuntu/FRR | Indexed table | Integer: `1=up`, `2=down`, `3=testing`. |
| `1.3.6.1.2.1.2.2.1.8` | `IF-MIB::ifOperStatus` | Operational interface state | cEOS, Ubuntu/FRR | Indexed table | Integer `1`-`7` per `IF-MIB` (`1=up`, `2=down`, `3=testing`, `4=unknown`, `5=dormant`, `6=notPresent`, `7=lowerLayerDown`). This is the value carried in linkUp/linkDown notification varbinds. |

`modules/snmp.py:collect()` cross-checks that `ifIndex`, `ifName`, `ifAdminStatus`
and `ifOperStatus` all return the identical set of table indices before
accepting a poll as valid, rejecting a partial/inconsistent table.

## CPU OID

| OID | Symbolic name / MIB | Purpose | Platform | Behavior | Value interpretation |
|---|---|---|---|---|---|
| `1.3.6.1.2.1.25.3.3.1.2` | `HOST-RESOURCES-MIB::hrProcessorLoad` | CPU utilization | cEOS **and** Ubuntu/FRR | Indexed table (`walk`), one row per logical processor/core | Integer percent `0`-`100`, averaged over the agent's implementation-defined interval. Verified identical on both platforms; cEOS was not assumed to expose this and was confirmed live rather than guessed. |

Verification example (Ubuntu/FRR, R3):

```
$ snmpwalk -v3 -l authPriv -u nmas-monitor -a SHA-256 -A <redacted> -x AES -X <redacted> 192.168.200.3 1.3.6.1.2.1.25.3.3.1.2
HOST-RESOURCES-MIB::hrProcessorLoad.196608 = INTEGER: 46
```

Verification example (cEOS, R1):

```
$ snmpwalk -v3 -l authPriv -u nmas-monitor -a SHA-256 -A <redacted> -x AES -X <redacted> 192.168.200.1 1.3.6.1.2.1.25.3.3.1.2
HOST-RESOURCES-MIB::hrProcessorLoad.4 = INTEGER: 46
```

Note the per-platform processor index differs (cEOS uses small integers such
as `4`/`6`/`9`; Ubuntu/FRR uses a large kernel-assigned index such as
`196608`) — the OID and semantics are identical, only the table index varies,
which is why `modules/snmp.py` walks the column rather than assuming a fixed
index.

The mean of these polled values (across every returned processor index) is
also the real, unmodified input to the collector-generated CPU threshold
evaluator (`modules/cpu_alerts.py`) — see "CPU monitoring: polling, plus
collector-generated threshold alerting" in `docs/SNMP_IMPLEMENTATION.md`.
This OID is never used to claim a native CPU threshold trap on either
platform; no such trap exists here.

## Notification (trap) OIDs

| OID | Symbolic name / MIB | Purpose | Platform | Behavior | Value interpretation |
|---|---|---|---|---|---|
| `1.3.6.1.6.3.1.1.5.3` | `IF-MIB::linkDown` (`snmpTraps.3`) | Interface transitioned operationally down | cEOS (native agent); Ubuntu/FRR (repository-owned link watcher, see `docs/SNMP_IMPLEMENTATION.md`) | Notification (`SNMPv2-Trap-PDU`) | `snmpTrapOID.0` value. Carries `ifIndex`, `ifAdminStatus`, `ifOperStatus` varbinds for the affected interface. |
| `1.3.6.1.6.3.1.1.5.4` | `IF-MIB::linkUp` (`snmpTraps.4`) | Interface transitioned operationally up | cEOS (native agent); Ubuntu/FRR (link watcher) | Notification | Same varbind set as `linkDown`, `ifOperStatus`/`ifAdminStatus` = `1`. |

Verification example — live notification captured at NMAS during a
disposable-dummy-interface transition test on R3 (`192.168.200.3`), decoded
by `snmptrapd` with `format2 NMAS_SNMP source=%b version=%s varbinds=%v`:

```
NMAS_SNMP source=UDP: [192.168.200.3]:54114->[192.168.200.100]:162 version=3 varbinds=
  .1.3.6.1.2.1.1.3.0 = Timeticks: (82200424) 9 days, 12:20:04.24
  .1.3.6.1.6.3.1.1.4.1.0 = OID: .1.3.6.1.6.3.1.1.5.4          (linkUp)
  .1.3.6.1.2.1.2.2.1.1.52 = INTEGER: 52                        (ifIndex)
  .1.3.6.1.2.1.2.2.1.7.52 = INTEGER: 1                         (ifAdminStatus = up)
  .1.3.6.1.2.1.2.2.1.8.52 = INTEGER: 1                         (ifOperStatus = up)
```

followed, on the matching down transition, by the same varbind set with
`snmpTrapOID.0 = .1.3.6.1.6.3.1.1.5.3` (linkDown) and
`ifAdminStatus`/`ifOperStatus = 2`. See `docs/SNMP_IMPLEMENTATION.md` for the
full test procedure and equivalent R4 evidence, and to distinguish this real
transition test from the separate cEOS `test snmp notification` synthetic
delivery check.

## Fields not yet backed by a discrete OID entry

`sysContact`, `sysLocation`, and per-interface counters (`ifInOctets`,
`ifOutOctets`, error/discard counters) are not currently polled. They are out
of scope for the device-side SNMP Infrastructure-as-Code phase this document
covers and are not claimed as implemented.
