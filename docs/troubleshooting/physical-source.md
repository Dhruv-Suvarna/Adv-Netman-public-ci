# Physical-state evidence source (RB01 / RB07 / HC04 / HC05)

Status: implemented against an **injected, read-only reader**; verified with **SIMULATED** fixtures only (`web/core/tests/test_troubleshooting_physical_source.py`, IDs PHYSRC-001..020).
No live/gateway-recorded claim is made. Source pins were not refreshed by this subtask.

## Flow
`RuntimeDeps.phy_source(info) -> reader` → `collectors.PhysicalCollector` (STATE_SNAPSHOT, no device command, no default reader) →
`normalization.normalize_physical_state` (parser `phy.state` / `physical-source-1.0`) → observations → `runtime.map_observations` (existing pass-through, rate and reset paths) →
engine keys consumed unchanged by RB01 LF03/LF04 and RB07 PH01/PH03..PH09: `interface.transceiver@<if>`, `interface.fec@<if>`, `interface.l1_events@<if>`,
`interface.rate.{in_crc_errors,in_fcs_errors,in_align_errors,in_runts,in_giants,in_los,in_lof}@<if>`, `interface.counter_reset@<if>` (via `interface.counter_event=reset`).
Request building / peer scope: `adapters/physical.py` (`PhysicalContext(links)`, `requests_for_device`, `gap_reason`). New `RuntimeDeps` fields: `phy_source`, `phy_context`.

## Reader contract
`reader.read({interfaces, include, window_s, device, platform, os_version}) -> document` (optional `reader.provenance()` → gateway dict stored on the run).
Document `nmas.troubleshooting.physical-source/1`:

* `schema`, `device`, `platform`, `os_version` – must equal the admitted device (platform canonicalised; version exact when the inventory states one).
* `source_identity {id, kind ∈ gnmi-physical|snmp-entity|phy-agent|cli-structured, read_only: true}`.
* `capability {status: SUPPORTED, api}`; `scope {interfaces: [...]}` – must equal the asked interfaces (otherwise `SCOPE_MISMATCH` for every key).
* `provenance {label ∈ SIMULATED|RECORDED|LIVE_GATEWAY_PINNED, collected_at}`.
* `interfaces: [{interface, optics, fec, counters, events, events_complete}]` – bounded to 8 interfaces, 32 samples/series, 64 events; unasked, duplicate or unnamed entries are dropped/ambiguous (never re-attributed).
  * `optics {present, virtual, part, type, supported, wavelength_nm, reach_m, speed_mbps, rx_dbm, tx_dbm, temp_c, measured_at, thresholds{rx_low_warn, rx_high_warn, tx_low_warn, tx_high_warn, temp_high_warn, rx_low_alarm?}}`
  * `fec {mode, counters{boot_id, samples[{at, uncorrected, corrected}]}}`
  * `counters {boot_id, samples[{at, in_crc_errors, ...}]}` (per-sample `boot_id` overrides)
  * `events [{at, kind ∈ LOS|LOF|LINK_DOWN|LINK_UP|OPTIC_ALARM|OPTIC_WARNING|CRC_BURST|FEC_DEGRADE|ERRDISABLE, detail}]` + `events_complete: true`

## Fail-closed rules (all tested)
* Missing/failed read, denial, transport error, byte/command budget, bad identity/platform/version/capability/scope/provenance → explicit missing records bound to **key and interface subject**; never a value.
* Virtual or absent optics (`virtual: true` / `present: false`) → `UNSUPPORTED_OPERATION` (UNAVAILABLE in the engine). Unstated presence or no block → `EMPTY`.
* DOM: the runbooks read an absent threshold as "within threshold", so any missing/malformed measurement or missing/inconsistent warning threshold makes the **whole** `interface.transceiver` observation `UNTRUSTED_PARSE` (engine refuses it, PH03/PH04 become INCONCLUSIVE). Stale (>120 s before collection) → `STALE`; future-dated → `UNTRUSTED_PARSE`.
* FEC `uncorrected` is a **same-epoch delta** over ≥10 s ending ≤120 s before collection; single sample, short/stale/unordered window, missing boot id, or mode absent → no FEC value (gap). A lifetime counter is never used.
* Framing counters become rates only under the same rule; a decrease or boot-id change emits `interface.counter_event=reset` (→ `counter_reset.reset=true`, PH01 INCONCLUSIVE) and no rate.
* Event history is only a value when `events_complete` is true and every event parses and is within the bound; otherwise a gap (absence of events proves nothing).
* Peer end: read only from the peer device (must be admitted and in `affected_scope.devices`) and only when `PhysicalContext.links` maps the target interface; no link map ⇒ peer keys are `SCOPE_MISMATCH` gaps. No source ⇒ `NOT_CONFIGURED` gaps.
* Restart: no collector state; each run re-reads and re-derives from the document's own epochs, so a restarted NMAS or a rebooted device cannot turn a reset into health.

## Verification
`cd web && DJANGO_DEBUG=1 /opt/ai-orchestrator/nmas-env/bin/python manage.py test core.tests.test_troubleshooting_physical_source --noinput` → 20 tests OK (SIMULATED fixtures, in-process readers).

## INCOMPLETE_WORK / operational gaps
* No production reader exists: site implementations (gNMI OpenConfig `/components/component/transceiver`, platform-FEC, interface counters; or SNMP ENTITY/DOM MIBs) and `deployment.py` settings wiring for `phy_source`/`phy_context` are not done (deployment.py was outside this scope).
* No live qualification on cEOS 4.36.2F / IOS-XE 17.06 / FRR; virtual cEOS/containerlab ports normally have **no** DOM, so expect `UNSUPPORTED_OPERATION` there.
* `PhysicalContext.links` must be fed from NetBox intent by the deployment; `interface.rate.*` from this source and from SNMP are not de-duplicated against each other.
* RB07 PH06 compares FEC modes from the reader's text (lower-cased); vendor mode-name normalisation (e.g. `reed-solomon` vs `rs-544`) is the reader's responsibility.
* Source pins in the compatibility documents were not refreshed.
