# Grafana Monitoring Taxonomy (Phase 2, current)

Status: current-state document, established 2026-09-20 in the same session
that reconciled the Grafana dashboard set into the three-page taxonomy
required by the future Django Monitoring area. This document supersedes
`docs/GRAFANA_DASHBOARDS.md` as the reference for *current* dashboard
structure; that file is preserved unchanged as the dated historical record
of the original Labs 2/3 four-dashboard implementation (2026-09-07) and now
carries a pointer to this document. Nothing here changed the underlying
monitoring architecture: collectors, InfluxDB, and the Grafana instance are
exactly as documented in `docs/GRAFANA_DASHBOARDS.md`, `docs/
NMAS_MONITORING_INFRASTRUCTURE.md`, `docs/SNMP_IMPLEMENTATION.md`, `docs/
SYSLOG_IMPLEMENTATION.md`, and `docs/STREAMING_TELEMETRY_IMPLEMENTATION.md`.

```text
Devices / collectors (SNMP, gNMI, syslog, NETCONF, collector-side CPU alerts)
        |
        v
   InfluxDB (network-monitoring bucket, unchanged)
        |
        v
     Grafana  --  7 dashboards: 3 canonical + 4 legacy/compatibility
```

## 1. Why a taxonomy reconciliation was needed

Phase 1 found the pre-existing four dashboards (`nmas-fleet-overview`,
`nmas-streaming-telemetry`, `nmas-snmp-monitoring`, `nmas-critical-syslog`)
do not map 1:1 onto the three pages the future Django Monitoring area
requires (Resources / Link Events / Link State & Traffic) -- each legacy
dashboard mixes resource and link concerns. Phase 1 also found a real
verifier defect: `monitoring/tests/verify_grafana.py` treated the "NMAS
Collector CPU Alerts" panel as a failure whenever no real CPU-threshold
event had recently occurred, even though an empty result there is the
*normal, healthy* outcome. Both are addressed in this phase.

## 2. Design decision: three new canonical dashboards, legacy dashboards retained

**Strategy chosen: create three new canonical dashboards matching the
taxonomy exactly, and retain the four existing dashboards unchanged as
legacy/compatibility.** Rejected alternatives:

- *Reorganizing/renaming the existing four dashboards in place* would have
  meant materially rewriting `fleet_dashboard()`, `telemetry_dashboard()`,
  `snmp_dashboard()`, and `syslog_dashboard()` -- all of which are already
  live-verified, tested, and (per `AGENTS.md`) not something this phase
  should be rewriting when nothing was reported broken about them. It would
  also have silently invalidated any bookmark/link to the current four
  dashboard UIDs.
- *Deleting the legacy dashboards* is explicitly disallowed by this phase's
  instructions ("do not delete working dashboards merely to make the
  structure aesthetically cleaner").

Creating three new, additive dashboards keeps the existing, verified
implementation completely intact (only a metadata field was added to
existing panel definitions -- see §5) while giving Django a clean, exact
mapping to build against. The four legacy dashboards are tagged `legacy` in
their Grafana `tags` array and each carries a one-line pointer in its
`description` to the canonical dashboard(s) that supersede it for new
consumers; the three canonical dashboards are tagged `canonical`. Nothing in
`modules/snmp.py`, `modules/syslog.py`, `modules/gnmi.py`,
`modules/netconf.py`, or `modules/cpu_alerts.py` changed -- no collector was
duplicated, and there is still exactly one InfluxDB instance and one Grafana
instance.

Source-logic duplication was minimized, not eliminated: three small shared
Python helpers in `monitoring/scripts/build_grafana_dashboards.py` --
`basic_filters()`, `link_state_filters()`, and
`recent_critical_syslog_panel()` -- are each defined once and called from
every dashboard function that needs that exact panel/filter, rather than
each canonical dashboard re-typing its own copy. Some duplication between a
legacy panel's Flux and a similar canonical panel's Flux is unavoidable:
Grafana's dashboard-JSON model has no way to reference another dashboard's
panel definition, and rewriting the legacy panels to call the new shared
helpers was judged higher-risk (touching already-verified, tested JSON) than
it was worth for this phase.

## 3. Dashboard inventory

| Dashboard | UID | Status | Panels | Variables |
|---|---|---|---:|---|
| NMAS Resources | `nmas-resources` | **canonical** | 9 | `device`, `platform`, `severity`, `unhealthy_only` |
| NMAS Link Events | `nmas-link-events` | **canonical** | 6 | `device`, `event_type`, `severity` |
| NMAS Link State & Traffic | `nmas-link-state-traffic` | **canonical** | 8 | `device`, `platform`, `interface`, `hide_zero_traffic`, `hide_down`, `active_only`, `include_mgmt`, `include_loopback` |
| NMAS Network Health Overview | `nmas-fleet-overview` | legacy | 12 | `device`, `platform` |
| NMAS Streaming Telemetry | `nmas-streaming-telemetry` | legacy | 11 | `device`, `platform`, `interface` |
| NMAS SNMP Monitoring | `nmas-snmp-monitoring` | legacy | 10 | `device` |
| NMAS Critical Syslog | `nmas-critical-syslog` | legacy | 6 | `device`, `severity` |

All seven live in the same `NMAS Network Monitoring` Grafana folder
(`nmas-network-monitoring`), use the same single datasource
(`nmas-influxdb`), and are generated by the same deterministic builder,
`monitoring/scripts/build_grafana_dashboards.py` (`python3
monitoring/scripts/build_grafana_dashboards.py [--check]`), exactly as
before. Live acceptance after this phase: **dashboards=7 panels=62
variables=23 queries=79**, all PASS (`monitoring/tests/verify_grafana.py
--verbose`).

## 4. NMAS Resources

Maps to the future Django "Resources" page: device/system health.

| Panel | Type | Source | Event-optional |
|---|---|---|---|
| Devices reporting (5m) | stat | `gnmi_telemetry` | no |
| Worst telemetry age | stat | `gnmi_telemetry` | no |
| Latest CPU by device | bargauge | `gnmi_telemetry` | no |
| NMAS Collector CPU Alerts (range) | stat | `collector_alert` | **yes** |
| Per-device health & freshness | table | `gnmi_telemetry` | yes (with `unhealthy_only=true`) |
| CPU utilization | timeseries | `gnmi_telemetry` | no |
| Memory utilization | timeseries | `gnmi_telemetry` | no |
| SNMP-polled CPU & device uptime | table | `snmp_poll` | no |
| Resource-related critical syslog | table | `syslog_event` | yes |

Filters: `device`, `platform`, `severity` (syslog panel only), time range
(native Grafana), and `unhealthy_only` (custom variable; hides `HEALTHY`
rows on the per-device table when `true`). "Non-zero-only" was considered
and intentionally **not** added to this page: CPU/memory are continuous
percentages, not sparse counters, so a "hide zero" toggle has no meaningful
target here -- adding one would have been a no-op control. Device
availability/health comes only from observed `gnmi_telemetry` freshness
(never fabricated for an absent device, per the existing fleet-overview
convention). Uptime is sourced from SNMP (`snmp_poll`/`sysUpTime`) because
gNMI does not stream an uptime leaf in the current schema (see
`monitoring/config/gnmi_paths.yml`).

## 5. NMAS Link Events

Maps to the future Django "Link Events" page: chronological interface/link
notifications.

| Panel | Type | Source | Event-optional |
|---|---|---|---|
| SNMP notifications (range) | stat | `snmp_trap` | **yes** |
| Critical syslog (range) | stat | `syslog_event` | **yes** |
| Trap types | bargauge | `snmp_trap` | **yes** |
| Notification volume over time (by event type) | timeseries | `snmp_trap` | **yes** |
| Recent SNMP notifications | table | `snmp_trap` | **yes** |
| Recent critical syslog | table | `syslog_event` | **yes** |

Filters: `device`, `event_type` (a new query-derived variable, distinct
values of `snmp_trap.event_type` -- `linkUp`/`linkDown`/
`ceosTestNotification`/`other`), `severity` (syslog panel), and time range.
Every panel on this page is event-optional: it is chronological, discrete
notification data, and a fully quiet/stable window legitimately contains
zero rows. This is not a blanket "allow empty" -- see §7.

**Filters considered and not implemented, with reasons (documented per this
phase's instructions rather than silently added as no-ops):**

- *"Interfaces with events only"* -- every row on this page already
  represents an interface/device with a real event; there is no "all
  interfaces including quiet ones" base view on an event-oriented page to
  narrow from, so a toggle here would do nothing.
- *"Hide administratively-down"* -- `snmp_trap` rows carry no admin-state
  field to filter on (a trap is a point-in-time notification, not a
  state snapshot), and reliably joining a trap's `ifindex` to a live
  admin-state observation would require assuming SNMP `ifindex` and gNMI/
  OpenConfig interface names always correspond 1:1, which is not verified
  across both platforms. Rather than build a fragile, silently-wrong join,
  this filter is **not implemented on Link Events**; it *is* implemented
  correctly on Link State & Traffic (§6), where a single measurement
  already carries both the state and the counters together. The future
  Django layer can add a client-side "hide admin-down interfaces'" trap
  rows filter if the interface-name correspondence is later formalized.

**Data-source honesty note:** no discrete "admin-state transition event" or
"interface error/discard event" measurement exists anywhere in the
collection schema -- `gnmi_telemetry` stores continuous sampled state and
counters, not discrete transition/error events. This page therefore does
not fabricate a derived "event log" for either; continuous interface state
and error/discard *rates* are correctly presented as continuous metrics on
NMAS Link State & Traffic instead. `linkUp`/`linkDown` SNMP notifications
are the only real, natively-emitted discrete link-transition events in the
current schema.

## 6. NMAS Link State & Traffic

Maps to the future Django "Link State & Traffic" page: current/historical
interface operational state and utilization.

| Panel | Type | Source | Event-optional |
|---|---|---|---|
| Interface administrative state | state-timeline | `gnmi_telemetry` | no |
| Interface operational state | state-timeline | `gnmi_telemetry` | no |
| Current interface state | table | `gnmi_telemetry` | no |
| Interface traffic rate | timeseries | `gnmi_telemetry` | no |
| Error and discard rate | timeseries | `gnmi_telemetry` | no |
| Active / highest-traffic interfaces | table | `gnmi_telemetry` (joined) | no |
| Latest interface counters | table | `gnmi_telemetry` | no |
| Latest NETCONF RPC snapshots | table | `netconf_snapshot` | no |

No panel on this dashboard is event-optional: every one of them is a
continuous state/metric view that should always show a current value while
the fleet is healthy (confirmed live: all eight panels returned real,
nonzero-frame data in this phase's live verification run).

Filters: `device`, `platform`, `interface`, and five custom boolean
variables -- `hide_zero_traffic`, `hide_down`, `active_only`,
`include_mgmt` (default `true`), `include_loopback` (default `true`). All
five default to reproducing the pre-existing, unfiltered dashboard
behavior (nothing hidden by default); an operator or the future Django
layer opts in to narrowing the view.

**"Active" is defined explicitly as admin UP *and* oper UP** (both fields
observed together on the same `gnmi_telemetry` `interface_state` sample).
This is the definition applied everywhere `active_only` appears.

**Management/loopback interface identification** uses real observed
interface-name patterns, not a guess: `Management0` and `Vlan200` (cEOS --
`Vlan200` is the frozen management SVI on every non-`R5` device per
`inventory.yml`) for "management", and `lo` (Linux) or an IF-MIB
`Loopback*` name (cEOS convention; none currently provisioned in this lab)
for "loopback". **Known limitation:** R3/R4 (Ubuntu/FRR) carry their
management traffic on a numbered 802.1Q subinterface (observed live:
`eth1.101`-`eth1.104`, alongside `eth0`/`eth1`/`eth2`/`eth3`/`lo`) whose
name does not self-describe a management role, so `include_mgmt=false`
reliably excludes management traffic on cEOS devices but **not** on R3/R4.
This is disclosed here rather than guessed at with an unverified subinterface-to-VLAN
mapping. A future Django-side or collector-side "interface role" tag would
resolve this cleanly.

**`hide_zero_traffic` / `hide_down` / `active_only` are honored together
only on the "Active / highest-traffic interfaces" ranking table**, not on
the two raw timeseries panels (traffic rate, error/discard rate). This is a
deliberate scoping decision, not an oversight: a historical time-range
chart should not retroactively hide data because an interface is down or
idle *right now* -- doing so would misrepresent history. The ranking table,
by contrast, is a current-state view (latest observed admin/oper state
joined with a recent mean traffic rate via Flux's `join()` on
`["device","interface"]`), so applying all three filters there is both
correct and useful. This was verified live: the join executes successfully
against the real InfluxDB instance and returns real ranked data (20 rows in
this phase's live check).

**Operator narrowing to one device + one interface:** every panel except
"Latest NETCONF RPC snapshots" (a device-level snapshot with no
per-interface tag in the stored schema) filters on both `${device:regex}`
and `${interface:regex}`, so selecting one device and one interface in the
dashboard variable dropdowns (or via a Django-constructed URL, see §8)
narrows every remaining panel without editing any query.

### Rate and utilization semantics

Ingress/egress traffic is a **non-negative derivative of the raw streamed
octet counters** (`in_octets`/`out_octets`), converted to bits/second --
identical math to the pre-existing streaming-telemetry dashboard, now also
filtered by management/loopback exclusion. **No percentage-utilization
panel is implemented, and none should be added without first adding a
capacity source:** no collector (gNMI stream set in
`monitoring/config/gnmi_paths.yml`, or the polled SNMP OID table in `docs/
SNMP_OIDS.md`) stores interface speed/capacity (`ifSpeed`/`ifHighSpeed` or
an OpenConfig equivalent) anywhere in the schema -- confirmed by inspection
of both files in this phase, not assumed. Fabricating a percentage against
an unknown denominator was rejected outright per this phase's explicit
data-honesty requirement. Errors and discards are likewise non-negative
counter derivatives (rate, not raw cumulative count).

## 7. Event-optional panel semantics (the Phase-1 CPU-alert-panel fix)

**The bug:** `monitoring/tests/verify_grafana.py` previously failed the
"NMAS Collector CPU Alerts" panel whenever it returned zero rows, even
though a quiet window with no CPU-threshold breach is the normal, healthy
outcome -- not a query failure, datasource failure, malformed Flux query,
missing measurement, or broken panel. The only prior tolerance mechanism
was a flat, dashboard-unscoped `ALLOW_EMPTY = {"Current non-UP interfaces",
"Recent linkDown notifications"}` set in `modules/grafana.py`, matched only
by panel *title*, and it simply did not include this panel.

**The fix -- a metadata mechanism, not a widened allow-list:**

1. `monitoring/scripts/build_grafana_dashboards.py`'s `panel()` builder now
   takes an `event_optional: bool = False` keyword argument. When set, it
   is written into the generated panel JSON itself as a plain field,
   `"eventOptional": true`. This is declared exactly once, at the same
   place each panel's Flux query is written -- there is no second,
   separately-maintained list to keep in sync with the panel set.
2. `modules/grafana.py` reads this field back directly from the very same
   generated source it already loads for every other structural check
   (`source_dashboards()`), via a small pure function:
   `panel_requires_data(panel) -> bool`, `not panel.get("eventOptional",
   False)`. The old `ALLOW_EMPTY` set is removed entirely.
3. `verify_grafana()`'s per-panel check becomes: **always execute the
   query and require `status == 200` with no Flux error** (unconditional --
   this proves the query executes, the datasource responds, and the result
   format/measurement/query are structurally valid, for every panel,
   event-optional or not) **and additionally require at least one data
   point, unless `panel_requires_data(panel)` is False.**

**Classification principle applied to every panel** (documented once here,
not scattered): a panel is event-optional exactly when either (a) its
target queries a measurement that is itself an event/notification log
(`snmp_trap`, `syslog_event`, `collector_alert`) rather than continuous
state/metrics, or (b) it is a *condition/exception filter* over continuous
state that only ever returns rows when something is currently abnormal
(e.g. "Current non-UP interfaces" -- filtered to non-UP only). Every
panel whose target queries continuous state/metrics without such a filter
(`gnmi_telemetry`, `snmp_poll` state/CPU, `netconf_snapshot`) remains
strict. This was checked against live data in this phase (see the exact
per-panel point counts in `verify_grafana.py`'s output above): every
strict panel returned real, nonzero data; the **only** panel that returned
zero rows was "NMAS Collector CPU Alerts" -- exactly the Phase-1 finding,
now correctly tolerated instead of failing the whole verifier run.

This was **not** solved by a blanket "allow every query to return empty."
The majority of panels across all seven dashboards remain strict (require
real data): every CPU/memory/freshness/uptime/state/counter panel on every
dashboard, all eight Link State & Traffic panels, and the resource
health-check panels on NMAS Resources. A genuinely broken/malformed query
still fails immediately regardless of `eventOptional`, because the
query-execution/status/error check happens unconditionally, before the
event-optional zero-rows exemption is ever considered (unit-tested in
`monitoring/tests/test_grafana.py::GrafanaLiveFailureModeTests`).

## 8. Django integration contract (Phase 6 input)

This section is the explicit hand-off contract for the future Django
Monitoring pages. **No Django code, iframe embedding, or authentication
integration was built in this phase** -- this is documentation only, per
this phase's explicit scope limit.

### Canonical dashboards

| Django page | Grafana UID | Grafana title |
|---|---|---|
| Resources | `nmas-resources` | NMAS Resources |
| Link Events | `nmas-link-events` | NMAS Link Events |
| Link State & Traffic | `nmas-link-state-traffic` | NMAS Link State & Traffic |

UIDs are hand-assigned string literals in
`monitoring/scripts/build_grafana_dashboards.py` (not Grafana-generated
integer IDs) and are therefore stable across regeneration/reprovisioning by
construction -- confirmed idempotent live in this phase (identical
`version`/`id` across three consecutive `master.py --grafana-only` runs).

### Variables and value format

Every variable is a Grafana dashboard template variable; Django constructs
a Grafana URL/embed link with `var-<name>=<value>` query parameters.

| Variable | Dashboards | Type | Value format |
|---|---|---|---|
| `device` | all | query (multi) | exact device name (`R1`, `S3`, `mgmt_swt`, ...) or `All` |
| `platform` | Resources, Link State & Traffic | query (multi) | `ceos` or `linux`, or `All` |
| `interface` | Link State & Traffic | query (multi) | exact interface name (`Ethernet1`, `eth0`, ...) or `All` |
| `event_type` | Link Events | query (multi) | `linkUp` / `linkDown` / `ceosTestNotification` / `other`, or `All` |
| `severity` | Resources, Link Events | query (multi) | e.g. `crit` (currently the only value the deployed syslog policy forwards) |
| `unhealthy_only` | Resources | custom, single | literal string `"false"` or `"true"` |
| `hide_zero_traffic`, `hide_down`, `active_only`, `include_mgmt`, `include_loopback` | Link State & Traffic | custom, single | literal string `"false"` or `"true"` |

Multi-value query variables use Grafana's standard `All` value; a specific
selection is the literal device/platform/interface/event-type/severity
string exactly as stored (these are real tag values read live from
InfluxDB by the variable's own query -- never hardcoded). To reduce the
view to **one device + one interface**, Django sets `var-device=<name>` and
`var-interface=<name>` on the Link State & Traffic dashboard URL; every
panel there (except the device-level NETCONF snapshot table) already
filters on both.

### Stable panel identifiers

Panels are identified by `title` (unique per dashboard, enforced by both
the generator and `modules/grafana.py`'s `EXPECTED` contract) -- there is no
separate numeric panel-ID contract, since Grafana panel IDs are only stable
within one generated dashboard version and are not part of the public URL
contract. If Django needs to deep-link to one panel, use Grafana's
`viewPanel=<panel id>` URL parameter read live from
`/api/dashboards/uid/<uid>` at link-construction time, not a hardcoded
number.

### Embedding vs. full-dashboard link

Grafana is intentionally published only on NMAS's loopback
(`127.0.0.1:3000`), per `docs/GRAFANA_DASHBOARDS.md` "Access" -- unchanged
in this phase. This means:

- **A same-origin iframe embed from a Django app running on the same NMAS
  host is technically feasible** (dashboards are already `editable: false`,
  read-only, single-datasource), but requires solving authentication
  (Grafana session/anonymous-viewer access or a signed embed token) and, if
  the Django app is reachable from outside `127.0.0.1`, either exposing
  Grafana beyond loopback or reverse-proxying it -- both are **out of
  scope for this phase** and were not attempted or evaluated further here.
- Until that is solved, the safe default is an **"Open full Grafana"**
  link built from the UID + variable query parameters above, opened in a
  new tab/window from the Django page, requiring the operator's existing
  Grafana credentials (`monitoring/runtime/monitoring.env`, never
  screenshotted, echoed, or committed).
- Every dashboard/panel in this taxonomy is safe to eventually embed from
  a data-sensitivity standpoint (no panel exposes credentials, and
  `validate_source()` still scans all Grafana source text for embedded
  secrets on every run) -- the only open question is the
  authentication/network-exposure mechanism, deferred to whichever phase
  builds the Django integration.

## 9. Known limitations (Phase 2)

- R3/R4's management-carrying interface cannot be honestly pattern-matched
  by name for the `include_mgmt` filter (§6).
- No interface speed/capacity source exists anywhere in the current
  collection schema; percentage utilization is not implemented and should
  not be added without first adding a truthful capacity source (§6).
- "Hide administratively-down" and "interfaces with events only" are not
  implemented on Link Events, for the reasons given in §5.
- No discrete admin-state-transition or interface-error/discard *event* log
  exists; Link Events surfaces only measurements that are genuinely stored
  as discrete events (`snmp_trap`, `syslog_event`) (§5).
- `syslog_event` carries no topic tag distinguishing resource-related from
  interface/link-related messages, so the syslog panel on both NMAS
  Resources and NMAS Link Events shows the same full critical-or-worse feed
  for the selected device/severity, not a topic-specific subset (§4, §5).
- Grafana embedding/authentication for the future Django UI was not
  designed or attempted in this phase (§8).
- All platform limitations already documented in `docs/
  GRAFANA_DASHBOARDS.md` "Limitations" (packet counters not stored, no
  native CPU SNMP threshold trap, R3/R4 adapter scope, cEOS syslog
  transport defect, SNMP poll freshness tied to verification-run cadence)
  are unchanged and still apply to every dashboard, legacy and canonical.
