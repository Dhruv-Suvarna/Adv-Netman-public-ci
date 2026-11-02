# Django NSOT Integration (Phase 7)

Status: implemented 2026-09-20 as a **read-only, multi-source aggregation**
layer over the project's existing NetBox, Git, topology, and live-device
data. NSOT is a presentation/aggregation layer, not a declaration that
NetBox owns every category of network state. No configuration change,
Device Builder, Golden-state mutation, deployment, or NetBox write was added
in this phase.

## 1. NSOT purpose

The NSOT page lets an operator inspect the current network and answer:
what is the network intended/stored to be (NetBox), what does Git currently
contain (templates/code/history), what do live devices currently report
where it is safe to ask, what does topology/inventory say, and whether
these sources currently agree. Every value on the page is tagged with the
source that actually produced it.

## 2. Multi-source architecture

```text
                         Django NSOT (core/templates/core/nsot/*)
                                        |
                                        v
                    core/services/nsot_service.py (orchestrator, TTL cache)
                                        |
        +---------------+---------------+---------------+---------------+
        |               |               |               |               |
        v               v               v               v               v
 nsot_netbox.py     nsot_git.py     nsot_live.py    topology_service.py (existing)
        |               |               |               |
        v               v               v               v
 modules/netbox_    `git` subprocess  Netmiko/EOS    GET /api/topology
 ipam.py +          (fixed argv,      (bounded,      (Phase 5 adapter,
 modules/ipam_      shell=False,      cEOS "show     unchanged)
 context.py         REPO_ROOT-pinned) running-config"
 (existing, read-                     only)
 only client)
```

NetBox remains passive storage: `core/services/nsot_netbox.py` is a thin
adapter around the already-authenticated `modules/netbox_ipam.py` client
construction (`load_config()` / `build_client()`) and `modules/
ipam_context.py`'s existing comparison machinery -- it opens no second,
differently-authenticated client, and every function only reads.

## 3. Source ownership matrix

| Category | Owner | Badge | Notes |
|---|---|---|---|
| Devices, interfaces, IP addresses, prefixes, VLANs, DHCP pools | NetBox (live) | `NETBOX` | Read via `nsot_netbox.py` -> `modules/netbox_ipam.py` |
| VLAN 200 management addressing | Git | `GIT` | Always static; never DHCP; no reservation control exists anywhere in this UI |
| Templates, Python modules, DHCP templates, repo history | Git | `GIT` | `nsot_git.py`; allowlisted catalogue only |
| Running configuration (cEOS only) | Live devices | `LIVE` | Explicit, bounded, redacted fetch; never automatic |
| Device/link neighbor state, node/edge counts | Topology service | `TOPOLOGY` | Reuses the existing Phase-5 `/api/topology` adapter, no second graph engine |
| BGP/OSPF/RIP structured intent | Not yet modeled | -- | Honestly reported as sparse/absent; Phase 8+ Device Builder scope |
| Candidate / Golden / Probation / UAT state | Not implemented | -- | Explicitly labeled "Not implemented yet -- Phase 8+"; no fabricated records |

## 4. Provenance badge model

`core/templatetags/nsot_extras.py::badge_class` maps a source or status
string to one of the existing Phase-3 badge CSS classes (`badge--info`,
`badge--neutral`, `badge--success`, `badge--warning`, `badge--danger`) --
no new CSS was required. A badge is only ever rendered next to a value that
source actually produced; a page section reflecting Python-derived
interpretation (e.g. IPAM reservation readiness) is marked "derived",
distinct from a raw NetBox field.

## 5. Freshness / timestamp semantics

Every adapter result distinguishes:

- `fetched_at` -- when this Django process last performed the read (NetBox,
  Git, IPAM aggregates).
- `observed_at` -- when a live device actually answered (running-config
  fetch only).
- `head_commit_time` -- Git's own commit timestamp (`%cI`), never confused
  with `fetched_at`.

No adapter labels a local fetch time as "source last modified" -- NetBox's
API does not expose a per-object true modification time in this model, so
none is fabricated.

### 5a. Materialized snapshot cache, manual refresh, and staleness (Phase 20.5)

Every `nsot_service.get_*` function is a thin loader wrapped by one shared
helper, `_cached()`, backed by Django's process-local `LocMemCache`
(`settings.NSOT_CACHE_TTL_SECONDS`, default 30s, env-bounded 1-300s). A
normal page view reads the current materialized snapshot -- it does not
re-run NetBox/Git/live queries on every request. This is the "browser ->
Django -> materialized snapshot -> response" shape, not a periodic
background poller: the TTL is a maximum staleness bound, not a scheduled
job, and the five-minute figure mentioned in planning is a fallback ceiling
this project's actual TTL (30s) is already well inside of.

Every NSOT subpage has an explicit **Refresh NSOT** control (`?refresh=1`)
that forces `_cached()` to bypass the TTL and re-run the loader
immediately. This is a per-page action, not a Device Builder mechanism, and
it is the only way page data is forced current outside the TTL window.

Each snapshot carries a `freshness` object (`{"state": "CURRENT" |
"STALE", "age_seconds": <float | null>}`) and a `cache` tag (`"hit"` |
`"miss"` | `"stale"`), rendered by the shared `core/nsot/_freshness.html`
partial next to every Refresh NSOT control. `age_seconds` is derived from
the snapshot's own `fetched_at`, so a `STALE` snapshot's displayed age
honestly reflects how old the underlying data really is, not when the
failed refresh attempt happened.

**Failure never destroys good data.** `_cached()` keeps a second, durable
(non-expiring) copy of the last successful snapshot per key
(`"<key>:last_good"`). If a load -- whether an ordinary TTL-expiry miss or
an explicit forced refresh -- raises an exception, or returns the
project's standard `{"status": "unavailable", ...}` envelope, `_cached()`
returns that last-good snapshot instead: unchanged data, `cache="stale"`,
`freshness.state="STALE"`, and a `refresh_error` field naming what went
wrong. The primary TTL-keyed cache entry is left untouched by a failed
load, so the next request retries the source rather than being pinned to
the failure. Only when no successful load has ever populated a key does
`_cached()` fall back to surfacing the raw failure envelope, still tagged
`STALE`. See `test_nsot.py`'s `NsotCacheFreshnessTests` for the exact
success/failure/no-prior-snapshot matrix.

## 6. Page / subpage map

```text
/nsot/                          Overview
/nsot/devices/                  Devices (list, paginated, filterable)
/nsot/devices/<name>/           Device detail
/nsot/devices/<name>/running-config/   Explicit LIVE fetch (GET-only)
/nsot/interfaces/               Interfaces (paginated, filterable by device)
/nsot/ipam/                     Prefixes, DHCP pools, reservation readiness
/nsot/vlans/                    VLANs / prefixes, VLAN 200 static marker
/nsot/routing/                  Routing / ASN (honest sparse-data view)
/nsot/platforms/                Device types + Git-documented image versions
/nsot/templates/                Git-backed allowlisted template/code catalogue
/nsot/drift/                    Drift / consistency status
```

Sub-navigation lives inside the NSOT page (`core/nsot/_subnav.html`); the
global sidebar is unchanged (Home / Monitoring / Device Builder / NSOT /
Automation).

## 7. Devices

`nsot_netbox.list_devices()` returns every IaC-owned device (managed and
unmanaged, e.g. R5/WebServer, clearly tagged `managed: false`), normalized
from `client.dcim.devices.filter(tag="csci5840-iac")` -- name, role, device
type, manufacturer, status, site, primary IPv4/IPv6, managed flag, tags.
The listing table supports a `device` name-substring filter, a `role`
filter, and Django `Paginator`-based pagination (25/page). Each row links
to a device detail page.

## 8. Device detail

`nsot_service.get_device_detail(name)` aggregates, per device:

- **Stored/intended (NetBox)**: summary fields + every interface with type,
  mode, untagged VLAN, MAC, and addresses (VLAN 200 clearly flagged
  "management . static").
- **Git**: the matching `templates/<name>.cfg.j2` catalogue entry (link to
  Templates/Code), and a NetBox-vs-Git field comparison reusing
  `modules/ipam_context.py::compare_facts()` -- never a generic text diff.
- **Live**: whether live retrieval is supported for this device's platform,
  and an explicit "Fetch running-config" action. The device detail page
  itself never performs the live fetch -- only a `GET` to the dedicated
  `running-config` route does, and only when the operator clicks it.
- **Topology**: neighbor edges from the existing topology graph, joined by
  device name.
- **Monitoring**: deep links to the three Monitoring subpages, built with
  `django.urls.reverse(...)?device=<name>` -- the Monitoring view already
  re-validates this parameter against its existing allowlist
  (`monitoring_service.validate_filters`), so NSOT never constructs a
  Grafana URL itself.

An unknown device name (or a name that does not match the device-name
shape `^[A-Za-z0-9_-]{1,64}$`) is rejected before any NetBox/live/Git call
and returns HTTP 404.

## 9. Interfaces

`nsot_netbox.list_interfaces(device=None)` lists every modeled interface
(device, name, type, mode, VLAN, addresses, description), optionally
filtered to one device, paginated 25/page. VLAN 200 interfaces are flagged
"management . static" the same way as on the device detail page.

## 10. IPAM / VLAN / prefixes

`/nsot/ipam/` shows NetBox prefixes, DHCP `ipam.IPRange` pools (via the
existing `modules/netbox_ipam.py::get_dhcp_ranges()`), and reservation
readiness (via the existing `modules/ipam_context.py::get_address_
reservations()` / `validate_reservations()`) -- explicitly labeled
"derived" since the readiness verdict is Python-computed, not a raw NetBox
field. `/nsot/vlans/` lists every VLAN; VLAN 200 is marked `MANAGEMENT /
STATIC` and the page carries no DHCP-enable button, no reservation-create
control, and no dynamic-address option anywhere -- verified by
`test_nsot.py::NsotRouteTests.test_vlans_page_has_no_dhcp_action_control`.

## 11. Routing / ASN

NetBox currently models no BGP/OSPF/RIP structured intent (`client.ipam.
asns.all()` returns zero records in this environment). `/nsot/routing/`
reports that honestly rather than fabricating a routing model, and
separately shows the frozen Lab 1 routing baseline documented in
`AGENTS.md`/`README.md` (RIPv2, OSPFv2/v3, eBGP) tagged `GIT` -- clearly
Git-sourced documentation, never presented as a NetBox record. Structured
routing intent is explicitly Phase 8+ (Device Builder) scope.

## 12. Platforms / images

`/nsot/platforms/` shows NetBox device types (model, manufacturer, device
count) plus the two known platform images from `AGENTS.md`'s frozen
baseline (Arista cEOS 4.36.2F; Ubuntu 24.04 + FRRouting 8.4.4), tagged
`GIT` since NetBox does not model an image/version field in this schema.
No image binary was added to Git and no vendor image was probed/downloaded.

## 13. Git / templates / code

`core/services/nsot_git.py` is the **only** module in the codebase that
shells out to `git`. Every call uses a fixed argument array
(`subprocess.run(["git", *args], cwd=REPO_ROOT, shell=False, timeout=
NSOT_GIT_TIMEOUT_SECONDS, ...)`) -- no browser text ever reaches a shell
command. The Templates/Code catalogue is allowlisted to five fixed
project-root directories (`templates/`, `modules/`, `netbox/scripts/`,
`dhcp/`, `monitoring/config/`) and four extensions (`.j2`, `.py`, `.yml`,
`.yaml`); a requested `?file=` path is only ever served if it exactly
matches a catalogue entry, so no arbitrary filesystem path (and no
`.env`/secret file, which is never `.j2`/`.py`/`.yml`) is reachable. Each
catalogued file shows a `tracked_clean` / `tracked_modified` / `untracked`
status from `git status --porcelain`.

Repository metadata (`/nsot/`'s overview card and every other page's Git
badge data) shows branch, HEAD short/full commit, commit message, commit
timestamp, and dirty state. Dirty files are split into
**PROJECT_SOURCE_DRIFT** vs **KNOWN_RUNTIME_LOG_MODIFICATIONS**
(`Run_Logs.log`, `logs/R2.log` -- the two files AGENTS.md/docs/
CURRENT_STATE.md document as expected runtime deltas); the rest of the
large pre-existing uncommitted NetBox/IPAM migration diff is honestly
reported as `PROJECT_SOURCE_DRIFT`, not hidden and not called a
catastrophic regression.

## 14. Live configuration retrieval

`core/services/nsot_live.py` supports exactly one platform (cEOS) and one
command (`"show running-config"`, a fixed constant -- no browser text ever
reaches a CLI). The SSH target address and credentials come only from
`inventory.yml` (trusted, Git-tracked, server-side) -- never from browser
input. After connecting, the code calls `conn.check_enable_mode()` /
`conn.enable()` -- **exactly** `master.py::verify_eos()`'s own established
read-only pattern, reused rather than reinvented -- because EOS requires
PRIVILEGED EXEC to return anything for `show running-config`. This raises
CLI privilege level only -- it is *not* configuration mode, and
`config_mode()`/`send_config_set()`/`write memory`/`copy running startup`
are never called anywhere in this module. Every connection has a
bounded timeout (`settings.NSOT_LIVE_READ_TIMEOUT_SECONDS`, default 8s) and
is always disconnected in a `finally` block. The fetch is **never**
triggered by loading the device detail page -- only an explicit `GET
/nsot/devices/<name>/running-config/` (itself `@require_GET`, returning 405
for any other method) performs it.

R3/R4 (Linux/FRR) are reported `not_supported` rather than a fabricated
result: no existing code in this repository establishes a safe read-only
`vtysh`-equivalent command, and Phase 7 did not invent one blind.

## 15. Redaction

`nsot_live.redact_config()` is a deterministic, line-scoped regex
redactor (see the module for the exact keyword list: `secret`, `password`,
`community`, `key-string`, `authentication-key`, `pre-shared-key`). It
masks only the trailing secret token on a matching line, preserving
command context (e.g. `snmp-server community ******** ro`,
`neighbor 10.0.0.1 password ********`). It is applied line-by-line, not as
a single multi-line regex over the whole text -- an earlier draft used a
greedy multi-line pattern and a keyword on one line could silently "absorb"
an unrelated secret on an earlier line into its unredacted prefix; this was
caught in this phase's own testing and fixed (see
`RedactionTests.test_redaction_is_line_scoped_not_multiline_greedy`).
**Known limitation**: this is pattern-based, not a semantic EOS config
parser -- a secret embedded in an unrecognized/vendor-extension directive,
a multi-line banner, or non-standard formatting is not guaranteed to be
caught. The rendered running-config template also never uses Django's
`|safe` filter, so any HTML/script content inside the (already-redacted)
config text is escaped, not executed.

## 16. Drift / consistency model

`/nsot/drift/` runs only comparisons this project can currently perform
reliably:

1. **NetBox vs Git addressing**, per managed device, reusing
   `modules/ipam_context.py::compare_facts()` (field-by-field, not a
   generic diff).
2. **NetBox DHCP reservation readiness**, using bulk-fetched device,
   interface, address, and MAC records with the same
   `validate_reservations()` semantic validator used by the offline tools.
3. **Topology device set vs NetBox managed-device set** (name-based).
4. **NetBox vs live running-config**: always reported `NOT_COMPARABLE` on
   this page -- there is no automatic full-fleet live comparison (that
   would mean an unbounded live SSH fan-out on every page load); a
   per-device comparison is only ever possible via the explicit, bounded
   running-config fetch on that device's own page.

`compare_live_state.py` (which diffs NetBox against a live `address_
report.py` CSV snapshot) was re-run manually as part of this phase's
verification (see Tests, below) but is intentionally **not** wired into
this page's automatic checks -- it requires a fresh live snapshot across
every device, which is exactly the kind of unbounded per-page-load live
fan-out this phase's safety rules prohibit.

## 17. Status vocabulary

| Status | Meaning |
|---|---|
| `IN_SYNC` | The compared sources agree. |
| `DRIFT` | The compared sources disagree on at least one field. |
| `UNMANAGED` | The device/domain is intentionally out of scope (R5/WebServer). |
| `UNAVAILABLE` | A source needed for the comparison could not be reached right now -- never conflated with drift. |
| `NOT_COMPARABLE` | No reliable automated comparison exists yet for this domain. |

## 18. Failure / degraded behavior

Every page combines multiple independent sources and degrades one at a
time: `nsot_netbox.*` functions catch any exception and return an
`{"status": "unavailable", ...}` envelope rather than raising; the same is
true of `nsot_git.get_repo_state()`/`list_catalogued_files()` and
`nsot_live.fetch_running_config()`. A NetBox outage leaves Git/topology
sections visible with their own real data; a Git failure leaves NetBox/live
sections visible; a live-device failure only affects that one device's
running-config action. No adapter ever substitutes a guessed value for an
unavailable one. Verified in `test_nsot.py` (`NsotRouteTests.
test_devices_page_degrades_when_netbox_unavailable`,
`GitAdapterTests.test_git_failure_degrades_gracefully`,
`NsotRunningConfigRouteTests.test_running_config_unavailable_does_not_crash`).

At the cache layer (Section 5a), a failed load is additionally protected
from ever overwriting the last known good snapshot -- see
`NsotCacheFreshnessTests.
test_failed_forced_refresh_preserves_last_good_snapshot_and_marks_stale`.

## 19. Security model

- **NetBox token**: never leaves `modules/netbox_ipam.py`'s existing
  `load_config()`/`build_client()`; Django adds no `NETBOX_*` setting and
  no view/template ever sees it.
- **Device credentials**: read only from `inventory.yml` server-side inside
  `nsot_live.py`; never accepted from a request, never echoed in an error
  message (`fetch_running_config` returns a fixed, generic message per
  exception class, never `str(exc)`).
- **Git command safety**: fixed argument arrays, `shell=False`, pinned
  `cwd=REPO_ROOT`, finite timeout -- see `nsot_git.py`.
- **Filesystem safety**: the Templates/Code catalogue is allowlisted to
  five fixed roots/four extensions; a `?file=` value not in that exact set
  is rejected (`GitAdapterTests.test_path_traversal_is_rejected`).
- **Live CLI safety**: one fixed command string, no config-mode call, GET-
  only route, bounded timeout, credentials never sourced from a request.
- **XSS**: the running-config and template/code views never use `|safe`;
  Django's default autoescaping is relied on throughout (verified with a
  `<script>` fixture in `test_nsot.py`).
- **Read-only API surface**: no NSOT route accepts POST/PUT/PATCH/DELETE
  for any network-state read or write; the only side-effecting call in
  this phase (`fetch_running_config`) is itself read-only against the
  device and is reachable only by `GET`.

## 20. Known limitations

- Drift and reservation readiness now materialize a bounded set of NetBox
  list queries and perform per-device equivalence in memory; they no longer
  issue a sequential/per-interface query waterfall. Live measurements on
  2026-09-26 were: Drift 6.802s cold, 0.004s cached, 4.610s forced refresh;
  IPAM 2.958s cold, 0.007s cached, 3.322s forced refresh. All nine NSOT
  subsection routes returned HTTP 200 and displayed Refresh NSOT. These are
  observations of this lab, not a real-time SLA.
- Redaction (Section 15) is pattern-based, not a config parser -- documented
  limitation, not a guarantee of catching every possible secret syntax.
- Live retrieval only supports cEOS; R3/R4 (Linux/FRR) honestly report
  `not_supported` rather than a fabricated or best-effort result.
- Routing/ASN data is currently sparse by design (NetBox models no BGP/
  OSPF/RIP intent yet) -- this page reflects that honestly rather than
  inventing structure ahead of Phase 8.
- Device SSH secret values are resolved from protected references under the
  ignored `monitoring/runtime/` provider. Inventory holds only references and
  usernames. Every managed cEOS device requires its own `nmas-automation`
  profile; missing metadata fails closed and no fleet fallback exists. NSOT
  shares this resolver with Health and execution.
- The process-local cache is per-Django-process (matching the existing
  Grafana/topology pattern in this codebase) -- it is not shared across
  multiple `manage.py runserver`/WSGI worker processes; documented, not a
  regression, consistent with the rest of this project's caching approach.

## 21. Future Candidate/Golden/UAT integration boundary

Candidate configuration, Golden state, Probationary state, UAT state,
change history, and deployment history do not exist yet. The Overview page
states this explicitly ("Not implemented yet -- Phase 8+") rather than
fabricating any such record. Notification history (which does exist, from
Phase 4) is not duplicated into NSOT in this phase; the existing
Notification Center remains the place to view it.

## 22. Phase-8 handoff

Phase 8 (structured Device Intent, Change, Configlet, and lifecycle data
models) can build directly on:

- `core/services/nsot_netbox.py` for normalized NetBox reads.
- `core/services/nsot_git.py` for repository metadata and the file
  catalogue pattern (extend `CATALOGUE_ROOTS` rather than building a new
  file-access path).
- `core/services/nsot_live.py` for the bounded, redacted, allowlisted
  live-read pattern -- a future write path must be a genuinely new module
  with its own explicit confirmation/approval flow, never an extension of
  this read-only one.
- The `IN_SYNC` / `DRIFT` / `UNMANAGED` / `UNAVAILABLE` / `NOT_COMPARABLE`
  vocabulary in `nsot_service.py`, ready to be extended with Candidate-vs-
  Golden and Golden-vs-live checks once those models exist.

NetBox remains passive storage; this rule does not change in Phase 8.
