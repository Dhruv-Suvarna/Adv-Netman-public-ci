# Dynamic Real-Time Network Topology (NetworkX)

Status: implemented and verified on 2026-09-07 against the frozen Lab 1
deployment. This phase added only a read-only NMAS visualization service,
repository-owned provisioning, tests, and documentation. It did not modify or
redeploy Containerlab, change a device, add a collector/database, or change an
existing monitoring schema.

## Architecture

```text
active Containerlab topology-data.json ---- read only ----\
read-only containerlab inspect ----------------------------> reconciler
repository inventory (monitoring metadata only) ----------/      |
                                                                 v
                                                        NetworkX Graph
                                                                 ^
gnmi_telemetry (freshness, CPU, memory, interface state/counters) |
snmp_poll (ifIndex -> interface identity) ------------------------|
snmp_trap (recent events) ----------------------------------------|
syslog_event (recent critical event counts) ----------------------/
                                                                 |
                                                 localhost HTTP :8050
                                                 /api/topology
                                                 /healthz
                                                 interactive SVG UI
```

`modules/topology_graph.py` is the authoritative graph and health layer. It
constructs an actual `networkx.Graph`, attaches normalized node/link evidence,
validates the allowed states and unique identities, then serializes NetworkX
node-link JSON. The browser is presentation only: it never decides topology or
health.

The service uses the existing repository virtualenv and existing InfluxDB
bucket. The UI is plain HTML/CSS/JavaScript with an SVG renderer, so there is no
CDN or heavyweight visualization platform.

## Authoritative topology source

Relationships come from the active deployment metadata:

`/home/student/clab-quickstart/clab-srlceos01/topology-data.json`

Each convergence also runs read-only:

```bash
containerlab inspect --name srlceos01 --format json
```

Provisioning refuses to continue unless the metadata and inspect node sets
match and all nodes report `running`. The live runtime metadata stays the
authority for the dynamic topology. (Historically the tracked
`srlceos01.clab.yml` described R3/R4 as cEOS; V2 Phase 1 corrected the tracked
file to the deployed Ubuntu/FRR R3/R4 so it now matches the runtime node set,
kinds, images and links exactly -- `test_topology_source` enforces this.)

The active metadata contains 15 Containerlab nodes and 24 link records. One
record connects `mgmt_swt:eth9` to the host-side `nmas-mgmt` interface. Because
the host is not a Containerlab node, the NetworkX graph explicitly records one
excluded host attachment and contains the authoritative 15 nodes and 23
container-to-container edges.

No node or edge list is duplicated in source. The small repository config in
`monitoring/config/topology.yml` contains only the runtime metadata location,
listener/refresh policy, health thresholds, deterministic layout seed, and a
Grafana link.

Containerlab `ethN` endpoint names map to real cEOS `EthernetN` telemetry names;
Linux names remain `ethN`. Both names are retained on each endpoint.

## Graph schema

### Nodes

Each node includes:

- canonical `id` / `canonical_name`;
- active kind, image, runtime state, and Containerlab-network management
  IPv4/IPv6 (`management_ipv4`/`management_ipv6` -- the per-container
  Containerlab bridge address, not the lab's monitoring VLAN; see "Dual-stack
  management addressing" below for that distinction);
- role derived from the documented naming convention (`router`, `switch`,
  `management-switch`, `host`, or `server`);
- whether it is monitored, monitoring VLAN interface/IPv4/IPv6
  (`monitoring_interface`, `monitoring_address`, `monitoring_address_v6`),
  and implementation (`native cEOS gNMI`, `Linux read-only adapter`, or
  `none`);
- `health`, reason, telemetry timestamp/age, CPU, and memory;
- critical-syslog and SNMP-trap counts in the recent-event window;
- deterministic `x`/`y` coordinates.

Container runtime state is shown as metadata but is not used to claim device
health. Health requires monitoring evidence.

### Edges

Every edge has a deterministic identity composed from sorted endpoint device
and Containerlab interface names. It includes:

- source/target and `data` or `management` plane;
- both Containerlab and monitoring interface names;
- endpoint admin/oper state, evidence timestamp/age, and cumulative
  error/discard counters;
- status, reason, evidence source, and last state-update time;
- recent mapped link-event count/type/timestamp.

The current graph is a simple graph. Provisioning rejects duplicate identities
or parallel edges instead of silently collapsing them.

## Presentation layout (hierarchical / layered)

The browser draws a deterministic, hierarchical/layered diagram instead of the
earlier radial (graph-center + shortest-path-ring) arrangement. This is a
presentation refinement only: it changes where an already-real node is drawn,
never which nodes or edges exist. Coordinates are computed in
`modules/topology_graph.py` (`build_base_graph`) from:

1. **Tier assignment** -- each node gets a purely cosmetic vertical row from
   an explicit, documented map keyed on the frozen Lab 1 device names
   (`AGENTS.md`):

   | Tier | Members |
   |---|---|
   | 0 (top) | `WebServer` (service/server) |
   | 1 | `R5` (upstream/core) |
   | 2 | `R3`, `R4` (upper routers) |
   | 3 | `S3`, `S4` (upper switches) |
   | 4 | `R1`, `R2` (edge routers) |
   | 5 | `S1`, `S2` (access switches) |
   | 6 (bottom) | `H1`-`H4` (hosts) |

   `mgmt_swt` is intentionally excluded from this stack (see "Management
   zone placement" below). A node outside this documented set (i.e. not part
   of the frozen baseline) still renders, via a role-based fallback tier,
   instead of raising -- but the frozen baseline is what the ordering is
   tuned for. **This tier map is visualization metadata only.** It does not
   define, infer, or alter a topology relationship; the graph's actual nodes
   and edges always come from `active_topology_snapshot()` (reconciled
   Containerlab metadata), never from this map.
2. **Within-tier ordering** -- left-to-right order in each row comes from a
   deterministic barycenter ("median heuristic") sweep over the graph's real
   `data`-plane adjacency: a node's column position is the average column of
   its already-placed neighbors in the tier above/below, alternated a couple
   of passes, tie-broken alphabetically. This is the standard technique
   layered ("Sugiyama-style") graph drawing tools use to cut down line
   crossings, and it is computed from the live edge list -- nothing about the
   drawn order is hardcoded per node. For example, `S1` connects to both `H1`
   and `H2` on the active topology, so those two hosts are ordered under `S1`
   and `H3`/`H4` under `S2`, purely because that is what the real adjacency
   says.
3. **Coordinates** -- `x` is `(column_index - center) * 150`, `y` is
   `tier * 130`, both fixed constants, so the same graph always produces the
   same layout (see "Determinism" below).

We deliberately do **not** call this a Clos or leaf-spine fabric anywhere in
the UI or docs: the real network is not a folded-Clos/leaf-spine fabric (it
has a single upstream core node `R5`, asymmetric router-to-switch fan-out,
and a dedicated out-of-band management switch attached to most devices), and
labeling it that way would misrepresent the actual design this phase must not
alter.

### Management zone placement

`mgmt_swt` sits in a dedicated column to the left of the data-plane stack
(`data-plane leftmost x - 340` world units), vertically centered on the
overall diagram, rather than in the middle of the topology where its eight
management links radiate out to (`R1`-`R4`, `S1`-`S4`). Concretely:

- management (`plane: management`) edges are dashed, drawn at reduced opacity
  (`0.4`), and rendered in an SVG layer beneath the data-plane edges and node
  layers, so they visually recede instead of dominating the picture;
- the management column's *x* position is derived only from where the
  data-plane nodes already ended up -- it never feeds back into or shifts a
  data-plane coordinate (verified in
  `monitoring/tests/test_topology_layout.py`);
- no synthetic NMAS/host graph node was added. The host-side `nmas-mgmt`
  attachment stays intentionally excluded from the NetworkX graph (as
  before); only the real `mgmt_swt` container node and its real container-to
  -container links are drawn.

### Zoom, pan, fit, reset, and manual node positioning

The SVG uses a `<g id="viewport">` group for all nodes/edges; pan and zoom
apply a `translate(...) scale(...)` transform to that group only, while the
outer `<svg>` viewBox always tracks the canvas's actual pixel size -- so the
graph viewport zooms/pans, not the page, the header, or the operational
details sidebar (both stay fixed by the existing CSS grid layout).

A floating **toolbar lives inside the canvas itself**, top-left, as its own
opaque bordered panel (`.viewport-toolbar`, `z-index:6`) so it can never be
mistaken for missing, hidden behind the SVG, or clipped at 1366x768/1920x1080:

- **`+` / `−`** step the zoom in/out around the canvas center.
- **`Fit`** fits the *currently displayed* node positions, including any
  manually dragged nodes.
- **`Reset View`** recomputes the fixed, deterministic camera fit from the
  backend layout only -- it does not clear manual node drags.
- **`Reset Node Positions`** clears manual per-node drag offsets (see below)
  without touching the camera.
- **Mouse wheel** anywhere over the canvas zooms in/out centered on the
  cursor.
- **Click-and-drag on empty canvas** pans the view. This is owned by a
  dedicated `#bg` rect kept pixel-exact with the canvas on every render/
  resize (numeric `x`/`y`/`width`/`height`, not just a `100%` length) and
  marked `pointer-events:all` both as an SVG attribute and in the
  stylesheet, so panning does not depend on how a given browser hit-tests a
  transparent SVG fill. Left-drag only; `user-select:none` on the canvas
  prevents accidental text selection while dragging.
- Zoom is clamped to a sensible range (`0.2x`-`4x`) so the diagram can
  neither disappear nor be zoomed absurdly far past readability.

**Individual nodes are draggable**, purely as a client-side presentation
convenience: `nodeOffsets[id] = {dx, dy}` records a manual offset applied
only when rendering (`nodeDisplay()`), on top of the deterministic backend
`x`/`y`. Dragging a node moves it and every edge line touching it live;
releasing without meaningful movement (below a ~4px screen threshold)
instead opens Operational Details, exactly like before drag support existed.
Nothing about a drag is written back to the server, InfluxDB, or any file --
the backend graph coordinates from `build_base_graph` are unaffected, and a
health refresh recomputing them server-side has no visibility into
`nodeOffsets` at all.

On first load, the page automatically fits all 15 nodes and 23 links inside
the canvas -- verified against both a 1366x768 and a 1920x1080 viewport.

**View state and manual node positions both survive health refreshes.** The
20-second auto-refresh re-renders node/edge colors and details every cycle,
but it does not reset the user's pan/zoom position or clear a dragged node:
the client keeps a signature of node/edge ids and their backend `x`/`y`
coordinates across refreshes, and only recomputes the fitted camera when
that signature actually changes (a real topology convergence) or on first
load; `nodeOffsets` is separate module state that a render only prunes for a
node id that no longer exists, never wipes wholesale. A plain health-state
change (colors, CPU, timestamps) touches neither.

**Resizing the window** updates the SVG viewBox (and the `#bg` pan target)
to the new pixel size immediately. If the user has not manually panned or
zoomed since the last fit/reset, the view re-fits automatically (including
any dragged nodes) so it stays usable across common laptop (1366x768) and
desktop (1920x1080) sizes; once a user has manually adjusted the view, a
resize preserves their pan/zoom rather than silently discarding it.

**A note on verification**: this environment has no headless browser, so the
automated tests for this interaction layer (`monitoring/tests/
test_topology_layout.py::InteractionContractTests`) are static source/DOM
contract checks -- the right elements, handlers, and CSS exist and are wired
to the right targets -- not a simulated pointer/mouse session. Real drag/pan/
zoom/click behavior should still be confirmed manually in a browser.

### Dual-stack management addressing

The management VLAN (Vlan200, `192.168.200.0/24` + `2001:db8:200::/64`) is
dual-stack by design, but until this phase the topology only carried its
IPv4 side. This section covers how the real, verified IPv6 side was added
to the visualization -- presentation/monitoring-wiring metadata only; no
device configuration, addressing, VLAN, or monitoring transport changed.

**Discovery, not derivation.** No IPv6 value here was guessed from an IPv4
address, a device number, or a naming pattern. Each one was read directly
from the persistent, already-deployed device configuration
(`templates/<device>.cfg.j2`) and independently cross-checked live against
the running deployment on 2026-09-07:

```bash
docker exec clab-srlceos01-R3 ip -o -6 addr show dev Vlan200        # Linux/FRR (R3, R4)
docker exec clab-srlceos01-S3 Cli -p 15 -c "show ipv6 interface brief"  # cEOS
```

Both sources agreed exactly, for every monitored device:

| Device | Management interface | IPv4 | IPv6 |
|---|---|---|---|
| R1 | Vlan200 | 192.168.200.1 | 2001:db8:200::1 |
| R2 | Vlan200 | 192.168.200.2 | 2001:db8:200::2 |
| R3 | Vlan200 | 192.168.200.3 | 2001:db8:200::3 |
| R4 | Vlan200 | 192.168.200.4 | 2001:db8:200::4 |
| R5 | Management0 | 172.20.20.16 (Containerlab-assigned) | 3fff:172:20:20::10 (Containerlab-assigned) |
| S1 | Vlan200 | 192.168.200.11 | 2001:db8:200::11 |
| S2 | Vlan200 | 192.168.200.12 | 2001:db8:200::12 |
| S3 | Vlan200 | 192.168.200.13 | 2001:db8:200::13 |
| S4 | Vlan200 | 192.168.200.14 | 2001:db8:200::14 |
| mgmt_swt | Vlan200 | 192.168.200.10 | 2001:db8:200::10 |
| H1-H4, WebServer | -- | -- | -- (unmonitored; no management-plane address) |

**R5 is deliberately different.** `R5.cfg.j2` has no Vlan200 SVI at all (it
peers EBGP directly on point-to-point links plus a WebServer transit link);
its real management path has always been Containerlab's own auto-assigned
`Management0` interface (`inventory.yml`: `address: auto`,
`source_interface: Management0`), which this phase already resolved for
IPv4. The IPv6 side follows the exact same "auto" resolution now, reading
the live Containerlab-assigned address for both families -- never a
fabricated Vlan200-style value for a device that has no Vlan200 interface.

**Where the value lives.** `inventory.yml`'s existing
`network_devices.<device>.monitoring` block gained one new sibling key,
`address_v6`, next to the pre-existing `address`/`source_interface` (R5
intentionally has no `address_v6` key -- see above). This is the same file
that already recorded the IPv4 monitoring address and interface name; nothing
about device configuration, VLANs, or monitoring transport changed.

**Field naming.** The pre-existing `management_ipv4`/`management_ipv6` node
fields (populated from live Containerlab inspect) are a *different* network
-- Containerlab's own per-container control-plane bridge -- and were left
untouched to avoid a silent meaning change for any existing consumer. The
new monitoring-VLAN fields are named as a sibling of the pre-existing
`monitoring_address`: `monitoring_address` (unchanged, IPv4), new
`monitoring_address_v6`, and new `monitoring_interface` (from the
already-recorded `source_interface`). `modules/topology.py`'s new
`resolve_monitoring_metadata()` is a small, pure, offline-unit-tested
function that only reads these fields verbatim (or the live Containerlab
address for "auto") -- it contains no IPv4-to-IPv6 derivation logic at all.

**UI.** A **Show Addresses** toolbar toggle (default **on**) displays each
monitored device compactly as ID / role / `v4 <addr>` / `v6 <addr>` (omitted
entirely, not shown as a blank/placeholder line, when a device genuinely has
no IPv6). Unmonitored hosts and WebServer never show a "management" address,
consistent with them having none. The node box widens/heightens only for a
device that actually has an address to show; Fit/Reset View account for each
node's current box size, and the toggle is client-side presentation state
that survives the 20-second refresh and a manual node drag without touching
backend coordinates, InfluxDB, or the topology service. The full address
(interface + IPv4 + IPv6) is also in the node's hover tooltip and in
Operational Details, alongside every field that already existed there.

### Limitations of this presentation layer

- Tier membership is keyed on the frozen Lab 1 device names as documented
  metadata, not derived from an inferred network role; a future device
  outside that naming convention gets a reasonable but not hand-tuned
  position.
- The barycenter crossing-reduction sweep is a heuristic (as used by
  layered/Sugiyama-style graph drawing tools generally), not an exact
  minimum-crossing solver; it is adequate for this topology's size (15
  nodes) but is not guaranteed optimal for a much larger or denser graph.
- Long management edges (e.g. `mgmt_swt` to a lower-tier switch) still cross
  visually through the vertical space between tiers; they are pushed behind
  data-plane elements and dimmed, but with eight fan-out links to a device in
  its own column, exactly zero visual crossings is not achievable without
  fabricating positions that ignore the real device layout.
- Host (H1-H4) and WebServer data-plane addresses are intentionally not
  surfaced: their only currently recorded values come from a point-in-time
  DHCP-lease capture (`address_report.csv`), which can go stale on lease
  renewal, so they are left out rather than risk showing an address as
  "management" or as current when it may no longer be either.

## Deterministic health model

The configured gNMI stream interval is 20 seconds. The UI refreshes every 20
seconds, while the backend caches an identical query result for 10 seconds to
avoid unnecessary InfluxDB load.

Node precedence:

1. `UNKNOWN`: node has no configured continuous monitoring stream, or no
   retained telemetry exists.
2. `HEALTHY`: latest real telemetry age is at most 60 seconds.
3. `STALE`: age is more than 60 and at most 120 seconds.
4. `OFFLINE`: age exceeds 120 seconds.

The five unmonitored endpoints H1-H4 and WebServer are therefore `UNKNOWN`, not
falsely healthy because their containers happen to run or no failure event was
seen.

Link precedence:

1. `DOWN` when any fresh monitored endpoint has `oper-status != UP`.
2. A mapped `linkDown`/`linkUp` notification newer than interface telemetry is
   authoritative until a newer stream sample arrives.
3. `DEGRADED` when fresh admin state is not `UP`, or only part of a monitored
   two-ended link has fresh evidence.
4. `UNKNOWN` when no fresh monitored endpoint evidence exists.
5. `UP` when all applicable monitored endpoint evidence is fresh and reports
   admin/oper `UP`. For a host-facing edge, the monitored switch endpoint's
   fresh carrier/oper state is the available real link evidence.

Recent events are never treated as proof of current health merely because a
failure is absent. Syslog/trap counts set a visible device attention flag.
Recent link events are mapped through real `snmp_poll` device/ifIndex/interface
records and shown on the matching edge. Newer current gNMI state supersedes an
older event.

If InfluxDB is unavailable, the graph remains viewable but all operational
states become explicit `UNKNOWN`; `/healthz` returns 503 and the UI marks the
backend error. An outage does not become fake green state.

## Existing InfluxDB mapping

No schema was changed.

| Measurement | Graph use |
|---|---|
| `gnmi_telemetry`, system identity/CPU/memory | Node freshness, CPU, calculated memory utilization |
| `gnmi_telemetry`, interface state | Endpoint admin/oper state and edge classification |
| `gnmi_telemetry`, interface counters | Endpoint error/discard detail |
| `snmp_poll`, `ifOperStatus` | Stable device + ifIndex to interface mapping for traps |
| `snmp_trap`, `raw_varbinds` | Recent device trap counts and mapped linkUp/linkDown evidence |
| `syslog_event`, `message` | Recent critical event count and latest event time |

Latest state searches the existing 30-day retention so an offline device does
not disappear. Event context uses the configured 15-minute window. Queries
select only needed fields/tags and return neither credentials nor raw event
payloads to the browser.

## Visualization and API

Local access:

```text
UI:       http://127.0.0.1:8050/
Graph:    http://127.0.0.1:8050/api/topology
Health:   http://127.0.0.1:8050/healthz
```

The UI shows labels, device/link state colors, a legend, last refresh/backend
time, and a Grafana link. Selecting a node or link exposes the operational
details above. Management links are dashed and dimmer, and render behind
data-plane links (see "Presentation layout" below for how coordinates are
computed and how zoom/pan/fit/reset behave); health refreshes cannot make
nodes jump.

The service binds only to `127.0.0.1`. For remote viewing:

```bash
ssh -L 8050:127.0.0.1:8050 student@<nmas-host>
```

Then open `http://127.0.0.1:8050/` locally.

## Provisioning and service security

Provision and verify without entering device configuration:

```bash
python3 master.py --topology-only
```

The full `master.py` workflow calls the same topology module after the existing
Grafana stage; `master.py` remains a thin orchestrator.

The content-aware provisioner deploys to `/etc/nmas-topology/` and manages one
`nmas-topology.service`. It restarts only when repository source, reconciled
active metadata, config, unit, or protected runtime environment changes. The
InfluxDB token is passed through root-owned mode-600 `influx.env` and systemd's
environment mechanism; it is absent from topology JSON, HTML, API results, and
tracked files.

The unit uses the same root-owned virtualenv model as the existing gNMI
collector and adds `NoNewPrivileges`, `PrivateTmp`, read-only home/system
protection, and SUID/SGID restrictions. The HTTP response adds no-store,
content-type, framing, referrer, and Content Security Policy headers. There is
no wildcard listener or cross-origin API.

## Safe failure demonstration

No real topology interface is shut or flapped. The normal/default UI and API
always show `mode=REAL` and real monitoring evidence.

The UI checkbox calls:

```text
/api/topology?demo=safe-link-down
```

This creates an opt-in response-local overlay on one deterministic data-plane
edge. The page and API say `DEMO/SYNTHETIC — NO REAL NETWORK CHANGE`; the edge
retains `real_status` and uses `status_source=synthetic-demo-overlay`. Nothing
is written to InfluxDB or disk, no collector is altered, and unchecking the box
immediately returns to real state.

The existing retained R3/R4 safe-test evidence was also interpreted: four real
linkUp/linkDown records map to the disposed `nmastest0` dummy interfaces. The
verification proves those interface identities are not in the active graph, so
they correctly do not alter a production edge.

This phase does **not** claim a real production-link DOWN was observed. Such a
demonstration remains prohibited without separate explicit approval.

## Automated verification

Offline model contracts:

```bash
python3 -m unittest discover -s monitoring/tests -p 'test_*.py' -v
```

Live acceptance:

```bash
/home/student/Scripts/.venv/bin/python monitoring/tests/verify_topology.py
```

Observed live matrix:

```text
SERVICE_HEALTH               PASS
HTML_UI                      PASS
API_SCHEMA                   PASS
NETWORKX_GRAPH               PASS   nodes=15 edges=23
ACTIVE_TOPOLOGY              PASS   nodes=15 edges=23 host_links_excluded=1
NO_DUPLICATES                PASS
SOURCE_HASH                  PASS
MONITORING_METADATA          PASS
VALID_STATES                 PASS
UNKNOWN_IS_EXPLICIT          PASS
REAL_NODE_R1                 PASS   native cEOS gNMI / HEALTHY
REAL_NODE_R3                 PASS   Linux read-only adapter / HEALTHY
REAL_LINK_STATE              PASS   R3:eth1--S3:eth1 / both endpoints UP
SAFE_HISTORICAL_EVENTS       PASS   four disposable-interface events excluded
SAFE_DEMO                    PASS
DYNAMIC_REFRESH              PASS
PROCESS_AND_BIND             PASS
SECRETS                      PASS
REPRODUCIBLE_SOURCE          PASS
SUMMARY: PASS checks=19 nodes=15 edges=23
```

The verifier rebuilds the active snapshot twice; recreates the API output as a
NetworkX graph; checks exact node/edge identities, uniqueness, source hash,
metadata, states, and localhost binding; compares R1, R3, and R3--S3 directly
with independent InfluxDB reads; tests historical dummy-event isolation and the
safe demo; waits beyond the cache and proves a newer generation time with
unchanged identities/layout; and scans source/output for runtime secrets.

### Presentation-layout refinement regression

`monitoring/tests/test_topology_layout.py` extends the offline suite with
layout SEMANTICS for the hierarchical policy above (tier ordering by y,
`mgmt_swt` outside the main horizontal region and in its own presentation
tier, determinism/refresh-stability of coordinates, 15/23 node/edge identity
preservation against a fixture mirroring the real edge list, and that
zoom/pan/fit/reset controls and the management-edge layering/opacity are
present in the served page) without asserting exact pixel coordinates.

After applying the layout/UI change, `monitoring/tests/verify_topology.py`
was rerun live (post `python3 master.py --topology-only`) and reproduced the
same `19/19 PASS`, `nodes=15 edges=23` result as the original evidence above.
Two additional `--topology-only` convergence calls both reported `NetworkX
topology unchanged` with the service `MainPID` unchanged, confirming the
layout change is idempotent like the rest of this phase. Two of several
`REAL_NODE_R1`/`REAL_NODE_R3` reruns intermittently failed on an exact
timestamp-equality race between the cached `/api/topology` response and a
second, independent live InfluxDB read taken a few seconds later while gNMI
telemetry kept streaming; this comparison lives entirely in
`verify_topology.py`'s pre-existing evidence check (not in this phase's
diff), reproduces with or without the layout change, and always cleared on
immediate retry with the underlying node `health` reported `HEALTHY`
throughout.

## Idempotency evidence

After the finalized `--topology-only` convergence/acceptance, two additional
calls to its `provision_topology()` convergence path both reported `NetworkX
topology unchanged`. The following remained identical:

- PID: `548714`;
- activation timestamp: `861480352675` (monotonic systemd value);
- combined deployed source/config hash:
  `ea63b3ed995c4578ffa424a1239f5015b4923514992b1f2f1c523cf05013ac95`;
- 15 node identities, 23 edge identities, and all layout coordinates;
- existing Grafana/InfluxDB containers and monitoring services.

The full orchestrated runs completed the 20/20 NMAS gate and 19-check topology
matrix; the two final content-convergence calls specifically proved that the
settled service/configuration does not restart or drift.

## Final video commands

Run/show these without displaying runtime environment files:

```bash
python3 master.py --topology-only
curl -s http://127.0.0.1:8050/healthz | python3 -m json.tool
/home/student/Scripts/.venv/bin/python monitoring/tests/verify_topology.py
systemctl status nmas-topology.service --no-pager
ss -lnt | grep ':8050'
```

In the browser:

1. Show the `REAL` badge, 15 nodes/23 links, legend, and current refresh time.
2. Select R1 and R3 to show native-versus-adapter monitoring, freshness, CPU,
   memory, and events.
3. Select R3--S3 to show both interface names and real UP endpoint evidence.
4. Enable the safe synthetic checkbox, show the unambiguous demo banner and
   DOWN edge, then disable it and show the unchanged real UP state.
5. Follow the Grafana link to correlate existing monitoring dashboards.

## Regression and preservation evidence

After the finalized topology code and convergence:

- SNMP: all 10 devices passed agent/auth/sysName/uptime/CPU/interface/storage;
  R3/R4 `snmpd` and watcher PIDs were unchanged, and a fresh R1 safe test
  notification was ingested into InfluxDB.
- Syslog: all 10 devices passed configuration/critical-marker/raw-log/storage;
  Linux daemons, cEOS forwarders, and the NMAS ingest service were unchanged.
- Telemetry: all 10 devices passed gNMI/TLS/auth/capabilities/Subscribe,
  persistent stream/InfluxDB, NETCONF hello/capabilities, and read-only GET;
  the collector and four R3/R4 adapter PIDs were unchanged.
- Grafana: four dashboards, 38 panels, eight variables, and all 46 queries
  passed through the existing datasource; secrets check passed.
- NMAS: the established `20/20` health gate passed after the topology work;
  InfluxDB and Grafana remained healthy.
- Containers: all 15 lab containers and both monitoring containers remained
  running; active kinds remained eight cEOS and seven Linux containers.
- Routing: R3/R4 each retained two Full OSPFv2 and two Full OSPFv3 neighbors;
  R5 retained two Established IPv4 and two Established IPv6 BGP peers.
- Topology: tracked file HEAD/worktree hashes both remained
  `e03064e8b38760b186657e936c3842646f893541`; the active runtime metadata SHA-256
  remained `f2713edcc012030e6c3d93a74b39747a4ffecf43b96e468f6ef39daec2051405`.

No Containerlab lifecycle command or disruptive topology test was run.

## Limitations

- H1-H4 and WebServer have no continuous monitoring stream and correctly
  remain `UNKNOWN`; their host-facing links use fresh switch-side physical
  evidence.
- Counter totals are shown for troubleshooting, but the graph does not label a
  link degraded solely because an old cumulative error exists.
- Routing/control-plane health is absent from the existing telemetry schema
  and is not invented here.
- The service reflects active topology metadata at provisioning time. A
  deliberate future topology lifecycle change requires rerunning
  `--topology-only`; health refreshes require no restart.
- No real topology-link DOWN/recovery visualization was tested because the
  project safety policy prohibits real link flaps. Only the safe labelled
  response-local demonstration and retained disposable-interface evidence were
  proven.
