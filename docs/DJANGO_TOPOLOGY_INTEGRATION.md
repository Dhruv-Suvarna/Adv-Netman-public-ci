# Django Topology Integration (Phase 5)

Status: implemented 2026-09-20 as a read-only integration of the existing
NetworkX topology service into the Django Home page. No topology discovery,
graph construction, device access, NetBox behavior, Containerlab lifecycle,
or network mutation was added to Django.

## 1. Existing topology architecture

The authoritative graph remains the Labs 2/3 implementation:

```text
active topology-data.json + read-only containerlab inspect
                         + existing inventory monitoring metadata
                         + existing InfluxDB evidence
                                      |
                                      v
                         modules/topology_graph.py (NetworkX)
                                      |
                                      v
                     localhost GET /api/topology (127.0.0.1:8050)
```

`modules/topology.py` reconciles the active runtime metadata with read-only
Containerlab inspection. `modules/topology_graph.py` builds and validates the
NetworkX graph, adds deterministic layout and operational evidence, and emits
schema-version-1 node-link JSON. `monitoring/scripts/topology_server.py`
serves that payload and maintains the existing 10-second backend cache. Phase
5 did not change any of those files.

The independently re-run pre-change verifier reported 19/19 PASS, 15 nodes,
23 edges, localhost-only binding, real health evidence, and a non-persistent
safe demo overlay.

## 2. Django integration pattern

Phase 5 uses a same-origin read-only adapter:

```text
Home / browser
      |
      | GET /api/topology/ (same origin)
      v
core.views.topology_data
      |
      v
core.services.topology_service
      |
      | fixed server-controlled GET
      v
existing http://127.0.0.1:8050/api/topology
```

This avoids browser CORS configuration and does not expose an operator-
selectable upstream URL. It also preserves the service-layer rule: the view
calls one topology service function; it does not import HTTP, Containerlab,
NetworkX, NetBox, device, or monitoring-database logic.

The Home view also calls `get_topology_summary()` for an initial server-side
snapshot. That prevents an avoidable blank first paint and gives Django a
fully graceful unavailable state even before JavaScript starts. Subsequent
refreshes use the same service through the GET-only endpoint.

## 3. Service endpoint and configuration

The browser endpoint is:

- `GET /api/topology/`
- all POST/PUT/PATCH/DELETE requests receive HTTP 405

The upstream is configured once in `web/config/settings.py`:

- `TOPOLOGY_SERVICE_URL`, default
  `http://127.0.0.1:8050/api/topology`
- `TOPOLOGY_SERVICE_TIMEOUT_SECONDS`, default `2.5`, constrained to
  `0.1..10` seconds

The upstream URL must use HTTP(S), have a hostname, contain no query or
fragment, and target exactly `/api/topology`. Browser request parameters can
never select or alter it.

## 4. Schema consumed

The adapter accepts only `schema_version: 1` and validates:

- a graph object containing node and edge arrays;
- unique, non-null node and edge identities;
- finite `x`/`y` coordinates;
- node health in `HEALTHY`, `STALE`, `OFFLINE`, `UNKNOWN`;
- edge status in `UP`, `DOWN`, `DEGRADED`, `UNKNOWN`;
- every edge source and target refers to an included node;
- no recursively nested secret-shaped key is present.

The graph and operational metadata are not recalculated or reclassified in
Django. Validated upstream fields are relayed as presentation data. If the
upstream backend includes a raw internal error string, Django replaces only
that error text with a generic message while preserving the explicit backend
ERROR state.

## 5. Refresh behavior

The existing API advertises `refresh_interval_seconds: 20`. The Home renderer
uses that value (bounded to 10-300 seconds, with 20 seconds as a fallback) and
also exposes a labeled **Refresh now** button.

Health refresh updates colors, timestamps, metadata, and selected-item
details. Pan, zoom, address visibility, and manually dragged node offsets
remain browser state and survive a normal refresh. A true topology/layout
identity change causes the viewport to re-fit. **Reset Nodes** clears all
manual offsets and restores authoritative API coordinates; **Reset View**
restores the camera fit without changing node offsets.

## 6. Caching behavior

Django adds no cache. The existing topology service already caches the graph
for `backend_cache_seconds: 10`, so a second cache would add complexity and
could obscure freshness. There is therefore no Redis, Celery, database table,
or indefinite last-known-good store for topology data.

If a later refresh fails, the already-rendered graph may remain visible for
operator continuity, but it is immediately and explicitly labeled
`STALE / READ-ONLY` and overlaid with the unavailable message. A successful
retry replaces it. A first-load failure displays no invented topology.

## 7. Node/detail behavior

Selecting a node shows only fields actually supplied by the API, including:

- canonical name, role, platform, image, and runtime state;
- evidence-derived health and reason;
- monitoring interface and monitoring IPv4/IPv6;
- Containerlab management IPv4/IPv6;
- monitoring implementation and telemetry freshness;
- CPU, memory, event counts, and latest event when present;
- neighbor names derived only from the API's current edge array.

Missing values render as an em dash. No value is fabricated.

## 8. Link/detail behavior

Selecting a link shows its real source/target, plane, state, reason, evidence
source, last update, and recent event metadata. Each API-supplied endpoint
shows Containerlab interface name, monitoring interface name, admin/oper
state, evidence age/freshness, and error/discard totals. Bandwidth and traffic
utilization are not claimed because they are not topology API fields; those
belong to Phase 6 monitoring views.

## 9. Show-addresses behavior

**Hide/Show Addresses** changes only SVG presentation. When enabled, monitored
nodes show the API's `monitoring_address` and `monitoring_address_v6` values.
Unmonitored nodes remain compact. The browser does not query NetBox or devices
for addresses.

## 10. Presentation-only dragging

The renderer adapts the existing topology service's SVG pointer model.
Dragging stores only `nodeOffsets[id] = {dx, dy}` in the JavaScript closure,
moves that SVG group, and redraws its incident SVG lines. Offsets are never
serialized, placed in a form, sent by `fetch`, stored in localStorage, written
to Django, or written to the upstream service. The only topology network call
in `topology.js` is an explicit GET to the fixed same-origin endpoint.

## 11. Read-only guarantees

- Django exposes only `GET /api/topology/`.
- The adapter creates an upstream `urllib.request.Request(method="GET")`.
- The browser script contains no POST/PUT/PATCH/DELETE topology request.
- Home contains no create/delete/edit/apply/push controls.
- Django views contain no Netmiko, pynetbox, Paramiko, subprocess, device,
  InfluxDB, or Containerlab inspection logic.
- Phase 5 did not change topology backend files, topology YAML, devices,
  NetBox, DHCP, routing, links, or Containerlab runtime.

## 12. Degraded-state behavior

Timeouts, connection failures, HTTP errors, malformed UTF-8/JSON, oversized
responses, invalid configuration, secret-shaped fields, and schema violations
all collapse to the public message:

> Topology service temporarily unavailable.

Home still returns HTTP 200 and all capability cards, header notifications,
profile access, and theme controls remain usable. The proxy returns HTTP 503
with only the generic status/message. Internal exception text is not sent to
the browser.

## 13. Security considerations

- Upstream URL and timeout are server-controlled settings, never query args.
- Response size is capped at 2 MiB.
- Known secret-shaped keys (`password`, `secret`, `token`, `webhook`,
  `credential`, API/private-key variants) cause response rejection.
- DOM content is created with `textContent`; no upstream value is inserted as
  HTML.
- Django's standard security middleware remains enabled.
- No credential or runtime secret is included in JavaScript or templates.

## 14. Theme behavior

Home remains neutral/default for Basic Minimal and Dark Mode. Dark Angels Home
uses `core`; Adeptus Mechanicus Home uses `core`. It does not switch Home to
Ravenwing/Monitoring. The graph sits on its own opaque, high-contrast dark
surface inside the themed card, leaving the operator artwork visible around
it without allowing it to interfere with link labels or pointer interaction.
All ten existing artwork files are unchanged and continue to resolve.

## 15. Known limitations

- The committed Django interaction tests are DOM/source contract tests and do
  not add a Selenium/Playwright dependency. Checkpoint validation additionally
  exercised the live page with the host's existing headless Firefox and
  geckodriver, including real pointer drag/pan and browser fetch observation.
- Node positions persist only for the lifetime of the loaded page. They are
  intentionally not stored in localStorage or server state.
- The proxy validates schema version 1, but does not maintain a duplicate
  allowlist of every optional topology field; the authoritative backend owns
  that schema.
- Link traffic rates/utilization are not part of this Home view.

## 16. Phase 6 handoff

Phase 6 should integrate the canonical Grafana monitoring taxonomy into the
Monitoring pages, not turn Home into a second Grafana dashboard. It should
reuse the stable dashboard UIDs and variables documented in
`docs/GRAFANA_MONITORING_TAXONOMY.md`. Topology link utilization must only be
added later if a real supported data contract exists; it must not be inferred
or fabricated from this integration.
