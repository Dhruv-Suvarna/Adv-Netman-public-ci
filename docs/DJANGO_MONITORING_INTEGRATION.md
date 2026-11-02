# Django Monitoring Integration (Phase 6)

Status: implemented 2026-09-20 as a read-only Django control surface around
the existing Grafana/InfluxDB monitoring system. No collector, telemetry
database, datasource, dashboard, or monitoring writer was added.

## 1. Architecture

```text
devices / existing collectors
            |
            v
existing InfluxDB
            |
            v
existing Grafana canonical dashboards
            |
            v
Django Monitoring controls and authenticated dashboard iframes/links
```

Grafana remains the sole graph/dashboard renderer. Django validates ordinary
GET parameters, translates them to known Grafana variables, checks Grafana's
credential-free health endpoint with a finite timeout, and builds links to the
canonical dashboards. Django never queries raw InfluxDB and never redraws the
Grafana panels.

## 2. Canonical dashboard mapping

| Django page | Grafana title | Stable UID |
|---|---|---|
| Resources | NMAS Resources | `nmas-resources` |
| Link Events | NMAS Link Events | `nmas-link-events` |
| Link State & Traffic | NMAS Link State & Traffic | `nmas-link-state-traffic` |

The four legacy dashboards remain available in Grafana but are not referenced
by the Django wrappers. Tests compare the Django filter contract with the
variables in the generated canonical JSON.

## 3. Grafana configuration

`web/config/settings.py` owns the single configured base URL:

- `GRAFANA_BASE_URL` (default `http://127.0.0.1:3000`)
- `GRAFANA_HEALTH_TIMEOUT_SECONDS` (default 2.5, allowed range 0.1-10)
- `GRAFANA_EMBED_ENABLED` (default true; operator kill switch)

The actual deployment publishes Grafana only as
`127.0.0.1:3000:3000`. InfluxDB is likewise loopback-only and remains
accessible to browser users only indirectly through Grafana's server-side
proxy datasource. No InfluxDB token enters Django or the browser.

## 4. Embedding and authentication decision

The intended authenticated embedding behavior is defined at both ends:

- administrator credentials are supplied from the ignored
  `monitoring/runtime/monitoring.env` file;
- anonymous viewing is not enabled;
- dashboard requests without a Grafana session redirect to `/login`;
- Compose sets Grafana's supported `GF_SECURITY_ALLOW_EMBEDDING=true` option;
- `GRAFANA_EMBED_ENABLED` defaults true but remains an operator kill switch;
- Grafana is bound to host loopback.

Before rendering an iframe, Django first performs its bounded credential-free
health check and then requests the fixed canonical dashboard URL. It refuses
to embed when the live response contains any `X-Frame-Options` value or an
incompatible CSP `frame-ancestors` directive. A reachable Grafana that
prohibits framing therefore retains the secure **Open Full Grafana Dashboard**
fallback; an unavailable Grafana retains the unavailable state. The setting
alone can never force an iframe past a prohibitive live response.

Grafana authentication remains independent. The operator authenticates with
Grafana in the browser, after which the same-site session cookie can authorize
the iframe on port 3000. Django does not forward, store, proxy, or render
Grafana credentials, and no credential is placed in an iframe URL. The full
dashboard link remains available as a useful fallback/action.

### Dashboard-only presentation

The iframe and full-dashboard link deliberately use different presentation
modes while targeting the same canonical UID, variables, and time range.
Grafana 11.5.2 dashboard scenes recognize `kiosk=true` (or an empty kiosk
value) as full kiosk mode; the legacy `kiosk=tv` value is ignored and exposes
the normal Grafana application shell. Iframe URLs therefore add:

```text
kiosk=true&theme=dark&_dash.hideTimePicker=true&_dash.hideVariables=true&_dash.hideLinks=true
```

This supported Grafana URL mode removes the global sidebar/navigation,
search, and dashboard edit/share chrome. The `_dash` parameters remove the
duplicate Grafana time, variable, and dashboard-link controls because Django
owns those controls in the wrapper. The **Open Full Grafana Dashboard** URL
never receives these presentation parameters and continues to open the normal
Grafana interface. This is presentation only, not an authorization boundary;
Grafana authentication and account permissions remain authoritative.

### 2026-09-27 iframe-regression diagnosis

Clean main at merge `5f6f500` still had two Phase-6 assumptions: the Compose
definition did not persist `allow_embedding`, and Django's static embed flag
defaulted false without inspecting the running service. The port-8001 process
therefore always selected the fallback. The live Grafana container happened
to be frame-capable because it had been created from an uncommitted Compose
change in a different legacy worktree, but that state was not reproducible
from main.

The live Grafana 11.5.2 settings API and targeted container inspection showed
`allow_embedding=true`, `cookie_samesite=lax`, `cookie_secure=false`, the
default localhost root URL/domain, and anonymous access disabled. Unauthenticated
requests to all three canonical dashboards returned a login redirect with no
`X-Frame-Options` or CSP `frame-ancestors`. Grafana itself was not rejecting
the iframe; Django was incorrectly classifying support from its default-false
flag. No Grafana recreation was needed because the running container already
matched the corrected desired setting.

Authenticated Chromium acceptance against ports 8001/3000 rendered Resources,
Link Events, and Link State & Traffic inside their canonical iframes with HTTP
200 dashboard responses. Device/platform/severity/unhealthy/time filters were
passed to the Resources iframe, and a normal reload retained both the filtered
URL and rendered content. Browser inspection found no XFO/CSP framing error,
page exception, or failed canonical-dashboard request.

## 5. Filter model

All controls are ordinary bookmarkable Django GET parameters. One service-side
mapping in `core/services/monitoring_service.py` maps only known Django keys to
known `var-*` names. Unknown keys are ignored, invalid known values are omitted,
and no browser value can select a dashboard UID or Grafana host.

| Page | Django parameter | Grafana variable |
|---|---|---|
| Resources | `device` | `device` |
| Resources | `platform` | `platform` |
| Resources | `severity` | `severity` |
| Resources | `unhealthy_only` | `unhealthy_only` |
| Link Events | `device` | `device` |
| Link Events | `event_type` | `event_type` |
| Link Events | `severity` | `severity` |
| Link State & Traffic | `device` | `device` |
| Link State & Traffic | `platform` | `platform` |
| Link State & Traffic | `interface` | `interface` |
| Link State & Traffic | `hide_zero_traffic` | `hide_zero_traffic` |
| Link State & Traffic | `hide_down` | `hide_down` |
| Link State & Traffic | `active_only` | `active_only` |
| Link State & Traffic | `include_mgmt` | `include_mgmt` |
| Link State & Traffic | `include_loopback` | `include_loopback` |

Device and interface values are length/character validated. Platform,
severity, event type, and boolean values use closed allowlists. Values are URL
encoded with Python's standard URL encoder. Reset Filters links to the same
canonical route without a query string and performs no write.

## 6. Time ranges

`time_range` accepts only `15m`, `1h`, `3h`, `6h`, `24h`, or `7d`, mapped to
the matching Grafana `from=now-*` expression with `to=now`. Raw Grafana time
expressions are never accepted. Defaults preserve the generated dashboard
intent: Resources 6h, Link Events 24h, and Link State & Traffic 3h.

## 7. Resources

The page wraps `nmas-resources` and supports device, platform, severity,
unhealthy-only, and time controls. CPU, memory, uptime, freshness, collector
alerts, and resource/system event presentation remains inside Grafana; Django
does not reproduce those panels.

## 8. Link Events

The page wraps `nmas-link-events` and supports device, event type, severity,
and time controls. It does not add "hide administratively-down" or
"interfaces with events only" because the stored event rows cannot truthfully
support those filters. It does not turn continuous gNMI samples into fake
transition events, and it does not claim topic classification that
`syslog_event` does not carry.

## 9. Link State & Traffic

The page wraps `nmas-link-state-traffic` and supports device, platform,
interface, time, hide-zero-traffic, hide-down, active-only, include-management,
and include-loopback controls. "Active" retains the Phase-2 definition:
administrative state UP **and** operational state UP.

Traffic is a non-negative derivative of octet counters expressed as bits per
second. Errors/discards are counter derivatives. No current collector stores a
trusted interface-speed/capacity denominator, so no percentage utilization is
displayed or implied.

## 10. Full Grafana and website-return behavior

The full-dashboard action always targets the same canonical UID and preserves
the current valid filter/time state. It opens in a new tab with
`noopener noreferrer`.

No stable externally browser-reachable Django base URL is configured in the
current localhost deployment. The canonical dashboard JSON was therefore not
modified to hardcode a misleading "Return to Website" link. Once a stable
application URL exists, a deterministic dashboard link can be added through
the repository-owned generator and reverified. Until then, the original Django
tab remains the safe return route.

## 11. Degraded behavior

Django checks only fixed `<GRAFANA_BASE_URL>/api/health`, without credentials,
using a finite timeout, disabled environment proxies, and a 64-KiB response
cap. Connection, timeout, HTTP, JSON, encoding, configuration, and unhealthy
database failures collapse to:

> Grafana monitoring service temporarily unavailable.

The wrapper still returns HTTP 200, keeps navigation and controls available,
and renders no fabricated operational values.

## 12. Theme contexts and responsiveness

- Basic Minimal: default context.
- Dark Mode: default context.
- Dark Angels: `ravenwing` on Monitoring and all three subpages.
- Adeptus Mechanicus: `monitoring` (Data / Monitoring) context.

The existing theme registry remains authoritative; no fifth theme was added
and no artwork was changed. Filter grids and dashboard actions collapse for
reduced-width screens. The optional iframe container, if deliberately enabled
later, is width-constrained within the application shell.

## 13. Security and read-only guarantees

- Base URL must be credential-free HTTP(S); userinfo, query, and fragments are
  rejected.
- Dashboard keys, UIDs, filter names, enumerated values, and time ranges are
  server-controlled allowlists.
- No arbitrary proxy target or browser-controlled upstream exists.
- No Grafana administrator credential, InfluxDB token, NetBox token, device
  secret, or Slack webhook enters template context.
- All monitoring forms use GET. There is no monitoring POST/action endpoint.
- The service imports no Netmiko, Paramiko, pynetbox, subprocess, or InfluxDB
  client and performs no device access.

## 14. Service boundary

`core/services/monitoring_service.py` owns canonical metadata, the stable
filter mapping, validation, URL construction, bounded health status, and safe
page context. It deliberately does not SSH devices, inspect Containerlab,
query or write NetBox, read or write InfluxDB, mutate Grafana, generate alerts,
run collectors, or restart services.

## 15. Known data/deployment limitations

1. No interface-speed/capacity source exists, so percentage utilization is
   unavailable.
2. Link Events cannot truthfully join administrative state to stored event
   rows.
3. No discrete gNMI transition history is fabricated from continuous samples.
4. `syslog_event` lacks a richer resource-vs-link topic tag.
5. `include_mgmt=false` cannot identify R3/R4's numbered management-carrying
   subinterfaces by name reliably; this remains the documented Phase-2
   limitation.
6. Embedding requires a separate authenticated Grafana browser session; a
   prohibitive live XFO/CSP response intentionally returns to link-only mode.
7. Loopback browser links are appropriate for the current local deployment;
   remote browser access would require a separately designed safe exposure or
   reverse-proxy arrangement.

## 16. Dashboard source impact

No Grafana dashboard source or generator changed in Phase 6. There is no
duplicate dashboard, datasource, collector, or InfluxDB bucket. Dashboard
panel/variable/query counts remain governed by the existing Grafana verifier.

## 17. Phase 7 handoff

Phase 7 should add read-only NSOT aggregation behind
`core/services/nsot_service.py`, drawing from NetBox, Git, live devices, and
automation metadata through established module boundaries. It must not place
monitoring behavior in NetBox or change the Monitoring service into a data
collector.
