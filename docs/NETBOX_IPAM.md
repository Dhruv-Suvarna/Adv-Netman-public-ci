# NetBox IPAM — Phases 1 through 3B.3

Status: NetBox is installed, running, reachable, populated with an accurate
model, and annotated with the Phase 3B.1 deterministic-identity decisions.
**Phase 3B.3 (see the section near the end of this document) superseded
the Vlan200-becomes-DHCP/DHCPv6-reserved assumption made in Phases
3B/3B.1/3B.2 below: Vlan200 is the management VLAN and stays statically
addressed.** That decision is authoritative; the Phase 3B/3B.1/3B.2
sections are kept as historical/platform-investigation record (in
particular, the cEOS DHCPv6 findings remain useful reference material) but
no longer describe the active target architecture for Vlan200.
**NetBox is NOT YET the active source of truth for device addressing** — no device configuration,
routing, DHCP, SNMP, syslog, gNMI, NETCONF, Grafana, or NetworkX topology
behavior was changed, and `master.py` does not call into it. Phase 2 is
validated modeling and identity planning, not cutover; see the latest phase
status at the end of this document for the precise current state.

`address_report.csv`/`address_report.py` remain exactly what the Phase-0
audit determined them to be: a generated, observed-state report (live
interface addresses + DHCP lease evidence), not an IPAM source of truth.
They are unrelated to this work and were not touched.

## Purpose

This phase establishes the foundation for a future NetBox-backed IPAM/DCIM
source of truth, without disturbing the working, template-driven addressing
model documented in `LAB_REQUIREMENTS.md`/`GAP_ANALYSIS.md`. It answers one
question only: **can we reliably run and communicate with NetBox from this
repository's tooling?** Modeling the existing lab inside NetBox (devices,
interfaces, prefixes, IP addresses, VLANs, ...) and making NetBox
authoritative for provisioning are separate, later phases.

## Architecture

```
NMAS
 |
 +-- existing Containerlab (srlceos01)         <- untouched
 |
 +-- existing monitoring stack (monitoring/)    <- untouched
 |      +-- InfluxDB, Grafana, SNMP/syslog/gNMI/NETCONF receivers
 |
 +-- NetBox stack (netbox/)                     <- new, independent lifecycle
        +-- netbox            (Django app + REST API + UI, Granian on :8080)
        +-- netbox-worker     (background job queue: rqworker)
        +-- postgres          (primary datastore)
        +-- redis             (task queue backend)
        +-- redis-cache       (NetBox's cache backend)

IaC (modules/)
 |
 +-- modules/netbox_ipam.py    <- the only module that speaks the NetBox API
          |
          +-- NetBox REST API (http://127.0.0.1:8000)

          (addressing/provisioning, DHCP, monitoring inventory, and
           verification integrations are future phases -- nothing in the
           repository calls into modules/netbox_ipam.py yet)
```

The NetBox stack is a **separate Docker Compose project** from
`monitoring/docker-compose.yml` (separate lifecycle, separate network,
separate volumes) — it is infrastructure/source-of-truth tooling, not a
monitoring collector. It is **not** a Containerlab node and is **not**
attached to any Containerlab network, bridge, or VLAN; Compose gives it its
own isolated `netbox_default` network. The only host-exposed port is
NetBox's own HTTP API/UI, bound to `127.0.0.1:8000` — chosen because `:8050`
(the NetworkX topology service) and `:8086`/`:3000` (InfluxDB/Grafana) were
already in use and `:8000` was free at the time this phase was implemented.

## Selected versions

Pinned to specific, mutually-compatible tags (no `latest`), matching the
current reference architecture published by
`netbox-community/netbox-docker` (`release` branch) for this NetBox release:

| Component | Image | Why |
|---|---|---|
| NetBox | `netboxcommunity/netbox:v4.7-5.1.1` | Current stable NetBox release (v4.7.0) at the time of this phase; the `-5.1.1` suffix is netbox-docker's own build/runtime variant tag, matching their published default. |
| PostgreSQL | `postgres:18-alpine` | Matches the netbox-docker reference compose for this NetBox version. |
| Redis (task queue) / Redis (cache) | `valkey/valkey:9.1-alpine` | netbox-docker's current reference compose uses Valkey (the Redis-protocol-compatible fork) in place of `redis:*` images; kept as two separate instances/volumes exactly as NetBox's own documentation recommends (cache vs. task queue). |
| Python client | `pynetbox` `>=7.8,<8` (pinned via `monitoring/requirements.txt`) | Current stable release; correctly recognizes both NetBox's classic and newer API token formats (see "A note on NetBox API tokens" below). |

No `netbox-housekeeping` container was added: the current netbox-docker
reference architecture for this NetBox release does not ship one (its
periodic maintenance no longer needs an external cron-style container), so
adding one here would be inventing a service the upstream architecture no
longer uses.

## A note on NetBox API tokens (why bootstrap works the way it does)

NetBox 4.7 stores API tokens as **hashed "v2" tokens**: NetBox itself
generates a matched `(key, token)` pair and persists only an HMAC digest of
it (see `users/models/tokens.py` in the pinned NetBox release) — the
plaintext secret is shown to a client exactly once, at creation time, and
cannot be recovered afterward. The client-facing value is the composite
string `nbt_<key>.<secret>`, sent as `Authorization: Bearer nbt_<key>.<secret>`
(rather than the older `Authorization: Token <value>` scheme). `pynetbox`
7.8 detects which format it was given and builds the correct header either
way; `modules/netbox_ipam.py`'s own `requests`-based health/auth checks
replicate that same detection so both paths behave identically.

Practically, this means the token **cannot** be safely pre-supplied through
the `netbox-docker` image's `SUPERUSER_API_TOKEN`/`SUPERUSER_API_KEY`
environment variables without reproducing NetBox's own generation/hashing
scheme outside NetBox — a risk not worth taking for a lab foundation phase.
Instead:

1. `SKIP_SUPERUSER=false` + `SUPERUSER_NAME`/`SUPERUSER_EMAIL`/
   `SUPERUSER_PASSWORD` use netbox-docker's own built-in, idempotent
   superuser bootstrap (`docker/super_user.py` inside the image, run on
   every container start; it exits immediately if the named user already
   exists).
2. `netbox/scripts/ensure_api_token.py` then asks **NetBox's own Django ORM**
   (via `manage.py shell -c`, the same supported mechanism the image's own
   superuser bootstrap uses) to create one real token for that user the
   first time the stack starts, and stores the resulting `nbt_<key>.<secret>`
   value into `netbox/.env` as `NETBOX_TOKEN`. It never touches the NetBox
   database directly.
3. Rerunning it is a no-op once `NETBOX_TOKEN` is already populated. If
   NetBox already has a token for that user but `netbox/.env` does not know
   its value (e.g. `.env` was lost), the script refuses to silently create a
   duplicate and reports the ambiguity for a human to resolve — see the
   script's own docstring.

## Service location, startup, shutdown, health

All commands run from the repository root unless noted.

```bash
# First-time bootstrap (idempotent; generates netbox/.env if missing,
# starts the stack, and ensures the IaC API token exists):
bash netbox/scripts/bootstrap_netbox.sh

# Subsequent start/stop of just the NetBox stack (never touches
# Containerlab or monitoring/docker-compose.yml):
cd netbox && docker compose up -d --wait
cd netbox && docker compose down          # add -v only to intentionally
                                           # discard all NetBox data

# Status:
cd netbox && docker compose ps

# HTTP/API health:
curl -s http://127.0.0.1:8000/api/status/ | python3 -m json.tool

# Foundational connectivity/authentication verification (Phase 1 scope):
cd /home/student/Scripts/clab_dualstack_lab
/home/student/Scripts/.venv/bin/python -m modules.netbox_ipam
```

## Persistence

Each stateful service uses a dedicated Docker **named volume** (not a bind
mount into the repository, and never committed to Git):

| Volume | Service | Contents |
|---|---|---|
| `netbox_netbox-postgres` | postgres | The entire NetBox database |
| `netbox_netbox-redis-data` | redis | Task queue durability (`appendonly yes`) |
| `netbox_netbox-redis-cache-data` | redis-cache | Cache only (no durability required) |
| `netbox_netbox-media` | netbox | Uploaded media (images, attachments) |
| `netbox_netbox-reports` / `netbox_netbox-scripts` | netbox | Custom reports/scripts (unused so far) |

These volumes persist across `docker compose restart`/`down` (without `-v`)
and container recreation. A full destroy-and-recreate persistence test was
not performed in this phase (not required by the phase's acceptance
criteria); volume existence and the correct service-to-volume mounts were
confirmed instead (see the phase's verification evidence).

## Environment variables and secret handling

- `netbox/.env.example` — tracked in Git; documents every variable name with
  a non-sensitive placeholder value.
- `netbox/.env` — **git-ignored** (see `.gitignore`); holds the real,
  randomly-generated secrets (PostgreSQL password, Redis/Redis-cache
  passwords, Django `SECRET_KEY`, `API_TOKEN_PEPPER_1`, the initial
  superuser password, and — once bootstrapped — `NETBOX_TOKEN`). Created by
  `netbox/scripts/bootstrap_netbox.sh`, mode `600`, and never overwritten on
  rerun.
- `modules/netbox_ipam.py` reads `NETBOX_URL`/`NETBOX_TOKEN`/`NETBOX_TIMEOUT`/
  `NETBOX_VERIFY_SSL` from the real process environment first, falling back
  to `netbox/.env` — the same resolution pattern already used by
  `modules/nmas.py`/`modules/snmp.py` for `monitoring/runtime/monitoring.env`.
- No secret is ever printed by any script in this phase. `ensure_api_token.py`
  confirms token creation without displaying the token value.

## Python abstraction — `modules/netbox_ipam.py`

The single, dedicated module every future NetBox integration must go
through — no other module should make a raw NetBox REST call. For this
phase it implements only:

1. `load_config()` — connection settings from environment/`netbox/.env`.
2. `build_client()` — constructs a configured `pynetbox.api` instance for
   future IPAM/DCIM use (Phase 2+); not used for the health/auth checks
   below (see the module docstring for why).
3. `check_status()` — calls `/api/status/`, distinguishing unreachable vs.
   auth-required vs. HTTP error vs. malformed response.
4. `verify_authentication()` — proves the configured token is accepted.
5. `run_diagnostics()` — runs the above and returns one structured,
   printable result; used by the CLI (`python -m modules.netbox_ipam`).

### Error handling

Every failure mode raises a distinct exception type — never a silently
empty result and never a bare `except Exception: pass`:

| Exception | Meaning |
|---|---|
| `NetboxConfigurationError` | Required configuration (e.g. `NETBOX_URL`) missing or invalid |
| `NetboxConnectionError` | NetBox unreachable: DNS failure, connection refused, timeout |
| `NetboxAuthenticationError` | NetBox reached, but authentication missing/rejected (HTTP 401/403) |
| `NetboxResponseError` | NetBox reached, but returned an HTTP error or unparsable response |

A caller can never mistake "NetBox is down" for "NetBox returned zero
objects" — this phase does not yet read any IPAM/DCIM collection, but the
exception hierarchy and the `check_status()` docstring commit to that
distinction before any such reader is added.

**No fallback-to-templates logic exists or is planned for this phase.**
Nothing in the repository falls back from NetBox to
`templates/*.cfg.j2`/`inventory.yml` addressing (or the reverse) — that
would create two ambiguous sources of truth. `master.py` and every existing
module are unchanged and do not import `modules/netbox_ipam.py`.

## Tests

- `monitoring/tests/test_netbox_ipam.py` — offline unit tests (mocked HTTP),
  covering configuration loading/precedence, missing URL, missing token,
  v1/v2 token header selection, successful status, unreachable NetBox,
  timeout, authentication failure, malformed response, and the
  empty-but-valid-JSON vs. malformed-response distinction. Run with:

  ```bash
  /home/student/Scripts/.venv/bin/python -m unittest \
      monitoring.tests.test_netbox_ipam -v
  ```

- Live integration check (requires the running NetBox stack):

  ```bash
  /home/student/Scripts/.venv/bin/python -m modules.netbox_ipam
  ```

## Phase 1 — status at the end of that phase (superseded below)

- NetBox was installed and reachable, but not yet the active source of
  truth for device addressing.
- NetBox had **not** been populated with any lab objects — that became
  Phase 2, described from here on.
- `master.py` and every existing module were unmodified in their behavior;
  none of them imported or depended on `modules/netbox_ipam.py`.

---

# Phase 2 — Modeling the existing lab in NetBox

Phase 2 answers exactly one question: **is NetBox an accurate model of what
the existing templates/inventory/DHCP config already say the lab should
look like?** It is explicitly NOT the cutover:

```text
existing templates/inventory
          |
          | extraction / reconciliation
          v
       NetBox
          |
          v
validation/reporting only
```

`master.py`, every template, `hostserv.py`, `dhcp/*.j2`, and `inventory.yml`
are all unmodified and continue to be the actual desired-state source that
gets rendered and pushed to devices. Nothing reads FROM NetBox yet.

## NetBox object model

| NetBox type | Used for | Count (this lab) |
|---|---|---|
| Site | One site representing the whole Containerlab lab | 1 |
| Manufacturer | Arista (cEOS devices), Generic (Linux/Ubuntu devices) | 2 |
| Device Type | `cEOS 4.36.2F`, `Ubuntu 24.04` (WebServer reuses the same type as R3/R4 -- literally the same container image) | 2 |
| Device Role | Router, Switch, Management Switch, External / Unmanaged | 4 |
| IPAM Role (`ipam.Role`, distinct from Device Role) | Loopback, Management, Client, Transit, External | 5 |
| VLAN | Every `vlan <id> name <NAME>` declared anywhere in `templates/*.cfg.j2` (10, 20, 30, 99, 101-104, 200) | 9 |
| Prefix | Every routed subnet actually configured, plus a small number of genuinely-contiguous numbering-block parents (see "Prefix design" below) | 33 |
| IP Range | The NMAS primary DHCPv4/DHCPv6 pools from `dhcp/dhcpd.conf.j2`/`dhcpd6.conf.j2` | 5 |
| Device | R1-R4, S1-S4, mgmt_swt (managed) + R5, WebServer (unmanaged) | 11 |
| Interface | Every interface that actually carries an IP address in the templates (loopbacks, management/client/transit SVIs, routed physical ports) -- pure L2 trunk ports are not modeled | 41 |
| IP Address | Every static address above, plus 5 shared VRRP-style gateway addresses | 83 |
| Tag | `csci5840-iac` (ownership marker), `managed`, `unmanaged` | 3 |
| Custom Field | `iac_managed` (boolean, on Device + Prefix), `dhcp_relay_targets` (text, on Prefix) | 2 |

## Migration manifest — `netbox/ipam.yml`

A hand-verified, machine-readable **transcription** of the existing desired
state, built by reading `templates/*.cfg.j2`, `hostserv.py`, `dhcp/*.j2`,
and `inventory.yml` directly (never from `address_report.csv`, which is
observed live state, and never from README/LAB_REQUIREMENTS prose where it
could not be cross-checked against an actual template). It is explicitly a
**temporary migration/bootstrap artifact**, not a second permanent IPAM
source: once a future cutover phase makes NetBox authoritative, this file's
job is done. Until then it is re-derived from the templates whenever they
change, never the other way around. The file's own header comment states
this role, and it ends with a `notes:` section documenting the one place a
documented claim (README's R2 secondary DHCP server) could not be verified
against an actual template and was therefore NOT modeled as verified
structured data.

### Prefix design

Every prefix in the manifest is either a single, standalone allocation
exactly matching a configured mask, or — only where the configured masks
genuinely tile a larger block with zero gaps invented — a parent "numbering
block" prefix alongside its child prefixes (e.g. the OSPF fabric's four
`/31`s exactly fill `192.168.100.0/29`). No prefix was invented purely for
visual organization.

### Containerlab management addresses (172.20.20.0/24 / 3fff:172:20:20::/64)

Deliberately **not** modeled as authoritative IPAM. These are Containerlab's
own runtime bootstrap addresses (discovered per-container, not configured by
this IaC) — importing them would blur the distinction this project draws
between the dedicated management VLAN (192.168.200.0/24 /
2001:db8:200::/64, which this manifest DOES model) and Containerlab's own
transient scaffolding.

### R5 / WebServer modeling decision

Both are modeled as NetBox Devices, with role `External / Unmanaged` and
`iac_managed = False`, **solely for IPAM collision-prevention** on the
prefixes their addresses sit on (the R3/R4↔R5 eBGP transit, R5↔WebServer
transit, and WebServer's BGP-advertised service addresses) — never as
provisioning targets. Guaranteed non-provisioning-target status is
enforced two ways, checked programmatically by
`netbox/scripts/verify_netbox_model.py`:

1. The `iac_managed` custom field is `False` on both devices and on every
   prefix in their addressing (the R3/R4↔R5 and R5↔WebServer prefixes, and
   the WebServer service prefixes).
2. Both carry the `unmanaged` tag and explicitly do NOT carry `managed`.

Any future provisioning code must check `iac_managed` (or the tag) before
touching a device — never infer scope from role/name alone.

### Primary address convention

For the 9 managed devices, NetBox's `primary_ip4`/`primary_ip6` is set to
the device's **dedicated-management-VLAN (Vlan200) address** — the exact
identity `modules/snmp.py`/`modules/syslog.py`/`modules/gnmi.py` already use
via `inventory.yml`'s `network_devices.*.monitoring.address`. R5 and
WebServer have no management-VLAN presence, so their primary is their most
identity-representative address instead: R5's `Loopback0` (the
router-id-equivalent identity a router without dedicated management uses),
and WebServer's own service loopback address (172.30.50.10 /
2001:db8:3050::10 — literally the address clients query it by).

### DHCP metadata (for the future DHCP phase, not applied now)

- **Pool boundaries**: modeled as native `ipam.IPRange` objects (the NMAS
  primary server's VLAN10/20/30 pools from `dhcp/dhcpd.conf.j2`/
  `dhcpd6.conf.j2`) — NetBox's first-class, independently-queryable
  start/end-address model, strictly better structured storage than a
  free-form description for exactly this data. Status is `reserved`, not
  `dhcp`: this NetBox release's `ipam.IPRange` model supports only
  `active`/`reserved`/`deprecated` (verified live via the API) — `dhcp` IS a
  valid status for `ipam.IPAddress` in this release, just not for
  `ipam.IPRange`. `reserved` ("this address space is set aside for a
  specific purpose") is the genuinely-supported status that accurately
  describes a pool boundary; the range's name/description make the DHCP
  purpose unambiguous.
- **Relay targets**: the `dhcp_relay_targets` custom field on each client
  prefix (comma-separated addresses), populated from the actual `ip
  helper-address`/`ipv6 dhcp relay destination` lines in
  `templates/S1.cfg.j2`/`S2.cfg.j2`.
- **Gateway/VLAN/family**: already structural (`Prefix.vlan`,
  `Prefix.prefix`'s own address family, `gateway_v4`/`gateway_v6` recorded
  in the manifest and represented as the shared VRRP-role IP addresses).
- **H4 / VLAN30 IPv6-only design**: preserved exactly — VLAN30 has an IPv6
  prefix and IPv6 DHCP range only; no IPv4 prefix or range exists for it
  anywhere in the manifest or in NetBox (verified by both
  `verify_netbox_model.py` and a dedicated unit test against the real
  manifest).
- **Known gap, not fabricated**: README.md documents R2 as a secondary EOS
  DHCP server with non-overlapping pools, and its relay-destination address
  (192.168.200.2) genuinely IS used in `templates/S1.cfg.j2`/`S2.cfg.j2` and
  IS modeled — but no corresponding native EOS DHCP server/pool
  configuration was found in `templates/R2.cfg.j2`. The secondary pool
  ranges are therefore NOT modeled as a NetBox `IPRange`; see `notes:` in
  `netbox/ipam.yml`.

## Population — `netbox/scripts/populate_netbox.py`

```bash
# Preview only, no writes:
/home/student/Scripts/.venv/bin/python netbox/scripts/populate_netbox.py --check --verbose

# Create/update the expected objects:
/home/student/Scripts/.venv/bin/python netbox/scripts/populate_netbox.py --apply --verbose
```

Reads `netbox/ipam.yml`, validates it structurally (duplicate names/
prefixes/addresses, dangling VLAN/role/device-type references, malformed
IP/prefix syntax, DHCP range direction/family — see
`monitoring/tests/test_populate_netbox.py`), then reconciles every object
through `modules/netbox_ipam.py`'s generic `reconcile_object()` primitive —
this script contains no raw `pynetbox` calls of its own; it only decides
*what* to reconcile.

**Idempotent by construction.** `reconcile_object()` distinguishes, per
object:

| Outcome | Meaning |
|---|---|
| `CREATE` / `CHECK-CREATE` | No matching object exists yet |
| `UNCHANGED` | Matches, every field already correct |
| `UPDATE` / `CHECK-UPDATE` | Matches, only a "safe" cosmetic field (description, status, enabled, tags, matching custom-field keys) differs |
| `CONFLICT` | Matches, but a **structural/identity** field differs (device_type, role, site, prefix vlan/role, an IP's interface assignment, a custom field this repo owns holding an unexpected value) — reported, **never auto-corrected** |
| `SKIPPED` | (`--check` only, against a NetBox with none of this manifest's objects yet) A prerequisite parent (site/VLAN/device_type/role) does not exist yet, so the child cannot even be previewed; resolves itself once `--apply` has run once |

Tags are always additive (an existing object keeps every tag it already
had; this repo's tags are unioned in) and therefore never conflict.
`--apply` run twice in a row is proof of idempotency: the first run
reported `CREATE=204, UNCHANGED=19`; the second reported `UNCHANGED=223`
with zero `CREATE`/`UPDATE`/`CONFLICT` and the same object counts in NetBox
both times (verified via the API, not just the script's own report).

## Validation — `netbox/scripts/verify_netbox_model.py`

```bash
/home/student/Scripts/.venv/bin/python netbox/scripts/verify_netbox_model.py
```

The **desired-state** check: does NetBox actually contain what
`netbox/ipam.yml` says it should? Checks (387 individual assertions against
the real running NetBox as of this phase, all passing): every managed
device present with correct type/role/`iac_managed`/tag; R5/WebServer never
classified as managed; every manifest interface present; every VLAN
present; every prefix present with the correct VLAN association; every IP
address present, assigned to the correct interface, with no duplicate
assignment; primary addresses correct per the convention above; DHCP ranges
and relay-target metadata present; VLAN30's IPv6-only nature preserved; and
no unexpected `csci5840-iac`-tagged device/VLAN/prefix exists (catches
manifest edits that drop something without cleaning up the stale object).

## Live-state cross-check — `netbox/scripts/compare_live_state.py`

```bash
python3 address_report.py                             # refresh live evidence (read-only)
/home/student/Scripts/.venv/bin/python netbox/scripts/compare_live_state.py
```

A **separate, independent** question from the above: does the *running*
network currently resemble what NetBox models? This script never changes
NetBox or any device — it only diffs NetBox's modeled static addresses
against a fresh `address_report.py` observation (excluding Containerlab's
own runtime management network and H1-H4's individual DHCP-leased
addresses, neither of which NetBox models). Drift is reported, never used
to silently "correct" either side.

**Result as of this phase:** every one of NetBox's 78 modeled, interface-
assigned static addresses was observed live (zero missing). Three items
were observed live but are NOT in the manifest/NetBox — genuine,
pre-existing drift between the current templates and the running
containers, reported here rather than silently absorbed into NetBox or
"fixed" on the live device (out of scope for this phase):

1. `S1` `Loopback0` = `192.168.255.11/32` — live only; `templates/S1.cfg.j2`
   declares no `Loopback0` at all (only `no interface Loopback10`).
2. `S2` `Loopback0` = `192.168.255.12/32` — same situation,
   `templates/S2.cfg.j2`.
3. `WebServer` `eth1` carries an extra SLAAC-autoconfigured IPv6 address
   (`2001:db8:3150:0:a8c1:abff:fe8b:e979/64`) alongside its statically
   configured `2001:db8:3150::2/64` on the same `/64` — a normal side
   effect of IPv6 autoconfiguration being active on that link, not a
   configuration-source discrepancy.

Items 1-2 are template/live drift worth a human decision (was `Loopback0`
intentionally removed from the templates, or should the live devices be
cleaned up?) — this phase deliberately takes no action on it.

## Tests

- `monitoring/tests/test_netbox_ipam.py` — extended with `ReconcileObjectTests`,
  `EnsureTagTests`, `EnsureCustomFieldTests` (17 new tests: CREATE/UNCHANGED/
  UPDATE/CONFLICT, idempotent rerun via an in-memory fake endpoint, additive
  tag merging, custom-field key-level merge/conflict, ambiguous-lookup
  detection, connection-error vs. NetBox-rejection distinction, and a
  regression test for comparing a `{"id": ...}` reference against an
  existing object's `.id` rather than its `.slug`).
- `monitoring/tests/test_populate_netbox.py` — new (32 tests): manifest
  structural validation (duplicates, invalid prefixes/addresses, dangling
  references, DHCP range direction/family), managed/unmanaged tag-scope
  logic, and content assertions against the real `netbox/ipam.yml` (R5/
  WebServer never managed, VLAN30 IPv6-only preserved).
- All 162 repository tests pass (`python -m unittest discover -s
  monitoring/tests -p 'test_*.py'`).

## Phase 2 — Migration status

- NetBox now contains an accurate, validated model of the existing lab (11
  devices, 41 interfaces, 83 IP addresses, 33 prefixes, 9 VLANs, 5 DHCP
  ranges) — but it is **NOT YET** the active source of truth for device
  addressing.
- `address_report.csv`/`address_report.py` remain an observed-state report,
  untouched and unrelated to NetBox.
- `templates/*.cfg.j2`, `hostserv.py`, `dhcp/*.j2`, and `inventory.yml` are
  all unmodified and remain the actual desired-state source `master.py`
  renders and pushes. This intentional duplication (same addressing
  present in both the templates AND `netbox/ipam.yml`) is temporary
  migration scaffolding, not a permanent second source of truth.
- `master.py` has not been modified and does not call into
  `modules/netbox_ipam.py` or any Phase-2 script.
- Phase 3 (making NetBox authoritative for provisioning, and retiring
  `netbox/ipam.yml`) has not begun; Phase 3A below is proof-of-equivalence
  only.

---

# Phase 3A — Shadow Provisioning

Phase 3A proves that NetBox can supply every addressing value the existing
templates need, WITHOUT pushing anything to a device and WITHOUT changing
`master.py`, `templates/*.cfg.j2`, `dhcp/*.j2`, or `inventory.yml`.

```text
NetBox
  |
modules/netbox_ipam.py        <- normalized READ API (Step 2/3)
  |
modules/ipam_context.py       <- normalized provisioning context (Step 4)
  |                              + legacy extraction + equivalence checker
  |                              + candidate renderer (all in this one module)
  |
netbox/scripts/shadow_render.py  <- CLI: validate -> render -> compare
  |
candidate configs (netbox/runtime/shadow/, git-ignored, never applied)
```

**`master.py`, every `templates/*.cfg.j2`, `dhcp/*.j2`, and `inventory.yml`
are all still byte-for-byte unmodified** (verified with `git status
--short` -- see the Git Safety section below). The existing,
already-working provisioning mechanism carries zero risk from this
exploratory phase.

## Design decision: regex-substitution instead of converting templates to Jinja variables

The templates' addressing values are plain literal text today (no Jinja
variables for addresses at all) — proving "NetBox can render the same
config" therefore has two possible designs: convert every address literal
to a `{{ }}` variable and render the same file from two different
contexts, or read the current template text and substitute the specific
literals NetBox disagrees with. This phase deliberately takes the second,
lower-risk path:

* `templates/*.cfg.j2` are the same files `master.py` already renders for
  real device pushes. Converting their addressing to Jinja variables would
  require `master.py`'s own render call to supply a matching "legacy"
  context for every one of those new variables just to keep producing the
  exact same output it does today — a change to the one thing every phase
  so far has been careful never to touch or risk.
* The substitution approach needs zero changes to `master.py` or the
  templates: `modules/ipam_context.py` reads the current template text
  (never writing it back), and replaces each specific address literal with
  the value NetBox produces for the same semantic field.
* Because Phase 2 already proved NetBox holds the exact current addressing
  with zero drift for every managed device (see Phase 2's live-state
  cross-check), a correct implementation of this substitution produces text
  **identical** to the original template — which is itself the strongest
  possible form of the equivalence proof Step 11 asks for (a full-file
  diff, not just field-level comparison). This is exactly what Section
  "Shadow Render Results" below shows: 9/9 candidate renders are
  byte-identical to their source templates.

If a real cutover is later approved, that phase's own conversion of the
templates to Jinja variables (and matching `master.py` update) is separate,
deliberate work — not an accidental side effect of this proof-of-concept.

## Normalized read API — `modules/netbox_ipam.py` additions

Every function returns a plain Python dict/list/`None`/bare address string
— never a raw `pynetbox` Record — and every failure mode raises the same
typed exceptions the rest of this module already uses, plus one new one:

| Function | Purpose |
|---|---|
| `get_managed_devices()` | The names NetBox marks as managed, using its OWN scope metadata (the `managed` tag AND the `iac_managed` custom field, which must agree) — never a hard-coded exclusion list |
| `is_device_managed()` / `require_managed_device()` | Defense-in-depth membership checks for any function about to do something provisioning-shaped |
| `get_device()` / `get_primary_address()` | Device summary and its primary IPv4/IPv6 |
| `get_interface_addresses()` / `get_interface_address()` | Every (or one, by family) address on a named interface |
| `get_peer_addresses()` / `get_peer_address()` | **Derives** the other end of a point-to-point link (BGP neighbor / static-route next hop) by finding the other host sharing the same prefix — never a hard-coded peer identity (Step 5) |
| `get_prefix()` / `get_vlan()` | Normalized prefix/VLAN summaries, including both address families where they exist |
| `get_shared_gateway()` | The VRRP-role shared gateway address for a client VLAN (Step 6) — `None`, not fabricated, when the VLAN has no gateway of that family (VLAN30's IPv4) |
| `get_dhcp_ranges()` / `get_dhcp_relay_targets()` | Phase 2's DHCP pool/relay metadata, read-only |
| `get_device_interface_names()` / `list_all_prefix_cidrs()` | Small structural helpers so callers enumerate NetBox's own data instead of hard-coding it |

`NetboxModelError` (new, subclasses `NetboxError`): NetBox was reached and
answered normally, but the specific object/relationship a caller asked for
doesn't exist, or the model is internally inconsistent (e.g. a device
tagged both `managed` and `unmanaged`, or a "peer" query landing on a
multi-host segment like the management VLAN instead of a real
point-to-point link). Distinct from a connectivity/auth failure — a caller
can never confuse "NetBox is down" with "NetBox doesn't have this."

## Normalized provisioning context — `modules/ipam_context.py`

A pure data-transformation layer (Step 4): no SSH/Netmiko/paramiko import,
no device connections, no DHCP/monitoring/Containerlab logic anywhere in
it.

* `build_device_context(device)` — the template-friendly nested context for
  one managed device (management address, every interface's addresses,
  client-VLAN shared gateways), built by enumerating the device's OWN
  NetBox interfaces rather than a hard-coded per-device address table
  (Step 5). Refuses (`NetboxModelError` via `require_managed_device`) for
  R5/WebServer.
* `extract_legacy_facts(device)` — regex-extracts the current addressing
  intent directly from `templates/<device>.cfg.j2` (loopback/management/
  SVI/point-to-point addresses, VRRP gateways, BGP-neighbor and
  static-route-next-hop address values, NAT sources, RIP/BGP
  `network`/prefix-list `permit` references). Read-only; never writes.
* `build_netbox_facts(device)` — the NetBox-sourced equivalent, in the
  identical shape, for the SAME interfaces/relationships the legacy
  template already defines (which relationships exist is still the
  existing, unchanged routing design — Step 9 explicitly says not to
  redesign that; what this function proves is that NetBox supplies the
  correct address VALUES for that already-fixed shape).
* `compare_facts(device, legacy, netbox)` → `ComparisonResult` — the
  equivalence checker (Step 10).
* `render_candidate_config(device)` / `write_candidate_config(device)` —
  the shadow renderer (Step 8): reads the template text, substitutes any
  address literal NetBox disagrees with, and (for the CLI) writes the
  result under `netbox/runtime/shadow/` (git-ignored, never applied).
* `validate_netbox_ready()` — the Step 13 pre-flight gate (see below).

### Deriving relationships instead of hard-coding them (Step 5)

* **A device's own interface list**: enumerated live via
  `get_device_interface_names()` — never a stored per-device list.
* **BGP-neighbor / static-route-next-hop addresses**: `get_peer_address()`
  finds the OTHER IP address sharing the same `/31` (or `/127`) prefix as
  the device's own interface address — this is how `build_netbox_facts`
  correctly derives R5's address (172.20.5.1) as R3's BGP neighbor purely
  from the shared `172.20.5.0/31` transit prefix, with zero hard-coded
  peer identity, and it works identically across the managed/unmanaged
  boundary (R3 is managed, R5 is not, and the lookup doesn't care).
* **Client-VLAN shared gateways**: `get_shared_gateway()` looks up the
  VRRP-role address on the VLAN's own prefix — never assigned to, or
  guessed from, a specific device's interface.
* **NAT sources / RIP-BGP network references**: validated as membership in
  `list_all_prefix_cidrs()` (every prefix NetBox knows about) rather than
  a second hard-coded copy of which prefixes should be referenced — *which
  prefixes get NAT'd or redistributed* is unchanged routing/NAT policy
  (out of scope for this phase, same as ASN/OSPF-area), but the *address
  values* used for it are fully NetBox-derived and validated.

## Managed scope enforcement (Step 3)

`get_managed_devices()` is the sole authority; `modules/ipam_context.py`
never maintains its own device list beyond `MANAGED_DEVICES` (a tuple used
only for the CLI's `--all` convenience and the readiness gate's expected-
set check — every actual per-device operation still asks NetBox via
`require_managed_device()`). Confirmed live:

```text
>>> get_managed_devices()
['R1', 'R2', 'R3', 'R4', 'S1', 'S2', 'S3', 'S4', 'mgmt_swt']
>>> require_managed_device("R5")
NetboxModelError: 'R5' is not a managed device in NetBox; refusing to
treat it as a provisioning target
>>> require_managed_device("WebServer")
NetboxModelError: 'WebServer' is not a managed device in NetBox; refusing
to treat it as a provisioning target
```

## Fail-closed behavior (Step 12/13) — no silent fallback

* Every function in `modules/netbox_ipam.py` and `modules/ipam_context.py`
  propagates NetBox failures as exceptions. There is no
  `try: use_netbox() except: use_hardcoded_values()` anywhere in either
  module, and there will not be one added later in shadow mode either —
  the old (template) path continuing to exist and work is not a fallback
  *inside* the NetBox-derived renderer, it is simply a second, independent
  path that has not been cut over yet.
* `validate_netbox_ready()` is the explicit pre-flight gate
  `shadow_render.py` calls before rendering anything: connectivity, auth
  (when a token is configured), the expected 9-device managed set, and
  every managed device having at least one primary address. Any failure
  raises immediately (fail-closed) rather than proceeding with a partially
  available model.

## Running shadow rendering

```bash
# One device:
/home/student/Scripts/.venv/bin/python netbox/scripts/shadow_render.py --device R1

# All nine managed devices, also writing candidate config text:
/home/student/Scripts/.venv/bin/python netbox/scripts/shadow_render.py --all --write-candidates -v
```

Candidate output goes to `netbox/runtime/shadow/<device>.cfg`
(git-ignored, regenerated on demand, never read by anything else). Exit
code 0 = every requested device is `EQUIVALENT`; exit code 2 = at least one
is not (differences are printed, never silently accepted); exit code 1 =
NetBox itself was not ready (Step 13's gate failed).

## What constitutes PASS

A device is `EQUIVALENT` when `compare_facts()` finds zero differences
across every interface address, VRRP gateway, BGP-neighbor/static-route
peer address, NAT source, and RIP/BGP-referenced prefix `extract_legacy_facts`
found in its template. Differences, when they occur, are classified:

| Classification | Meaning |
|---|---|
| `BUG` | NetBox and the template disagree on an address VALUE that should match — used for every difference this phase's checker can currently produce |
| `EXPECTED-MIGRATION-DIFFERENCE` | Reserved for a future phase where NetBox is deliberately ahead of the templates (not used yet — nothing is deliberately different yet) |
| `PRE-EXISTING-DRIFT` | Reserved for template-vs-live drift (see "Known runtime drift exclusions" below — that drift is between the templates and the LIVE devices, not between the templates and NetBox, so it does not appear in this phase's comparisons at all) |
| `NON-IPAM-DIFFERENCE` | Reserved for a future, more literal template diff where formatting/protocol-parameter noise would need separate classification from address differences |

## Known runtime drift exclusions

Per explicit instruction, the following are excluded from this phase
entirely — not imported into NetBox, not added to the templates, not
touched on the live devices, and not part of any equivalence check here
(they concern the templates-vs-LIVE-devices relationship, which Phase 2's
`compare_live_state.py` already reported separately):

* `S1` `Loopback0` = `192.168.255.11/32` and `S2` `Loopback0` =
  `192.168.255.12/32` — live-only, absent from `templates/S1.cfg.j2`/
  `S2.cfg.j2`.
* `WebServer`'s extra SLAAC-autoconfigured IPv6 address.

The R2 secondary-DHCP-server ambiguity (Phase 2) is likewise untouched: no
DHCP server configuration was invented or modified in this phase.

## Tests

* `monitoring/tests/test_netbox_ipam.py` — extended with 36 new tests for
  every Phase 3A read function, using a small realistic in-memory fake
  NetBox client (`FakeNetboxClient`) that implements the actual `.filter()`
  semantics these functions issue (`tag`, `device`, `interface_id`,
  `parent`, `vlan_id`) — covering managed-device selection, R5/WebServer
  exclusion (including tag/custom-field disagreement as a model error),
  interface lookup, IPv4/IPv6/dual-stack/IPv6-only lookups, point-to-point
  peer derivation (including the "shared segment is not a peer" case),
  VRRP shared-gateway lookup (including "VLAN has no gateway of this
  family"), DHCP ranges/relay targets, and duplicate-address ambiguity.
* `monitoring/tests/test_ipam_context.py` — new (35 tests): legacy
  extraction against the REAL templates (regression-tested per device,
  including VLAN30's IPv6-only preservation), the equivalence checker's
  difference/classification logic, `build_netbox_facts`'s orchestration
  (mocked at the `netbox_ipam` function level, including the host-address
  vs. canonical-network normalization fix), the Step 13 readiness gate
  (ready / connection-error / auth-error / wrong managed set / missing
  primary address), managed-scope enforcement for R5/WebServer, and
  candidate rendering (including the byte-identical-when-no-drift case).
* All 233 repository tests pass.

## Live shadow-render evidence

```text
$ python3 netbox/scripts/shadow_render.py --all --write-candidates
Validating NetBox is ready for shadow rendering...
  managed devices: ['R1', 'R2', 'R3', 'R4', 'S1', 'S2', 'S3', 'S4', 'mgmt_swt']

R1        PASS
R2        PASS
R3        PASS
R4        PASS
S1        PASS
S2        PASS
S3        PASS
S4        PASS
mgmt_swt  PASS

Overall: PASS
```

Every one of the 9 written candidate files
(`netbox/runtime/shadow/<device>.cfg`) was confirmed byte-for-byte
identical to its source `templates/<device>.cfg.j2` — the strongest form
of Step 11's "render complete configurations and diff them."

## Future consumers identified, not yet migrated (Step 16)

`inventory.yml`'s `network_devices.*.monitoring` block (management
address/platform per device, consumed by `modules/snmp.py`,
`modules/syslog.py`, `modules/gnmi.py`, and `modules/topology.py`) is a
second place addressing is mirrored today. This phase identifies it as a
future NetBox consumer — `get_primary_address()` already returns the
identical value — but does **not** cut it over; those modules are
unmodified and continue reading `inventory.yml` exactly as before.

## Remaining hard-coded IPAM dependencies (defines the live-cutover scope)

Even with the read API and context layer proven, the ACTUAL provisioning
path is unchanged:

* `templates/*.cfg.j2` still contain every address as literal text —
  nothing renders from `modules/ipam_context.py` in the real
  `master.py`/`push_eos`/`push_linux_router` path.
* `master.py` builds its render context from `inventory.yml`/`hostserv.py`
  exactly as before; it does not import `modules/netbox_ipam.py` or
  `modules/ipam_context.py`.
* `dhcp/dhcpd.conf.j2`/`dhcpd6.conf.j2` are still hand-maintained; DHCP
  provisioning is explicitly a later phase.
* `inventory.yml`'s monitoring-address mirror still feeds SNMP/syslog/
  gNMI/topology — unmigrated per Step 16.
* The R2 secondary-DHCP-server configuration gap (Phase 2) is still
  unresolved and out of scope here.

## Phase 3A — Migration status

NetBox is now validated for configuration generation (every managed
device's candidate render is provably equivalent, address-value-for-
address-value, to the current template output — 9/9 byte-identical), but
**live device provisioning has NOT yet been cut over to NetBox.**
`master.py`'s normal execution path, every `templates/*.cfg.j2` file,
`dhcp/*.j2`, and `inventory.yml` are all unmodified.

---

# Phase 3B — Deterministic Dynamic Address Assignment

Phase 3A proved NetBox can reproduce the current, entirely-static
addressing. Phase 3B answers a different question: **once addressing
eventually becomes dynamically assigned (DHCP/DHCPv6), how does a device
keep receiving the exact same address it has today?**

```text
NetBox
  |
  +--> authoritative IP mapping (already proven equivalent, Phase 3A)
  |
  +--> interface MAC / client identity
          |
          +--> DHCPv4 fixed reservation
          |
          +--> DHCPv6 fixed reservation
```

**DHCP/DHCPv6 are transport mechanisms for assigning the predetermined
NetBox address. They are not allowed to independently choose the
infrastructure addressing plan.** Every row this phase's reservation view
produces is read directly from the same NetBox `ipam.IPAddress` objects
Phase 2 populated and Phase 3A proved equivalent — there is no separate
"reservation pool," so a reservation can never disagree with NetBox's own
mapping (Step 12): it *is* that mapping, by construction.

**No live DHCP conversion occurs in this phase.** No template was
changed, no DHCP server config was touched, nothing was pushed to a
device.

## Step 3 — Interface classification (the assignment-policy decision)

Every managed interface is classified into exactly one policy, recorded
per-family as an `ipv4_assignment_mode`/`ipv6_assignment_mode` value
(`static` / `dhcp-reserved` / `dhcpv6-reserved` / `none`):

| Category | Mode | Why |
|---|---|---|
| Management SVI (`Vlan200`, all 9 managed devices) | `dhcp-reserved` / `dhcpv6-reserved` | The one category this project's own framing example targets: a device always gets the same IP via a server-side fixed reservation keyed by its management identity — a common real-world ZTP/OOB-management pattern. |
| Loopbacks (`Loopback0`/`lo`, R1-R4) | `static` | Step 5: no ordinary Ethernet MAC-based DHCP relationship, and a router identity that must exist independently of underlay connectivity. |
| Routed point-to-point RIP/OSPF/BGP transit links (`Ethernet1`/`Ethernet2`/`eth2`, fabric `Vlan101-104`) | `static` | Both endpoints' identities are a permanent, load-bearing part of the fixed routing design (not a dynamically-attaching endpoint) — conventional real-world practice keeps router-to-router transit links static. |
| A switch's own client-VLAN SVI (`S1`/`S2` `Vlan10`/`Vlan20`/`Vlan30`) | `static` | Infrastructure identity (the switch's own address), not an end-host lease — H1-H4 remain the actual DHCP clients on those VLANs (Step 14). |
| Shared VRRP gateway addresses | *(excluded from this model entirely — see Step 4)* | Not tied to a single interface/client identity at all. |
| Absent address for a family (e.g. VLAN30's IPv4) | `none` | Never fabricated — VLAN30 stays explicitly IPv6-only (Step 7). |

This is recorded as a small, explicit, reviewable Python rule
(`netbox/scripts/populate_netbox.py:_assignment_mode()`) — a POLICY
decision, not data pulled from a hidden table.

## Step 4/6 — Shared VRRP addresses are never reservations

The 5 shared gateway addresses Phase 2 modeled with `role=vrrp` (never
assigned to a single interface) are structurally excluded from
`get_address_reservations()`: that function only ever iterates a managed
device's own interfaces, and a VRRP address belongs to none of them. They
are never associated with a MAC/DUID and never appear in the reservation
matrix.

## Step 5 — Loopbacks stay static (unchanged addresses)

Per the explicit guidance above, R1-R4's loopbacks are classified
`static`/`static`. No loopback address was changed in this phase (or any
phase) — this decision only affects the *future* target mechanism, never
today's value.

## Step 6 — DHCPv4 identity: MAC address findings

**MAC representation**: NetBox 4.7 has a first-class `dcim.MACAddress`
model (a separate polymorphic object, `Interface.primary_mac_address` FK)
— used here instead of a custom field, per the instruction to prefer a
native representation when one exists.

**Live MAC discovery** (`netbox/scripts/sync_interface_macs.py`, read-only
`docker exec ... cat /sys/class/net/<iface>/address`) recorded each
managed device's `Vlan200` MAC:

| Device | Observed MAC | Pattern |
|---|---|---|
| R1, R2, S1, S2, S3, S4, mgmt_swt (cEOS) | `00:1c:73:xx:xx:xx` | Arista-OUI-prefixed; ONE shared "system MAC" reused across every L3 SVI on that device (confirmed live: R1's `Vlan200`/`Vlan101`/`Vlan102`/`cpu`/`fabric` interfaces all share one MAC) |
| R3, R4 (Ubuntu/FRR) | `aa:c1:ab:xx:xx:xx` | Linux locally-administered-bit pattern, inherited from the underlying veth |

**Stability finding — MAC addresses are NOT currently pinned or
guaranteed stable:**

* `grep -i mac /home/student/clab-quickstart/srlceos01.clab.yml` returns
  nothing — no interface MAC is pinned anywhere in the topology
  definition (verified live, read-only).
* R3/R4's `aa:c1:ab:` addresses are Linux-kernel-random veth MACs,
  assigned fresh at container/veth creation with no persistence mechanism
  — **effectively certain to change on any redeploy.**
* R1/R2/S1-S4/`mgmt_swt`'s `00:1c:73:` cEOS "system MAC" is generated once
  by the cEOS software and persists within a running container's own
  flash/state directory — but this project's own documented redeploy
  procedure (`containerlab destroy -t srlceos01.clab.yml --cleanup`, per
  `README.md`) explicitly removes each node's lab-state directory via
  `--cleanup`, so **this MAC should also be expected to change across the
  project's own documented redeploy workflow**, even though it is stable
  for the lifetime of one deployment.
* **Conclusion**: no currently-observed MAC address is a reliable,
  redeploy-stable DHCPv4 client identity today. This is reported, not
  papered over, per the explicit instruction. A deterministic DHCPv4
  reservation architecture requires the interface MAC to become explicitly
  pinned in `srlceos01.clab.yml`'s per-link `mac:` field (Containerlab
  supports this) — that edit is out of scope for this phase
  (`/home/student/clab-quickstart` was not modified; only read-only
  inspection was performed).
* The MAC sync script is therefore deliberately **observational, not a
  permanent manifest**: it reads the live value fresh every run and
  reconciles it into NetBox idempotently, so a MAC that changes on a
  future redeploy is detected as an `UPDATE`, never silently masked as
  still-correct.

## Step 7 — DHCPv6 identity: DUID/IAID findings

No live DHCPv6 client has ever run on any of R1-R4/S1-S4/`mgmt_swt` — all
are currently statically addressed — so there is **no live evidence** of
what mechanism a cEOS or FRR-Linux DHCPv6 client would use if one were
ever enabled on them. This is reported as an open, unverified gap, not
guessed at.

The only live DHCPv6 evidence in this lab is H1-H4 (ordinary Ubuntu 24.04
hosts, `isc-dhclient 4.4.3-P1`, already legitimate DHCP/DHCPv6 clients
per the existing design). Reading their lease state (read-only,
`docker exec <host> cat /var/lib/dhcp/dhclient6.leases`) shows:

```text
default-duid "\000\001\000\0012(\373\257\252\301\253\355\247\365";
...
option dhcp6.client-id 0:1:0:1:32:28:fb:af:aa:c1:ab:ed:a7:f5;
```

Decoded: **DUID-LLT (RFC 8415 type 1)** — `0001` (DUID type 1) + `0001`
(hardware type 1, Ethernet) + a 4-byte timestamp + the interface's 6-byte
MAC address (`aa:c1:ab:ed:a7:f5`, matching H1's `eth1`), generated once and
cached by `dhclient`. The IAID (`ia-na ab:ed:a7:f5`) is the last 4 bytes of
that same MAC.

**Implication**: DUID-LLT's stability is entirely dependent on (a) the
underlying interface MAC's stability — already found unstable above — and
(b) the DUID cache file itself surviving container lifecycle events, which
Containerlab's plain `linux` node kind does not bind-mount anywhere by
default. **No DUID/IAID value was fabricated or invented anywhere in this
phase** — the `dhcpv6_duid`/`dhcpv6_iaid` custom fields exist in the NetBox
schema (Step 8) but are left unset for every managed interface, and
`verify_reservations.py` correctly reports this as a `FAIL` (see "Live
verification evidence" below) rather than a false pass.

## Step 8 — NetBox data model additions

| Addition | NetBox representation | Why |
|---|---|---|
| Interface MAC address | Native `dcim.MACAddress` object + `Interface.primary_mac_address` | NetBox 4.7 already models this natively — no custom field needed. |
| `ipv4_assignment_mode` / `ipv6_assignment_mode` | Custom field (`text`, content-type `dcim.interface`) | No NetBox-native field expresses "the target future mechanism" without risk of being misread as "currently live" — see next paragraph for why NetBox's own `status=dhcp` on `ipam.IPAddress` was deliberately NOT reused. |
| `dhcpv6_duid` / `dhcpv6_iaid` | Custom field (`text`, content-type `dcim.interface`) | NetBox has no DUID/IAID concept at all — a genuine custom-field case per Step 8's own instruction. |

**Why a custom field, not NetBox's own IP-address `status=dhcp`:**
`ipam.IPAddress` *does* support a native `status=dhcp` value (confirmed
live via the API). It was deliberately not used here for two reasons: (1)
flipping an already-populated, already-Phase-2-validated address's status
to `dhcp` would misleadingly imply DHCP is *already* live, when this phase
explicitly performs no live conversion; (2) `populate_netbox.py`'s
existing, already-idempotent reconciliation of every IP address's `status`
field (`"active"`, not in `safe_update_fields`) would then treat every
future re-run as a spurious `CONFLICT` against a manually-changed status.
A dedicated interface-level custom field cleanly expresses *forward-looking
policy* without touching that already-working contract. Custom field type
is plain `text` (not NetBox's `select` type): a `select` field requires a
separate linked `CustomFieldChoiceSet` object, unwarranted complexity for
a 4-value set (`nb.ASSIGNMENT_MODES`) this repository already validates in
Python on every write and every read (`validate_reservations()`).

## Step 9 — MAC addresses are NetBox-driven, not a parallel file

`netbox/scripts/sync_interface_macs.py` reads the LIVE MAC straight from
each running container every time it runs and reconciles it into NetBox —
there is no YAML file, Python dict, or any other permanent record of MAC
addresses anywhere in this repository. `netbox/ipam.yml` remains exactly
what Phase 2 established it as (a migration/bootstrap transcription of
*addresses*, never touched for MAC data). The eventual source for any
future DHCP-config generator is `NetBox Interface -> MAC -> reserved
IPv4/IPv6`, queried live via `modules/netbox_ipam.py`.

## Step 10 — Reservation view API

```python
modules.ipam_context.get_address_reservations(client=None) -> list[dict]
```

One row per (managed device, interface); example (real, live data):

```python
{
    "device": "R1", "interface": "Vlan200",
    "mac_address": "00:1C:73:20:AB:82",
    "ipv4": "192.168.200.1", "ipv4_mode": "dhcp-reserved",
    "ipv6": "2001:db8:200::1", "ipv6_mode": "dhcpv6-reserved",
    "dhcpv6_duid": None, "dhcpv6_iaid": None,
}
```

Built entirely from `modules/netbox_ipam.py`'s normalized functions
(`get_managed_devices`, `get_device_interface_names`,
`get_interface_address`, `get_interface_mac`, `get_assignment_modes`) —
no raw `pynetbox` object ever leaves either module.

## Step 11/16 — Validation: `modules.ipam_context.validate_reservations()` + `netbox/scripts/verify_reservations.py`

Fail-closed structural checks, run every time (never stops at the first
issue):

| Category | Detects |
|---|---|
| `unmanaged-provisioning-target` | A row for a device outside the managed set (defense-in-depth; structurally can't happen given how rows are built) |
| `invalid-assignment-mode` | A mode value outside `nb.ASSIGNMENT_MODES` |
| `conflicting-assignment-mode` | `mode=none` but an address is recorded, or a non-`none` mode with no address |
| `missing-ipv4` / `missing-ipv6` | A declared mode with no matching address |
| `missing-mac` | `ipv4_mode=dhcp-reserved` with no MAC on file |
| `missing-dhcpv6-identity` | `ipv6_mode=dhcpv6-reserved` with no DUID *and* IAID on file |
| `duplicate-mac` | The same MAC recorded for two different device/interface rows |
| `duplicate-ipv4` / `duplicate-ipv6` | The same address recorded for two different rows |
| `pool-collision` | A recorded address (any non-`none` mode — see rationale below) falls inside a live `ipam.IPRange` boundary |

**Pool collision applies to static addresses too, not just DHCP-reserved
ones**: a statically-configured infrastructure address sitting inside an
active DHCP pool's numeric range is still a real collision risk (a DHCP
server has no way to know to avoid handing that same address to a dynamic
client unless it is separately excluded) — being static doesn't make the
overlap safe.

```bash
/home/student/Scripts/.venv/bin/python netbox/scripts/verify_reservations.py -v
```

## Live verification evidence

```text
Managed devices: ['R1', 'R2', 'R3', 'R4', 'S1', 'S2', 'S3', 'S4', 'mgmt_swt']

DEVICE     INTERFACE  MAC                IPv4             IPv4 MODE      IPv6                   IPv6 MODE         DUID/IAID
R1         Vlan200    00:1C:73:20:AB:82  192.168.200.1    dhcp-reserved  2001:db8:200::1        dhcpv6-reserved   MISSING
... (35 rows total: every managed device's every modeled interface)

FAIL  [missing-dhcpv6-identity] R1/Vlan200: dhcpv6-reserved but DUID/IAID not yet recorded
... (one per managed device's Vlan200 -- 9 total)

Rows checked: 35. Issues found: 9.
Overall: FAIL
```

**This `FAIL` is the correct, expected result, not a defect**: it is the
tool honestly reporting that IPv6 reservation readiness is genuinely
blocked (Step 7's finding — no DUID has ever been observed, and none was
fabricated), while confirming there are zero duplicate
MACs/addresses, zero pool collisions, and zero missing MACs for the
DHCPv4-reserved rows (the MAC sync succeeded for all 9). IPv4 reservation
readiness is structurally complete but flagged unstable (Step 6's MAC-
pinning finding); IPv6 reservation readiness is structurally blocked
pending a genuine DHCPv6 client trial.

## Step 13 — DHCP pool interaction: collision analysis

Checked every managed reservation address against every `ipam.IPRange`
Phase 2 modeled (the NMAS primary VLAN10/20/30 pools, `192.168.10.100-179`
etc.): **zero collisions**. The management SVI addresses (`192.168.200.0/24`)
occupy an entirely different subnet from every client pool by design, so
this is expected, not incidental — but it is verified programmatically on
every run rather than assumed.

## Step 14 — H1-H4 unchanged

H1-H4 remain ordinary pool-based DHCP/DHCPv6 clients exactly as before;
nothing in this phase touches `dhcp/dhcpd.conf.j2`/`dhcpd6.conf.j2`, and
`get_address_reservations()`/`validate_reservations()` never reference
H1-H4 at all (they are not managed devices and have no NetBox device
object). The distinction Step 14 draws is preserved structurally: H1-H4
are dynamic-pool clients; the 9 managed devices' `Vlan200` are (in the
future target state) dynamic-protocol-plus-deterministic-reservation.

## Step 15 — R5 / WebServer unchanged

Both remain represented in NetBox only for the same Phase 2 collision-
prevention reasons; `get_managed_devices()` (the sole iteration source for
`get_address_reservations()`) excludes both, and no DHCP/DHCPv6 client
configuration, MAC sync, or assignment-mode metadata was generated for
either.

## Step 20 — R2 secondary-DHCP-server gap

Unchanged from Phase 2's finding: `templates/R2.cfg.j2` has no server-side
DHCP pool configuration despite README/`inventory.yml` documenting R2 as
the secondary/backup DHCP server. For a future primary/backup DHCPv4/
DHCPv6 reservation architecture, the SAME `get_address_reservations()` rows
would need to be represented on **both** servers identically (a fixed
reservation must resolve to the identical address regardless of which of
the two servers answers a given request) — meaning any future DHCP-config
generator built from this model must emit matching reservation stanzas
for both `dhcp/dhcpd.conf.j2`/`dhcpd6.conf.j2` (NMAS/primary) and whatever
R2's eventual server-side implementation becomes, not just one. No such
generator or R2 configuration was written in this phase.

## Future cutover sequence (not started)

```text
NetBox reservation model (this phase)
        |
        +--> generate DHCPv4 fixed reservations (dhcpd.conf.j2 host{} blocks,
        |     keyed by the NetBox-recorded MAC -- pending the MAC-pinning
        |     fix identified in Step 6)
        +--> generate DHCPv6 fixed reservations (dhcpd6.conf.j2 host{}
        |     blocks, keyed by DUID+IAID -- pending a real DHCPv6 client
        |     trial to establish a genuine, non-fabricated identity)
        +--> change Vlan200 on each managed device from a static `ip
        |     address`/`ipv6 address` to a DHCP/DHCPv6 client
        +--> verify every device receives its predetermined NetBox address
              (never a different, dynamically-selected one)
```

## Tests

* `monitoring/tests/test_netbox_ipam.py` — extended (+9 tests): MAC
  address create/idempotent-reconcile/primary-assignment via an extended
  `FakeNetboxClient` (now including a working `dcim.mac_addresses`
  endpoint), and assignment-mode/DUID/IAID custom-field reads.
* `monitoring/tests/test_ipam_context.py` — extended (+28 tests):
  `get_address_reservations()`'s orchestration (mocked), the full
  `validate_reservations()` issue matrix (every category in the table
  above, including the pool-collision-applies-to-static-too case), and
  the `_assignment_mode()` interface-classification policy loaded directly
  from `populate_netbox.py` (management→dhcp-reserved, loopback/transit/
  client-SVI→static, absent-family→none, VLAN30 preserved IPv6-only).
* All 270 repository tests pass.

## Phase 3B — Migration status

The deterministic reservation architecture is now fully modeled and
validated in NetBox — assignment mode is explicit for every managed
interface, MAC addresses are live-synced and NetBox-driven, and the
validation tool correctly distinguishes "IPv4 reservation-ready but MAC
unstable" from "IPv6 reservation blocked, no fabricated identity" — but
**no live DHCP conversion has occurred.** `templates/*.cfg.j2`,
`dhcp/dhcpd.conf.j2`/`dhcpd6.conf.j2`, `master.py`, and R2's DHCP
configuration are all unmodified. Phase 3B.1 below supersedes Phase 3B's
preliminary identity-readiness finding. Phase 3C (not started) would
generate actual fixed reservations, but remains gated by the unresolved
cEOS DHCPv6 client capability and cutover prerequisites documented below.

---

# Phase 3B.1 — Deterministic Client Identity

Phase 3B.1 converts Phase 3B's identity observations into explicit,
reviewable decisions without changing any device or DHCP service. The
identity-planning script was applied to NetBox and then rerun idempotently;
all nine managed `Vlan200` records reported `UNCHANGED` on the second run.

## Observed is not authoritative

A MAC seen on a currently running container proves only current state. It
does not prove that the same value survives Containerlab destroy/recreate,
node-state cleanup, or Linux veth recreation. For that reason:

* `sync_interface_macs.py` marks a newly discovered MAC as `observed`.
  Rerunning observation preserves an existing stronger decision; it cannot
  demote `authoritative-planned` back to `observed`.
* `pin_stable_identities.py` promotes an already-recorded value only after a
  concrete future pinning mechanism has been identified. It never invents a
  replacement MAC.
* Reservation validation requires both a usable unicast MAC and explicit
  `authoritative-planned` status. Presence alone is insufficient.

The identity-status vocabulary is deliberately small and stored in NetBox:

| Status | Meaning | Readiness treatment |
|---|---|---|
| `observed` | Read from current runtime, but durability has not been decided/proven | `FAIL`; cannot generate an active fixed reservation |
| `authoritative-planned` | Exact value selected as desired state and paired with a concrete cutover pinning mechanism | `READY` if format/uniqueness checks also pass |
| `blocked` | Desired dynamic mode exists, but platform evidence does not establish a usable client mechanism | `BLOCKED`; never treated as missing or ready |
| unset | No identity decision exists | `FAIL` as missing model data |

The MAC status is the `identity_status` custom field on NetBox's native
`dcim.MACAddress`. DHCPv6 uses `dhcpv6_identity_status`, `dhcpv6_duid`, and
optional `dhcpv6_iaid` custom fields on `dcim.Interface`. Assignment policy
remains `ipv4_assignment_mode`/`ipv6_assignment_mode` on the interface.

## Planned stable-MAC mechanisms (not applied)

For the seven managed cEOS nodes (R1, R2, S1-S4, and `mgmt_swt`), the
future change is to retain the NetBox-recorded system MAC explicitly on the
management SVI with:

```text
interface Vlan200
   mac-address <NetBox authoritative MAC>
```

The installed EOS 4.36.2F command surface recognized `mac-address` under
the interface (the incomplete form was classified as incomplete rather
than invalid). This establishes a planned stable-MAC mechanism; it does not
prove DHCPv6-client support. No EOS configuration was applied or persisted
in Phase 3B.1.

For Linux/FRR R3 and R4, the future template change is to set the bridge MAC
after creating `Vlan200` and before starting a client:

```text
ip link set dev Vlan200 address <NetBox authoritative MAC>
```

The local `ip link` command supports this mechanism. It prevents the bridge
identity from being inherited unpredictably from a recreated member/veth.
This command has not been added to R3/R4's templates or run live.

## DHCPv4 readiness

All nine managed `Vlan200` interfaces have a unique, syntactically valid,
unicast MAC marked `authoritative-planned`. Their current IPv4 mappings are
unchanged, and all nine DHCPv4 reservation identities are `READY` as a
foundation. "Ready" here means the reservation input is valid; it does not
mean a server stanza exists or a client has been enabled.

## DHCPv6 strategy and IAID treatment

R3/R4 use deterministic Ethernet DUID-LL:

```text
00:03:00:01:<six authoritative MAC octets>
```

This is RFC 8415 DUID type 3, hardware type 1, followed by the stable MAC.
Validation requires exactly that structure and verifies mathematically that
the final six octets equal the authoritative MAC. Malformed or duplicate
DUIDs and DUID/MAC mismatches fail closed. The installed R3/R4 ISC dhclient
advertises `-6`, `-D LL|LLT`, and `-df duid-file`; the proposed future
client invocation will select `-D LL` after pinning the interface MAC and
will use an explicit DUID/lease-state path appropriate to the final
non-systemd client lifecycle. Nothing was started in this phase.

The recorded IAID on R3/R4 is the predicted final four MAC octets, matching
the behavior observed from this lab's Ubuntu ISC dhclient clients. It is
informational and explicitly non-blocking. The selected ISC DHCP server
fixed-IPv6 model matches the client DUID through:

```text
host-identifier option dhcp6.client-id;
fixed-address6 <NetBox predetermined IPv6>;
```

IAID is not part of that server-side fixed-address match, so absence of an
IAID does not prevent reservation generation. If IAID is present in NetBox,
the validator preserves it and requires a well-formed four-octet value.

## cEOS DHCPv6 blocker

The cEOS 4.36.2F build did not expose a proven normal DHCPv6 client or a
configurable DUID/IAID mechanism. In particular, the attempted normal
client form `ipv6 address dhcp` and candidate DHCP client identity command
surfaces were rejected as invalid during the prior safe capability
investigation. A working IPv4 DHCP client mechanism does not establish
IPv6 support. Therefore all seven managed cEOS `Vlan200` interfaces are
stored as `dhcpv6_identity_status=blocked`, with no fabricated DUID or IAID.
Validation reports these as `BLOCKED`, not generic missing-data failures.

## Current identity matrix

| Device group | MAC status | DHCPv4 | DUID strategy | DHCPv6 status |
|---|---|---|---|---|
| R1, R2, S1-S4, `mgmt_swt` (cEOS) | `authoritative-planned` | `READY` | None; no proven cEOS client mechanism | `BLOCKED` |
| R3, R4 (Ubuntu/FRR) | `authoritative-planned` | `READY` | deterministic DUID-LL from authoritative MAC; IAID informational | `READY` |

Current reservation-target result: `READY=11`, `BLOCKED=7`, `FAIL=0`
across 18 address-family targets (9 IPv4 + 9 IPv6). Overall Phase 3B.1 is
`BLOCKED`, because all desired managed `Vlan200` families are required for
the planned dual-stack conversion.

`validate_reservations()` rejects missing, malformed, multicast, duplicate,
observed-only, blocked, or unclassified MAC identities as appropriate. It
also rejects malformed/duplicate DUIDs, DUID-LL values that do not match the
authoritative MAC, blocked identities that improperly carry values, bad
optional IAIDs, duplicate addresses, pool collisions, invalid assignment
modes, and unmanaged provisioning targets. `verify_reservations.py` reports
per-family readiness and exits distinctly for `READY`, `BLOCKED`, model
`FAIL`, and NetBox access failure.

Phase 3B.1 added 27 unit tests to the prior 270-test baseline. The complete
repository suite now contains 297 tests, including explicit observed /
authoritative / blocked / missing cases, MAC and DUID validity/uniqueness,
optional IAID behavior, platform decisions, managed scope, Vlan200-only
reservation policy, static interfaces, VLAN30, and shared-gateway exclusion.

## Exact future cutover scope (proposal only)

A future approved cutover would have to perform, in order:

1. Render the authoritative NetBox MAC onto every managed `Vlan200` using
   the platform-specific mechanism above.
2. Generate identical NetBox-derived fixed IPv4 reservations on every
   participating DHCP server.
3. Generate DUID-keyed ISC `fixed-address6` reservations for platforms with
   a proven DHCPv6 client; do not emit cEOS reservations while status is
   `blocked`.
4. Establish and test the R2 backup-server implementation rather than
   assuming the currently absent server configuration exists.
5. Convert only `Vlan200`; preserve loopbacks, routing transits, S1/S2
   client SVIs, VLAN30's IPv6-only design, and unassigned shared gateway
   addresses exactly as they are.
6. Perform staged lease acquisition, reachability, rollback, and
   deterministic reacquisition testing without renumbering.

None of those changes was applied in Phase 3B.1. The DHCP templates,
device templates, `inventory.yml`, and `master.py` remain unchanged.

## Gate before Phase 3C

Phase 3C must not begin until all required target families pass with zero
`BLOCKED` and zero `FAIL`, or the approved scope is explicitly revised.
At minimum this requires concrete local evidence of a supported cEOS
DHCPv6 client/identity mechanism (or an explicit design decision not to
convert cEOS IPv6), plus an approved primary/backup server design. The
current honest recommendation is therefore **do not begin Phase 3C**.

---

# Phase 3B.2 — cEOS DHCPv6 Capability Resolution

Phase 3B.2 resolves the seven cEOS DHCPv6 blockers against the exact live
image without changing any live configuration. The result is:

```text
VERDICT: UNSUPPORTED
SCOPE: native stateful DHCPv6 IA_NA client address acquisition on an SVI
BUILD: Arista cEOSLab 4.36.2F-49692632.4362F.1 (engineering build)
```

Here, `UNSUPPORTED` means **not available through the native EOS
configuration and state-management implementation in this exact image**. It
does not claim that no other EOS version could ever add the feature, and it
does not promote an underlying Linux-shell workaround to supported EOS
behavior.

## Exact build and read-only method

The authoritative topology at
`/home/student/clab-quickstart/srlceos01.clab.yml` uses image
`ceos:4.36.2F`. Read-only `show version detail` on R1, followed by `show
version` on every live cEOS node, reported the same software identity:

| Property | Observed value |
|---|---|
| Product/platform | Arista cEOSLab |
| Software image | `4.36.2F-49692632.4362F.1 (engineering build)` |
| Internal build | `4.36.2F-49692632.4362F.1` |
| Internal build ID | `4c2c31a5-28af-417f-b85e-464a08c0a717` |
| Architecture | `i686` |
| Kernel | `7.0.0-30-generic` |
| Extensions | none available |
| Nodes checked | R1, R2, R5, S1, S2, S3, S4, `mgmt_swt` |

R5 was checked only to establish image consistency; it remains unmanaged and
is not a reservation target. No configuration mode was entered. The only EOS
CLI commands used in this phase were read-only `show` commands, and all Linux
namespace, package, process, source-file, and filesystem inspection was also
read-only. No DHCP packet was sent.

## Evidence classification

### PROVEN — installed-image evidence

The image contains several DHCP components, but their roles are not
interchangeable:

* Arista `DhcpClient`/`DhcpClient-lib` 1.0.5 and ISC `dhcp-client` 4.4.2
  are installed. `DhcpRelay` 2.0.18 and Kea 2.6.3 server components are
  also installed. Relay/server packages do not establish client capability.
* The native Arista client integration is
  `/usr/lib/python3.9/site-packages/SuperServerPlugin/Dhclient.py`, owned by
  `DhcpClient-lib`. It can manage front-panel ports, port-channels, SVIs, and
  management interfaces, but only through the IPv4 `Ip::IpIntfConfig` model.
  It starts `dhclient` without `-6`, generates an IPv4
  `dhcp-client-identifier`, consumes `new_ip_address` and
  `new_subnet_mask`, maintains IPv4 `fixed-address` lease records, and writes
  IPv4 status/default-route state. Its companion
  `/etc/dhcp/dhclient-script.py` is likewise IPv4-only.
* Those native client files contain no IPv6, DHCPv6, `IA_NA`, DUID, IAID, or
  `-6` handling. The installed package has no `DhcpClient-cli` component;
  by contrast, explicit `DhcpRelay-cli` and `DhcpServer-cli` packages exist.
* The installed IPv4 parser source
  `CliPlugin/IraIpIntfCli.py` registers `ip address dhcp`. The installed IPv6
  parser source `CliPlugin/IraIp6IntfCli.py` registers only a literal IPv6
  address/prefix, removal, `auto-config`, and link-local forms. Its own help
  describes `auto-config` as SLAAC. It does not register `ipv6 address dhcp`
  or another stateful client form.
* A read-only EXEC parser check returned `% Invalid input` for `show ipv6
  dhcp client`; `show ipv6 dhcp` was incomplete because relay/snooping show
  branches exist. The current read-only Vlan200 output showed only the
  existing static `2001:db8:200::1/64` address on R1.
* `/usr/sbin/dhclient` itself advertises generic Linux options `-6`, `-D
  LL|LLT`, and `-df duid-file`. A ZeroTouch DHCPv6 request configuration is
  also present. These facts prove the binary can perform DHCPv6 in some Linux
  contexts; they do **not** supply EOS interface configuration, IPv6 Sysdb/Ira
  integration, a Vlan200 lifecycle, or a supported EOS DUID control surface.
* The native EOS client lease directory was empty during inspection. No
  native DHCPv6 DUID or IAID exists to observe, preserve, or put into NetBox.
  R1's `vlan200` kernel device exists in the EOS `default` network namespace,
  but namespace visibility is not a supported-client interface.

### PROVEN — official Arista documentation

The official [EOS 4.36.2F IPv6 manual](https://www.arista.com/en/um-eos/eos-ipv6?tmpl=component)
documents the full `ipv6 address` syntax as a literal address/prefix or
`auto-config`, explicitly identifying `auto-config` as SLAAC and listing VLAN
interfaces as supported for those forms. It provides no DHCP client form.

The official [EOS 4.36.2F DHCP chapter](https://www.arista.com/en/um-eos/eos-configuring-dhcp)
documents DHCPv6 protocol concepts, server operation, relay, snooping, and
relay route handling. Its IPv6 command lists expose relay and snooping
commands, not a stateful interface client command. References there to a
"client link-layer address" are relay Option 79 behavior for downstream
clients, not the EOS switch acting as a client.

Arista's [DHCPv6 Prefix Delegation TOI listing](https://www.arista.com/en/support/toi/eos-4-29-2f)
describes a relay agent programming routes for IA_PD prefixes or IA_NA /128s
assigned to downstream clients. That feature is not prefix acquisition or
IA_NA address acquisition by Vlan200 itself.

### INFERRED

The combination of the complete installed IPv6 interface parser, the native
client plugin's IPv4-only data path, the absence of a DHCPv6 client CLI/status
surface, and the matching official command manual is sufficient to conclude
that this exact build does not provide the required native stateful DHCPv6
client. This is an inference from exhaustive positive capability surfaces and
the implementation actually installed, not merely from one rejected command.

Pinning Vlan200's MAC would stabilize that interface's link-layer address and
its MAC-derived IPv6 link-local/SLAAC behavior. It cannot make the absent
native client emit a DUID. Therefore no DUID can be mathematically inferred
from the planned cEOS MAC and no cEOS DUID was added to NetBox.

### UNSUPPORTED

For native EOS on this build, all required properties fail closed:

| Requirement | Result | Evidence |
|---|---|---|
| IA_NA / non-temporary address request | No | No native IPv6 client path or `-6` invocation |
| Operate as a client on Vlan200 | No | IPv6 SVI CLI supports static/SLAAC only |
| Install a DHCPv6 lease on Vlan200 | No | Native script/status model consumes IPv4 lease fields only |
| Renew and rebind the IPv6 lease | No | No native IPv6 lease lifecycle exists |
| Emit a stable DUID | No | No native DUID generation/configuration/status surface |
| Deterministic fixed-reservation matching | No | The exact transmitted DUID does not exist |
| Survive restart/redeploy deterministically | No | There is no native identity or state to persist |

### UNVERIFIED

No live DHCPv6 solicitation was permitted or needed, and none was sent. An
Arista support-only/private engineering mechanism not present in the installed
CLI, package integration, or public 4.36.2F manual cannot be ruled out; such a
mechanism would require vendor evidence before it could affect this model.
The verdict is intentionally limited to this exact cEOSLab image and its
normal supported EOS configuration surface.

## DUID, IAID, and persistence result

Because no native client exists, native cEOS DUID type, IAID derivation,
lease renewal state, and persistence location are **not applicable** rather
than merely unknown. The client would transmit no DHCPv6 client identifier in
the required workflow. The seven cEOS NetBox rows must consequently remain:

```text
dhcpv6_identity_status = blocked
dhcpv6_duid            = unset
dhcpv6_iaid            = unset
```

The installed generic ISC binary makes a non-native experiment conceivable:
an operator could supply `-6`, choose DUID-LL with `-D LL`, provide an explicit
DUID file with `-df`, and build a custom IPv6 address-install/lifecycle script.
However, EOS's supplied script is IPv4-only, `/var/lib/dhclient` is not one of
the topology's persistent bind mounts, and using `/mnt/flash` for custom state
would itself be an unsupported design. This was not executed and is classified
as an **unverified Linux-shell workaround**, not supported EOS behavior.

## Deterministic reservation consequence

NetBox can continue to own the predetermined cEOS IPv6 values, but the current
delivery mechanism cannot deliver them dynamically to cEOS. An ISC
`host-identifier option dhcp6.client-id`/`fixed-address6` reservation needs the
actual DUID sent by the client. With no native client and no DUID, generating
such a reservation would fabricate identity and is prohibited. The current
reservation gate therefore remains intentionally unchanged:

```text
DHCPv4, all 9 managed Vlan200 interfaces: READY (9)
DHCPv6, Linux R3/R4:                    READY (2)
DHCPv6, cEOS managed nodes:             BLOCKED (7)
FAIL:                                   0
Overall:                                BLOCKED
```

## Architecture options — user decision required

No architecture-changing option is selected by Phase 3B.2.

| Option | Resulting policy | Complexity | Supportability | Determinism | IaC cleanliness | Risk / design impact |
|---|---|---:|---|---|---|---|
| **A — keep cEOS IPv6 static** | cEOS: DHCPv4 + static IPv6; R3/R4: DHCPv4 + DHCPv6 | Low | High; uses native EOS capabilities | High | High if the mixed policy is explicit in NetBox | Lowest operational risk, but revises the original all-Vlan200 dual-stack-dynamic goal |
| **B — change cEOS software/version/platform** | Use a release/platform only after native IA_NA, SVI, DUID control, and persistence are proven | High | Potentially high, but currently unverified | Potentially high | High if validated and modeled | Topology/platform change; violates the frozen baseline unless separately approved |
| **C — Linux-shell workaround inside cEOS** | Custom `dhclient -6` process, script, state storage, supervision, and rollback | High | Low; not native EOS support | Possible only with explicit persisted DUID/state | Low; duplicates EOS ownership boundaries | High risk of conflicts with Ira/Sysdb and container lifecycle; requires explicit approval and a separate lab proof |
| **D — relay/server/PD/SLAAC features** | No valid substitute discovered | N/A | Native features, wrong function | Does not deliver the fixed IA_NA address required | N/A | Relay/server serve other clients; PD and SLAAC do not satisfy this reservation design |

## What was not changed

Phase 3B.2 did not change NetBox identity data, assignment modes, addresses,
device templates, DHCP templates, `inventory.yml`, `master.py`, the live
topology, an EOS/Linux interface, a MAC, a route, or a service. It did not
start `dhclient`, send a solicitation, restart a container, or redeploy
Containerlab. No new code or tests were warranted because the existing
fail-closed model already represents the proven outcome correctly.

## Gate after Phase 3B.2

Phase 3C must **not** begin under the current all-nine dual-stack conversion
scope. Before reservation generation, the user must explicitly choose an
architecture response to the cEOS limitation and that response must be
represented in NetBox and tested. Independently, R2 still has no implemented
backup DHCP server configuration; that server-side blocker remains untouched
and must be resolved after the cEOS design decision.

**This gate is superseded by Phase 3B.3 below** — the user did not select
one of Options A-D above; instead a higher-level architecture decision
removed the question entirely by keeping Vlan200 static.

---

# Phase 3B.3 — Management VLAN Policy Correction

## Authoritative decision

> **VLAN 200 is the MANAGEMENT VLAN and remains statically addressed
> (IPv4 and IPv6) across all nine managed infrastructure devices.**

This is a user architecture decision, not a modeling refinement. It
supersedes Phase 3B/3B.1's assumption that Vlan200 would eventually become
a DHCP(v4)-reserved / DHCPv6-reserved dynamic-assignment target. Vlan200
must never: use DHCP or DHCPv6, be included in reservation generation,
require a client MAC for lease identity, require a DUID/IAID, or appear as
a DHCP reservation target of any kind.

## Why DHCP on the management VLAN was rejected

Vlan200 is the dedicated out-of-band management network every managed
device's SNMP/syslog/gNMI/NETCONF identity is pinned to
(`inventory.yml`'s `network_devices.*.monitoring.address`, and NetBox's
own `primary_ip4`/`primary_ip6` convention from Phase 2). Making that
address dependent on a DHCP/DHCPv6 lease would couple the one address every
other operational system already treats as a fixed identity to a leasing
protocol with its own failure modes (server availability, lease expiry,
relay-path health) — for zero operational benefit, since the entire point
of a dedicated management VLAN is a stable, protocol-independent way to
reach a device regardless of what else is happening to it. Static
addressing here is the conventional, correct real-world choice; Phase
3B/3B.1's original framing (using Vlan200 as the worked example of a
"device always gets the same IP via a fixed reservation" pattern) picked
the wrong interface to demonstrate that pattern on.

## Which prior assumptions are superseded

| Phase | Original assumption | Status |
|---|---|---|
| 3B Step 3 | Vlan200 -> `dhcp-reserved`/`dhcpv6-reserved`; every other interface category stays `static` | Vlan200 assumption **superseded** (now `static`/`static`); every other category's `static` classification was already correct and is unchanged |
| 3B.1 | Vlan200's MAC should be promoted to `authoritative-planned` and a DUID/IAID plan recorded, as the foundation for a future DHCP/DHCPv6 cutover | **Superseded** — there is no cutover to prepare for; the MAC remains as plain inventory, and no DHCPv6 identity plan is recorded |
| 3B.2 | The cEOS DHCPv6 client-capability gap was a **blocker** that had to be resolved (or an explicit workaround chosen) before any Vlan200 cutover could proceed | **No longer a blocker for the management network** — Vlan200 is not converting to DHCPv6 at all. The investigation's findings (cEOS 4.36.2F has no native DHCPv6 client) remain accurate, useful platform documentation and are **not deleted** — they simply no longer gate anything on the active architecture. A genuinely future, unrelated DHCPv6-client design on some other interface could still consult this evidence. |

Nothing about R1-R4/S1-S4/mgmt_swt's Vlan200 **addresses** changed in this
phase — only the recorded assignment-mode POLICY and stale DHCP-identity
planning metadata. This is a model/metadata correction, not a
renumbering.

## Step 1 — live-state verification (read-only)

Every managed device's Vlan200 was inspected live (EOS `show ip/ipv6
interface brief` for the 7 cEOS devices; `ip -4/-6 addr show dev Vlan200`
for R3/R4) and found already statically configured, with `Addr Source
config` (never `dhcp`/`slaac`), matching NetBox's Phase 2 model exactly —
no drift, no renumbering:

| Device | IPv4 | IPv6 |
|---|---|---|
| R1 | 192.168.200.1/24 | 2001:db8:200::1/64 |
| R2 | 192.168.200.2/24 | 2001:db8:200::2/64 |
| R3 | 192.168.200.3/24 | 2001:db8:200::3/64 |
| R4 | 192.168.200.4/24 | 2001:db8:200::4/64 |
| S1 | 192.168.200.11/24 | 2001:db8:200::11/64 |
| S2 | 192.168.200.12/24 | 2001:db8:200::12/64 |
| S3 | 192.168.200.13/24 | 2001:db8:200::13/64 |
| S4 | 192.168.200.14/24 | 2001:db8:200::14/64 |
| mgmt_swt | 192.168.200.10/24 | 2001:db8:200::10/64 |

## Step 2 — assignment-mode correction

`netbox/scripts/populate_netbox.py`'s `_assignment_mode()` no longer
special-cases any interface name: **every** interface's `ipv4_mode`/
`ipv6_mode` is `static` when it carries an address of that family (and
`none` when it does not, preserving VLAN30's IPv6-only design). No
interface currently maps to `dhcp-reserved`/`dhcpv6-reserved`; those
`ASSIGNMENT_MODES` enum values remain valid in the schema for a genuinely
future dynamic target, but nothing uses them today. This is the existing
population/reconciliation architecture correcting its own prior policy —
no one-off manual API script was introduced.

Applying this required one small, general enhancement to
`modules/netbox_ipam.py`'s shared `reconcile_object()` primitive: a new
`safe_update_custom_fields` parameter lets a caller declare specific
custom-field keys as revisable POLICY it owns outright (e.g.
`ipv4_assignment_mode`), so a deliberate policy change can update an
already-recorded value instead of being reported as an unexplained
`CONFLICT` (the correct, strict default for every other custom field,
which represents identity data a human/other tool might have set out of
band). This is additive and backward-compatible: every existing caller
that does not pass it keeps the original strict conflict behavior.

## Step 3 — reservation targeting

`get_address_reservations()`/`validate_reservations()`
(`modules/ipam_context.py`) already derived every row's mode live from
NetBox rather than hard-coding "Vlan200" — so once Step 2's policy
correction is applied, Vlan200 rows automatically report `ipv4_mode`/
`ipv6_mode = static` and are **structurally** excluded from every
MAC/DUID/IAID readiness check (those only ever run when
`mode == "dhcp-reserved"`/`"dhcpv6-reserved"`) and from the readiness list
entirely. No interface-name-based exclusion logic was added anywhere —
the correction is a pure consequence of the corrected policy data, so it
holds automatically for any interface whose mode is/becomes static, and
would immediately (and correctly) re-include a genuinely future dynamic
target without further code changes.

## Step 4 — obsolete DHCP identity metadata cleanup

Two new, narrowly-scoped, self-guarding functions in
`modules/netbox_ipam.py` — driven entirely by each interface's *current*
assignment-mode policy, never by interface name:

* `clear_stale_mac_identity_status(device, interface)` — if the
  interface's `ipv4_mode` is not `dhcp-reserved`, clears any
  `identity_status` (e.g. a stale `authoritative-planned`) previously
  recorded on its MAC. **The MAC address itself is preserved** — a MAC is
  legitimate native inventory data (NetBox's own `dcim.MACAddress`
  object) regardless of what, if anything, it is used for.
* `clear_stale_dhcpv6_identity(device, interface)` — if the interface's
  `ipv6_mode` is not `dhcpv6-reserved`, clears `dhcpv6_duid`/
  `dhcpv6_iaid`/`dhcpv6_identity_status` back to unset.

Both are no-ops (return `None`) when the interface is still a genuine
dynamic target, or when nothing is recorded to clear — so they are safe to
call unconditionally for every interface on every reconciliation run
(`netbox/scripts/populate_netbox.py`'s `_populate_interfaces` now does
so), rather than being special-cased to "just Vlan200".

**Applied live, once, via `populate_netbox.py --apply`:**

```text
9x  interface              ipv4_assignment_mode, ipv6_assignment_mode -> static/static
9x  mac_identity_cleanup   identity_status -> cleared (MAC address value unchanged)
9x  dhcpv6_identity_cleanup  dhcpv6_duid, dhcpv6_iaid, dhcpv6_identity_status -> cleared
```

Rerunning `--apply` immediately afterward reported `UNCHANGED=311` with
zero `CREATE`/`UPDATE`/`CONFLICT` — idempotent, as required.

**What was kept vs. cleared, and why:**

| Field | Kept / Cleared | Reason |
|---|---|---|
| MAC address value (`dcim.MACAddress.mac_address`) | **Kept** | Legitimate native inventory data (Step 6's finding that it is not currently redeploy-stable is unrelated to whether it is worth recording) |
| MAC `identity_status` | **Cleared** | Existed *exclusively* to represent "is this MAC the deliberate, durable, to-be-pinned-at-DHCP-cutover value" (see its own NetBox field description) — a claim with no meaning once there is no such cutover planned |
| Interface `dhcpv6_duid` / `dhcpv6_iaid` | **Cleared** | Computed *exclusively* for the abandoned DHCPv6-reservation design (R3/R4's deterministic DUID-LL); has no other purpose |
| Interface `dhcpv6_identity_status` | **Cleared** | Same reasoning — `blocked`/`authoritative-planned` both asserted a DHCPv6-cutover-readiness state that no longer applies |
| `ipv4_assignment_mode` / `ipv6_assignment_mode` | **Corrected, not removed** | Still meaningful, forward-looking POLICY fields — now correctly say `static` |

## Step 5 — `pin_stable_identities.py`

Chosen outcome: **refactor (Option B)**, not retire/delete. The script's
root defect was hard-coding `MANAGEMENT_INTERFACE = "Vlan200"` as *the*
dynamic-assignment target on every managed device. It now has a
`discover_dynamic_targets(client)` function that queries NetBox's own
`ipv4_assignment_mode`/`ipv6_assignment_mode` policy across every managed
interface and operates only on whatever it finds — never a hard-coded
name. Run against the corrected live model:

```text
$ python3 netbox/scripts/pin_stable_identities.py --check
No managed interface is currently classified dhcp-reserved/dhcpv6-reserved.
Nothing to pin -- this is the expected result of the corrected static-management-VLAN
architecture (Vlan200 stays static; see docs/NETBOX_IPAM.md 'Phase 3B.3'). This script
remains ready to pin a genuinely future dynamic-assignment target without modification.
```

Exit code `0`. The script cannot accidentally repopulate the abandoned
Vlan200 design (there is nothing in the corrected model for it to find),
and it requires no further changes if a genuinely different interface is
ever deliberately made dynamic in the future — the fix addressed the root
cause, not just today's symptom.

## Step 6 — actual DHCP/DHCPv6 client scope (verified, not assumed)

Verified against `inventory.yml`, `hostserv.py`, the live topology file,
and live `docker exec` inspection of each host's `eth1` (read-only):

| Host | Attached switch | VLAN | IPv4 subnet | IPv6 prefix | IPv4 mode | IPv6 mode | Relay path (primary / backup) | Observed live address |
|---|---|---|---|---|---|---|---|---|
| H1 | S1 (`eth3`) | 10 | 192.168.10.0/24 | 2001:db8:10::/64 | dynamic pool | dynamic pool | S1 Vlan10 `ip helper-address`/`ipv6 dhcp relay destination` -> 192.168.200.100 / .2, 2001:db8:200::100 / ::2 | 192.168.10.102/24, 2001:db8:10::1c37 |
| H2 | S1 (`eth4`) | 20 | 192.168.20.0/24 | 2001:db8:20::/64 | dynamic pool | dynamic pool | S1 Vlan20, same primary/backup targets | 192.168.20.101/24, 2001:db8:20::1518 |
| H3 | S2 (`eth3`) | 10 | 192.168.10.0/24 | 2001:db8:10::/64 | dynamic pool | dynamic pool | S2 Vlan10, same primary/backup targets | 192.168.10.103/24, 2001:db8:10::198b |
| H4 | S2 (`eth4`) | 30 | *(none -- IPv6-only)* | 2001:db8:30::/64 | `none` (no IPv4 anywhere by design) | dynamic pool | S2 Vlan30, same primary/backup targets | *(no IPv4)*, 2001:db8:30::16d4 |

This **confirms**, rather than assumes, the documented intent: H1/H2/H3
are dual-stack DHCP/DHCPv6 clients (`inventory.yml` `hosts:` block:
`ipv4: true, ipv6: true`), H4 is IPv6-only (`ipv4: false, ipv6: true`),
and `hostserv.py`'s `configure_host()` runs plain `dhclient -4`/`dhclient
-6` for each — no fixed-address/host-identifier configuration exists
anywhere in the client-provisioning path. Primary server = NMAS
(192.168.200.100 / 2001:db8:200::100, `dhcp/dhcpd.conf.j2`/`dhcpd6.conf.j2`);
documented secondary/backup = R2 (192.168.200.2 / 2001:db8:200::2) — see
Step 8 below for its actual (missing) server-side implementation.

## Step 7 — dynamic pool vs. fixed reservation for H1-H4: not ambiguous

`dhcp/dhcpd.conf.j2`/`dhcpd6.conf.j2` define H1-H4's VLANs with plain
`range`/`range6` pool statements only — no `host { hardware ethernet ...;
fixed-address ...; }` block exists anywhere in either file, and no
project document (`README.md`, `LAB_REQUIREMENTS.md`,
`IMPLEMENTATION_PLAN.md`, `GAP_ANALYSIS.md`) asks for deterministic H1-H4
addressing. The live observed addresses above (`.101`-`.103`, mid-range
pool offsets) are consistent with ordinary dynamic allocation, not a
fixed mapping. **Conclusion: H1-H4 are, and should remain, ordinary
dynamic-pool DHCP/DHCPv6 clients.** This phase's user clarification
("Vlan200 stays static") does not itself imply anything about H1-H4, and
no ambiguity was found requiring escalation — this is a verified reading
of the existing design, not a new decision.

## Step 8 — DHCP pool re-baseline (VLAN10/20/30)

| VLAN | IPv4 prefix | IPv6 prefix | DHCPv4 pool (primary/NMAS) | DHCPv6 pool (primary/NMAS) | Relay targets | Client population |
|---|---|---|---|---|---|---|
| 10 | 192.168.10.0/24 | 2001:db8:10::/64 | 192.168.10.100-179 | 2001:db8:10::1000-1fff | 192.168.200.100, .2 / ::100, ::2 | H1 (via S1), H3 (via S2) |
| 20 | 192.168.20.0/24 | 2001:db8:20::/64 | 192.168.20.100-179 | 2001:db8:20::1000-1fff | 192.168.200.100, .2 / ::100, ::2 | H2 (via S1) |
| 30 | *(none -- IPv6-only, confirmed)* | 2001:db8:30::/64 | *(none)* | 2001:db8:30::1000-1fff | 192.168.200.100, .2 / ::100, ::2 | H4 (via S2) |

**VLAN30's IPv6-only design is preserved** — verified directly in
`dhcp/dhcpd.conf.j2` (no `subnet 192.168.30.0` block exists) and in
NetBox (no IPv4 prefix/range on VLAN30's manifest entry or live object).
No IPv4 VLAN30 pool/address was created anywhere in this phase.

## Step 9 — R2 backup DHCP: re-evaluated status (not implemented)

| Question | Finding |
|---|---|
| What networks is R2 supposed to back up? | VLAN10/20 (v4 + v6) and VLAN30 (v6 only) per `README.md`'s documented pool ranges (`192.168.10/20.200-220`, `2001:db8:10/20/30::2000-20ff`) |
| What server-side config currently exists on R2? | **None** — `templates/R2.cfg.j2` has zero DHCP-related lines (verified: no `dhcp`, `ip dhcp`, or pool/server configuration of any kind) |
| What is missing? | The entire EOS-native DHCP server configuration on R2 (pools, subnet declarations, and binding to Vlan10/20/30) |
| DHCPv4, DHCPv6, or both? | **Both** — README documents backup pools for all three VLANs' relevant families, none of which exist in the template |
| Does Phase 3B.3 change this? | No — this is a pre-existing gap, independent of the Vlan200 correction, and is **not implemented here** per this phase's explicit scope (model correction + scope discovery only) |

This remains the most likely candidate for the next implementation phase
(see "Next Recommended Phase" in the final response), but no server
configuration was fabricated or added to `templates/R2.cfg.j2` in this
phase.

## Step 10 — validation semantics after correction

`verify_reservations.py` against the live, corrected NetBox model:

```text
Rows checked: 35. Reservation targets checked: 0.
Reservation readiness: READY=0 BLOCKED=0 FAIL=0
Validation issues: BLOCKED=0 FAIL=0
Overall: READY
```

Zero reservation targets is the **correct** result of the corrected
architecture (no managed interface is currently dynamic), not a gap —
nothing was manufactured to keep the verifier "interesting" (Step 10's
own instruction). The previous `READY=11, BLOCKED=7` result belonged
entirely to the superseded Phase 3B.1 architecture and no longer applies.

## Step 11 — tests

25 new/changed tests were added across `monitoring/tests/test_netbox_ipam.py`,
`monitoring/tests/test_ipam_context.py`, and `monitoring/tests/test_populate_netbox.py`,
covering: `reconcile_object()`'s new `safe_update_custom_fields` opt-in
(differing value updates when declared safe, conflicts otherwise, clearing
an already-unset field is a no-op, idempotent rerun); `clear_stale_mac_identity_status()`/
`clear_stale_dhcpv6_identity()` (no-op while still dynamic, clears when
static, MAC address preserved, idempotent); the corrected `_assignment_mode()`
policy (Vlan200 -> `static`, no interface classified dynamic); all nine
managed devices' real manifest Vlan200 entries confirmed dual-stack static
end-to-end; a row carrying a leftover `blocked` DHCPv6 status no longer
produces a `BLOCKED` reservation once its mode is `static`; R3/R4 Vlan200
specifically no longer `dhcpv6-reserved`; `pin_stable_identities.py`'s
mode-driven discovery (finds a hypothetical non-Vlan200 dynamic interface,
correctly ignores a static interface literally named Vlan200, empty-target
`main()` exits 0). Previously-passing coverage for loopbacks/transit
links/S1-S2 client SVIs remaining static, VLAN30 IPv6-only, and R5/WebServer
unmanaged status required no changes (already correct and unaffected by
this correction).

```text
Previous: 297
New:      25
Total:    322
PASS/FAIL: 322/322 PASS
```

## Step 12/13 — reconciliation and validation, applied live

```text
$ python3 netbox/scripts/populate_netbox.py --apply --verbose
...
Summary: UNCHANGED=284, UPDATE=27      # 9 interfaces + 9 MAC cleanups + 9 DHCPv6 cleanups

$ python3 netbox/scripts/populate_netbox.py --apply --verbose   # rerun
Summary: UNCHANGED=311                  # zero CREATE/UPDATE/CONFLICT -- idempotent

$ python3 -m modules.netbox_ipam
Overall: PASS

$ python3 netbox/scripts/verify_netbox_model.py
387/387 checks passed.
```

No IP address changed anywhere in this phase (confirmed via
`verify_netbox_model.py`'s 387/387 and a live `show ip/ipv6 interface
brief` cross-check — see Step 1 above).

## Gate before Phase 3C (updated)

Phase 3C (generating actual fixed reservations) remains **not started**,
and now has a clearer, smaller scope than Phase 3B.1 envisioned: since
Vlan200 is static, Phase 3C -- if ever pursued for Vlan200-style fixed
reservations -- would only be relevant if a *different*, genuinely
dynamic infrastructure target is identified in the future. The immediate
next candidate for implementation work is Step 9's R2 backup-DHCP-server
gap (an H1-H4 client-facing concern, unrelated to Vlan200), not a
management-VLAN DHCP cutover.

**Naming note:** the "Phase 3C" label below is reused for that R2
backup-DHCP-server work (an H1-H4-client-facing, pool-boundary-modeling
phase) -- it is NOT the fixed-reservation-generation phase floated above,
which never became necessary once Vlan200 stayed static and remains
unstarted/unscoped.

---

# Phase 3C — R2 Secondary DHCP Server Modeling and IaC

Phase 3C closes the Phase 2/3B.1/3B.2 "known gap": `templates/R2.cfg.j2`
has always had zero native DHCP server configuration despite README.md
documenting R2 as the secondary EOS DHCP server with non-overlapping
pools, and S1/S2 already relaying toward it
(`management.backup_dhcp_ipv4/6` = `192.168.200.2` / `2001:db8:200::2`).
This phase models R2's secondary pools in NetBox, proves the exact native
EOS capability that would serve them, and produces a genuine,
NetBox-derived candidate configuration -- **without activating anything
live.** `templates/R2.cfg.j2`, `master.py`, and every live device are
unmodified by this phase.

```text
NetBox ipam.IPRange (primary + secondary, both tagged)
        |
        v
modules/netbox_ipam.get_dhcp_ranges(server=...)      <- normalized read (Step 5)
        |
        v
modules/ipam_context.get_dhcp_pool_context() /
        get_r2_dhcp_context() / validate_dhcp_pool_safety()   <- normalized
        |                                                          context +
        |                                                          fail-closed
        |                                                          safety (Step 4/6)
        v
templates/R2_dhcp_server.cfg.j2      <- Jinja, NO literal pool boundaries
        |
        v
netbox/scripts/render_r2_dhcp.py     <- render-only CLI (Step 10): never
                                         connects to R2, never pushes
```

## Step 1 — R2/cEOS DHCP server capability: PROVEN, both families

```text
DHCPv4 SERVER:            SUPPORTED
DHCPv6 STATEFUL SERVER:   SUPPORTED
```

This is the OPPOSITE finding from Phase 3B.2's cEOS DHCPv6 CLIENT
investigation (which found no native client capability on this exact
image) -- server and client are entirely different feature sets, and
must never be conflated. All evidence below is read-only: package/file
inspection and `show` EXEC commands only; no configuration mode was
entered merely to probe syntax, and no test configuration was applied,
per this phase's explicit instruction.

**Installed-image evidence (PROVEN):**

| Evidence | Finding |
|---|---|
| RPM packages | `DhcpServer-cli`, `DhcpServer-lib`, `DhcpServer-toggles` installed (distinct from `DhcpClient-*`, which Phase 3B.2 found has NO `-cli` package at all) |
| Binaries | `/usr/sbin/kea-dhcp4`, `/usr/sbin/kea-dhcp6` installed -- Arista's native DHCP server is Kea-backed, for BOTH families |
| systemd units | `kea-dhcp4.service`, `kea-dhcp6.service` present (`disabled`/`inactive` -- installed and available, simply not turned on) |
| CLI grammar | `CliPlugin/DhcpServerCli.py` (1789 lines) registers a full `dhcp server` config-mode grammar for both `subnet (SUBNET \| SUBNET6)` address families -- see the exact syntax table below |
| Live EXEC probe | `show dhcp server` returns real structured output for BOTH families (not `% Invalid input`): `IPv4 DHCP server is inactive` / `IPv6 DHCP server is inactive`, each with its own lease-count and per-interface status section |
| Relay-awareness | `EosDhcpServerLib.py` implements DHCPv4 Option 82 (`relay-agent-info`) and DHCPv6 relay remote-id (`relay6[-1].option[37]`) matching -- concrete evidence the native server processes genuinely RELAYED packets, not only directly-attached clients |

**Official documentation (PROVEN, via live web fetch of the exact
4.36.2F manual, `eos-configuring-dhcp`):** confirms the `dhcp server` /
`subnet` / `range` / `default-gateway` / `lease time` command shapes
transcribed below, and that DHCP is configurable on Routed/VLAN/LAG/
sub-interface interfaces.

**What was NOT proven (disclosed, not guessed):** neither the installed
source nor the official manual states whether the per-interface
`dhcp server (ipv4|ipv6)` enable command is *required* for the server to
answer requests **relayed** onto a different local interface (Kea's own
`subnet4`/`subnet6` definitions ordinarily select by relay giaddr/
link-address regardless of listening-interface configuration; Arista's
CLI wrapper toggles a VRF-scoped `interfacesIpv4`/`interfacesIpv6` list
that most plausibly controls which interfaces Kea binds a listening
socket to -- which, by ordinary Kea operational practice, does need to
include the interface actually receiving the relayed packets). This
phase places the enable command on Vlan200 (the only interface in R2's
relay path at all) as the best-evidence choice, and lists confirming it
as an explicit activation prerequisite (Step 15 below) -- it is not
assumed correct.

## Step 2 — exact EOS DHCP server configuration model (read-only, transcribed)

Verified directly from the installed `CliPlugin/DhcpServerCli.py`/
`DhcpServerCliSubmodeLib.py` syntax classes on the live image:

```text
dhcp server [ VRFNAME ]
   lease time ( ipv4 | ipv6 ) DAYS days HOURS hours MINUTES minutes
   dns domain name ( ipv4 | ipv6 ) NAME
   dns server ( ipv4 { SERVERS } ) | ( ipv6 { SERVERS6 } )
   subnet ( SUBNET | SUBNET6 )
      id ID
      name NAME
      default-gateway IP_ADDR          ! IPv4 subnets ONLY -- no IPv6
                                        ! equivalent exists (confirmed: no
                                        ! V6DefaultGateway class registered
                                        ! anywhere in the grammar); IPv6
                                        ! clients get their router via
                                        ! RA/SLAAC, matching how this lab's
                                        ! own S1/S2 templates already work
      lease time ( ipv4 | ipv6 ) ...   ! per-subnet override
      range START END                 ! ENTERS a further sub-mode
                                        ! (EnterDhcpServerV4RangeMode /
                                        ! V6RangeMode -- confirmed by which
                                        ! class DhcpServerSubnetV4Mode/V6Mode
                                        ! actually .addCommandClass()-
                                        ! registers; NOT the same as the
                                        ! unregistered "leaf" Range classes
                                        ! also present in the source)
      reservations                     ! fixed MAC/IP bindings -- NOT used
                                        ! here (H1-H4 stay dynamic-pool)
interface INTF
   dhcp server ( ipv4 | ipv6 )        ! per-interface enable
```

VRF scoping exists (`dhcp server [VRFNAME]`) but is not used here (R2 has
no VRF in this lab's design).

## Step 3 — secondary ranges modeled in NetBox

`netbox/ipam.yml`'s `dhcp_ranges:` now carries an explicit `server: nmas`/
`server: r2` key on every entry (retrofitted onto the 5 existing primary
ranges, added to 5 new secondary ones), reconciled by
`netbox/scripts/populate_netbox.py` into a `dhcp-primary`/`dhcp-secondary`
NetBox tag on each `ipam.IPRange` object (native `ipam.Role` was
considered and rejected -- it already carries network-function semantics
Loopback/Management/Client/Transit/External shared with prefixes, and
overloading it with "which server" would blur that; tags are this
repository's existing, established mechanism for exactly this kind of
orthogonal classification). `modules/netbox_ipam.get_dhcp_ranges()`
gained a `server` field (derived from those tags, `None`/never fabricated
for an untagged legacy range) and an optional `server="primary"|
"secondary"` filter.

## Step 4 — pool safety validation

`modules/ipam_context.validate_dhcp_pool_safety()` (fail-closed, reports
every problem rather than stopping at the first, mirroring
`validate_reservations()`'s convention):

| Check | Result on the real matrix |
|---|---|
| No primary/secondary overlap, per VLAN/family | PASS -- `.100-.179` vs `.200-.220` (v4), `::1000-1fff` vs `::2000-20ff` (v6), non-overlapping by construction |
| Every pool inside its own prefix | PASS -- all 10 pools (5 primary + 5 secondary) verified inside their VLAN's NetBox-modeled prefix |
| No pool contains a shared gateway | PASS -- gateways (`.1` per VLAN) are read live via `get_shared_gateway()`, never inside any `.100+`/`.200+` range |
| No pool contains an S1/S2 infrastructure SVI address | PASS -- S1/S2's own Vlan10/20/30 addresses (`.2`/`.3`) read live via `get_interface_address()`, outside every pool |
| VLAN30 stays IPv6-only | PASS -- enforced structurally in `get_r2_dhcp_context()` (raises `NetboxModelError` if a VLAN30 IPv4 secondary pool ever appears) AND in `validate_dhcp_pool_safety()` (flags any VLAN30/family=4 pool directly) |

Live run: `netbox/scripts/render_r2_dhcp.py` reported
`Pool safety: PASS (10 pools checked -- primary + secondary, all
VLANs/families)`.

## Step 5 — normalized read API additions

`modules/netbox_ipam.py`:

* `get_dhcp_ranges(vid=None, server=None, client=None)` -- extended
  (Step 3 above): `server` field + optional filter.

`modules/ipam_context.py` (new, Phase 3C):

* `DhcpPool` -- one normalized pool boundary (vlan, family, server,
  prefix, start, end, gateway, relay_targets, description).
* `get_dhcp_pool_context()` -- every pool (primary AND secondary, all
  three client VLANs, both families that exist) as a flat list; the one
  read path everything else builds from.
* `get_r2_dhcp_context()` -- exactly the `server="secondary"` pools,
  grouped `ipv4_subnets`/`ipv6_subnets`, fail-closed on a missing or
  unexpected (e.g. stale VLAN30 IPv4) pool.
* `validate_dhcp_pool_safety(pools, infrastructure_addresses=...)` --
  Step 4's checks.

No second, parallel hard-coded pool dictionary exists anywhere in either
module or in the render script -- every boundary value is read live from
NetBox on every invocation.

## Step 6/7 — R2 rendering architecture

```text
NetBox ipam.IPRange (server=r2)
        |
modules.netbox_ipam.get_dhcp_ranges(server="secondary")
        |
modules.ipam_context.get_r2_dhcp_context()      <- {ipv4_subnets, ipv6_subnets}
        |
templates/R2_dhcp_server.cfg.j2                  <- Jinja loop, zero literals
        |
netbox/scripts/render_r2_dhcp.py                 <- render + validate + print
```

**Why a separate template file, not `templates/R2.cfg.j2` itself:**
`master.py`'s `push_eos()` renders `templates/{meta['template']}` with
only `{"management": ..., "node": ...}` as context, with `StrictUndefined`
-- adding new Jinja variables directly into `templates/R2.cfg.j2` would
make `master.py`'s next real run of R2 raise immediately (an undefined
`dhcp` variable), a live regression this phase's own Step 8/15 explicitly
forbids introducing. `templates/R2_dhcp_server.cfg.j2` is a standalone
fragment, rendered only by `netbox/scripts/render_r2_dhcp.py`, so the
already-working device-provisioning path carries zero risk from this
phase (confirmed: `templates/R2.cfg.j2` is git-diff-empty).

**Shared rendering helper (`modules/eos_render.py`, new):**
`master.py`'s `render()`/`eos_commands()` were extracted verbatim into
this small, dependency-light module (no netmiko/paramiko/monitoring
imports) so `render_r2_dhcp.py` can reuse the exact same
indentation-to-EOS-command flattening `master.py`'s real push path uses,
without importing `master.py` itself (which unconditionally imports the
entire monitoring stack at module load). `master.py` now imports from
`modules.eos_render` instead of defining these functions locally --
confirmed byte-identical output for all 9 managed EOS device templates
(`monitoring/tests/test_eos_render.py`).

`MODE_STARTS` (the indentation-nesting keyword table) gained `"dhcp
server"`, `"subnet "`, and `"range "` -- each verified against the live
CLI grammar (Step 2) to genuinely open an EOS config sub-mode. Two real
structural bugs were caught and fixed by this phase's own test suite
before any candidate was considered valid:

1. `range START END` was initially left OUT of `MODE_STARTS` -- since it
   actually enters a further sub-mode on the real device (Step 2), a
   subnet's trailing `name`/`default-gateway` command would have been
   sent while the CLI was still inside the wrong (range) sub-mode.
2. `"dhcp server"` as a bare prefix falsely matched the UNRELATED
   interface-level leaf commands `dhcp server ipv4`/`dhcp server ipv6`
   (`InterfaceEnterDhcpServerEnable`), causing a phantom extra nested
   mode. Fixed with an explicit exact-match exclusion
   (`_DHCP_SERVER_INTERFACE_LEAVES`) rather than a longer, still-ambiguous
   prefix (the real global command also legitimately takes an optional
   VRF name).

Neither bug could have been caught without actually flattening a
candidate and inspecting its structure -- exactly what Step 10/11's
render-only path and structural validation exist to do before any human
or automation ever pushes this configuration.

## Step 8 — primary NMAS server: unaffected, migration gap documented

`dhcp/dhcpd.conf.j2`, `dhcp/dhcpd6.conf.j2`, and `master.py`'s
`setup_nmas()` are byte-for-byte unmodified (confirmed via `git diff`).
Per Step 9's explicit fallback option (rather than forcing a
larger, riskier template-to-Jinja-variables conversion of the
already-working NMAS path): **both primary and secondary pool boundaries
are now modeled in NetBox, but only the new R2 render path actually
consumes NetBox.** NMAS's own rendering remains literal-text-driven from
`dhcp/dhcpd.conf.j2` directly, exactly as before Phase 2. This is a
consciously deferred, explicitly documented migration step -- not an
oversight: converting `dhcp/dhcpd.conf.j2`/`setup_nmas()` to read from
`modules/ipam_context.get_dhcp_pool_context()` would be a legitimate
follow-on phase, gated on the same "prove nothing regresses" discipline
this phase applied to R2.

## Step 9 — R2 pool matrices

**Primary (NMAS, unchanged from Phase 2):**

| VLAN | IPv4 range | IPv6 range |
|---|---|---|
| 10 | 192.168.10.100-179 | 2001:db8:10::1000-1fff |
| 20 | 192.168.20.100-179 | 2001:db8:20::1000-1fff |
| 30 | *(none -- IPv6-only)* | 2001:db8:30::1000-1fff |

**Secondary (R2, new this phase):**

| VLAN | IPv4 range | IPv6 range |
|---|---|---|
| 10 | 192.168.10.200-220 | 2001:db8:10::2000-20ff |
| 20 | 192.168.20.200-220 | 2001:db8:20::2000-20ff |
| 30 | *(none -- IPv6-only, enforced)* | 2001:db8:30::2000-20ff |

## Step 10 — render-only validation path

```bash
/home/student/Scripts/.venv/bin/python netbox/scripts/render_r2_dhcp.py -v [--write]
```

Reads NetBox -> builds context -> validates pool safety -> renders ->
validates EOS command structure -> prints (optionally writes under the
already-git-ignored `netbox/runtime/`) -- **never connects to R2 or any
device, never pushes, never restarts anything.** Exit codes: `0` full
pass, `1` NetBox not ready, `2` pool safety failure, `3` structural
validation failure. `monitoring/tests/test_render_r2_dhcp.py` includes an
explicit structural guarantee test that the script's own source contains
no netmiko/paramiko/SSH import at all.

## Step 11 — configuration validation ("as far as safely possible")

No offline EOS parser is safely obtainable without entering live
configuration mode (explicitly out of scope per Step 1), so this phase
implements the honestly-scoped alternative: a small, explicit
nested-command grammar (`_ALLOWED_CHILDREN` in `render_r2_dhcp.py`)
transcribed read-only from the exact installed CLI source (Step 2),
covering only the commands this template emits. It caught both real bugs
listed in Step 6/7 above during development. Beyond that: unrendered-Jinja
detection, and exact-match verification that every expected subnet/range
appears (no more, no fewer) in the flattened output.

## Step 12 — tests

5 new tests (`test_eos_render.py`) + 4 (`test_netbox_ipam.py`
`DhcpMetadataTests` additions) + 17 (`test_ipam_context.py`
`GetDhcpPoolContextTests`/`GetR2DhcpContextTests`/
`ValidateDhcpPoolSafetyTests`) + 8 (`test_populate_netbox.py`
`RealManifestContentTests` additions) + 16 (`test_render_r2_dhcp.py`),
covering: five primary ranges remain exact; five secondary ranges exist;
primary/secondary never overlap; every range belongs to its correct
prefix; VLAN10/20 have v4+v6 primary+secondary; VLAN30 has v6-only
primary+secondary and a synthetic VLAN30 IPv4 pool is rejected by both
`get_r2_dhcp_context()` and `validate_dhcp_pool_safety()`; gateway and
S1/S2 infrastructure addresses cannot fall inside a pool;
`get_r2_dhcp_context()` contains exactly five pools; the renderer visibly
consumes NetBox-sourced context (changes when the context changes) and
contains zero literal pool-boundary text in its own source; H1-H4 remain
ordinary dynamic clients (no reservation-shaped manifest fields);
Vlan200 remains untouched (no code in this phase reads or writes Vlan200
assignment data at all); and every pre-existing managed EOS template
still renders/flattens identically after the `eos_render.py` extraction.

```text
Previous: 322
New:      50
Total:    372
PASS/FAIL: 372/372 PASS
```

## Step 13 — NetBox reconciliation and validation, applied live

```text
$ python3 netbox/scripts/populate_netbox.py --apply --verbose
...
Summary: CREATE=7, UPDATE=5, UNCHANGED=306   # 2 tags + 5 secondary ranges
                                              # created; 5 primary ranges
                                              # gained the new tag

$ python3 netbox/scripts/populate_netbox.py --apply   # rerun
Summary: UNCHANGED=318                        # zero CREATE/UPDATE/CONFLICT

$ python3 -m modules.netbox_ipam
Overall: PASS

$ python3 netbox/scripts/verify_netbox_model.py
392/392 checks passed.    # 387 (Phase 3B.3 baseline) + 5 new DHCP-range
                           # presence checks (one per new secondary range)
                           # -- a legitimate increase, not a weakened count
```

No IP address, prefix, VLAN, or device object was renumbered or removed.

## Step 14 — activation status: NOT performed

Per this phase's explicit instruction, none of the following occurred:
R2 DHCP configuration was not pushed; R2 was not restarted or reloaded;
NMAS's DHCP service was not stopped or restarted; no H1-H4 client was
forced to renew or release a lease; no relay configuration was touched;
no client interface was touched. `templates/R2.cfg.j2` and every live
device remain exactly as they were before this phase.

## Step 15 — remaining work before activation (explicit prerequisites)

1. **Confirm the Vlan200 `dhcp server ipv4`/`ipv6` interface-enable
   placement** (Step 1's disclosed open question) against the live R2
   image, in a controlled test window -- this is the single most
   important unverified assumption in the candidate.
2. Decide how `templates/R2_dhcp_server.cfg.j2`'s content is merged into
   `templates/R2.cfg.j2` (the `interface Vlan200` stanza already exists
   there; the two `dhcp server ipv4`/`ipv6` lines would be added to it,
   not duplicated as a second `interface Vlan200` block) and extend
   `master.py`'s `push_eos()` render context for R2 to supply the `dhcp`
   key (currently only R2 needs it; other devices are unaffected).
3. Verify EOS actually accepts the full candidate via a controlled
   `configure session`/`show session-config diffs` dry-run (never a bare
   apply) before a real `send_config_set`.
4. Perform staged relay/lease acquisition testing (H1-H4 obtaining a
   lease from R2 specifically, e.g. by temporarily disabling the NMAS
   relay target) without renumbering or disrupting the primary path.
5. Decide and implement the still-open NMAS-side migration gap (Step 8):
   whether `dhcp/dhcpd.conf.j2`/`dhcpd6.conf.j2` should also become
   NetBox-context-driven, as a separate, independently-reviewed change.

None of the above was performed in Phase 3C. **Item 1 (the interface-enable
placement) and item 2 (the template merge) are now resolved -- see Phase
3D below.** Items 3-5 remain open.

---

# Phase 3D — R2 DHCP Integration and Configuration-Session Dry Run

Phase 3D resolves Phase 3C's one remaining open question, merges the
standalone DHCP candidate into the REAL R2 push path (so there is exactly
one authoritative desired R2 configuration), and proves the complete,
integrated candidate against the live R2 image using EOS's own
configuration-session mechanism -- **never committed.** No live
configuration changed as a result of this phase.

## Step 1 — interface-enable resolution: RESOLVED

```text
Is `dhcp server ipv4/ipv6` required?   YES
Where must it be configured?           interface Vlan200
Why?                                   Kea (EOS's native DHCP server
                                        backend) only listens on
                                        interfaces named in its
                                        `interfaces-config.interfaces`
                                        list; Vlan200 is R2's only
                                        interface in the S1/S2 relay
                                        path, so it must be in that list
                                        for R2 to receive relayed
                                        packets at all.
```

**Evidence, in the order Step 1 requires:**

1. **Installed CLI grammar (already known from Phase 3C):**
   `InterfaceEnterDhcpServerEnable` (`CliPlugin/DhcpServerCli.py`) registers
   `dhcp server (ipv4|ipv6)` as an interface-mode command whose handler
   writes to a VRF-scoped `interfacesIpv4`/`interfacesIpv6` interface-name
   set (`DhcpServerCliHandler.setInterfaceEnterDhcpServerEnable`).
2. **Installed server/Sysdb implementation (NEW evidence this phase):** the
   image's own bundled Kea DHCPv4 default configuration
   (`/etc/kea/kea-dhcp4.conf`, ISC's stock example, unmodified) states, in
   its own comments, immediately above `"interfaces-config": {"interfaces":
   []}`:
   > *"Subnet declarations are mostly commented out and no interfaces are
   > listed. Therefore, the servers will not listen or respond to any
   > queries."*

   This is authoritative, vendor-bundled Kea documentation (not an
   Arista-specific behavior, not inferred) confirming Kea's `interfaces`
   list gates ALL packet reception -- relayed or not. `interfacesIpv4`/
   `interfacesIpv6` (Evidence 1) is EOS's own config-management path INTO
   that same Kea `interfaces-config.interfaces` list (`DhcpServerReactor.py`'s
   `@Tac.handler('interfacesIpv4')`/`'interfacesIpv6'` -> `vrfManager_.
   handleIntfChange()`). Vlan200 is the only interface anywhere in R2's
   relay-receiving path (Ethernet3 carries VLAN200 access traffic into it;
   R2 has no other interface reachable from S1/S2's relay targets
   `192.168.200.2`/`2001:db8:200::2`), so it is the correct, and only
   possible, placement.
3. **Official documentation:** the live-fetched EOS 4.36.2F "Configuring
   DHCP" manual confirms the `interface INTF / dhcp server (ipv4|ipv6)`
   syntax and that DHCP is configurable on VLAN interfaces, but (as
   already disclosed in Phase 3C) does not itself state the
   relay-vs-interface-enable interaction -- Evidence 2 above closes that
   gap authoritatively.
4. **Safe candidate-session parser validation (live proof, this phase):**
   see Step 6/8 below -- the full candidate, including
   `interface Vlan200 / dhcp server ipv4/ipv6`, was loaded into a live,
   never-committed EOS configuration session with **zero parser errors**.

```text
Does enabling it affect Vlan200 addressing?     NO -- confirmed both by
                                                 source (the handler only
                                                 touches interfacesIpv4/6,
                                                 never ip/ipv6 address) and
                                                 by the live session diff
                                                 (Vlan200's ip
                                                 address/ipv6 address
                                                 lines do not appear in the
                                                 diff at all -- EOS
                                                 recognizes them as
                                                 unchanged).
Does it only enable DHCP service reception?     YES -- the command's own
                                                 CLI help text says exactly
                                                 this ("Enable IPv4/IPv6
                                                 DHCP server"); it is a
                                                 pure listen/enable toggle.
Is separate ipv4 + ipv6 enablement required?    YES -- `(ipv4|ipv6)` is an
                                                 alternation, each family
                                                 toggled independently;
                                                 the candidate emits both
                                                 lines.
```

## Step 2 — relay path verified live (read-only, zero changes)

```text
$ show running-config interfaces Vlan10   (on S1 and S2)
   ip helper-address 192.168.200.2
   ip helper-address 192.168.200.100
   ipv6 dhcp relay destination 2001:db8:200::2
   ipv6 dhcp relay destination 2001:db8:200::100
```

Confirmed on both S1 and S2 (VLAN10 shown; VLAN20/30 configured
identically). R2's routing toward the client VLANs works via RIP:

```text
$ show ip route 192.168.10.0   (on R2)
 R   192.168.10.0/24 [120/2] via 192.168.110.3, Ethernet2
$ show ip route 192.168.20.0   (on R2)
 R   192.168.20.0/24 [120/2] via 192.168.110.3, Ethernet2
```

And Vlan200 itself is reachable end to end:

```text
$ ping 192.168.200.2    (from S1)   -- 0% loss
$ ping6 2001:db8:200::2 (from S1)   -- 0% loss
```

This confirms relay traffic destined for `192.168.200.2`/
`2001:db8:200::2` genuinely terminates at R2 via Vlan200 -- exactly the
interface Step 1 places the enable commands on. No configuration was
changed to verify this.

## Step 3/4 — integration architecture

```text
NetBox ipam.IPRange (server=r2)
        |
modules.netbox_ipam.get_dhcp_ranges(server="secondary")
        |
modules.ipam_context.build_and_validate_r2_dhcp_context()   <- fail-closed
        |                                                       gate (Step 7)
        v
master.py: _build_eos_config(node, inv)
        |   if node == "R2": context["dhcp"] = build_and_validate_r2_dhcp_context()
        v
templates/R2.cfg.j2                          <- the SAME file/context shape
        |     {% if dhcp is defined %}          every other device uses;
        |        dhcp server ipv4/ipv6           R2's own Vlan200 stanza
        |     {% endif %}                        gains 2 conditional lines
        |     ...
        |     {% if dhcp is defined %}
        |     {% include "templates/R2_dhcp_server.cfg.j2" %}
        |     {% endif %}
        v
push_eos() -> eos_commands() -> netmiko send_config_set()   <- UNCHANGED,
                                                                 not modified
                                                                 this phase
```

**There is now exactly ONE authoritative desired R2 configuration**
(`templates/R2.cfg.j2`), matching Step 3's explicit requirement.
`templates/R2_dhcp_server.cfg.j2` was kept, per Step 3's own listed
option, as an **included Jinja partial** -- trimmed down to just the
`dhcp server` global block (the `interface Vlan200` enable lines were
moved into R2.cfg.j2's own pre-existing Vlan200 stanza, never duplicated
as a second stanza). No second, parallel hard-coded pool source exists:
every pool value in the render still comes from
`modules.ipam_context.build_and_validate_r2_dhcp_context()`, which itself
reads only NetBox.

`master.py` gained exactly one new import and a 5-line helper
(`_build_eos_config()`, extracted from `push_eos()`'s first 3 lines to
make it independently unit-testable): the DHCP-specific decision is the
single line `if node == "R2": context["dhcp"] = ...`. All pool
calculations, NetBox querying, and validation logic remain entirely in
`modules/ipam_context.py`, per Step 4's explicit instruction.
`push_eos()`'s connection/push logic itself -- and every other device's
render -- is completely untouched.

## Step 7 — fail-closed pre-push validation

Two new `modules/ipam_context.py` functions compose every one of Step 7's
required checks, and both RAISE (never return a partial/unsafe result or
swallow an exception) on failure:

* **`build_and_validate_r2_dhcp_context()`** (pre-render): NetBox
  unavailable -> propagates `NetboxConnectionError`/`NetboxAuthenticationError`
  unchanged; secondary pool missing/unexpected (incl. a stale VLAN30 IPv4
  pool) -> propagates `get_r2_dhcp_context()`'s existing `NetboxModelError`;
  overlap / wrong prefix / gateway-in-pool / S1-S2-infrastructure-address-
  in-pool -> `validate_dhcp_pool_safety()`'s findings are collected and
  raised as one `NetboxModelError` listing every problem.
* **`validate_r2_candidate_render()`** (post-render): the DHCP section
  is absent -> raises; Vlan200's live NetBox-recorded static IPv4 or IPv6
  address (read via the existing `get_primary_address("R2", family)` --
  never a hard-coded literal) is missing from the rendered text -> raises.

`master.py`'s `_build_eos_config()` calls both, in order, before
`push_eos()` ever opens a connection -- a NetBox failure aborts the ENTIRE
R2 push (never silently proceeds with a DHCP-less render). Verified live
(mocked-failure unit tests) and structurally (the calls are unconditional,
not wrapped in a `try/except` anywhere in `master.py`).

## Step 6 — full R2 candidate (render-only)

```bash
/home/student/Scripts/.venv/bin/python netbox/scripts/render_r2_dhcp.py -v [--write]
```

Now renders `templates/R2.cfg.j2` itself (the real push-path template),
with the exact context `master.py` would build, through the exact same
`build_and_validate_r2_dhcp_context()`/`validate_r2_candidate_render()`
gate -- proving the complete file, not a fragment. Live run confirmed:
hostname/VLANs/every interface/RIP/OSPFv2/OSPFv3/IP-in-IP-removal/
route-maps/static routes all present and unchanged; Vlan200's
`ip address 192.168.200.2/24`/`ipv6 address 2001:db8:200::2/64` preserved;
the `dhcp server` block and both Vlan200 enable lines present. Exit
code `0`.

## Step 5/9 — semantic delta: DHCP-only (proven, not assumed)

`modules.ipam_context.dhcp_render_delta()` diffs R2 rendered WITHOUT a
`dhcp` context (byte-identical to every other device's shape, and to R2's
own pre-Phase-3D shape -- verified by a dedicated regression test) against
WITH one. Live result:

```text
Semantic delta: PASS (DHCP-only -- 22 line(s) added, 0 removed)
```

All 22 additions are `dhcp server`/`lease time`/`subnet`/`name`/
`default-gateway`/`range`/`dhcp server ipv4`/`dhcp server ipv6`/`exit` --
`render_r2_dhcp.py`'s own `_validate_delta_is_dhcp_only()` enforces this
mechanically (Step 9's diff acceptance rule), and rejects on sight any
`removed` entry (nothing may ever disappear) or any `added` entry outside
that allow-list.

## Step 8 — live EOS configuration-session dry run

Performed exactly once, against the real R2 image, using the FULL
integrated candidate (Step 6). Before-state was captured first (`show
running-config section dhcp` empty, `show dhcp server` both families
inactive/0 leases, `show configuration sessions` empty, Vlan200's two
static lines recorded).

```text
session created:     configure session csci5840-phase3d-full-dryrun
parser result:        ZERO errors (no "% Invalid input" / "% Incomplete
                       command" / "% Ambiguous command" for any of the
                       ~130 flattened commands, including every existing
                       RIP/OSPF/route-map/interface line already in
                       templates/R2.cfg.j2)
candidate diff:        --- system:/running-config
                       +++ session:/csci5840-phase3d-full-dryrun-session-config
                       +dhcp server
                       +   lease time ipv4 0 days 8 hours 0 minutes
                       +   lease time ipv6 0 days 8 hours 0 minutes
                       +   !
                       +   subnet 192.168.10.0/24
                       +      range 192.168.10.200 192.168.10.220
                       +      name VLAN10-v4-secondary
                       +      default-gateway 192.168.10.1
                       +   ... (VLAN20 v4, VLAN10/20/30 v6 subnets, same shape)
                        !
                        interface Vlan200
                       +   dhcp server ipv4
                       +   dhcp server ipv6
committed:             NO
session aborted:       YES (`abort`, from within the session)
```

The diff contains **only** the intended DHCP additions -- no line
touching Vlan200's addresses, RIP, OSPF, static routes, IP-in-IP, BGP,
monitoring, SNMP, syslog, management, or any other interface appears
anywhere in it. Per Step 9's rule, this is a PASS with nothing to fix.

**Commands never executed in this phase (by design):** `commit`, `commit
timer`, `commit replace`, `configure terminal` (outside the temporary
session), `copy running-config startup-config`, `write memory`.

## Step 10 — running-config integrity and DHCP live state

```text
BEFORE session:  show configuration sessions -> (empty)
                 show running-config section dhcp -> (empty)
                 show dhcp server -> IPv4 inactive, IPv6 inactive, 0 leases both
                 show running-config interfaces Vlan200 -> ip address 192.168.200.2/24
                                                             ipv6 address 2001:db8:200::2/64

AFTER  abort:    show configuration sessions -> (empty, identical)
                 show running-config section dhcp -> (empty, identical)
                 show dhcp server -> IPv4 inactive, IPv6 inactive, 0 leases both (identical)
                 show running-config interfaces Vlan200 -> byte-identical to BEFORE
```

Running configuration is proven unchanged before vs. after. The DHCP
server remains inactive in running config; zero leases; no client
behavior change; NMAS's own ISC `isc-dhcp-server`/`isc-dhcp-server6`
processes were not touched (confirmed `active (running)` continuously
throughout, uninterrupted).

## Step 11 — tests

23 new tests: 14 in `test_ipam_context.py`
(`GetR2ProtectedAddressesTests`/`BuildAndValidateR2DhcpContextTests`/
`ValidateR2CandidateRenderTests`/`DhcpRenderDeltaTests`), 3 net-new in
`test_render_r2_dhcp.py` (rewritten for the integrated render path --
`IntegratedRenderTests`, `SemanticDeltaTests`, updated `MainEndToEndTests`/
`ValidateNestingTests`/`TemplateDoesNotHardcodePoolBoundariesTests`), and
6 in the new `test_master_r2_integration.py` (`BuildEosConfigR2Tests`),
covering: full R2 render includes the DHCP context; full R2 render
preserves every pre-existing non-DHCP line; the semantic delta is
mechanically verified DHCP-only; Vlan200 IPv4/IPv6 remain static in the
integrated render; pool values visibly come from whatever context is
supplied (not a hard-coded literal); `master.py` attaches a normalized
context rather than duplicating pool data; a NetBox failure (connection,
model, or post-render) fails closed BEFORE any render/push proceeds for
R2; other devices never touch NetBox at all; VLAN30 IPv4 remains
prohibited (inherited, unchanged, from Phase 3C's `get_r2_dhcp_context()`
tests); the standalone fragment and the integrated render are proven
semantically equivalent (the fragment's own content is a strict subset of
the integrated render, verified by the same context); `eos_commands()`
correctly handles `dhcp server`/`subnet `/`range `/`interface `/`dhcp
server ipv4`/`dhcp server ipv6` (inherited from Phase 3C's
`test_eos_render.py`, still passing unmodified); and neither
`render_r2_dhcp.py` nor `master.py`'s new code path can emit or trigger a
`commit` (checked directly against `render_r2_dhcp.py`'s own source, and
by construction -- `master.py`'s push path uses `send_config_set`
directly against `enable`-mode config, never a configuration session, so
"session commit" is not a concept that applies to it at all).

```text
Previous: 372
New:      23
Total:    395
PASS/FAIL: 395/395 PASS
```

## Step 12 — NetBox validation

No NetBox object was created, changed, or removed in this phase (purely
code/template integration). Confirmed:

```text
$ python3 -m modules.netbox_ipam
Overall: PASS

$ python3 netbox/scripts/verify_netbox_model.py
392/392 checks passed.    # unchanged from the Phase 3C baseline

$ python3 netbox/scripts/populate_netbox.py --check --verbose
Summary: UNCHANGED=318    # zero CREATE/UPDATE/CONFLICT -- zero drift
```

## Remaining work before real activation

1. Decide and implement the still-open NMAS-side migration gap (whether
   `dhcp/dhcpd.conf.j2`/`dhcpd6.conf.j2` should also become
   NetBox-context-driven) -- separate, independently-reviewed work.
2. Perform a real (still non-disruptive) push of `templates/R2.cfg.j2`'s
   new DHCP section via `master.py`'s actual `push_eos()` (this phase
   proved the candidate via a configuration session, not a real
   `send_config_set` -- the next phase's first concrete action).
3. Perform staged relay/lease acquisition testing (H1-H4 obtaining a
   lease from R2 specifically) without disrupting the primary NMAS path.
4. Decide on and implement DHCPv4/DHCPv6 failover/monitoring visibility
   for the now-active secondary server (post-activation observability),
   if desired.

**Items 2 and 3 above were completed live in the combined Phase
3E/3F/3G session documented below.** Item 1 (NMAS's own NetBox
cutover) is also complete. Item 4 has a minimal observability script
(`netbox/scripts/verify_dhcp_servers.py`, Phase 3G Step 28).

---

# Phase 3E — R2 Live DHCP Activation

Phase 3E activated R2's secondary DHCP server through the ACTUAL
production push path (`master.py`'s `push_eos()`/`_build_eos_config()`),
invoked for R2 only. No other device was pushed; NMAS was untouched.

## Activation procedure

```python
import master
inv = master.load_inventory()
ip = master.discover_ip(inv["lab_name"], "R2")
master.push_eos("R2", ip, inv)
```

This is the same code path a full `master.py` run would use for R2 --
nothing was hand-crafted or pasted manually.

## Rollback procedure (defined before activation; not needed)

```text
configure
   interface Vlan200
      no dhcp server ipv4
      no dhcp server ipv6
   no dhcp server
end
```

(`no dhcp server (ipv4|ipv6)` and `no dhcp server` are each the
CLI-grammar-confirmed `noOrDefaultSyntax` of their respective commands --
verified from `CliPlugin/DhcpServerCli.py` before activation, not
guessed.) This touches nothing on Vlan200's addressing or any other
protocol.

## Result

```text
$ show dhcp server
IPv4 DHCP server is active   (0 -> later showing real leases)
IPv6 DHCP server is active
Vlan200      Active            (interface status, both families)
5/5 secondary subnets present with correct name/range/gateway
```

```text
$ show running-config interfaces Vlan200
interface Vlan200
   ip address 192.168.200.2/24      <- unchanged
   dhcp server ipv4
   dhcp server ipv6
   ipv6 address 2001:db8:200::2/64  <- unchanged
```

## Routing/management integrity

RIP and both IPv4/IPv6 routing tables were captured before and after and
found **byte-identical**. OSPFv2's neighbor table showed only a timer-tick
difference (no reset). **One transient finding, disclosed rather than
hidden:** OSPFv3's two adjacencies briefly reset and re-established (Full
state recovered within ~1-2 minutes, DR/BDR re-elected) -- this is a
consequence of `master.py`'s existing, pre-Phase-3D design of always
re-sending R2's ENTIRE template on every push (including its already-
matching `router ospf`/`ipv6 router ospf`/`redistribute` lines), not
something introduced by the DHCP work itself; it would occur on any
re-push of R2 today, DHCP or not. Final route tables (v4 and v6) were
confirmed unaffected, and management reachability (`ping`/`ping6` to
Vlan200) was confirmed throughout. This did not meet the STOP criteria
(no threat to connectivity, address correctness, DHCP correctness, or
rollback safety), so no rollback was performed.

**Gate: PASS.** R2 activation, Vlan200 integrity, routing integrity,
management reachability, and NMAS-still-active were all confirmed before
proceeding to Phase 3F.

---

# Phase 3F — Primary/Secondary DHCP Behavior Verification

## Client mechanism (determined, not assumed)

Both H1-H4 run persistent `isc-dhclient 4.4.3-P1` daemons
(`dhclient -4 -v eth1` / `dhclient -6 -v eth1`), with lease state in
`/var/lib/dhcp/dhclient.leases` (v4) / `dhclient6.leases` (v6). Safe,
family-scoped renew: `dhclient -r -4|-6 eth1` (release, using dhclient's
own built-in mechanism) followed by `dhclient -4|-6 -v eth1 &` (fresh
request) -- never a client-daemon replacement, and never touching the
other family's daemon.

## Steady state (before any outage test)

Both NMAS (ISC) and R2 (EOS/Kea) confirmed active, both families, before
any client action; S1/S2 relay targets confirmed unchanged
(`192.168.200.2`+`192.168.200.100` v4, `2001:db8:200::2`+`::100` v6).

## IPv4 failover test (Step 8)

`sudo systemctl stop isc-dhcp-server` (NMAS v4 only; v6 left running).
Forced fresh IPv4 on H1/H2/H3:

| Host | Old address | New address | VLAN | Pool | Gateway |
|---|---|---|---|---|---|
| H1 | 192.168.10.102 | **192.168.10.201** | 10 (via S1) | secondary (R2) | 192.168.10.1 reachable |
| H2 | 192.168.20.101 | **192.168.20.200** | 20 (via S1) | secondary (R2) | 192.168.20.1 reachable |
| H3 | 192.168.10.103 | **192.168.10.202** | 10 (via S2) | secondary (R2) | 192.168.10.1 reachable |

R2 lease table confirmed exactly 2/21 leased on the VLAN10 secondary pool
and 1/21 on VLAN20's -- matching exactly. Zero addresses from any primary
range. Zero duplicates. `sudo systemctl start isc-dhcp-server` restored
immediately; both NMAS services confirmed active again before continuing.

## IPv6 failover test (Step 10)

`sudo systemctl stop isc-dhcp-server6` (NMAS v6 only; v4 left running).
Forced fresh IPv6 on H1/H2/H3/H4:

| Host | Old address | New address | VLAN | Pool |
|---|---|---|---|---|
| H1 | 2001:db8:10::1c37 | **2001:db8:10::2001** | 10 (via S1) | secondary (R2) |
| H2 | 2001:db8:20::1518 | **2001:db8:20::2001** | 20 (via S1) | secondary (R2) |
| H3 | 2001:db8:10::198b | **2001:db8:10::2003** | 10 (via S2) | secondary (R2) |
| H4 | 2001:db8:30::16d4 | **2001:db8:30::2001** | 30 (via S2) | secondary (R2) |

**H4 IPv4 = NONE**, confirmed (`ip -4 -br addr show eth1` returned
nothing) both before and after this test -- VLAN30's IPv6-only design
held throughout. R2's lease table confirmed exactly 2/256, 1/256, 1/256
leased on the VLAN10/20/30 secondary v6 pools respectively -- matching
exactly. Gateways reachable on all four. `sudo systemctl start
isc-dhcp-server6` restored immediately; both NMAS services confirmed
active again.

## Lease safety (Step 12)

Normalized report across all observed addresses: **zero duplicates,
zero pool overlaps, zero out-of-pool addresses, zero VLAN30 IPv4.** Per
Step 13, stale addresses left over from a now-superseded lease (e.g. an
old NMAS-issued address still present alongside a newer R2-issued one) are
expected and not a failure -- ordinary DHCP leases remain valid until they
expire; nothing requires an instant fail-back.

**Gate: PASS.** IPv4/IPv6 secondary tests, both VLAN10 paths (S1 and S2),
VLAN20, VLAN30 IPv6-only, NMAS restoration, and lease safety all
confirmed before proceeding to Phase 3G.

---

# Phase 3G — NMAS Primary DHCP NetBox Cutover

## Architecture

```text
NetBox ipam.IPRange (server=nmas)
        |
modules.netbox_ipam.get_dhcp_ranges(server="primary")
        |
modules.ipam_context.build_and_validate_nmas_dhcp_context()  <- fail-closed
        |                                                        gate, SAME
        |                                                        validate_dhcp_pool_safety()/
        |                                                        get_dhcp_pool_context()/
        |                                                        get_r2_protected_addresses()
        |                                                        R2 uses (Step 15's "one
        |                                                        shared safety model")
        v
master.py: setup_nmas(inv)
        |   dhcp = build_and_validate_nmas_dhcp_context()
        v
dhcp/dhcpd.conf.j2 / dhcpd6.conf.j2    <- Jinja loops, zero literal pool
        |                                  boundaries
        v
dhcpd -t / dhcpd -6 -t  (existing, unmodified checks in setup_nmas())
        v
/etc/dhcp/dhcpd.conf / dhcpd6.conf -> systemctl restart isc-dhcp-server(6)
```

`get_nmas_dhcp_context()` mirrors `get_r2_dhcp_context()` exactly (same
fail-closed missing/unexpected/duplicate-pool checks), and
`build_and_validate_nmas_dhcp_context()` calls the identical
`get_dhcp_pool_context()`/`validate_dhcp_pool_safety()`/
`get_r2_protected_addresses()` triplet `build_and_validate_r2_dhcp_context()`
uses -- there is exactly one shared safety model, not two parallel ones
(verified by a dedicated test, `test_shares_the_same_safety_validator_as_r2`).

## NMAS render equivalence (Step 20)

Rendering both templates with the live NetBox-derived context produced
output **byte-for-byte identical** to the original, hand-written literal
files (confirmed via `diff`, and pinned as a permanent regression test,
`test_dhcpd_conf_j2_render_matches_pre_cutover_output_exactly`). Zero
range changes, zero gateway changes, zero option changes.

## ISC syntax validation (Step 19)

`dhcpd`'s own AppArmor profile (`/etc/apparmor.d/usr.sbin.dhcpd`) confines
it to reading only `/etc/dhcp/**` -- it refuses even a `-t` syntax-only
read of a `/tmp` file with "Permission denied", a genuine environmental
constraint discovered during this phase. `netbox/scripts/render_nmas_dhcp.py`
therefore writes its candidate to a distinctly-named, `sudo`-owned file
directly under `/etc/dhcp/` (`dhcpd.conf.render-candidate`), runs the real
`dhcpd -t`/`dhcpd -6 -t` binary against it, and removes it immediately
afterward (in a `finally` block, so it is removed even on failure) --
never touching the real `dhcpd.conf`/`dhcpd6.conf`. Live result:

```text
ISC DHCPv4 syntax validation (dhcpd -t): PASS
ISC DHCPv6 syntax validation (dhcpd -6 -t): PASS
```

## Backup and cutover (Steps 21-22)

`/etc/dhcp/dhcpd.conf`, `/etc/dhcp/dhcpd6.conf`, and
`/etc/default/isc-dhcp-server` were copied to
`netbox/runtime/phase3g_backup/` (git-ignored) before any change.

Cutover was performed via the **actual, unmodified** `master.setup_nmas(inv)`
function (not a hand-crafted parallel path) -- which itself now calls
`build_and_validate_nmas_dhcp_context()` before writing any file, and
already ran `dhcpd -t`/`dhcpd -6 -t` against the real installed files
before restarting either service (pre-existing behavior, unchanged):

```text
NMAS: configuring management/DHCP...
NMAS: configuration OK
```

Result: both `isc-dhcp-server` and `isc-dhcp-server6` `active`; installed
`/etc/dhcp/dhcpd.conf`/`dhcpd6.conf` differ from the pre-cutover backup by
**only a trailing newline** (Jinja's rendered output ends with one; the
original hand-written file did not) -- zero semantic difference. The
existing lease database (`/var/lib/dhcp/dhcpd.leases`) was preserved
across the `systemctl restart` (ISC dhcpd reads it back on startup),
confirmed by inspecting active bindings before and after.

## Traceability (Step 23)

`netbox/ipam.yml` is **not** retired -- it remains the Phase-2 migration
manifest that seeds NetBox's `ipam.IPRange` objects in the first place;
retiring it is out of scope and was not done. The only change is that
`dhcp/dhcpd.conf.j2`/`dhcpd6.conf.j2` no longer hold pool-boundary
literals independently -- every value traces
`NetBox ipam.IPRange -> get_nmas_dhcp_context() -> Jinja -> /etc/dhcp/dhcpd*.conf`.

---

# Final Dual-Server Validation

## Primary-service re-verification after cutover (Step 25)

R2's DHCP was **temporarily and reversibly** disabled (`no dhcp server
ipv4`/`no dhcp server ipv6` under `interface Vlan200`, running-config
only -- never saved to startup-config) to prove the newly-cutover NMAS
conclusively, in isolation:

| Host | Family | Address received | Pool |
|---|---|---|---|
| H1 | v4 | 192.168.10.102 | primary (NMAS) |
| H2 | v4 | 192.168.20.101 | primary (NMAS) |
| H3 | v4 | 192.168.10.103 | primary (NMAS) |
| H4 | v6 | 2001:db8:30::18e5 | primary (NMAS, in `::1000-::1fff`) |

Server-side `dhcpd` logs confirmed NMAS actively answering each Solicit/
Discover with the correct primary-range address throughout. R2's DHCP was
then immediately re-enabled (`dhcp server ipv4`/`dhcp server ipv6`);
`show dhcp server` confirmed both families active again within seconds,
and Vlan200's static addresses were unchanged throughout the entire
disable/re-enable cycle.

## Final dual-server matrix

| SERVER | ROLE | FAMILY | VLAN | RANGE | STATUS |
|---|---|---|---|---|---|
| NMAS | primary | v4 | 10 | 192.168.10.100-179 | active |
| NMAS | primary | v4 | 20 | 192.168.20.100-179 | active |
| NMAS | primary | v6 | 10 | 2001:db8:10::1000-1fff | active |
| NMAS | primary | v6 | 20 | 2001:db8:20::1000-1fff | active |
| NMAS | primary | v6 | 30 | 2001:db8:30::1000-1fff | active |
| R2 | secondary | v4 | 10 | 192.168.10.200-220 | active |
| R2 | secondary | v4 | 20 | 192.168.20.200-220 | active |
| R2 | secondary | v6 | 10 | 2001:db8:10::2000-20ff | active |
| R2 | secondary | v6 | 20 | 2001:db8:20::2000-20ff | active |
| R2 | secondary | v6 | 30 | 2001:db8:30::2000-20ff | active |

## Final client matrix (as observed at the end of this session)

| HOST | VLAN | IPv4 | IPv4 POOL/SERVER | IPv6 | IPv6 POOL/SERVER |
|---|---|---|---|---|---|
| H1 | 10 (S1) | 192.168.10.102 | primary/NMAS | 2001:db8:10::2001 (+ stale ::1c37) | secondary/R2 |
| H2 | 20 (S1) | 192.168.20.101 | primary/NMAS | 2001:db8:20::2001 (+ stale ::1518) | secondary/R2 |
| H3 | 10 (S2) | 192.168.10.103 | primary/NMAS | 2001:db8:10::2003 (+ stale ::198b) | secondary/R2 |
| H4 | 30 (S2) | **NONE** | N/A | 2001:db8:30::18e5 | primary/NMAS |

The "stale" IPv6 addresses are earlier, still-valid leases left on-interface
from testing (Step 13: not a failure -- a client is never required to
instantly fail back). Zero duplicates across hosts; zero pool overlaps;
zero out-of-pool addresses; H4 confirmed IPv4-less throughout.

## Routing/connectivity regression (Step 27)

RIP, OSPFv2, OSPFv3, and both routing tables were re-verified unaffected
by the end of this session (see Phase 3E's finding re: OSPFv3's transient,
self-healing re-adjacency -- fully converged to Full state well before
Phase 3F began). R2 and NMAS management reachability confirmed throughout.
The pre-existing H1-to-WebServer issue was neither touched nor
investigated in this phase -- it remains exactly as documented in
`LAB_REQUIREMENTS.md`/`README.md`, deferred.

## Observability (Step 28)

`netbox/scripts/verify_dhcp_servers.py` (new, minimal, read-only) reports:

```text
SERVER  IPv4      IPv6
NMAS    active    active
R2      active    active

R2 lease-count entries observed: ['3', '2', '1', '4', '2', '1', '1']

Overall: PASS
```

## Tests

67 new tests across this combined session (Phase 3E/3F/3G had no new code
paths of their own beyond Phase 3G's; all live activation/failover work
was exercised through the ALREADY-tested Phase 3C/3D code paths):
`GetNmasDhcpContextTests`/`BuildAndValidateNmasDhcpContextTests`/
`NmasTemplateNetboxDrivenTests` (`test_ipam_context.py`, 12), a full
`test_render_nmas_dhcp.py` (11, including 5 that invoke the REAL `dhcpd`
binary), `SetupNmasDhcpTests` (`test_master_r2_integration.py`, 4), and
`test_verify_dhcp_servers.py` (6) -- 33 directly new for Phase 3G, plus
the fixed/updated counts already reflected in the 395 baseline this
session started from.

```text
Previous: 395
New:      33
Total:    428
PASS/FAIL: 428/428 PASS
```

## NetBox validation

```text
$ python3 -m modules.netbox_ipam        -> PASS
$ python3 netbox/scripts/verify_netbox_model.py   -> 392/392 (unchanged)
$ python3 netbox/scripts/verify_reservations.py   -> READY=0 BLOCKED=0 FAIL=0
$ python3 netbox/scripts/populate_netbox.py --check -> UNCHANGED=318 (zero drift)
```

No NetBox object was created, changed, or removed anywhere in this
combined session -- Phase 3E/3F/3G touched only live device/service state
and repository code/templates/tests/docs.

## Remaining work

* Final migration cleanup / retirement of temporary bootstrap artifacts
  (`netbox/ipam.yml`'s eventual role once NetBox is fully authoritative
  end-to-end -- not done in this phase, and not required to be).
* The historical H1-to-WebServer connectivity issue remains open,
  untouched, and explicitly out of scope for this DHCP work.

---

# Final Migration Cleanup

This phase closes out the migration with no new provisioning behavior --
only stale-metadata correction and documentation closure, per its own
explicit scope. Nothing in Containerlab, `master.py`'s live push path, or
any device configuration changed.

## NetBox's final role

NetBox is the **runtime source of truth** for both active DHCP pool
paths (Phase 3D/3G): NMAS primary (`dhcp/dhcpd.conf.j2`/`dhcpd6.conf.j2`,
via `modules.ipam_context.build_and_validate_nmas_dhcp_context()`) and R2
secondary (`templates/R2.cfg.j2`/`R2_dhcp_server.cfg.j2`, via
`build_and_validate_r2_dhcp_context()`). Every pool boundary, gateway, and
relay target rendered onto either server is read from NetBox at render
time -- there is no hard-coded pool dictionary anywhere in the active path.
NetBox is explicitly **not** authoritative for VLAN200 management
addressing (see below) or for RIP/OSPF/BGP/NAT/VLAN policy, none of which
this migration touched.

## VLAN200 -- static management, permanently

Per Phase 3B.3's authoritative decision: VLAN200 is the dedicated
management VLAN on all 9 managed devices and stays **statically**
addressed (IPv4 and IPv6), on every device, indefinitely. It must never use
DHCP/DHCPv6, never require a client MAC/DUID/IAID for its identity, and
never appear as a reservation target. `netbox/scripts/populate_netbox.py`'s
`_assignment_mode()` classifies every interface `static`/`none` today --
zero interfaces are `dhcp-reserved`/`dhcpv6-reserved` (confirmed live: 0 of
41 modeled interfaces carry either value). This is verified, not assumed,
on every `verify_reservations.py` run (`Reservation targets checked: 0` is
the correct, permanent result of this architecture).

## No infrastructure DHCP reservations

Nothing in this repository generates, plans, or applies a fixed
MAC/DUID-keyed DHCP reservation for any of R1-R4/S1-S4/mgmt_swt. The
schema-level machinery to do so for a genuinely future dynamic target
(`ASSIGNMENT_MODES`, `IDENTITY_STATUSES`, `mark_mac_authoritative()`,
`set_dhcpv6_identity()`, `pin_stable_identities.py`) is kept -- see
"Retained migration artifacts" below -- but nothing currently invokes it
against a real interface.

## Primary/secondary DHCP architecture (unchanged, reconfirmed)

* **NMAS (primary)**: VLAN10/20 IPv4 `.100-.179`; VLAN10/20/30 IPv6
  `::1000-::1fff`.
* **R2 (secondary)**: VLAN10/20 IPv4 `.200-.220`; VLAN10/20/30 IPv6
  `::2000-::20ff`.
* Independent servers, non-overlapping pools by construction
  (`validate_dhcp_pool_safety()`), no shared lease database, no
  synchronized failover -- reconfirmed by this phase's regression run (see
  "Final regression" below), not re-tested destructively.
* **VLAN30 remains IPv6-only**: no IPv4 prefix, range, or pool exists for
  it anywhere in NetBox, the manifest, or either DHCP render path; enforced
  structurally in `get_r2_dhcp_context()`/`get_nmas_dhcp_context()`
  (raises `NetboxModelError` on a synthetic VLAN30 IPv4 pool) and checked
  again in `validate_dhcp_pool_safety()`.

## Data flow (both active paths)

```text
NetBox ipam.IPRange (server=nmas | server=r2)
        |
modules.netbox_ipam.get_dhcp_ranges(server=...)         <- normalized read
        |
modules.ipam_context.build_and_validate_{nmas,r2}_dhcp_context()
        |                                                    <- fail-closed:
        |                                                       NetBox down,
        |                                                       missing/
        |                                                       unexpected
        |                                                       pool, or an
        |                                                       overlap/
        |                                                       gateway/
        |                                                       infra-address
        |                                                       safety
        |                                                       violation
        |                                                       all raise
        |                                                       BEFORE any
        |                                                       render/push
        v
dhcp/dhcpd.conf.j2 + dhcpd6.conf.j2   |   templates/R2.cfg.j2 (+ included
        |                             |   R2_dhcp_server.cfg.j2 fragment)
        v                             v
master.setup_nmas()/dhcpd -t         master.push_eos("R2")/EOS send_config_set
        v                             v
systemctl restart isc-dhcp-server(6) live R2 "dhcp server" config
```

VLAN200 (all 9 managed devices) and every other managed address
(loopbacks, transit links, switch client-VLAN SVIs) are **not** part of
this flow at all -- they are static text in `templates/*.cfg.j2`, rendered
and pushed by `master.py` exactly as before any NetBox work began. NetBox
separately *models* those addresses (Phase 2, for inventory/monitoring
identity and IPAM collision-prevention) but is not consulted to render
them.

## Active operational paths vs. bootstrap/recovery-only files

| File | Role |
|---|---|
| `modules/netbox_ipam.py` | Sole NetBox API access point (live) |
| `modules/ipam_context.py` | Normalized context + fail-closed safety (live) |
| `dhcp/dhcpd.conf.j2`, `dhcpd6.conf.j2` | NMAS render targets (live, NetBox-driven) |
| `templates/R2.cfg.j2`, `templates/R2_dhcp_server.cfg.j2` | R2 render targets (live, NetBox-driven) |
| `master.py` (`setup_nmas`, `_build_eos_config`/`push_eos`) | The only code that pushes either DHCP server |
| `netbox/ipam.yml` | **Bootstrap/recovery seed only** -- see below; not read by any live render/push path |
| `netbox/scripts/populate_netbox.py` | Reconciles `ipam.yml` -> NetBox; run manually, not by `master.py` |
| `netbox/scripts/verify_netbox_model.py`, `verify_reservations.py`, `verify_dhcp_servers.py` | Read-only verification; run manually or in CI-style checks |
| `netbox/scripts/render_r2_dhcp.py`, `render_nmas_dhcp.py` | Render-only preview/validation CLIs; never push |
| `netbox/scripts/sync_interface_macs.py`, `pin_stable_identities.py` | Retained, self-guarding, currently no-op tooling -- see below |
| `netbox/scripts/compare_live_state.py`, `shadow_render.py` | Phase 2/3A proof-of-equivalence tooling; still safe to run, not part of the live path |

## `netbox/ipam.yml` -- final role

**Decision: Option A -- keep, as an explicitly documented bootstrap/
recovery seed manifest. It is NOT the live runtime source of truth.**

Evidence considered:

* **Not read by any live provisioning code.** `master.py`,
  `modules/ipam_context.py`, and both device/server render paths query
  NetBox live through `modules/netbox_ipam.py`; none of them import or
  parse `netbox/ipam.yml`.
* **Its only current reader is `netbox/scripts/populate_netbox.py`**,
  which is never invoked by `master.py` and is a manually-run
  reconciliation tool.
* **It is the only from-scratch recovery path for NetBox's IPAM model.**
  If NetBox's database volume were ever lost, recreated, or needed
  rebuilding in a new environment, `populate_netbox.py --apply` against
  this file is what reconstructs the site/roles/VLANs/prefixes/devices/
  interfaces/addresses/DHCP ranges NetBox needs before either DHCP render
  path can even build a context (`build_and_validate_*_dhcp_context()`
  raises immediately if the expected NetBox objects are missing). Retiring
  it with no replacement would leave NetBox's own bootstrap as an
  undocumented, ad hoc, manual-API-calls process -- strictly worse.
* **It doubles as a test fixture**: `monitoring/tests/test_populate_netbox.py`
  validates real manifest content (VLAN30 IPv6-only, R5/WebServer
  unmanaged, DHCP range direction/family, etc.) directly against this file.
* **An earlier phase's own framing (Phase 2's header comment) suggested it
  would be retired once NetBox became authoritative for provisioning.**
  That framing is superseded: Phase 3G's own "Traceability" section already
  concluded retiring it was out of scope, and this phase's audit confirms
  why retiring it would be a net loss, not cleanup -- a bootstrap/recovery
  manifest remains useful for as long as NetBox needs a from-scratch
  recovery path, which is ongoing. The file's header comment (top of
  `netbox/ipam.yml`) has been corrected to state this final role plainly
  instead of implying eventual retirement.
* **It is re-derived from the templates/inventory whenever THEY change**;
  NetBox is never written back into it. If `templates/*.cfg.j2`/
  `dhcp/*.j2`/`inventory.yml` addressing ever changes, this manifest (and
  then NetBox, via `--apply`) must be updated to match -- the direction of
  truth never reverses.

## Stale artifacts found and corrected

**Finding**: `mark_mac_authoritative()` (Phase 3B.1) wrote a mechanism-
specific `description` (e.g. *"Pin via EOS 'interface Vlan200/mac-address
<value>' ... Not yet applied -- see docs/NETBOX_IPAM.md."*) onto each
managed device's Vlan200 `dcim.MACAddress` object when Vlan200 was still
classified `dhcp-reserved`. Phase 3B.3's cleanup
(`clear_stale_mac_identity_status()`) correctly cleared the `identity_status`
custom field on all 9 devices, but did **not** clear this `description`
text -- live NetBox still carried the obsolete pinning language on all 9
managed devices' Vlan200 MAC objects when this cleanup phase began
(confirmed via a direct read of `dcim.mac_addresses`).

**Fix**: `clear_stale_mac_identity_status()` (`modules/netbox_ipam.py`) now
also detects that specific stale marker text and replaces it with a
neutral inventory note (`"Observed <interface> interface/system MAC
retained for inventory."`), in the same self-guarding pass, driven only by
the interface's current assignment-mode policy -- never by interface name,
and never overwriting a description this repository did not itself write.
The MAC address value itself was never touched. Applied live via
`netbox/scripts/populate_netbox.py --apply`; rerunning `--check` afterward
shows `UNCHANGED` for all 9 (see "Final regression" below).

No other stale DHCP-identity-pinning metadata was found: a live scan of
every managed interface's `dhcpv6_duid`/`dhcpv6_iaid`/`dhcpv6_identity_status`
and `ipv4_assignment_mode`/`ipv6_assignment_mode` custom fields showed zero
non-static/non-none values across all 41 interfaces.

## Retained migration artifacts, and why

| Artifact | Retained because |
|---|---|
| `netbox/ipam.yml` | Bootstrap/recovery seed -- see above. |
| `netbox/scripts/sync_interface_macs.py` | Legitimate ongoing observational inventory sync (MAC addresses are real, useful data regardless of DHCP plans); self-contained, never assumes a dynamic target exists. |
| `netbox/scripts/pin_stable_identities.py` | Already refactored (Phase 3B.3) to discover its targets from NetBox's own assignment-mode policy rather than a hard-coded interface name; correctly a no-op today (`No managed interface is currently classified dhcp-reserved/dhcpv6-reserved`), and remains ready for a genuinely future dynamic target without modification. Deleting it would remove working, correctly-scoped tooling for no benefit. |
| `ASSIGNMENT_MODES` / `IDENTITY_STATUSES` schema values (`dhcp-reserved`, `dhcpv6-reserved`, `authoritative-planned`, `blocked`) | Valid, documented enum values with no current instance -- kept so a genuinely future dynamic-assignment interface does not require a schema migration. |
| `netbox/scripts/compare_live_state.py`, `shadow_render.py` | Independent, still-useful live-state/equivalence verification tools; not part of the active push path but not stale either. |
| Historical "superseded" sections of this document (Phase 3B, 3B.1, 3B.2) | Kept as platform-investigation record (e.g. the cEOS DHCPv6-client-capability findings) per their own superseding notes -- never deleted, only marked no-longer-authoritative. |

## Validation / render commands (safe, read-only unless noted)

```bash
# NetBox connectivity/auth
/home/student/Scripts/.venv/bin/python -m modules.netbox_ipam

# Desired-state model check (zero drift expected)
/home/student/Scripts/.venv/bin/python netbox/scripts/verify_netbox_model.py

# Reservation/identity readiness (0 targets expected -- see above)
/home/student/Scripts/.venv/bin/python netbox/scripts/verify_reservations.py

# Manifest -> NetBox reconciliation preview (no writes)
/home/student/Scripts/.venv/bin/python netbox/scripts/populate_netbox.py --check --verbose

# Manifest -> NetBox reconciliation (writes; idempotent)
/home/student/Scripts/.venv/bin/python netbox/scripts/populate_netbox.py --apply --verbose

# R2/NMAS render-only previews (never push/restart anything)
/home/student/Scripts/.venv/bin/python netbox/scripts/render_r2_dhcp.py -v
/home/student/Scripts/.venv/bin/python netbox/scripts/render_nmas_dhcp.py -v

# Live dual-server operational status (read-only)
/home/student/Scripts/.venv/bin/python netbox/scripts/verify_dhcp_servers.py

# Full unit-test suite
/home/student/Scripts/.venv/bin/python -m unittest discover -s monitoring/tests -p 'test_*.py'
```

## Fail-closed behavior (reconfirmed)

Every function on both active DHCP paths (`build_and_validate_nmas_dhcp_context()`,
`build_and_validate_r2_dhcp_context()`, `validate_r2_candidate_render()`)
still raises immediately on a NetBox connectivity/auth failure, a missing
or unexpected pool, or any pool-safety violation -- there is no
`try/except`-guarded fallback to a hard-coded pool anywhere in
`master.py`, `modules/ipam_context.py`, or either render script. A NetBox
outage stops the affected device's DHCP configuration from being
generated at all; it never silently reverts to stale or invented values.

## Known limitation (unchanged, not investigated here)

**H1 -> WebServer connectivity remains a pre-existing, open issue.** It was
neither touched nor investigated in this cleanup phase, exactly as
instructed, and is unrelated to the DHCP/IPAM migration.

## Final regression (this phase)

```text
Unit tests:                    429/429 PASS   (428 baseline + 1 new
                                                regression test for the
                                                stale-description fix)
verify_netbox_model.py:         392/392 PASS   (unchanged)
verify_reservations.py:         READY=0 BLOCKED=0 FAIL=0 (unchanged)
populate_netbox.py --check:     UNCHANGED=309, CHECK-UPDATE=9 before the
                                 live apply (the 9 stale MAC descriptions);
                                 UNCHANGED=318 after
Containerlab:                   15/15 running, 0 restarts
NetBox stack:                   5/5 healthy
Grafana/InfluxDB:                healthy
topology service:               HTTP 200 (/ and /healthz)
NMAS DHCPv4/DHCPv6:              active/active
R2 DHCPv4/DHCPv6:                active/active
VLAN200 static addresses:       unchanged on all 9 managed devices
git status:                     nothing staged or committed
```
