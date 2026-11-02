# NMAS Monitoring Infrastructure

Status: implemented on the NMAS host only. No network device configuration, Containerlab topology, routing, addressing, VLAN, DHCP, NAT, or forwarding behavior was changed.

## Approved scope

The running Lab 1 deployment remains frozen. This phase prepares NMAS for later device-side monitoring work:

- cEOS: R1, R2, R5, S1, S2, S3, S4, and `mgmt_swt`.
- Ubuntu/FRR: R3 and R4.
- Nokia SR Linux is not part of the approved live baseline.
- The known H1-to-WebServer issue is out of scope.

## Architecture

| Component | Purpose | Current endpoint |
|---|---|---|
| Net-SNMP client tools | Future SNMP polling and OID translation | Local commands: `snmpget`, `snmpwalk`, `snmptranslate` |
| `snmptrapd` | Future SNMP notification receiver | `192.168.200.100:162/udp` |
| rsyslog | Future centralized network Syslog receiver | `192.168.200.100:514/udp,tcp` |
| InfluxDB 2.7 | Central time-series/event storage | `127.0.0.1:8086` |
| Grafana 11.5 | Visualization service and future dashboards | `127.0.0.1:3000` |
| Python virtual environment | Future gNMI/NETCONF clients and collectors | `/home/student/Scripts/.venv` |
| Future topology service | Will consume stored device/interface/link state | Not implemented in this phase |

InfluxDB is the single storage backend for future SNMP polling, SNMP traps, Syslog-derived events, gNMI updates, NETCONF snapshots, health data, and topology state. The intended record dimensions are device, hostname, management IP, interface, source protocol, metric/event, timestamp, severity, and operational state.

No production device data is populated in this phase. The health check writes one clearly labelled local `nmas_test` record and queries it back.

## Repository layout

- `monitoring/docker-compose.yml`: InfluxDB and Grafana services.
- `monitoring/runtime/`: ignored persistent data and protected generated environment file.
- `monitoring/config/rsyslog-lab-monitoring.conf`: NMAS Syslog receiver template.
- `monitoring/config/snmptrapd.conf`: NMAS trap receiver template with a placeholder authorization value.
- `monitoring/config/lab-monitoring-logrotate`: raw remote-event retention policy.
- `monitoring/scripts/install_nmas_receivers.sh`: installs host receiver configuration and enables services.
- `monitoring/scripts/start_nmas_monitoring.sh`: creates protected local secrets on first run and starts the Compose stack.
- `monitoring/tests/verify_nmas_infrastructure.sh`: NMAS-only health and synthetic storage verification.
- `monitoring/requirements.txt`: future gNMI/NETCONF/topology Python dependencies.

## Provisioning entry point

Run from the repository:

```bash
python3 master.py
```

`master.py` remains an orchestrator. Its existing Lab 1 configuration functions, templates, host operations, routing and addressing behavior are unchanged. Its flow is now:

1. `modules/nmas.py:entrypoint()` validates protected runtime inputs and bootstraps host/Python dependencies before third-party imports.
2. Re-execute in the managed virtual environment if needed, then validate the inventory monitoring address.
3. Execute the existing Lab 1 configuration flow.
4. Call `ensure_nmas_infrastructure()` before existing Lab 1 verification.
5. Converge receivers/logrotate, start the Compose services, enforce retention, and require all 20 NMAS checks to pass.
6. Continue the existing Lab 1 verification/reporting flow.

For this frozen lab, provision and test **only NMAS** with:

```bash
python3 master.py --nmas-only
```

This branch exits before importing or executing the Lab 1 device automation. It requires the inventory's management interface and `192.168.200.100` address to exist; it does not create interfaces or configure addresses. Both idempotency tests used this branch. Do not use the full entry point as an NMAS-only check: its preserved Lab 1 flow configures network devices.

Use `--verbose` to display stage details. Normal output shows one PASS/FAIL line per stage. On failure, the failing stage's captured output is shown with monitoring passwords/tokens redacted, the process exits nonzero, and later dependent stages do not run. `verify_nmas()` reuses the existing 20-check script as the authoritative health gate.

## Supported fresh-host inputs

The bootstrap target is Ubuntu 24.04 with systemd, Python 3, sudo, and access to Ubuntu package repositories, Python package indexes and the pinned container images. The executing user needs noninteractive sudo (or a valid `sudo -v` session) and write access to the checkout and virtual-environment parent. Existing Docker installations are preserved; Docker privileges can be obtained through sudo without changing user groups.

Provide the repository, the already deployed Lab 1 topology/images and its valid inventory/credentials. The normal Lab 1 flow expects the management interface to exist; Containerlab deployment is an external prerequisite and is never performed by the NMAS module. Monitoring bootstrap does not install or configure Containerlab. The two topology copies are deliberately left untouched.

`bootstrap_nmas.sh` installs only missing packages: Python venv support, SNMP tools/receiver, rsyslog, logrotate, curl, OpenSSL, iproute2 and CA certificates. It installs Ubuntu Docker/Compose packages only if those capabilities are missing (and uses the Compose plugin package for an existing Docker CE installation). Grafana and InfluxDB are always Compose services, never apt services.

`install_python_dependencies.sh` reuses `<repository-parent>/.venv` (currently `/home/student/Scripts/.venv`) or creates it when absent. `NMAS_VENV` can select another environment explicitly. It installs both requirement files without `--upgrade`, validates dependency health and imports, and refuses to overwrite an incomplete existing environment. A genuinely fresh VM was not rebuilt during validation; bootstrap paths were inspected and the current healthy VM was used for two convergence tests.

## Desired state and runtime state

| Source-controlled desired state | Role |
|---|---|
| `modules/nmas.py` | Stage orchestration, input checks, failure handling, safe CLI branch |
| `monitoring/scripts/bootstrap_nmas.sh` | Missing host dependencies and Docker/logrotate availability |
| `monitoring/scripts/install_python_dependencies.sh` | Existing/new virtual environment and requirement installation |
| `monitoring/scripts/common.sh` | Shared environment paths and Docker privilege handling |
| `monitoring/scripts/install_nmas_receivers.sh` and `monitoring/config/*` | Receiver files, systemd drop-ins, permissions and raw-log retention |
| `monitoring/scripts/start_nmas_monitoring.sh` | Protected credential generation, Grafana directory ownership and Compose startup |
| `monitoring/docker-compose.yml` and `monitoring/grafana/provisioning/*` | Pinned service images, ports, persistent mounts and stable datasource UID |
| `monitoring/scripts/influxdb_retention.py` | In-place 30-day bucket retention via API |
| `monitoring/tests/verify_nmas_infrastructure.sh` | Mandatory 20-check gate |
| `monitoring/tests/test_nmas.py` | Offline failure/credential regression tests |

Generated runtime state stays in ignored `monitoring/runtime/`: `monitoring.env`, InfluxDB data and Grafana data. Installed `/etc` receiver files/drop-ins are copies of tracked desired state. Service logs and database content are runtime data, not source files.

The existing random-credential model is retained: new installations generate mode-600 `monitoring.env` with all seven required credentials/org/bucket fields. Repeated runs reuse it. Inputs must use unique unquoted `KEY=VALUE` entries with letters, digits, underscores, dots or hyphens; this matches the generated format and prevents shell expansion when verification reads it. Partial/insecure files fail validation. Missing credentials alongside existing database data cause failure rather than regenerating incompatible credentials. Restore the original credential file with restored database data. This task adds no secrets to source and does not implement credential rotation.

## Repeated execution

Installed apt packages are not reinstalled. Python packages satisfying requirements are retained. Receiver configuration is copied only when contents or required ownership/mode differ. Healthy receivers are restarted only if their configuration or listener binding requires it; enabling/starting an already active service does not restart it. Log files are never truncated during provisioning.

Grafana's bind-mounted directory remains UID 472/GID 0, mode 0750. Compose preserves existing healthy containers when their specification matches; real changes to the service definition can require recreation while preserving persistent bind-mounted data. Grafana's container binding supports Docker port forwarding while its host publication remains localhost-only. The tracked service definition sets `GF_SECURITY_ALLOW_EMBEDDING=true` so the authenticated Django dashboard wrappers can be framed; it does not enable anonymous access or expose Grafana beyond loopback.

InfluxDB retention is applied through the existing API reconciliation script on both first and repeated runs. No initialization-only Compose environment variable is needed: adding one to an already initialized service would unnecessarily recreate that container. The script updates the existing bucket only if retention differs and verifies the result. The provisioned Grafana datasource retains UID `nmas-influxdb` and is verified instead of recreated through API calls. Verification writes only clearly labelled synthetic local records.

Two NMAS-only runs were performed against the healthy baseline; both passed, followed by all 20 mandatory checks. Container IDs, receiver activation timestamps, existing synthetic data, bucket identity, and datasource identity were compared before and after. No device-side provisioning was run.

## Ports and binding policy

- UDP 162: `snmptrapd` binds only to `192.168.200.100`.
- UDP/TCP 514: rsyslog binds only to `192.168.200.100`.
- TCP 8086: InfluxDB is published only on `127.0.0.1`.
- TCP 3000: Grafana is published only on `127.0.0.1`.

No device is configured to send to these ports yet. The later device configuration phase must use the approved management path and must not alter forwarding behavior.

## Security and credentials

- No device credentials, SNMP secrets, gNMI credentials, NETCONF credentials, database tokens, or Grafana passwords are committed.
- InfluxDB and Grafana credentials are generated into the ignored, mode-600 runtime environment file.
- The trap template contains `LAB_TRAP_COMMUNITY_PLACEHOLDER`; this is not a production credential and must be replaced with an approved SNMPv3/trap authorization policy before device notifications are enabled.
- InfluxDB and Grafana are localhost-only in this phase.
- Grafana permits framing but remains authenticated; anonymous access is not
  enabled, and Django verifies the live framing headers before emitting an
  iframe.
- Future device-side configuration must prefer SNMPv3 authPriv and TLS/authenticated gNMI/NETCONF where supported.

## Retention

Raw network Syslog is written to `/var/log/lab-monitoring/remote-syslog.log` and rotated by `/etc/logrotate.d/lab-monitoring`:

- Daily rotation, including empty files so archives age out during quiet periods.
- At most 30 daily archives plus the current log (approximately 31 days of raw logs).
- Archives older than 30 days are removed when the daily rotation runs.
- Compression enabled after the newest rotation; missing files are tolerated.
- The active system logrotate timer must continue running for this policy to be enforced.

The InfluxDB `network-monitoring` bucket has 30-day retention (2592000 seconds), verified through the API. The existing bucket is updated in place; the API reconciliation script applies the same policy to a newly initialized bucket. Rerun `monitoring/scripts/influxdb_retention.py --apply` using the existing virtual environment to reconcile it. No bucket or volume is recreated.

SNMP service and socket drop-ins in `monitoring/config/snmptrapd-{service,socket}.conf` reset the distribution wildcard listeners and bind only `192.168.200.100:162/udp`. Syslog bindings remain unchanged. Trap daemon operational output remains in the system journal; the raw-file policy covers the named files, not journal storage.

## Health checks

Run:

```bash
/home/student/Scripts/clab_dualstack_lab/monitoring/tests/verify_nmas_infrastructure.sh
```

The check verifies:

- rsyslog and snmptrapd are active.
- UDP 162 and UDP/TCP 514 listeners exist.
- Net-SNMP commands exist.
- InfluxDB and Grafana Compose containers are running and healthy.
- InfluxDB and Grafana HTTP health endpoints respond.
- `ncclient`, `pygnmi`, `networkx`, and `requests` import in the existing Python environment.
- A local synthetic InfluxDB write can be queried back.

It does not contact, configure, poll, subscribe to, or send test traffic to any network device.

## Later phases intentionally excluded

This phase does not:

- Configure SNMP on cEOS or Ubuntu/FRR.
- Configure device Syslog forwarding.
- Create gNMI subscriptions.
- Run NETCONF queries against devices.
- Create production network dashboards.
- Build the dynamic topology service.
- Repair H1-to-WebServer connectivity.
- Change Containerlab or its running containers.
