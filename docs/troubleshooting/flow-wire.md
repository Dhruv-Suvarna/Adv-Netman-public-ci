# NetFlow v9 / IPFIX wire ingestion (`adapters/flow_wire.py`)

Decodes NetFlow v9 (RFC 3954) and IPFIX (RFC 7011) datagrams into the flow-record dictionaries that
`normalization.normalize_flow_records` / `collectors.FlowCollector` already consume. Nothing is stored here: evidence, scoping,
sampling scaling and budgets remain in the existing collector.

**It does not open a listener and does not touch any device exporter.** A deployment-owned receiver (not part of this task) must call
`FlowWireInput.ingest(bytes, exporter_address)`. No NMAS platform currently has a validated live exporter
(`capabilities.py`: NETFLOW is UNSUPPORTED for every known platform), so `collect()` through a capability-probed collector is still
refused for real targets until that is evidenced. Everything below is verified against generated binary datagrams only, not live traffic.

## API

* `FlowWireDecoder(WireConfig).decode(datagram, exporter_addr, exporter_name, received_at)` -> dict `nmas.troubleshooting.flow-wire-decode/1`
  (`records`, `events`, `event_counts`, ...). Never raises on hostile input.
* `FlowWireInput(exporters={addr: device}, config)`: `ingest`, `ingest_many(max_datagrams)`, `drain(exporter, limit)`, `health()`, `collect(collector, target, selector, ...)`.
* `WireConfig` bounds: datagram bytes (9216), sets (64) and records (1024) per datagram, fields/template (64), templates/domain (64),
  exporter-domains (256), events/datagram (32), pending queue (50 000), template TTL (1800 s), per-exporter default sampling.

## Supported fields

| IE | Name | Notes |
|---|---|---|
| 8/12, 27/28 | src/dst IPv4, IPv6 | length must be 4/16 |
| 7/11, 4 | ports, protocol | ICMP type/code (IE 32) not decoded; ports `None` if absent |
| 1, 2, 85, 86 | octet/packet delta or total counts | 1-8 byte integers; packets default 0 + `PACKETS_MISSING` |
| 21/22 | sysUpTime first/last (v9) | converted via header uptime/export time |
| 150-153, 160 | absolute seconds / milliseconds | preferred when present |
| 34, 50, 305+306 | sampling interval (inline or options) | see sampling below |

Other IEs, enterprise-specific IEs and IPFIX variable-length fields are length-skipped correctly. IPFIX template withdrawal and
options templates (v9 scope + option fields, IPFIX scope count) are handled. Sets 0/1 (v9), 2/3 (IPFIX) are templates; ids >= 256 data.

## Behaviour

* **Scoping:** templates/sampling/sequence state keyed by `(exporter address, observation domain)`; template id < 256 rejected.
* **Lifecycle:** refresh on re-announce; change replaces (`TEMPLATE_CHANGED`); TTL expiry removes the template and drops its data
  (`TEMPLATE_EXPIRED`); v9 sysUptime regression or IPFIX sequence reset to <= 256 flushes the domain (`EXPORTER_RESTART`).
* **Sequence:** v9 counts packets, IPFIX counts data records; gaps -> `SEQUENCE_GAP` with the missing amount; behind-expected
  datagrams -> `DUPLICATE_OR_REORDERED_DISCARDED` (not processed, to avoid double counting).
* **Sampling:** `record` (inline field) > `options` (same exporter+domain, keyed by scope) > `configured` (operator-asserted) > unknown.
  Conflicting advertised rates give no rate. Unknown rate => the normalizer yields `quality=UNKNOWN`, no scaled estimate.
* **Backpressure:** queue overflow rejects new records and counts `DROPPED_BACKPRESSURE`; `health()["data_loss"]` and the bundle flag
  `WIRE_DATA_LOSS` report any counted loss.
* **Privacy:** `collect()` selector-filters on full addresses in memory, then masks to /24 (/64) before the collector, so the raw
  evidence blob has no host addresses. Selector prefixes narrower than the mask are widened for the collector after exact pre-filtering
  (`wire_ingest.selector_widened`). Payload is never retained.

## Limitations (truthful)

* Data for unknown/expired templates is **lost**, not buffered; absence of flows is never proof of no traffic.
* Reordered and duplicate datagrams are indistinguishable on UDP; both are discarded.
* IPFIX restart detection is a heuristic (sequence reset to <= 256); v9 uses sysUptime. A restart that preserves counters is undetectable.
* Not supported: sFlow, NetFlow v5/v7/v8, IPFIX over TCP/SCTP, enterprise IEs, sampler-id-to-flow correlation (a single advertised rate per domain is assumed, conflicts yield unknown), ICMP type/code, MPLS/VLAN/interface fields, template/DTLS security.
* Timestamps fall back to export time (`TIMESTAMP_FROM_EXPORT_TIME`) when no supported time field exists; IPFIX sysUpTime IEs without `systemInitTimeMilliseconds` are not converted.
* Not exercised against live cEOS/IOS-XE/FRR exports; no gateway-recorded evidence exists for this module.

## Verification

`cd web && DJANGO_DEBUG=1 DJANGO_SECRET_KEY=test /opt/ai-orchestrator/nmas-env/bin/python manage.py test core.tests.test_troubleshooting_flow_wire core.tests.test_troubleshooting_collectors`
-> 128 tests OK (29 in the flow-wire module). Run locally on the NMAS venv; not gateway-attested.
