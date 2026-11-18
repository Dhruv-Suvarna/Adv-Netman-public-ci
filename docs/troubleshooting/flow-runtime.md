# Wire-flow input in the persistent troubleshooting runtime

Subtask f2-flow_runtime, JOB-7349EED42129. Spec §2.1, §3.1, UT-004/006/017/022, IT-16/19.
Source: `/home/student/Scripts/clab_dualstack_lab`, tracked HEAD `cbb9c96` plus existing uncommitted substrate. No runtime deployment, listener, exporter configuration, capability promotion, migration, remote write or compatibility-ledger change.

The existing `FlowWireInput` decoder feeds the existing `FlowCollector` through `adapters.flow_runtime.FlowRuntimeInput`. `RuntimeDeps.flow_input(DeviceAdmission)` returns a binding or `None`. `CollectorProvider` invokes it only for admitted devices when flow keys are requested. The existing capability gate still applies; unsupported inputs do not drain the queue. Defaults remain unconfigured and fail closed.

A deployment-owned runtime factory can attach:

```python
from core.services.troubleshooting.adapters.flow_runtime import FlowRuntimeInput

# receiver_input is an existing, deployment-owned FlowWireInput.
# This callback must select an authorized service selector for this case/run.
deps.flow_input = lambda info: FlowRuntimeInput(
    receiver_input,
    {"protocol": 6, "dst_ports": [443], "src_prefixes": ["10.1.1.5/32"]},
    expected_exporters=(info.device,),
)
```

This is an injection seam, not a new deployment setting. The factory must bind selectors to the incident's authorized service; a generic shared input queue must not be drained concurrently by multiple case workers. One receiver thread owns the decoder. Selectors are mandatory. Full-address matching precedes mandatory /24 or /64 masking; out-of-scope records are excluded before storage. No packet payload or original binary datagram is persisted by this seam.

`TsEvidenceRef.scope.wire_ingest` uses `nmas.troubleshooting.flow-runtime/1` and retains per-record exporter, observation domain, template, sampling source/rate, timestamp source and flags; receiver cumulative loss counters, template summary, backpressure, privacy and selector-widening metadata. Receiver health is explicitly labeled cumulative and may include other services/exporters. `scope.normalized_flow` preserves normalized values, flags, coverage and sampling uncertainty, including null estimates when sampling is unknown. Raw pointer/hash, stored hash, parser/version, redaction, collector flags and gateway/live provenance retain the existing runtime bridge contracts. The raw hash describes the privacy-masked collector record JSON, **not original UDP datagram bytes**. An external raw store supplies its own immutable pointer under the existing store contract; the default stores redacted JSON in the existing evidence blob table.

Wire-data loss makes evidence partial. Exporter sequence gaps measure missing export packets (v9) or export records (IPFIX), never measured production packet loss. Sampled volume, including sampling=1, cannot prove loss, latency or availability. `flow.health` remains an explicit missing observation and wire scope records `production_health=UNKNOWN`, `measured_packet_loss=null`; service-health tests cannot pass from volume alone. Missing input produces NOT_CONFIGURED, not healthy or zero traffic.

Completed device manifests preserve existing `(case, run_key)` resume semantics: a fresh provider reuses persistent observations/evidence without invoking or draining replacement input. The decoder/queue is in memory; this change does not persist templates or make draining transactional with database ingestion. A crash before evidence persistence requires deployment-owned durable replay. Decoder restart without templates produces explicit UNKNOWN_TEMPLATE/data-loss uncertainty, not invented records. Record limits leave excess records queued, while prefiltering drains the selected exporter's out-of-scope records as specified by FlowWireInput.

## External prerequisites / INCOMPLETE_WORK

- An approved existing receiver must pass bounded datagrams and receipt times to `FlowWireInput.ingest`, enforce exporter identity mapping/source admission, secure transport and receiver access, retention/privacy, queue ownership, and durable replay/acknowledgment across crashes. This code opens no socket and installs no receiver.
- Operators must configure authorized exporters, template refresh/expiry, sampling and clock alignment outside this subtask. Current production NETFLOW capability claims remain unsupported; a validated deployment capability provider is required before real collection is allowed.
- Real service loss/latency/availability require independent service probes or trusted production monitors; flow volume is insufficient. Original-datagram archival/provenance, if required, belongs to the secured external receiver.
- Live/gateway-attested validation remains unavailable here: `python3 -I /opt/ai-orchestrator/gateway/client/aiorch_gw.py help` returned `{"ok": false, "error": "gateway not available for this run (HTTP/1.1 503 Blocked)"}`. No live network or end-to-end production-health success is claimed.

## Verification (generated binary replay only)

- `DJANGO_DEBUG=1 /home/student/Scripts/.venv-ci/bin/python web/manage.py test core.tests.test_troubleshooting_flow_runtime --verbosity 1` → **8 tests PASS**. FWRT001 selector/provenance/raw privacy/uncertainty; FWRT002 fresh-provider persistent resume/deduplication; FWRT003 missing input; FWRT004 unknown sampling; FWRT005 template loss/sequence gaps/backpressure; FWRT006 exporter isolation/capability refusal; FWRT007 unscoped refusal; FWRT008 record budget preserves queue remainder.
- `DJANGO_DEBUG=1 /home/student/Scripts/.venv-ci/bin/python web/manage.py test core.tests.test_troubleshooting_flow_runtime core.tests.test_troubleshooting_flow_wire core.tests.test_troubleshooting_dns_source --verbosity 1` → **59 tests PASS** (6 flow-runtime tests before the two additional boundary tests above).
- `DJANGO_DEBUG=1 /home/student/Scripts/.venv-ci/bin/python web/manage.py test core.tests.test_troubleshooting_runtime_ports core.tests.test_troubleshooting_deployment --verbosity 1` → **40 tests PASS**.
- `python3 -I -m py_compile web/core/services/troubleshooting/runtime.py web/core/services/troubleshooting/adapters/flow_runtime.py web/core/tests/test_troubleshooting_flow_runtime.py` → PASS.
- Scoped `git diff --check` → PASS. Whole-tree diff check also reported a preexisting trailing blank line in out-of-scope `Run_Logs.log`; untouched.
- Initial `.venv-ci/bin/python` relative to the repository failed (no such file); corrected to the absolute environment path above.

Source SHA-256 pins:

```text
d8752ec5d6821573cffdc96d7be70fc871adda5337d71074b9921addad0ec63a  web/core/services/troubleshooting/runtime.py
1eb543d1f920aad5c399450f519e7bfe2869502efd1bdba5bb1db7ecd5908784  web/core/services/troubleshooting/adapters/flow_runtime.py
0bfae33d7502f6ed753a00d1823430d3604fcf4c246cbc643a919b73e2db2589  web/core/tests/test_troubleshooting_flow_runtime.py
```

## Resumed verification — 2026-11-09

Preserved the existing scoped runtime integration and evidence checkpoints. Re-ran
`DJANGO_DEBUG=1 /home/student/Scripts/.venv-ci/bin/python web/manage.py test core.tests.test_troubleshooting_flow_runtime core.tests.test_troubleshooting_flow_wire core.tests.test_troubleshooting_dns_source --verbosity 1`: **61 tests PASS**, 15.205s.
Added FWRT009 (duplicate binary datagrams cannot inflate persistent volume) and
FWRT010 (fresh receiver without templates persists template-loss uncertainty).
`DJANGO_DEBUG=1 /home/student/Scripts/.venv-ci/bin/python web/manage.py test core.tests.test_troubleshooting_flow_runtime --verbosity 1`: **10 tests PASS**, 3.925s.
Scoped `python3 -I -m py_compile` and `git diff --check --` on the four assigned paths passed.
These are local generated-datagram tests; no live receiver, exporter, production health,
or gateway evidence is claimed. External prerequisites above remain INCOMPLETE_WORK
for deployment, outside completion of this bounded runtime-integration subtask.
