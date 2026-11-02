# Version 2 Phase 2: network configuration validation and live push

Network configuration validation is a separate evidence domain. It validates configuration intended for or observed on
network devices. It is not Tier-2 whole-Change validation and it is not hosted Tier-3 validation of NMAS source code.

## Evidence and status

`NetworkConfigValidationRun` is append-only. A run pins the operation, device/platform, candidate or live-state hash,
read-only source fingerprints, structured checks, warnings/errors, NetBox observations, provenance, timestamp and
authenticated actor. Earlier evidence is never rewritten when an intent is revised or revalidated.

The result vocabulary is:

- `PASS`: all applicable checks passed.
- `WARNING`: configuration is technically usable but carries non-blocking evidence, such as an address outside the
  currently modelled NetBox prefixes.
- `BLOCKED`: a pre-write candidate/running/removal assessment found unsafe or incomplete configuration.
- `FAIL`: live post-write state did not match the approved intent.

Candidate and removal validation reuse the canonical accepted-intent snapshot, platform renderer and Phase-13 semantic
engine. They add explicit syntax, managed-scope, NetBox prefix relationship and OSPF network-statement checks. An
authoritative allocation collision blocks; NMAS never writes NetBox merely to make a validation pass. VLAN 200 dynamic
addressing and targets outside NetBox's authoritative managed set are fail-closed.

The Automation workbench can explicitly assess a sanitized running snapshot. That path parses with the platform importer,
checks address validity/duplicates, VLAN 200 policy, managed scope, NetBox agreement, unsupported constructs and expected
critical features, stores evidence, and performs no remediation.

## Push lifecycle

There is still one executor:

```
accepted intent -> network config validation -> Tier-2 whole-Change validation
                -> plan -> precheck -> explicit approval -> existing execution engine
                -> Phase-15 live postcheck -> network config live evidence
```

Execution refuses missing, stale or non-passing network configuration evidence in addition to all existing plan, precheck,
scope, capability, acknowledgement and locking gates. Transport acceptance is never success. Phase-15 postcheck results are
persisted again as the distinct `POST_PUSH` or `POST_REMOVAL` network-config evidence and feed Phase-1 capability evidence.

OSPFv2 network statements now have structured intent, field validation, UI editing, cEOS/FRR rendering and import support.
They do not yet have a concrete live configuration read-back evaluator, so the capability matrix reports post-write
validation as not implemented and Complete mode remains fail-closed for an OSPF process Configlet. Exhaustive per-platform
capability work remains Version 2 Phase 4.

## Automation lifecycle

Configuration Changes retains Change/DeviceIntent as its single data model. “Start New Revision” clones accepted state into
a new immutable revision, then editing continues in Device Builder. Revalidation appends new evidence. Validated candidates
can be exported through the existing audited candidate export. Never-executed drafts retain the existing guarded delete;
archive is the safe retirement path for historical changes and preserves every revision/evidence row while blocking future
execution. Remove Configuration continues through its dependency-aware snapshot and the same execution lifecycle.
