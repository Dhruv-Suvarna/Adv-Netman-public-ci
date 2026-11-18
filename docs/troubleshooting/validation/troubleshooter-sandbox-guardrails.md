# Troubleshooter sandbox guardrails

## Enforced and tested in the development candidate

### Exact target authorization

`web/core/services/troubleshooting/target_policy.py` defines the common capability and target decision model:

- separate `READ_DIAGNOSTIC`, `OBSERVE_IDENTITY`, `PROPOSE_CHANGE` and `APPLY_CHANGE` capabilities;
- exact topology and tenant match;
- authoritative inventory presence, writable scope, explicit R5/exclusion denial;
- verified identity, in-service lifecycle, admitted production state and revocation checks;
- literal endpoint equality against authoritative device endpoints and currently approved management-path endpoints;
- protected VM1 host/management addresses;
- fixed transport and command-catalog operation identifiers;
- digest-bound authorization reference and expiry;
- mandatory validation of that reference against a live NMAS-created handoff, including agent identity, tenant, case/target state and wall-time budget; validation repeats at grant use;
- 60-second default, maximum 300-second, tamper-evident grant;
- immediate revalidation for expiry, operation/address substitution, inventory revision, revocation and management-path change;
- IPv4-mapped IPv6 canonicalization.

`web/core/services/troubleshooting/adapters/nmas_providers.py::target_policy` builds snapshots from the tracked topology/inventory, managed-device lifecycle/identity/admission rows, resolver scope, approved `ManagementPath` rows and the existing management guard. It does no discovery and opens no connection. With the current production database's zero management paths, diagnostic endpoint authorization fails closed.

`web/core/services/troubleshooting/deployment.py::_settings_config` rejects every direct network-capable provider from real settings while `NMAS_TS_SANDBOX_ENFORCEMENT=True`. This closes the activation bypass where an injected Python factory could connect before target validation. Test-only programmatic providers remain available solely because `core.tests.runner.NmasTestRunner` turns the flag off in the automated test process.

### AI and change separation

Existing controls traced and regression-tested:

- `ai.py::TOOLS`, `_validate_args` and `call_tool`: registered typed tools, forbidden raw-command/approval/privilege fields, device scope, nonce/idempotency, row/byte/device/time/call budgets and audit.
- `collectors.py`: platform command registry, parameter typing, command-count/output/time limits and a second read-only validator immediately before execution.
- `ai_runtime.py::MODEL_TOOLS`: write/proposal tools are not exposed to the model; NMAS, not the model, opens a handoff after deterministic exhaustion.
- `governance.py`: AI can create a structured proposal only. The Change Engine executor reports unsupported and apply refuses. Existing human approval, eligibility, device locks, validation, postcheck and rollback stay authoritative.

No shell, sudo, Docker, Containerlab, route/firewall, host configuration, raw credential, tool-registration or arbitrary URL tool was added.

### Research separation

`web/core/services/troubleshooting/research.py` and the `research_public_document` typed AI tool provide a separate evidence-only capability. See `ai-research-egress-policy.md`.

### Production activation refusal

`web/config/settings.py` keeps:

- target policy factory fixed to the NMAS provider adapter;
- sandbox enforcement on;
- research hostname set empty unless explicitly reviewed through environment configuration;
- device transports absent;
- model provider absent under existing deployment behavior.

Therefore deploying source alone still does not activate live diagnostic traffic.

## Implemented but awaiting activation

`deploy/sandbox/` contains:

- a strict dedicated diagnostic-worker systemd template with no capabilities, no home/devices/Docker, read-only system protection and `IPAddressDeny=any` plus exact generated IPv4 `/32` and IPv6 `/128` cgroup-BPF allows;
- a separate research-broker systemd template bound to a dedicated network namespace;
- a dual-stack nftables policy that permits DNS only to explicit resolvers, rejects private/local/shared/test/multicast/metadata-like ranges and IPv4-mapped IPv6, then permits public TCP/443;
- a fail-closed manifest renderer that rejects R5, unverified/non-admitted/non-in-service devices, protected host endpoints, empty target scope, missing DNS resolvers and missing research hosts.

These artifacts were tested as pure fixtures. They were not installed, loaded or activated. The referenced standalone worker commands still need implementation/packaging and an operator-created dedicated UID before activation; this is deliberately a readiness blocker, not hidden fallback to the web process.

## Blocked by external/change-window authorization

- Create dedicated service accounts/directories and root-owned environment files.
- Establish and validate separate worker/research network namespaces or systemd cgroup-BPF support.
- Select university-approved DNS resolvers and public research hostnames.
- Export/review exact active `ManagementPath` endpoints after inventory reconciliation.
- Validate management SSH recovery out-of-band, then install/reload/start units and policies in an approved window.
- Confirm university-owned address/subnet boundaries and whether any lab address overlaps shared infrastructure.

## Unsupported/unresolved

- Complete production sandbox isolation is not proved. Current web/maintenance services have Docker-group access, the gNMI collector and gateway have root-level privilege, and the staged narrower worker is inactive.
- There is no safe basis to authorize R2/R4 while identity is UNVERIFIED or any device without an approved management path.
- The application policy cannot contain a compromised process that retains root/Docker-admin privilege; kernel/service privilege separation is mandatory.
- This candidate has not been packaged, reviewed, deployed, migrated or activated. Gate B remains held.

## Source map

| Guardrail | Source/tests |
|---|---|
| Common target policy | `target_policy.py`; `test_troubleshooting_target_policy.py` |
| NMAS snapshot adapter | `adapters/nmas_providers.py::target_policy` |
| Unsafe direct-provider refusal | `deployment.py::_settings_config`; `test_troubleshooting_sandbox_artifacts.py` |
| Public research broker | `research.py`; `test_troubleshooting_research.py` |
| AI research tool and prompt-injection boundary | `ai.py`, `ai_runtime.py`; `test_troubleshooting_ai.py` |
| Staged cgroup/nft/process isolation | `deploy/sandbox/*`; `test_troubleshooting_sandbox_artifacts.py` |

## Completed standalone enforcement

- `worker_ipc.py` provides HMAC-authenticated versioned bounded Unix messages, kernel peer-UID checks, signed responses, durable nonce replay protection, restrictive sockets and sanitized audit records.
- `diagnostic_worker.py` accepts device/handoff/topology/fixed operation identifiers, never an address or raw command. It independently rereads the healthy active path, invokes `TargetPolicy`, revalidates around connection, uses the approved credential broker, source-bound pinned SSH, and clears credentials.
- `research_worker.py` is a distinct non-Django process with no database, inventory, credential or Docker access. `ai_runtime.py` now has no in-process HTTP fallback.
- `collectors.py`, `runtime.py`, `deployment.py` and `ai_runtime.py` carry typed operation IDs to the worker. The untyped diagnostic transport method always refuses.
- `deploy/sandbox/` now contains sysusers, three hardened units, distinct sockets/keys/state, namespace nft policies, exact rendering, namespace DNS, activation and rollback artifacts.

Code enforcement and disposable namespace behavior are tested. Live identities, namespaces, cgroup/nft rules and processes remain inactive. The root orchestrator gateway remains outside the sandbox and must not receive a Troubleshooter role.
