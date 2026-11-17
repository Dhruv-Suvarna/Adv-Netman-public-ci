# Completion-only model brokers and lease-bound dispatch

Code: `web/core/services/troubleshooting/model_broker.py` (server), `model_backend_anthropic.py`,
`model_backend_openai.py` (provider calls), `agent_dispatch.py` (lease + failover), command
`manage.py troubleshooting_ai dispatch|agents`. Units and templates: `deploy/sandbox/nmas-ts-model-broker@.service.in`,
`model-broker.env.in`, `nmas-ts-model.sysusers.in`, `nmas-ts-model.tmpfiles.in`, `nmas-troubleshooter-dispatch@.service.in`.

## Shape

```
website (no IPC key) ── opens handoff ──► TsAIHandoff (OPEN)
administrator ── systemctl start nmas-troubleshooter-dispatch@<handoff> ──►
  nmas-ts-runtime (PrivateNetwork, AF_UNIX only, DB writes limited to core_ts*)
      │  probe ► acquire global lease ► continue ► heartbeat ► transfer/pause/release
      ├─► /run/nmas-ts-model/codex.sock     nmas-ts-model-codex     ► provider API (TLS)
      ├─► /run/nmas-ts-model/claude-a.sock  nmas-ts-model-claude-a  ► provider API (TLS)
      └─► /run/nmas-ts-model/claude-b.sock  nmas-ts-model-claude-b  ► provider API (TLS)
```

Each broker is its own locked account with its own IPC key and its own provider credential in
`/etc/nmas/model-broker-<instance>.env` (`root:nmas-ts-model-<instance> 0640`). The runtime holds the three IPC keys and no
provider credential; a broker holds one provider credential and no diagnostic, research or device key. The website holds
neither and only reports whether each fixed socket exists.

## What a broker accepts

Exactly two authenticated payloads, both through the existing `worker_ipc` envelope (peer-UID check, HMAC, replay ledger,
sanitized audit log):

| Payload | Result |
|---|---|
| `{"schema": "…model-completion/1", "request": <ai-model-request/1>}` | one `ai-model-response/1` for the pinned identity |
| `{"schema": "…model-health/1"}` | credential-free status: `authenticated`, `restricted_interface`, `recent_error`, `cooldown_until`, counters |

There is no field that names a URL, path, command, tool or model. The provider call declares no tools, so the model can
only return text. That text is untrusted: it must parse as one JSON object with `action` `tool` or `conclude`, and only
the contract fields are forwarded. Anything else is `INVALID_MODEL_OUTPUT`, which spends the handoff's model-retry budget
and is not treated as a provider outage. Scope, budgets, write refusal and approval refusal stay in `ai.call_tool`.

Quota is reported as unknown (`quota_reliable: false`); a completion-only credential cannot observe it and it is never
estimated. Usage is stored as `input_units` / `output_units`, because the stored-secret policy refuses checkpoint keys
containing `token`.

## Failure codes and failover

`QUOTA_EXHAUSTED`, `RATE_LIMITED`, `CONTEXT_EXHAUSTED`, `AUTHENTICATION_UNAVAILABLE`, `PROVIDER_TIMEOUT`,
`PROVIDER_UNREACHABLE`, `PROVIDER_ERROR`, `PROVIDER_REFUSED`, `PROVIDER_REQUEST_REJECTED`, `OUTPUT_TRUNCATED`.
The broker makes one bounded attempt (`max_retries=0`) and keeps a cooldown for capacity and availability failures.

`agent_dispatch.dispatch` probes all three brokers, acquires the singleton lease for the best eligible agent and runs
`ai_runtime.continue_handoff` with that fence. On a provider failure the continuation has already checkpointed with the
handoff OPEN; the dispatcher atomically transfers the lease to the next agent that has not failed in this dispatch and
continues. Tool results are keyed by a content nonce, so a successor repeating the same request replays the stored result
instead of collecting again. With no eligible agent the lease becomes `PAUSED` and no tool authority exists. A finished
continuation releases the lease to `IDLE`; every acquire, transfer, pause and release advances the fence.

A pinned broker never substitutes another model. A provider refusal is a failover to the next agent, so the Anthropic
server-side `fallbacks` option is deliberately not used here.

## Containment (unit)

Host network namespace with a cgroup address filter: all RFC 1918, loopback, link-local, CGNAT, multicast and all IPv6
are denied; the only exception is the local resolver stub `127.0.0.53`. `RestrictAddressFamilies=AF_UNIX AF_INET`, no
capabilities, `ProtectSystem=strict`, Docker/containerd sockets, the production database, inventory, monitoring tree and
every other NMAS secret file inaccessible. Provider SDKs live in a separate `/opt/nmas-model/venv`; the worker runtime
keeps no network SDK. Verified with a transient unit on VM1 using the exact address policy: lab device, loopback service,
Containerlab gateway and host management address unreachable, Docker socket and web environment unreadable, IPv6 socket
refused, hostname-verified TLS to both provider API hosts established.

## Enrollment (per broker, performed by the owner)

1. Install the sysusers and tmpfiles fragments; build `/opt/nmas-model/venv` from a hash-pinned lock of
   `model-broker-requirements.in`.
2. Render `/etc/nmas/model-broker-<instance>.env` from `model-broker.env.in` with a fresh 32+ byte IPC key, the pinned
   model id and a provider API key created for that broker only (`anthropic` backend for ClaudeA and ClaudeB, `openai`
   backend for Codex). Put the matching IPC key and identity in `/etc/nmas/troubleshooter-ipc-client.env`.
3. `systemctl start nmas-ts-model-broker@<instance>` and check `manage.py troubleshooting_ai agents`.

Developer CLI logins (`~/.claude*`, `~/.codex`) are not production credentials and are never read by a broker.

## Tests

`core.tests.test_troubleshooting_model_broker` (handler contract, output reduction, error mapping, health),
`core.tests.test_troubleshooting_agent_dispatch` (three real authenticated broker sockets with scripted providers:
quota, rate limit, context exhaustion, refusal, crash, mid-task crash, all-unavailable pause and restart recovery,
busy lease, stale owner, duplicate tool request, wrong key), and `ModelBrokerArtifactTests`. Provider failures are
mocked; no live provider call is made by any test.
