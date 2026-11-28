# Managed AI continuation bound to runtime diagnostics (`ai_runtime.py`)

Global multi-agent ownership and failover are implemented separately in
`agent_orchestrator.py`; see `agent-failover.md`. The continuation still owns
no provider credential or device authority.

Source: `web/core/services/troubleshooting/ai_runtime.py`, command `web/core/management/commands/troubleshooting_ai.py`,
tests `web/core/tests/test_troubleshooting_ai_runtime.py` (spec IDs UT-057..UT-063 binding; cases AIR001..AIR007). Source HEAD pin: cbb9c96 plus uncommitted working tree.

## What it does
* Reads no credentials. The model provider is any object with `complete(request) -> dict`, produced by a
  deployment-configured factory (`settings.TROUBLESHOOTING_AI_PROVIDER`, dotted path, or `--provider`). Default: none -> `PROVIDER_UNAVAILABLE`.
* The staged production factory is
  `core.services.troubleshooting.model_provider.completion_only_provider`.
  It accepts only the bounded `ai-model-request/1` object over a dedicated,
  HMAC-authenticated Unix socket and returns only `ai-model-response/1` from
  the configured provider/model identity. It has no network SDK, credential,
  shell, Docker, filesystem-path, destination, or generic RPC interface. The
  separately operated provider broker is not included or activated by the
  application package and requires its own reviewed service, key, peer-UID
  policy and provider egress approval.
* Typed I/O: `ai-model-request/1` (redacted, size-bounded; tool list, registered test catalog, handoff context) and `ai-model-response/1`
  (`action` = `tool` | `conclude`; unknown fields rejected; invalid output counts against the handoff's model-retry budget, then escalates).
* `RuntimeDiagnosticRunner` is the `ai.Runtime.runner`: a model-requested registered runbook test performs a bounded read-only collection
  (exactly `TestSpec.sources`, one admitted target) through `runtime.CollectorProvider`, ingests bundles, and evaluates the `TestSpec` on persisted
  observations. Missing transports yield UNAVAILABLE/INCONCLUSIVE with a reason, never an invented PASS.
* Authority stays in `ai.call_tool`: scope, budgets (tool calls/bytes/iterations), nonce idempotency, audit. `propose_remediation` and any
  non-read-only tool are not exposed to the model; attempts are audited `MCP_DENIED`. Raw CLI/command params are rejected. The model cannot approve or authorize.
* Persistence: handoff checkpoint stores model identity, request/response digests, cited evidence, usage, failures; tool results are keyed by a
  content-derived nonce, so a replacement worker repeating a request replays the stored result (no second collection, no extra tool budget).
* Hypotheses cite evidence ids; uncited claims are marked unverified by `ai`.

## Command
```
manage.py troubleshooting_ai continue --handoff TSAI-... --tenant T --actor NAME [--device D ...] [--provider pkg.mod.factory] [--deps pkg.mod.factory] [--runbook ID]
```
Prints a JSON result. Exit non-zero (CommandError) for `PROVIDER_UNAVAILABLE`, `NOT_AUTHORIZED`, `HANDOFF_NOT_OPEN`. It never opens a handoff; the
handoff stays OPEN and resumable when the provider is unavailable. Without `--deps`/`TROUBLESHOOTING_RUNTIME_DEPS` runtime collection fails closed (gaps recorded).

## Verification (local, NOT gateway-attested)
`cd web && DJANGO_DEBUG=1 DJANGO_SECRET_KEY=test /opt/ai-orchestrator/nmas-env/bin/python manage.py test core.tests.test_troubleshooting_ai_runtime core.tests.test_troubleshooting_ai` -> 33 tests OK.
Tests cross the real `runtime` collection and `ai.call_tool` boundary with a scripted transport and a provider **double**; this is not live-model evidence.

## External live prerequisites (unmet here)
1. A real model provider factory configured by the deployment (credentials owned by that factory, outside this repo) and egress to it.
2. A `RuntimeDeps` factory with real device transports and inventory, plus gateway-attested device evidence for any live claim.
3. A live-model acceptance run recorded by the gateway; until then model behaviour is UNKNOWN.

The three fixed completion-only factories (`codex_provider`,
`claude_a_provider`, `claude_b_provider`) also require separately operated,
approved brokers. Their presence in source is not evidence that any provider
is live.

