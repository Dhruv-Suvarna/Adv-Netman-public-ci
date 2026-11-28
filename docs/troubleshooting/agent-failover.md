# Global Troubleshooter agent lease and failover

Implementation: `web/core/services/troubleshooting/agent_orchestrator.py`. The
lease table is created within the not-yet-deployed Troubleshooter migration
0037, so the production migration plan remains exactly 0036 through 0039.

The singleton database row is the only global execution owner across every
case. Every acquisition, transfer, pause, or recovery increments a monotonic
fence. The handoff checkpoint carries the current fence and every governed
tool request fails closed when its runtime does not present that fence. The
completion broker checks the fence both before and after a provider call, so a
response that returns after transfer is discarded.

Supported identities are exactly `Codex`, `ClaudeA`, and `ClaudeB`. Their
completion-only adapters use separate fixed Unix sockets and IPC keys. They do
not expose a shell, filesystem, Docker, SSH, device credentials, destinations,
or generic RPC.

Selection rejects unauthenticated, unresponsive, unrestricted, cooling-down,
or context-insufficient providers. Reliable quota below 10 percent is rejected;
10–25 percent is eligible only for short bounded work. Unknown quota stays
`UNKNOWN` and is eligible only for bounded work with checkpoint reserve. A
heartbeat renews liveness but only verified progress refreshes the stall clock.

Failover waits for the existing bounded in-flight deadline, checkpoints the
case, fences the old owner, and atomically transfers to the next eligible
agent. If no agent is eligible, the singleton becomes `PAUSED`; the case stays
open and no tool authority exists. Provider recovery can later acquire a new,
higher fence.

The lease is bound to real continuations by `agent_dispatch.dispatch` (`manage.py troubleshooting_ai dispatch`,
unit `nmas-troubleshooter-dispatch@<handoff>`): it probes the three brokers, acquires, passes the fence into
`ai.call_tool`, records verified progress after every completed exchange, transfers on a provider failure and releases
to `IDLE` when the continuation ends. `release` also advances the fence. See `model-broker.md`.

Focused tests: `core.tests.test_troubleshooting_agent_orchestrator` and, across three real authenticated broker
sockets, `core.tests.test_troubleshooting_agent_dispatch`. These are
isolated provider doubles and a disposable Django database, not live-provider
or live-device evidence.

